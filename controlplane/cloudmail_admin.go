package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

type cloudMailAdmin struct {
	cloudMailConnection
	mu    sync.Mutex
	token string
}

var errCloudMailAddressTaken = errors.New("cloud-mail address is already in use")

func newCloudMailAdminFromEnv() *cloudMailAdmin {
	connection := cloudMailConnectionFromEnv("CLOUDMAIL_ADMIN_EMAIL", "CLOUDMAIL_ADMIN_PASSWORD")
	if connection == nil {
		return nil
	}
	connection.client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &cloudMailAdmin{cloudMailConnection: *connection}
}

func (m *cloudMailAdmin) adminToken(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.token != "" {
		return m.token, nil
	}
	token, err := m.login(ctx)
	m.token = token
	return token, err
}

func (m *cloudMailAdmin) call(ctx context.Context, method, path string, body any) (cloudMailResponse, int, error) {
	for attempt := 0; attempt < 2; attempt++ {
		token, err := m.adminToken(ctx)
		if err != nil {
			return cloudMailResponse{}, 0, err
		}
		var reply cloudMailResponse
		status, err := m.request(ctx, method, path, body, token, &reply)
		if status != http.StatusUnauthorized && reply.Code != http.StatusUnauthorized {
			if err == nil && reply.Code != http.StatusOK {
				err = fmt.Errorf("cloud-mail rejected the request (code %d)", reply.Code)
			}
			return reply, status, err
		}
		m.mu.Lock()
		if m.token == token {
			m.token = ""
		}
		m.mu.Unlock()
	}
	return cloudMailResponse{}, 0, errors.New("cloud-mail authentication retry failed")
}

func (m *cloudMailAdmin) addUser(ctx context.Context, address, password string) error {
	reply, status, err := m.call(ctx, http.MethodPost, "/api/user/add", object{"email": address, "password": password})
	// Cloud-mail also uses a generic business error for an existing user or alias.
	if status == http.StatusConflict || reply.Code == http.StatusConflict ||
		(reply.Code == 501 && (strings.EqualFold(reply.Message, "This email is already registered") ||
			strings.EqualFold(reply.Message, "This email has been deleted"))) {
		return errCloudMailAddressTaken
	}
	return err
}

func (m *cloudMailAdmin) findUser(ctx context.Context, address string) (int64, error) {
	const pageSize = 50
	var id int64
	for page := 1; ; page++ {
		query := url.Values{"email": {address}, "num": {strconv.Itoa(page)}, "size": {strconv.Itoa(pageSize)}}
		reply, _, err := m.call(ctx, http.MethodGet, "/api/user/list?"+query.Encode(), nil)
		if err != nil {
			return 0, err
		}
		var result struct {
			Total int `json:"total"`
			List  []struct {
				ID      int64  `json:"userId"`
				Email   string `json:"email"`
				Deleted int    `json:"isDel"`
			} `json:"list"`
		}
		if err := json.Unmarshal(reply.Data, &result); err != nil {
			return 0, err
		}
		for _, user := range result.List {
			if !strings.EqualFold(user.Email, address) {
				continue
			}
			if id != 0 || user.ID <= 0 || user.Deleted != 0 {
				return 0, errors.New("cloud-mail returned an ambiguous or deleted user")
			}
			id = user.ID
		}
		if page*pageSize >= result.Total || len(result.List) == 0 {
			break
		}
	}
	if id == 0 {
		return 0, errors.New("cloud-mail user was not found")
	}
	return id, nil
}

func (m *cloudMailAdmin) setPassword(ctx context.Context, id int64, password string) error {
	_, _, err := m.call(ctx, http.MethodPut, "/api/user/setPwd", object{"userId": id, "password": password})
	return err
}

func (m *cloudMailAdmin) setStatus(ctx context.Context, id int64, disabled bool) error {
	status := 0
	if disabled {
		status = 1
	}
	_, _, err := m.call(ctx, http.MethodPut, "/api/user/setStatus", object{"userId": id, "status": status})
	return err
}

func (m *cloudMailAdmin) deleteUser(ctx context.Context, id int64) error {
	_, _, err := m.call(ctx, http.MethodDelete, "/api/user/delete?userIds="+strconv.FormatInt(id, 10), nil)
	return err
}
