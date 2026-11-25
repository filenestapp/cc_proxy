package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const cloudMailHTTPTimeout = 15 * time.Second

type mailSender interface {
	send(context.Context, string, string, string) error
}

type cloudMailConnection struct {
	baseURL  string
	email    string
	password string
	client   *http.Client
}

type cloudMailSender struct {
	cloudMailConnection
	mu        sync.Mutex
	token     string
	accountID int64
}

func newCloudMailSenderFromEnv() mailSender {
	connection := cloudMailConnectionFromEnv("CLOUDMAIL_NOREPLY_EMAIL", "CLOUDMAIL_NOREPLY_PASSWORD")
	if connection == nil {
		return nil
	}
	return &cloudMailSender{cloudMailConnection: *connection}
}

func cloudMailConnectionFromEnv(emailKey, passwordKey string) *cloudMailConnection {
	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("CLOUDMAIL_URL")), "/")
	email := strings.TrimSpace(os.Getenv(emailKey))
	password := os.Getenv(passwordKey)
	endpoint, err := url.ParseRequestURI(baseURL)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "https" && endpoint.Scheme != "http") ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || email == "" || password == "" {
		return nil
	}
	return &cloudMailConnection{baseURL: baseURL, email: email, password: password, client: &http.Client{Timeout: cloudMailHTTPTimeout}}
}

func (m *cloudMailConnection) request(ctx context.Context, method, path string, body any, token string, out any) (int, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, m.baseURL+path, reader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept-Language", "en")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	client := m.client
	if client == nil {
		client = &http.Client{Timeout: cloudMailHTTPTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("cloud-mail returned HTTP %d", resp.StatusCode)
	}
	if out != nil && len(data) != 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

type cloudMailResponse struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func (m *cloudMailConnection) login(ctx context.Context) (string, error) {
	var response cloudMailResponse
	_, err := m.request(ctx, http.MethodPost, "/api/login", object{"email": m.email, "password": m.password}, "", &response)
	if err != nil {
		return "", err
	}
	if response.Code != 200 {
		return "", errors.New("cloud-mail login was rejected")
	}
	var data struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(response.Data, &data); err != nil || data.Token == "" {
		return "", errors.New("cloud-mail login returned no token")
	}
	return data.Token, nil
}

func (m *cloudMailSender) loadAccount(ctx context.Context) error {
	var response cloudMailResponse
	status, err := m.request(ctx, http.MethodGet, "/api/account/list?size=100", nil, m.token, &response)
	if err != nil {
		return err
	}
	if status == http.StatusUnauthorized || response.Code == http.StatusUnauthorized {
		return errors.New("cloud-mail session expired")
	}
	if response.Code != 200 {
		return errors.New("cloud-mail account lookup was rejected")
	}
	type senderAccount struct {
		AccountID int64  `json:"accountId"`
		Email     string `json:"email"`
	}
	var accounts []senderAccount
	if bytes.HasPrefix(response.Data, []byte("{")) {
		var page struct {
			List []senderAccount `json:"list"`
		}
		if err := json.Unmarshal(response.Data, &page); err != nil {
			return err
		}
		accounts = page.List
	} else if err := json.Unmarshal(response.Data, &accounts); err != nil {
		return err
	}
	for _, account := range accounts {
		if account.AccountID > 0 && strings.EqualFold(account.Email, m.email) {
			m.accountID = account.AccountID
			return nil
		}
	}
	return errors.New("cloud-mail noreply account was not found")
}

func (m *cloudMailSender) send(ctx context.Context, to, subject, content string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if m.token == "" {
			token, err := m.login(ctx)
			if err != nil {
				return err
			}
			m.token, m.accountID = token, 0
		}
		if m.accountID == 0 {
			if err := m.loadAccount(ctx); err != nil {
				m.token = ""
				continue
			}
		}
		var response cloudMailResponse
		status, err := m.request(ctx, http.MethodPost, "/api/email/send", object{
			"accountId": m.accountID, "receiveEmail": []string{to}, "subject": subject, "content": content,
		}, m.token, &response)
		if err == nil && response.Code == 200 {
			return nil
		}
		if status != http.StatusUnauthorized && response.Code != http.StatusUnauthorized {
			if err != nil {
				return err
			}
			return errors.New("cloud-mail rejected the email")
		}
		m.token, m.accountID = "", 0
	}
	return errors.New("cloud-mail authentication retry failed")
}
