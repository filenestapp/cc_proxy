package main

import (
	"slices"
	"strconv"

	"github.com/jackc/pgx/v5"
)

func (a *api) adminRoutes() {
	a.bind("POST /admin/session", "", "", a.adminLogin)
	a.bind("GET /admin/session", "admin", "", a.adminWhoami)
	a.bind("DELETE /admin/session", "", "", a.adminLogout)
	a.bind("GET /admin/admins", "admin", "", a.adminList)
	a.bind("POST /admin/admins", "admin", "admins_add", a.adminAdd)
	a.bind("POST /admin/admins/{name}/password", "admin", "admins_password", a.adminPassword)
	a.bind("DELETE /admin/admins/{name}", "admin", "admins_delete", a.adminDelete)
	a.bind("GET /admin/audit", "admin", "", a.auditList)
	a.bind("GET /admin/settings", "admin", "", a.settingsGet)
	a.bind("PUT /admin/settings", "admin", "settings_put", a.settingsPut)
	a.bind("GET /admin/hosts", "admin", "", a.hostList)
	a.bind("POST /admin/hosts", "admin", "hosts_add", a.hostAdd)
	a.bind("PUT /admin/hosts/{name}", "admin", "hosts_update", a.hostUpdate)
	a.bind("DELETE /admin/hosts/{name}", "admin", "hosts_delete", a.hostDelete)
	a.bind("POST /admin/hosts/{name}/rotate-token", "admin", "hosts_rotate", a.hostRotate)
	a.bind("POST /admin/hosts/{name}/ips", "admin", "ips_add", a.ipAdd)
	a.bind("GET /admin/ips", "admin", "", a.ipList)
	a.bind("POST /admin/ips/{ip}/ban", "admin", "ips_ban", a.ipBan)
	a.bind("DELETE /admin/ips/{ip}", "admin", "ips_delete", a.ipDelete)
	a.bind("POST /admin/ips/{ip}/available", "admin", "ips_available", a.ipAvailable)
	a.bind("GET /admin/users", "admin", "", a.userList)
	a.bind("POST /admin/users", "admin", "users_add", a.userAdd)
	a.bind("PUT /admin/users/{name}", "admin", "users_update", a.userUpdate)
	a.bind("DELETE /admin/users/{name}", "admin", "users_delete", a.userDelete)
	a.bind("POST /admin/users/{name}/password", "admin", "users_password", a.userPassword)
	a.bind("POST /admin/users/{name}/assign", "admin", "users_assign", a.userAssign)
	a.bind("POST /admin/users/{name}/reassign", "admin", "users_reassign", a.userReassign)
	a.bind("POST /admin/users/{name}/release", "admin", "users_release", a.userRelease)
	a.bind("POST /admin/users/{name}/devices", "admin", "devices_add", a.deviceAdd)
	a.bind("POST /admin/users/{name}/devices/{device}/revoke", "admin", "devices_revoke", a.deviceRevoke)
	a.bind("GET /admin/topology", "admin", "", a.topology)
	a.bind("GET /admin/alerts", "admin", "", a.alertList)
	a.bind("POST /admin/alerts/test", "admin", "alerts_test", a.alertTest)
}

func (a *api) adminLogin(r *apiRequest) (response, error) {
	var body credentials
	if err := r.decode(&body, "username", "password"); err != nil {
		return response{}, err
	}
	keys := []string{"admin:" + body.Username, "admin-addr:" + r.Address}
	if a.limiter.blocked(a.store.clock(), keys...) {
		return response{}, failure(429, "too many failed sign-ins; try again later")
	}
	token, csrf, err := a.store.loginAdmin(r.Context(), body.Username, body.Password, r.Address)
	if err != nil {
		if statusOf(err) == 401 {
			a.limiter.fail(a.store.clock(), keys...)
			a.writeAudit(r, body.Username, "admin sign-in failed", "", "")
		}
		return response{}, err
	}
	a.writeAudit(r, body.Username, "admin sign-in", "", "")
	return response{status: 200, body: object{"admin": body.Username, "csrf": csrf},
		cookie: a.sessionCookie(r, token, sessionTTL)}, nil
}

func (a *api) adminWhoami(r *apiRequest) (response, error) {
	out := object{"admin": r.Session.Admin, "csrf": nil}
	if r.Session.CSRF != "" {
		out["csrf"], out["expires_at"] = r.Session.CSRF, r.Session.ExpiresAt
	}
	return ok(out, nil)
}

func (a *api) adminLogout(r *apiRequest) (response, error) {
	if token := cookieValue(r.Request); token != "" {
		name, err := a.store.logoutAdmin(r.Context(), token)
		if err != nil {
			return response{}, err
		}
		if name != "" {
			a.writeAudit(r, name, "admin sign-out", "", "")
		}
	}
	return response{status: 200, body: object{"signed_out": true}, cookie: a.sessionCookie(r, "", -1)}, nil
}

func (a *api) adminList(r *apiRequest) (response, error) {
	return ok(a.store.listAdmins(r.Context()))
}

type accountInput struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

func accountPassword(name, supplied string) (string, object) {
	out := object{"name": name}
	if supplied == "" {
		supplied = randomToken(12)
		out["password"] = supplied
	}
	return supplied, out
}

func (a *api) adminAdd(r *apiRequest) (response, error) {
	var body accountInput
	if err := r.decode(&body, "name"); err != nil {
		return response{}, err
	}
	pw, out := accountPassword(body.Name, body.Password)
	return created(out, a.store.addAdmin(r.Context(), body.Name, pw))
}

func (a *api) adminPassword(r *apiRequest) (response, error) {
	var body accountInput
	if err := r.decode(&body); err != nil {
		return response{}, err
	}
	name := r.PathValue("name")
	pw, out := accountPassword(name, body.Password)
	return ok(out, a.store.setAdminPassword(r.Context(), name, pw))
}

func (a *api) adminDelete(r *apiRequest) (response, error) {
	name := r.PathValue("name")
	return ok(object{"deleted": name}, a.store.deleteAdmin(r.Context(), name))
}

func (a *api) auditList(r *apiRequest) (response, error) {
	query := r.URL.Query()
	limit := 100
	if query.Has("limit") {
		n, err := strconv.Atoi(query.Get("limit"))
		if err != nil {
			return response{}, failure(400, "limit must be an integer")
		}
		limit = n
	}
	var before *int64
	if cursor := query.Get("before"); cursor != "" {
		id, err := strconv.ParseInt(cursor, 10, 64)
		if err != nil {
			return response{}, failure(400, "before must be an integer")
		}
		before = &id
	}
	return ok(a.store.auditLog(r.Context(), limit, before, query.Get("actor")))
}

func (a *api) settingsGet(r *apiRequest) (response, error) {
	return ok(loadSettings(r.Context(), a.store.pool))
}

func (a *api) settingsPut(r *apiRequest) (response, error) {
	values, err := settingsPatch(r.Body)
	if err != nil {
		return response{}, err
	}
	ctx := r.Context()
	var updated int64
	err = a.store.write(ctx, func(tx pgx.Tx) error {
		if err := setSettings(ctx, tx, values); err != nil {
			return err
		}
		if err := bumpVersion(ctx, tx); err != nil {
			return err
		}
		updated, err = version(ctx, tx)
		return err
	})
	return ok(object{"version": updated}, err)
}

func (a *api) hostList(r *apiRequest) (response, error) {
	return ok(listHosts(r.Context(), a.store.pool))
}

func (a *api) hostAdd(r *apiRequest) (response, error) {
	var body struct {
		Name string `json:"name"`
		hostOptions
	}
	if err := r.decode(&body, "name"); err != nil {
		return response{}, err
	}
	token, err := a.store.addHost(r.Context(), body.Name, body.hostOptions)
	return created(object{"host": body.Name, "agent_token": token}, err)
}

func (a *api) hostUpdate(r *apiRequest) (response, error) {
	var options hostOptions
	allowed := []string{"public_host", "server_name", "handshake_server", "handshake_port", "port_min", "port_max",
		"block_private", "block_cidrs"}
	for key := range r.Body {
		if !slices.Contains(allowed, key) {
			return response{}, failure(409, "cannot update %s", key)
		}
	}
	if err := r.decode(&options); err != nil {
		return response{}, err
	}
	name := r.PathValue("name")
	return ok(object{"host": name}, a.store.updateHost(r.Context(), name, options))
}

func (a *api) hostDelete(r *apiRequest) (response, error) {
	name := r.PathValue("name")
	return ok(object{"deleted": name}, a.store.deleteHost(r.Context(), name))
}

func (a *api) hostRotate(r *apiRequest) (response, error) {
	name := r.PathValue("name")
	token, err := a.store.rotateAgentToken(r.Context(), name)
	return ok(object{"host": name, "agent_token": token}, err)
}

func (a *api) ipAdd(r *apiRequest) (response, error) {
	var body struct {
		IPs []string `json:"ips"`
	}
	if err := r.decode(&body, "ips"); err != nil {
		return response{}, err
	}
	if body.IPs == nil {
		return response{}, failure(400, "ips must be a list")
	}
	added, err := a.store.addIPs(r.Context(), r.PathValue("name"), body.IPs)
	return created(object{"added": added}, err)
}

func (a *api) ipList(r *apiRequest) (response, error) {
	return ok(listIPs(r.Context(), a.store.pool, r.URL.Query().Get("host"), a.store.now()))
}

func (a *api) ipBan(r *apiRequest) (response, error) {
	var body struct {
		Note string `json:"note"`
	}
	if err := r.decode(&body); err != nil {
		return response{}, err
	}
	ip := r.PathValue("ip")
	released, err := a.store.banIP(r.Context(), ip, body.Note)
	return ok(object{"banned": ip, "released_users": released}, err)
}

func (a *api) ipDelete(r *apiRequest) (response, error) {
	ip := r.PathValue("ip")
	return ok(object{"deleted": ip}, a.store.deleteIP(r.Context(), ip))
}

func (a *api) ipAvailable(r *apiRequest) (response, error) {
	ip := r.PathValue("ip")
	return ok(object{"available": ip}, a.store.makeAvailable(r.Context(), ip))
}

func (a *api) userList(r *apiRequest) (response, error) {
	ctx := r.Context()
	var users []userView
	err := a.store.snapshot(ctx, func(tx pgx.Tx) error {
		var err error
		users, err = listUsers(ctx, tx)
		return err
	})
	return ok(users, err)
}

func (a *api) userAdd(r *apiRequest) (response, error) {
	body := struct {
		accountInput
		Mode       string  `json:"mode"`
		MaxDevices integer `json:"max_devices"`
	}{Mode: "exclusive", MaxDevices: maxDevices}
	if err := r.decode(&body, "name"); err != nil {
		return response{}, err
	}
	pw, out := accountPassword(body.Name, body.Password)
	return created(out, a.store.addUser(r.Context(), body.Name, pw, body.Mode, int(body.MaxDevices)))
}

func (a *api) userUpdate(r *apiRequest) (response, error) {
	var body struct {
		MaxDevices integer `json:"max_devices"`
	}
	if err := r.decode(&body, "max_devices"); err != nil {
		return response{}, err
	}
	name := r.PathValue("name")
	return ok(object{"name": name}, a.store.setMaxDevices(r.Context(), name, int(body.MaxDevices)))
}

func (a *api) userDelete(r *apiRequest) (response, error) {
	name := r.PathValue("name")
	return ok(object{"deleted": name}, a.store.deleteUser(r.Context(), name))
}

func (a *api) userPassword(r *apiRequest) (response, error) {
	var body struct {
		accountInput
		RevokeDevices bool `json:"revoke_devices"`
	}
	if err := r.decode(&body); err != nil {
		return response{}, err
	}
	name := r.PathValue("name")
	pw, out := accountPassword(name, body.Password)
	return ok(out, a.store.setUserPassword(r.Context(), name, pw, body.RevokeDevices))
}

func (a *api) userAssign(r *apiRequest) (response, error) {
	return a.bindUser(r, false)
}

func (a *api) userReassign(r *apiRequest) (response, error) {
	return a.bindUser(r, true)
}

func (a *api) bindUser(r *apiRequest, moving bool) (response, error) {
	var choice assignment
	if err := r.decode(&choice); err != nil {
		return response{}, err
	}
	u, err := a.store.assign(r.Context(), r.PathValue("name"), choice, moving)
	if err != nil {
		return response{}, err
	}
	return ok(u, nil)
}

func (a *api) userRelease(r *apiRequest) (response, error) {
	name := r.PathValue("name")
	ip, err := a.store.releaseUser(r.Context(), name)
	return ok(object{"user": name, "released": ip}, err)
}

func (a *api) deviceAdd(r *apiRequest) (response, error) {
	var body struct {
		Name     string `json:"name"`
		Platform string `json:"platform"`
	}
	if err := r.decode(&body, "name"); err != nil {
		return response{}, err
	}
	name := r.PathValue("name")
	token, err := a.store.addDevice(r.Context(), name, body.Name, body.Platform)
	return created(object{"user": name, "device": body.Name, "token": token}, err)
}

func (a *api) deviceRevoke(r *apiRequest) (response, error) {
	name, device := r.PathValue("name"), r.PathValue("device")
	return ok(object{"revoked": name + "/" + device}, a.store.revokeDevice(r.Context(), name, device))
}

func (a *api) topology(r *apiRequest) (response, error) {
	ctx := r.Context()
	var out struct {
		topologyView
		Alerts []alertView `json:"alerts"`
	}
	err := a.store.snapshot(ctx, func(tx pgx.Tx) error {
		cfg, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		monitor, err := decodeMonitor(cfg)
		if err != nil {
			return err
		}
		out.topologyView, err = a.store.topology(ctx, tx, monitor)
		if err != nil {
			return err
		}
		out.Alerts, err = listAlerts(ctx, tx, false)
		return err
	})
	return ok(out, err)
}

func (a *api) alertList(r *apiRequest) (response, error) {
	return ok(listAlerts(r.Context(), a.store.pool, r.URL.Query().Get("all") == "1"))
}

func (a *api) alertTest(r *apiRequest) (response, error) {
	ctx := r.Context()
	cfg, err := loadSettings(ctx, a.store.pool)
	if err != nil {
		return response{}, err
	}
	alerts, err := parseAlertSettings(cfg.Alerts)
	if err != nil {
		return response{}, err
	}
	sample := alertView{Rule: "test", Subject: "test", Severity: "warning", Summary: "Test alert"}
	results := make([]object, 0, len(alerts.Webhooks))
	for _, hook := range alerts.Webhooks {
		err := sendWebhook(ctx, hook.URL, alertPayload(hook.Format, sample, "firing"))
		result := object{"url": hook.URL, "ok": err == nil}
		if err != nil {
			result["error"] = err.Error()
		}
		results = append(results, result)
	}
	return ok(object{"webhooks": results}, nil)
}
