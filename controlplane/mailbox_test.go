package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	fakeMailAdminEmail    = "service-admin@aifree.sg"
	fakeMailAdminPassword = "test cloud-mail admin password"
)

type fakeCloudMailReply struct {
	status, code int
	message      string
	afterWrite   bool
}

type fakeCloudMailUser struct {
	ID       int64  `json:"userId"`
	Email    string `json:"email"`
	Password string `json:"-"`
	Status   int    `json:"status"`
}

type fakeCloudMail struct {
	mu       sync.Mutex
	token    string
	nextID   int64
	users    map[string]fakeCloudMailUser
	calls    map[string]int
	failures map[string][]fakeCloudMailReply
}

func newFakeCloudMail(t *testing.T) (*fakeCloudMail, *cloudMailAdmin) {
	t.Helper()
	fake := &fakeCloudMail{
		users: make(map[string]fakeCloudMailUser), calls: make(map[string]int),
		failures: make(map[string][]fakeCloudMailReply),
	}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	t.Setenv("CLOUDMAIL_URL", server.URL)
	t.Setenv("CLOUDMAIL_ADMIN_EMAIL", fakeMailAdminEmail)
	t.Setenv("CLOUDMAIL_ADMIN_PASSWORD", fakeMailAdminPassword)
	admin := newCloudMailAdminFromEnv()
	if admin == nil {
		t.Fatal("cloud-mail admin was not configured")
	}
	return fake, admin
}

func (f *fakeCloudMail) failNext(path string, reply fakeCloudMailReply) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures[path] = append(f.failures[path], reply)
}

func (f *fakeCloudMail) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[path]
}

func (f *fakeCloudMail) user(address string) (fakeCloudMailUser, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	user, exists := f.users[address]
	return user, exists
}

// Exercise the v3.6.0 wire format and the control plane's receive-only create payload.
func (f *fakeCloudMail) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := r.URL.Path
	f.calls[path]++
	write := func(status, code int, message string, data any) {
		reply := object{"code": code, "message": message}
		if code == 200 {
			reply["message"], reply["data"] = "success", data
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(reply)
	}
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		UserID   int64  `json:"userId"`
		Status   *int   `json:"status"`
	}
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			write(200, 501, "Invalid control plane payload", nil)
			return
		}
	}
	if path == "/api/login" {
		if r.Method != http.MethodPost || body.Email != fakeMailAdminEmail || body.Password != fakeMailAdminPassword {
			write(200, 501, "Invalid credentials", nil)
			return
		}
		f.token = fmt.Sprintf("session-%d", f.calls[path])
		write(200, 200, "", object{"token": f.token})
		return
	}
	if f.token == "" || r.Header.Get("Authorization") != f.token {
		write(200, 401, "Authentication has expired. Please sign in again", nil)
		return
	}
	var failure fakeCloudMailReply
	if pending := f.failures[path]; len(pending) != 0 {
		failure = pending[0]
		f.failures[path] = pending[1:]
		if !failure.afterWrite {
			if failure.status == 401 || failure.code == 401 {
				f.token = ""
			}
			write(failure.status, failure.code, failure.message, nil)
			return
		}
	}

	var data any
	switch {
	case path == "/api/user/add" && r.Method == http.MethodPost:
		if !strings.HasSuffix(body.Email, "@aifree.sg") || len(body.Password) < 6 {
			write(200, 501, "Invalid fixture email or password", nil)
			return
		}
		if _, exists := f.users[body.Email]; exists {
			write(200, 501, "This Email is already registered", nil)
			return
		}
		f.nextID++
		f.users[body.Email] = fakeCloudMailUser{ID: f.nextID, Email: body.Email, Password: body.Password}
	case path == "/api/user/list" && r.Method == http.MethodGet:
		query := r.URL.Query()
		prefix := strings.ToLower(query.Get("email"))
		page, _ := strconv.Atoi(query.Get("num"))
		size, _ := strconv.Atoi(query.Get("size"))
		if page < 1 || size < 1 || size > 50 {
			write(200, 501, "Invalid fixture pagination", nil)
			return
		}
		var users []fakeCloudMailUser
		for _, user := range f.users {
			if strings.HasPrefix(strings.ToLower(user.Email), prefix) {
				users = append(users, user)
			}
		}
		slices.SortFunc(users, func(a, b fakeCloudMailUser) int {
			return cmp.Compare(b.ID, a.ID)
		})
		start := min((page-1)*size, len(users))
		end := min(start+size, len(users))
		data = object{"list": users[start:end], "total": len(users)}
	case path == "/api/user/setStatus" && r.Method == http.MethodPut:
		if body.UserID <= 0 || body.Status == nil || (*body.Status != 0 && *body.Status != 1) {
			write(200, 501, "Invalid fixture status update", nil)
			return
		}
		for address, user := range f.users {
			if user.ID == body.UserID {
				user.Status = *body.Status
				f.users[address] = user
			}
		}
	case path == "/api/user/setPwd" && r.Method == http.MethodPut:
		for address, user := range f.users {
			if user.ID == body.UserID {
				user.Password = body.Password
				f.users[address] = user
			}
		}
	case path == "/api/user/delete" && r.Method == http.MethodDelete:
		for address, user := range f.users {
			if strconv.FormatInt(user.ID, 10) == r.URL.Query().Get("userIds") {
				delete(f.users, address)
			}
		}
	default:
		write(404, 404, "Unknown endpoint", nil)
		return
	}
	if failure.afterWrite {
		write(failure.status, failure.code, failure.message, nil)
		return
	}
	write(200, 200, "", data)
}

func mailboxTestCustomer(t *testing.T, s *store, email string, verified, paid bool) int64 {
	t.Helper()
	ctx := t.Context()
	var id int64
	err := s.pool.QueryRow(ctx, `INSERT INTO customers(email,password_hash,created_at,email_verified_at)
		VALUES ($1,'unused',$2::double precision,CASE WHEN $3::boolean THEN $2::double precision END) RETURNING id`, email, s.now(), verified).Scan(&id)
	require(t, err)
	if paid {
		_, err = s.pool.Exec(ctx, `INSERT INTO subscriptions(customer_id,plan_code,stripe_subscription_id,status,current_period_end,created_at,updated_at)
			VALUES ($1,'standard',$2,'active',$3,$4,$4)`, id, fmt.Sprintf("sub_fixture_%d", id), s.now()+86400, s.now())
		require(t, err)
	}
	return id
}

func mailboxAdminRequest(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func wantMailboxHTTP(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status || (code != "" && responseCode(t, rec) != code) {
		t.Fatalf("expected HTTP %d %s, got HTTP %d %s", status, code, rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("mailbox response must not be cached")
	}
}

type mailboxCreateResponse struct {
	Mailbox         mailboxRecord `json:"mailbox"`
	InitialPassword string        `json:"initial_password"`
}

func TestMailboxProvisioningEndpoints(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	fake, admin := newFakeCloudMail(t)
	s.mailboxAdmin = admin
	h := newAPIWithMail(s, testAdminToken, "", nil, nil)
	c, customerCookie, _ := billingCustomer(t, s)
	path := fmt.Sprintf("/admin/customers/%d/mailbox", c.ID)
	const requested = `{"local_part":"  Team.Mail-1 "}`
	const address = "team.mail-1@aifree.sg"
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPost, path, requested), 403, "no_entitlement")
	unverified := mailboxTestCustomer(t, s, "unverified@example.com", false, true)
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPost, fmt.Sprintf("/admin/customers/%d/mailbox", unverified), requested), 403, "no_entitlement")
	_, err := s.pool.Exec(ctx, `INSERT INTO subscriptions(customer_id,plan_code,status,current_period_end,created_at,updated_at)
		VALUES($1,'standard','active',$2,$3,$3)`, c.ID, s.now()+3600, s.now())
	require(t, err)
	other := mailboxTestCustomer(t, s, "other@example.com", true, true)
	otherPath := fmt.Sprintf("/admin/customers/%d/mailbox", other)

	for _, part := range []string{"ab", "admin", "noreply", "Support", "-team", "team.", "team..mail", "bad@host", "with_space", strings.Repeat("a", 33)} {
		rec := mailboxAdminRequest(h, http.MethodPost, path, fmt.Sprintf(`{"local_part":%q}`, part))
		wantMailboxHTTP(t, rec, 400, "invalid_local_part")
	}
	wantMailboxHTTP(t, accountRequest(t, h, http.MethodPost, path, requested, customerCookie, ""), 401, "")

	require(t, s.addAdmin(ctx, "operator", testPassword))
	token, csrf, err := s.loginAdmin(ctx, "operator", testPassword, "127.0.0.1")
	require(t, err)
	adminCookie := &http.Cookie{Name: sessionCookie, Value: token}
	wantMailboxHTTP(t, accountRequest(t, h, http.MethodPost, path, requested, adminCookie, ""), 403, "")
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPut, "/admin/settings", `{"mailbox_quota":2}`), 400, "")
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPut, "/admin/settings", `{"mailbox_quota":0}`), 200, "")
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPost, path, requested), 409, "quota_exceeded")
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPut, "/admin/settings", `{"mailbox_quota":1}`), 200, "")
	if fake.count("/api/login") != 0 {
		t.Fatal("ineligible requests contacted the provider")
	}

	fake.failNext("/api/user/add", fakeCloudMailReply{status: 401, code: 401})
	fake.failNext("/api/user/list", fakeCloudMailReply{status: 200, code: 401})
	created := accountRequest(t, h, http.MethodPost, path, requested, adminCookie, csrf)
	wantMailboxHTTP(t, created, 201, "")
	var out mailboxCreateResponse
	require(t, json.Unmarshal(created.Body.Bytes(), &out))
	providerUser, exists := fake.user(address)
	if !exists || len(out.InitialPassword) < 24 || providerUser.Password != out.InitialPassword ||
		out.Mailbox.Address != address || out.Mailbox.Status != "active" || out.Mailbox.SetupPending {
		t.Fatal("provisioned mailbox or one-time password did not match the provider")
	}
	if fake.count("/api/login") != 3 || fake.count("/api/user/add") != 2 || fake.count("/api/user/list") != 2 {
		t.Fatal("expected one fresh login for each HTTP and business-code 401")
	}
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPost, path, requested), 409, "quota_exceeded")
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPost, otherPath, requested), 409, "address_taken")
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodGet, "/admin/mailboxes", ""), 200, "")
	me := accountRequest(t, h, http.MethodGet, "/v1/account/me", "", customerCookie, "")
	var view struct {
		Mailbox *customerMailboxView
	}
	require(t, json.Unmarshal(me.Body.Bytes(), &view))
	if view.Mailbox == nil || *view.Mailbox != (customerMailboxView{Address: address, Status: "active", WebmailURL: "https://mail.aifree.sg"}) {
		t.Fatalf("customer mailbox: %+v", view.Mailbox)
	}
	var row string
	require(t, s.pool.QueryRow(ctx, "SELECT row_to_json(m)::text FROM mailboxes m WHERE id=$1", out.Mailbox.ID).Scan(&row))
	for _, body := range []string{
		row, me.Body.String(),
		mailboxAdminRequest(h, http.MethodGet, "/admin/mailboxes", "").Body.String(),
		mailboxAdminRequest(h, http.MethodGet, "/admin/customers", "").Body.String(),
		mailboxAdminRequest(h, http.MethodGet, "/admin/audit", "").Body.String(),
	} {
		if strings.Contains(body, out.InitialPassword) || strings.Contains(body, "initial_password") {
			t.Fatal("a persisted or read-only response exposed the initial password")
		}
	}
	customers := mailboxAdminRequest(h, http.MethodGet, "/admin/customers?q=billing", "")
	if customers.Code != 200 || !strings.Contains(customers.Body.String(), address) || !strings.Contains(customers.Body.String(), `"mailbox_entitled":true`) {
		t.Fatalf("admin customer list omitted mailbox information: %s", customers.Body)
	}

	changePath := fmt.Sprintf("/admin/mailboxes/%d", out.Mailbox.ID)
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPost, changePath+"/disable", ""), 204, "")
	require(t, s.reconcileMailboxes(ctx))
	if user, _ := fake.user(address); user.Status != 1 {
		t.Fatal("reconciliation reversed a manual disable")
	}
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPost, changePath+"/enable", ""), 204, "")
	if user, _ := fake.user(address); user.Status != 0 {
		t.Fatal("manual enable did not restore provider access")
	}
	wantMailboxHTTP(t, accountRequest(t, h, http.MethodDelete, changePath, `{"confirm":"team.mail-1@aifree.sg"}`, adminCookie, ""), 403, "")
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodDelete, changePath, `{"confirm":"different@aifree.sg"}`), 400, "invalid_confirmation")
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodDelete, changePath, `{"confirm":"team.mail-1@aifree.sg"}`), 204, "")
	if _, exists := fake.user(address); exists {
		t.Fatal("confirmed deletion left the provider mailbox behind")
	}
	me = accountRequest(t, h, http.MethodGet, "/v1/account/me", "", customerCookie, "")
	if !strings.Contains(me.Body.String(), `"mailbox":null`) {
		t.Fatalf("deleted mailbox still visible to customer: %s", me.Body)
	}
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPost, otherPath, requested), 201, "")
}

func TestMailboxProvisioningFailureAndRetry(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	fake, admin := newFakeCloudMail(t)
	s.mailboxAdmin = admin
	h := newAPIWithMail(s, testAdminToken, "", nil, nil)
	id := mailboxTestCustomer(t, s, "retry@example.com", true, true)
	path := fmt.Sprintf("/admin/customers/%d/mailbox", id)

	fake.failNext("/api/user/add", fakeCloudMailReply{status: 401, code: 401})
	fake.failNext("/api/user/add", fakeCloudMailReply{status: 200, code: 401})
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPost, path, `{"local_part":"retry"}`), 502, "mail_unavailable")
	if fake.count("/api/login") != 2 || fake.count("/api/user/add") != 2 {
		t.Fatal("authentication failures exceeded one retry")
	}
	fake.failNext("/api/user/add", fakeCloudMailReply{status: 503, code: 503})
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPost, path, `{"local_part":"retry"}`), 502, "mail_unavailable")
	var rows int
	require(t, s.pool.QueryRow(ctx, "SELECT count(*) FROM mailboxes WHERE customer_id=$1", id).Scan(&rows))
	if rows != 0 {
		t.Fatal("failed upstream create left a reservation")
	}

	require(t, admin.addUser(ctx, "already@aifree.sg", "existing mailbox password"))
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPost, path, `{"local_part":"already"}`), 409, "address_taken")
	if fake.count("/api/user/setPwd") != 0 {
		t.Fatal("the provider's existing address was claimed or reset")
	}

	fake.failNext("/api/user/list", fakeCloudMailReply{status: 503, code: 503})
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPost, path, `{"local_part":"retry"}`), 502, "mail_unavailable")
	first, exists := fake.user("retry@aifree.sg")
	if !exists {
		t.Fatal("the setup fixture did not create an upstream user before the lookup failure")
	}
	before := fake.count("/api/user/add")
	require(t, s.reconcileMailboxes(ctx))
	publicMailbox, err := s.customerMailbox(ctx, id)
	require(t, err)
	if publicMailbox != nil {
		t.Fatal("a mailbox with an undisclosed password should remain hidden")
	}
	result := mailboxAdminRequest(h, http.MethodPost, path, `{"local_part":"retry"}`)
	wantMailboxHTTP(t, result, 201, "")
	var created mailboxCreateResponse
	require(t, json.Unmarshal(result.Body.Bytes(), &created))
	user, _ := fake.user("retry@aifree.sg")
	if created.InitialPassword == "" || user.ID != first.ID || user.Password == first.Password ||
		user.Password != created.InitialPassword || fake.count("/api/user/add") != before || fake.count("/api/user/setPwd") != 1 {
		t.Fatal("retry failed to finish the acknowledged create with a new initial password")
	}
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPost, path, `{"local_part":"retry"}`), 409, "quota_exceeded")

	otherID := mailboxTestCustomer(t, s, "ambiguous@example.com", true, true)
	otherPath := fmt.Sprintf("/admin/customers/%d/mailbox", otherID)
	fake.failNext("/api/user/add", fakeCloudMailReply{status: 503, code: 503, afterWrite: true})
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPost, otherPath, `{"local_part":"unknown"}`), 502, "mail_unavailable")
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPost, otherPath, `{"local_part":"unknown"}`), 409, "address_taken")
	if fake.count("/api/user/setPwd") != 1 {
		t.Fatal("an unacknowledged create must not allow a password reset")
	}
}

func TestMailboxProvisioningWithReceiveOnlyCloudMail(t *testing.T) {
	s := testStore(t)
	fake, admin := newFakeCloudMail(t)
	s.mailboxAdmin = admin
	t.Setenv("CLOUDMAIL_NOREPLY_EMAIL", "")
	t.Setenv("CLOUDMAIL_NOREPLY_PASSWORD", "")
	h := newAPI(s, testAdminToken, "", nil)
	id := mailboxTestCustomer(t, s, "inbound-only@example.com", true, true)
	path := fmt.Sprintf("/admin/customers/%d/mailbox", id)

	fake.failNext("/api/user/add", fakeCloudMailReply{status: 200, code: 403, message: "Permission denied"})
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPost, path, `{"local_part":"inbound"}`), 502, "mail_unavailable")
	if fake.count("/api/login") != 1 || fake.count("/api/user/add") != 1 {
		t.Fatal("a permission failure must not refresh the administrator token or retry the write")
	}

	fake.failNext("/api/user/add", fakeCloudMailReply{status: 200, code: 501, message: "This email has been deleted"})
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPost, path, `{"local_part":"old-alias"}`), 409, "address_taken")
	if fake.count("/api/user/list") != 0 || fake.count("/api/user/setPwd") != 0 {
		t.Fatal("setup must leave a cloud-mail address reserved by a deleted account alone")
	}

	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPost, path, `{"local_part":"inbound"}`), 201, "")
	if _, exists := fake.user("inbound@aifree.sg"); !exists || fake.count("/api/login") != 1 || fake.count("/api/email/send") != 0 {
		t.Fatal("receive-only setup must use the administrator account without requiring an outbound sender")
	}
}

func TestCustomerGeneratesPasswordForOwnActiveMailbox(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	fake, admin := newFakeCloudMail(t)
	s.mailboxAdmin = admin
	h := newAPIWithMail(s, testAdminToken, "", nil, nil)
	customer, cookie, csrf := billingCustomer(t, s)
	_, err := s.pool.Exec(ctx, `INSERT INTO subscriptions(customer_id,plan_code,status,current_period_end,created_at,updated_at)
		VALUES ($1,'standard','active',$2,$3,$3)`, customer.ID, s.now()+3600, s.now())
	require(t, err)
	mailbox, initialPassword, err := s.createMailbox(ctx, customer.ID, "customer-login")
	require(t, err)
	_, otherToken, otherCSRF, _, err := s.registerCustomer(ctx, "another@example.test", testPassword, "", "")
	require(t, err)
	other := &http.Cookie{Name: customerSessionCookie, Value: otherToken}

	const path = "/v1/account/mailbox/password"
	body := fmt.Sprintf(`{"current_password":%q}`, testPassword)
	wantMailboxHTTP(t, accountRequest(t, h, http.MethodPost, path, body, nil, ""), 401, "")
	wantMailboxHTTP(t, accountRequest(t, h, http.MethodPost, path, body, cookie, ""), 403, "csrf")
	wantMailboxHTTP(t, accountRequest(t, h, http.MethodPost, path, body, other, otherCSRF), 409, "mailbox_inactive")
	wantMailboxHTTP(t, accountRequest(t, h, http.MethodPost, path, `{"current_password":"incorrect"}`, cookie, csrf), 401, "invalid_credentials")
	if fake.count("/api/user/setPwd") != 0 {
		t.Fatal("an unauthorized request contacted the mailbox password API")
	}

	fake.failNext("/api/user/setPwd", fakeCloudMailReply{status: 503, code: 503})
	failed := accountRequest(t, h, http.MethodPost, path, body, cookie, csrf)
	wantMailboxHTTP(t, failed, 502, "mail_unavailable")
	if strings.Contains(failed.Body.String(), `"password"`) {
		t.Fatal("a failed password change returned a credential")
	}

	rec := accountRequest(t, h, http.MethodPost, path, body, cookie, csrf)
	wantMailboxHTTP(t, rec, 200, "")
	var generated struct{ Password string }
	require(t, json.Unmarshal(rec.Body.Bytes(), &generated))
	user, exists := fake.user(mailbox.Address)
	if !exists || generated.Password == "" || generated.Password == initialPassword || user.Password != generated.Password {
		t.Fatal("the generated password did not match the customer's mailbox")
	}
	me := accountRequest(t, h, http.MethodGet, "/v1/account/me", "", cookie, "")
	if strings.Contains(me.Body.String(), initialPassword) || strings.Contains(me.Body.String(), generated.Password) {
		t.Fatal("the customer profile exposed a mailbox password")
	}
	_, err = s.checkCustomerCredentials(ctx, customer.Email, testPassword)
	require(t, err)

	// An expired subscription cannot change the mailbox while provider disable is pending.
	_, err = s.pool.Exec(ctx, "UPDATE subscriptions SET status='cancelled' WHERE customer_id=$1", customer.ID)
	require(t, err)
	freshHandler := newAPIWithMail(s, testAdminToken, "", nil, nil)
	wantMailboxHTTP(t, accountRequest(t, freshHandler, http.MethodPost, path, body, cookie, csrf), 409, "mailbox_inactive")
	if fake.count("/api/user/setPwd") != 2 {
		t.Fatal("a customer without entitlement contacted the mailbox password API")
	}
}

func TestCloudMailV360LookupUsesExactAddressAcrossPages(t *testing.T) {
	fake, admin := newFakeCloudMail(t)
	const address = "mailbox@aifree.sg"
	fake.mu.Lock()
	fake.users[address] = fakeCloudMailUser{ID: 1, Email: strings.ToUpper(address)}
	for i := 2; i <= 51; i++ {
		prefixMatch := fmt.Sprintf("%s.other-%d.example", address, i)
		fake.users[prefixMatch] = fakeCloudMailUser{ID: int64(i), Email: prefixMatch}
	}
	fake.mu.Unlock()

	id, err := admin.findUser(t.Context(), address)
	require(t, err)
	if id != 1 || fake.count("/api/user/list") != 2 {
		t.Fatalf("expected the exact address on the second page, got user %d", id)
	}
}

func TestMailboxLifecycleTracksStripeEntitlement(t *testing.T) {
	ctx := t.Context()
	s := testStore(t)
	fake, admin := newFakeCloudMail(t)
	s.mailboxAdmin = admin
	now := time.Unix(2_000_000, 0)
	s.clock = func() time.Time { return now }
	c, _, _ := billingCustomer(t, s)
	_, err := s.pool.Exec(ctx, "UPDATE customers SET stripe_customer_id='cus_test' WHERE id=$1", c.ID)
	require(t, err)
	_, err = s.pool.Exec(ctx, "UPDATE plans SET stripe_price_id='price_standard' WHERE code='standard'")
	require(t, err)
	t.Setenv("STRIPE_WEBHOOK_SECRET", "fixture-signing-secret")
	stripe := &fakeStripe{subscriptions: make(map[string]stripeSubscription)}
	h := billingAPI(s, stripe)
	changeSubscription := func(subscription stripeSubscription, event string) {
		t.Helper()
		stripe.subscriptions[subscription.ID] = subscription
		stripeFixtureEvent(t, h, "customer.subscription.updated", event, fmt.Sprintf(`{"id":%q,"customer":"cus_test"}`, subscription.ID), now, 200)
	}
	subscription := stripeSubscriptionFixture(t, "sub_mail", "cus_test", "price_standard", now)
	changeSubscription(subscription, "evt_mail_paid")
	m, _, err := s.createMailbox(ctx, c.ID, "lifecycle")
	require(t, err)
	address := m.Address

	subscription.Status = "past_due"
	changeSubscription(subscription, "evt_mail_past_due")
	require(t, s.reconcileMailboxes(ctx))
	if user, _ := fake.user(address); user.Status != 0 {
		t.Fatal("past-due subscription lost the mailbox during its grace period")
	}
	subscription.Status, subscription.CancelAtPeriodEnd = "active", true
	changeSubscription(subscription, "evt_mail_cancel_scheduled")
	now = time.Unix(subscription.Items.Data[0].CurrentPeriodEnd, 0)
	require(t, s.expireSubscriptions(ctx))
	fake.failNext("/api/user/setStatus", fakeCloudMailReply{status: 503, code: 503})
	wantStatus(t, s.reconcileMailboxes(ctx), 502)
	view, err := s.customerMailbox(ctx, c.ID)
	require(t, err)
	if view == nil || view.Status != "disabled" {
		t.Fatal("customer view should reflect expired entitlement while the provider retries")
	}
	row, err := getMailbox(ctx, s.pool, s.now(), m.ID)
	require(t, err)
	if row.Status != "active" || !row.StatusSyncPending || row.ReclaimAt != nil {
		t.Fatalf("failed disable recorded the wrong observed or scheduled state: %+v", row)
	}
	require(t, s.reconcileMailboxes(ctx))
	row, err = getMailbox(ctx, s.pool, s.now(), m.ID)
	require(t, err)
	user, exists := fake.user(address)
	if !exists || user.Status != 1 || row.Status != "disabled" || row.ReclaimAt == nil ||
		*row.ReclaimAt != s.now()+mailboxRetention.Seconds() {
		t.Fatalf("expired subscription did not start disabled retention: %+v", row)
	}
	wantMailboxHTTP(t, mailboxAdminRequest(h, http.MethodPost, fmt.Sprintf("/admin/mailboxes/%d/enable", m.ID), ""), 403, "no_entitlement")

	now = now.Add(mailboxRetention - time.Second)
	require(t, s.reconcileMailboxes(ctx))
	if fake.count("/api/user/delete") != 0 {
		t.Fatal("mailbox was reclaimed before the retention deadline")
	}
	renewal := stripeSubscriptionFixture(t, "sub_mail_renewed", "cus_test", "price_standard", now)
	changeSubscription(renewal, "evt_mail_renewed")
	now = now.Add(time.Second)
	require(t, s.reconcileMailboxes(ctx))
	row, err = getMailbox(ctx, s.pool, s.now(), m.ID)
	require(t, err)
	if renewed, _ := fake.user(address); renewed.ID != user.ID || renewed.Password != user.Password ||
		renewed.Status != 0 || row.Status != "active" || row.ReclaimAt != nil {
		t.Fatal("renewal did not restore the original mailbox and cancel reclamation")
	}

	renewal.Status = "canceled"
	changeSubscription(renewal, "evt_mail_ended")
	require(t, s.reconcileMailboxes(ctx))
	now = now.Add(mailboxRetention)
	fake.failNext("/api/user/delete", fakeCloudMailReply{status: 503, code: 503, afterWrite: true})
	wantStatus(t, s.reconcileMailboxes(ctx), 502)
	row, err = getMailbox(ctx, s.pool, s.now(), m.ID)
	require(t, err)
	if row.Status != "deleting" {
		t.Fatalf("failed delete must retain pending reclamation: %+v", row)
	}
	require(t, s.reconcileMailboxes(ctx))
	row, err = getMailbox(ctx, s.pool, s.now(), m.ID)
	require(t, err)
	if _, exists := fake.user(address); exists || row.Status != "deleted" || fake.count("/api/user/delete") != 2 {
		t.Fatal("delete retry did not release the expired address")
	}
}

func TestMailboxConcurrentAddressReservation(t *testing.T) {
	s := testStore(t)
	fake, admin := newFakeCloudMail(t)
	s.mailboxAdmin = admin
	ids := []int64{
		mailboxTestCustomer(t, s, "one@example.com", true, true),
		mailboxTestCustomer(t, s, "two@example.com", true, true),
	}
	h := newAPIWithMail(s, testAdminToken, "", nil, nil)
	results := make(chan *httptest.ResponseRecorder, len(ids))
	start := make(chan struct{})
	for _, id := range ids {
		go func() {
			<-start
			results <- mailboxAdminRequest(h, http.MethodPost, fmt.Sprintf("/admin/customers/%d/mailbox", id), `{"local_part":"shared"}`)
		}()
	}
	close(start)
	expected := map[int]int{201: 1, 409: 1}
	for range ids {
		result := <-results
		expected[result.Code]--
		if result.Code == 409 {
			wantMailboxHTTP(t, result, 409, "address_taken")
		}
	}
	if expected[201] != 0 || expected[409] != 0 || fake.count("/api/user/add") != 1 {
		t.Fatalf("concurrent provisioning did not produce one local reservation and one provider create: %v", expected)
	}
}
