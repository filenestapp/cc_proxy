#!/usr/bin/env python3
"""Control plane HTTP API (v2: multiple exit hosts, password users bound to an exit IP and an entry port).

  server.py init  --db DB [--settings settings.json]
  server.py serve --db DB [--listen 0.0.0.0] [--port 8443] [--tls-cert C --tls-key K]

Environment: CP_ADMIN_TOKEN (admin API) and optionally CP_PROBE_TOKEN (vantage-point probers).
Each exit host has its own agent token, issued when the host is added. Device tokens are issued at sign-in.
All tokens and password hashes are stored hashed.

Routes (all JSON):
  Client app
    POST   /v1/login                            {"username", "password", "device", "platform"?} -> {"token", ...}
    GET    /v1/me                               (device token) user, exit IP, entry host:port
    GET    /v1/config?mode=proxy|domain|app     (device token) sing-box client config; ETag = hash of the config
    POST   /v1/logout                           (device token) revokes this device
  Admin  (Authorization: Bearer $CP_ADMIN_TOKEN)
    GET    /admin/hosts
    POST   /admin/hosts                         {"name", "public_host", "server_name", "handshake_server"?,
                                                 "handshake_port"?, "port_min"?, "port_max"?} -> {"agent_token"}
    PUT    /admin/hosts/{host}                  any of the fields above except name
    DELETE /admin/hosts/{host}                  only when no user is bound to it
    POST   /admin/hosts/{host}/rotate-token     -> {"agent_token"}
    POST   /admin/hosts/{host}/ips              {"ips": [...]}
    GET    /admin/ips[?host=]
    POST   /admin/ips/{ip}/ban                  {"note"?}
    POST   /admin/ips/{ip}/available            end cooldown / lift ban
    GET    /admin/users
    POST   /admin/users                         {"name", "password"?, "mode"?, "max_devices"?}
                                                 -> {"password"} when one was generated (shown once)
    PUT    /admin/users/{user}                  {"max_devices"}
    DELETE /admin/users/{user}
    POST   /admin/users/{user}/password         {"password"?, "revoke_devices"?} -> {"password"} if generated
    POST   /admin/users/{user}/assign           {"ip"?, "port"?, "host"?} -> {"egress_ip", "port", "entry"}
    POST   /admin/users/{user}/reassign         {"ip"?, "port"?, "host"?}  move atomically (no unassigned gap)
    POST   /admin/users/{user}/release
    POST   /admin/users/{user}/devices          {"name"} -> {"token"}  (headless devices; shown once)
    POST   /admin/users/{user}/devices/{dev}/revoke
    PUT    /admin/settings                      {"client_policy"?, "cooldown_seconds"?, "monitor"?, "alerts"?}
    GET    /admin/topology                      everything the dashboard shows, with firing alerts
    GET    /admin/alerts[?all=1]
    POST   /admin/alerts/test
  Agent  (Authorization: Bearer <host agent token>; every route is scoped to that host)
    GET    /agent/server-config                 ETag = hash of the config
    GET    /agent/ips                           text/plain
    GET    /agent/probe-targets
    POST   /agent/report                        heartbeat + egress probe results
  Prober (Authorization: Bearer $CP_PROBE_TOKEN)
    GET    /probe/targets
    POST   /probe/report                        {"vantage", "results"}
  GET /healthz, GET /dashboard

Serve behind TLS (a reverse proxy, or --tls-cert/--tls-key) whenever it is reachable beyond localhost:
passwords, tokens and the generated configs are credentials.
"""
import argparse
import getpass
import hmac
import ipaddress
import json
import os
import re
import secrets
import ssl
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from alerts import Alerter, payload, post_json
from auth import SESSION_TTL, AdminAuth, scrub
from monitor import Monitor
from store import AuthError, Conflict, NotFound, Store, config_etag, render

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "egress"))
import gen  # noqa: E402

LOGIN_WINDOW = 600        # seconds
LOGIN_MAX_FAILURES = 10   # per username and per client address within the window


class HTTPError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class LoginLimiter:
    """Counts failed sign-ins per username and per client address; blocks both after too many."""

    def __init__(self, clock=time.time):
        self.clock = clock
        self.failures = {}
        self.lock = threading.Lock()

    def _recent(self, key):
        cutoff = self.clock() - LOGIN_WINDOW
        hits = [t for t in self.failures.get(key, []) if t > cutoff]
        self.failures[key] = hits
        return hits

    def blocked(self, *keys):
        with self.lock:
            return any(len(self._recent(k)) >= LOGIN_MAX_FAILURES for k in keys)

    def fail(self, *keys):
        with self.lock:
            for k in keys:
                self._recent(k).append(self.clock())


ROUTES = []
COOKIE = "cp_session"


def route(method, pattern, auth):
    def deco(fn):
        ROUTES.append((method, re.compile("^" + pattern + "$"), auth, fn))
        return fn
    return deco


def parse_proxies(values):
    """CIDRs / addresses of reverse proxies whose X-Forwarded-For and X-Forwarded-Proto are believed."""
    return [ipaddress.ip_network(v.strip(), strict=False) for v in values if v and v.strip()]


def make_handler(store, admin_token, probe_token=None, monitor=None, alerter=None, auth=None, secure_cookies=False,
                 trusted_proxies=()):
    monitor = monitor or Monitor(store)
    alerter = alerter or Alerter(store, monitor)
    auth = auth or AdminAuth(store)
    limiter = LoginLimiter()

    class Handler(BaseHTTPRequestHandler):
        server_version = "cc-proxy-cp/0.2"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

        def _dispatch(self, method):
            parsed = urllib.parse.urlsplit(self.path)
            self._status = None
            self._actor = None
            try:
                for m, rx, kind, fn in ROUTES:
                    match = rx.match(parsed.path)
                    if match and m == method:
                        principal = self._auth(kind, method)
                        body = self._body() if method in ("POST", "PUT") else {}
                        query = dict(urllib.parse.parse_qsl(parsed.query))
                        fn(self, store, principal, body, query, *[urllib.parse.unquote(g) for g in match.groups()])
                        if kind == "admin" and method != "GET" and self._status and self._status < 400:
                            # Every successful admin change, with secrets scrubbed from the request body.
                            self.auth.audit(self._actor, "%s %s" % (method, fn.__name__),
                                            urllib.parse.unquote(parsed.path),
                                            json.dumps(scrub(body), ensure_ascii=False) if body else "",
                                            self.client_ip())
                        return
                raise HTTPError(404, "no route")
            except HTTPError as e:
                self._json(e.status, {"error": str(e)})
            except AuthError as e:
                self._json(401, {"error": str(e)})
            except NotFound as e:
                self._json(404, {"error": "not found: %s" % e})
            except (Conflict, gen.InventoryError) as e:
                self._json(409, {"error": str(e)})
            except (ValueError, TypeError) as e:
                self._json(400, {"error": str(e)})

        def _trusted(self, addr):
            try:
                a = ipaddress.ip_address(addr)
            except ValueError:
                return False
            return any(a in net for net in trusted_proxies)

        def client_ip(self):
            """The requesting client's address (review finding CC-08). Forwarding headers count only when the TCP
            peer is a trusted proxy; then the rightmost X-Forwarded-For entry that is not itself a trusted proxy is
            the client. A direct request cannot choose its identity with a header."""
            peer = self.client_address[0]
            if not self._trusted(peer):
                return peer
            hops = [h.strip() for h in ",".join(self.headers.get_all("X-Forwarded-For") or []).split(",") if h.strip()]
            for hop in reversed(hops):
                if not self._trusted(hop):
                    try:
                        return str(ipaddress.ip_address(hop))
                    except ValueError:
                        return peer  # garbage in the header: fall back to the proxy itself
            return peer

        def via_https(self):
            return secure_cookies or (self._trusted(self.client_address[0])
                                      and self.headers.get("X-Forwarded-Proto", "") == "https")

        def _cookie(self):
            for part in self.headers.get("Cookie", "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == COOKIE:
                    return v
            return ""

        def _auth(self, kind, method="GET"):
            if kind is None:
                return None
            header = self.headers.get("Authorization", "")
            token = header[7:] if header.startswith("Bearer ") else ""
            if kind == "admin":
                if admin_token and token and hmac.compare_digest(token, admin_token):
                    self._actor = "api-token"
                    return "api-token"
                session = self.auth.session(self._cookie())
                if session:
                    # Cookies ride along on cross-site requests; changes also need the CSRF token.
                    if method != "GET" and not self.auth.csrf_ok(session, self.headers.get("X-CSRF-Token", "")):
                        raise HTTPError(403, "missing or wrong CSRF token")
                    self._actor = session["admin"]
                    return session
            if kind == "probe" and probe_token and hmac.compare_digest(token, probe_token):
                return "probe"
            if kind == "agent" and token:
                host = store.host_for_agent_token(token)
                if host:
                    return host
            if kind == "device" and token:
                device = store.device_for_token(token)
                if device:
                    return device
            raise HTTPError(401, "unauthorized")

        def _body(self):
            length = int(self.headers.get("Content-Length") or 0)
            if not length:
                return {}
            if length > 1 << 20:
                raise HTTPError(413, "body too large")
            try:
                data = json.loads(self.rfile.read(length))
            except json.JSONDecodeError:
                raise HTTPError(400, "body is not JSON")
            if not isinstance(data, dict):
                raise HTTPError(400, "body must be a JSON object")
            return data

        def _send(self, status, payload_bytes, ctype, etag=None, headers=()):
            self._status = status
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload_bytes)))
            self.send_header("X-Content-Type-Options", "nosniff")
            if ctype.startswith("text/html"):
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Content-Security-Policy",
                                 "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                                 "style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Cache-Control", "no-store")
            if etag is not None:
                self.send_header("ETag", '"%s"' % etag)
            self.end_headers()
            self.wfile.write(payload_bytes)

        def _json(self, status, obj, etag=None, headers=()):
            self._send(status, (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode(), "application/json",
                       etag, headers)

        def session_cookie(self, value, max_age):
            secure = self.via_https()
            return ("Set-Cookie", "%s=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d%s"
                    % (COOKIE, value, max_age, "; Secure" if secure else ""))

        def versioned(self, render_fn):
            """Serve render_fn() with a hash of its content as ETag; 304 when the caller already has it.

            Hashing the rendered config (not the global version) means admin changes that do not touch this
            caller's config, such as adding an IP to the pool, cause no download and no reload."""
            obj = render_fn()
            body, etag = render(obj), config_etag(obj)
            if self.headers.get("If-None-Match", "").strip('"') == etag:
                self.send_response(304)
                self.send_header("ETag", '"%s"' % etag)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._send(200, body, "application/json", etag)

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def do_PUT(self):
            self._dispatch("PUT")

        def do_DELETE(self):
            self._dispatch("DELETE")

    # Set after the class body: a class body cannot read an enclosing name it also assigns.
    Handler.mon = monitor
    Handler.alerter = alerter
    Handler.auth = auth
    Handler.limiter = limiter
    return Handler


def need(body, key):
    if key not in body:
        raise HTTPError(400, "missing field %r" % key)
    return body[key]


def new_password():
    return secrets.token_urlsafe(12)


# -- client app --------------------------------------------------------------------------------------------

@route("POST", "/v1/login", None)
def login(h, store, _p, body, _q):
    username, password = str(need(body, "username")), str(need(body, "password"))
    device = str(need(body, "device"))
    keys = ("user:" + username, "addr:" + h.client_ip())
    if h.limiter.blocked(*keys):
        raise HTTPError(429, "too many failed sign-ins; try again later")
    try:
        token, summary = store.login(username, password, device, body.get("platform", ""))
    except AuthError:
        h.limiter.fail(*keys)
        raise
    h._json(200, dict(summary, token=token, device=device))


@route("GET", "/v1/me", "device")
def me(h, store, device, _b, _q):
    h._json(200, dict(store.user_summary(device["user_name"]), device=device["name"]))


@route("GET", "/v1/config", "device")
def device_config(h, store, device, _b, query):
    mode = query.get("mode", "app")
    if mode not in gen.CLIENT_MODES:
        raise HTTPError(400, "mode must be one of %s" % ", ".join(gen.CLIENT_MODES))
    h.versioned(lambda: store.client_config(device, mode))


@route("POST", "/v1/logout", "device")
def logout(h, store, device, _b, _q):
    store.revoke_device(device["user_name"], device["name"])
    h._json(200, {"signed_out": device["name"]})


# -- admin console session ---------------------------------------------------------------------------------

@route("POST", "/admin/session", None)
def admin_login(h, store, _p, body, _q):
    name, password = str(need(body, "username")), str(need(body, "password"))
    keys = ("admin:" + name, "admin-addr:" + h.client_ip())
    if h.limiter.blocked(*keys):
        raise HTTPError(429, "too many failed sign-ins; try again later")
    result = h.auth.login(name, password, h.client_ip())
    if not result:
        h.limiter.fail(*keys)
        h.auth.audit(name, "admin sign-in failed", "", "", h.client_ip())
        raise HTTPError(401, "wrong username or password")
    token, csrf = result
    h.auth.audit(name, "admin sign-in", "", "", h.client_ip())
    h._json(200, {"admin": name, "csrf": csrf}, headers=[h.session_cookie(token, SESSION_TTL)])


@route("GET", "/admin/session", "admin")
def admin_whoami(h, store, principal, _b, _q):
    if principal == "api-token":
        h._json(200, {"admin": "api-token", "csrf": None})
    else:
        h._json(200, {"admin": principal["admin"], "csrf": principal["csrf"], "expires_at": principal["expires_at"]})


@route("DELETE", "/admin/session", None)
def admin_logout(h, store, _p, _b, _q):
    token = h._cookie()
    session = h.auth.session(token)
    if session:
        h.auth.logout(token)
        h.auth.audit(session["admin"], "admin sign-out", "", "", h.client_ip())
    h._json(200, {"signed_out": True}, headers=[h.session_cookie("", 0)])


@route("GET", "/admin/admins", "admin")
def admins_list(h, store, _p, _b, _q):
    h._json(200, h.auth.list())


@route("POST", "/admin/admins", "admin")
def admins_add(h, store, _p, body, _q):
    generated = "password" not in body
    password = body.get("password") or new_password()
    h.auth.add(need(body, "name"), password)
    h._json(201, dict({"name": body["name"]}, **({"password": password} if generated else {})))


@route("POST", "/admin/admins/([^/]+)/password", "admin")
def admins_password(h, store, _p, body, _q, name):
    generated = "password" not in body
    password = body.get("password") or new_password()
    h.auth.set_password(name, password)
    h._json(200, dict({"name": name}, **({"password": password} if generated else {})))


@route("DELETE", "/admin/admins/([^/]+)", "admin")
def admins_delete(h, store, _p, _b, _q, name):
    h.auth.delete(name)
    h._json(200, {"deleted": name})


@route("GET", "/admin/audit", "admin")
def audit_list(h, store, _p, _b, query):
    h._json(200, h.auth.audit_log(query.get("limit", 100), query.get("before"), query.get("actor")))


@route("GET", "/admin/settings", "admin")
def settings_get(h, store, _p, _b, _q):
    h._json(200, store.settings())


# -- admin: hosts and IPs ----------------------------------------------------------------------------------

HOST_FIELDS = ("public_host", "server_name", "handshake_server", "handshake_port", "port_min", "port_max",
               "block_private", "block_cidrs")


@route("GET", "/admin/hosts", "admin")
def hosts_list(h, store, _p, _b, _q):
    h._json(200, store.list_hosts())


@route("POST", "/admin/hosts", "admin")
def hosts_add(h, store, _p, body, _q):
    kwargs = {k: body[k] for k in HOST_FIELDS if k in body}
    token = store.add_host(need(body, "name"), **kwargs)
    h._json(201, {"host": body["name"], "agent_token": token})


@route("PUT", "/admin/hosts/([^/]+)", "admin")
def hosts_update(h, store, _p, body, _q, name):
    store.update_host(name, **body)
    h._json(200, {"host": name})


@route("DELETE", "/admin/hosts/([^/]+)", "admin")
def hosts_delete(h, store, _p, _b, _q, name):
    store.delete_host(name)
    h._json(200, {"deleted": name})


@route("POST", "/admin/hosts/([^/]+)/rotate-token", "admin")
def hosts_rotate(h, store, _p, _b, _q, name):
    h._json(200, {"host": name, "agent_token": store.rotate_agent_token(name)})


@route("POST", "/admin/hosts/([^/]+)/ips", "admin")
def ips_add(h, store, _p, body, _q, host):
    ips = need(body, "ips")
    if not isinstance(ips, list):
        raise HTTPError(400, "ips must be a list")
    h._json(201, {"added": store.add_ips(host, ips)})


@route("GET", "/admin/ips", "admin")
def ips_list(h, store, _p, _b, query):
    h._json(200, store.list_ips(query.get("host")))


@route("POST", "/admin/ips/([^/]+)/ban", "admin")
def ips_ban(h, store, _p, body, _q, ip):
    h._json(200, {"banned": ip, "released_users": store.ban_ip(ip, body.get("note", ""))})


@route("DELETE", "/admin/ips/([^/]+)", "admin")
def ips_delete(h, store, _p, _b, _q, ip):
    store.delete_ip(ip)
    h._json(200, {"deleted": ip})


@route("POST", "/admin/ips/([^/]+)/available", "admin")
def ips_available(h, store, _p, _b, _q, ip):
    store.make_available(ip)
    h._json(200, {"available": ip})


# -- admin: users and devices ------------------------------------------------------------------------------

@route("GET", "/admin/users", "admin")
def users_list(h, store, _p, _b, _q):
    h._json(200, store.list_users())


@route("POST", "/admin/users", "admin")
def users_add(h, store, _p, body, _q):
    generated = "password" not in body
    password = body.get("password") or new_password()
    store.add_user(need(body, "name"), password, body.get("mode", "exclusive"), body.get("max_devices", 5))
    h._json(201, dict({"name": body["name"]}, **({"password": password} if generated else {})))


@route("PUT", "/admin/users/([^/]+)", "admin")
def users_update(h, store, _p, body, _q, name):
    store.set_max_devices(name, need(body, "max_devices"))
    h._json(200, {"name": name})


@route("DELETE", "/admin/users/([^/]+)", "admin")
def users_delete(h, store, _p, _b, _q, name):
    store.delete_user(name)
    h._json(200, {"deleted": name})


@route("POST", "/admin/users/([^/]+)/password", "admin")
def users_password(h, store, _p, body, _q, name):
    generated = "password" not in body
    password = body.get("password") or new_password()
    store.set_password(name, password, bool(body.get("revoke_devices")))
    h._json(200, dict({"name": name}, **({"password": password} if generated else {})))


@route("POST", "/admin/users/([^/]+)/assign", "admin")
def users_assign(h, store, _p, body, _q, name):
    ip, port = store.assign(name, body.get("ip"), body.get("port"), body.get("host"))
    h._json(200, dict(store.user_summary(name), port=port))


@route("POST", "/admin/users/([^/]+)/reassign", "admin")
def users_reassign(h, store, _p, body, _q, name):
    """Move a bound user to another IP / port atomically: clients never see an unassigned user."""
    ip, port = store.reassign(name, body.get("ip"), body.get("port"), body.get("host"))
    h._json(200, dict(store.user_summary(name), port=port))


@route("POST", "/admin/users/([^/]+)/release", "admin")
def users_release(h, store, _p, _b, _q, name):
    h._json(200, {"user": name, "released": store.release(name)})


@route("POST", "/admin/users/([^/]+)/devices", "admin")
def devices_add(h, store, _p, body, _q, user):
    token = store.add_device(user, need(body, "name"), body.get("platform", ""))
    h._json(201, {"user": user, "device": body["name"], "token": token})


@route("POST", "/admin/users/([^/]+)/devices/([^/]+)/revoke", "admin")
def devices_revoke(h, store, _p, _b, _q, user, device):
    store.revoke_device(user, device)
    h._json(200, {"revoked": "%s/%s" % (user, device)})


@route("PUT", "/admin/settings", "admin")
def settings_put(h, store, _p, body, _q):
    store.configure(body.get("client_policy"), body.get("cooldown_seconds"), body.get("monitor"), body.get("alerts"))
    h._json(200, {"version": store.version()})


# -- admin: monitoring -------------------------------------------------------------------------------------

@route("GET", "/admin/topology", "admin")
def topology(h, store, _p, _b, _q):
    h._json(200, dict(h.mon.topology(), alerts=h.alerter.list()))


@route("GET", "/admin/alerts", "admin")
def alerts_list(h, store, _p, _b, query):
    h._json(200, h.alerter.list(include_resolved=query.get("all") == "1"))


@route("POST", "/admin/alerts/test", "admin")
def alerts_test(h, store, _p, _b, _q):
    """Send a test notification to every configured webhook; report each result."""
    sample = {"rule": "test", "subject": "test", "severity": "warning", "summary": "Test alert",
              "started_at": None, "fired_at": None, "resolved_at": None}
    results = []
    for hook in h.alerter.settings()["webhooks"]:
        try:
            post_json(hook["url"], payload(hook.get("format", "generic"), sample, "firing"))
            results.append({"url": hook["url"], "ok": True})
        except (OSError, ValueError) as e:
            results.append({"url": hook["url"], "ok": False, "error": str(e)})
    h._json(200, {"webhooks": results})


# -- agents and probers ------------------------------------------------------------------------------------

@route("GET", "/agent/server-config", "agent")
def agent_config(h, store, host, _b, _q):
    h.versioned(lambda: store.server_config(host))


@route("GET", "/agent/ips", "agent")
def agent_ips(h, store, host, _b, _q):
    ips = "".join(e["ip"] + "\n" for e in store.list_ips(host) if e["status"] != "banned")
    h._send(200, ips.encode(), "text/plain")


@route("GET", "/agent/probe-targets", "agent")
def agent_probe_targets(h, store, host, _b, _q):
    h._json(200, {"egress_targets": h.mon.egress_targets()})


@route("POST", "/agent/report", "agent")
def agent_report(h, store, host, body, _q):
    """Heartbeat plus egress probe results: {config_etag, singbox_running, probes: [...]}.
    The agent is identified by its token; any "agent" field in the body is ignored."""
    h.mon.heartbeat(host, body.get("config_etag"), body.get("singbox_running"), body.get("apply_error"))
    own = {e["ip"] for e in store.list_ips(host)}
    probes = body.get("probes", [])
    if not isinstance(probes, list) or any(not isinstance(p, dict) or p.get("subject") not in own for p in probes):
        raise HTTPError(400, "probes must be results for this host's egress IPs")
    h._json(200, {"recorded": h.mon.record("egress", host, probes)})


@route("GET", "/probe/targets", "probe")
def probe_targets(h, store, _p, _b, _q):
    h._json(200, {"entries": h.mon.entries()})


@route("POST", "/probe/report", "probe")
def probe_report(h, store, _p, body, _q):
    """Entry latency from a vantage point: {vantage, results: [{subject, target, ok, latency_ms}]}"""
    h._json(200, {"recorded": h.mon.record("entry", need(body, "vantage"), need(body, "results"))})


@route("GET", "/healthz", None)
def healthz(h, store, _p, _b, _q):
    h._json(200, {"ok": True, "version": store.version()})


CONSOLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "console.html")


@route("GET", "/(?:console|dashboard)?/?", None)
def console(h, store, _p, _b, _q):
    """The admin console: a static page that holds no data; it signs in and then calls the /admin API."""
    with open(CONSOLE, "rb") as f:
        page = f.read()
    h._send(200, page, "text/html; charset=utf-8", headers=[("Cache-Control", "no-store")])


# -- entry points ------------------------------------------------------------------------------------------

def build_server(store, listen, port, admin_token, probe_token=None, monitor=None, alerter=None, auth=None,
                 secure_cookies=False, trusted_proxies=()):
    return ThreadingHTTPServer((listen, port), make_handler(store, admin_token, probe_token, monitor, alerter, auth,
                                                            secure_cookies, trusted_proxies))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init")
    i.add_argument("--db", required=True)
    i.add_argument("--settings", help="JSON with optional client_policy, cooldown_seconds, monitor, alerts")
    i.add_argument("--admin", help="create this console admin; the generated password is printed once")
    a = sub.add_parser("admin-add", help="create a console admin (password from CP_ADMIN_PASSWORD or a prompt)")
    a.add_argument("--db", required=True)
    a.add_argument("name")
    s = sub.add_parser("serve")
    s.add_argument("--db", required=True)
    s.add_argument("--listen", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8443)
    s.add_argument("--tls-cert")
    s.add_argument("--tls-key")
    s.add_argument("--trusted-proxy", action="append", default=[],
                   help="reverse proxy address or CIDR whose X-Forwarded-For / -Proto are believed (repeatable); "
                        "also CP_TRUSTED_PROXIES, comma-separated")
    args = p.parse_args(argv)

    store = Store(args.db)
    if args.cmd == "init":
        cfg = json.load(open(args.settings)) if args.settings else {}
        store.configure(cfg.get("client_policy", {}), cfg.get("cooldown_seconds"), cfg.get("monitor"),
                        cfg.get("alerts"))
        print("initialised %s" % args.db)
        if args.admin:
            password = new_password()
            AdminAuth(store).add(args.admin, password)
            print("console admin %s, password %s (shown once)" % (args.admin, password))
        return 0
    if args.cmd == "admin-add":
        password = os.environ.get("CP_ADMIN_PASSWORD") or getpass.getpass("password for %s: " % args.name)
        AdminAuth(store).add(args.name, password)
        print("console admin %s created" % args.name)
        return 0

    admin = os.environ.get("CP_ADMIN_TOKEN")
    auth = AdminAuth(store)
    if not admin and not auth.count():
        sys.exit("no way to administer this control plane: set CP_ADMIN_TOKEN or create an admin "
                 "(server.py admin-add --db DB NAME)")
    monitor = Monitor(store)
    alerter = Alerter(store, monitor)
    httpd = build_server(store, args.listen, args.port, admin, os.environ.get("CP_PROBE_TOKEN"), monitor, alerter,
                         auth, secure_cookies=bool(args.tls_cert),
                         trusted_proxies=parse_proxies(args.trusted_proxy + os.environ.get("CP_TRUSTED_PROXIES", "").split(",")))
    if args.tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    alerter.start()
    print("control plane on %s:%d (version %d)" % (args.listen, args.port, store.version()), flush=True)
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
