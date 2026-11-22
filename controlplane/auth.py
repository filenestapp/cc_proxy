"""Admin accounts, browser sessions and the audit log for the admin console.

* Admins sign in with a username and password (PBKDF2, like users). A session is a random token in an HttpOnly,
  SameSite=Strict cookie; only its SHA-256 is stored. Sessions last SESSION_TTL and are bound to a CSRF token that
  every state-changing request must echo in the X-CSRF-Token header.
* CP_ADMIN_TOKEN (Bearer) still works for cpctl and scripts; it is recorded as actor "api-token".
* Every successful admin change is written to the audit log (who, what, when, from where). Secrets are never
  logged: request fields named like password/token/secret/key are dropped.

None of this is configuration, so nothing here bumps the config version.
"""
import hmac
import secrets

from store import Conflict, NotFound, check_name, check_password, check_password_policy, hash_password, hash_token

SESSION_TTL = 12 * 3600
AUDIT_KEEP = 180 * 24 * 3600
SENSITIVE = ("password", "token", "secret", "private", "key")

SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
  name TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  created_at REAL NOT NULL,
  last_login REAL
);
CREATE TABLE IF NOT EXISTS admin_sessions (
  token_hash TEXT PRIMARY KEY,
  admin TEXT NOT NULL REFERENCES admins(name) ON DELETE CASCADE,
  csrf TEXT NOT NULL,
  created_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  address TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY,
  at REAL NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  address TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_at ON audit(at);
"""

# Same dummy hash trick as user sign-in: a missing account costs the same time as a wrong password.
_DUMMY = hash_password("x", salt=b"\1" * 16)


def scrub(value):
    """Copy of a request body with secrets removed, for the audit log."""
    if isinstance(value, dict):
        return {k: ("***" if any(s in k.lower() for s in SENSITIVE) else scrub(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    return value


class AdminAuth:
    def __init__(self, store):
        self.store = store
        self.db = store.db
        with store.lock:
            self.db.executescript(SCHEMA)

    def _now(self):
        return self.store.clock()

    # -- accounts ----------------------------------------------------------------------------------------

    def count(self):
        with self.store.lock:
            return self.db.execute("SELECT COUNT(*) FROM admins").fetchone()[0]

    def add(self, name, password):
        check_name("admin", name)
        check_password_policy(password)
        pw = hash_password(password)
        with self.store.lock:
            if self.db.execute("SELECT 1 FROM admins WHERE name = ?", (name,)).fetchone():
                raise Conflict("admin %s exists" % name)
            self.db.execute("INSERT INTO admins(name, password_hash, created_at) VALUES(?, ?, ?)",
                            (name, pw, self._now()))

    def set_password(self, name, password):
        check_password_policy(password)
        pw = hash_password(password)
        with self.store.lock:
            cur = self.db.execute("UPDATE admins SET password_hash = ? WHERE name = ?", (pw, name))
            if not cur.rowcount:
                raise NotFound("admin %s" % name)
            # Other sessions of this admin end; whoever changed it signs in again with the new password.
            self.db.execute("DELETE FROM admin_sessions WHERE admin = ?", (name,))

    def delete(self, name):
        with self.store.lock:
            if not self.db.execute("SELECT 1 FROM admins WHERE name = ?", (name,)).fetchone():
                raise NotFound("admin %s" % name)
            if self.count() <= 1:
                raise Conflict("cannot delete the last admin")
            self.db.execute("DELETE FROM admin_sessions WHERE admin = ?", (name,))
            self.db.execute("DELETE FROM admins WHERE name = ?", (name,))

    def list(self):
        with self.store.lock:
            now = self._now()
            return [{
                "name": r["name"], "created_at": r["created_at"], "last_login": r["last_login"],
                "sessions": self.db.execute("SELECT COUNT(*) FROM admin_sessions WHERE admin = ? AND expires_at > ?",
                                            (r["name"], now)).fetchone()[0],
            } for r in self.db.execute("SELECT * FROM admins ORDER BY name")]

    # -- sessions ----------------------------------------------------------------------------------------

    def login(self, name, password, address=""):
        """Returns (session_token, csrf_token) or None for wrong credentials."""
        with self.store.lock:
            row = self.db.execute("SELECT * FROM admins WHERE name = ?", (name,)).fetchone()
        if not check_password(password or "", row["password_hash"] if row else _DUMMY) or not row:
            return None
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        now = self._now()
        with self.store.lock:
            self.db.execute("DELETE FROM admin_sessions WHERE expires_at <= ?", (now,))
            self.db.execute("INSERT INTO admin_sessions(token_hash, admin, csrf, created_at, expires_at, address) "
                            "VALUES(?, ?, ?, ?, ?, ?)", (hash_token(token), name, csrf, now, now + SESSION_TTL, address))
            self.db.execute("UPDATE admins SET last_login = ? WHERE name = ?", (now, name))
        return token, csrf

    def session(self, token):
        """The live session row for a cookie value, or None."""
        if not token:
            return None
        with self.store.lock:
            return self.db.execute("SELECT * FROM admin_sessions WHERE token_hash = ? AND expires_at > ?",
                                   (hash_token(token), self._now())).fetchone()

    @staticmethod
    def csrf_ok(session, header):
        return bool(header) and hmac.compare_digest(session["csrf"], header)

    def logout(self, token):
        with self.store.lock:
            self.db.execute("DELETE FROM admin_sessions WHERE token_hash = ?", (hash_token(token),))

    # -- audit -------------------------------------------------------------------------------------------

    def audit(self, actor, action, target="", detail="", address=""):
        now = self._now()
        with self.store.lock:
            self.db.execute("INSERT INTO audit(at, actor, action, target, detail, address) VALUES(?, ?, ?, ?, ?, ?)",
                            (now, actor, action, target, detail[:2000], address))
            self.db.execute("DELETE FROM audit WHERE at < ?", (now - AUDIT_KEEP,))

    def audit_log(self, limit=100, before=None, actor=None):
        q, args = "SELECT * FROM audit WHERE 1=1", []
        if before:
            q += " AND id < ?"
            args.append(int(before))
        if actor:
            q += " AND actor = ?"
            args.append(actor)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(max(1, min(int(limit), 500)))
        with self.store.lock:
            return [dict(r) for r in self.db.execute(q, args)]
