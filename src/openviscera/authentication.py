"""Local MFA, credential recovery and signed session metadata.

TOTP is RFC 6238 compatible, not phishing-resistant. Server key compromise is
outside this boundary. No secret, challenge, password or recovery code is logged.
"""
import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
import time
from contextlib import contextmanager
from urllib.parse import quote, urlencode

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .domain import RuleError, canonical, normalized, require

AUTH_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS login_challenges (
       hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
       expires INTEGER NOT NULL, epoch TEXT NOT NULL, failures INTEGER NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS session_context (
       hash TEXT PRIMARY KEY REFERENCES sessions(hash) ON DELETE CASCADE,
       created_at INTEGER NOT NULL, method TEXT NOT NULL, epoch TEXT NOT NULL)""",
]
WINDOW = 900
MAX_FAILURES = 8
CHALLENGE_TTL = 300
SETUP_TTL = 600
MAX_SESSIONS = 20


def token_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def totp(secret, counter, digits=6, algorithm="sha1"):
    """HOTP moving counter = floor(unix_time / 30); expose digits for RFC vectors."""
    raw = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(raw, struct.pack(">Q", counter), algorithm).digest()
    offset = digest[-1] & 15
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
    return str(value % (10 ** digits)).zfill(digits)


def recovery_hash(uid, code):
    return token_hash("openviscera-recovery-v1:" + uid + ":" + code.replace("-", "").upper())


def new_recovery_codes(uid):
    # 128 random bits per code. Only hashes persist; plaintext is returned once.
    values = [secrets.token_hex(16).upper() for _ in range(10)]
    codes = ["-".join(v[i:i + 8] for i in range(0, 32, 8)) for v in values]
    return codes, [recovery_hash(uid, v) for v in codes]


def install_auth_schema(store, c):
    columns = {row[1] for row in c.execute("PRAGMA table_info(users)")}
    if "security" not in columns:
        c.execute("ALTER TABLE users ADD COLUMN security TEXT NOT NULL DEFAULT '{}'")
        # Caller verifies old identities before migration. Only additive identity
        # metadata is re-sealed; historical event actors and signatures are untouched.
        for row in c.execute("SELECT * FROM users").fetchall():
            store._seal_identity(c, "user", row["id"], row)
    for statement in AUTH_SCHEMA:
        c.execute(statement)


class AuthenticationMixin:
    def _security(self, row):
        state = json.loads(row["security"])
        require(isinstance(state, dict), "Invalid account security state", 503)
        return state

    def _save_security(self, c, uid, state):
        c.execute("UPDATE users SET security=? WHERE id=?", (canonical(state).decode(), uid))
        self._seal_identity(c, "user", uid, c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone())

    def _cipher(self):
        seed = self.key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                      serialization.NoEncryption())
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                   info=b"openviscera-mfa-secret-v1").derive(seed)
        return AESGCM(key)

    def _encrypt_secret(self, uid, secret):
        nonce = secrets.token_bytes(12)
        data = self._cipher().encrypt(nonce, secret.encode(), ("mfa:" + uid).encode())
        return base64.b64encode(nonce + data).decode()

    def _decrypt_secret(self, uid, encrypted):
        try:
            data = base64.b64decode(encrypted, validate=True)
            return self._cipher().decrypt(data[:12], data[12:], ("mfa:" + uid).encode()).decode()
        except (InvalidTag, ValueError) as exc:
            raise RuleError("MFA secret integrity failure", 503) from exc

    def _limited(self, c, bucket, maximum=MAX_FAILURES):
        count = c.execute("SELECT COUNT(*) FROM attempts WHERE bucket=? AND at>=?",
                          (bucket, int(time.time()) - WINDOW)).fetchone()[0]
        require(count < maximum, "Too many failed authentication attempts; retry after 15 minutes", 429)

    def _consume_factor(self, uid, state, code, pending=False):
        """Caller persists successful consumption within the same write transaction."""
        if pending:
            target = state.get("pending", {})
            if target.get("expires", 0) <= int(time.time()):
                return None
        else:
            if not state.get("enabled"):
                return None
            target = state
        if re.fullmatch(r"[0-9]{6}", code):
            secret = self._decrypt_secret(uid, target["secret"])
            counter = int(time.time()) // 30
            # Never accept a counter twice, across logins or sensitive actions.
            for candidate in [counter, counter - 1, counter + 1]:
                if candidate > target.get("last_counter", -1) and hmac.compare_digest(totp(secret, candidate), code):
                    target["last_counter"] = candidate
                    return "totp"
        elif not pending and re.fullmatch(r"[0-9A-Fa-f-]{32,39}", code):
            wanted = recovery_hash(uid, code)
            for digest in state.get("recovery_hashes", []):
                if hmac.compare_digest(digest, wanted):
                    state["recovery_hashes"].remove(digest)
                    return "recovery"
        return None

    def _drop_challenges(self, c, uid):
        c.execute("DELETE FROM identity_seals WHERE kind='challenge' AND id IN "
                  "(SELECT hash FROM login_challenges WHERE user_id=?)", (uid,))
        c.execute("DELETE FROM login_challenges WHERE user_id=?", (uid,))

    def _invalidate_auth(self, c, uid):
        c.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        self._drop_challenges(c, uid)

    def _new_session(self, c, row, method):
        from .store import user_public
        now = int(time.time())
        c.execute("DELETE FROM sessions WHERE expires<=?", (now,))
        existing = c.execute("SELECT s.hash FROM sessions s JOIN session_context m ON s.hash=m.hash "
                             "WHERE s.user_id=? ORDER BY m.created_at,s.hash", (row["id"],)).fetchall()
        for old in existing[:max(0, len(existing) - MAX_SESSIONS + 1)]:
            c.execute("DELETE FROM sessions WHERE hash=?", (old[0],))
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        digest = token_hash(token)
        c.execute("INSERT INTO sessions VALUES (?,?,?,?)", (digest, row["id"], csrf, now + 8 * 3600))
        c.execute("INSERT INTO session_context VALUES (?,?,?,?)",
                  (digest, now, method, self._security(row).get("epoch", "initial")))
        self._seal_identity(c, "session", digest, c.execute("SELECT * FROM sessions WHERE hash=?", (digest,)).fetchone())
        self._seal_identity(c, "session_context", digest, c.execute("SELECT * FROM session_context WHERE hash=?", (digest,)).fetchone())
        self._admin_event(c, row["id"], "login", {"user_id": row["id"], "method": method})
        return token, csrf, user_public(row)

    def authenticate_password(self, username, password, ip):
        from .store import password_matches
        now = int(time.time())
        buckets = ["ip:" + ip, "user:" + normalized(username)]
        failed = False
        with self.transaction() as c:
            c.execute("DELETE FROM attempts WHERE at<?", (now - WINDOW,))
            for bucket, maximum in zip(buckets, [30, MAX_FAILURES]):
                self._limited(c, bucket, maximum)
            row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if row:
                self._check_identity(c, "user", row["id"], row)
            good = password_matches(password, row["password"] if row else self.dummy_password)
            if not row or not row["active"] or not good:
                c.executemany("INSERT INTO attempts VALUES (?,?)", [(b, now) for b in buckets])
                failed = True
            else:
                c.execute("DELETE FROM attempts WHERE bucket=?", (buckets[1],))
                security = self._security(row)
                if security.get("enabled"):
                    self._limited(c, "mfa:" + row["id"])
                    # One outstanding password-authenticated challenge per user.
                    self._drop_challenges(c, row["id"])
                    challenge = secrets.token_urlsafe(32)
                    digest = token_hash(challenge)
                    c.execute("INSERT INTO login_challenges VALUES (?,?,?,?,0)",
                              (digest, row["id"], now + CHALLENGE_TTL, security["epoch"]))
                    self._seal_identity(c, "challenge", digest, c.execute("SELECT * FROM login_challenges WHERE hash=?", (digest,)).fetchone())
                    result = {"mfa_required": True, "challenge": challenge, "expires_in": CHALLENGE_TTL}
                else:
                    result = self._new_session(c, row, "password")
        require(not failed, "Invalid credentials", 401)
        return result

    def complete_mfa_login(self, challenge, code, ip):
        now = int(time.time())
        failed = False
        with self.transaction() as c:
            self._limited(c, "mfa-ip:" + ip, 30)
            record = c.execute("SELECT * FROM login_challenges WHERE hash=?", (token_hash(challenge),)).fetchone()
            if not record:
                c.execute("INSERT INTO attempts VALUES (?,?)", ("mfa-ip:" + ip, now))
                failed = True
            else:
                self._check_identity(c, "challenge", record["hash"], record)
                row = self._user(c, record["user_id"])
                state = self._security(row)
                self._limited(c, "mfa:" + row["id"])
                valid = (record["expires"] > now and record["failures"] < 5 and row["active"] and
                         state.get("enabled") and state.get("epoch") == record["epoch"])
                method = self._consume_factor(row["id"], state, code) if valid else None
                if not method:
                    failed = True
                    c.executemany("INSERT INTO attempts VALUES (?,?)", [("mfa:" + row["id"], now), ("mfa-ip:" + ip, now)])
                    c.execute("UPDATE login_challenges SET failures=failures+1 WHERE hash=?", (record["hash"],))
                    self._seal_identity(c, "challenge", record["hash"], c.execute("SELECT * FROM login_challenges WHERE hash=?", (record["hash"],)).fetchone())
                else:
                    self._save_security(c, row["id"], state)
                    self._drop_challenges(c, row["id"])
                    c.execute("DELETE FROM attempts WHERE bucket=?", ("mfa:" + row["id"],))
                    result = self._new_session(c, self._user(c, row["id"]), method)
        require(not failed, "Invalid or expired authentication code/challenge", 401)
        return result

    def _validate_session_security(self, c, session, user):
        context = c.execute("SELECT * FROM session_context WHERE hash=?", (session["hash"],)).fetchone()
        require(context is not None, "Session security metadata unavailable; sign in again", 401)
        self._check_identity(c, "session_context", session["hash"], context)
        state = self._security(user)
        require(context["epoch"] == state.get("epoch", "initial"), "Credential version changed; sign in again", 401)
        require(not state.get("enabled") or context["method"] in {"totp", "recovery"}, "Multi-factor sign-in required", 401)
        return context

    def account_requirements(self, actor, require_mfa=False):
        with self.transaction(False) as c:
            state = self._security(self._user(c, actor["id"]))
            return {"enrollment_required": bool(require_mfa and not state.get("enabled")),
                    "password_change_required": bool(state.get("password_change_required"))}

    def account_security(self, actor, current_token=None):
        with self.transaction(False) as c:
            row = self._user(c, actor["id"])
            state = self._security(row)
            result = {"mfa_enabled": bool(state.get("enabled")),
                      "password_change_required": bool(state.get("password_change_required")),
                      "recovery_codes_remaining": len(state.get("recovery_hashes", [])), "sessions": []}
            for session in c.execute("SELECT * FROM sessions WHERE user_id=? AND expires>? ORDER BY expires DESC",
                                     (actor["id"], int(time.time()))):
                self._check_identity(c, "session", session["hash"], session)
                context = self._validate_session_security(c, session, row)
                result["sessions"].append({"id": session["hash"], "created_at": context["created_at"],
                                           "expires_at": session["expires"], "method": context["method"],
                                           "current": current_token is not None and session["hash"] == token_hash(current_token)})
            return result

    @contextmanager
    def _reauthenticated(self, actor, password, code="", factor=None):
        """Persist failed-attempt counters even though no privileged action is committed."""
        from .store import password_matches
        with self.transaction() as c:
            row = self._user(c, actor["id"])
            require(row["active"] and row["org_id"] == actor["org_id"], "Account unavailable", 403)
            state = self._security(row)
            bucket = "account-security:" + row["id"]
            self._limited(c, bucket)
            good = password_matches(password, row["password"])
            if good and (factor == "pending" or state.get("enabled")):
                good = bool(self._consume_factor(row["id"], state, code, pending=factor == "pending"))
            if not good:
                c.execute("INSERT INTO attempts VALUES (?,?)", (bucket, int(time.time())))
            else:
                c.execute("DELETE FROM attempts WHERE bucket=?", (bucket,))
                yield c, row, state
        require(good, "Current password or authentication code is incorrect, expired or already used", 403)

    def begin_mfa_setup(self, actor, password):
        with self._reauthenticated(actor, password) as (c, row, state):
            require(not state.get("enabled"), "MFA already enabled; disable with a current factor before replacing it")
            secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
            state["pending"] = {"secret": self._encrypt_secret(row["id"], secret), "expires": int(time.time()) + SETUP_TTL}
            self._save_security(c, row["id"], state)
            self._admin_event(c, row["id"], "mfa_setup_started", {"user_id": row["id"]})
            # Opaque ID avoids putting a real person's name into third-party authenticators.
            label = "OpenViscera:" + row["id"]
            uri = "otpauth://totp/" + quote(label, safe="") + "?" + urlencode(
                {"secret": secret, "issuer": "OpenViscera", "algorithm": "SHA1", "digits": 6, "period": 30})
            return {"secret": secret, "uri": uri, "expires_in": SETUP_TTL}

    def confirm_mfa_setup(self, actor, password, code):
        with self._reauthenticated(actor, password, code, factor="pending") as (c, row, state):
            require(not state.get("enabled"), "MFA already enabled")
            pending = state.pop("pending")
            codes, digests = new_recovery_codes(row["id"])
            state.update(enabled=True, secret=pending["secret"], last_counter=pending["last_counter"],
                         recovery_hashes=digests, epoch=secrets.token_hex(16))
            self._save_security(c, row["id"], state)
            self._invalidate_auth(c, row["id"])
            self._admin_event(c, row["id"], "mfa_enabled", {"user_id": row["id"], "sessions_revoked": True})
            return {"recovery_codes": codes, "reauthentication_required": True}

    def manage_mfa(self, actor, password, code, operation):
        require(operation in {"disable", "recovery-codes"}, "Unknown security operation", 422)
        with self._reauthenticated(actor, password, code) as (c, row, state):
            require(state.get("enabled"), "MFA is not enabled")
            if operation == "disable":
                state = {"epoch": secrets.token_hex(16),
                         "password_change_required": state.get("password_change_required", False)}
                result = {"reauthentication_required": True}
            else:
                codes, digests = new_recovery_codes(row["id"])
                state.update(recovery_hashes=digests, epoch=secrets.token_hex(16))
                result = {"recovery_codes": codes, "reauthentication_required": True}
            self._save_security(c, row["id"], state)
            self._invalidate_auth(c, row["id"])
            self._admin_event(c, row["id"], "mfa_" + operation.replace("-", "_"), {"user_id": row["id"], "sessions_revoked": True})
            return result

    def change_password(self, actor, current_password, new_password, code=""):
        from .store import password_hash
        require(14 <= len(new_password) <= 1024 and current_password != new_password,
                "Choose a different password between 14 and 1024 characters", 422)
        with self._reauthenticated(actor, current_password, code) as (c, row, state):
            c.execute("UPDATE users SET password=? WHERE id=?", (password_hash(new_password), row["id"]))
            state.update(epoch=secrets.token_hex(16), password_change_required=False)
            state.pop("pending", None)
            self._save_security(c, row["id"], state)
            self._invalidate_auth(c, row["id"])
            self._admin_event(c, row["id"], "password_changed", {"user_id": row["id"], "sessions_revoked": True})

    def revoke_account_sessions(self, actor, current_token, session_id=None, others=False):
        require(others != (session_id is not None), "Choose one session or all other sessions", 422)
        with self.transaction() as c:
            row = self._user(c, actor["id"])
            require(row["active"], "Account unavailable", 403)
            if others:
                c.execute("DELETE FROM sessions WHERE user_id=? AND hash<>?", (row["id"], token_hash(current_token)))
            else:
                require(c.execute("SELECT 1 FROM sessions WHERE user_id=? AND hash=?", (row["id"], session_id)).fetchone(),
                        "Session not found", 404)
                c.execute("DELETE FROM sessions WHERE user_id=? AND hash=?", (row["id"], session_id))
            self._admin_event(c, row["id"], "sessions_revoked", {"user_id": row["id"], "others": others})
        return {"reauthentication_required": not others and session_id == token_hash(current_token)}

    def recover_account(self, username, new_password, reason, reset_mfa=False):
        """Trusted LOCAL CLI only; deliberately no HTTP recovery endpoint."""
        from .store import password_hash
        require(14 <= len(new_password) <= 1024 and 10 <= len(reason.strip()) <= 1000,
                "Recovery requires a 14+ character password and a 10-1000 character reason", 422)
        with self.transaction() as c:
            row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            require(row is not None, "Account not found", 404)
            self._check_identity(c, "user", row["id"], row)
            state = {} if reset_mfa else self._security(row)
            state.pop("pending", None)
            state.update(epoch=secrets.token_hex(16), password_change_required=True)
            c.execute("UPDATE users SET password=? WHERE id=?", (password_hash(new_password), row["id"]))
            self._save_security(c, row["id"], state)
            self._invalidate_auth(c, row["id"])
            c.execute("DELETE FROM attempts WHERE bucket IN (?,?,?)", ("user:" + normalized(row["username"]),
                      "mfa:" + row["id"], "account-security:" + row["id"]))
            self._admin_event(c, "local-recovery", "account_recovered", {"user_id": row["id"],
                              "reset_mfa": reset_mfa, "reason": reason.strip(), "password_change_required": True})
        return {"recovered": True, "password_change_required": True}
