"""SQLite transactions, signed event ledger, tenant boundaries and credential storage."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager, closing
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from .domain import (RuleError, apply, canonical, digest, item, normalized, now_iso, require)
from .models import CaseCreate, MODELS, ROLES, UserCreate, LabCreate

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE users (id TEXT PRIMARY KEY, org_id TEXT NOT NULL, username TEXT UNIQUE COLLATE NOCASE,
 display_name TEXT NOT NULL, role TEXT NOT NULL, lab_id TEXT, password TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE labs (id TEXT PRIMARY KEY, org_id TEXT NOT NULL, name TEXT NOT NULL, name_norm TEXT NOT NULL,
 turnaround_days INTEGER NOT NULL, UNIQUE(org_id,name_norm));
CREATE TABLE cases (id TEXT PRIMARY KEY, org_id TEXT NOT NULL, ref_norm TEXT NOT NULL,
 state TEXT NOT NULL, UNIQUE(org_id,ref_norm));
CREATE TABLE events (case_id TEXT NOT NULL REFERENCES cases(id), seq INTEGER NOT NULL, body TEXT NOT NULL,
 hash TEXT NOT NULL, signature TEXT NOT NULL, PRIMARY KEY(case_id,seq));
CREATE TABLE containers (org_id TEXT NOT NULL, name TEXT NOT NULL, case_id TEXT NOT NULL REFERENCES cases(id),
 specimen_id TEXT NOT NULL, PRIMARY KEY(org_id,name));
CREATE TABLE commands (org_id TEXT NOT NULL, actor_id TEXT NOT NULL, key TEXT NOT NULL,
 payload_hash TEXT NOT NULL, case_id TEXT NOT NULL, event_id TEXT NOT NULL, version INTEGER NOT NULL,
 PRIMARY KEY(org_id,actor_id,key));
CREATE TABLE blobs (org_id TEXT NOT NULL, hash TEXT NOT NULL, content BLOB NOT NULL, PRIMARY KEY(org_id,hash));
CREATE TABLE sessions (hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), csrf TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE identity_seals (kind TEXT NOT NULL, id TEXT NOT NULL, signature TEXT NOT NULL, PRIMARY KEY(kind,id));
CREATE TABLE attempts (bucket TEXT NOT NULL, at INTEGER NOT NULL);
CREATE INDEX attempts_time ON attempts(bucket,at);
CREATE INDEX cases_org ON cases(org_id,ref_norm);
CREATE TABLE administrative_events (seq INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL,
 hash TEXT NOT NULL, signature TEXT NOT NULL);
CREATE TRIGGER no_event_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'append-only ledger'); END;
CREATE TRIGGER no_event_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'append-only ledger'); END;
CREATE TRIGGER no_admin_update BEFORE UPDATE ON administrative_events BEGIN SELECT RAISE(ABORT,'append-only ledger'); END;
CREATE TRIGGER no_admin_delete BEFORE DELETE ON administrative_events BEGIN SELECT RAISE(ABORT,'append-only ledger'); END;
"""


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    value = hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=1, maxmem=64 * 1024 * 1024)
    return salt.hex() + ":" + value.hex()


def password_matches(password, encoded):
    try:
        salt, value = encoded.split(":")
        return hmac.compare_digest(password_hash(password, bytes.fromhex(salt)).split(":")[1], value)
    except (ValueError, TypeError):
        return False


def user_public(row):
    return {k: row[k] for k in ("id", "org_id", "username", "display_name", "role", "lab_id", "active")}


def validate(model, data):
    try:
        return model.model_validate(data).model_dump(mode="json")
    except ValidationError as exc:
        # Do not echo request contents (which may contain passwords or evidence).
        errors = [".".join(str(x) for x in e["loc"]) + ": " + e["msg"] for e in exc.errors()]
        raise RuleError("; ".join(errors), 422) from exc


def verify_events(events, public_key, state=None, replay=False):
    previous, projection = "0" * 64, None
    require(bool(events), "Empty evidence ledger")
    for seq, event in enumerate(events, 1):
        body = event["body"]
        require(body["schema"] == 1 and body["seq"] == seq and body["previous_hash"] == previous,
                "Evidence ledger sequence/chain mismatch")
        require(event["hash"] == digest(body), "Evidence event hash mismatch")
        try:
            public_key.verify(base64.b64decode(event["signature"], validate=True), canonical(body))
        except (InvalidSignature, ValueError) as exc:
            raise RuleError("Evidence signature verification failed") from exc
        if seq == 1:
            require(body["action"] == "create", "Ledger must begin with case creation")
            case_id, org_id = body["case_id"], body["actor"]["org_id"]
        require(body["case_id"] == case_id and body["actor"]["org_id"] == org_id,
                "Cross-case or cross-organization event")
        if replay:
            projection = apply(projection, body["action"], body["data"], body["actor"],
                               body["recorded_at"], body["event_id"], body["case_id"])
            require(digest(projection) == body["after_digest"], "Replayed projection does not match event")
        previous = event["hash"]
    if state is not None:
        require(state["version"] == len(events) and digest(state) == events[-1]["body"]["after_digest"],
                "Stored case projection differs from the signed ledger")
    return previous


class Store:
    def __init__(self, data_dir):
        self.path = Path(data_dir)
        self.db = self.path / "openviscera.sqlite3"
        require(self.db.is_file() and (self.path / "signing.key").is_file(),
                "Data directory is not initialized; run openviscera init", 503)
        self.key = Ed25519PrivateKey.from_private_bytes((self.path / "signing.key").read_bytes())
        self.public_key = self.key.public_key()
        with self.transaction(False) as c:
            meta = dict(c.execute("SELECT name,value FROM meta"))
            require(meta.get("schema") == "1", "Unsupported database schema", 503)
            require(meta.get("public_key") == self.public_b64, "Signing key does not match this database", 503)
        self.dummy_password = password_hash(secrets.token_urlsafe(24))

    @property
    def public_b64(self):
        return base64.b64encode(self.public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

    @classmethod
    def initialize(cls, data_dir):
        path = Path(data_dir)
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        require(not (path / "openviscera.sqlite3").exists() and not (path / "signing.key").exists(),
                "Refusing to overwrite an existing database or signing key")
        key = Ed25519PrivateKey.generate()
        with (path / "signing.key").open("xb") as f:
            f.write(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                      serialization.NoEncryption()))
        os.chmod(path / "signing.key", 0o600)
        public = base64.b64encode(key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        (path / "public-key.txt").write_text(public + "\n")
        with closing(sqlite3.connect(path / "openviscera.sqlite3")) as c, c:
            c.executescript(SCHEMA)
            c.executemany("INSERT INTO meta VALUES (?,?)", [("schema", "1"), ("public_key", public)])
        os.chmod(path / "openviscera.sqlite3", 0o600)
        return cls(path)

    @contextmanager
    def transaction(self, write=True):
        c = sqlite3.connect(self.db, timeout=15, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("PRAGMA synchronous=FULL")
        c.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            yield c
            c.commit()
        except sqlite3.IntegrityError as exc:
            c.rollback()
            raise RuleError("Duplicate identifier or integrity constraint violation") from exc
        except BaseException:
            c.rollback()
            raise
        finally:
            c.close()

    def _admin_event(self, c, actor_id, action, target):
        last = c.execute("SELECT hash FROM administrative_events ORDER BY seq DESC LIMIT 1").fetchone()
        body = {"actor_id": actor_id, "action": action, "target": target, "at": now_iso(),
                "previous_hash": last["hash"] if last else "0" * 64}
        c.execute("INSERT INTO administrative_events(body,hash,signature) VALUES (?,?,?)",
                  (canonical(body).decode(), digest(body), base64.b64encode(self.key.sign(canonical(body))).decode()))

    def _seal_identity(self, c, kind, identifier, record):
        message = canonical({"kind": kind, "id": identifier, "record": dict(record)})
        signature = base64.b64encode(self.key.sign(message)).decode()
        c.execute("INSERT OR REPLACE INTO identity_seals VALUES (?,?,?)", (kind, identifier, signature))

    def _check_identity(self, c, kind, identifier, record):
        require(record is not None, "Identity not found", 404)
        seal = c.execute("SELECT signature FROM identity_seals WHERE kind=? AND id=?", (kind, identifier)).fetchone()
        require(seal is not None, "Identity store integrity failure", 503)
        try:
            self.public_key.verify(base64.b64decode(seal[0], validate=True),
                                   canonical({"kind": kind, "id": identifier, "record": dict(record)}))
        except (InvalidSignature, ValueError) as exc:
            raise RuleError("Identity store integrity failure", 503) from exc
        return record

    def _user(self, c, identifier):
        row = c.execute("SELECT * FROM users WHERE id=?", (identifier,)).fetchone()
        return self._check_identity(c, "user", identifier, row)

    def _lab(self, c, identifier, org_id):
        row = c.execute("SELECT * FROM labs WHERE id=? AND org_id=?", (identifier, org_id)).fetchone()
        return self._check_identity(c, "lab", identifier, row)

    def add_lab(self, org_id, data, actor_id="bootstrap"):
        values = validate(LabCreate, data)
        lab = {"id": uuid.uuid4().hex, "org_id": org_id, **values}
        with self.transaction() as c:
            c.execute("INSERT INTO labs VALUES (?,?,?,?,?)",
                      (lab["id"], org_id, lab["name"], normalized(lab["name"]), lab["turnaround_days"]))
            self._seal_identity(c, "lab", lab["id"], c.execute("SELECT * FROM labs WHERE id=?", (lab["id"],)).fetchone())
            self._admin_event(c, actor_id, "lab_created", lab)
        return lab

    def add_user(self, org_id, data, actor_id="bootstrap"):
        v = validate(UserCreate, data)
        uid = uuid.uuid4().hex
        hashed = password_hash(v.pop("password"))
        with self.transaction() as c:
            require((v["role"] == "lab") == bool(v["lab_id"]), "Laboratory identity is required only for lab users", 422)
            if v["lab_id"]:
                self._lab(c, v["lab_id"], org_id)
            c.execute("INSERT INTO users VALUES (?,?,?,?,?,?,?,1)",
                      (uid, org_id, v["username"], v["display_name"], v["role"], v["lab_id"], hashed))
            record = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
            self._seal_identity(c, "user", uid, record)
            result = user_public(record)
            self._admin_event(c, actor_id, "user_created", result)
        return result

    def set_active(self, actor, uid, active):
        require(actor["role"] == "admin" and uid != actor["id"], "Cannot disable yourself or act without admin role", 403)
        with self.transaction() as c:
            require(c.execute("SELECT 1 FROM users WHERE id=? AND org_id=?", (uid, actor["org_id"])).fetchone(),
                    "Unknown user", 404)
            self._user(c, uid)
            c.execute("UPDATE users SET active=? WHERE id=?", (int(active), uid))
            self._seal_identity(c, "user", uid, c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone())
            c.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
            self._admin_event(c, actor["id"], "user_status_changed", {"id": uid, "active": active})

    def login(self, username, password, ip):
        now = int(time.time())
        buckets = ["ip:" + ip, "user:" + normalized(username)]
        with self.transaction() as c:
            c.execute("DELETE FROM attempts WHERE at<?", (now - 900,))
            for bucket, maximum in zip(buckets, [30, 8]):
                count = c.execute("SELECT COUNT(*) FROM attempts WHERE bucket=?", (bucket,)).fetchone()[0]
                require(count < maximum, "Too many failed logins; retry after the 15-minute window", 429)
            row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if row:
                self._check_identity(c, "user", row["id"], row)
            good = password_matches(password, row["password"] if row else self.dummy_password)
            if not row or not row["active"] or not good:
                c.executemany("INSERT INTO attempts VALUES (?,?)", [(b, now) for b in buckets])
                failed = True
            else:
                failed = False
                token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                c.execute("DELETE FROM sessions WHERE expires<=?", (now,))
                c.execute("DELETE FROM attempts WHERE bucket=?", (buckets[1],))
                c.execute("INSERT INTO sessions VALUES (?,?,?,?)",
                          (hashlib.sha256(token.encode()).hexdigest(), row["id"], csrf, now + 8 * 3600))
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                self._seal_identity(c, "session", token_hash, c.execute("SELECT * FROM sessions WHERE hash=?", (token_hash,)).fetchone())
                self._admin_event(c, row["id"], "login", {"user_id": row["id"]})
                user = user_public(row)
        require(not failed, "Invalid credentials", 401)
        return token, csrf, user

    def session(self, token):
        require(bool(token), "Authentication required", 401)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self.transaction(False) as c:
            session = c.execute("SELECT * FROM sessions WHERE hash=? AND expires>?", (token_hash, int(time.time()))).fetchone()
            require(session is not None, "Session expired or invalid", 401)
            self._check_identity(c, "session", token_hash, session)
            user = self._user(c, session["user_id"])
            require(user["active"], "Account disabled", 401)
            return user_public(user), session["csrf"]

    def logout(self, token):
        with self.transaction() as c:
            c.execute("DELETE FROM sessions WHERE hash=?", (hashlib.sha256(token.encode()).hexdigest(),))

    def catalog(self, actor):
        with self.transaction(False) as c:
            users = [user_public(self._check_identity(c, "user", r["id"], r)) for r in c.execute("SELECT * FROM users WHERE org_id=? ORDER BY display_name",
                                                      (actor["org_id"],))]
            labs = [dict(self._check_identity(c, "lab", r["id"], r)) for r in c.execute("SELECT * FROM labs WHERE org_id=? ORDER BY name", (actor["org_id"],))]
        return {"users": users, "labs": labs}

    def _events(self, c, case_id):
        return [{"body": json.loads(r["body"]), "hash": r["hash"], "signature": r["signature"]}
                for r in c.execute("SELECT * FROM events WHERE case_id=? ORDER BY seq", (case_id,))]

    def _load(self, c, actor, case_id):
        row = c.execute("SELECT state FROM cases WHERE id=? AND org_id=?", (case_id, actor["org_id"])).fetchone()
        require(row is not None, "Case not found", 404)
        s = json.loads(row["state"])
        require(s["org_id"] == actor["org_id"] and s["id"] == case_id, "Case identity projection mismatch")
        if actor["role"] == "lab":
            require(any(r["lab_id"] == actor["lab_id"] for r in s["requests"]), "Case not found", 404)
        verify_events(self._events(c, case_id), self.public_key, s)
        return s

    def visible(self, actor, state):
        if actor["role"] != "lab":
            return state
        s = json.loads(json.dumps(state))
        s["authority"] = "Restricted to department staff"
        s["requests"] = [r for r in s["requests"] if r["lab_id"] == actor["lab_id"]]
        specimens = {r["specimen_id"] for r in s["requests"]}
        requests = {r["id"] for r in s["requests"]}
        s["specimens"] = [x for x in s["specimens"] if x["id"] in specimens]
        s["transfers"] = [t for t in s["transfers"] if t["specimen_id"] in specimens and
                          (t["sender_id"] == actor["id"] or t["recipient_id"] == actor["id"])]
        s["reports"] = [r for r in s["reports"] if r["request_id"] in requests]
        report_files = {r["attachment_id"] for r in s["reports"]}
        s["attachments"] = [a for a in s["attachments"] if a["id"] in report_files or
                            (a["uploaded_by"] == actor["id"] and a["specimen_id"] in specimens)]
        s["opinions"], s["notes"], s["followups"] = [], [], []
        return s

    def get_case(self, actor, case_id):
        with self.transaction(False) as c:
            return self.visible(actor, self._load(c, actor, case_id))

    def list_cases(self, actor, search="", limit=200, offset=0):
        require(1 <= limit <= 200 and offset >= 0, "Invalid pagination", 422)
        with self.transaction(False) as c:
            rows = c.execute("SELECT state FROM cases WHERE org_id=? AND ref_norm LIKE ? ORDER BY ref_norm",
                             (actor["org_id"], "%" + normalized(search) + "%")).fetchall()
            states = [json.loads(r["state"]) for r in rows]
            if actor["role"] == "lab":
                states = [s for s in states if any(r["lab_id"] == actor["lab_id"] for r in s["requests"])]
            result = [self.visible(actor, self._load(c, actor, s["id"])) for s in states[offset:offset + limit]]
        return {"items": result, "total": len(states), "limit": limit, "offset": offset}

    def all_cases(self, actor):
        # Bounded queue projections are returned by the HTTP layer, not entire evidence documents.
        states, offset = [], 0
        while True:
            page = self.list_cases(actor, limit=200, offset=offset)
            states.extend(page["items"])
            offset += len(page["items"])
            if offset >= page["total"]:
                return states

    def _append(self, c, actor, case_id, old, action, data):
        eid, recorded = uuid.uuid4().hex, now_iso()
        state = apply(old, action, data, actor, recorded, eid, case_id)
        last = c.execute("SELECT hash FROM events WHERE case_id=? ORDER BY seq DESC LIMIT 1", (case_id,)).fetchone()
        body = {"schema": 1, "case_id": case_id, "seq": state["version"], "event_id": eid, "actor": actor,
                "recorded_at": recorded, "action": action, "data": data,
                "previous_hash": last["hash"] if last else "0" * 64, "after_digest": digest(state)}
        c.execute("INSERT INTO events VALUES (?,?,?,?,?)", (case_id, state["version"], canonical(body).decode(),
                  digest(body), base64.b64encode(self.key.sign(canonical(body))).decode()))
        c.execute("UPDATE cases SET state=? WHERE id=?", (canonical(state).decode(), case_id))
        if action == "collect":
            c.execute("INSERT INTO containers VALUES (?,?,?,?)",
                      (actor["org_id"], normalized(data["container_id"]), case_id, eid))
        return state, eid

    def _replay(self, c, actor, key, payload):
        require(isinstance(key, str) and 8 <= len(key) <= 100, "Idempotency-Key (8-100 characters) is required", 422)
        old = c.execute("SELECT * FROM commands WHERE org_id=? AND actor_id=? AND key=?",
                        (actor["org_id"], actor["id"], key)).fetchone()
        if old:
            require(old["payload_hash"] == digest(payload), "Idempotency key reused with different input")
            return {"case": self.visible(actor, self._load(c, actor, old["case_id"])),
                    "event_id": old["event_id"], "command_version": old["version"], "replayed": True}

    def _remember(self, c, actor, key, payload, state, eid):
        c.execute("INSERT INTO commands VALUES (?,?,?,?,?,?,?)",
                  (actor["org_id"], actor["id"], key, digest(payload), state["id"], eid, state["version"]))
        return {"case": self.visible(actor, state), "event_id": eid,
                "command_version": state["version"], "replayed": False}

    def create_case(self, actor, data, key):
        require(actor["role"] in {"examiner", "coordinator"}, "Case creation requires examiner or coordinator role", 403)
        data = validate(CaseCreate, data)
        payload = {"action": "create", "data": data}
        with self.transaction() as c:
            replay = self._replay(c, actor, key, payload)
            if replay:
                return replay
            require(c.execute("SELECT 1 FROM users WHERE id=? AND org_id=? AND role='examiner' AND active=1",
                              (data["examiner_id"], actor["org_id"])).fetchone(), "Select an active department examiner", 422)
            self._user(c, data["examiner_id"])
            require(actor["role"] != "examiner" or actor["id"] == data["examiner_id"],
                    "Examiner can create only their assigned cases", 403)
            cid = uuid.uuid4().hex
            c.execute("INSERT INTO cases VALUES (?,?,?,?)", (cid, actor["org_id"], normalized(data["case_ref"]), "{}"))
            state, eid = self._append(c, actor, cid, None, "create", data)
            return self._remember(c, actor, key, payload, state, eid)

    def command(self, actor, case_id, action, data, expected_version, key, blob=None):
        require(action in MODELS, "Unknown command", 422)
        require(actor["role"] in ROLES[action], "Role does not permit this action", 403)
        require(action != "attach" or blob is not None, "Use the attachment upload endpoint", 422)
        data = validate(MODELS[action], data)
        payload = {"case_id": case_id, "action": action, "data": data, "expected_version": expected_version}
        with self.transaction() as c:
            replay = self._replay(c, actor, key, payload)
            if replay:
                return replay
            s = self._load(c, actor, case_id)
            require(s["version"] == expected_version, "Case changed; refresh before submitting (stale version)")
            if actor["role"] == "examiner" and action in {"collect", "request", "review", "draft", "issue"}:
                require(s["examiner_id"] == actor["id"], "Only the assigned examiner may perform this action", 403)
            if action == "request" or (action == "handover" and data["recipient_lab_id"]):
                lab_id = data.get("lab_id") or data["recipient_lab_id"]
                self._lab(c, lab_id, actor["org_id"])
            if action == "handover" and data["recipient_id"]:
                recipient = c.execute("SELECT * FROM users WHERE id=? AND org_id=? AND active=1",
                                      (data["recipient_id"], actor["org_id"])).fetchone()
                require(recipient and recipient["role"] in ROLES["acknowledge"], "Recipient cannot acknowledge custody", 422)
                self._check_identity(c, "user", recipient["id"], recipient)
                if recipient["role"] == "lab":
                    require(any(r["lab_id"] == recipient["lab_id"] and r["specimen_id"] == data["specimen_id"]
                                for r in s["requests"]), "No examination request for this laboratory")
            if action == "handover" and data["recipient_lab_id"]:
                require(any(r["lab_id"] == data["recipient_lab_id"] and r["specimen_id"] == data["specimen_id"]
                            for r in s["requests"]), "No examination request for this laboratory")
            if actor["role"] == "lab":
                if action == "report":
                    item(self.visible(actor, s), "attachments", data["attachment_id"])
                    require(item(s, "requests", data["request_id"])["lab_id"] == actor["lab_id"],
                            "Report is not assigned to your laboratory", 403)
                if action in {"attach", "seal", "handover"}:
                    require(any(r["specimen_id"] == data["specimen_id"] and r["lab_id"] == actor["lab_id"]
                                for r in s["requests"]), "Specimen is not assigned to your laboratory", 403)
            if blob is not None:
                require(hashlib.sha256(blob).hexdigest() == data["sha256"] and len(blob) == data["size"],
                        "Attachment content hash/length mismatch", 422)
                c.execute("INSERT OR IGNORE INTO blobs VALUES (?,?,?)", (actor["org_id"], data["sha256"], blob))
            state, eid = self._append(c, actor, case_id, s, action, data)
            return self._remember(c, actor, key, payload, state, eid)

    def attachment(self, actor, case_id, attachment_id):
        with self.transaction(False) as c:
            s = self.visible(actor, self._load(c, actor, case_id))
            a = item(s, "attachments", attachment_id)
            row = c.execute("SELECT content FROM blobs WHERE org_id=? AND hash=?", (actor["org_id"], a["sha256"])).fetchone()
            require(row is not None and hashlib.sha256(row[0]).hexdigest() == a["sha256"], "Attachment is missing or modified")
            return a, row[0]

    def evidence(self, actor, case_id):
        require(actor["role"] != "lab", "Laboratory accounts cannot export departmental evidence", 403)
        with self.transaction(False) as c:
            state = self._load(c, actor, case_id)
            events = self._events(c, case_id)
            head = verify_events(events, self.public_key, state, replay=True)
            files = {}
            for a in state["attachments"]:
                row = c.execute("SELECT content FROM blobs WHERE org_id=? AND hash=?", (actor["org_id"], a["sha256"])).fetchone()
                require(row is not None and hashlib.sha256(row[0]).hexdigest() == a["sha256"], "Missing or modified evidence file")
                files["files/" + a["sha256"]] = row[0]
        return state, events, files, head
