"""Atomic dispatch batches, password lifecycle and signed, bounded HTTP access auditing."""
import base64
import hashlib
import json
import sqlite3
import uuid

from cryptography.exceptions import InvalidSignature
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from .domain import apply, canonical, digest, now_iso, require

# A separate chain per department; anonymous requests cannot pollute another tenant's chain.
AUDIT_SCHEMA = [
    """CREATE TABLE access_events (org_id TEXT NOT NULL, seq INTEGER NOT NULL, body TEXT NOT NULL,
       hash TEXT NOT NULL, signature TEXT NOT NULL, PRIMARY KEY(org_id,seq))""",
    """CREATE TRIGGER no_access_update BEFORE UPDATE ON access_events
       BEGIN SELECT RAISE(ABORT,'append-only access ledger'); END""",
    """CREATE TRIGGER no_access_delete BEFORE DELETE ON access_events
       BEGIN SELECT RAISE(ABORT,'append-only access ledger'); END""",
]


def verify_access_events(events, public_key, org_id, start=1, previous="0" * 64):
    for seq, event in enumerate(events, start):
        body = event["body"]
        require(body["format"] == "openviscera-access-v1" and body["org_id"] == org_id and
                body["seq"] == seq and body["previous_hash"] == previous, "Access audit chain/sequence mismatch")
        require(digest(body) == event["hash"], "Access audit hash mismatch")
        try:
            public_key.verify(base64.b64decode(event["signature"], validate=True), canonical(body))
        except (InvalidSignature, ValueError) as exc:
            from .domain import RuleError
            raise RuleError("Access audit signature mismatch") from exc
        previous = event["hash"]
    return previous


class GovernanceMixin:
    def record_access(self, actor, method, route, status, case_ids, request_id):
        """Append before releasing the HTTP response. No bodies, cookies, passwords or queries."""
        org_id = actor["org_id"] if actor else "__unauthenticated__"
        with self.transaction() as c:
            last = c.execute("SELECT * FROM access_events WHERE org_id=? ORDER BY seq DESC LIMIT 1", (org_id,)).fetchone()
            if last:
                # Refuse to build on an altered tail; full chain checks are available via audit.
                previous_body = json.loads(last["body"])
                verify_access_events([{"body": previous_body, "hash": last["hash"], "signature": last["signature"]}],
                                     self.public_key, org_id, last["seq"], previous_body["previous_hash"])
            body = {"format": "openviscera-access-v1", "org_id": org_id,
                    "seq": last["seq"] + 1 if last else 1, "previous_hash": last["hash"] if last else "0" * 64,
                    "recorded_at": now_iso(), "actor_id": actor["id"] if actor else None,
                    "method": method, "route": route, "status": status,
                    "case_ids": sorted(set(case_ids)), "request_id": request_id}
            c.execute("INSERT INTO access_events VALUES (?,?,?,?,?)",
                      (org_id, body["seq"], canonical(body).decode(), digest(body),
                       base64.b64encode(self.key.sign(canonical(body))).decode()))

    def access_audit(self, actor, offset=0, limit=200):
        require(actor["role"] in {"admin", "auditor"}, "Audit permission required", 403)
        require(0 <= offset and 1 <= limit <= 200, "Invalid audit pagination", 422)
        with self.transaction(False) as c:
            rows = c.execute("SELECT * FROM access_events WHERE org_id=? ORDER BY seq", (actor["org_id"],)).fetchall()
            events = [{"body": json.loads(r["body"]), "hash": r["hash"], "signature": r["signature"]} for r in rows]
            head = verify_access_events(events, self.public_key, actor["org_id"])
        # Administrators/auditors have explicit department-wide access to audit METADATA,
        # not to restricted clinical contents. Only opaque case IDs and route templates are stored.
        return {"events": events[offset:offset + limit], "total": len(events), "offset": offset,
                "head": head, "public_key": self.public_b64,
                "previous_hash": events[offset - 1]["hash"] if 0 < offset <= len(events) else "0" * 64}

    def change_password(self, actor, current_password, new_password):
        from .store import password_hash, password_matches
        require(14 <= len(new_password) <= 1024 and current_password != new_password,
                "Choose a different password between 14 and 1024 characters", 422)
        import time
        now = int(time.time())
        bucket = "password-change:" + actor["id"]
        failed = False
        with self.transaction() as c:
            row = self._user(c, actor["id"])
            require(row["active"] and row["org_id"] == actor["org_id"], "Account is unavailable", 403)
            count = c.execute("SELECT COUNT(*) FROM attempts WHERE bucket=? AND at>=?", (bucket, now - 900)).fetchone()[0]
            require(count < 8, "Too many failed password changes; retry after 15 minutes", 429)
            if not password_matches(current_password, row["password"]):
                c.execute("INSERT INTO attempts VALUES (?,?)", (bucket, now))
                failed = True
            else:
                c.execute("UPDATE users SET password=? WHERE id=?", (password_hash(new_password), actor["id"]))
                self._seal_identity(c, "user", actor["id"], c.execute("SELECT * FROM users WHERE id=?", (actor["id"],)).fetchone())
                c.execute("DELETE FROM sessions WHERE user_id=?", (actor["id"],))
                c.execute("DELETE FROM attempts WHERE bucket=?", (bucket,))
                self._admin_event(c, actor["id"], "password_changed", {"user_id": actor["id"], "sessions_revoked": True})
        require(not failed, "Current password is incorrect", 403)

    def batch_handover(self, actor, case_id, data, key):
        from .models import BatchHandover, ROLES
        from .store import validate
        require(actor["role"] in ROLES["handover"], "Role does not permit handover", 403)
        data = validate(BatchHandover, data)
        ids = [x["specimen_id"] for x in data["items"]]
        require(len(ids) == len(set(ids)), "A batch cannot contain a specimen twice", 422)
        payload = {"action": "batch_handover", "case_id": case_id, **data}
        with self.transaction() as c:
            replay = self._replay(c, actor, key, payload)
            if replay:
                return replay
            state = self._load(c, actor, case_id)
            require(state["version"] == data["expected_version"], "Case changed; refresh before submitting (stale version)")
            original = state
            for index, values in enumerate(data["items"]):
                self._authorize_command(c, actor, state, "handover", values)
                state = apply(state, "handover", values, actor, now_iso(), "preview-" + str(index), case_id)
            if data["preview"]:
                # Preview is non-mutating; even the command idempotency registry is untouched.
                return {"valid": True, "preview": True, "count": len(ids), "expected_version": original["version"],
                        "projected_version": state["version"], "specimen_ids": ids}
            state = original
            for values in data["items"]:
                state, eid = self._append(c, actor, case_id, state, "handover", values)
            return self._remember(c, actor, key, payload, state, eid)

    def locate_specimen(self, actor, token):
        require(isinstance(token, str) and 1 <= len(token) <= 160, "Invalid specimen lookup", 422)
        from .domain import normalized
        prefix = "openviscera:specimen:"
        specimen_id = token[len(prefix):] if token.startswith(prefix) else None
        with self.transaction(False) as c:
            if specimen_id:
                row = c.execute("SELECT case_id,specimen_id FROM containers WHERE org_id=? AND specimen_id=?",
                                (actor["org_id"], specimen_id)).fetchone()
            else:
                row = c.execute("SELECT case_id,specimen_id FROM containers WHERE org_id=? AND name=?",
                                (actor["org_id"], normalized(token))).fetchone()
            require(row is not None, "Specimen not found", 404)
            state = self.visible(actor, self._load(c, actor, row["case_id"]))
            specimen = next((sp for sp in state["specimens"] if sp["id"] == row["specimen_id"]), None)
            require(specimen is not None, "Specimen not found", 404)
            return {"case_id": state["id"], "case_ref": state["case_ref"], "specimen": specimen, "version": state["version"]}


class AccessAuditMiddleware:
    def __init__(self, app, store):
        self.app, self.store = app, store

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope["path"].startswith("/api/"):
            return await self.app(scope, receive, send)
        scope["ov_request_id"] = uuid.uuid4().hex
        blocked = False

        async def audit_send(message):
            nonlocal blocked
            if blocked:
                return
            if message["type"] == "http.response.start":
                state = scope.get("state", {})
                route = getattr(scope.get("route"), "path", "unmatched-api-route")
                case_ids = state.get("audit_case_ids", [])
                cid = scope.get("path_params", {}).get("case_id")
                if cid and len(cid) == 32 and all(c in "0123456789abcdef" for c in cid):
                    case_ids = [*case_ids, cid]
                try:
                    await run_in_threadpool(self.store.record_access, state.get("actor"), scope["method"], route,
                                            message["status"], case_ids, scope["ov_request_id"])
                except Exception:
                    # Clinical bytes never leave this layer if durable audit storage fails.
                    blocked = True
                    await JSONResponse({"detail": "Access audit unavailable; response withheld"}, status_code=503,
                                       headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})(scope, receive, send)
                    return
                message["headers"] = list(message.get("headers", [])) + [(b"x-audit-request-id", scope["ov_request_id"].encode())]
            await send(message)
        await self.app(scope, receive, audit_send)
