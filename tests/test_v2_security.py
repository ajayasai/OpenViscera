"""HTTP privacy boundaries, audit failure behavior and recoverable schema upgrades."""
import base64
import copy
import hashlib
import json
import sqlite3
import uuid
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from openviscera import domain_v1
from openviscera.app import create_app
from openviscera.domain import RuleError, canonical, digest, now_iso
from openviscera.evidence import check_database, encrypted_backup, restore_backup, export_bundle, verify_bundle
from openviscera.governance import verify_access_events
from openviscera.migrations import migrate
from openviscera.store import Store

PASSWORD = "synthetic-test-password-123"


def login(client, role="examiner"):
    result = client.post("/api/login", json={"username": role, "password": PASSWORD})
    assert result.status_code == 200
    client.headers["X-CSRF-Token"] = result.json()["csrf"]


@pytest.fixture
def client(env):
    with TestClient(create_app(env[0].path, "http://localhost", True), base_url="http://localhost") as c:
        yield c


def restrict(d, s):
    return d.do(s["id"], "access_policy", {"mode": "restricted", "member_ids": [d.users["examiner"]["id"]], "reason": "Restricted test case"})


@pytest.mark.parametrize("endpoint", ["case", "events", "export", "documents", "attachment", "lookup-id", "lookup-container"])
def test_restricted_case_not_disclosed_through_http(client, env, endpoint):
    _, _, _, d = env
    s = d.reported("PRIVATE-HTTP")
    restrict(d, s)
    login(client, "coordinator")
    root = "/api/cases/" + s["id"]
    urls = {"case": root, "events": root + "/events", "export": root + "/export",
            "documents": root + "/documents/chronology", "attachment": root + "/attachments/" + s["attachments"][0]["id"],
            "lookup-id": "/api/locate?token=openviscera:specimen:" + s["specimens"][0]["id"],
            "lookup-container": "/api/locate?token=" + s["specimens"][0]["container_id"]}
    response = client.get(urls[endpoint])
    assert response.status_code == 404
    assert s["case_ref"] not in response.text and s["authority"] not in response.text
    assert client.get("/api/cases").json()["total"] == 0
    dashboard = client.get("/api/dashboard").json()
    assert dashboard["case_count"] == 0 and sum(dashboard["counts"].values()) == 0


def test_access_audit_captures_reads_exports_denials_and_no_sensitive_payloads(client, env):
    store, users, _, d = env
    s = d.reported("AUDIT-HTTP")
    login(client)
    response = client.get("/api/cases/" + s["id"])
    rid = response.headers["x-audit-request-id"]
    assert response.headers["x-request-id"] == rid
    client.get("/api/cases/" + s["id"] + "/export")
    client.get("/api/cases", params={"search": "SENSITIVE SEARCH TERMS"})
    client.get("/api/dashboard")
    client.get("/api/locate", params={"token": s["specimens"][0]["container_id"]})
    client.get("/api/admin/access-audit")  # Examiner is denied this privileged metadata.
    audit = store.access_audit(users["auditor"])
    assert verify_access_events(audit["events"], store.public_key, users["examiner"]["org_id"]) == audit["head"]
    text = json.dumps(audit)
    for forbidden in [PASSWORD, s["case_ref"], s["authority"], "SENSITIVE SEARCH TERMS", s["specimens"][0]["container_id"]]:
        assert forbidden not in text
    event = next(e for e in audit["events"] if e["body"]["request_id"] == rid)
    assert event["body"]["case_ids"] == [s["id"]]
    assert event["body"]["actor_id"] == users["examiner"]["id"]
    assert any(e["body"]["status"] == 403 for e in audit["events"])
    assert any(e["body"]["route"].endswith("/export") for e in audit["events"])
    check_database(store)


def test_failed_login_audit_contains_no_entered_credentials(client, env):
    store, _, _, _ = env
    response = client.post("/api/login", json={"username": "sensitive-user-input", "password": "sensitive-password-input"})
    assert response.status_code == 401
    with store.transaction(False) as c:
        rows = c.execute("SELECT * FROM access_events WHERE org_id='__unauthenticated__'").fetchall()
        text = str([dict(r) for r in rows])
    assert "sensitive-user-input" not in text and "sensitive-password-input" not in text
    assert rows


def test_audit_append_failure_withholds_clinical_response(client, env, monkeypatch):
    store, _, _, d = env
    s = d.reported("WITHHELD")
    login(client)
    def fail(*args):
        raise sqlite3.OperationalError("Synthetic full audit storage")
    monkeypatch.setattr(store.__class__, "record_access", fail)
    response = client.get("/api/cases/" + s["id"])
    assert response.status_code == 503
    assert s["authority"] not in response.text and "response withheld" in response.text
    assert response.headers["cache-control"] == "no-store"


def test_committed_write_after_audit_failure_can_be_retried_idempotently(client, env, monkeypatch):
    store, _, _, d = env
    s = d.new("AUDIT-WRITE")
    login(client)
    original = Store.record_access
    def fail(*args):
        raise sqlite3.OperationalError("Audit unavailable")
    monkeypatch.setattr(Store, "record_access", fail)
    data = {"expected_version": s["version"], "data": {"text": "Saved once, even if response was withheld"}}
    key = uuid.uuid4().hex
    url = "/api/cases/" + s["id"] + "/commands/note"
    assert client.post(url, json=data, headers={"Idempotency-Key": key}).status_code == 503
    monkeypatch.setattr(Store, "record_access", original)
    response = client.post(url, json=data, headers={"Idempotency-Key": key})
    assert response.status_code == 200 and response.json()["replayed"]
    assert len(response.json()["case"]["notes"]) == 1


def test_audit_tenant_isolation_and_pagination(client, env):
    store, users, _, _ = env
    login(client)
    for _ in range(5):
        client.get("/api/me")
    own = store.access_audit(users["auditor"], offset=2, limit=2)
    assert len(own["events"]) == 2
    assert own["events"][0]["body"]["seq"] == 3
    assert verify_access_events(own["events"], store.public_key, "org-a", 3, own["previous_hash"])
    other_admin = store.add_user("org-b", {"username": "other_admin", "display_name": "Other admin", "role": "admin", "password": PASSWORD})
    assert store.access_audit(other_admin)["events"] == []
    with pytest.raises(RuleError):
        store.access_audit(users["examiner"])


def test_modified_access_chain_detected(client, env):
    store, users, _, _ = env
    login(client)
    with closing(sqlite3.connect(store.db)) as c, c:
        with pytest.raises(sqlite3.IntegrityError, match="append-only access"):
            c.execute("DELETE FROM access_events")
        c.execute("DROP TRIGGER no_access_update")
        c.execute("UPDATE access_events SET signature=?", (base64.b64encode(b"x" * 64).decode(),))
    with pytest.raises(RuleError, match="Access audit signature"):
        check_database(store)
    with pytest.raises(RuleError):
        store.access_audit(users["auditor"])
    assert client.get("/api/me").status_code == 503


def test_password_change_revokes_all_sessions(client, env):
    store, _, _, _ = env
    login(client)
    token, _, _ = store.login("examiner", PASSWORD, "synthetic-host")
    result = client.post("/api/account/password", json={"current_password": PASSWORD, "new_password": "new-synthetic-password-123"})
    assert result.status_code == 200 and result.json()["reauthentication_required"]
    assert client.get("/api/me").status_code == 401
    with pytest.raises(RuleError):
        store.session(token)
    assert client.post("/api/login", json={"username": "examiner", "password": PASSWORD}).status_code == 401
    assert client.post("/api/login", json={"username": "examiner", "password": "new-synthetic-password-123"}).status_code == 200


@pytest.mark.parametrize("problem", ["incorrect", "too-short", "same-password"])
def test_password_change_rejections(client, env, problem):
    store, _, _, _ = env
    login(client)
    data = {"current_password": PASSWORD, "new_password": "different-synthetic-password-123"}
    if problem == "incorrect":
        data["current_password"] = "wrong-current-password"
    elif problem == "too-short":
        data["new_password"] = "short"
    else:
        data["new_password"] = PASSWORD
    assert client.post("/api/account/password", json=data).status_code in {403, 422}
    assert store.login("examiner", PASSWORD, "local")


def legacy_append(self, c, actor, case_id, old, action, data):
    """Reproduce the v0.1 event writer against its frozen reducer, using ephemeral test keys."""
    eid, recorded = uuid.uuid4().hex, now_iso()
    state = domain_v1.apply(old, action, data, actor, recorded, eid, case_id)
    last = c.execute("SELECT hash FROM events WHERE case_id=? ORDER BY seq DESC LIMIT 1", (case_id,)).fetchone()
    body = {"schema": 1, "case_id": case_id, "seq": state["version"], "event_id": eid, "actor": actor,
            "recorded_at": recorded, "action": action, "data": data,
            "previous_hash": last["hash"] if last else "0" * 64, "after_digest": digest(state)}
    c.execute("INSERT INTO events VALUES (?,?,?,?,?)", (case_id, state["version"], canonical(body).decode(),
               digest(body), base64.b64encode(self.key.sign(canonical(body))).decode()))
    c.execute("UPDATE cases SET state=? WHERE id=?", (canonical(state).decode(), case_id))
    if action == "collect":
        c.execute("INSERT INTO containers VALUES (?,?,?,?)", (actor["org_id"], domain_v1.normalized(data["container_id"]), case_id, eid))
    return state, eid


def make_v1(env, monkeypatch):
    store, users, _, d = env
    with monkeypatch.context() as context:
        context.setattr(Store, "_append", legacy_append)
        s = d.issued("LEGACY-CASE")
    with store.transaction() as c:
        c.execute("DROP TABLE access_events")
        c.execute("UPDATE meta SET value='1' WHERE name='schema'")
    old_bytes = canonical(s)
    old_events = store.evidence(users["examiner"], s["id"])[1]
    return s, old_bytes, old_events


def test_migration_preserves_v1_signatures_bundle_and_issued_record(env, monkeypatch):
    store, users, _, d = env
    s, before, old_events = make_v1(env, monkeypatch)
    bundle = export_bundle(store, users["examiner"], s["id"])
    with pytest.raises(RuleError, match="upgrade required"):
        Store(store.path)
    result = migrate(store.path)
    assert result["schema"] == 2 and result["changed"]
    upgraded = Store(store.path)
    assert canonical(upgraded.get_case(users["examiner"], s["id"])) == before
    assert upgraded.evidence(users["examiner"], s["id"])[1] == old_events
    assert verify_bundle(bundle, upgraded.public_b64)["valid"]
    assert not migrate(store.path)["changed"]
    d.store = upgraded
    d.do(s["id"], "note", {"text": "New v2 event after old issued opinion"})
    events = upgraded.evidence(users["examiner"], s["id"])[1]
    assert events[-1]["body"]["schema"] == 2 and events[:-1] == old_events
    check_database(upgraded)


def test_v1_backup_can_be_restored_then_migrated(env, monkeypatch, tmp_path):
    store, users, _, _ = env
    s, before, _ = make_v1(env, monkeypatch)
    legacy = Store(store.path, allow_legacy=True)
    content = encrypted_backup(legacy, "legacy-synthetic-backup-password")
    restored = restore_backup(content, "legacy-synthetic-backup-password", tmp_path / "v1-restored")
    assert migrate(restored.path)["changed"]
    assert canonical(Store(restored.path).get_case(users["examiner"], s["id"])) == before


def test_migration_failure_is_atomic(env, monkeypatch):
    store, _, _, _ = env
    make_v1(env, monkeypatch)
    def fail(*args):
        raise sqlite3.OperationalError("Synthetic migration failure")
    monkeypatch.setattr(Store, "_admin_event", fail)
    with pytest.raises(sqlite3.OperationalError):
        migrate(store.path)
    with store.transaction(False) as c:
        assert c.execute("SELECT value FROM meta WHERE name='schema'").fetchone()[0] == "1"
        assert not c.execute("SELECT 1 FROM sqlite_master WHERE name='access_events'").fetchone()


def test_migration_rejects_damaged_existing_evidence(env, monkeypatch):
    store, _, _, _ = env
    make_v1(env, monkeypatch)
    with store.transaction() as c:
        c.execute("DROP TRIGGER no_event_update")
        c.execute("UPDATE events SET hash='damaged'")
    with pytest.raises(RuleError, match="hash mismatch"):
        migrate(store.path)
    with store.transaction(False) as c:
        assert c.execute("SELECT value FROM meta WHERE name='schema'").fetchone()[0] == "1"


def test_password_change_failures_are_persistently_throttled(client, env):
    login(client)
    values = {"current_password": "incorrect-value", "new_password": "new-safe-synthetic-password"}
    for _ in range(8):
        assert client.post("/api/account/password", json=values).status_code == 403
    values["current_password"] = PASSWORD
    assert client.post("/api/account/password", json=values).status_code == 429
