import base64
import sqlite3
from contextlib import closing
import uuid

import pytest
from fastapi.testclient import TestClient

from openviscera.app import MAX_REQUEST, create_app
from openviscera.demo import sample_pdf
from openviscera.domain import RuleError

PASSWORD = "synthetic-test-password-123"


@pytest.fixture
def client(env):
    store, _, _, _ = env
    with TestClient(create_app(store.path, "http://localhost", True), base_url="http://localhost") as client:
        yield client


def login(client, username="examiner", password=PASSWORD):
    response = client.post("/api/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = response.json()["csrf"]
    return response


def test_authenticated_dashboard(client, env):
    _, _, _, d = env
    d.dispatched("API-PENDING")
    assert client.get("/api/dashboard").status_code == 401
    login(client)
    result = client.get("/api/dashboard").json()
    assert result["case_count"] == 1
    assert result["counts"]["receipt"] == 1
    assert result["counts"]["reports"] == 1
    assert result["queues"]["reports"][0]["overdue"]


def test_security_headers_and_cookie_flags(client):
    response = login(client)
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert "no-store" in response.headers["cache-control"]
    assert "object-src 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"


def test_secure_cookie_production(env):
    store, _, _, _ = env
    with TestClient(create_app(store.path, "https://localhost"), base_url="https://localhost") as c:
        response = login(c)
        assert "secure" in response.headers["set-cookie"].lower()
        assert "max-age=" in response.headers["strict-transport-security"]


def test_csrf_origin_and_host_checks(client):
    login(client)
    client.headers.pop("X-CSRF-Token")
    assert client.post("/api/logout", json={}).status_code == 403
    assert client.post("/api/login", json={"username": "examiner", "password": PASSWORD},
                       headers={"Origin": "https://attacker.invalid"}).status_code == 403
    assert client.get("/api/me", headers={"Host": "attacker.invalid"}).status_code == 400
    assert client.post("/api/login", content="x", headers={"Content-Type": "text/plain"}).status_code == 415


def test_body_limit_even_without_content_length(client):
    chunks = iter([b"x" * (MAX_REQUEST // 2), b"x" * (MAX_REQUEST // 2 + 1)])
    result = client.post("/api/login", content=chunks, headers={"Content-Type": "application/json"})
    assert result.status_code == 413


def test_validation_does_not_echo_password(client):
    secret = "password-must-not-be-echoed"
    result = client.post("/api/login", json={"username": "examiner", "password": secret, "unexpected": secret})
    assert result.status_code == 422
    assert secret not in result.text


def test_login_rate_limit_persists_across_clients(client):
    for _ in range(8):
        assert client.post("/api/login", json={"username": "unknown", "password": "wrong"}).status_code == 401
    assert client.post("/api/login", json={"username": "unknown", "password": "wrong"}).status_code == 429


def test_logout_revokes_session(client):
    login(client)
    assert client.post("/api/logout", json={}).status_code == 200
    assert client.get("/api/me").status_code == 401


def test_admin_can_disable_and_revoke_other_user(env):
    store, users, _, _ = env
    token, _, _ = store.login("examiner", PASSWORD, "localhost")
    with TestClient(create_app(store.path, "http://localhost", True), base_url="http://localhost") as c:
        login(c, "admin")
        result = c.post("/api/admin/users/" + users["examiner"]["id"] + "/active", json={"active": False})
        assert result.status_code == 200
    with pytest.raises(RuleError) as error:
        store.session(token)
    assert error.value.status == 401
    with pytest.raises(RuleError):
        store.login("examiner", PASSWORD, "localhost")


def test_create_and_mutate_requires_idempotency_and_current_version(client, env):
    _, users, _, _ = env
    login(client)
    data = {"case_ref": "API", "authority": "Synthetic", "examiner_id": users["examiner"]["id"]}
    assert client.post("/api/cases", json=data).status_code == 422
    response = client.post("/api/cases", json=data, headers={"Idempotency-Key": uuid.uuid4().hex})
    assert response.status_code == 201
    s = response.json()["case"]
    endpoint = f'/api/cases/{s["id"]}/commands/note'
    command = {"expected_version": 1, "data": {"text": "Administrative note"}}
    assert client.post(endpoint, json=command, headers={"Idempotency-Key": uuid.uuid4().hex}).status_code == 200
    assert client.post(endpoint, json=command, headers={"Idempotency-Key": uuid.uuid4().hex}).status_code == 409


@pytest.mark.parametrize("filename", ["../report.pdf", "folder/report.pdf", "folder\\report.pdf", "file\r\n.pdf"])
def test_upload_rejects_unsafe_filename(client, env, filename):
    _, _, _, d = env
    s = d.collected("UPLOAD-PATH")
    login(client)
    payload = {"expected_version": s["version"], "specimen_id": s["specimens"][0]["id"], "filename": filename,
               "media_type": "application/pdf", "content_b64": base64.b64encode(sample_pdf()).decode()}
    result = client.post(f'/api/cases/{s["id"]}/attachments', json=payload, headers={"Idempotency-Key": uuid.uuid4().hex})
    assert result.status_code == 422


def test_upload_download_and_mime_signature(client, env):
    _, _, _, d = env
    s = d.collected("UPLOAD")
    login(client)
    content = sample_pdf()
    payload = {"expected_version": s["version"], "specimen_id": s["specimens"][0]["id"], "filename": "report.pdf",
               "media_type": "application/pdf", "content_b64": base64.b64encode(content).decode()}
    url = f'/api/cases/{s["id"]}/attachments'
    invalid = {**payload, "content_b64": base64.b64encode(b"not-a-pdf").decode()}
    assert client.post(url, json=invalid, headers={"Idempotency-Key": uuid.uuid4().hex}).status_code == 422
    result = client.post(url, json=payload, headers={"Idempotency-Key": uuid.uuid4().hex})
    assert result.status_code == 201
    attachment = result.json()["case"]["attachments"][0]
    fetched = client.get(url + "/" + attachment["id"])
    assert fetched.content == content
    assert fetched.headers["content-disposition"].startswith("attachment;")


def test_direct_attach_command_cannot_reference_unstored_bytes(client, env):
    _, _, _, d = env
    s = d.collected("ATTACH-BYPASS")
    login(client)
    result = client.post(f'/api/cases/{s["id"]}/commands/attach', json={"expected_version": s["version"], "data": {}},
                         headers={"Idempotency-Key": uuid.uuid4().hex})
    assert result.status_code == 422


def test_schema_requires_authentication(client):
    assert client.get("/api/schema").status_code == 401
    login(client)
    assert "record_receipt" in client.get("/api/schema").json()["commands"]


def test_insecure_deployment_requires_explicit_loopback(env):
    store, _, _, _ = env
    with pytest.raises(RuleError):
        create_app(store.path, "http://example.invalid", True)
    with pytest.raises(RuleError):
        create_app(store.path, "http://localhost", False)


def test_lab_cannot_read_other_laboratory_reports(client, env):
    store, users, _, d = env
    s = d.reported("LAB-ISOLATION")
    other = store.add_lab("org-a", {"name": "Other partner lab"})
    s = d.do(s["id"], "request", {"specimen_id": s["specimens"][0]["id"], "examination": "Other examination",
                                 "lab_id": other["id"], "due_at": d.due})
    s = d.attachment(s["id"], s["specimens"][0]["id"])
    hidden_file = s["attachments"][-1]["id"]
    s = d.do(s["id"], "report", {"request_id": s["requests"][-1]["id"], "attachment_id": hidden_file,
                                 "laboratory_reference": "Other lab report", "received_at": d.past}, "coordinator")
    login(client, "lab")
    view = client.get(f'/api/cases/{s["id"]}').json()["case"]
    assert len(view["requests"]) == len(view["reports"]) == 1
    assert client.get(f'/api/cases/{s["id"]}/attachments/{hidden_file}').status_code == 404
    assert client.get(f'/api/cases/{s["id"]}/export').status_code == 403


def test_download_detects_altered_blob(client, env):
    store, _, _, d = env
    s = d.reported("TAMPER-DOWNLOAD")
    login(client)
    with closing(sqlite3.connect(store.db)) as c, c:
        c.execute("UPDATE blobs SET content=?", (b"modified",))
    result = client.get(f'/api/cases/{s["id"]}/attachments/{s["attachments"][0]["id"]}')
    assert result.status_code == 409
