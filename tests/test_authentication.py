"""Synthetic RFC vectors, MFA/recovery attacks, policy boundaries and migrations."""
import base64
import copy
import json
import time as system_time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from openviscera import authentication as auth
from openviscera.app import create_app
from openviscera.cli import main
from openviscera.domain import RuleError, canonical
from openviscera.evidence import check_database, encrypted_backup, restore_backup
from openviscera.migrations import migrate
from openviscera.store import Store

PASSWORD = "synthetic-test-password-123"
NEW_PASSWORD = "synthetic-replacement-password-456"


@pytest.fixture
def clock(monkeypatch):
    current = [int(system_time.time()) // 30 * 30 + 2]
    monkeypatch.setattr(auth, "time", SimpleNamespace(time=lambda: current[0]))
    return current


def enable(store, actor, clock):
    setup = store.begin_mfa_setup(actor, PASSWORD)
    confirmed = store.confirm_mfa_setup(actor, PASSWORD, auth.totp(setup["secret"], clock[0] // 30))
    clock[0] += 30
    return setup["secret"], confirmed["recovery_codes"]


def signin(store, clock, secret, username="examiner"):
    result = store.login(username, PASSWORD, "test-client")
    return store.complete_mfa_login(result["challenge"], auth.totp(secret, clock[0] // 30), "test-client")


@pytest.mark.parametrize("seconds,expected", [
    (59, ["94287082", "46119246", "90693936"]),
    (1111111109, ["07081804", "68084774", "25091201"]),
    (1111111111, ["14050471", "67062674", "99943326"]),
    (1234567890, ["89005924", "91819424", "93441116"]),
    (2000000000, ["69279037", "90698825", "38618901"]),
    (20000000000, ["65353130", "77737706", "47863826"]),
])
def test_rfc6238_appendix_b_vectors(seconds, expected):
    keys = [b"12345678901234567890", b"12345678901234567890123456789012",
            b"1234567890123456789012345678901234567890123456789012345678901234"]
    for key, algorithm, code in zip(keys, ["sha1", "sha256", "sha512"], expected):
        assert auth.totp(base64.b32encode(key).decode().rstrip("="), seconds // 30, 8, algorithm) == code


def test_mfa_password_step_never_creates_authenticated_session(env, clock):
    store, users, _, _ = env
    old, _, _ = store.login("examiner", PASSWORD, "test-client")
    secret, codes = enable(store, users["examiner"], clock)
    with pytest.raises(RuleError):
        store.session(old)
    result = store.login("examiner", PASSWORD, "test-client")
    assert set(result) == {"challenge", "mfa_required", "expires_in"}
    assert result["mfa_required"] and len(codes) == 10 and len(set(codes)) == 10
    with store.transaction(False) as c:
        assert c.execute("SELECT COUNT(*) FROM sessions WHERE user_id=?", (users["examiner"]["id"],)).fetchone()[0] == 0
        raw = c.execute("SELECT security FROM users WHERE id=?", (users["examiner"]["id"],)).fetchone()[0]
        audit = str([dict(r) for r in c.execute("SELECT * FROM administrative_events")])
    assert secret not in raw and secret not in audit
    assert all(code not in raw and code not in audit for code in codes)
    token, _, actor = store.complete_mfa_login(result["challenge"], auth.totp(secret, clock[0] // 30), "test-client")
    assert store.session(token)[0] == actor
    assert store.account_security(actor, token)["sessions"][0]["method"] == "totp"
    check_database(store)


def test_totp_and_login_challenge_cannot_be_replayed(env, clock):
    store, users, _, _ = env
    secret, _ = enable(store, users["examiner"], clock)
    challenge = store.login("examiner", PASSWORD, "test")["challenge"]
    code = auth.totp(secret, clock[0] // 30)
    store.complete_mfa_login(challenge, code, "test")
    with pytest.raises(RuleError):
        store.complete_mfa_login(challenge, code, "test")
    challenge = store.login("examiner", PASSWORD, "test")["challenge"]
    with pytest.raises(RuleError):
        store.complete_mfa_login(challenge, code, "test")
    clock[0] += 30
    assert store.complete_mfa_login(challenge, auth.totp(secret, clock[0] // 30), "test")


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_totp_clock_window_and_monotonic_consumption(env, clock, offset):
    store, users, _, _ = env
    secret, _ = enable(store, users["examiner"], clock)
    clock[0] += 60
    challenge = store.login("examiner", PASSWORD, "test")["challenge"]
    code = auth.totp(secret, clock[0] // 30 + offset)
    assert store.complete_mfa_login(challenge, code, "test")
    with store.transaction(False) as c:
        assert json.loads(store._user(c, users["examiner"]["id"])["security"])["last_counter"] == clock[0] // 30 + offset


@pytest.mark.parametrize("code", ["00000000", "not-a-code", "١٢٣٤٥٦", "1234567", ""])
def test_malformed_codes_fail_without_session(env, clock, code):
    store, users, _, _ = env
    enable(store, users["examiner"], clock)
    challenge = store.login("examiner", PASSWORD, "test")["challenge"]
    with pytest.raises(RuleError):
        store.complete_mfa_login(challenge, code, "test")
    assert store.account_security(users["examiner"])["sessions"] == []


def test_recovery_is_one_time_and_does_not_disable_mfa(env, clock):
    store, users, _, _ = env
    _, codes = enable(store, users["examiner"], clock)
    first = store.login("examiner", PASSWORD, "test")
    token, _, _ = store.complete_mfa_login(first["challenge"], codes[0], "test")
    state = store.account_security(users["examiner"], token)
    assert state["mfa_enabled"] and state["recovery_codes_remaining"] == 9
    assert state["sessions"][0]["method"] == "recovery"
    second = store.login("examiner", PASSWORD, "test")
    with pytest.raises(RuleError):
        store.complete_mfa_login(second["challenge"], codes[0], "test")
    assert store.complete_mfa_login(second["challenge"], codes[1].lower(), "test")


def test_concurrent_factor_consumption_commits_once(env, clock):
    store, users, _, _ = env
    secret, _ = enable(store, users["examiner"], clock)
    challenge = store.login("examiner", PASSWORD, "test")["challenge"]
    def run(_):
        try:
            store.complete_mfa_login(challenge, auth.totp(secret, clock[0] // 30), "test")
            return True
        except RuleError:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(run, range(2))) == 1
    check_database(store)


def test_challenge_replaced_expired_and_failed_limit(env, clock):
    store, users, _, _ = env
    secret, _ = enable(store, users["examiner"], clock)
    old = store.login("examiner", PASSWORD, "test")["challenge"]
    challenge = store.login("examiner", PASSWORD, "test")["challenge"]
    with pytest.raises(RuleError):
        store.complete_mfa_login(old, auth.totp(secret, clock[0] // 30), "test")
    for _ in range(5):
        with pytest.raises(RuleError):
            store.complete_mfa_login(challenge, "wrong", "test")
    with pytest.raises(RuleError):
        store.complete_mfa_login(challenge, auth.totp(secret, clock[0] // 30), "test")
    challenge = store.login("examiner", PASSWORD, "test")["challenge"]
    clock[0] += 301
    with pytest.raises(RuleError):
        store.complete_mfa_login(challenge, auth.totp(secret, clock[0] // 30), "test")


def test_account_factor_throttle_persists_across_new_challenges_and_restart(env, clock):
    store, users, _, _ = env
    enable(store, users["examiner"], clock)
    for _ in range(8):
        challenge = store.login("examiner", PASSWORD, "test")["challenge"]
        with pytest.raises(RuleError):
            store.complete_mfa_login(challenge, "wrong", "different-ip")
    restarted = Store(store.path)
    with pytest.raises(RuleError) as error:
        restarted.login("examiner", PASSWORD, "fresh-ip")
    assert error.value.status == 429
    clock[0] += 901
    assert restarted.login("examiner", PASSWORD, "fresh-ip")["mfa_required"]


def test_setup_expiry_wrong_password_and_replacement(env, clock):
    store, users, _, _ = env
    with pytest.raises(RuleError):
        store.begin_mfa_setup(users["examiner"], "incorrect")
    first = store.begin_mfa_setup(users["examiner"], PASSWORD)
    second = store.begin_mfa_setup(users["examiner"], PASSWORD)
    assert first["secret"] != second["secret"]
    with pytest.raises(RuleError):
        store.confirm_mfa_setup(users["examiner"], PASSWORD, auth.totp(first["secret"], clock[0] // 30))
    clock[0] += 601
    with pytest.raises(RuleError):
        store.confirm_mfa_setup(users["examiner"], PASSWORD, auth.totp(second["secret"], clock[0] // 30))
    assert not store.account_security(users["examiner"])["mfa_enabled"]


def test_setup_confirmation_throttled_and_not_just_six_digit_guessing(env, clock):
    store, users, _, _ = env
    value = store.begin_mfa_setup(users["examiner"], PASSWORD)
    for _ in range(8):
        with pytest.raises(RuleError):
            store.confirm_mfa_setup(users["examiner"], PASSWORD, "wrong")
    with pytest.raises(RuleError) as error:
        store.confirm_mfa_setup(users["examiner"], PASSWORD, auth.totp(value["secret"], clock[0] // 30))
    assert error.value.status == 429


def test_mfa_secret_ciphertext_is_bound_to_account(env):
    store, users, _, _ = env
    encrypted = store._encrypt_secret(users["examiner"]["id"], "SYNTHETICSECRET")
    assert store._decrypt_secret(users["examiner"]["id"], encrypted) == "SYNTHETICSECRET"
    with pytest.raises(RuleError, match="integrity"):
        store._decrypt_secret(users["reviewer"]["id"], encrypted)


@pytest.mark.parametrize("table,mutation", [
    ("users", "UPDATE users SET security='{}' WHERE username='examiner'"),
    ("login_challenges", "UPDATE login_challenges SET failures=0,expires=9999999999"),
    ("session_context", "UPDATE session_context SET method='totp'"),
])
def test_unsigned_security_changes_fail_integrity_checks(env, clock, table, mutation):
    store, users, _, _ = env
    enable(store, users["examiner"], clock)
    store.login("examiner", PASSWORD, "test")
    store.login("reviewer", PASSWORD, "test")
    with store.transaction() as c:
        c.execute(mutation)
    with pytest.raises(RuleError, match="integrity"):
        check_database(store)


def test_missing_session_context_fails_closed(env):
    store, users, _, _ = env
    token, _, _ = store.login("examiner", PASSWORD, "test")
    with store.transaction() as c:
        c.execute("DELETE FROM session_context")
    with pytest.raises(RuleError):
        store.session(token)
    with pytest.raises(RuleError, match="metadata"):
        check_database(store)


def test_session_listing_revoke_others_and_other_users_protected(env):
    store, users, _, _ = env
    one, _, _ = store.login("examiner", PASSWORD, "test")
    two, _, _ = store.login("examiner", PASSWORD, "test")
    alien, _, _ = store.login("reviewer", PASSWORD, "test")
    rows = store.account_security(users["examiner"], one)["sessions"]
    assert len(rows) == 2 and sum(r["current"] for r in rows) == 1
    assert all("csrf" not in r and one not in str(r) for r in rows)
    with pytest.raises(RuleError) as error:
        store.revoke_account_sessions(users["examiner"], one, auth.token_hash(alien))
    assert error.value.status == 404
    assert store.revoke_account_sessions(users["examiner"], one, others=True) == {"reauthentication_required": False}
    assert store.session(one) and store.session(alien)
    with pytest.raises(RuleError):
        store.session(two)
    assert store.revoke_account_sessions(users["examiner"], one, auth.token_hash(one))["reauthentication_required"]


def test_sessions_bounded_per_account(env, monkeypatch):
    store, users, _, _ = env
    monkeypatch.setattr(auth, "MAX_SESSIONS", 2)
    for _ in range(3):
        store.login("examiner", PASSWORD, "test")
    assert len(store.account_security(users["examiner"])["sessions"]) == 2
    check_database(store)


@pytest.mark.parametrize("operation", ["disable", "recovery-codes", "password"])
def test_credential_changes_require_factor_and_revoke_all_sessions(env, clock, operation):
    store, users, _, _ = env
    secret, codes = enable(store, users["examiner"], clock)
    token, _, _ = signin(store, clock, secret)
    challenge = store.login("examiner", PASSWORD, "test")["challenge"]
    clock[0] += 30
    def act(code):
        if operation == "password":
            return store.change_password(users["examiner"], PASSWORD, NEW_PASSWORD, code)
        return store.manage_mfa(users["examiner"], PASSWORD, code, operation)
    with pytest.raises(RuleError):
        act("wrong")
    result = act(codes[0])
    with pytest.raises(RuleError):
        store.session(token)
    with pytest.raises(RuleError):
        store.complete_mfa_login(challenge, auth.totp(secret, clock[0] // 30), "test")
    if operation == "disable":
        assert not store.account_security(users["examiner"])["mfa_enabled"]
    elif operation == "recovery-codes":
        assert set(codes).isdisjoint(result["recovery_codes"])
    else:
        with pytest.raises(RuleError):
            store.login("examiner", PASSWORD, "test")
        assert store.login("examiner", NEW_PASSWORD, "test")["mfa_required"]


def test_deactivated_and_reenabled_user_cannot_complete_old_challenge(env, clock):
    store, users, _, _ = env
    secret, _ = enable(store, users["examiner"], clock)
    challenge = store.login("examiner", PASSWORD, "test")["challenge"]
    store.set_active(users["admin"], users["examiner"]["id"], False)
    store.set_active(users["admin"], users["examiner"]["id"], True)
    with pytest.raises(RuleError):
        store.complete_mfa_login(challenge, auth.totp(secret, clock[0] // 30), "test")


def test_http_login_factor_cookie_and_csrf(env, clock):
    store, users, _, _ = env
    secret, _ = enable(store, users["examiner"], clock)
    with TestClient(create_app(store.path, "http://localhost", True), base_url="http://localhost") as client:
        first = client.post("/api/login", json={"username": "examiner", "password": PASSWORD})
        assert first.status_code == 200 and first.json()["mfa_required"]
        assert not client.cookies.get("ov_session")
        assert client.get("/api/cases").status_code == 401
        values = {"challenge": first.json()["challenge"], "code": auth.totp(secret, clock[0] // 30)}
        assert client.post("/api/login/mfa", json=values, headers={"Origin": "https://evil.invalid"}).status_code == 403
        result = client.post("/api/login/mfa", json=values)
        assert result.status_code == 200 and "HttpOnly" in result.headers["set-cookie"]
        assert client.get("/api/cases").status_code == 200
        assert client.post("/api/account/sessions/revoke", json={"others": True}).status_code == 403
        client.headers["X-CSRF-Token"] = result.json()["csrf"]
        state = client.get("/api/account/security").json()
        assert state["mfa_enabled"] and state["sessions"][0]["current"]
        assert "secret" not in state and "recovery_hashes" not in state
        assert client.post("/api/account/sessions/revoke", json={"others": True}).status_code == 200


@pytest.mark.parametrize("path", ["/api/cases", "/api/catalog", "/api/dashboard", "/api/schema", "/api/locate?token=hidden", "/api/admin/access-audit"])
def test_required_mfa_prevents_pre_enrollment_reads(env, path):
    store, _, _, _ = env
    with TestClient(create_app(store.path, "http://localhost", True, require_mfa=True), base_url="http://localhost") as client:
        first = client.post("/api/login", json={"username": "admin", "password": PASSWORD})
        assert first.json()["security"]["enrollment_required"]
        assert client.get(path).status_code == 403
        assert client.get("/api/me").status_code == 200
        assert client.get("/api/account/security").status_code == 200


def test_required_mfa_blocks_writes_and_unlocks_only_after_enrollment_and_factor(env, clock):
    store, users, _, _ = env
    app = create_app(store.path, "http://localhost", True, require_mfa=True)
    with TestClient(app, base_url="http://localhost") as client:
        first = client.post("/api/login", json={"username": "examiner", "password": PASSWORD}).json()
        client.headers["X-CSRF-Token"] = first["csrf"]
        assert client.post("/api/cases", json={"case_ref": "BLOCK", "authority": "Synthetic", "examiner_id": users["examiner"]["id"]},
                           headers={"Idempotency-Key": "synthetic-case-key"}).status_code == 403
        setup = client.post("/api/account/mfa/setup", json={"current_password": PASSWORD}).json()
        assert setup["qr_data_url"].startswith("data:image/svg+xml;base64,")
        assert "examiner" not in setup["uri"]
        response = client.post("/api/account/mfa/confirm", json={"current_password": PASSWORD,
                               "code": auth.totp(setup["secret"], clock[0] // 30)})
        codes = response.json()["recovery_codes"]
        assert not client.cookies.get("ov_session")
        challenge = client.post("/api/login", json={"username": "examiner", "password": PASSWORD}).json()["challenge"]
        result = client.post("/api/login/mfa", json={"challenge": challenge, "code": codes[0]}).json()
        client.headers["X-CSRF-Token"] = result["csrf"]
        assert client.get("/api/cases").status_code == 200
        assert client.post("/api/account/mfa/disable", json={"current_password": PASSWORD, "code": codes[1]}).status_code == 403


def test_local_recovery_requires_personal_password_change_and_keeps_mfa_by_default(env, clock):
    store, users, _, d = env
    case = d.issued("RECOVERY-PRESERVES-EVIDENCE")
    before = canonical(case)
    _, codes = enable(store, users["examiner"], clock)
    store.recover_account("examiner", NEW_PASSWORD, "Synthetic verified recovery authorization")
    assert store.account_security(users["examiner"])["mfa_enabled"]
    with TestClient(create_app(store.path, "http://localhost", True), base_url="http://localhost") as client:
        challenge = client.post("/api/login", json={"username": "examiner", "password": NEW_PASSWORD}).json()["challenge"]
        response = client.post("/api/login/mfa", json={"challenge": challenge, "code": codes[0]}).json()
        assert response["security"]["password_change_required"]
        client.headers["X-CSRF-Token"] = response["csrf"]
        assert client.get("/api/cases").status_code == 403
        assert client.get(f'/api/cases/{case["id"]}/export').status_code == 403
        assert client.post("/api/account/mfa/setup", json={"current_password": NEW_PASSWORD}).status_code == 403
        assert client.post("/api/account/password", json={"current_password": NEW_PASSWORD,
                           "new_password": PASSWORD, "code": codes[1]}).status_code == 200
    assert not store.account_security(users["examiner"])["password_change_required"]
    assert canonical(store.get_case(users["examiner"], case["id"])) == before
    check_database(store)


def test_local_explicit_mfa_reset_is_audited_and_revokes_everything(env, clock, monkeypatch, capsys):
    store, users, _, _ = env
    secret, _ = enable(store, users["examiner"], clock)
    token, _, _ = signin(store, clock, secret)
    monkeypatch.setattr("builtins.input", lambda prompt: "Synthetic independently verified local recovery")
    monkeypatch.setattr("getpass.getpass", lambda prompt: NEW_PASSWORD)
    assert main(["recover-account", "examiner", "--data", str(store.path), "--reset-mfa"]) == 0
    output = capsys.readouterr().out
    assert NEW_PASSWORD not in output
    assert not store.account_security(users["examiner"])["mfa_enabled"]
    with pytest.raises(RuleError):
        store.session(token)
    with store.transaction(False) as c:
        events = [json.loads(r[0]) for r in c.execute("SELECT body FROM administrative_events")]
    record = next(e for e in events if e["action"] == "account_recovered")
    assert record["target"]["reset_mfa"] and record["target"]["reason"].startswith("Synthetic")


def test_backup_restore_keeps_mfa_but_revokes_challenges_and_pending_enrollment(env, clock, tmp_path):
    store, users, _, _ = env
    secret, _ = enable(store, users["examiner"], clock)
    token, _, _ = signin(store, clock, secret)
    challenge = store.login("examiner", PASSWORD, "test")["challenge"]
    store.begin_mfa_setup(users["reviewer"], PASSWORD)
    backup = encrypted_backup(store, "synthetic-backup-password")
    restored = restore_backup(backup, "synthetic-backup-password", tmp_path / "restored")
    assert restored.account_security(users["examiner"])["mfa_enabled"]
    assert restored.account_security(users["examiner"])["recovery_codes_remaining"] == 0
    with pytest.raises(RuleError):
        restored.session(token)
    with pytest.raises(RuleError):
        restored.complete_mfa_login(challenge, auth.totp(secret, clock[0] // 30), "test")
    with restored.transaction(False) as c:
        assert "pending" not in json.loads(restored._user(c, users["reviewer"]["id"])["security"])
    clock[0] += 90
    assert signin(restored, clock, secret)
    check_database(restored)


def test_real_schema3_shape_upgrade_preserves_event_bytes_and_revokes_sessions(env):
    store, users, _, d = env
    case = d.issued("SCHEMA3-TO4")
    old_events = copy.deepcopy(store.evidence(users["examiner"], case["id"])[1])
    token, _, _ = store.login("examiner", PASSWORD, "test")
    with store.transaction() as c:
        c.execute("DROP TABLE session_context")
        c.execute("DROP TABLE login_challenges")
        c.execute("ALTER TABLE users DROP COLUMN security")
        for row in c.execute("SELECT * FROM users").fetchall():
            store._seal_identity(c, "user", row["id"], row)
        c.execute("UPDATE meta SET value='3' WHERE name='schema'")
    with pytest.raises(RuleError, match="upgrade"):
        Store(store.path)
    assert migrate(store.path)["schema"] == 4
    assert not migrate(store.path)["changed"]
    upgraded = Store(store.path)
    assert upgraded.evidence(users["examiner"], case["id"])[1] == old_events
    assert upgraded.get_case(users["examiner"], case["id"]) == case
    with pytest.raises(RuleError):
        upgraded.session(token)
    check_database(upgraded)


def test_mfa_policy_configuration_fails_closed(env, monkeypatch):
    monkeypatch.setenv("OV_REQUIRE_MFA", "typo")
    with pytest.raises(RuleError, match="OV_REQUIRE_MFA"):
        create_app(env[0].path, "http://localhost", True)
