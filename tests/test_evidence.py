import base64
import copy
import io
import json
import sqlite3
from contextlib import closing
import zipfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openviscera.documents import document
from openviscera.domain import RuleError
from openviscera.evidence import (check_database, encrypted_backup, export_bundle, restore_backup, verify_bundle)
from openviscera.store import Store


def test_signed_export_pinned_key_and_head(env):
    store, users, _, d = env
    s = d.issued("SIGNED")
    bundle = export_bundle(store, users["examiner"], s["id"])
    result = verify_bundle(bundle, store.public_b64)
    assert result["valid"] and result["key_pinned"] and not result["checkpoint_pinned"]
    assert verify_bundle(bundle, store.public_b64, result["head"])["checkpoint_pinned"]
    with pytest.raises(RuleError, match="checkpoint"):
        verify_bundle(bundle, store.public_b64, "0" * 64)


def test_bundle_cannot_substitute_its_own_signing_key(env):
    store, users, _, d = env
    s = d.reported("WRONG-KEY")
    bundle = export_bundle(store, users["examiner"], s["id"])
    other = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    with pytest.raises(RuleError, match="signed evidence bundle"):
        verify_bundle(bundle, base64.b64encode(other).decode())


@pytest.mark.parametrize("member", ["case.json", "events.json", "manifest.json", "manifest.sig", "attachment"])
def test_bundle_detects_modified_members(env, member):
    store, users, _, d = env
    s = d.reported("MODIFIED")
    content = export_bundle(store, users["examiner"], s["id"])
    result = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(content)) as old, zipfile.ZipFile(result, "w") as changed:
        for name in old.namelist():
            data = old.read(name)
            if name == member or member == "attachment" and name.startswith("files/"):
                data += b"changed"
            changed.writestr(name, data)
    with pytest.raises(RuleError):
        verify_bundle(result.getvalue(), store.public_b64)


@pytest.mark.parametrize("path", ["../outside", "/absolute", "files/../../outside", "files\\escape"])
def test_bundle_rejects_path_traversal(env, path):
    store, users, _, d = env
    s = d.new("PATH")
    content = export_bundle(store, users["examiner"], s["id"])
    result = io.BytesIO(content)
    with zipfile.ZipFile(result, "a") as archive:
        archive.writestr(path, b"unsafe")
    with pytest.raises(RuleError, match="Unsafe ZIP"):
        verify_bundle(result.getvalue(), store.public_b64)


def test_append_only_database_triggers(env):
    store, _, _, d = env
    d.new("APPEND")
    with closing(sqlite3.connect(store.db)) as c, c:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            c.execute("UPDATE events SET hash='changed'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            c.execute("DELETE FROM events")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            c.execute("DELETE FROM administrative_events")


def test_altered_projection_is_detected(env):
    store, users, _, d = env
    s = d.new("PROJECTION")
    with closing(sqlite3.connect(store.db)) as c, c:
        altered = copy.deepcopy(s)
        altered["authority"] = "Unauthorized modification"
        c.execute("UPDATE cases SET state=? WHERE id=?", (json.dumps(altered), s["id"]))
    with pytest.raises(RuleError, match="projection differs"):
        store.get_case(users["examiner"], s["id"])


def test_modified_org_index_cannot_disclose_case(env):
    store, users, _, d = env
    s = d.new("ROW-ORG")
    with closing(sqlite3.connect(store.db)) as c, c:
        c.execute("UPDATE cases SET org_id='org-b' WHERE id=?", (s["id"],))
    with pytest.raises(RuleError, match="identity projection mismatch"):
        store.get_case(users["outsider"], s["id"])


def test_modified_event_detected_even_after_trigger_removed(env):
    store, _, _, d = env
    d.new("EVENT")
    with closing(sqlite3.connect(store.db)) as c, c:
        c.execute("DROP TRIGGER no_event_update")
        c.execute("UPDATE events SET signature=?", (base64.b64encode(b"x" * 64).decode(),))
    with pytest.raises(RuleError, match="signature"):
        check_database(store)


def test_truncation_against_retained_projection_detected(env):
    store, users, _, d = env
    s = d.collected("TRUNCATED")
    with closing(sqlite3.connect(store.db)) as c, c:
        c.execute("DROP TRIGGER no_event_delete")
        c.execute("DELETE FROM events WHERE case_id=? AND seq=2", (s["id"],))
    with pytest.raises(RuleError, match="projection differs"):
        store.get_case(users["examiner"], s["id"])


def test_missing_blob_detected(env):
    store, _, _, d = env
    d.reported("MISSING-BLOB")
    with closing(sqlite3.connect(store.db)) as c, c:
        c.execute("DELETE FROM blobs")
    with pytest.raises(RuleError, match="Attachment integrity"):
        check_database(store)


def test_container_registry_tampering_detected(env):
    store, _, _, d = env
    d.collected("REGISTRY")
    with closing(sqlite3.connect(store.db)) as c, c:
        c.execute("DELETE FROM containers")
    with pytest.raises(RuleError, match="registry mismatch"):
        check_database(store)


def test_identity_role_tampering_detected(env):
    store, users, _, _ = env
    with closing(sqlite3.connect(store.db)) as c, c:
        c.execute("UPDATE users SET role='admin' WHERE id=?", (users["examiner"]["id"],))
    with pytest.raises(RuleError, match="Identity store integrity"):
        store.login("examiner", "synthetic-test-password-123", "127.0.0.1")


def test_injected_session_is_not_accepted(env):
    import hashlib
    import time
    store, users, _, _ = env
    token = "attacker-controlled-session"
    with closing(sqlite3.connect(store.db)) as c, c:
        c.execute("INSERT INTO sessions VALUES (?,?,?,?)", (hashlib.sha256(token.encode()).hexdigest(),
                  users["admin"]["id"], "forged-csrf", int(time.time()) + 1000))
    with pytest.raises(RuleError, match="Identity store integrity"):
        store.session(token)


def test_backup_restore_and_session_invalidation(env, tmp_path):
    store, users, _, d = env
    s = d.issued("BACKUP")
    token, _, _ = store.login("examiner", "synthetic-test-password-123", "127.0.0.1")
    content = encrypted_backup(store, "synthetic-backup-password")
    assert not content.startswith(b"SQLite")
    restored = restore_backup(content, "synthetic-backup-password", tmp_path / "restored")
    assert restored.get_case(users["examiner"], s["id"]) == s
    with pytest.raises(RuleError) as error:
        restored.session(token)
    assert error.value.status == 401
    assert check_database(restored)["heads"] == check_database(store)["heads"]


def test_backup_rejects_wrong_password_tampering_and_overwrite(env, tmp_path):
    store, _, _, d = env
    d.new("BACKUP-ERROR")
    content = encrypted_backup(store, "synthetic-backup-password")
    for data, password in [(content, "different-passphrase"), (content[:-1] + bytes([content[-1] ^ 1]), "synthetic-backup-password")]:
        with pytest.raises(RuleError, match="passphrase or modified"):
            restore_backup(data, password, tmp_path / "bad-restore")
        assert not (tmp_path / "bad-restore").exists()
    with pytest.raises(RuleError, match="must not exist"):
        restore_backup(content, "synthetic-backup-password", store.path)


def test_initialize_refuses_existing_data(env):
    store, _, _, _ = env
    with pytest.raises(RuleError, match="overwrite"):
        Store.initialize(store.path)


@pytest.mark.parametrize("kind", ["label", "dispatch", "receipt", "chronology", "opinion"])
def test_pdf_exports_are_valid_pdf(env, kind):
    store, users, _, d = env
    s = d.issued("PDF")
    identifiers = {"label": s["specimens"][0]["id"], "dispatch": s["transfers"][0]["id"],
                   "receipt": s["transfers"][0]["id"], "opinion": s["opinions"][0]["id"], "chronology": None}
    _, events, _, _ = store.evidence(users["examiner"], s["id"])
    content = document(s, kind, identifiers[kind], events)
    assert content.startswith(b"%PDF-")
    assert content.rstrip().endswith(b"%%EOF")


def test_unicode_pdf_fails_loudly_without_configured_font(env, monkeypatch):
    _, _, _, d = env
    s = d.collected("UNICODE")
    s["specimens"][0]["description"] = "தமிழ்"
    monkeypatch.delenv("OV_PDF_FONT", raising=False)
    with pytest.raises(RuleError, match="Unicode font"):
        document(s, "label", s["specimens"][0]["id"])
