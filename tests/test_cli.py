import json

import pytest

from openviscera.cli import main
from openviscera.domain import RuleError, now_iso
from openviscera.evidence import export_bundle
from openviscera.store import Store


def test_initialization_and_refusal_to_overwrite(tmp_path, monkeypatch):
    monkeypatch.setattr("getpass.getpass", lambda prompt: "synthetic-password-123")
    target = tmp_path / "initialized"
    args = ["init", "--data", str(target), "--department", "synthetic"]
    assert main(args) == 0
    assert main(args) == 1
    assert Store(target).login("admin", "synthetic-password-123", "local")


@pytest.mark.parametrize("passwords", [["short", "short"], ["synthetic-password-123", "different-password"]])
def test_init_password_validation(tmp_path, monkeypatch, passwords):
    values = iter(passwords)
    monkeypatch.setattr("getpass.getpass", lambda prompt: next(values))
    target = tmp_path / "bad"
    assert main(["init", "--data", str(target)]) == 1
    assert not target.exists()


def test_verify_and_checkpoint_commands(env, tmp_path, capsys):
    store, users, _, d = env
    s = d.issued("CLI")
    bundle = tmp_path / "evidence.zip"
    bundle.write_bytes(export_bundle(store, users["examiner"], s["id"]))
    assert main(["verify", str(bundle), "--public-key", str(store.path / "public-key.txt")]) == 0
    assert json.loads(capsys.readouterr().out)["valid"]
    checkpoint = tmp_path / "checkpoint.json"
    args = ["audit", "--data", str(store.path), "--output", str(checkpoint)]
    assert main(args) == 0
    assert main(args) == 1
    assert s["id"] in json.loads(checkpoint.read_text())["checkpoint"]["heads"]


def test_backup_restore_commands(env, tmp_path, monkeypatch):
    store, _, _, d = env
    d.issued("BACKUP-CLI")
    monkeypatch.setattr("getpass.getpass", lambda prompt: "synthetic-backup-passphrase")
    backup = tmp_path / "backup.ovb"
    args = ["backup", "--data", str(store.path), "--output", str(backup)]
    assert main(args) == 0
    assert main(args) == 1
    target = tmp_path / "restored"
    assert main(["restore", str(backup), "--data", str(target)]) == 0
    assert main(["restore", str(backup), "--data", str(target)]) == 1


def test_demo_command_random_credentials(tmp_path, capsys):
    target = tmp_path / "demo"
    assert main(["demo", "--data", str(target)]) == 0
    output = capsys.readouterr().out
    assert "SYNTHETIC DEMONSTRATION ONLY" in output
    assert "examiner:" in output and "synthetic-test-password-123" not in output
    assert main(["demo", "--data", str(target)]) == 1


def test_serve_configuration_and_unsafe_binding(env, monkeypatch):
    store, _, _, _ = env
    calls = []
    monkeypatch.setattr("uvicorn.run", lambda *a, **kw: calls.append((a, kw)))
    assert main(["serve", "--data", str(store.path), "--insecure-local"]) == 0
    assert calls[0][1]["host"] == "127.0.0.1"
    assert calls[0][1]["proxy_headers"] is False
    assert main(["serve", "--data", str(store.path), "--insecure-local", "--host", "0.0.0.0"]) == 1
    assert len(calls) == 1


def test_duplicate_report_bytes_cannot_be_new_revision(env):
    _, _, _, d = env
    s = d.reported("DUPLICATE-PDF")
    a = s["attachments"][-1]
    with d.store.transaction(False) as c:
        content = c.execute("SELECT content FROM blobs WHERE hash=?", (a["sha256"],)).fetchone()[0]
    s = d.attachment(s["id"], s["specimens"][0]["id"], content=content)
    with pytest.raises(RuleError, match="Identical report"):
        d.do(s["id"], "report", {"request_id": s["requests"][0]["id"], "attachment_id": s["attachments"][-1]["id"],
                           "laboratory_reference": "SAME-BYTES", "received_at": now_iso(),
                           "supersedes": s["reports"][-1]["id"]})
