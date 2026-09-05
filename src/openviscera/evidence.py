"""Portable evidence bundles, bounded verification and authenticated encrypted backups."""
import base64
import hashlib
import io
import json
import os
import secrets
import sqlite3
import tempfile
import zipfile
from pathlib import Path
from contextlib import closing

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .domain import RuleError, canonical, digest, normalized, now_iso, require
from .store import Store, verify_events

MAX_BUNDLE = 100 * 1024 * 1024


def export_bundle(store, actor, case_id):
    state, events, files, head = store.evidence(actor, case_id)
    files.update({"case.json": canonical(state), "events.json": canonical(events)})
    require(sum(len(v) for v in files.values()) <= MAX_BUNDLE, "Case exceeds the 100 MiB bundle limit")
    manifest = {"format": "openviscera-evidence-v1", "case_id": case_id, "exported_at": now_iso(),
                "head": head, "sequence": len(events), "public_key": store.public_b64,
                "files": {name: {"sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
                          for name, content in sorted(files.items())}}
    payload = canonical(manifest)
    require(len(files) + 2 <= 1000, "Too many evidence bundle entries")
    require(sum(len(v) for v in files.values()) + len(payload) + 88 <= MAX_BUNDLE, "Bundle metadata exceeds limit")
    files["manifest.json"] = payload
    files["manifest.sig"] = base64.b64encode(store.key.sign(payload))
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(files.items()):
            archive.writestr(name, content)
    content = output.getvalue()
    require(len(content) <= MAX_BUNDLE, "Compressed bundle exceeds limit")
    return content


def verify_bundle(content, trusted_public_key, expected_head=None):
    """Never extracts ZIP members. A separately trusted public key is mandatory."""
    require(len(content) <= MAX_BUNDLE, "Bundle is too large")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(trusted_public_key.strip(), validate=True))
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            info = archive.infolist()
            names = [i.filename for i in info]
            require(len(names) == len(set(names)) and len(names) <= 1000, "Duplicate or excessive ZIP entries")
            require(sum(i.file_size for i in info) <= MAX_BUNDLE, "Uncompressed bundle exceeds limit")
            require(all(not n.startswith("/") and ".." not in n.split("/") and "\\" not in n for n in names),
                    "Unsafe ZIP member path")
            payload = archive.read("manifest.json")
            public_key.verify(base64.b64decode(archive.read("manifest.sig"), validate=True), payload)
            manifest = json.loads(payload)
            require(manifest["format"] == "openviscera-evidence-v1", "Unknown evidence bundle format")
            require(manifest["public_key"] == trusted_public_key.strip(), "Bundle key differs from trusted key")
            require(set(names) == set(manifest["files"]) | {"manifest.json", "manifest.sig"}, "Unexpected or missing ZIP entries")
            for name, entry in manifest["files"].items():
                data = archive.read(name)
                require(len(data) == entry["size"] and hashlib.sha256(data).hexdigest() == entry["sha256"],
                        "Evidence attachment/hash mismatch: " + name)
            state = json.loads(archive.read("case.json"))
            events = json.loads(archive.read("events.json"))
            head = verify_events(events, public_key, state, replay=True)
            require(head == manifest["head"] and len(events) == manifest["sequence"] and
                    state["id"] == manifest["case_id"], "Manifest does not match ledger")
            require(expected_head is None or head == expected_head, "External checkpoint does not match bundle head")
            for attachment in state["attachments"]:
                require("files/" + attachment["sha256"] in manifest["files"], "Referenced attachment missing")
            return {"valid": True, "case_id": state["id"], "events": len(events), "head": head,
                    "key_pinned": True, "checkpoint_pinned": expected_head is not None}
    except (InvalidSignature, ValueError, KeyError, zipfile.BadZipFile, TypeError) as exc:
        raise RuleError("Invalid, malformed or incorrectly signed evidence bundle") from exc


def check_database(store):
    """Replay every case and administrative chain; return heads for external retention."""
    heads = {}
    with store.transaction(False) as c:
        require(c.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "SQLite integrity check failed")
        for row in c.execute("SELECT * FROM cases ORDER BY id"):
            state = json.loads(row["state"])
            heads[row["id"]] = verify_events(store._events(c, row["id"]), store.public_key, state, replay=True)
            require(row["org_id"] == state["org_id"], "Case organization projection mismatch")
            for a in state["attachments"]:
                file = c.execute("SELECT content FROM blobs WHERE org_id=? AND hash=?", (state["org_id"], a["sha256"])).fetchone()
                require(file is not None and hashlib.sha256(file[0]).hexdigest() == a["sha256"], "Attachment integrity failure")
        expected_registry = {(s["org_id"], normalized(sp["container_id"]), s["id"], sp["id"])
                             for row in c.execute("SELECT state FROM cases") for s in [json.loads(row[0])]
                             for sp in s["specimens"]}
        actual_registry = {tuple(r) for r in c.execute("SELECT * FROM containers")}
        require(expected_registry == actual_registry, "Container uniqueness registry mismatch")
        for table, kind, identifier in [("users", "user", "id"), ("labs", "lab", "id"), ("sessions", "session", "hash")]:
            for row in c.execute("SELECT * FROM " + table):
                store._check_identity(c, kind, row[identifier], row)
        previous = "0" * 64
        for row in c.execute("SELECT * FROM administrative_events ORDER BY seq"):
            body = json.loads(row["body"])
            require(body["previous_hash"] == previous and digest(body) == row["hash"], "Administrative audit chain mismatch")
            try:
                store.public_key.verify(base64.b64decode(row["signature"], validate=True), canonical(body))
            except (InvalidSignature, ValueError) as exc:
                raise RuleError("Administrative event signature mismatch") from exc
            previous = row["hash"]
    return {"format": "openviscera-checkpoint-v1", "checked_at": now_iso(), "public_key": store.public_b64,
            "heads": heads, "administrative_head": previous}


def encrypted_backup(store, password):
    require(len(password) >= 14, "Backup passphrase must be at least 14 characters", 422)
    check_database(store)
    with tempfile.TemporaryDirectory() as temporary:
        snapshot = Path(temporary) / "snapshot.sqlite3"
        with closing(sqlite3.connect(store.db)) as source, closing(sqlite3.connect(snapshot)) as destination:
            source.backup(destination)
        require(snapshot.stat().st_size + 32 <= MAX_BUNDLE, "Backup snapshot exceeds 100 MiB limit")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("openviscera.sqlite3", snapshot.read_bytes())
            archive.writestr("signing.key", (store.path / "signing.key").read_bytes())
        plain = output.getvalue()
    require(len(plain) + 48 <= MAX_BUNDLE, "Encrypted backup exceeds 100 MiB limit")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    key = hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)
    return b"OVB1" + salt + nonce + AESGCM(key).encrypt(nonce, plain, b"OpenViscera-backup-v1")


def restore_backup(content, password, destination):
    target = Path(destination)
    require(not target.exists(), "Restore destination must not exist")
    require(content[:4] == b"OVB1" and 48 <= len(content) <= MAX_BUNDLE, "Invalid or oversized backup")
    salt, nonce = content[4:20], content[20:32]
    key = hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)
    try:
        plain = AESGCM(key).decrypt(nonce, content[32:], b"OpenViscera-backup-v1")
    except InvalidTag as exc:
        raise RuleError("Incorrect passphrase or modified backup") from exc
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target.parent) as temporary:
        stage = Path(temporary) / "restore"
        stage.mkdir(mode=0o700)
        with zipfile.ZipFile(io.BytesIO(plain)) as archive:
            require(sorted(archive.namelist()) == ["openviscera.sqlite3", "signing.key"], "Unexpected backup entries")
            require(sum(i.file_size for i in archive.infolist()) <= MAX_BUNDLE, "Backup expands beyond limit")
            for name in archive.namelist():
                (stage / name).write_bytes(archive.read(name))
                os.chmod(stage / name, 0o600)
        restored = Store(stage)
        check_database(restored)
        # Sessions are intentionally invalidated on restore.
        with restored.transaction() as c:
            c.execute("DELETE FROM sessions")
        (stage / "public-key.txt").write_text(restored.public_b64 + "\n")
        require(not target.exists(), "Restore target appeared during validation")
        stage.rename(target)
    return Store(target)
