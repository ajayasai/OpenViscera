"""Synthetic lifecycle gates, independent review, authorization and replay regressions."""
import base64
import copy
import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from openviscera import domain_v2
from openviscera.app import create_app, queue_snapshot
from openviscera.domain import (RuleError, active_holds, canonical, digest, disposed, evidence_fingerprint,
                               lifecycle_snapshot, now_iso, opinion_pending, retention)
from openviscera.evidence import check_database, export_bundle, verify_bundle, encrypted_backup, restore_backup
from openviscera.migrations import migrate
from openviscera.store import Store

PASSWORD = "synthetic-test-password-123"


def ready(d, ref="LIFECYCLE"):
    """Current reviewed evidence, returned to local custody BEFORE issuing an opinion."""
    s = d.reviewed(ref)
    sid = s["specimens"][0]["id"]
    s = d.do(s["id"], "handover", {"specimen_id": sid, "recipient_id": d.users["examiner"]["id"],
            "occurred_at": now_iso(), "destination": "Synthetic retained-specimen store", "note": "Documented return"}, "lab")
    s = d.do(s["id"], "acknowledge", {"transfer_id": s["transfers"][-1]["id"], "occurred_at": now_iso(),
            "observed_seal": "SYNTHETIC-SEAL-01", "note": "Accepted local custody"})
    s = d.do(s["id"], "draft", {"kind": "final", "body": "Synthetic human-authored opinion only.",
            "report_ids": [r["id"] for r in s["reports"]]})
    oid = s["opinions"][-1]["id"]
    d.do(s["id"], "approve", {"opinion_id": oid}, "reviewer")
    return d.do(s["id"], "issue", {"opinion_id": oid})


def plan(d, s, until=None):
    s = d.do(s["id"], "propose_retention", {"specimen_id": s["specimens"][0]["id"],
        "retain_until": until or d.due, "authority_reference": "SYNTHETIC-POLICY-ONLY", "reason": "Human-entered test instruction"})
    return d.do(s["id"], "decide_retention", {"retention_id": s["controls"]["retentions"][-1]["id"],
        "decision": "approve", "reason": "Independent synthetic review"}, "reviewer")


def propose(d, s):
    return d.do(s["id"], "propose_disposal", {"specimen_id": s["specimens"][0]["id"],
        "authority_reference": "SYNTHETIC-AUTHORITY", "method": "Synthetic authorized method", "reason": "Test proposal only"})


def approve(d, s):
    return d.do(s["id"], "decide_disposal", {"disposal_id": s["controls"]["disposals"][-1]["id"],
        "decision": "approve", "reason": "Independently verified test instruction"}, "reviewer")


def attach_certificate(d, s, specimen_id=None, purpose="administrative"):
    actor = d.users["examiner"]
    content = b"Synthetic administrative certificate - not real case evidence."
    return d.store.command(actor, s["id"], "attach", {"specimen_id": specimen_id or s["specimens"][0]["id"],
        "filename": "synthetic-certificate.txt", "media_type": "text/plain", "purpose": purpose,
        "size": len(content), "sha256": hashlib.sha256(content).hexdigest()},
        s["version"], uuid.uuid4().hex, blob=content)["case"]


def execution_data(s):
    return {"disposal_id": s["controls"]["disposals"][-1]["id"], "attachment_id": s["attachments"][-1]["id"],
            "occurred_at": now_iso(), "note": "Synthetic completion record; no physical action performed."}


def hold(d, s, case_wide=False, role="coordinator"):
    return d.do(s["id"], "place_hold", {"specimen_id": None if case_wide else s["specimens"][0]["id"],
        "authority_reference": "SYNTHETIC-HOLD", "reason": "Preserve pending external instruction"}, role)


def release(d, s, role="coordinator"):
    s = d.do(s["id"], "request_hold_release", {"hold_id": s["controls"]["holds"][-1]["id"],
        "authority_reference": "SYNTHETIC-RELEASE", "reason": "Documented release requested"}, role)
    return d.do(s["id"], "decide_hold_release", {"release_id": s["controls"]["hold_releases"][-1]["id"],
        "decision": "approve", "reason": "Independent release review"}, "reviewer")


def test_retention_and_holds_do_not_rewrite_or_stale_issued_opinion(env):
    store, _, _, d = env
    s = ready(d)
    before = copy.deepcopy(s["opinions"])
    fingerprint = evidence_fingerprint(s)
    s = hold(d, plan(d, s))
    assert evidence_fingerprint(s) == fingerprint and not opinion_pending(s)
    assert s["opinions"] == before
    s = release(d, s)
    assert s["opinions"] == before and not opinion_pending(s)
    assert not active_holds(s, s["specimens"][0]["id"])
    check_database(store)


def test_complete_disposal_keeps_all_evidence_and_closes_physical_workflow(env):
    store, users, _, d = env
    s = approve(d, propose(d, plan(d, ready(d))))
    before = copy.deepcopy(s)
    s = attach_certificate(d, s)
    assert not opinion_pending(s)
    data = execution_data(s)
    key = uuid.uuid4().hex
    result = store.command(users["examiner"], s["id"], "record_disposal", data, s["version"], key)
    replay = store.command(users["examiner"], s["id"], "record_disposal", data, s["version"], key)
    s = result["case"]
    sid = s["specimens"][0]["id"]
    assert replay["replayed"] and replay["event_id"] == result["event_id"]
    assert disposed(s, sid) and not opinion_pending(s)
    for field in ["specimens", "reports", "opinions", "transfers"]:
        assert s[field] == before[field]
    assert len(s["attachments"]) == len(before["attachments"]) + 1
    view = lifecycle_snapshot(s, actor_id=users["examiner"]["id"])["specimens"][0]
    assert view["disposed"] and not view["eligible_for_proposal"] and not view["retention_due"]
    assert queue_snapshot([s], users["examiner"])["counts"]["lifecycle"] == 0
    bundle = export_bundle(store, users["examiner"], s["id"])
    assert verify_bundle(bundle, store.public_b64)["valid"]
    check_database(store)


@pytest.mark.parametrize("action,data", [
    ("seal", {"seal_ref": "NEW", "reason": "Must not resume"}),
    ("handover", {"destination": "Elsewhere", "note": "Must not resume"}),
    ("request", {"examination": "Another examination"}),
    ("record_return", {"external_sender_name": "Synthetic sender", "observed_seal": "OLD", "destination": "Here", "note": "Must not resume"}),
])
def test_disposed_specimen_cannot_restart_physical_steps(env, action, data):
    _, users, lab, d = env
    s = attach_certificate(d, approve(d, propose(d, plan(d, ready(d)))))
    s = d.do(s["id"], "record_disposal", execution_data(s))
    data = {**data, "specimen_id": s["specimens"][0]["id"]}
    if action == "request":
        data.update(lab_id=lab["id"], due_at=now_iso())
    else:
        data["occurred_at"] = now_iso()
    if action == "handover":
        data["recipient_id"] = users["courier"]["id"]
    if action == "record_return":
        data["attachment_id"] = s["attachments"][-1]["id"]
    with pytest.raises(RuleError, match="disposed"):
        d.do(s["id"], action, data)


def test_disposal_blocked_without_policy_or_current_opinion(env):
    _, _, _, d = env
    s = ready(d)
    with pytest.raises(RuleError, match="retention instruction"):
        propose(d, s)
    s = plan(d, s)
    s = d.do(s["id"], "note", {"text": "Additional evidence requiring a supplementary opinion"})
    with pytest.raises(RuleError, match="current issued opinion"):
        propose(d, s)


@pytest.mark.parametrize("case_wide", [False, True])
def test_active_hold_blocks_even_when_deadline_elapsed(env, case_wide):
    _, _, _, d = env
    s = hold(d, plan(d, ready(d)), case_wide)
    with pytest.raises(RuleError, match="preservation hold"):
        propose(d, s)
    s = release(d, s)
    assert propose(d, s)["controls"]["disposals"][-1]["status"] == "pending"


def test_case_hold_covers_specimens_collected_after_placement(env):
    _, _, _, d = env
    s = hold(d, d.collected("CASE-HOLD"), case_wide=True)
    s = d.do(s["id"], "collect", {"container_id": "SECOND", "description": "Synthetic later specimen", "quantity": "1",
        "unit": "container", "preservative": "Human entry", "collected_at": now_iso(), "location": "Collection room"})
    assert active_holds(s, s["specimens"][-1]["id"])


def test_hold_release_needs_independent_reviewer_and_rejection_preserves_hold(env):
    _, _, _, d = env
    s = hold(d, d.collected("SELF-RELEASE"), role="reviewer")
    s = d.do(s["id"], "request_hold_release", {"hold_id": s["controls"]["holds"][0]["id"],
        "authority_reference": "TEST-RELEASE", "reason": "Request by reviewer"}, "reviewer")
    data = {"release_id": s["controls"]["hold_releases"][0]["id"], "decision": "approve", "reason": "Cannot approve self"}
    with pytest.raises(RuleError, match="independent reviewer"):
        d.do(s["id"], "decide_hold_release", data, "reviewer")
    other = d.store.add_user("org-a", {"username": "second_reviewer", "display_name": "Second reviewer", "role": "reviewer", "password": PASSWORD})
    s = d.do(s["id"], "decide_hold_release", {**data, "decision": "reject"}, other)
    assert active_holds(s, s["specimens"][0]["id"])
    assert s["controls"]["hold_releases"][0]["status"] == "rejected"


def test_future_retention_and_pending_shortening_block_disposal(env):
    _, _, _, d = env
    future = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
    s = plan(d, ready(d), future)
    with pytest.raises(RuleError, match="deadline has not elapsed"):
        propose(d, s)
    s = d.do(s["id"], "propose_retention", {"specimen_id": s["specimens"][0]["id"], "retain_until": d.due,
        "authority_reference": "SHORTENING-REQUEST", "reason": "Requires review"})
    assert datetime.fromisoformat(retention(s, s["specimens"][0]["id"])["retain_until"]) == datetime.fromisoformat(future)
    with pytest.raises(RuleError, match="Retention change awaiting"):
        propose(d, s)


def test_retention_before_collection_and_naive_datetimes_rejected(env):
    _, _, _, d = env
    s = d.collected("BAD-RETENTION")
    common = {"specimen_id": s["specimens"][0]["id"], "authority_reference": "TEST", "reason": "Invalid date"}
    for value in ["2000-01-01T00:00:00+00:00", "2026-10-01T12:00:00"]:
        with pytest.raises(RuleError) as error:
            d.do(s["id"], "propose_retention", {**common, "retain_until": value})
        assert error.value.status == 422


@pytest.mark.parametrize("change", ["note", "hold_release", "retention", "reviewer_deactivated"])
def test_disposal_execution_rechecks_all_gates_and_approval(env, change):
    store, users, _, d = env
    s = attach_certificate(d, approve(d, propose(d, plan(d, ready(d)))))
    if change == "note":
        s = d.do(s["id"], "note", {"text": "New substantive evidence"})
    elif change == "hold_release":
        s = release(d, hold(d, s))
    elif change == "retention":
        s = plan(d, s)
    else:
        store.set_active(users["admin"], users["reviewer"]["id"], False)
    with pytest.raises(RuleError):
        d.do(s["id"], "record_disposal", execution_data(s))
    assert not disposed(store.get_case(users["examiner"], s["id"]), s["specimens"][0]["id"])


def test_stale_disposal_can_be_cancelled_and_freshly_reapproved(env):
    _, _, _, d = env
    s = approve(d, propose(d, plan(d, ready(d))))
    old = s["controls"]["disposals"][-1]["id"]
    s = release(d, hold(d, s))
    assert lifecycle_snapshot(s)["specimens"][0]["proposal_stale"]
    with pytest.raises(RuleError, match="outstanding disposal"):
        propose(d, s)
    s = d.do(s["id"], "cancel_disposal", {"disposal_id": old, "reason": "Fresh review after hold release"})
    s = approve(d, propose(d, s))
    assert s["controls"]["disposals"][0]["status"] == "cancelled"
    assert s["controls"]["disposals"][-1]["status"] == "approved"


def test_explicit_rejection_and_duplicate_decision(env):
    _, _, _, d = env
    s = propose(d, plan(d, ready(d)))
    data = {"disposal_id": s["controls"]["disposals"][-1]["id"], "decision": "reject", "reason": "Authority insufficient"}
    s = d.do(s["id"], "decide_disposal", data, "reviewer")
    with pytest.raises(RuleError, match="already decided"):
        d.do(s["id"], "decide_disposal", data, "reviewer")
    assert propose(d, s)["controls"]["disposals"][-1]["status"] == "pending"


def test_disposal_requires_certificate_and_post_approval_actual_time(env):
    _, _, _, d = env
    s = approve(d, propose(d, plan(d, ready(d))))
    with pytest.raises(RuleError, match="administrative certificate"):
        d.do(s["id"], "record_disposal", execution_data(s))
    s = attach_certificate(d, s)
    with pytest.raises(RuleError, match="precedes"):
        d.do(s["id"], "record_disposal", {**execution_data(s), "occurred_at": d.past})
    with pytest.raises(RuleError, match="future"):
        d.do(s["id"], "record_disposal", {**execution_data(s), "occurred_at": "2099-01-01T00:00:00Z"})


def test_administrative_attachment_cannot_be_used_as_report(env):
    _, _, _, d = env
    s = d.received("ADMIN-AS-REPORT")
    from openviscera.demo import sample_pdf
    content = sample_pdf("SYNTHETIC ADMINISTRATIVE DOCUMENT")
    s = d.store.command(d.users["examiner"], s["id"], "attach", {"specimen_id": s["specimens"][0]["id"],
        "filename": "admin.pdf", "media_type": "application/pdf", "purpose": "administrative", "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest()}, s["version"], uuid.uuid4().hex, blob=content)["case"]
    with pytest.raises(RuleError, match="Administrative attachment"):
        d.do(s["id"], "report", {"request_id": s["requests"][0]["id"], "attachment_id": s["attachments"][-1]["id"],
            "laboratory_reference": "CANNOT-BE-REPORT", "received_at": now_iso()})


def test_late_report_after_disposal_reopens_opinion_but_not_physical_inventory(env):
    _, _, _, d = env
    s = attach_certificate(d, approve(d, propose(d, plan(d, ready(d)))))
    s = d.do(s["id"], "record_disposal", execution_data(s))
    old = copy.deepcopy(s["opinions"])
    s = d.add_report(s)
    assert opinion_pending(s) and disposed(s, s["specimens"][0]["id"])
    assert s["opinions"] == old


def test_hold_vs_disposal_race_cannot_commit_both(env):
    store, users, _, d = env
    s = attach_certificate(d, approve(d, propose(d, plan(d, ready(d)))))
    sid = s["specimens"][0]["id"]
    commands = [("record_disposal", execution_data(s)), ("place_hold", {"specimen_id": sid,
                "authority_reference": "URGENT-SYNTHETIC-HOLD", "reason": "Concurrent preservation instruction"})]
    def submit(command):
        try:
            store.command(users["examiner"], s["id"], *command, s["version"], uuid.uuid4().hex)
            return True
        except RuleError:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(submit, commands)) == 1
    final = store.get_case(users["examiner"], s["id"])
    assert not (disposed(final, sid) and active_holds(final, sid))
    check_database(store)


def test_reassignment_needs_active_target_and_independent_review(env):
    store, users, _, d = env
    s = ready(d)
    original = copy.deepcopy(s["opinions"])
    s = d.do(s["id"], "propose_reassignment", {"new_examiner_id": users["other_examiner"]["id"], "reason": "Recorded handover of responsibility"})
    assert s["examiner_id"] == users["examiner"]["id"]
    rid = s["controls"]["reassignments"][-1]["id"]
    with pytest.raises(RuleError) as error:
        d.do(s["id"], "decide_reassignment", {"reassignment_id": rid, "decision": "approve", "reason": "Cannot approve own request"})
    assert error.value.status == 403
    s = d.do(s["id"], "decide_reassignment", {"reassignment_id": rid, "decision": "approve", "reason": "Independent appointment review"}, "reviewer")
    assert s["examiner_id"] == users["other_examiner"]["id"] and s["opinions"] == original
    assert opinion_pending(s)
    with pytest.raises(RuleError, match="assigned examiner"):
        d.do(s["id"], "draft", {"kind": "supplementary", "report_ids": [r["id"] for r in s["reports"]], "body": "Former examiner cannot draft"})
    s = d.do(s["id"], "draft", {"kind": "supplementary", "report_ids": [r["id"] for r in s["reports"]], "body": "New examiner human-authored opinion"}, "other_examiner")
    oid = s["opinions"][-1]["id"]
    d.do(s["id"], "approve", {"opinion_id": oid}, "reviewer")
    s = d.do(s["id"], "issue", {"opinion_id": oid}, "other_examiner")
    assert not opinion_pending(s)
    check_database(store)


@pytest.mark.parametrize("role", ["outsider", "reviewer", "examiner"])
def test_invalid_reassignment_target(env, role):
    _, users, _, d = env
    s = d.collected("BAD-TARGET")
    with pytest.raises(RuleError):
        d.do(s["id"], "propose_reassignment", {"new_examiner_id": users[role]["id"], "reason": "Invalid target test"})


def test_reassignment_rechecks_active_target_at_approval(env):
    store, users, _, d = env
    s = d.collected("DEACTIVATED-TARGET")
    s = d.do(s["id"], "propose_reassignment", {"new_examiner_id": users["other_examiner"]["id"], "reason": "Proposed assignment"})
    store.set_active(users["admin"], users["other_examiner"]["id"], False)
    with pytest.raises(RuleError, match="active department examiner"):
        d.do(s["id"], "decide_reassignment", {"reassignment_id": s["controls"]["reassignments"][-1]["id"],
            "decision": "approve", "reason": "Cannot assign inactive account"}, "reviewer")


def test_reassignment_restricted_case_requires_explicit_membership(env):
    _, users, _, d = env
    s = d.collected("RESTRICTED-TARGET")
    s = d.do(s["id"], "access_policy", {"mode": "restricted", "member_ids": [users[x]["id"] for x in ["examiner", "reviewer"]], "reason": "Restricted case"})
    with pytest.raises(RuleError, match="explicit case access"):
        d.do(s["id"], "propose_reassignment", {"new_examiner_id": users["other_examiner"]["id"], "reason": "Must grant membership first"})


def test_lab_cannot_read_lifecycle_or_admin_certificates(env):
    store, users, _, d = env
    s = attach_certificate(d, hold(d, plan(d, ready(d))))
    lab = store.get_case(users["lab"], s["id"])
    assert not any(name in lab.get("controls", {}) for name in ["holds", "retentions", "disposals", "reassignments"])
    assert all(a.get("purpose") != "administrative" for a in lab["attachments"])
    assert queue_snapshot([lab], users["lab"])["counts"]["lifecycle"] == 0
    with TestClient(create_app(store.path, "http://localhost", True), base_url="http://localhost") as client:
        response = client.post("/api/login", json={"username": "lab", "password": PASSWORD})
        client.headers["X-CSRF-Token"] = response.json()["csrf"]
        response = client.get("/api/cases/" + s["id"])
        assert response.json()["lifecycle"] is None and "SYNTHETIC-HOLD" not in response.text
        assert client.get(f'/api/cases/{s["id"]}/attachments/{s["attachments"][-1]["id"]}').status_code == 404
        body = {"purpose": "administrative", "expected_version": s["version"], "specimen_id": s["specimens"][0]["id"],
                "filename": "certificate.txt", "media_type": "text/plain", "content_b64": base64.b64encode(b"Test").decode()}
        assert client.post(f'/api/cases/{s["id"]}/attachments', json=body, headers={"Idempotency-Key": uuid.uuid4().hex}).status_code == 403


@pytest.mark.parametrize("role", ["auditor", "lab", "courier", "admin"])
def test_disposal_role_boundary(env, role):
    _, _, _, d = env
    s = plan(d, ready(d))
    with pytest.raises(RuleError) as error:
        d.do(s["id"], "propose_disposal", {"specimen_id": s["specimens"][0]["id"],
            "authority_reference": "TEST", "method": "TEST", "reason": "Disallowed role"}, role)
    assert error.value.status == 403


def v2_append(self, c, actor, case_id, old, action, data):
    data = {k: v for k, v in data.items() if k != "purpose"}
    eid, recorded = uuid.uuid4().hex, now_iso()
    state = domain_v2.apply(old, action, data, actor, recorded, eid, case_id, schema=2)
    last = c.execute("SELECT hash FROM events WHERE case_id=? ORDER BY seq DESC LIMIT 1", (case_id,)).fetchone()
    body = {"schema": 2, "case_id": case_id, "seq": state["version"], "event_id": eid, "actor": actor,
            "recorded_at": recorded, "action": action, "data": data,
            "previous_hash": last["hash"] if last else "0" * 64, "after_digest": digest(state)}
    c.execute("INSERT INTO events VALUES (?,?,?,?,?)", (case_id, state["version"], canonical(body).decode(), digest(body),
              base64.b64encode(self.key.sign(canonical(body))).decode()))
    c.execute("UPDATE cases SET state=? WHERE id=?", (canonical(state).decode(), case_id))
    if action == "collect":
        c.execute("INSERT INTO containers VALUES (?,?,?,?)", (actor["org_id"], domain_v2.normalized(data["container_id"]), case_id, eid))
    return state, eid


def test_v2_migration_preserves_signatures_issued_records_and_old_bundle(env, monkeypatch):
    store, users, _, d = env
    with monkeypatch.context() as patch:
        patch.setattr(Store, "_append", v2_append)
        s = d.issued("V2-HISTORICAL")
    with store.transaction() as c:
        c.execute("UPDATE meta SET value='2' WHERE name='schema'")
    old_events = store.evidence(users["examiner"], s["id"])[1]
    old_state = canonical(s)
    bundle = export_bundle(store, users["examiner"], s["id"])
    with pytest.raises(RuleError, match="upgrade required"):
        Store(store.path)
    result = migrate(store.path)
    assert result["schema"] == 4 and result["changed"]
    assert canonical(store.get_case(users["examiner"], s["id"])) == old_state
    assert store.evidence(users["examiner"], s["id"])[1] == old_events
    assert verify_bundle(bundle, store.public_b64)["valid"]
    assert not opinion_pending(s) and not migrate(store.path)["changed"]
    s = hold(d, s)
    events = store.evidence(users["examiner"], s["id"])[1]
    assert events[:-1] == old_events and events[-1]["body"]["schema"] == 3
    assert not opinion_pending(s)
    check_database(store)


def test_lifecycle_survives_encrypted_backup_restore(env, tmp_path):
    store, users, _, d = env
    s = attach_certificate(d, approve(d, propose(d, plan(d, ready(d)))))
    s = d.do(s["id"], "record_disposal", execution_data(s))
    backup = encrypted_backup(store, "synthetic-recovery-passphrase")
    restored = restore_backup(backup, "synthetic-recovery-passphrase", tmp_path / "restored")
    assert canonical(restored.get_case(users["examiner"], s["id"])) == canonical(s)
    check_database(restored)


def test_frozen_v2_reducer_matches_original_main_source():
    assert hashlib.sha256(Path(domain_v2.__file__).read_bytes()).hexdigest() == "b0912b95a3cedf858bc777f47a60ee817dd254b8f3e132d7278097d7ac6db21d"


def test_cannot_record_pending_disposal_before_independent_approval(env):
    _, _, _, d = env
    s = attach_certificate(d, propose(d, plan(d, ready(d))))
    with pytest.raises(RuleError, match="independent approval") as exc:
        d.do(s["id"], "record_disposal", execution_data(s))
    assert exc.value.status == 409


def test_pending_reassignment_blocks_new_opinion_approval(env):
    _, users, _, d = env
    s = d.reviewed("REASSIGN-BLOCK")
    s = d.do(s["id"], "draft", {"kind": "final", "body": "Synthetic opinion awaiting independent review.",
        "report_ids": [r["id"] for r in s["reports"]]})
    s = d.do(s["id"], "propose_reassignment", {"new_examiner_id": users["other_examiner"]["id"], "reason": "Pending staffing decision"})
    with pytest.raises(RuleError, match="reassignment"):
        d.do(s["id"], "approve", {"opinion_id": s["opinions"][-1]["id"]}, "reviewer")


def test_scanner_and_queue_honor_restricted_lifecycle_access(env):
    store, users, _, d = env
    s = plan(d, ready(d))
    s = d.do(s["id"], "access_policy", {"mode": "restricted", "member_ids": [users[x]["id"] for x in ["examiner", "reviewer"]], "reason": "Synthetic restricted lifecycle"})
    value = s["specimens"][0]["container_id"]
    found = store.locate_specimen(users["examiner"], value)
    assert found["lifecycle"]["retention"] is not None
    assert queue_snapshot(store.all_cases(users["coordinator"]), users["coordinator"])["counts"]["lifecycle"] == 0
    with pytest.raises(RuleError):
        store.locate_specimen(users["coordinator"], value)
