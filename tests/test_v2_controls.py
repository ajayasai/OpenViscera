"""Version-2 workflow regression tests: never substitute administrative edits for evidence."""
import copy
import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from openviscera import domain_v1
from openviscera.domain import (RuleError, blockers, evidence_fingerprint, latest_report,
                               now_iso, opinion_pending, opinion_withdrawal)
from openviscera.evidence import check_database, export_bundle, verify_bundle


def restrict(d, s, members):
    return d.do(s["id"], "access_policy", {"mode": "restricted", "member_ids": members,
                                          "reason": "Synthetic restricted-case policy"})


def test_restricted_case_removes_existence_from_all_store_views(env):
    store, users, _, d = env
    s = d.reported("RESTRICTED")
    restrict(d, s, [users["examiner"]["id"], users["reviewer"]["id"]])
    for role in ["admin", "coordinator", "courier", "auditor", "other_examiner", "lab", "outsider"]:
        assert store.list_cases(users[role])["total"] == 0
        assert store.all_cases(users[role]) == []
        with pytest.raises(RuleError) as error:
            store.get_case(users[role], s["id"])
        assert error.value.status == 404
    assert store.list_cases(users["reviewer"])["total"] == 1


def test_access_revocation_also_blocks_idempotent_replays(env):
    store, users, _, d = env
    s = d.new("REVOKED")
    key = uuid.uuid4().hex
    data = {"text": "Synthetic coordination note"}
    result = store.command(users["coordinator"], s["id"], "note", data, s["version"], key)
    restrict(d, result["case"], [users["examiner"]["id"]])
    with pytest.raises(RuleError) as error:
        store.command(users["coordinator"], s["id"], "note", data, s["version"], key)
    assert error.value.status == 404


def test_access_policy_does_not_change_clinical_fingerprint(env):
    _, users, _, d = env
    s = d.issued("POLICY")
    fingerprint = evidence_fingerprint(s)
    s = restrict(d, s, [users["examiner"]["id"], users["reviewer"]["id"]])
    assert evidence_fingerprint(s) == fingerprint
    assert not opinion_pending(s)


@pytest.mark.parametrize("problem", ["missing-owner", "outsider", "duplicate", "not-assigned", "disabled"])
def test_invalid_access_policy_rejected(env, problem):
    store, users, _, d = env
    s = d.new("ACL-INVALID")
    members = [users["examiner"]["id"]]
    role = "examiner"
    if problem == "missing-owner":
        members = [users["reviewer"]["id"]]
    elif problem == "outsider":
        members += [users["outsider"]["id"]]
    elif problem == "duplicate":
        members *= 2
    elif problem == "not-assigned":
        role = "other_examiner"
    else:
        store.set_active(users["admin"], users["courier"]["id"], False)
        members += [users["courier"]["id"]]
    with pytest.raises(RuleError):
        d.do(s["id"], "access_policy", {"mode": "restricted", "member_ids": members, "reason": "Test restriction"}, role)


def test_handover_requires_recipient_case_membership(env):
    _, users, _, d = env
    s = d.requested("RESTRICTED-TRANSFER")
    sid = s["specimens"][0]["id"]
    d.do(s["id"], "seal", {"specimen_id": sid, "seal_ref": "SEAL", "occurred_at": d.past, "reason": "Sealed"})
    restrict(d, s, [users["examiner"]["id"]])
    with pytest.raises(RuleError, match="explicit access"):
        d.do(s["id"], "handover", {"specimen_id": sid, "recipient_id": users["courier"]["id"],
                                   "occurred_at": d.past, "destination": "Synthetic lab", "note": "Transfer"})


def correction_data(s, field="description", replacement="Corrected synthetic description"):
    sp = s["specimens"][0]
    return {"target": "specimen", "target_id": sp["id"], "field": field,
            "expected_value": sp[field], "replacement": replacement, "reason": "Correct transcription with independent review"}


def test_controlled_correction_preserves_original_and_requires_independence(env):
    store, users, _, d = env
    s = d.issued("CORRECTION")
    original = copy.deepcopy(s)
    s = d.do(s["id"], "correct", correction_data(s))
    assert s["specimens"] == original["specimens"]
    assert opinion_pending(s) and any("Correction" in b for b in blockers(s))
    proposal = s["controls"]["corrections"][0]
    # Even a hypothetical role change cannot authorize self-approval.
    with pytest.raises(RuleError, match="independent"):
        from openviscera.domain import apply
        apply(s, "decide_correction", {"correction_id": proposal["id"], "decision": "approve", "reason": "Review"},
              {**users["examiner"], "role": "reviewer"}, now_iso(), uuid.uuid4().hex)
    s = d.do(s["id"], "decide_correction", {"correction_id": proposal["id"], "decision": "approve", "reason": "Evidence checked"}, "reviewer")
    assert s["specimens"][0]["description"] == "Corrected synthetic description"
    assert s["controls"]["corrections"][0]["expected_value"] == original["specimens"][0]["description"]
    assert s["opinions"] == original["opinions"]
    assert check_database(store)["heads"][s["id"]]
    assert verify_bundle(export_bundle(store, users["examiner"], s["id"]), store.public_b64)["valid"]


def test_rejected_correction_does_not_change_recorded_facts(env):
    _, _, _, d = env
    s = d.collected("REJECT-CORRECTION")
    original = copy.deepcopy(s["specimens"])
    s = d.do(s["id"], "correct", correction_data(s))
    cid = s["controls"]["corrections"][0]["id"]
    s = d.do(s["id"], "decide_correction", {"correction_id": cid, "decision": "reject", "reason": "No supporting evidence"}, "reviewer")
    assert s["specimens"] == original
    with pytest.raises(RuleError, match="already decided"):
        d.do(s["id"], "decide_correction", {"correction_id": cid, "decision": "approve", "reason": "Try again"}, "reviewer")


@pytest.mark.parametrize("replacement", ["0", "-1", "NaN", "Infinity", "1000001", "0.0000001", "not-a-number"])
def test_invalid_quantity_correction(env, replacement):
    _, _, _, d = env
    s = d.collected("BAD-CORRECTION")
    with pytest.raises(RuleError):
        d.do(s["id"], "correct", correction_data(s, "quantity", replacement))


def test_stale_duplicate_and_wrong_field_corrections(env):
    _, _, _, d = env
    s = d.collected("CORRECT-BOUNDARY")
    data = correction_data(s)
    with pytest.raises(RuleError, match="target changed"):
        d.do(s["id"], "correct", {**data, "expected_value": "Not the actual value"})
    with pytest.raises(RuleError):
        d.do(s["id"], "correct", {**data, "field": "authority"})
    d.do(s["id"], "correct", data)
    with pytest.raises(RuleError, match="already pending"):
        d.do(s["id"], "correct", data)


def test_case_authority_correction_is_supported(env):
    _, _, _, d = env
    s = d.new("AUTHORITY")
    s = d.do(s["id"], "correct", {"target": "case", "target_id": s["id"], "field": "authority",
                                  "expected_value": s["authority"], "replacement": "Correct synthetic authority", "reason": "Transcription correction"})
    s = d.do(s["id"], "decide_correction", {"correction_id": s["controls"]["corrections"][0]["id"], "decision": "approve", "reason": "Verified"}, "reviewer")
    assert s["authority"] == "Correct synthetic authority"


def test_report_withdrawal_no_fallback_and_requires_replacement(env):
    store, _, _, d = env
    s = d.issued("WITHDRAW-REPORT")
    original_opinion = copy.deepcopy(s["opinions"][0])
    old_id = s["reports"][0]["id"]
    s = d.add_report(s)
    new_id = s["reports"][-1]["id"]
    s = d.do(s["id"], "withdraw_report", {"report_id": new_id, "reason": "Laboratory confirms report was assigned in error"})
    assert latest_report(s, s["requests"][0]["id"]) is None  # Do not revive old_id.
    with pytest.raises(RuleError, match="disputed"):
        d.do(s["id"], "review", {"report_id": new_id, "note": "Try review"})
    with pytest.raises(RuleError, match="pending report withdrawal"):
        d.add_report(s)
    s = d.do(s["id"], "decide_withdrawal", {"withdrawal_id": s["controls"]["report_withdrawals"][0]["id"],
                                          "decision": "approve", "reason": "Independently checked laboratory correction"}, "reviewer")
    assert any("unavailable or withdrawn" in b for b in blockers(s))
    assert s["opinions"][0] == original_opinion
    s = d.add_report(s)
    assert s["reports"][-1]["supersedes"] == new_id and s["reports"][0]["id"] == old_id
    assert latest_report(s, s["requests"][0]["id"])["revision"] == 3
    check_database(store)


def test_withdrawal_rejection_and_duplicate_decision(env):
    _, _, _, d = env
    s = d.reported("REJECT-WITHDRAWAL")
    rid = s["reports"][0]["id"]
    s = d.do(s["id"], "withdraw_report", {"report_id": rid, "reason": "Suspected wrong assignment"})
    wid = s["controls"]["report_withdrawals"][0]["id"]
    with pytest.raises(RuleError, match="already withdrawn"):
        d.do(s["id"], "withdraw_report", {"report_id": rid, "reason": "Duplicate proposal"})
    s = d.do(s["id"], "decide_withdrawal", {"withdrawal_id": wid, "decision": "reject", "reason": "Assignment verified correct"}, "reviewer")
    assert latest_report(s, s["requests"][0]["id"])["id"] == rid
    with pytest.raises(RuleError, match="already decided"):
        d.do(s["id"], "decide_withdrawal", {"withdrawal_id": wid, "decision": "approve", "reason": "Again"}, "reviewer")


def test_withdraw_opinion_preserves_original_and_reopens_case(env):
    _, _, _, d = env
    s = d.issued("WITHDRAW-OPINION")
    original = copy.deepcopy(s["opinions"][0])
    s = d.do(s["id"], "withdraw_opinion", {"opinion_id": original["id"], "reason": "Significant correction requires reissue"}, "reviewer")
    assert opinion_pending(s) and opinion_withdrawal(s, original["id"])
    assert s["opinions"][0] == original
    with pytest.raises(RuleError, match="already withdrawn"):
        d.do(s["id"], "withdraw_opinion", {"opinion_id": original["id"], "reason": "Duplicate"}, "reviewer")
    s = d.do(s["id"], "draft", {"kind": "supplementary", "body": "Corrected synthetic opinion", "report_ids": [s["reports"][0]["id"]]})
    oid = s["opinions"][-1]["id"]
    d.do(s["id"], "approve", {"opinion_id": oid}, "reviewer")
    s = d.do(s["id"], "issue", {"opinion_id": oid})
    assert not opinion_pending(s)


def test_late_request_acceptance_works_without_fabricated_custody(env):
    store, _, lab, d = env
    s = d.received("ADDITIONAL")
    transfers = copy.deepcopy(s["transfers"])
    s = d.do(s["id"], "request", {"specimen_id": s["specimens"][0]["id"], "examination": "Additional synthetic examination",
                                 "lab_id": lab["id"], "due_at": d.due})
    rid = s["requests"][-1]["id"]
    assert s["requests"][-1]["received_at"] is None
    d.do(s["id"], "request_receipt", {"request_id": rid, "accepted_at": now_iso(), "note": "Laboratory accepts the additional examination"}, "lab")
    s = store.get_case(d.users["examiner"], s["id"])
    assert s["requests"][-1]["received_at"]
    assert s["requests"][-1]["receipt_source"] == "authenticated_additional_request"
    assert s["transfers"] == transfers
    check_database(store)


def test_external_request_acceptance_requires_documentary_proof(env):
    _, _, lab, d = env
    s = d.received("ADDITIONAL-EXTERNAL", external=True)
    sid = s["specimens"][0]["id"]
    s = d.do(s["id"], "request", {"specimen_id": sid, "examination": "Additional exam", "lab_id": lab["id"], "due_at": d.due})
    rid = s["requests"][-1]["id"]
    data = {"request_id": rid, "accepted_at": now_iso(), "note": "External confirmation"}
    with pytest.raises(RuleError, match="evidence is required"):
        d.do(s["id"], "request_receipt", data, "coordinator")
    with pytest.raises(RuleError, match="precedes"):
        d.do(s["id"], "request_receipt", {**data, "accepted_at": d.past, "attachment_id": s["attachments"][0]["id"]}, "coordinator")
    s = d.do(s["id"], "request_receipt", {**data, "attachment_id": s["attachments"][0]["id"]}, "coordinator")
    assert s["requests"][-1]["receipt_source"] == "documented_additional_request"
    with pytest.raises(RuleError, match="already confirmed"):
        d.do(s["id"], "request_receipt", {**data, "attachment_id": s["attachments"][0]["id"]}, "coordinator")


def test_external_return_retains_evidence_and_can_resume_custody(env):
    store, users, _, d = env
    s = d.received("RETURN", external=True)
    sid = s["specimens"][0]["id"]
    s = d.do(s["id"], "record_return", {"specimen_id": sid, "attachment_id": s["attachments"][0]["id"],
                 "external_sender_name": "Synthetic external officer", "occurred_at": now_iso(),
                 "observed_seal": "SYNTHETIC-SEAL-01", "destination": "Department storage", "note": "Recorded documented return"}, "coordinator")
    assert s["specimens"][0]["holder_id"] == users["coordinator"]["id"]
    assert s["transfers"][-1]["receipt_source"] == "documented_external_return"
    assert not s["specimens"][0]["quarantined"]
    s = d.do(s["id"], "handover", {"specimen_id": sid, "recipient_id": users["examiner"]["id"],
                                  "occurred_at": now_iso(), "destination": "Department examiner", "note": "Transfer returned specimen"}, "coordinator")
    s = d.do(s["id"], "acknowledge", {"transfer_id": s["transfers"][-1]["id"], "occurred_at": now_iso(),
                                      "observed_seal": "SYNTHETIC-SEAL-01", "note": "Accepted return"})
    assert s["specimens"][0]["holder_id"] == users["examiner"]["id"]
    check_database(store)


def test_external_return_mismatch_is_never_silently_resolved(env):
    _, _, _, d = env
    s = d.received("RETURN-MISMATCH", external=True)
    s = d.do(s["id"], "record_return", {"specimen_id": s["specimens"][0]["id"], "attachment_id": s["attachments"][0]["id"],
                 "external_sender_name": "External officer", "occurred_at": now_iso(), "observed_seal": "DIFFERENT-RETURN-SEAL",
                 "discrepancy": False, "destination": "Storage", "note": "Actual return observation"}, "coordinator")
    assert s["specimens"][0]["quarantined"]
    assert s["transfers"][-1]["seal_ref"] == "SYNTHETIC-SEAL-01"
    assert s["specimens"][0]["seal_ref"] == "DIFFERENT-RETURN-SEAL"
    s = d.do(s["id"], "resolve", {"transfer_id": s["transfers"][-1]["id"], "reason": "Reviewed external resealing documentation"}, "reviewer")
    assert not s["specimens"][0]["quarantined"]


def batch_data(d, users, count=3):
    s = d.new("BATCH")
    for index in range(count):
        s = d.do(s["id"], "collect", {"container_id": f"BATCH-{index}", "description": "Synthetic batch specimen", "quantity": "1",
               "unit": "container", "preservative": "Examiner entry", "collected_at": d.past, "location": "Room"})
        s = d.do(s["id"], "seal", {"specimen_id": s["specimens"][-1]["id"], "seal_ref": "BATCH-SEAL", "occurred_at": d.past, "reason": "Sealed"})
    values = {"expected_version": s["version"], "items": [{"specimen_id": sp["id"], "recipient_id": users["courier"]["id"],
              "occurred_at": d.past, "destination": "Synthetic receiving office", "note": "Batch transfer"} for sp in s["specimens"]]}
    return s, values


def test_batch_preview_commit_and_idempotent_retry(env):
    store, users, _, d = env
    s, data = batch_data(d, users)
    before = copy.deepcopy(s)
    preview = store.batch_handover(users["examiner"], s["id"], {**data, "preview": True}, uuid.uuid4().hex)
    assert preview["valid"] and preview["count"] == 3
    assert store.get_case(users["examiner"], s["id"]) == before
    key = uuid.uuid4().hex
    result = store.batch_handover(users["examiner"], s["id"], data, key)
    replay = store.batch_handover(users["examiner"], s["id"], data, key)
    assert len(result["case"]["transfers"]) == 3
    assert replay["replayed"] and replay["event_id"] == result["event_id"]
    assert all(sp["holder_id"] == users["examiner"]["id"] for sp in result["case"]["specimens"])
    check_database(store)


def test_batch_late_failure_rolls_back_entire_batch(env):
    store, users, _, d = env
    s, data = batch_data(d, users)
    data["items"][-1]["recipient_id"] = users["outsider"]["id"]
    with pytest.raises(RuleError):
        store.batch_handover(users["examiner"], s["id"], data, uuid.uuid4().hex)
    assert store.get_case(users["examiner"], s["id"]) == s


def test_batch_duplicate_and_role_rejections(env):
    store, users, _, d = env
    s, data = batch_data(d, users)
    with pytest.raises(RuleError, match="specimen twice"):
        store.batch_handover(users["examiner"], s["id"], {**data, "items": [data["items"][0]] * 2}, uuid.uuid4().hex)
    with pytest.raises(RuleError) as e:
        store.batch_handover(users["auditor"], s["id"], data, uuid.uuid4().hex)
    assert e.value.status == 403


def test_two_concurrent_batches_only_one_commits(env):
    store, users, _, d = env
    s, data = batch_data(d, users)
    def submit(_):
        try:
            store.batch_handover(users["examiner"], s["id"], data, uuid.uuid4().hex)
            return True
        except RuleError as e:
            assert "stale version" in e.message
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(submit, range(2))) == 1
    assert len(store.get_case(users["examiner"], s["id"])["transfers"]) == 3


def test_specimen_qr_lookup_and_case_acl(env):
    store, users, _, d = env
    s = d.collected("QR")
    sp = s["specimens"][0]
    for token in [sp["container_id"], sp["container_id"].lower(), "openviscera:specimen:" + sp["id"]]:
        assert store.locate_specimen(users["examiner"], token)["case_id"] == s["id"]
    restrict(d, s, [users["examiner"]["id"]])
    with pytest.raises(RuleError) as error:
        store.locate_specimen(users["coordinator"], "openviscera:specimen:" + sp["id"])
    assert error.value.status == 404


def test_frozen_legacy_reducer_matches_original_file():
    # This digest is from the actual v0.1.0 source, not derived from the current reducer.
    from pathlib import Path
    original = Path(domain_v1.__file__).read_bytes()
    assert hashlib.sha256(original).hexdigest() == "c6f029801b029a1a31487a1e2f028d9da3ccbbc5a3087f01e2056c20f8cf12df"


def test_dispatch_snapshot_does_not_rewrite_history_after_correction(env):
    from openviscera.documents import dispatch_snapshot
    store, users, _, d = env
    s = d.received("HISTORICAL-LETTER", external=True)
    original = s["specimens"][0]["description"]
    transfer_id = s["transfers"][0]["id"]
    s = d.do(s["id"], "correct", correction_data(s))
    d.do(s["id"], "decide_correction", {"correction_id": s["controls"]["corrections"][0]["id"], "decision": "approve", "reason": "Corrected now"}, "reviewer")
    state, events, _, _ = store.evidence(users["examiner"], s["id"])
    assert state["specimens"][0]["description"] != original
    snapshot = dispatch_snapshot(events, transfer_id)
    assert snapshot["specimens"][0]["description"] == original
    assert snapshot["transfers"][0]["acknowledged_at"] is None
    with pytest.raises(RuleError):
        dispatch_snapshot(events, "nonexistent-transfer")
    with pytest.raises(RuleError):
        dispatch_snapshot(None, transfer_id)
