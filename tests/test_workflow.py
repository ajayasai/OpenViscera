import copy
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from openviscera.domain import RuleError, blockers, opinion_pending
from openviscera.evidence import check_database
from openviscera.models import ROLES


def test_full_lifecycle_and_replay(env):
    store, users, lab, d = env
    s = d.issued("COMPLETE")
    assert not blockers(s)
    assert not opinion_pending(s)
    assert s["reports"][0]["reviewed_by"] == users["examiner"]["id"]
    assert s["opinions"][0]["approved_by"] == users["reviewer"]["id"]
    assert check_database(store)["heads"][s["id"]]


def test_receipt_does_not_imply_report_review(env):
    _, _, _, d = env
    s = d.reported("REVIEW")
    assert s["requests"][0]["received_at"]
    assert s["reports"][0]["reviewed_at"] is None
    assert any("unreviewed" in b for b in blockers(s))


def test_revision_reopens_pending_opinion_preserves_issued(env):
    _, _, _, d = env
    issued = d.issued("REVISED")
    old_opinion = copy.deepcopy(issued["opinions"][0])
    s = d.add_report(issued)
    assert opinion_pending(s)
    assert s["opinions"][0] == old_opinion
    assert s["reports"][1]["supersedes"] == s["reports"][0]["id"]
    assert s["reports"][1]["reviewed_at"] is None
    s = d.do(s["id"], "review", {"report_id": s["reports"][-1]["id"], "note": "Reviewed revision"})
    s = d.do(s["id"], "draft", {"kind": "supplementary", "body": "Synthetic supplementary opinion",
                                "report_ids": [s["reports"][-1]["id"]]})
    oid = s["opinions"][-1]["id"]
    s = d.do(s["id"], "approve", {"opinion_id": oid}, "reviewer")
    s = d.do(s["id"], "issue", {"opinion_id": oid})
    assert not opinion_pending(s)
    assert s["opinions"][0] == old_opinion


def test_revision_invalidates_unissued_approval(env):
    _, _, _, d = env
    s = d.reviewed("STALE")
    s = d.do(s["id"], "draft", {"kind": "final", "body": "Synthetic draft", "report_ids": [s["reports"][0]["id"]]})
    oid = s["opinions"][0]["id"]
    s = d.do(s["id"], "approve", {"opinion_id": oid}, "reviewer")
    s = d.add_report(s)
    s = d.do(s["id"], "review", {"report_id": s["reports"][-1]["id"], "note": "Reviewed new revision"})
    with pytest.raises(RuleError, match="stale"):
        d.do(s["id"], "issue", {"opinion_id": oid})


def test_external_receipt_is_explicit_and_evidenced(env):
    store, users, _, d = env
    s = d.received("EXTERNAL", external=True)
    r, t = s["requests"][0], s["transfers"][0]
    assert r["receipt_source"] == "documented_external_receipt"
    assert t["receipt_evidence_id"] in {a["id"] for a in s["attachments"]}
    assert t["acknowledged_by"] == users["coordinator"]["id"]
    assert check_database(store)["heads"][s["id"]]


def test_wrong_seal_forces_quarantine_and_independent_resolution(env):
    _, _, _, d = env
    s = d.received("BAD-SEAL", discrepancy=True)
    assert s["specimens"][0]["quarantined"]
    assert s["transfers"][0]["discrepancy"]
    s = d.do(s["id"], "resolve", {"transfer_id": s["transfers"][0]["id"], "reason": "Documented investigation completed"}, "reviewer")
    assert not s["specimens"][0]["quarantined"]
    assert s["transfers"][0]["discrepancy"]  # historical fact is never erased


def test_mismatch_is_discrepancy_even_when_checkbox_false(env):
    _, _, _, d = env
    s = d.dispatched("MISMATCH")
    s = d.do(s["id"], "acknowledge", {"transfer_id": s["transfers"][0]["id"], "occurred_at": d.past,
                                      "observed_seal": "DIFFERENT", "discrepancy": False, "note": "Entered observed seal"}, "lab")
    assert s["specimens"][0]["quarantined"]


def test_unsealed_dispatch_rejected(env):
    _, users, _, d = env
    s = d.requested("NO-SEAL")
    with pytest.raises(RuleError, match="Seal"):
        d.do(s["id"], "handover", {"specimen_id": s["specimens"][0]["id"], "recipient_id": users["courier"]["id"],
                                   "occurred_at": d.past, "destination": "Lab", "note": "Send"})


def test_only_current_custodian_can_dispatch(env):
    _, users, _, d = env
    s = d.dispatched("WRONG-SENDER")
    with pytest.raises(RuleError, match="custodian"):
        d.do(s["id"], "handover", {"specimen_id": s["specimens"][0]["id"], "recipient_id": users["courier"]["id"],
                                   "occurred_at": d.past, "destination": "Lab", "note": "Send"}, "coordinator")


def test_recipient_must_authenticate_and_duplicate_ack_rejected(env):
    _, _, _, d = env
    s = d.dispatched("ACK")
    data = {"transfer_id": s["transfers"][0]["id"], "occurred_at": d.past, "observed_seal": "SYNTHETIC-SEAL-01", "note": "Received"}
    with pytest.raises(RuleError, match="named recipient"):
        d.do(s["id"], "acknowledge", data, "courier")
    d.do(s["id"], "acknowledge", data, "lab")
    with pytest.raises(RuleError, match="already acknowledged"):
        d.do(s["id"], "acknowledge", data, "lab")


def test_wrong_case_attachment_rejected(env):
    _, _, _, d = env
    a, b = d.received("A"), d.received("B")
    a = d.attachment(a["id"], a["specimens"][0]["id"])
    with pytest.raises(RuleError, match="Unknown attachments"):
        d.do(b["id"], "report", {"request_id": b["requests"][0]["id"], "attachment_id": a["attachments"][0]["id"],
                                 "laboratory_reference": "Wrong case", "received_at": d.past}, "coordinator")


def test_wrong_specimen_attachment_rejected(env):
    _, _, _, d = env
    s = d.received("TWO-SPECIMENS")
    s = d.do(s["id"], "collect", {"container_id": "SECOND", "description": "Second specimen", "quantity": "1",
                                  "unit": "container", "preservative": "Entered", "collected_at": d.past, "location": "Room"})
    s = d.attachment(s["id"], s["specimens"][-1]["id"])
    with pytest.raises(RuleError, match="Wrong specimen"):
        d.do(s["id"], "report", {"request_id": s["requests"][0]["id"], "attachment_id": s["attachments"][0]["id"],
                                 "laboratory_reference": "Wrong specimen", "received_at": d.past}, "coordinator")


@pytest.mark.parametrize("duplicate", ["DUP", "dup", " DUP ", "ＤＵＰ"])
def test_container_uniqueness_normalizes_unicode_across_cases(env, duplicate):
    _, _, _, d = env
    a, b = d.new("ONE"), d.new("TWO")
    values = {"container_id": "DUP", "description": "Synthetic", "quantity": "1", "unit": "container",
              "preservative": "Entered", "collected_at": d.past, "location": "Room"}
    d.do(a["id"], "collect", values)
    with pytest.raises(RuleError, match="Duplicate identifier"):
        d.do(b["id"], "collect", {**values, "container_id": duplicate})


def test_idempotent_retry_does_not_duplicate_and_conflict_rejected(env):
    store, users, _, d = env
    s = d.new("IDEMPOTENT")
    key = uuid.uuid4().hex
    a = store.command(users["examiner"], s["id"], "note", {"text": "Note"}, s["version"], key)
    b = store.command(users["examiner"], s["id"], "note", {"text": "Note"}, s["version"], key)
    assert a["event_id"] == b["event_id"] and b["replayed"]
    assert len(b["case"]["notes"]) == 1
    with pytest.raises(RuleError, match="different input"):
        store.command(users["examiner"], s["id"], "note", {"text": "Changed"}, s["version"], key)


def test_concurrent_commands_have_one_winner(env):
    store, users, _, d = env
    s = d.new("RACE")
    def write(i):
        try:
            store.command(users["examiner"], s["id"], "note", {"text": f"Parallel {i}"}, s["version"], uuid.uuid4().hex)
            return "success"
        except RuleError as error:
            assert "stale version" in error.message
            return "conflict"
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(write, range(16)))
    assert outcomes.count("success") == 1
    assert store.get_case(users["examiner"], s["id"])["version"] == 2
    check_database(store)


def test_cross_department_isolation(env):
    store, users, _, d = env
    s = d.new("PRIVATE")
    with pytest.raises(RuleError) as error:
        store.get_case(users["outsider"], s["id"])
    assert error.value.status == 404
    assert store.list_cases(users["outsider"])["total"] == 0


@pytest.mark.parametrize("action", list(ROLES))
def test_auditor_cannot_mutate_any_workflow_action(env, action):
    store, users, _, d = env
    s = d.new("READONLY")
    with pytest.raises(RuleError) as error:
        store.command(users["auditor"], s["id"], action, {}, s["version"], uuid.uuid4().hex)
    assert error.value.status == 403


def test_other_examiner_cannot_review_assigned_case(env):
    _, _, _, d = env
    s = d.reported("ASSIGNED")
    with pytest.raises(RuleError, match="assigned examiner"):
        d.do(s["id"], "review", {"report_id": s["reports"][0]["id"], "note": "Review"}, "other_examiner")


def test_self_approval_not_allowed_even_after_role_change(env):
    store, users, _, d = env
    s = d.reviewed("SELF-APPROVAL")
    s = d.do(s["id"], "draft", {"kind": "final", "body": "Draft", "report_ids": [s["reports"][0]["id"]]})
    actor = {**users["examiner"], "role": "reviewer"}
    with pytest.raises(RuleError, match="Author cannot approve"):
        store.command(actor, s["id"], "approve", {"opinion_id": s["opinions"][0]["id"]}, s["version"], uuid.uuid4().hex)


def test_first_opinion_cannot_be_supplementary(env):
    _, _, _, d = env
    s = d.reviewed("FIRST")
    s = d.do(s["id"], "draft", {"kind": "supplementary", "body": "Draft", "report_ids": [s["reports"][0]["id"]]})
    with pytest.raises(RuleError, match="First issued opinion"):
        d.do(s["id"], "approve", {"opinion_id": s["opinions"][0]["id"]}, "reviewer")


@pytest.mark.parametrize("quantity", ["0", "-1", "NaN", "Infinity", "1000001"])
def test_invalid_quantities(env, quantity):
    _, _, _, d = env
    s = d.new("QUANTITY")
    with pytest.raises(RuleError) as error:
        d.do(s["id"], "collect", {"container_id": "Q", "description": "Synthetic", "quantity": quantity, "unit": "container",
                                  "preservative": "Entered", "collected_at": d.past, "location": "Room"})
    assert error.value.status == 422


def test_future_and_naive_collection_times_rejected(env):
    _, _, _, d = env
    s = d.new("TIME")
    values = {"container_id": "T", "description": "Synthetic", "quantity": "1", "unit": "container",
              "preservative": "Entered", "location": "Room"}
    for value in ["2020-01-01T12:00:00", (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()]:
        with pytest.raises(RuleError) as error:
            d.do(s["id"], "collect", {**values, "collected_at": value})
        assert error.value.status == 422


def test_custody_time_cannot_go_backwards(env):
    _, _, _, d = env
    s = d.dispatched("CHRONOLOGY")
    before = (datetime.fromisoformat(d.past) - timedelta(hours=1)).isoformat()
    with pytest.raises(RuleError, match="precedes"):
        d.do(s["id"], "acknowledge", {"transfer_id": s["transfers"][0]["id"], "occurred_at": before,
                                      "observed_seal": "SYNTHETIC-SEAL-01", "note": "Received"}, "lab")


def test_report_before_receipt_does_not_clear_receipt_gap(env):
    _, _, _, d = env
    s = d.dispatched("NO-RECEIPT")
    s = d.add_report(s)
    assert any("receipt missing" in b for b in blockers(s))
    assert s["reports"][0]["reviewed_at"] is None


def test_old_report_cannot_be_reviewed(env):
    _, _, _, d = env
    s = d.reported("OLD")
    old = s["reports"][0]["id"]
    s = d.add_report(s)
    with pytest.raises(RuleError, match="superseded"):
        d.do(s["id"], "review", {"report_id": old, "note": "Review"})


def test_lab_view_hides_department_notes_and_opinions(env):
    store, users, _, d = env
    s = d.issued("LAB-SCOPE")
    d.do(s["id"], "note", {"text": "Internal department note"})
    view = store.get_case(users["lab"], s["id"])
    assert view["notes"] == view["opinions"] == []
    assert view["authority"] == "Restricted to department staff"
    with pytest.raises(RuleError) as error:
        store.evidence(users["lab"], s["id"])
    assert error.value.status == 403
