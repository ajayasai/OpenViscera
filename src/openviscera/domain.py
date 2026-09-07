"""Version-three workflow. Earlier reducers remain byte-for-byte frozen for replay."""
import copy

from . import domain_v2 as v2
from .domain_v2 import (RuleError, canonical, digest, dt, item, normalized, now_iso, require,
                        timestamp, controls, may_access, latest_report, report_withdrawal,
                        opinion_withdrawal)  # noqa: F401

LIFECYCLE_ACTIONS = {
    "propose_reassignment", "decide_reassignment", "propose_retention", "decide_retention",
    "place_hold", "request_hold_release", "decide_hold_release", "propose_disposal",
    "decide_disposal", "cancel_disposal", "record_disposal",
}
PHYSICAL_ACTIONS = {"seal", "request", "handover", "acknowledge", "record_receipt",
                    "request_receipt", "record_return"}


def records(state, name):
    return controls(state).get(name, [])


def record(state, name, identifier):
    found = next((r for r in records(state, name) if r["id"] == identifier), None)
    require(found is not None, "Unknown lifecycle record for this case", 404)
    return found


def append_record(state, name, value):
    state.setdefault("controls", {}).setdefault(name, []).append(value)


def evidence_fingerprint(state):
    # Administrative certificates do not pretend to be clinical evidence. They remain
    # hashed/signed/exported, and are forbidden as laboratory-report attachments.
    if any(a.get("purpose") == "administrative" for a in state["attachments"]):
        state = {**state, "attachments": [a for a in state["attachments"]
                                         if a.get("purpose") != "administrative"]}
    return v2.evidence_fingerprint(state)


def blockers(state):
    reasons = v2.blockers(state)
    if any(r["status"] == "pending" for r in records(state, "reassignments")):
        reasons.append("Examiner reassignment awaiting independent decision")
    return reasons


def opinion_pending(state):
    issued = [o for o in state["opinions"] if o["issued_at"]]
    return (not issued or bool(opinion_withdrawal(state, issued[-1]["id"])) or
            issued[-1]["evidence_fingerprint"] != evidence_fingerprint(state))


def opinion_ready(state, opinion):
    reasons = blockers(state)
    require(not reasons, "Opinion blocked: " + "; ".join(reasons))
    require(not opinion_withdrawal(state, opinion["id"]), "Opinion is withdrawn")
    require(opinion["evidence_fingerprint"] == evidence_fingerprint(state),
            "Opinion is stale: evidence changed; create a new draft")
    wanted = {latest_report(state, r["id"])["id"] for r in state["requests"]}
    require(set(opinion["report_ids"]) == wanted, "Opinion must cover every current report revision")
    require(opinion["kind"] == ("supplementary" if any(o["issued_at"] for o in state["opinions"]) else "final"),
            "First issued opinion must be final; subsequent opinions must be supplementary")


def disposed(state, specimen_id):
    return next((d for d in records(state, "disposals")
                 if d["specimen_id"] == specimen_id and d["status"] == "completed"), None)


def retention(state, specimen_id):
    return next((r for r in reversed(records(state, "retentions"))
                 if r["specimen_id"] == specimen_id and r["status"] == "approved"), None)


def active_holds(state, specimen_id):
    return [h for h in records(state, "holds")
            if h["status"] == "active" and h["specimen_id"] in {None, specimen_id}]


def disposal_fingerprint(state, specimen_id):
    """Any intervening custody/policy/hold change requires a fresh disposal approval."""
    return digest({"evidence": evidence_fingerprint(state),
                   "retentions": [r for r in records(state, "retentions") if r["specimen_id"] == specimen_id],
                   "holds": [h for h in records(state, "holds") if h["specimen_id"] in {None, specimen_id}],
                   "hold_releases": [r for r in records(state, "hold_releases")
                                     if record(state, "holds", r["hold_id"])["specimen_id"] in {None, specimen_id}],
                   "reassignments": records(state, "reassignments")})


def disposal_blockers(state, specimen_id, at, actor_id=None):
    """An administrative gate, never a determination of legal disposal authority."""
    sp = item(state, "specimens", specimen_id)
    reasons = []
    if disposed(state, specimen_id):
        return ["Specimen already recorded as disposed"]
    plan = retention(state, specimen_id)
    if not plan:
        reasons.append("No independently approved retention instruction")
    elif dt(at) < dt(plan["retain_until"]):
        reasons.append("Retention deadline has not elapsed")
    if any(r["specimen_id"] == specimen_id and r["status"] == "pending" for r in records(state, "retentions")):
        reasons.append("Retention change awaiting independent decision")
    if active_holds(state, specimen_id):
        reasons.append("Active preservation hold")
    if sp["holder_id"].startswith("external:"):
        reasons.append("Specimen is recorded at an external laboratory")
    if actor_id is not None and sp["holder_id"] != actor_id:
        reasons.append("Only the recorded local custodian may dispose")
    if not sp["seal_ref"]:
        reasons.append("No recorded specimen seal")
    reasons.extend(blockers(state))
    if opinion_pending(state):
        reasons.append("Current evidence has no current issued opinion")
    return list(dict.fromkeys(reasons))


def lifecycle_snapshot(state, at=None, actor_id=None):
    at = at or now_iso()
    specimens = []
    for sp in state["specimens"]:
        plan = retention(state, sp["id"])
        completed = disposed(state, sp["id"])
        pending = next((p for p in reversed(records(state, "disposals"))
                        if p["specimen_id"] == sp["id"] and p["status"] in {"pending", "approved"}), None)
        reasons = disposal_blockers(state, sp["id"], at, actor_id)
        stale = bool(pending and pending["snapshot"] != disposal_fingerprint(state, sp["id"]))
        specimens.append({"specimen_id": sp["id"], "container_id": sp["container_id"],
                          "retention": plan, "holds": active_holds(state, sp["id"]),
                          "disposed": completed, "proposal": pending, "proposal_stale": stale,
                          "blockers": reasons, "eligible_for_proposal": not reasons and not pending,
                          "eligible_to_record": bool(pending and pending["status"] == "approved"
                                                     and not stale and not reasons),
                          "retention_due": bool(plan and dt(plan["retain_until"]) <= dt(at) and not completed)})
    return {"generated_at": at, "specimens": specimens,
            "pending_reassignments": [r for r in records(state, "reassignments") if r["status"] == "pending"],
            "pending_retentions": [r for r in records(state, "retentions") if r["status"] == "pending"],
            "pending_hold_releases": [r for r in records(state, "hold_releases") if r["status"] == "pending"]}


def _decision(target, data, actor, recorded):
    require(target["status"] == "pending", "Proposal already decided")
    require(actor["id"] != target["proposed_by"], "An independent reviewer must decide the proposal", 403)
    target.update(status="approved" if data["decision"] == "approve" else "rejected",
                  decided_by=actor["id"], decided_at=recorded, decision_reason=data["reason"])


def _require_disposal_ready(state, sid, at, actor_id=None):
    reasons = disposal_blockers(state, sid, at, actor_id)
    require(not reasons, "Disposal blocked: " + "; ".join(reasons))


def apply(state, action, data, actor, recorded, event_id, case_id=None, schema=3):
    require(schema in {1, 2, 3}, "Unsupported event schema")
    if schema < 3:
        return v2.apply(state, action, data, actor, recorded, event_id, case_id, schema=schema)
    uid = actor["id"]
    if action in PHYSICAL_ACTIONS:
        sid = data.get("specimen_id")
        if action in {"acknowledge", "record_receipt"}:
            sid = item(state, "transfers", data["transfer_id"])["specimen_id"]
        elif action == "request_receipt":
            sid = item(state, "requests", data["request_id"])["specimen_id"]
        require(not disposed(state, sid), "Specimen is recorded as disposed; physical workflow cannot resume")
    if action == "report":
        require(item(state, "attachments", data["attachment_id"]).get("purpose") != "administrative",
                "Administrative attachment cannot be registered as a laboratory report", 422)
    if action not in LIFECYCLE_ACTIONS | {"draft", "approve", "issue"}:
        return v2.apply(state, action, data, actor, recorded, event_id, case_id, schema=2)
    if action == "draft":
        s = v2.apply(state, action, data, actor, recorded, event_id, case_id, schema=2)
        s["opinions"][-1].update(evidence_fingerprint=evidence_fingerprint(state), workflow_version=3)
        return s
    s = copy.deepcopy(state)
    proposed = {"id": event_id, **data, "proposed_by": uid, "proposed_at": recorded, "status": "pending"}
    if action == "propose_reassignment":
        require(data["new_examiner_id"] != s["examiner_id"], "Select a different examiner", 422)
        require(not any(r["status"] == "pending" for r in records(s, "reassignments")), "Reassignment already pending")
        append_record(s, "reassignments", {**proposed, "previous_examiner_id": s["examiner_id"]})
    elif action == "decide_reassignment":
        target = record(s, "reassignments", data["reassignment_id"])
        _decision(target, data, actor, recorded)
        if data["decision"] == "approve":
            require(s["examiner_id"] == target["previous_examiner_id"], "Examiner changed; proposal is stale")
            s["examiner_id"] = target["new_examiner_id"]
    elif action == "propose_retention":
        sp = item(s, "specimens", data["specimen_id"])
        require(not disposed(s, sp["id"]), "Cannot change retention after recorded disposal")
        require(dt(data["retain_until"]) >= dt(sp["collected_at"]), "Retention deadline precedes collection", 422)
        require(not any(r["specimen_id"] == sp["id"] and r["status"] == "pending" for r in records(s, "retentions")),
                "A retention change is already pending")
        append_record(s, "retentions", {**proposed, "supersedes_id": (retention(s, sp["id"]) or {}).get("id")})
    elif action == "decide_retention":
        target = record(s, "retentions", data["retention_id"])
        if data["decision"] == "approve":
            require(not disposed(s, target["specimen_id"]), "Cannot change retention after recorded disposal")
            require((retention(s, target["specimen_id"]) or {}).get("id") == target["supersedes_id"],
                    "Retention instruction changed; proposal is stale")
        _decision(target, data, actor, recorded)
    elif action == "place_hold":
        if data["specimen_id"]:
            item(s, "specimens", data["specimen_id"])
            require(not disposed(s, data["specimen_id"]), "Cannot place a physical hold on an already disposed specimen")
        append_record(s, "holds", {"id": event_id, **data, "placed_by": uid, "placed_at": recorded, "status": "active"})
    elif action == "request_hold_release":
        hold = record(s, "holds", data["hold_id"])
        require(hold["status"] == "active", "Hold is already released")
        require(not any(r["hold_id"] == hold["id"] and r["status"] == "pending" for r in records(s, "hold_releases")),
                "Hold release is already pending")
        append_record(s, "hold_releases", proposed)
    elif action == "decide_hold_release":
        target = record(s, "hold_releases", data["release_id"])
        hold = record(s, "holds", target["hold_id"])
        require(hold["status"] == "active", "Hold is already released")
        _decision(target, data, actor, recorded)
        if data["decision"] == "approve":
            hold.update(status="released", released_at=recorded, released_by=uid, release_id=target["id"])
    elif action == "propose_disposal":
        sid = data["specimen_id"]
        _require_disposal_ready(s, sid, recorded, uid)
        require(not any(r["specimen_id"] == sid and r["status"] in {"pending", "approved"}
                        for r in records(s, "disposals")), "Cancel or decide the outstanding disposal proposal first")
        append_record(s, "disposals", {**proposed, "snapshot": disposal_fingerprint(s, sid)})
    elif action == "decide_disposal":
        target = record(s, "disposals", data["disposal_id"])
        if data["decision"] == "approve":
            _require_disposal_ready(s, target["specimen_id"], recorded)
            require(target["snapshot"] == disposal_fingerprint(s, target["specimen_id"]),
                    "Disposal proposal is stale; cancel and propose again")
        _decision(target, data, actor, recorded)
    elif action == "cancel_disposal":
        target = record(s, "disposals", data["disposal_id"])
        require(target["status"] in {"pending", "approved"}, "Disposal cannot be cancelled in its current state")
        target.update(status="cancelled", cancelled_by=uid, cancelled_at=recorded, cancellation_reason=data["reason"])
    elif action == "record_disposal":
        target = record(s, "disposals", data["disposal_id"])
        require(target["status"] == "approved", "Disposal requires independent approval")
        require(target["decided_by"] != uid, "Approver cannot record their own disposal execution", 403)
        sid = target["specimen_id"]
        _require_disposal_ready(s, sid, recorded, uid)
        require(target["snapshot"] == disposal_fingerprint(s, sid), "Disposal approval is stale; cancel and propose again")
        proof = item(s, "attachments", data["attachment_id"])
        require(proof["specimen_id"] == sid and proof.get("purpose") == "administrative",
                "Disposal needs a matching administrative certificate attachment", 422)
        timestamp(data["occurred_at"], recorded, target["decided_at"])
        timestamp(data["occurred_at"], recorded, item(s, "specimens", sid)["last_custody_at"])
        require(dt(data["occurred_at"]) >= dt(retention(s, sid)["retain_until"]),
                "Disposal time precedes the retention deadline", 422)
        target.update(status="completed", executed_by=uid, executed_at=data["occurred_at"], recorded_at=recorded,
                      attachment_id=proof["id"], execution_note=data["note"])
    elif action == "approve":
        opinion = item(s, "opinions", data["opinion_id"])
        require(uid != opinion["author_id"], "Author cannot approve their own opinion", 403)
        require(not opinion["approved_at"] and not opinion["issued_at"], "Opinion is already approved or issued")
        opinion_ready(s, opinion)
        opinion.update(approved_by=uid, approved_at=recorded)
    elif action == "issue":
        opinion = item(s, "opinions", data["opinion_id"])
        require(opinion["approved_at"] and not opinion["issued_at"], "Opinion needs approval and must not already be issued")
        opinion_ready(s, opinion)
        opinion["issued_at"] = recorded
    s["version"] += 1
    return s
