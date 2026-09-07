"""Versioned reducers and fail-closed case controls. Version 1 is deliberately frozen."""
import copy
from decimal import Decimal, InvalidOperation

from . import domain_v1 as legacy
from .domain_v1 import (RuleError, canonical, digest, dt, item, normalized, now_iso, require, timestamp)  # noqa: F401

NEW_ACTIONS = {"access_policy", "correct", "decide_correction", "withdraw_report", "decide_withdrawal",
               "withdraw_opinion", "request_receipt", "record_return"}


def controls(state):
    return state.get("controls", {})


def may_access(actor, state):
    """Restrict case existence, not just the screen. Role is never an ACL bypass."""
    if actor["org_id"] != state["org_id"]:
        return False
    policy = controls(state).get("access", {"mode": "department"})
    if policy["mode"] == "restricted" and actor["id"] not in policy["member_ids"]:
        return False
    return actor["role"] != "lab" or any(r["lab_id"] == actor["lab_id"] for r in state["requests"])


def report_withdrawal(state, report_id):
    return next((w for w in reversed(controls(state).get("report_withdrawals", []))
                 if w["report_id"] == report_id and w["status"] in {"pending", "approved"}), None)


def opinion_withdrawal(state, opinion_id):
    return next((w for w in controls(state).get("opinion_withdrawals", []) if w["opinion_id"] == opinion_id), None)


def latest_report(state, request_id):
    # Never fall back silently to an older revision when the newest one is withdrawn.
    report = legacy.latest_report(state, request_id)
    return None if report and report_withdrawal(state, report["id"]) else report


def evidence_fingerprint(state):
    base = legacy.evidence_fingerprint(state)
    clinical = {k: v for k, v in controls(state).items()
                if k in {"corrections", "report_withdrawals", "opinion_withdrawals"} and v}
    return digest({"base": base, "controls": clinical}) if clinical else base


def blockers(state):
    reasons = legacy.blockers(state)
    for correction in controls(state).get("corrections", []):
        if correction["status"] == "pending":
            reasons.append("Correction awaiting independent decision: " + correction["id"])
    for withdrawal in controls(state).get("report_withdrawals", []):
        if withdrawal["status"] == "pending":
            reasons.append("Report withdrawal awaiting independent decision: " + withdrawal["report_id"])
    for request in state["requests"]:
        last = legacy.latest_report(state, request["id"])
        if last and report_withdrawal(state, last["id"]):
            reasons.append("Current report unavailable or withdrawn: " + last["laboratory_reference"])
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
    issued = [o for o in state["opinions"] if o["issued_at"]]
    require(opinion["kind"] == ("supplementary" if issued else "final"),
            "First issued opinion must be final; subsequent opinions must be supplementary")


def _records(state, name):
    return state.setdefault("controls", {}).setdefault(name, [])


def _record(state, name, identifier):
    found = next((x for x in controls(state).get(name, []) if x["id"] == identifier), None)
    require(found is not None, "Unknown control record for this case", 404)
    return found


def _correction_target(state, correction):
    if correction["target"] == "case":
        require(correction["target_id"] == state["id"] and correction["field"] == "authority",
                "Only requesting-authority text can be corrected on a case", 422)
        return state
    require(correction["field"] in {"description", "preservative", "quantity", "unit"},
            "This specimen field cannot be corrected through this operation", 422)
    return item(state, "specimens", correction["target_id"])


def _proof(state, attachment_id, specimen_id):
    attachment = item(state, "attachments", attachment_id)
    require(attachment["specimen_id"] == specimen_id, "Receipt evidence belongs to another specimen")
    return attachment


def _currently_at_lab(state, specimen, lab_id):
    if specimen["holder_id"] == "external:" + lab_id:
        return True
    # v1 records already link acknowledged laboratory holders to their requests.
    return any(r["specimen_id"] == specimen["id"] and r["lab_id"] == lab_id and r["received_at"]
               and r["received_by"] == specimen["holder_id"] for r in state["requests"])


def apply(state, action, data, actor, recorded, event_id, case_id=None, schema=2):
    """Only schema=1 invokes the frozen reducer; signed v2 rules are explicitly versioned."""
    require(schema in {1, 2}, "Unsupported event schema")
    if schema == 1:
        return legacy.apply(state, action, data, actor, recorded, event_id, case_id)
    uid = actor["id"]
    if action == "create":
        return legacy.apply(state, action, data, actor, recorded, event_id, case_id)
    if action not in NEW_ACTIONS and action not in {"approve", "issue", "draft"}:
        if action == "review":
            require(not report_withdrawal(state, data["report_id"]), "Withdrawn or disputed report cannot be reviewed")
        s = legacy.apply(state, action, data, actor, recorded, event_id, case_id)
        if action == "report":
            # A pending withdrawal cannot be defeated by submitting another report first.
            require(not any(w["status"] == "pending" and item(state, "reports", w["report_id"])["request_id"] == data["request_id"]
                            for w in controls(state).get("report_withdrawals", [])),
                    "Resolve the pending report withdrawal before registering a replacement")
        if action in {"acknowledge", "record_receipt"}:
            transfer = item(s, "transfers", data["transfer_id"])
            transfer["receipt_lab_id"] = transfer.get("recipient_lab_id") or actor.get("lab_id")
        return s
    s = copy.deepcopy(state)
    if action == "access_policy":
        require(actor["role"] in {"admin", "examiner"}, "Access-policy permission required", 403)
        require(actor["role"] != "examiner" or s["examiner_id"] == uid, "Only assigned examiner may manage case access", 403)
        require(len(data["member_ids"]) == len(set(data["member_ids"])), "Duplicate case members", 422)
        require(data["mode"] != "restricted" or s["examiner_id"] in data["member_ids"],
                "Restricted cases must retain their assigned examiner", 422)
        require(data["mode"] != "department" or not data["member_ids"], "Department access cannot include a member list", 422)
        # Managers cannot accidentally remove their own only path back into the record.
        require(data["mode"] != "restricted" or uid in data["member_ids"], "Policy author must retain access", 422)
        s.setdefault("controls", {})["access"] = {**data, "changed_by": uid, "changed_at": recorded}
    elif action == "correct":
        target = _correction_target(s, data)
        require(str(target[data["field"]]) == data["expected_value"], "Correction target changed; refresh first")
        require(data["replacement"] != data["expected_value"], "Correction must change the recorded value", 422)
        replacement = data["replacement"]
        if data["field"] == "quantity":
            try:
                number = Decimal(replacement)
                require(number.is_finite() and 0 < number <= 1000000 and number.as_tuple().exponent >= -6,
                        "Corrected quantity must be positive, bounded and have at most six decimal places", 422)
                replacement = str(number)
            except InvalidOperation as exc:
                raise RuleError("Invalid corrected quantity", 422) from exc
        records = _records(s, "corrections")
        require(not any(x["status"] == "pending" and x["target_id"] == data["target_id"] and
                        x["field"] == data["field"] for x in records), "A correction for this field is already pending")
        records.append({"id": event_id, **data, "replacement": replacement, "proposed_by": uid,
                        "proposed_at": recorded, "status": "pending"})
    elif action == "decide_correction":
        correction = _record(s, "corrections", data["correction_id"])
        require(correction["status"] == "pending", "Correction already decided")
        require(uid != correction["proposed_by"], "Correction requires an independent reviewer", 403)
        target = _correction_target(s, correction)
        if data["decision"] == "approve":
            require(str(target[correction["field"]]) == correction["expected_value"], "Correction target changed; cannot apply stale proposal")
            target[correction["field"]] = correction["replacement"]
        correction.update(status="approved" if data["decision"] == "approve" else "rejected",
                          decided_by=uid, decided_at=recorded, decision_reason=data["reason"])
    elif action == "withdraw_report":
        report = item(s, "reports", data["report_id"])
        require(not report_withdrawal(s, report["id"]), "Report already withdrawn or awaiting a decision")
        _records(s, "report_withdrawals").append({"id": event_id, **data, "status": "pending",
                                                  "proposed_by": uid, "proposed_at": recorded})
    elif action == "decide_withdrawal":
        withdrawal = _record(s, "report_withdrawals", data["withdrawal_id"])
        require(withdrawal["status"] == "pending", "Withdrawal already decided")
        require(uid != withdrawal["proposed_by"], "Withdrawal requires an independent reviewer", 403)
        withdrawal.update(status="approved" if data["decision"] == "approve" else "rejected",
                          decided_by=uid, decided_at=recorded, decision_reason=data["reason"])
    elif action == "withdraw_opinion":
        opinion = item(s, "opinions", data["opinion_id"])
        require(opinion["issued_at"], "Only an issued opinion can be withdrawn")
        require(not opinion_withdrawal(s, opinion["id"]), "Opinion already withdrawn")
        _records(s, "opinion_withdrawals").append({"id": event_id, **data, "withdrawn_by": uid, "withdrawn_at": recorded})
    elif action == "request_receipt":
        request = item(s, "requests", data["request_id"])
        specimen = item(s, "specimens", request["specimen_id"])
        require(request["received_at"] is None, "Request receipt already confirmed")
        require(_currently_at_lab(s, specimen, request["lab_id"]), "Specimen is not recorded at this laboratory")
        require(not any(t["specimen_id"] == specimen["id"] and not t["acknowledged_at"] for t in s["transfers"]),
                "Cannot accept another request during a pending handover")
        timestamp(data["accepted_at"], recorded, request["created_at"])
        if actor["role"] == "lab":
            require(actor["lab_id"] == request["lab_id"], "Request is assigned to another laboratory", 403)
        else:
            require(data["attachment_id"], "Documentary acceptance evidence is required", 422)
        if data["attachment_id"]:
            _proof(s, data["attachment_id"], specimen["id"])
        request.update(received_at=data["accepted_at"], received_by=uid,
                       receipt_source="authenticated_additional_request" if actor["role"] == "lab" else "documented_additional_request",
                       acceptance_evidence_id=data["attachment_id"], acceptance_note=data["note"])
    elif action == "record_return":
        sp = item(s, "specimens", data["specimen_id"])
        require(sp["holder_id"].startswith("external:"), "Only an externally held specimen can be returned this way")
        require(not any(t["specimen_id"] == sp["id"] and not t["acknowledged_at"] for t in s["transfers"]),
                "Cannot record a return while a handover is pending")
        _proof(s, data["attachment_id"], sp["id"])
        timestamp(data["occurred_at"], recorded, sp["last_custody_at"])
        discrepancy = data["discrepancy"] or data["observed_seal"] != sp["seal_ref"]
        s["transfers"].append({"id": event_id, "specimen_id": sp["id"], "sender_id": sp["holder_id"],
                               "recipient_id": uid, "recipient_lab_id": None, "recipient_name": actor["display_name"],
                               "external_sender_name": data["external_sender_name"], "occurred_at": data["occurred_at"],
                               "destination": data["destination"], "note": data["note"], "seal_ref": sp["seal_ref"],
                               "observed_seal": data["observed_seal"], "acknowledged_at": data["occurred_at"],
                               "acknowledged_by": uid, "acknowledgement_note": data["note"],
                               "receipt_evidence_id": data["attachment_id"], "receipt_source": "documented_external_return",
                               "discrepancy": discrepancy, "resolution": None})
        sp["seal_history"].append({"kind": "external_seal_observation", "seal_ref": data["observed_seal"],
                                    "occurred_at": data["occurred_at"], "recorded_at": recorded,
                                    "actor_id": uid, "reason": data["note"], "attachment_id": data["attachment_id"]})
        sp.update(holder_id=uid, last_custody_at=data["occurred_at"], location=data["destination"],
                  seal_ref=data["observed_seal"], quarantined=sp["quarantined"] or discrepancy)
    elif action == "draft":
        s = legacy.apply(s, action, data, actor, recorded, event_id, case_id)
        s["opinions"][-1].update(evidence_fingerprint=evidence_fingerprint(state), workflow_version=2)
        return s
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
