"""Deterministic, replayable workflow. Persistence and network I/O belong elsewhere."""
import copy
import hashlib
import json
import unicodedata
from datetime import datetime, timezone


class RuleError(Exception):
    def __init__(self, message, status=409):
        self.message, self.status = message, status
        super().__init__(message)


def require(condition, message, status=409):
    if not condition:
        raise RuleError(message, status)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def normalized(value):
    return unicodedata.normalize("NFKC", value).strip().casefold()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def dt(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def timestamp(value, recorded, after=None):
    parsed = dt(value)
    require(parsed.tzinfo is not None, "Timezone is required", 422)
    require(parsed <= dt(recorded), "Event time cannot be in the future", 422)
    if after:
        require(parsed >= dt(after), "Event time precedes the preceding custody event", 422)


def item(state, collection, identifier):
    found = next((x for x in state[collection] if x["id"] == identifier), None)
    require(found is not None, f"Unknown {collection} item for this case", 404)
    return found


def latest_report(state, request_id):
    reports = [r for r in state["reports"] if r["request_id"] == request_id]
    return reports[-1] if reports else None


def evidence_fingerprint(state):
    """Administrative follow-ups and opinion actions do not alter the evidence snapshot."""
    return digest({k: state[k] for k in ("case_ref", "authority", "examiner_id", "specimens", "requests",
                                       "transfers", "reports", "attachments", "notes")})


def blockers(state):
    reasons = []
    if not state["requests"]:
        reasons.append("No laboratory examinations requested")
    for specimen in state["specimens"]:
        if specimen["quarantined"]:
            reasons.append(f'Unresolved discrepancy: {specimen["container_id"]}')
        if not any(r["specimen_id"] == specimen["id"] for r in state["requests"]):
            reasons.append(f'No examination requested for container: {specimen["container_id"]}')
    for transfer in state["transfers"]:
        if transfer["acknowledged_at"] is None:
            reasons.append(f'Unacknowledged handover: {transfer["id"]}')
    for request in state["requests"]:
        if not request["received_at"]:
            reasons.append(f'Laboratory receipt missing: {request["examination"]} ({request["id"]})')
        report = latest_report(state, request["id"])
        if report is None:
            reasons.append(f'Report outstanding: {request["examination"]} ({request["id"]})')
        elif report["reviewed_at"] is None:
            reasons.append(f'Latest report unreviewed: {report["laboratory_reference"]}')
    return reasons


def opinion_pending(state):
    issued = [o for o in state["opinions"] if o["issued_at"]]
    return not issued or issued[-1]["evidence_fingerprint"] != evidence_fingerprint(state)


def opinion_ready(state, opinion):
    require(not blockers(state), "Opinion blocked: " + "; ".join(blockers(state)))
    require(opinion["evidence_fingerprint"] == evidence_fingerprint(state),
            "Opinion is stale: evidence changed; create a new draft")
    wanted = {latest_report(state, r["id"])["id"] for r in state["requests"]}
    require(set(opinion["report_ids"]) == wanted, "Opinion must cover every current report revision")
    issued = [o for o in state["opinions"] if o["issued_at"]]
    require(opinion["kind"] == ("supplementary" if issued else "final"),
            "First issued opinion must be final; subsequent opinions must be supplementary")


def apply(state, action, data, actor, recorded, event_id, case_id=None):
    """Apply a validated command to a copy. Identifiers and time come from the signed event."""
    uid = actor["id"]
    if action == "create":
        return {"id": case_id, "org_id": actor["org_id"], **data, "created_at": recorded,
                "version": 1, "specimens": [], "requests": [], "transfers": [], "reports": [],
                "attachments": [], "opinions": [], "notes": [], "followups": []}
    s = copy.deepcopy(state)
    eid = event_id
    if action == "collect":
        timestamp(data["collected_at"], recorded)
        require(not any(normalized(x["container_id"]) == normalized(data["container_id"])
                        for x in s["specimens"]), "Container identifier already exists")
        s["specimens"].append({"id": eid, **data, "collected_by": uid, "holder_id": uid,
                               "last_custody_at": data["collected_at"], "seal_ref": None,
                               "seal_history": [], "quarantined": False})
    elif action == "seal":
        sp = item(s, "specimens", data["specimen_id"])
        require(sp["holder_id"] == uid, "Only the recorded custodian may seal", 403)
        require(not any(t["specimen_id"] == sp["id"] and not t["acknowledged_at"]
                        for t in s["transfers"]), "Cannot reseal during a pending handover")
        timestamp(data["occurred_at"], recorded, sp["last_custody_at"])
        sp["seal_history"].append({**data, "actor_id": uid, "recorded_at": recorded})
        sp["seal_ref"] = data["seal_ref"]
        sp["last_custody_at"] = data["occurred_at"]
    elif action == "request":
        item(s, "specimens", data["specimen_id"])
        require(not any(r["specimen_id"] == data["specimen_id"] and r["lab_id"] == data["lab_id"]
                        and normalized(r["examination"]) == normalized(data["examination"])
                        for r in s["requests"]), "Duplicate examination request")
        # A new examination requires its own receipt confirmation, even for an existing container.
        s["requests"].append({"id": eid, **data, "created_at": recorded, "created_by": uid,
                              "received_at": None, "received_by": None})
    elif action == "handover":
        sp = item(s, "specimens", data["specimen_id"])
        require(sp["holder_id"] == uid, "Sender is not the current recorded custodian", 403)
        require(data["recipient_id"] != uid, "Sender and recipient must differ")
        require(sp["seal_ref"], "Seal the specimen before handover")
        require(not sp["quarantined"], "Resolve the discrepancy before another handover")
        require(not any(t["specimen_id"] == sp["id"] and not t["acknowledged_at"]
                        for t in s["transfers"]), "A handover is already awaiting acknowledgement")
        timestamp(data["occurred_at"], recorded, sp["last_custody_at"])
        s["transfers"].append({"id": eid, **data, "sender_id": uid, "seal_ref": sp["seal_ref"],
                               "acknowledged_at": None, "discrepancy": False, "resolution": None})
        sp["last_custody_at"] = data["occurred_at"]
    elif action in {"acknowledge", "record_receipt"}:
        transfer = item(s, "transfers", data["transfer_id"])
        external = action == "record_receipt"
        if external:
            require(transfer["recipient_lab_id"], "This transfer requires the named user's acknowledgement")
            proof = item(s, "attachments", data["attachment_id"])
            require(proof["specimen_id"] == transfer["specimen_id"], "Receipt evidence belongs to another specimen")
            transfer["receipt_evidence_id"] = data["attachment_id"]
            transfer["external_recipient_name"] = data["recipient_name"]
        else:
            require(transfer["recipient_id"] == uid, "Only the named recipient may acknowledge", 403)
        require(not transfer["acknowledged_at"], "Handover is already acknowledged")
        timestamp(data["occurred_at"], recorded, transfer["occurred_at"])
        sp = item(s, "specimens", transfer["specimen_id"])
        discrepancy = data["discrepancy"] or data["observed_seal"] != transfer["seal_ref"]
        transfer.update(acknowledged_at=data["occurred_at"], acknowledged_by=uid,
                        acknowledgement_note=data["note"], observed_seal=data["observed_seal"],
                        discrepancy=discrepancy)
        holder = "external:" + transfer["recipient_lab_id"] if external else uid
        sp.update(holder_id=holder, last_custody_at=data["occurred_at"], location=transfer["destination"],
                  quarantined=discrepancy)
        receipt_lab = transfer["recipient_lab_id"] if external else actor.get("lab_id")
        if receipt_lab:
            for request in s["requests"]:
                if request["specimen_id"] == sp["id"] and request["lab_id"] == receipt_lab:
                    if request["received_at"] is None:
                        request.update(received_at=data["occurred_at"], received_by=uid,
                                       receipt_source="documented_external_receipt" if external else "authenticated_recipient")
    elif action == "resolve":
        transfer = item(s, "transfers", data["transfer_id"])
        require(transfer["discrepancy"] and transfer["resolution"] is None, "No open discrepancy")
        require(uid not in (transfer["sender_id"], transfer["recipient_id"], transfer.get("acknowledged_by")),
                "Discrepancy resolution requires an independent reviewer", 403)
        transfer["resolution"] = {"reviewer_id": uid, "reason": data["reason"], "at": recorded}
        sp = item(s, "specimens", transfer["specimen_id"])
        sp["quarantined"] = any(t["specimen_id"] == sp["id"] and t["discrepancy"]
                                 and not t["resolution"] for t in s["transfers"])
    elif action == "attach":
        item(s, "specimens", data["specimen_id"])
        s["attachments"].append({"id": eid, **data, "uploaded_by": uid, "uploaded_at": recorded})
    elif action == "report":
        request = item(s, "requests", data["request_id"])
        attachment = item(s, "attachments", data["attachment_id"])
        require(attachment["specimen_id"] == request["specimen_id"],
                "Wrong specimen: attachment and examination request do not match")
        require(attachment["media_type"] == "application/pdf", "Laboratory report must be a PDF attachment")
        current = latest_report(s, request["id"])
        require(data["supersedes"] == (current["id"] if current else None),
                "Revision must explicitly supersede the latest report")
        require(not any(r["attachment_id"] == attachment["id"] for r in s["reports"]),
                "Attachment already registered as a report")
        require(not any(r["request_id"] == request["id"] and
                        item(s, "attachments", r["attachment_id"])["sha256"] == attachment["sha256"]
                        for r in s["reports"]), "Identical report bytes already registered for this request")
        timestamp(data["received_at"], recorded,
                  item(s, "specimens", request["specimen_id"])["collected_at"])
        s["reports"].append({"id": eid, **data, "revision": current["revision"] + 1 if current else 1,
                            "lab_id": request["lab_id"], "registered_by": uid, "reviewed_at": None,
                            "reviewed_by": None, "review_note": None})
    elif action == "review":
        report = item(s, "reports", data["report_id"])
        require(latest_report(s, report["request_id"])["id"] == report["id"], "Cannot review a superseded report")
        require(report["reviewed_at"] is None, "Report is already reviewed; append a case note for clarification")
        report.update(reviewed_at=recorded, reviewed_by=uid, review_note=data["note"])
    elif action == "draft":
        require(len(set(data["report_ids"])) == len(data["report_ids"]), "Duplicate report references")
        for rid in data["report_ids"]:
            item(s, "reports", rid)
        s["opinions"].append({"id": eid, **data, "author_id": uid, "created_at": recorded,
                              "evidence_fingerprint": evidence_fingerprint(s), "approved_by": None,
                              "approved_at": None, "issued_at": None})
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
    elif action == "note":
        s["notes"].append({"id": eid, **data, "actor_id": uid, "at": recorded})
    elif action == "followup":
        item(s, "requests", data["request_id"])
        require(dt(data["next_due_at"]) >= dt(recorded), "Next follow-up must not be in the past", 422)
        s["followups"].append({"id": eid, **data, "actor_id": uid, "at": recorded})
    else:
        raise RuleError("Unknown command", 422)
    s["version"] += 1
    return s
