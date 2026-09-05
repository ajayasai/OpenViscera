"""Synthetic-only demonstrations. Credentials are generated, not hardcoded."""
import hashlib
import io
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from reportlab.pdfgen.canvas import Canvas


def sample_pdf(message="SYNTHETIC LABORATORY REPORT - NOT FOR CLINICAL USE"):
    stream = io.BytesIO()
    canvas = Canvas(stream)
    canvas.setTitle("Synthetic OpenViscera test report")
    canvas.drawString(50, 790, message)
    canvas.drawString(50, 770, "Administrative workflow demonstration. No medical conclusion.")
    canvas.save()
    return stream.getvalue()


class Driver:
    """Small integration-test/demo client exercising the same validated command service."""
    def __init__(self, store, users, lab):
        self.store, self.users, self.lab = store, users, lab
        self.past = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        self.due = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

    def new(self, ref, actor=None):
        actor = actor or self.users["examiner"]
        return self.store.create_case(actor, {"case_ref": ref, "authority": "Synthetic requesting authority",
                                             "examiner_id": actor["id"]}, uuid.uuid4().hex)["case"]

    def do(self, case_id, action, data, role="examiner"):
        actor = self.users[role] if isinstance(role, str) else role
        version = self.store.get_case(actor, case_id)["version"]
        return self.store.command(actor, case_id, action, data, version, uuid.uuid4().hex)["case"]

    def attachment(self, case_id, specimen_id, role="coordinator", content=None):
        actor = self.users[role]
        content = content or sample_pdf()
        version = self.store.get_case(actor, case_id)["version"]
        metadata = {"specimen_id": specimen_id, "filename": "synthetic-report.pdf", "media_type": "application/pdf",
                    "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        return self.store.command(actor, case_id, "attach", metadata, version, uuid.uuid4().hex, blob=content)["case"]

    def collected(self, ref):
        s = self.new(ref)
        return self.do(s["id"], "collect", {"container_id": "DEMO-" + ref, "description": "Synthetic specimen",
                                          "quantity": "1", "unit": "container", "preservative": "Examiner-entered test value",
                                          "collected_at": self.past, "location": "Synthetic collection room"})

    def requested(self, ref):
        s = self.collected(ref)
        return self.do(s["id"], "request", {"specimen_id": s["specimens"][0]["id"],
                                           "examination": "Synthetic external examination", "lab_id": self.lab["id"],
                                           "due_at": self.due})

    def dispatched(self, ref, external=False, courier=False):
        s = self.requested(ref)
        sp = s["specimens"][0]["id"]
        s = self.do(s["id"], "seal", {"specimen_id": sp, "seal_ref": "SYNTHETIC-SEAL-01",
                                      "occurred_at": self.past, "reason": "Initial synthetic seal record"})
        recipient = ({"recipient_lab_id": self.lab["id"], "recipient_name": "Synthetic lab receiving officer"}
                     if external else {"recipient_id": self.users["courier" if courier else "lab"]["id"]})
        return self.do(s["id"], "handover", {"specimen_id": sp, **recipient, "occurred_at": self.past,
                                             "destination": "Synthetic partner laboratory", "note": "Synthetic dispatch"})

    def received(self, ref, external=False, discrepancy=False):
        s = self.dispatched(ref, external)
        data = {"transfer_id": s["transfers"][0]["id"], "occurred_at": self.past,
                "observed_seal": "OTHER-SEAL" if discrepancy else "SYNTHETIC-SEAL-01",
                "discrepancy": discrepancy, "note": "Synthetic receipt acknowledgement"}
        if external:
            s = self.attachment(s["id"], s["specimens"][0]["id"])
            data.update(attachment_id=s["attachments"][-1]["id"], recipient_name="Synthetic external recipient")
            self.do(s["id"], "record_receipt", data, "coordinator")
        else:
            self.do(s["id"], "acknowledge", data, "lab")
        return self.store.get_case(self.users["examiner"], s["id"])

    def reported(self, ref):
        s = self.received(ref)
        return self.add_report(s)

    def add_report(self, s):
        s = self.attachment(s["id"], s["specimens"][0]["id"], content=sample_pdf("SYNTHETIC REPORT " + uuid.uuid4().hex))
        return self.do(s["id"], "report", {"request_id": s["requests"][0]["id"],
                                           "attachment_id": s["attachments"][-1]["id"],
                                           "laboratory_reference": "SYN-REPORT-" + str(len(s["reports"]) + 1),
                                           "received_at": self.past,
                                           "supersedes": s["reports"][-1]["id"] if s["reports"] else None}, "coordinator")

    def reviewed(self, ref):
        s = self.reported(ref)
        return self.do(s["id"], "review", {"report_id": s["reports"][-1]["id"],
                                          "note": "Synthetic human review recorded; no interpretation inferred"})

    def issued(self, ref):
        s = self.reviewed(ref)
        s = self.do(s["id"], "draft", {"kind": "final", "body": "Synthetic final opinion for workflow testing only.",
                                      "report_ids": [s["reports"][-1]["id"]]})
        oid = s["opinions"][-1]["id"]
        s = self.do(s["id"], "approve", {"opinion_id": oid}, "reviewer")
        return self.do(s["id"], "issue", {"opinion_id": oid})


def populate(store):
    org = "synthetic-department"
    lab = store.add_lab(org, {"name": "Synthetic Partner Laboratory", "turnaround_days": 30})
    users, credentials = {}, {}
    for role in ["admin", "examiner", "coordinator", "courier", "lab", "reviewer", "auditor"]:
        password = secrets.token_urlsafe(18)
        users[role] = store.add_user(org, {"username": role, "display_name": "Demo " + role.title(),
                                         "role": role, "lab_id": lab["id"] if role == "lab" else None,
                                         "password": password})
        credentials[role] = password
    d = Driver(store, users, lab)
    d.requested("SYN-001")
    d.dispatched("SYN-002", courier=True)
    d.received("SYN-003")
    d.reported("SYN-004")
    d.reviewed("SYN-005")
    d.add_report(d.issued("SYN-006"))
    d.received("SYN-007", external=True, discrepancy=True)
    return credentials
