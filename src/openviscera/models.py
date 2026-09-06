"""Strict command contracts. No medical interpretation or preservative recommendations."""
from decimal import Decimal
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, model_validator

Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=240)]
Note = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=12000)]
Identifier = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class CaseCreate(Strict):
    case_ref: Text
    authority: Text
    examiner_id: Identifier
    priority: Literal["routine", "urgent"] = "routine"


class Collect(Strict):
    container_id: Identifier
    description: Text
    quantity: Annotated[Decimal, Field(gt=0, le=1000000, max_digits=16, decimal_places=6)]
    unit: Text
    preservative: Text
    collected_at: AwareDatetime
    location: Text


class Seal(Strict):
    specimen_id: Identifier
    seal_ref: Text
    occurred_at: AwareDatetime
    reason: Note


class RequestExam(Strict):
    specimen_id: Identifier
    examination: Text
    lab_id: Identifier
    due_at: AwareDatetime


class Handover(Strict):
    specimen_id: Identifier
    recipient_id: Identifier | None = None
    recipient_lab_id: Identifier | None = None
    recipient_name: Text | None = None
    occurred_at: AwareDatetime
    destination: Text
    note: Note


    @model_validator(mode="after")
    def one_recipient(self):
        if bool(self.recipient_id) == bool(self.recipient_lab_id):
            raise ValueError("Choose exactly one user recipient or external laboratory")
        if self.recipient_lab_id and not self.recipient_name:
            raise ValueError("Named external recipient is required")
        return self


class Acknowledge(Strict):
    transfer_id: Identifier
    occurred_at: AwareDatetime
    observed_seal: Text
    discrepancy: bool = False
    note: Note


class RecordReceipt(Acknowledge):
    attachment_id: Identifier
    recipient_name: Text


class Resolve(Strict):
    transfer_id: Identifier
    reason: Note


class Attach(Strict):
    specimen_id: Identifier
    filename: Text
    media_type: Literal["application/pdf", "image/png", "image/jpeg", "text/plain"]
    sha256: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
    size: Annotated[int, Field(gt=0, le=5 * 1024 * 1024)]


class Report(Strict):
    request_id: Identifier
    attachment_id: Identifier
    laboratory_reference: Text
    received_at: AwareDatetime
    supersedes: Identifier | None = None


class Review(Strict):
    report_id: Identifier
    note: Note


class Draft(Strict):
    kind: Literal["final", "supplementary"]
    body: Note
    report_ids: Annotated[list[Identifier], Field(min_length=1, max_length=200)]


class OpinionAction(Strict):
    opinion_id: Identifier


class AddNote(Strict):
    text: Note


class Followup(Strict):
    request_id: Identifier
    method: Literal["phone", "email", "letter", "portal", "other"]
    note: Note
    next_due_at: AwareDatetime


class Command(Strict):
    expected_version: Annotated[int, Field(ge=1)]
    data: dict


class Upload(Strict):
    expected_version: Annotated[int, Field(ge=1)]
    specimen_id: Identifier
    filename: Text
    media_type: Literal["application/pdf", "image/png", "image/jpeg", "text/plain"]
    content_b64: Annotated[str, StringConstraints(min_length=1, max_length=7 * 1024 * 1024)]


class Login(Strict):
    username: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    password: Annotated[str, StringConstraints(strip_whitespace=False, min_length=1, max_length=1024)]


class UserCreate(Strict):
    username: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_.-]{3,64}$")]
    display_name: Text
    role: Literal["admin", "examiner", "coordinator", "courier", "lab", "reviewer", "auditor"]
    lab_id: Identifier | None = None
    password: Annotated[str, StringConstraints(strip_whitespace=False, min_length=14, max_length=1024)]


class LabCreate(Strict):
    name: Text
    turnaround_days: Annotated[int, Field(ge=1, le=730)] = 30


MODELS = {
    "collect": Collect, "seal": Seal, "request": RequestExam, "handover": Handover,
    "acknowledge": Acknowledge, "record_receipt": RecordReceipt, "resolve": Resolve, "attach": Attach, "report": Report,
    "review": Review, "draft": Draft, "approve": OpinionAction, "issue": OpinionAction,
    "note": AddNote, "followup": Followup,
}
ROLES = {
    "collect": {"examiner", "coordinator"}, "seal": {"examiner", "coordinator", "courier", "lab"},
    "request": {"examiner", "coordinator"}, "handover": {"examiner", "coordinator", "courier", "lab"},
    "acknowledge": {"examiner", "coordinator", "courier", "lab"},
    "record_receipt": {"examiner", "coordinator"}, "resolve": {"reviewer"},
    "attach": {"examiner", "coordinator", "lab", "reviewer"},
    "report": {"examiner", "coordinator", "lab"}, "review": {"examiner", "reviewer"},
    "draft": {"examiner"}, "approve": {"reviewer"}, "issue": {"examiner"},
    "note": {"examiner", "coordinator", "reviewer"}, "followup": {"examiner", "coordinator"},
}


class UserStatus(Strict):
    active: bool


# Version-2 additive commands. Historic version-1 contracts are unchanged.
class AccessPolicy(Strict):
    mode: Literal["department", "restricted"]
    member_ids: Annotated[list[Identifier], Field(max_length=100)]
    reason: Note


class Correct(Strict):
    target: Literal["case", "specimen"]
    target_id: Identifier
    field: Literal["authority", "description", "preservative", "quantity", "unit"]
    expected_value: Text
    replacement: Text
    reason: Note


class CorrectionDecision(Strict):
    correction_id: Identifier
    decision: Literal["approve", "reject"]
    reason: Note


class WithdrawReport(Strict):
    report_id: Identifier
    reason: Note


class WithdrawalDecision(Strict):
    withdrawal_id: Identifier
    decision: Literal["approve", "reject"]
    reason: Note


class WithdrawOpinion(Strict):
    opinion_id: Identifier
    reason: Note


class RequestReceipt(Strict):
    request_id: Identifier
    accepted_at: AwareDatetime
    attachment_id: Identifier | None = None
    note: Note


class RecordReturn(Strict):
    specimen_id: Identifier
    attachment_id: Identifier
    external_sender_name: Text
    occurred_at: AwareDatetime
    observed_seal: Text
    discrepancy: bool = False
    destination: Text
    note: Note


class BatchHandover(Strict):
    expected_version: Annotated[int, Field(ge=1)]
    items: Annotated[list[Handover], Field(min_length=1, max_length=100)]
    preview: bool = False


class ChangePassword(Strict):
    current_password: Annotated[str, StringConstraints(strip_whitespace=False, min_length=1, max_length=1024)]
    new_password: Annotated[str, StringConstraints(strip_whitespace=False, min_length=14, max_length=1024)]


MODELS.update({
    "access_policy": AccessPolicy, "correct": Correct, "decide_correction": CorrectionDecision,
    "withdraw_report": WithdrawReport, "decide_withdrawal": WithdrawalDecision,
    "withdraw_opinion": WithdrawOpinion, "request_receipt": RequestReceipt, "record_return": RecordReturn,
})
ROLES.update({
    "access_policy": {"admin", "examiner"}, "correct": {"examiner", "coordinator"},
    "decide_correction": {"reviewer"}, "withdraw_report": {"examiner", "coordinator"},
    "decide_withdrawal": {"reviewer"}, "withdraw_opinion": {"examiner", "reviewer"},
    "request_receipt": {"examiner", "coordinator", "lab"}, "record_return": {"examiner", "coordinator"},
})
