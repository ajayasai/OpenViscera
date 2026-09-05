"""Privacy-minimizing QR labels and administrative PDFs; never medical interpretation."""
import io
import os
from html import escape

import qrcode
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image,
                               KeepTogether)

from .domain import evidence_fingerprint, item, now_iso, require


def document(state, kind, identifier=None, events=None, catalog=None):
    require(kind in {"label", "dispatch", "receipt", "chronology", "opinion"}, "Unknown document type", 404)
    catalog = catalog or {"users": [], "labs": []}
    def account(identifier):
        user = next((u for u in catalog["users"] if u["id"] == identifier), None)
        return user["display_name"] + " (" + identifier + ")" if user else identifier
    def laboratory(identifier):
        lab = next((v for v in catalog["labs"] if v["id"] == identifier), None)
        return lab["name"] if lab else identifier
    styles = getSampleStyleSheet()
    font = os.environ.get("OV_PDF_FONT")
    font_name = "Helvetica"
    if font:
        # Deployment-controlled font path, never a request parameter.
        if "OVUnicode" not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont("OVUnicode", font))
        font_name = "OVUnicode"
    for name in ["Normal", "BodyText", "Title", "Heading1", "Heading2"]:
        styles[name].fontName = font_name
    styles["BodyText"].fontSize = 9
    styles["BodyText"].leading = 13
    styles.add(ParagraphStyle(name="SmallOV", fontName=font_name, fontSize=7, leading=10,
                              textColor=colors.HexColor("#46576B")))
    output, story = io.BytesIO(), []

    def text(value, style="BodyText"):
        value = str(value)
        if not font:
            require(all(ord(ch) < 256 for ch in value),
                    "This PDF needs a Unicode font. Configure OV_PDF_FONT on the server; JSON export preserves all text.", 422)
        return Paragraph(escape(value).replace("\n", "<br/>"), styles[style])

    def pairs(rows):
        table = Table([[text(k), text(v if v is not None else "Not recorded")]
                       for k, v in rows], colWidths=[43 * mm, 125 * mm])
        table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                   ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                                   ("TOPPADDING", (0, 0), (-1, -1), 5),
                                   ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#DCE3E8"))]))
        story.extend([table, Spacer(1, 5 * mm)])

    if kind == "label":
        sp = item(state, "specimens", identifier)
        qr = qrcode.make("openviscera:specimen:" + sp["id"])
        image = io.BytesIO()
        qr.save(image, format="PNG")
        image.seek(0)
        label = [text("SPECIMEN IDENTIFIER", "Heading2"), text(sp["container_id"], "Title"),
                 text("Case: " + state["case_ref"]), text(sp["description"]),
                 text("Collected: " + sp["collected_at"]), text("Seal: " + str(sp["seal_ref"] or "NOT SEALED")),
                 text("Preservative (as entered): " + sp["preservative"]),
                 Image(image, width=28 * mm, height=28 * mm),
                 text("QR contains an opaque identifier only, not a name or medical result.", "SmallOV")]
        story.append(KeepTogether(label))
    else:
        titles = {"dispatch": "Specimen dispatch covering letter", "receipt": "Handover receipt",
                  "chronology": "Case chronology", "opinion": "Expert opinion record"}
        story.extend([text("OPENVISCERA", "Heading2"), text(titles[kind], "Title"),
                      text("Case " + state["case_ref"] + " | Version " + str(state["version"])), Spacer(1, 5 * mm)])
        if kind == "dispatch":
            transfer = item(state, "transfers", identifier)
            sp = item(state, "specimens", transfer["specimen_id"])
            pairs([("Authority", state["authority"]), ("Container", sp["container_id"]),
                   ("Specimen", sp["description"]), ("Quantity", sp["quantity"] + " " + sp["unit"]),
                   ("Preservative (entered)", sp["preservative"]), ("Seal at dispatch", transfer["seal_ref"]),
                   ("Sender", account(transfer["sender_id"])),
                   ("Recipient", transfer["recipient_name"] or account(transfer["recipient_id"])),
                   ("Destination", transfer["destination"]), ("Handover time", transfer["occurred_at"]),
                   ("Reference", transfer["id"])])
            story.append(text("Requested examinations", "Heading2"))
            for request in state["requests"]:
                if request["specimen_id"] == sp["id"]:
                    story.append(text(request["examination"] + " | Laboratory " + laboratory(request["lab_id"])))
            story.append(text("Please acknowledge receipt, seal condition and any discrepancy. This covering letter is not proof of receipt."))
        elif kind == "receipt":
            transfer = item(state, "transfers", identifier)
            pairs([("Transfer reference", transfer["id"]), ("Sender", account(transfer["sender_id"])),
                   ("Intended recipient", transfer["recipient_name"] or account(transfer["recipient_id"])),
                   ("Dispatched at", transfer["occurred_at"]), ("Acknowledged at", transfer["acknowledged_at"]),
                   ("Seal dispatched", transfer["seal_ref"]), ("Seal observed", transfer.get("observed_seal")),
                   ("Discrepancy", str(transfer["discrepancy"])),
                   ("Receipt evidence", transfer.get("receipt_evidence_id")),
                   ("Acknowledgement note", transfer.get("acknowledgement_note"))])
            story.append(text("An unacknowledged record is a pending handover, not a completed receipt. External receipts are evidence-backed staff transcriptions, not authenticated laboratory signatures."))
        elif kind == "opinion":
            opinion = item(state, "opinions", identifier)
            status = "ISSUED" if opinion["issued_at"] else "DRAFT / NOT ISSUED"
            story.extend([text(status, "Heading1"), text(opinion["kind"].upper(), "Heading2"), text(opinion["body"]), Spacer(1, 6 * mm)])
            if opinion["issued_at"] and opinion["evidence_fingerprint"] != evidence_fingerprint(state):
                story.append(text("HISTORICAL ISSUED RECORD: later evidence has been recorded. Check the current pending-opinion status.", "Heading2"))
            pairs([("Author", account(opinion["author_id"])), ("Independent approver", account(opinion["approved_by"])),
                   ("Approved at", opinion["approved_at"]), ("Issued at", opinion["issued_at"]),
                   ("Evidence fingerprint", opinion["evidence_fingerprint"])])
            story.append(text("Incorporated report revisions", "Heading2"))
            for rid in opinion["report_ids"]:
                report = item(state, "reports", rid)
                story.append(text(report["laboratory_reference"] + " | revision " + str(report["revision"]) + " | " + rid))
        else:
            require(events is not None, "Chronology requires verified events")
            for event in events:
                b = event["body"]
                story.extend([text(f'{b["seq"]:04d} / {b["action"]}', "Heading2"),
                              text(b["recorded_at"] + " | " + b["actor"]["display_name"]),
                              text("Event: " + b["event_id"], "SmallOV")])
                for key, value in b["data"].items():
                    story.append(text(key.replace("_", " ") + ": " + str(value)))
                story.append(text("Event hash: " + event["hash"], "SmallOV"))
    story.extend([Spacer(1, 6 * mm), text("Generated " + now_iso() + ". Verify against the signed evidence bundle. Administrative tracking only; no medical inference or legal certification.", "SmallOV")])
    doc = SimpleDocTemplate(output, pagesize=A4, topMargin=16 * mm, bottomMargin=19 * mm,
                            leftMargin=20 * mm, rightMargin=20 * mm, title="OpenViscera " + kind)

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont(font_name, 8)
        canvas.drawString(20 * mm, 10 * mm, "OpenViscera | Confidential case document")
        canvas.drawRightString(190 * mm, 10 * mm, str(doc.page))
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()
