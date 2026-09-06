"""Authenticated, same-origin web API and local-asset browser workbench."""
import base64
import hashlib
import hmac
import os
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .domain import (RuleError, blockers, dt, evidence_fingerprint, latest_report, now_iso,
                     opinion_pending, require, report_withdrawal, opinion_withdrawal)
from .documents import document
from .evidence import export_bundle
from .models import (CaseCreate, Command, LabCreate, Login, MODELS, Upload, UserCreate, UserStatus,
                     BatchHandover, ChangePassword)
from .store import Store
from .governance import AccessAuditMiddleware

MAX_REQUEST = 8 * 1024 * 1024
STATIC = Path(__file__).parent / "static"


class RequestGuard:
    """Bound bodies even when Content-Length is missing; reject cross-site writes."""
    def __init__(self, app, origin, secure):
        self.app, self.origin, self.secure = app, origin, secure

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        messages = []
        if scope["method"] not in {"GET", "HEAD", "OPTIONS"}:
            origin = headers.get(b"origin", b"").decode("latin1")
            if (origin and origin != self.origin) or headers.get(b"sec-fetch-site") == b"cross-site":
                return await JSONResponse({"detail": "Cross-origin writes are forbidden"}, 403)(scope, receive, send)
            if headers.get(b"content-type", b"").split(b";")[0] != b"application/json":
                return await JSONResponse({"detail": "Use application/json"}, 415)(scope, receive, send)
            try:
                declared = int(headers.get(b"content-length", b"0"))
            except ValueError:
                return await JSONResponse({"detail": "Invalid Content-Length"}, 400)(scope, receive, send)
            if declared > MAX_REQUEST:
                return await JSONResponse({"detail": "Request body exceeds 8 MiB"}, 413)(scope, receive, send)
            total = 0
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                total += len(message.get("body", b""))
                if total > MAX_REQUEST:
                    return await JSONResponse({"detail": "Request body exceeds 8 MiB"}, 413)(scope, receive, send)
                messages.append(message)
                if not message.get("more_body", False):
                    break

        async def buffered_receive():
            return messages.pop(0) if messages else await receive()

        async def secure_send(message):
            if message["type"] == "http.response.start":
                extra = [(b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff"),
                         (b"referrer-policy", b"no-referrer"), (b"x-frame-options", b"DENY"),
                         (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                         (b"x-request-id", scope.get("ov_request_id", uuid.uuid4().hex).encode()),
                         (b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self'; "
                          b"img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")]
                if self.secure:
                    extra.append((b"strict-transport-security", b"max-age=31536000"))
                message["headers"] = list(message.get("headers", [])) + extra
            await send(message)
        await self.app(scope, buffered_receive, secure_send)


def queue_snapshot(states, actor):
    queues = {name: [] for name in ["dispatch", "receipt", "reports", "review", "opinions", "exceptions", "followups"]}
    now = dt(now_iso())
    for s in states:
        def add(name, label, **extra):
            queues[name].append({"case_id": s["id"], "case_ref": s["case_ref"], "priority": s["priority"],
                                 "label": label, **extra})
        for sp in s["specimens"]:
            if not any(t["specimen_id"] == sp["id"] for t in s["transfers"]):
                add("dispatch", sp["container_id"], specimen_id=sp["id"], sealed=bool(sp["seal_ref"]))
            if sp["quarantined"]:
                add("exceptions", sp["container_id"] + ": unresolved discrepancy", specimen_id=sp["id"])
        for t in s["transfers"]:
            if not t["acknowledged_at"]:
                add("receipt", "Handover acknowledgement missing", transfer_id=t["id"], due_at=t["occurred_at"])
        for r in s["requests"]:
            if not r["received_at"] and any(t["specimen_id"] == r["specimen_id"] and t["acknowledged_at"] for t in s["transfers"]):
                add("receipt", "Laboratory receipt missing: " + r["examination"], request_id=r["id"])
            report = latest_report(s, r["id"])
            if not report:
                days = max(0, (now - dt(r["due_at"])).days)
                add("reports", r["examination"], request_id=r["id"], due_at=r["due_at"], overdue_days=days,
                    overdue=now > dt(r["due_at"]))
                followups = [f for f in s["followups"] if f["request_id"] == r["id"]]
                if followups and dt(followups[-1]["next_due_at"]) <= now:
                    add("followups", r["examination"], request_id=r["id"], due_at=followups[-1]["next_due_at"])
            elif not report["reviewed_at"]:
                add("review", report["laboratory_reference"], report_id=report["id"], revision=report["revision"])
        if actor["role"] != "lab" and opinion_pending(s):
            add("opinions", "Supplementary opinion pending" if any(o["issued_at"] for o in s["opinions"])
                else "Final opinion pending", blockers=blockers(s))
    for entries in queues.values():
        entries.sort(key=lambda x: (x["priority"] != "urgent", x.get("due_at", "9999"), x["case_ref"]))
    return {"case_count": len(states), "counts": {k: len(v) for k, v in queues.items()},
            "queues": {k: v[:200] for k, v in queues.items()}, "queue_limit": 200, "generated_at": now_iso()}


def create_app(data_dir=None, origin=None, insecure_local=False):
    data_dir = data_dir or os.environ.get("OV_DATA", "./var")
    origin = (origin or os.environ.get("OV_ORIGIN", "https://localhost")).rstrip("/")
    parsed = urlsplit(origin)
    require(parsed.scheme in {"http", "https"} and parsed.hostname and not parsed.username and
            not parsed.path and not parsed.query and not parsed.fragment, "Configure a valid OV_ORIGIN", 503)
    if insecure_local:
        require(parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"},
                "Insecure mode is restricted to loopback origins", 503)
    else:
        require(parsed.scheme == "https", "HTTPS origin required outside explicit loopback demo mode", 503)
    store = Store(data_dir)
    app = FastAPI(title="OpenViscera", version="0.2.0", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store
    app.add_middleware(RequestGuard, origin=origin, secure=not insecure_local)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[parsed.hostname])
    app.add_middleware(AccessAuditMiddleware, store=store)

    @app.exception_handler(RuleError)
    async def rule_error(request, exc):
        return JSONResponse({"detail": exc.message}, status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def input_error(request, exc):
        errors = [{"field": ".".join(map(str, e["loc"])), "message": e["msg"]} for e in exc.errors()]
        return JSONResponse({"detail": "Request validation failed", "errors": errors}, status_code=422)

    def auth(request: Request):
        actor, csrf = store.session(request.cookies.get("ov_session"))
        request.state.actor = actor
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            require(hmac.compare_digest(request.headers.get("X-CSRF-Token", ""), csrf), "Invalid CSRF token", 403)
        return actor

    def key(request):
        return request.headers.get("Idempotency-Key", "")

    def enriched(actor, s):
        return {"case": s,
                "report_status": {r["id"]: ("withdrawn" if (report_withdrawal(s, r["id"]) or {}).get("status") == "approved"
                                             else "disputed" if report_withdrawal(s, r["id"]) else
                                             "superseded" if (latest_report(s, r["request_id"]) or {}).get("id") != r["id"]
                                             else "reviewed" if r["reviewed_at"] else "received") for r in s["reports"]},
                "opinion_status": {o["id"]: ("withdrawn" if opinion_withdrawal(s, o["id"]) else
                                               "issued" if o["issued_at"] else "approved" if o["approved_at"] else "draft")
                                   for o in s["opinions"]},
                "blockers": blockers(s) if actor["role"] != "lab" else [],
                "pending_opinion": opinion_pending(s) if actor["role"] != "lab" else None,
                "evidence_fingerprint": evidence_fingerprint(s) if actor["role"] != "lab" else None}

    @app.get("/healthz")
    def health():
        return {"status": "ok", "version": "0.2.0"}

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html", media_type="text/html")

    @app.post("/api/login")
    def login(data: Login, request: Request):
        token, csrf, actor = store.login(data.username, data.password, request.client.host if request.client else "unknown")
        request.state.actor = actor
        response = JSONResponse({"user": actor, "csrf": csrf})
        response.set_cookie("ov_session", token, httponly=True, secure=not insecure_local,
                            samesite="strict", max_age=8 * 3600, path="/")
        return response

    @app.post("/api/logout")
    def logout(request: Request, actor=Depends(auth)):
        store.logout(request.cookies["ov_session"])
        response = JSONResponse({"ok": True})
        response.delete_cookie("ov_session", path="/", secure=not insecure_local, httponly=True, samesite="strict")
        return response

    @app.get("/api/me")
    def me(request: Request, actor=Depends(auth)):
        _, csrf = store.session(request.cookies["ov_session"])
        return {"user": actor, "csrf": csrf, "public_key": store.public_b64}

    @app.get("/api/catalog")
    def catalog(actor=Depends(auth)):
        return store.catalog(actor)

    @app.post("/api/admin/labs", status_code=201)
    def add_lab(data: LabCreate, actor=Depends(auth)):
        require(actor["role"] == "admin", "Administrator required", 403)
        return store.add_lab(actor["org_id"], data.model_dump(), actor["id"])

    @app.post("/api/admin/users", status_code=201)
    def add_user(data: UserCreate, actor=Depends(auth)):
        require(actor["role"] == "admin", "Administrator required", 403)
        return store.add_user(actor["org_id"], data.model_dump(), actor["id"])

    @app.post("/api/admin/users/{user_id}/active")
    def user_active(user_id: str, data: UserStatus, actor=Depends(auth)):
        store.set_active(actor, user_id, data.active)
        return {"ok": True}

    @app.get("/api/schema")
    def schema(actor=Depends(auth)):
        return {"openapi": app.openapi(), "commands": {name: model.model_json_schema() for name, model in MODELS.items()}}

    @app.get("/api/cases")
    def cases(request: Request, search: str = "", limit: int = 200, offset: int = 0, actor=Depends(auth)):
        require(len(search) <= 240, "Search too long", 422)
        result = store.list_cases(actor, search, limit, offset)
        request.state.audit_case_ids = [s["id"] for s in result["items"]]
        return result

    @app.post("/api/cases", status_code=201)
    def create_case(data: CaseCreate, request: Request, actor=Depends(auth)):
        result = store.create_case(actor, data.model_dump(), key(request))
        request.state.audit_case_ids = [result["case"]["id"]]
        return result

    @app.post("/api/account/password")
    def change_password(data: ChangePassword, request: Request, actor=Depends(auth)):
        store.change_password(actor, data.current_password, data.new_password)
        response = JSONResponse({"ok": True, "reauthentication_required": True})
        response.delete_cookie("ov_session", path="/", secure=not insecure_local, httponly=True, samesite="strict")
        return response

    @app.get("/api/admin/access-audit")
    def access_audit(offset: int = 0, limit: int = 200, actor=Depends(auth)):
        return store.access_audit(actor, offset, limit)

    @app.get("/api/locate")
    def locate(request: Request, token: str, actor=Depends(auth)):
        found = store.locate_specimen(actor, token)
        request.state.audit_case_ids = [found["case_id"]]
        return found

    @app.post("/api/cases/{case_id}/batch-handover")
    def batch_handover(case_id: str, data: BatchHandover, request: Request, actor=Depends(auth)):
        return store.batch_handover(actor, case_id, data.model_dump(mode="json"), key(request))

    @app.get("/api/cases/{case_id}")
    def case(case_id: str, actor=Depends(auth)):
        return enriched(actor, store.get_case(actor, case_id))

    @app.post("/api/cases/{case_id}/commands/{action}")
    def command(case_id: str, action: str, data: Command, request: Request, actor=Depends(auth)):
        return store.command(actor, case_id, action, data.data, data.expected_version, key(request))

    @app.post("/api/cases/{case_id}/attachments", status_code=201)
    def upload(case_id: str, data: Upload, request: Request, actor=Depends(auth)):
        try:
            content = base64.b64decode(data.content_b64, validate=True)
        except ValueError as exc:
            raise RuleError("Attachment is not valid base64", 422) from exc
        require(0 < len(content) <= 5 * 1024 * 1024, "Attachment must be between 1 byte and 5 MiB", 413)
        signatures = {"application/pdf": b"%PDF-", "image/png": b"\x89PNG\r\n\x1a\n", "image/jpeg": b"\xff\xd8\xff"}
        if data.media_type in signatures:
            require(content.startswith(signatures[data.media_type]), "Attachment format signature mismatch", 422)
        else:
            try:
                text = content.decode("utf-8")
                require("\x00" not in text, "Text attachment contains binary data", 422)
            except UnicodeDecodeError as exc:
                raise RuleError("Text attachment must be UTF-8", 422) from exc
        # Original user name is metadata only. Never use it as a filesystem path or HTTP header.
        require("/" not in data.filename and "\\" not in data.filename and not any(ord(x) < 32 for x in data.filename),
                "Unsafe attachment filename", 422)
        values = {"specimen_id": data.specimen_id, "filename": data.filename, "media_type": data.media_type,
                  "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
        return store.command(actor, case_id, "attach", values, data.expected_version, key(request), blob=content)

    @app.get("/api/cases/{case_id}/attachments/{attachment_id}")
    def attachment(case_id: str, attachment_id: str, actor=Depends(auth)):
        meta, content = store.attachment(actor, case_id, attachment_id)
        suffix = {"application/pdf": ".pdf", "image/png": ".png", "image/jpeg": ".jpg", "text/plain": ".txt"}[meta["media_type"]]
        return Response(content, media_type=meta["media_type"], headers={
            "Content-Disposition": 'attachment; filename="' + meta["sha256"] + suffix + '"'})

    @app.get("/api/dashboard")
    def dashboard(request: Request, actor=Depends(auth)):
        states = store.all_cases(actor)
        request.state.audit_case_ids = [s["id"] for s in states]
        return queue_snapshot(states, actor)

    @app.get("/api/cases/{case_id}/events")
    def events(case_id: str, actor=Depends(auth)):
        _, ledger, _, head = store.evidence(actor, case_id)
        return {"events": ledger, "head": head, "public_key": store.public_b64}

    @app.get("/api/cases/{case_id}/export")
    def export(case_id: str, actor=Depends(auth)):
        content = export_bundle(store, actor, case_id)
        return Response(content, media_type="application/zip", headers={
            "Content-Disposition": 'attachment; filename="OpenViscera-evidence.zip"'})

    @app.get("/api/cases/{case_id}/documents/{kind}")
    def pdf(case_id: str, kind: str, identifier: str | None = None, actor=Depends(auth)):
        require(actor["role"] != "lab", "Departmental document export requires a staff account", 403)
        state, ledger, _, _ = store.evidence(actor, case_id)
        content = document(state, kind, identifier, ledger, store.catalog(actor))
        return Response(content, media_type="application/pdf", headers={
            "Content-Disposition": 'attachment; filename="OpenViscera-document.pdf"'})

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app
