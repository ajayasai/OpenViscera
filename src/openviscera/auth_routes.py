"""Same-origin account security endpoints, without remote administrator MFA bypass."""
import base64
import io
from typing import Annotated

import qrcode
import qrcode.image.svg
from fastapi import Depends, Request
from fastapi.responses import JSONResponse
from pydantic import StringConstraints

from .domain import require
from .models import ChangePassword, Strict

Password = Annotated[str, StringConstraints(strip_whitespace=False, min_length=1, max_length=1024)]
Code = Annotated[str, StringConstraints(strip_whitespace=True, max_length=64)]


class SecurityProof(Strict):
    current_password: Password
    code: Code = ""


class PasswordChange(ChangePassword):
    code: Code = ""


class LoginFactor(Strict):
    challenge: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_-]{43}$")]
    code: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]


class SessionRevoke(Strict):
    session_id: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")] | None = None
    others: bool = False


def clear_cookie(response, secure):
    response.delete_cookie("ov_session", path="/", secure=secure, httponly=True, samesite="strict")
    return response


def login_response(result, request, store, secure, require_mfa):
    if isinstance(result, dict):
        return clear_cookie(JSONResponse(result), secure)
    token, csrf, actor = result
    request.state.actor = actor
    security = store.account_requirements(actor, require_mfa)
    response = JSONResponse({"user": actor, "csrf": csrf, "security": security})
    response.set_cookie("ov_session", token, httponly=True, secure=secure, samesite="strict", max_age=8 * 3600, path="/")
    return response


def install_auth_routes(app, store, auth, secure, require_mfa):
    @app.post("/api/login/mfa")
    def login_mfa(data: LoginFactor, request: Request):
        result = store.complete_mfa_login(data.challenge, data.code, request.client.host if request.client else "unknown")
        return login_response(result, request, store, secure, require_mfa)

    @app.get("/api/account/security")
    def security(request: Request, actor=Depends(auth)):
        return {**store.account_security(actor, request.cookies["ov_session"]),
                **store.account_requirements(actor, require_mfa), "mfa_required_by_policy": require_mfa}

    @app.post("/api/account/mfa/setup")
    def setup(data: SecurityProof, actor=Depends(auth)):
        result = store.begin_mfa_setup(actor, data.current_password)
        image = qrcode.make(result["uri"], image_factory=qrcode.image.svg.SvgPathImage)
        output = io.BytesIO()
        image.save(output)
        result["qr_data_url"] = "data:image/svg+xml;base64," + base64.b64encode(output.getvalue()).decode()
        return result

    @app.post("/api/account/mfa/confirm")
    def confirm(data: SecurityProof, actor=Depends(auth)):
        result = store.confirm_mfa_setup(actor, data.current_password, data.code)
        return clear_cookie(JSONResponse(result), secure)

    @app.post("/api/account/mfa/{operation}")
    def manage(operation: str, data: SecurityProof, actor=Depends(auth)):
        require(not require_mfa or operation != "disable", "Deployment policy requires MFA; disabling is forbidden", 403)
        result = store.manage_mfa(actor, data.current_password, data.code, operation)
        return clear_cookie(JSONResponse(result), secure)

    @app.post("/api/account/sessions/revoke")
    def revoke(data: SessionRevoke, request: Request, actor=Depends(auth)):
        result = store.revoke_account_sessions(actor, request.cookies["ov_session"], data.session_id, data.others)
        response = JSONResponse(result)
        return clear_cookie(response, secure) if result["reauthentication_required"] else response
