"""Actual Chromium MFA enrollment, recovery, session revocation and password change."""
import os
import socket
import threading
import time
from pathlib import Path

import pytest
import uvicorn

from openviscera.app import create_app
from openviscera.authentication import totp
from openviscera.evidence import check_database

pytestmark = pytest.mark.skipif(os.environ.get("OV_BROWSER_TEST") != "1", reason="Opt-in real browser integration")
PASSWORD = "synthetic-test-password-123"
NEW_PASSWORD = "browser-new-synthetic-password-456"


def test_mfa_browser(env, tmp_path):
    from playwright.sync_api import sync_playwright
    store, users, _, _ = env
    with socket.socket() as socket_:
        socket_.bind(("127.0.0.1", 0))
        port = socket_.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    app = create_app(store.path, url, True, require_mfa=True)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", access_log=False, ws="none"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(.05)
    assert server.started
    screenshots = Path(os.environ.get("OV_SCREENSHOT_DIR", str(tmp_path / "screenshots")))
    screenshots.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(executable_path=os.environ.get("OV_CHROMIUM"), headless=True, args=["--no-sandbox"])
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            page.set_default_timeout(6000)
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            if os.environ.get("OV_BROWSER_INPROCESS") == "1":
                from fastapi.testclient import TestClient
                client = TestClient(app, base_url=url)
                def local_fetch(source, path, options):
                    response = client.request(options.get("method", "GET"), path,
                                              headers=options.get("headers", {}), content=options.get("body"))
                    return {"status": response.status_code, "text": response.text}
                page.expose_binding("ovTestFetch", local_fetch)
                static = Path(__file__).parents[1] / "src/openviscera/static"
                shell = (static / "index.html").read_text()
                for name in ["app", "controls", "lifecycle", "security"]:
                    shell = shell.replace(f'<script src="/static/{name}.js" defer></script>', '')
                shell = shell.replace('<link rel="stylesheet" href="/static/style.css">', '')
                page.set_content(shell)
                page.add_style_tag(content=(static / "style.css").read_text())
                page.evaluate("""() => {
                    window.fetch = async (path, options = {}) => {
                        const r = await window.ovTestFetch(path, options);
                        return {ok: r.status >= 200 && r.status < 300, status: r.status,
                                json: async () => JSON.parse(r.text), text: async () => r.text};
                    };
                    crypto.randomUUID = () => ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g,
                        c => (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16));
                }""")
                for name in ["app", "controls", "lifecycle", "security"]:
                    page.add_script_tag(content=(static / (name + ".js")).read_text())
            else:
                page.goto(url)
            def click(label):
                page.get_by_role("button", name=label, exact=True).click()
            def fill(name, value):
                page.locator(f'#modal [name="{name}"]').fill(value)
            def password_login(password=PASSWORD):
                page.get_by_label("Username", exact=True).fill("examiner")
                page.get_by_label("Password", exact=True).fill(password)
                click("Sign in to workbench")
            def factor_login(code):
                page.get_by_label("Authentication or recovery code", exact=True).fill(code)
                click("Verify and sign in")
            def save_codes():
                page.get_by_role("heading", name="Save your recovery codes", exact=True).wait_for()
                codes = page.locator(".recovery-codes").inner_text().splitlines()
                page.get_by_label("I have saved these codes securely").check()
                click("I saved my codes — sign in")
                return codes
            password_login()
            page.get_by_role("heading", name="Account security", exact=True).wait_for()
            assert page.get_by_text("This deployment requires MFA.", exact=False).is_visible()
            click("Set up authenticator")
            fill("current_password", PASSWORD)
            click("Create setup key")
            secret = page.locator("#mfa-setup-secret").inner_text()
            fill("code", totp(secret, int(time.time()) // 30))
            click("Enable MFA")
            codes = save_codes()
            assert len(codes) == 10
            assert page.locator("#mfa-setup-secret").count() == 0
            password_login()
            page.get_by_role("heading", name="Verify your sign-in", exact=True).wait_for()
            page.screenshot(path=str(screenshots / "mfa-signin.png"), full_page=True)
            factor_login(codes[0])
            page.get_by_role("button", name="Account", exact=True).wait_for()
            click("Account")
            page.get_by_text("MFA enabled", exact=True).wait_for()
            challenge = store.login("examiner", PASSWORD, "synthetic-other-browser")["challenge"]
            other_token, _, _ = store.complete_mfa_login(challenge, codes[1], "synthetic-other-browser")
            click("Refresh")
            page.get_by_role("button", name="Revoke session", exact=True).wait_for()
            click("Revoke all other sessions")
            page.get_by_role("button", name="Revoke session", exact=True).wait_for(state="hidden")
            from openviscera.domain import RuleError
            with pytest.raises(RuleError):
                store.session(other_token)
            page.screenshot(path=str(screenshots / "account-security.png"), full_page=True)
            click("Regenerate recovery codes")
            fill("current_password", PASSWORD)
            fill("code", codes[2])
            click("Confirm")
            replacements = save_codes()
            password_login()
            factor_login(codes[3])
            page.get_by_text("Invalid or expired authentication code/challenge", exact=False).wait_for()
            factor_login(replacements[0])
            page.get_by_role("button", name="Account", exact=True).wait_for()
            click("Account")
            click("Change password")
            fill("current_password", PASSWORD)
            fill("code", replacements[1])
            fill("new_password", NEW_PASSWORD)
            click("Change password and sign out")
            password_login(NEW_PASSWORD)
            factor_login(replacements[2])
            page.get_by_role("heading", name="Account security", exact=True).wait_for()
            page.set_viewport_size({"width": 390, "height": 844})
            page.screenshot(path=str(screenshots / "account-security-mobile.png"), full_page=True)
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
            if os.environ.get("OV_BROWSER_INPROCESS") != "1":
                assert page.evaluate("localStorage.length") == 0
            assert errors == []
            browser.close()
            check_database(store)
    finally:
        server.should_exit = True
        thread.join(timeout=10)
