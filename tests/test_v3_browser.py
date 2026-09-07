"""Real-browser retention, preservation, disposal, and reassignment forms."""
import os
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
import uvicorn
from fastapi.testclient import TestClient

from openviscera.app import create_app
from openviscera.domain import disposed, opinion_pending
from openviscera.evidence import check_database
from test_v3_lifecycle import ready

pytestmark = pytest.mark.skipif(os.environ.get("OV_BROWSER_TEST") != "1", reason="Opt-in real browser integration")


def test_browser_lifecycle_and_reassignment(env, tmp_path):
    from playwright.sync_api import sync_playwright
    store, users, _, d = env
    original = ready(d, "LIFECYCLE-UI")
    reassignment = ready(d, "REASSIGNMENT-UI")
    certificate = tmp_path / "synthetic-certificate.txt"
    certificate.write_text("Synthetic disposal certificate for browser validation. No real specimen was disposed.")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    server = uvicorn.Server(uvicorn.Config(create_app(store.path, url, True), host="127.0.0.1", port=port,
                                          log_level="error", access_log=False, ws="none"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    assert server.started
    screenshots = Path(os.environ.get("OV_SCREENSHOT_DIR", str(tmp_path / "screenshots")))
    screenshots.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=os.environ.get("OV_CHROMIUM"), headless=True,
                                                  args=["--no-sandbox"])
            page = browser.new_page(viewport={"width": 1440, "height": 1060}, timezone_id="UTC")
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            if os.environ.get("OV_BROWSER_INPROCESS") == "1":
                client = TestClient(create_app(store.path, url, True), base_url=url)
                def local_fetch(source, path, options):
                    response = client.request(options.get("method", "GET"), path,
                                              headers=options.get("headers", {}), content=options.get("body"))
                    return {"status": response.status_code, "text": response.text}
                page.expose_binding("ovTestFetch", local_fetch)
                static = Path(__file__).parents[1] / "src/openviscera/static"
                shell = (static / "index.html").read_text()
                for name in ["app", "controls", "lifecycle"]:
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
                for name in ["app", "controls", "lifecycle"]:
                    page.add_script_tag(content=(static / (name + ".js")).read_text())
            else:
                page.goto(url)

            def login(role):
                page.get_by_label("Username", exact=True).fill(role)
                page.get_by_label("Password", exact=True).fill("synthetic-test-password-123")
                page.get_by_role("button", name="Sign in to workbench", exact=True).click()
                page.get_by_role("button", name="Sign out", exact=True).wait_for()

            def logout():
                page.get_by_role("button", name="Sign out", exact=True).click()
                page.get_by_label("Username", exact=True).wait_for()

            def tab(name):
                page.locator(".tabs").get_by_role("button", name=name, exact=True).click()
                page.get_by_role("heading", name=name, exact=True).wait_for()

            def fill(name, value):
                page.locator(f"#modal [name='{name}']").fill(value)

            def save():
                page.locator("#modal").get_by_role("button", name="Save record", exact=True).click()
                try:
                    page.locator("#modal").wait_for(state="hidden", timeout=5000)
                except Exception:
                    print("FORM ERROR:", page.locator("#modal").inner_text())
                    raise

            def act(name):
                page.get_by_role("button", name=name, exact=True).click()

            login("examiner")
            page.evaluate("id => navigate('case/' + id)", original["id"])
            page.get_by_role("heading", name="LIFECYCLE-UI", exact=True).wait_for()
            tab("Lifecycle")
            act("Set retention")
            fill("retain_until", datetime.fromisoformat(d.due).strftime("%Y-%m-%dT%H:%M:%S"))
            fill("authority_reference", "SYNTHETIC-RETENTION-POLICY")
            fill("reason", "Human-entered retention instruction for synthetic browser test")
            save()
            logout()
            login("reviewer")
            act("Review retention")
            fill("reason", "Independently checked the synthetic retention instruction")
            save()
            logout()
            login("coordinator")
            act("Place case hold")
            fill("authority_reference", "SYNTHETIC-PRESERVATION-HOLD")
            fill("reason", "Preserve all specimens pending documented authority")
            save()
            assert page.get_by_role("button", name="Propose disposal", exact=True).count() == 0
            page.screenshot(path=str(screenshots / "lifecycle-held.png"), full_page=True)
            act("Request hold release")
            fill("authority_reference", "SYNTHETIC-HOLD-RELEASE")
            fill("reason", "New external instruction requests hold release")
            save()
            logout()
            login("reviewer")
            act("Review hold release")
            fill("reason", "Independently checked release authorization")
            save()
            logout()
            login("examiner")
            act("Propose disposal")
            fill("authority_reference", "SYNTHETIC-DISPOSAL-AUTHORITY")
            fill("method", "Human-entered synthetic method; no physical action")
            fill("reason", "Recorded workflow gates and authority reviewed")
            save()
            logout()
            login("reviewer")
            act("Review disposal")
            fill("reason", "Independent synthetic disposal review")
            save()
            logout()
            login("examiner")
            act("Attach disposal certificate")
            page.locator("#modal input[type=file]").set_input_files(certificate)
            save()
            act("Record completed disposal")
            fill("occurred_at", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3])
            fill("note", "Synthetic documentary completion; original evidence retained")
            save()
            page.get_by_text("Disposed — physical workflow closed", exact=True).wait_for()
            page.screenshot(path=str(screenshots / "lifecycle-completed.png"), full_page=True)
            tab("Specimens")
            assert page.get_by_role("button", name="Handover", exact=True).count() == 0
            assert page.get_by_role("button", name="Reseal", exact=True).count() == 0
            final = store.get_case(users["examiner"], original["id"])
            assert disposed(final, final["specimens"][0]["id"])
            assert final["opinions"] == original["opinions"] and not opinion_pending(final)

            page.evaluate("id => navigate('case/' + id)", reassignment["id"])
            page.get_by_role("heading", name="REASSIGNMENT-UI", exact=True).wait_for()
            tab("Lifecycle")
            act("Reassign examiner")
            page.locator("#modal [name=new_examiner_id]").select_option(users["other_examiner"]["id"])
            fill("reason", "Synthetic reassignment after staff responsibility change")
            save()
            logout()
            login("reviewer")
            act("Review reassignment")
            fill("reason", "Independently approved the replacement examiner")
            save()
            logout()
            login("other_examiner")
            page.get_by_text("Further opinion work pending", exact=True).wait_for()
            final = store.get_case(users["other_examiner"], reassignment["id"])
            assert final["examiner_id"] == users["other_examiner"]["id"]
            assert final["opinions"] == reassignment["opinions"]
            page.screenshot(path=str(screenshots / "examiner-reassignment.png"), full_page=True)
            page.set_viewport_size({"width": 390, "height": 844})
            page.screenshot(path=str(screenshots / "lifecycle-mobile.png"), full_page=True)
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            assert errors == []
            browser.close()
            check_database(store)
    finally:
        server.should_exit = True
        thread.join(timeout=10)
