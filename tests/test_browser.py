"""Opt-in real Chromium workflow. Run OV_BROWSER_TEST=1 pytest tests/test_browser.py."""
import os
import socket
import threading
import time
from pathlib import Path

import pytest
import uvicorn

from openviscera.app import create_app
from openviscera.demo import sample_pdf
from openviscera.domain import opinion_pending
from fastapi.testclient import TestClient

pytestmark = pytest.mark.skipif(os.environ.get("OV_BROWSER_TEST") != "1", reason="Opt-in real browser integration")


def test_browser_complete_workflow_and_revision(env, tmp_path):
    from playwright.sync_api import sync_playwright
    store, users, _, d = env
    d.requested("SYN-001")
    d.dispatched("SYN-002", courier=True)
    d.reported("SYN-003")
    d.received("SYN-004", external=True, discrepancy=True)
    d.reviewed("SYN-005")
    d.add_report(d.issued("SYN-006"))
    report = tmp_path / "synthetic-report.pdf"
    receipt = tmp_path / "synthetic-receipt.pdf"
    revision = tmp_path / "synthetic-revision.pdf"
    report.write_bytes(sample_pdf("SYNTHETIC REPORT V1"))
    receipt.write_bytes(sample_pdf("SYNTHETIC EXTERNAL RECEIPT"))
    revision.write_bytes(sample_pdf("SYNTHETIC REPORT V2"))
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
    screenshot_dir = Path(os.environ.get("OV_SCREENSHOT_DIR", str(tmp_path / "screenshots")))
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as playwright:
            executable = os.environ.get("OV_CHROMIUM")
            browser = playwright.chromium.launch(executable_path=executable, headless=True, args=["--no-sandbox"])
            page = browser.new_page(viewport={"width": 1440, "height": 1060}, device_scale_factor=1)
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            if os.environ.get("OV_BROWSER_INPROCESS") == "1":
                # Restricted environments can exercise the real UI and ASGI app
                # in memory without changing browser network/security policy.
                client = TestClient(create_app(store.path, url, True), base_url=url)
                def local_fetch(source, path, options):
                    response = client.request(options.get("method", "GET"), path,
                                              headers=options.get("headers", {}),
                                              content=options.get("body"))
                    return {"status": response.status_code, "text": response.text}
                page.expose_binding("ovTestFetch", local_fetch)
                static = Path(__file__).parents[1] / "src/openviscera/static"
                shell = (static / "index.html").read_text()
                shell = shell.replace('<script src="/static/app.js" defer></script>', '')
                shell = shell.replace('<script src="/static/controls.js" defer></script>', '')
                shell = shell.replace('<link rel="stylesheet" href="/static/style.css">', '')
                page.set_content(shell)
                page.add_style_tag(content=(static / "style.css").read_text())
                page.evaluate("""() => {
                    window.fetch = async (path, options = {}) => {
                        const r = await window.ovTestFetch(path, options);
                        return {ok: r.status >= 200 && r.status < 300, status: r.status,
                                json: async () => JSON.parse(r.text), text: async () => r.text};
                    };
                    // about:blank has no secure-context randomUUID; test-only shim.
                    crypto.randomUUID = () => ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g,
                        c => (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16));
                }""")
                page.add_script_tag(content=(static / "app.js").read_text())
                page.add_script_tag(content=(static / "controls.js").read_text())
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

            def fill(name, value):
                page.locator("#modal [name='" + name + "']").fill(value)

            def save(label="Save record"):
                page.locator("#modal").get_by_role("button", name=label, exact=True).click()
                try:
                    page.locator("#modal").wait_for(state="hidden", timeout=4000)
                except Exception:
                    print("FORM ERROR:", page.locator("#modal").inner_text())
                    print("INVALID FIELDS:", page.locator("#modal :invalid").evaluate_all("els => els.map(e => ({name:e.name,value:e.value,message:e.validationMessage}))"))
                    raise

            def tab(name):
                page.locator(".tabs").get_by_role("button", name=name, exact=True).click()
                page.get_by_role("heading", name=name, exact=True).wait_for()

            login("examiner")
            page.get_by_role("heading", name="Every specimen. Every next step.").wait_for()
            page.screenshot(path=str(screenshot_dir / "dashboard.png"), full_page=True)
            page.get_by_role("button", name="+ New case", exact=True).click()
            fill("case_ref", "BROWSER-001")
            fill("authority", "Synthetic browser-test authority")
            save()
            page.get_by_role("heading", name="BROWSER-001", exact=True).wait_for()
            page.get_by_role("button", name="+ Collect specimen", exact=True).click()
            for name, value in {"container_id":"BROWSER-CONTAINER", "description":"Synthetic specimen for browser test",
                                "quantity":"1", "unit":"container", "preservative":"Synthetic examiner entry", "location":"Synthetic collection room"}.items():
                fill(name, value)
            save()
            tab("Requests")
            page.get_by_role("button", name="+ Request examination", exact=True).click()
            fill("examination", "Synthetic laboratory examination")
            save()
            tab("Specimens")
            page.get_by_role("button", name="Seal", exact=True).click()
            fill("seal_ref", "BROWSER-SEAL")
            fill("reason", "Initial seal documented by custodian")
            save()
            page.get_by_role("button", name="External dispatch", exact=True).click()
            fill("recipient_name", "Synthetic receiving officer")
            fill("destination", "Synthetic external laboratory")
            fill("note", "Synthetic handover for test")
            save()
            tab("Attachments")
            page.get_by_role("button", name="+ Attach evidence", exact=True).click()
            page.locator("#modal input[type=file]").set_input_files(receipt)
            save()
            logout()
            login("coordinator")
            tab("Custody")
            page.get_by_role("button", name="Record external receipt", exact=True).click()
            fill("observed_seal", "BROWSER-SEAL")
            fill("recipient_name", "Synthetic receiving officer")
            fill("note", "Evidence-backed synthetic external receipt")
            save()
            tab("Reports")
            page.get_by_role("button", name="+ Receive report", exact=True).click()
            fill("laboratory_reference", "BROWSER-LAB-V1")
            page.locator("#modal input[type=file]").set_input_files(report)
            save()
            logout()
            login("examiner")
            tab("Reports")
            page.get_by_role("button", name="Record review", exact=True).click()
            fill("note", "Synthetic expert review completed without automated inference")
            save()
            tab("Opinions")
            page.get_by_role("button", name="+ Prepare opinion", exact=True).click()
            fill("body", "Synthetic human-authored opinion used only to test workflow behavior.")
            save()
            logout()
            login("reviewer")
            tab("Opinions")
            page.get_by_role("button", name="Independently approve", exact=True).click()
            save("Approve opinion")
            logout()
            login("examiner")
            tab("Opinions")
            page.get_by_role("button", name="Issue opinion", exact=True).click()
            save("Issue approved opinion")
            page.get_by_text("Current evidence incorporated", exact=True).wait_for()
            page.screenshot(path=str(screenshot_dir / "issued-opinion.png"), full_page=True)
            case_id = page.url.split("case/")[-1]
            original = store.get_case(users["examiner"], case_id)
            assert not opinion_pending(original)
            tab("Reports")
            page.get_by_role("button", name="+ Receive report", exact=True).click()
            fill("laboratory_reference", "BROWSER-LAB-V2")
            page.locator("#modal input[type=file]").set_input_files(revision)
            save()
            page.get_by_text("Further opinion work pending", exact=True).wait_for()
            page.screenshot(path=str(screenshot_dir / "report-revision.png"), full_page=True)
            current = store.get_case(users["examiner"], case_id)
            assert opinion_pending(current)
            assert current["opinions"][0] == original["opinions"][0]
            # v0.2 controls are exercised through actual browser forms, not only API calls.
            tab("Controls")
            page.get_by_role("button", name="Manage case access", exact=True).click()
            page.locator("#modal [name=mode]").select_option("restricted")
            page.locator("#modal [name=member_ids]").select_option([users[x]["id"] for x in ["examiner", "coordinator", "reviewer"]])
            fill("reason", "Synthetic restricted-case access review")
            save()
            page.get_by_role("button", name="Correct specimen", exact=True).click()
            fill("replacement", "Independently corrected synthetic specimen description")
            fill("reason", "Corrected transcription from synthetic source")
            save()
            logout()
            login("reviewer")
            tab("Controls")
            page.get_by_role("button", name="Review correction", exact=True).click()
            fill("reason", "Independently verified original and proposed text")
            save()
            assert store.get_case(users["examiner"], case_id)["specimens"][0]["description"].startswith("Independently corrected")
            logout()
            login("examiner")
            tab("Controls")
            page.get_by_role("button", name="Withdraw report", exact=True).click()
            latest_id = store.get_case(users["examiner"], case_id)["reports"][-1]["id"]
            page.locator("#modal [name=report_id]").select_option(latest_id)
            fill("reason", "Laboratory confirms revised report is invalid")
            save()
            logout()
            login("reviewer")
            tab("Controls")
            page.get_by_role("button", name="Review withdrawal", exact=True).click()
            fill("reason", "Independent review confirms withdrawal")
            save()
            page.get_by_role("button", name="Withdraw issued opinion", exact=True).click()
            fill("reason", "Synthetic opinion withdrawn pending complete replacement")
            save()
            tab("Opinions")
            page.get_by_text("WITHDRAWN", exact=True).wait_for()
            page.screenshot(path=str(screenshot_dir / "withdrawn-opinion.png"), full_page=True)
            logout()
            login("coordinator")
            tab("Controls")
            page.get_by_role("button", name="Record external return", exact=True).click()
            fill("external_sender_name", "Synthetic laboratory return officer")
            fill("observed_seal", "BROWSER-SEAL")
            fill("destination", "Department receiving room")
            fill("note", "Synthetic returned container and documentary receipt")
            save()
            assert store.get_case(users["examiner"], case_id)["specimens"][0]["holder_id"] == users["coordinator"]["id"]
            tab("Controls")
            page.screenshot(path=str(screenshot_dir / "case-controls.png"), full_page=True)
            tab("Chronology")
            page.get_by_text("Verified ledger head:", exact=False).wait_for()
            # A new case for a two-container atomic dispatch, including non-mutating preview.
            logout()
            login("examiner")
            page.locator("nav").get_by_role("button", name="Case register", exact=True).click()
            page.get_by_role("button", name="+ New case", exact=True).click()
            fill("case_ref", "BROWSER-BATCH")
            fill("authority", "Synthetic batch authority")
            save()
            page.get_by_role("heading", name="BROWSER-BATCH", exact=True).wait_for()
            batch_case_id = page.url.split("case/")[-1]
            for index in range(2):
                tab("Specimens")
                page.get_by_role("button", name="+ Collect specimen", exact=True).click()
                for name, value in {"container_id":f"BROWSER-BATCH-{index}", "description":"Synthetic batch specimen",
                                    "quantity":"1", "unit":"container", "preservative":"Recorded", "location":"Room"}.items():
                    fill(name, value)
                save()
                page.get_by_role("button", name="Seal", exact=True).click()
                fill("seal_ref", "BATCH-SEAL")
                fill("reason", "Sealed for batch")
                save()
            page.get_by_role("button", name="Batch handover", exact=True).click()
            page.locator("#modal [name=recipient_id]").select_option(users["courier"]["id"])
            fill("destination", "Synthetic dispatch desk")
            fill("note", "Batch all-or-nothing dispatch")
            page.get_by_role("button", name="Preview batch", exact=True).click()
            page.get_by_text("Validated 2 containers", exact=False).wait_for()
            assert len(store.get_case(users["examiner"], batch_case_id)["transfers"]) == 0
            page.screenshot(path=str(screenshot_dir / "batch-preview.png"), full_page=True)
            save("Commit entire batch")
            assert len(store.get_case(users["examiner"], batch_case_id)["transfers"]) == 2
            page.get_by_role("button", name="Find specimen", exact=True).click()
            fill("token", "BROWSER-BATCH-0")
            save("Find specimen")
            page.get_by_role("heading", name="BROWSER-BATCH", exact=True).wait_for()
            page.get_by_role("button", name="Account", exact=True).click()
            fill("current_password", "synthetic-test-password-123")
            fill("new_password", "browser-changed-password-123")
            save("Change password and sign out")
            page.get_by_label("Username", exact=True).wait_for()
            login("admin")
            page.locator("nav").get_by_role("button", name="Access audit", exact=True).click()
            page.get_by_role("heading", name="Access audit", exact=True).wait_for()
            page.screenshot(path=str(screenshot_dir / "access-audit.png"), full_page=True)

            page.set_viewport_size({"width": 390, "height": 844})
            page.screenshot(path=str(screenshot_dir / "mobile-audit.png"), full_page=True)
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
            assert errors == []
            browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=10)
