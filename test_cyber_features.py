"""
test_cyber_features.py
--------------------------
Covers the three cybersecurity-technique features added in response to
panel feedback that the project leaned too heavily on "AI" and not
enough on demonstrable security engineering:

  1. MITRE ATT&CK technique tagging (services/attack_mapping.py) — a
     campaign is tagged T1566.002 (Spearphishing Link) always, and also
     T1566.001 (Spearphishing Attachment) only when at least one
     generated email included a simulated attachment.
  2. Sender/domain spoofing simulation (services/domain_spoofing.py) — a
     synthetic, non-real, deterministic look-alike sender identity is
     generated once per campaign, stored on it, used as the "From" on
     every send, and revealed to the employee on the post-click
     education page.
  3. Browser-in-the-Browser (BITB) fake login (templates/bitb_login.html)
     — an alternative fake-login page style chosen at campaign creation,
     rendered by tracking.py based on campaigns.fake_login_style, with a
     matching explanation on the education page.

Uses mock mode (no GROQ_API_KEY) and a scratch DB/outbox, same pattern as
the other test_*.py files in this project. Mock mode's personalized
condition always sets attachment_filename="Policy_Update.pdf" (see
services/pretext_generator.py) and the generic condition never does —
this test relies on that existing, documented behaviour to exercise both
ATT&CK-tagging branches deterministically.
"""

import os
import re
import sys
import tempfile
from unittest.mock import patch

for var in ("GROQ_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
            "SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD"):
    os.environ.pop(var, None)

# MFA (services/totp.py) is mandatory for every real login, but this test
# file only exercises other features, so the login helper below is allowed
# to skip the MFA step via this test-only bypass (see auth.py's
# _MFA_TEST_BYPASS_ENV) rather than deriving a TOTP code for every login.
os.environ["PHISHSIM_DISABLE_MFA_FOR_TESTS"] = "1"

tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
tmp_db.close()

import database
database.DB_PATH = __import__("pathlib").Path(tmp_db.name)

from werkzeug.security import generate_password_hash
from app import create_app
from services.attack_mapping import get_campaign_attack_techniques
from services.domain_spoofing import generate_lookalike_domain, generate_spoofed_sender

failures = []


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}")
    if not condition:
        failures.append(label)


def setup_data():
    database.init_db()
    db = database.get_db()

    cur = db.execute("INSERT INTO organizations (name) VALUES (?)", ("Sampath Bank Sri Lanka",))
    org_id = cur.lastrowid
    db.execute(
        "INSERT INTO users (org_id, email, password_hash, role, full_name, department) "
        "VALUES (?, ?, ?, 'admin', ?, NULL)",
        (org_id, "core@sampath.test", generate_password_hash("password123"), "Core Admin"),
    )
    db.execute(
        "INSERT INTO employees (org_id, full_name, email, department, job_title) VALUES (?, ?, ?, ?, ?)",
        (org_id, "Jane Employee", "jane@sampath.test", "Finance", "Analyst"),
    )
    db.commit()
    db.close()
    return org_id


def login(client, email="core@sampath.test"):
    return client.post("/login", data={"email": email, "password": "password123"}, follow_redirects=True)


def main():
    org_id = setup_data()
    app = create_app()
    app.config["TESTING"] = True

    # =========================================================
    # 1. ATT&CK technique mapping (pure unit tests, no Flask needed)
    # =========================================================
    link_only = get_campaign_attack_techniques(has_any_attachment=False)
    link_and_attachment = get_campaign_attack_techniques(has_any_attachment=True)
    check("Link-only campaign maps to exactly T1566.002",
          [t["id"] for t in link_only] == ["T1566.002"])
    check("Link+attachment campaign maps to T1566.002 AND T1566.001",
          {t["id"] for t in link_and_attachment} == {"T1566.002", "T1566.001"})
    check("Every technique dict carries a real attack.mitre.org URL",
          all(t["url"].startswith("https://attack.mitre.org/techniques/") for t in link_and_attachment))

    # =========================================================
    # 2. Domain spoofing (pure unit tests)
    # =========================================================
    d1 = generate_lookalike_domain("Acme Corp")
    d2 = generate_lookalike_domain("Acme Corp")
    check("Lookalike domain generation is deterministic for the same org name", d1 == d2)
    check("Lookalike domain is a .com-style string", d1.endswith(".com"))
    check("Lookalike domain never equals the real-sounding bare org slug",
          d1 != "acmecorp.com")

    spoof = generate_spoofed_sender("Acme Corp")
    for key in ("display_name", "lookalike_domain", "spoofed_address", "link_display_text"):
        check(f"generate_spoofed_sender result has '{key}'", key in spoof)
    check("Spoofed display name mentions the real org name (looks plausible)",
          "Acme Corp" in spoof["display_name"])
    check("Spoofed address domain matches the generated lookalike domain",
          spoof["spoofed_address"].endswith("@" + spoof["lookalike_domain"]))
    check("Spoofed address is NOT at a generic/real-looking acmecorp.com domain",
          "@acmecorp.com" not in spoof["spoofed_address"])

    # =========================================================
    # 3. End-to-end: create a PERSONALIZED + BITB campaign, verify
    #    everything gets stored and rendered correctly.
    # =========================================================
    with app.test_client() as client:
        login(client)
        resp = client.post("/admin/campaign/new", data={
            "name": "Personalized BITB Test", "condition": "personalized",
            "stage2_scenario_id": "", "fake_login_style": "bitb",
        }, follow_redirects=True)
        check("Personalized/BITB campaign created OK", resp.status_code == 200)

    db = database.get_db()
    campaign = db.execute("SELECT * FROM campaigns WHERE name = 'Personalized BITB Test'").fetchone()
    campaign_id = campaign["id"]
    check("Campaign stores fake_login_style='bitb'", campaign["fake_login_style"] == "bitb")
    check("Campaign stores a spoofed_sender_name", bool(campaign["spoofed_sender_name"]))
    check("Campaign stores a spoofed_domain", bool(campaign["spoofed_domain"]))
    check("Campaign stores a spoofed_address matching domain+local-part",
          campaign["spoofed_address"].endswith("@" + campaign["spoofed_domain"]))
    check("Campaign's spoofed domain is the SAME deterministic one domain_spoofing.py would generate",
          campaign["spoofed_domain"] == generate_lookalike_domain("Sampath Bank Sri Lanka"))

    email_row = db.execute(
        "SELECT * FROM campaign_emails WHERE campaign_id = ?", (campaign_id,)
    ).fetchone()
    token = email_row["token"]
    check("Mock-mode personalized email has has_attachment=1 (mock always sets attachment_filename)",
          email_row["has_attachment"] == 1)
    db.close()

    # ---- campaign detail page shows both ATT&CK badges + spoofed sender ----
    with app.test_client() as client:
        login(client)
        body = client.get(f"/admin/campaign/{campaign_id}").get_data(as_text=True)
        check("Campaign page shows T1566.002 (Spearphishing Link)", "T1566.002" in body)
        check("Campaign page shows T1566.001 (Spearphishing Attachment) — has an attachment email",
              "T1566.001" in body)
        check("Campaign page shows the simulated sender identity",
              campaign["spoofed_sender_name"] in body and campaign["spoofed_address"] in body)

    # ---- compliance report (CSV) includes the ATT&CK section ----
    with app.test_client() as client:
        login(client)
        resp = client.get(f"/admin/campaign/{campaign_id}/report.csv")
        body = resp.get_data(as_text=True)
        check("CSV report includes the ATT&CK techniques section", "MITRE ATT&CK" in body)
        check("CSV report lists T1566.002", "T1566.002" in body)
        check("CSV report lists T1566.001", "T1566.001" in body)

    with app.test_client() as client:
        login(client)
        resp = client.get(f"/admin/campaign/{campaign_id}/report.pdf")
        check("PDF report (with ATT&CK section) still returns a well-formed PDF",
              resp.data[:4] == b"%PDF" and len(resp.data) > 1000)

    # ---- tracking.track_click renders the BITB template for this campaign ----
    with app.test_client() as client:
        resp = client.get(f"/track/click/{token}")
        body = resp.get_data(as_text=True)
        check("BITB-style campaign's click renders the fake browser window chrome",
              "bitb-addressbar" in body or "bitb-window" in body)
        check("BITB fake address bar shows the campaign's spoofed domain",
              campaign["spoofed_domain"] in body)
        check("BITB page does NOT render as the plain standard login card",
              'class="card shadow-sm"' not in body)

    # ---- submitting on the BITB page reveals spoofing + BITB explanation ----
    with app.test_client() as client:
        resp = client.post(f"/track/submit/{token}", data={"username": "whatever", "password": "whatever"})
        body = resp.get_data(as_text=True)
        check("Education page reveals the spoofed sender identity",
              campaign["spoofed_sender_name"] in body and campaign["spoofed_address"] in body)
        check("Education page explains sender/domain spoofing by name",
              re.search(r"sender/domain\s+spoofing", body.lower()) is not None)
        check("Education page explains the Browser-in-the-Browser technique by name",
              "browser-in-the-browser" in body.lower())

    db = database.get_db()
    submit_logged = db.execute(
        "SELECT * FROM interactions i JOIN campaign_emails ce ON i.campaign_email_id = ce.id "
        "WHERE ce.token = ? AND i.event_type = 'submit'", (token,)
    ).fetchone()
    check("Submission event was still logged normally (feature didn't break tracking)",
          submit_logged is not None)
    db.close()

    # =========================================================
    # 4. A GENERIC/'standard' campaign: no attachment -> only T1566.002,
    #    plain fake_login.html, no BITB explanation on the education page.
    # =========================================================
    with app.test_client() as client:
        login(client)
        client.post("/admin/campaign/new", data={
            "name": "Generic Standard Test", "condition": "generic",
            "stage2_scenario_id": "", "fake_login_style": "standard",
        }, follow_redirects=True)

    db = database.get_db()
    generic_campaign = db.execute("SELECT * FROM campaigns WHERE name = 'Generic Standard Test'").fetchone()
    generic_campaign_id = generic_campaign["id"]
    check("Generic campaign stores fake_login_style='standard'",
          generic_campaign["fake_login_style"] == "standard")
    generic_email = db.execute(
        "SELECT * FROM campaign_emails WHERE campaign_id = ?", (generic_campaign_id,)
    ).fetchone()
    generic_token = generic_email["token"]
    check("Generic/control template email has has_attachment=0 (never includes an attachment)",
          generic_email["has_attachment"] == 0)
    db.close()

    with app.test_client() as client:
        login(client)
        body = client.get(f"/admin/campaign/{generic_campaign_id}").get_data(as_text=True)
        check("Generic campaign page shows T1566.002", "T1566.002" in body)
        check("Generic campaign page does NOT show T1566.001 (no attachment email in this campaign)",
              "T1566.001" not in body)

    with app.test_client() as client:
        resp = client.get(f"/track/click/{generic_token}")
        body = resp.get_data(as_text=True)
        check("Standard-style campaign's click renders the plain login card, not BITB chrome",
              'class="card shadow-sm"' in body and "bitb-addressbar" not in body)

    with app.test_client() as client:
        resp = client.post(f"/track/submit/{generic_token}", data={"username": "x", "password": "y"})
        body = resp.get_data(as_text=True)
        check("Standard campaign's education page still reveals sender spoofing",
              re.search(r"sender/domain\s+spoofing", body.lower()) is not None)
        check("Standard campaign's education page does NOT mention BITB (wasn't used)",
              "browser-in-the-browser" not in body.lower())

    # =========================================================
    # 5. send_campaign / test_send_campaign actually pass the spoofed
    #    sender through to mailer.send_email()
    # =========================================================
    captured = {}

    def capture_send(to, subject, html_body, from_name=None, from_address=None):
        captured["from_name"] = from_name
        captured["from_address"] = from_address

    with patch("services.mailer.send_email", side_effect=capture_send):
        with app.test_client() as client:
            login(client)
            client.post(f"/admin/campaign/{campaign_id}/send", follow_redirects=True)
    check("send_campaign passed the campaign's spoofed display name to send_email",
          captured.get("from_name") == campaign["spoofed_sender_name"])
    check("send_campaign passed the campaign's spoofed address to send_email",
          captured.get("from_address") == campaign["spoofed_address"])

    captured.clear()
    with patch("services.mailer.send_email", side_effect=capture_send):
        with app.test_client() as client:
            login(client)
            client.post(f"/admin/campaign/{generic_campaign_id}/test-send", follow_redirects=True)
    check("test_send_campaign also passes the spoofed sender through",
          captured.get("from_name") == generic_campaign["spoofed_sender_name"])

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All MITRE ATT&CK / domain-spoofing / BITB checks passed.")


if __name__ == "__main__":
    main()
    os.unlink(tmp_db.name)
