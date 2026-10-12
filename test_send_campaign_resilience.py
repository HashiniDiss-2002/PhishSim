"""
test_send_campaign_resilience.py
-----------------------------------
Verifies the send_campaign fix for the Mailtrap "550 Too many emails per
second" bug report: one recipient's send failure must not crash the whole
request or lose the record of recipients that already sent successfully.

Covers:
  1. All-success path: every recipient gets sent_at set, status becomes
     'launched', success flash shown, no delay-related slowdown asserted
     (delay is mocked out via SEND_DELAY_SECONDS=0 for test speed).
  2. Partial-failure path (send_email raises on the 2nd of 3 recipients):
     recipients #1 and #3 still get sent_at recorded, #2 does not, the
     request returns 200 (not a 500), a warning flash names the failure
     count, and the campaign still moves to 'launched'.
"""

import os
import sys
import tempfile
from unittest.mock import patch

os.environ["SEND_DELAY_SECONDS"] = "0"  # skip the real delay for fast tests
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

failures = []


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}")
    if not condition:
        failures.append(label)


def setup_campaign():
    database.init_db()
    db = database.get_db()
    cur = db.execute("INSERT INTO organizations (name) VALUES (?)", ("Sampath Bank Sri Lanka",))
    org_id = cur.lastrowid
    db.execute(
        "INSERT INTO users (org_id, email, password_hash, role, full_name, department) "
        "VALUES (?, ?, ?, 'admin', ?, NULL)",
        (org_id, "core@sampath.test", generate_password_hash("password123"), "Core Admin"),
    )
    cur = db.execute(
        "INSERT INTO campaigns (org_id, name, condition, pretext_context, created_by, status) "
        "VALUES (?, 'Resilience Test', 'generic', 'n/a', "
        "(SELECT id FROM users WHERE email='core@sampath.test'), 'draft')",
        (org_id,),
    )
    campaign_id = cur.lastrowid

    employee_ids = []
    for i in range(3):
        db.execute(
            "INSERT INTO employees (org_id, full_name, email, department, job_title) VALUES (?, ?, ?, ?, ?)",
            (org_id, f"Employee {i}", f"emp{i}@sampath.test", "Finance", "Staff"),
        )
        employee_ids.append(db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"])

    for i, emp_id in enumerate(employee_ids):
        db.execute(
            "INSERT INTO campaign_emails (campaign_id, employee_id, token, subject, html_body) "
            "VALUES (?, ?, ?, 'Subj', '<p>body</p>')",
            (campaign_id, emp_id, f"tok-{i}"),
        )

    db.commit()
    db.close()
    return campaign_id


def login(client):
    return client.post("/login", data={"email": "core@sampath.test", "password": "password123"}, follow_redirects=True)


def test_all_success():
    campaign_id = setup_campaign()
    app = create_app()
    app.config["TESTING"] = True

    with patch("services.mailer.send_email") as mock_send:
        with app.test_client() as client:
            login(client)
            resp = client.post(f"/admin/campaign/{campaign_id}/send", follow_redirects=True)
            check("All-success send returns 200", resp.status_code == 200)
            body = resp.get_data(as_text=True)
            check("Success flash shown (no failures)", "Campaign sent to 3 recipients." in body)
        check("send_email called once per recipient", mock_send.call_count == 3)

    db = database.get_db()
    sent = db.execute(
        "SELECT COUNT(*) c FROM campaign_emails WHERE campaign_id = ? AND sent_at IS NOT NULL", (campaign_id,)
    ).fetchone()["c"]
    check("All 3 recipients have sent_at recorded", sent == 3)
    status = db.execute("SELECT status FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()["status"]
    check("Campaign status is 'launched'", status == "launched")
    db.close()


def test_partial_failure():
    campaign_id = setup_campaign()
    app = create_app()
    app.config["TESTING"] = True

    call_count = {"n": 0}

    def flaky_send(to, subject, html_body, from_name=None, from_address=None):
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise Exception("550 Too many emails per second")
        return None

    with patch("services.mailer.send_email", side_effect=flaky_send):
        with app.test_client() as client:
            login(client)
            resp = client.post(f"/admin/campaign/{campaign_id}/send", follow_redirects=True)
            check("Partial-failure send still returns 200, not a 500", resp.status_code == 200)
            body = resp.get_data(as_text=True)
            check("Warning flash names the failure count", "1 failed" in body)
            check("Warning flash shows the partial success count", "sent to 2 of 3" in body)

    db = database.get_db()
    emails = db.execute(
        "SELECT token, sent_at FROM campaign_emails WHERE campaign_id = ? ORDER BY token", (campaign_id,)
    ).fetchall()
    sent_tokens = {e["token"] for e in emails if e["sent_at"] is not None}
    check("Recipient #1 (tok-0) got sent_at recorded", "tok-0" in sent_tokens)
    check("Recipient #2 (tok-1, the failure) did NOT get sent_at recorded", "tok-1" not in sent_tokens)
    check("Recipient #3 (tok-2) still got sent_at recorded despite #2 failing", "tok-2" in sent_tokens)

    status = db.execute("SELECT status FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()["status"]
    check("Campaign still marked 'launched' despite partial failure", status == "launched")
    db.close()


def main():
    test_all_success()
    test_partial_failure()

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All send_campaign resilience checks passed.")


if __name__ == "__main__":
    main()
    os.unlink(tmp_db.name)
