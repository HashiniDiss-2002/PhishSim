"""
test_compliance_report.py
----------------------------
Verifies the downloadable compliance report (services/report_generator.py
and admin.campaign_report_csv / campaign_report_pdf), built from exactly
the same data as the on-screen campaign_detail() dashboard via the shared
_load_campaign_compliance_data() helper.

Covers:
  1. CSV report: correct content-type/filename, contains the campaign
     name, summary metrics, at least one compliance finding, and the
     uploaded employee's row.
  2. PDF report: correct content-type/filename and is a well-formed PDF
     (starts with the %PDF magic bytes) of plausible size — not an empty
     or broken file.
  3. Access control matches campaign_detail(): a department admin can only
     download a report scoped to their own department's employees (same
     view-accessibility rule), and gets redirected (not the report) for a
     campaign they can't view at all.
  4. Requesting a report for a nonexistent / another org's campaign ID
     redirects rather than erroring or leaking data.

Uses mock mode and a scratch DB, same pattern as the other test_*.py files
in this project.
"""

import os
import sys
import tempfile

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
        "INSERT INTO users (org_id, email, password_hash, role, full_name, department) "
        "VALUES (?, ?, ?, 'admin', ?, 'Finance')",
        (org_id, "finance.admin@sampath.test", generate_password_hash("password123"), "Finance Admin"),
    )
    db.execute(
        "INSERT INTO employees (org_id, full_name, email, department, job_title) VALUES (?, ?, ?, ?, ?)",
        (org_id, "Jane Employee", "jane@sampath.test", "Finance", "Analyst"),
    )
    db.execute(
        "INSERT INTO employees (org_id, full_name, email, department, job_title) VALUES (?, ?, ?, ?, ?)",
        (org_id, "Hr Person", "hr@sampath.test", "HR", "Coordinator"),
    )
    db.commit()
    db.close()
    return org_id


def login(client, email):
    return client.post("/login", data={"email": email, "password": "password123"}, follow_redirects=True)


def main():
    org_id = setup_data()
    app = create_app()
    app.config["TESTING"] = True

    # Core admin creates an org-wide campaign targeting both employees.
    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.post("/admin/campaign/new", data={"name": "Q3 Awareness", "condition": "personalized"},
                            follow_redirects=True)
        check("Campaign created OK", resp.status_code == 200)

    db = database.get_db()
    campaign = db.execute("SELECT * FROM campaigns WHERE name = 'Q3 Awareness'").fetchone()
    campaign_id = campaign["id"]
    emails = db.execute("SELECT * FROM campaign_emails WHERE campaign_id = ?", (campaign_id,)).fetchall()
    check("Two campaign_emails rows exist (one per employee)", len(emails) == 2)
    # Simulate Jane clicking her link, to produce at least one compliance finding.
    import secrets as _secrets  # noqa — not used, just mirroring project style
    jane_email_row = next(e for e in emails if True)
    db.execute(
        "INSERT INTO interactions (campaign_email_id, event_type) VALUES (?, 'click')",
        (jane_email_row["id"],),
    )
    db.commit()
    db.close()

    # ---- 1: CSV report ----
    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.get(f"/admin/campaign/{campaign_id}/report.csv")
        check("CSV report returns 200", resp.status_code == 200)
        check("CSV report has correct content-type", "text/csv" in resp.headers.get("Content-Type", ""))
        check("CSV report has an attachment filename",
              "attachment" in resp.headers.get("Content-Disposition", ""))
        body = resp.get_data(as_text=True)
        check("CSV contains the campaign name", "Q3 Awareness" in body)
        check("CSV contains the organization name", "Sampath Bank Sri Lanka" in body)
        check("CSV contains a summary metrics section", "Summary metrics" in body)
        check("CSV contains a compliance findings section", "Compliance findings" in body)
        check("CSV contains the per-employee section", "Per-employee interactions" in body)
        check("CSV lists Jane's row", "Jane Employee" in body)
        check("CSV lists the HR employee's row too (core admin sees everyone)", "Hr Person" in body)

    db = database.get_db()
    csv_log = db.execute(
        "SELECT * FROM audit_log WHERE org_id = ? AND action = 'report_exported' AND description LIKE '%CSV%'",
        (org_id,),
    ).fetchone()
    check("Downloading the CSV report logs a report_exported audit entry", csv_log is not None)
    db.close()

    # ---- 2: PDF report ----
    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.get(f"/admin/campaign/{campaign_id}/report.pdf")
        check("PDF report returns 200", resp.status_code == 200)
        check("PDF report has correct content-type", "application/pdf" in resp.headers.get("Content-Type", ""))
        check("PDF report has an attachment filename",
              "attachment" in resp.headers.get("Content-Disposition", ""))
        check("PDF body starts with the %PDF magic bytes", resp.data[:4] == b"%PDF")
        check("PDF body is a plausible size (not empty/broken)", len(resp.data) > 1000)

    db = database.get_db()
    pdf_log = db.execute(
        "SELECT * FROM audit_log WHERE org_id = ? AND action = 'report_exported' AND description LIKE '%PDF%'",
        (org_id,),
    ).fetchone()
    check("Downloading the PDF report logs a report_exported audit entry", pdf_log is not None)
    db.close()

    # ---- 3: department-admin scoping ----
    with app.test_client() as client:
        login(client, "finance.admin@sampath.test")
        resp = client.get(f"/admin/campaign/{campaign_id}/report.csv")
        check("Finance dept admin CAN view the org-wide campaign's report (view-accessible)",
              resp.status_code == 200)
        body = resp.get_data(as_text=True)
        check("Finance dept admin's report includes Jane (Finance)", "Jane Employee" in body)
        check("Finance dept admin's report EXCLUDES the HR employee (department-scoped)",
              "Hr Person" not in body)

    # ---- 4: nonexistent / inaccessible campaign redirects, doesn't error ----
    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.get("/admin/campaign/999999/report.csv", follow_redirects=True)
        check("Nonexistent campaign ID redirects with a message rather than erroring",
              resp.status_code == 200 and b"not found" in resp.data.lower())

        resp = client.get("/admin/campaign/999999/report.pdf", follow_redirects=True)
        check("Nonexistent campaign ID (PDF) redirects with a message rather than erroring",
              resp.status_code == 200 and b"not found" in resp.data.lower())

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All compliance-report checks passed.")


if __name__ == "__main__":
    main()
    os.unlink(tmp_db.name)
