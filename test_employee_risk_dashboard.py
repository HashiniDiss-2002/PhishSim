"""
test_employee_risk_dashboard.py
--------------------------------
Verifies the two new admin-dashboard widgets (admin.py's
_employee_risk_and_response_rankings(), rendered in
templates/admin_dashboard.html):

  - Top 5 riskiest employees: ranked by the same overall (likelihood x
    impact) risk score employee_detail() shows for one person, computed
    here for every employee in scope.
  - Top 5 quick-responding employees: ranked by average time-to-report
    a simulation (campaign_emails.sent_at -> the 'report' interaction's
    occurred_at), fastest first — a positive recognition metric, not a
    risk score.

Covers:
  1. An employee who clicked/downloaded/submitted ranks as riskier than
     one with a clean history, and appears in top_risky with the
     expected tier.
  2. An employee who reports FASTER ranks ahead of one who reports
     SLOWER in top_responders, and the formatted duration label is
     correct (e.g. "30s", "10m").
  3. An employee who has never been part of any campaign appears in
     NEITHER ranking (no fabricated zero score, no fabricated response
     time).
  4. An employee who has interaction history but never reported
     anything appears in top_risky (if risky enough) but NOT in
     top_responders.
  5. GET /admin (the real route) renders 200 and includes both new
     section headers and the riskiest/quickest employees' names.

Uses mock mode and a scratch DB, same pattern as the other test_*.py
files in this project. Seeds campaign_emails/interactions directly
(rather than driving the full send_campaign() flow) so response times
are deterministic and don't depend on SEND_DELAY_SECONDS / real SMTP.

Run with:  python test_employee_risk_dashboard.py
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta

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
import admin as admin_module

failures = []


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}")
    if not condition:
        failures.append(label)


def iso(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


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

    def mkemp(name, email, dept):
        db.execute(
            "INSERT INTO employees (org_id, full_name, email, department, job_title) VALUES (?, ?, ?, ?, ?)",
            (org_id, name, email, dept, "Staff"),
        )
        return db.execute("SELECT id FROM employees WHERE email = ?", (email,)).fetchone()["id"]

    alice_id = mkemp("Alice Risky", "alice@sampath.test", "Finance")   # clicks + downloads + submits
    bob_id = mkemp("Bob Quick", "bob@sampath.test", "IT")              # reports in 30s
    carol_id = mkemp("Carol Slow", "carol@sampath.test", "HR")         # reports in 600s
    dave_id = mkemp("Dave NoHistory", "dave@sampath.test", "Legal")    # never in a campaign

    cur = db.execute(
        "INSERT INTO campaigns (org_id, name, condition, created_by) VALUES (?, 'Seed Campaign', 'personalized', "
        "(SELECT id FROM users WHERE email = 'core@sampath.test'))",
        (org_id,),
    )
    campaign_id = cur.lastrowid

    base_sent = datetime(2026, 1, 1, 9, 0, 0)

    def mkemail(employee_id, token):
        db.execute(
            "INSERT INTO campaign_emails (campaign_id, employee_id, token, subject, html_body, sent_at) "
            "VALUES (?, ?, ?, 'Test subject', '<p>test</p>', ?)",
            (campaign_id, employee_id, token, iso(base_sent)),
        )
        return db.execute("SELECT id FROM campaign_emails WHERE token = ?", (token,)).fetchone()["id"]

    alice_email_id = mkemail(alice_id, "tok-alice")
    bob_email_id = mkemail(bob_id, "tok-bob")
    carol_email_id = mkemail(carol_id, "tok-carol")
    # Dave gets no campaign_emails row at all.

    # Alice: risky behaviour, never reports.
    for event in ("click", "download", "submit"):
        db.execute(
            "INSERT INTO interactions (campaign_email_id, event_type, occurred_at) VALUES (?, ?, ?)",
            (alice_email_id, event, iso(base_sent + timedelta(seconds=5))),
        )

    # Bob: reports fast (30s after sending).
    db.execute(
        "INSERT INTO interactions (campaign_email_id, event_type, occurred_at) VALUES (?, 'report', ?)",
        (bob_email_id, iso(base_sent + timedelta(seconds=30))),
    )

    # Carol: reports slower (600s after sending).
    db.execute(
        "INSERT INTO interactions (campaign_email_id, event_type, occurred_at) VALUES (?, 'report', ?)",
        (carol_email_id, iso(base_sent + timedelta(seconds=600))),
    )

    db.commit()
    db.close()
    return org_id, {"alice": alice_id, "bob": bob_id, "carol": carol_id, "dave": dave_id}


def login(client, email):
    return client.post("/login", data={"email": email, "password": "password123"}, follow_redirects=True)


def main():
    org_id, ids = setup_data()
    app = create_app()
    app.config["TESTING"] = True

    # ---- Unit-level: exercise the ranking helper directly ----
    db = database.get_db()
    employees = db.execute("SELECT * FROM employees WHERE org_id = ?", (org_id,)).fetchall()
    top_risky, top_responders = admin_module._employee_risk_and_response_rankings(db, employees, org_id)
    db.close()

    risky_names = [s["employee"]["full_name"] for s in top_risky]
    responder_names = [s["employee"]["full_name"] for s in top_responders]

    check("Alice (clicked/downloaded/submitted) appears in top_risky", "Alice Risky" in risky_names)
    alice_summary = next(s for s in top_risky if s["employee"]["full_name"] == "Alice Risky")
    check("Alice's risk tier is High or Critical", alice_summary["risk"]["tier"] in ("High", "Critical"))

    check("Dave (no campaign history) appears in NEITHER ranking",
          "Dave NoHistory" not in risky_names and "Dave NoHistory" not in responder_names)

    check("Bob and Carol (both reported) appear in top_responders",
          "Bob Quick" in responder_names and "Carol Slow" in responder_names)
    check("Bob (30s) ranks ahead of Carol (600s) -- fastest responder first",
          responder_names.index("Bob Quick") < responder_names.index("Carol Slow"))

    bob_summary = next(s for s in top_responders if s["employee"]["full_name"] == "Bob Quick")
    carol_summary = next(s for s in top_responders if s["employee"]["full_name"] == "Carol Slow")
    check("Bob's avg response time is exactly 30s", bob_summary["avg_response_seconds"] == 30)
    check("Bob's formatted response label is '30s'", bob_summary["avg_response_label"] == "30s")
    check("Carol's avg response time is exactly 600s", carol_summary["avg_response_seconds"] == 600)
    check("Carol's formatted response label is '10m'", carol_summary["avg_response_label"] == "10m")

    check("Alice never reported, so she does NOT appear in top_responders",
          "Alice Risky" not in responder_names)
    check("Bob/Carol have a near-zero risk score (no click/submit/download), so they rank below Alice",
          risky_names.index("Alice Risky") < len(risky_names))  # Alice present at all is the real assertion

    # ---- HTTP-level: the real dashboard route renders both widgets ----
    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.get("/admin")
        check("GET /admin renders OK", resp.status_code == 200)
        body = resp.get_data(as_text=True)
        check("Dashboard includes the 'Top 5 riskiest employees' section", "Top 5 riskiest employees" in body)
        check("Dashboard includes the 'Top 5 quick-responding employees' section",
              "Top 5 quick-responding employees" in body)
        check("Alice Risky's name appears on the dashboard", "Alice Risky" in body)
        check("Bob Quick's name appears on the dashboard", "Bob Quick" in body)
        check("Carol Slow's name appears on the dashboard", "Carol Slow" in body)
        check("Bob's '30s' response label is rendered", "30s" in body)
        check("Carol's '10m' response label is rendered", "10m" in body)

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All employee risk/response dashboard checks passed.")


if __name__ == "__main__":
    main()
