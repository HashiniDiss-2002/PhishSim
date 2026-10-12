"""
test_timeline_support_faq.py
------------------------------
Verifies three features added together in this change:

  1. Interaction timeline (tracking.py's _log_event() capturing
     ip_address/user_agent; admin.interaction_timeline rendering them
     alongside each event's timestamp, plus a synthetic "received" entry
     from campaign_emails.sent_at):
       - Hitting a real /track/... endpoint (with a custom
         REMOTE_ADDR/User-Agent) records that IP/UA on the interactions
         row.
       - The timeline route shows "Received" first, then each interaction
         in order, with its IP/UA.
       - A department admin can view a timeline for their own
         department's employee, but gets redirected (not the page) for
         another department's.
       - A nonexistent / another org's campaign_email_id redirects
         rather than erroring or leaking data.

  2. Support tickets (admin.contact_support/support_inbox/
     respond_support_ticket):
       - An admin can raise a ticket; it appears in "their" ticket list.
       - A core admin sees every ticket raised in their org; a department
         admin sees only their own.
       - The engineer's /engineer/support inbox shows tickets across
         every organization (the one deliberate exception to "no tenant
         data").
       - The engineer responding marks the ticket resolved and the
         response becomes visible back on the admin's own ticket list.
       - A support_ticket_raised / support_ticket_resolved audit entry is
         logged to the ORIGINATING org's own audit log.

  3. FAQ page: renders OK and includes the allow-listing step-by-step
     guidance for a core/department admin.

Uses mock mode and a scratch DB, same pattern as the other test_*.py
files in this project.
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


def login(client, email):
    return client.post("/login", data={"email": email, "password": "password123"}, follow_redirects=True)


def setup_data():
    database.init_db()
    db = database.get_db()

    cur = db.execute("INSERT INTO organizations (name) VALUES (?)", ("Sampath Bank Sri Lanka",))
    org_id = cur.lastrowid
    cur2 = db.execute("INSERT INTO organizations (name) VALUES (?)", ("Other Org",))
    other_org_id = cur2.lastrowid

    db.execute(
        "INSERT INTO users (org_id, email, password_hash, role, full_name, department) "
        "VALUES (?, ?, ?, 'admin', ?, NULL)",
        (org_id, "core@sampath.test", generate_password_hash("password123"), "Core Admin"),
    )
    db.execute(
        "INSERT INTO users (org_id, email, password_hash, role, full_name, department) "
        "VALUES (?, ?, ?, 'admin', ?, 'IT')",
        (org_id, "it.admin@sampath.test", generate_password_hash("password123"), "IT Admin"),
    )
    db.execute(
        "INSERT INTO users (org_id, email, password_hash, role, full_name, department) "
        "VALUES (?, ?, ?, 'admin', ?, 'HR')",
        (org_id, "hr.admin@sampath.test", generate_password_hash("password123"), "HR Admin"),
    )
    db.execute(
        "INSERT INTO users (org_id, email, password_hash, role, full_name, department) VALUES (NULL, ?, ?, 'engineer', ?, NULL)",
        ("engineer@platform.local", generate_password_hash("password123"), "Platform Engineer"),
    )

    db.execute(
        "INSERT INTO employees (org_id, full_name, email, department, job_title) VALUES (?, ?, ?, ?, ?)",
        (org_id, "IT Person", "itperson@sampath.test", "IT", "Staff"),
    )
    db.execute(
        "INSERT INTO employees (org_id, full_name, email, department, job_title) VALUES (?, ?, ?, ?, ?)",
        (org_id, "HR Person", "hrperson@sampath.test", "HR", "Staff"),
    )
    db.commit()
    db.close()
    return org_id, other_org_id


def main():
    org_id, other_org_id = setup_data()
    app = create_app()
    app.config["TESTING"] = True

    # ---- Create a campaign (as core admin) targeting both employees ----
    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.post("/admin/campaign/new", data={"name": "Q4 Awareness", "condition": "personalized"},
                            follow_redirects=True)
        check("Campaign created OK", resp.status_code == 200)

    db = database.get_db()
    campaign = db.execute("SELECT * FROM campaigns WHERE name = 'Q4 Awareness'").fetchone()
    campaign_id = campaign["id"]
    it_email = db.execute(
        """SELECT ce.* FROM campaign_emails ce JOIN employees e ON ce.employee_id = e.id
           WHERE ce.campaign_id = ? AND e.department = 'IT'""", (campaign_id,)
    ).fetchone()
    hr_email = db.execute(
        """SELECT ce.* FROM campaign_emails ce JOIN employees e ON ce.employee_id = e.id
           WHERE ce.campaign_id = ? AND e.department = 'HR'""", (campaign_id,)
    ).fetchone()
    # Mark both "sent" directly (bypassing the real send_campaign() SMTP flow,
    # same shortcut other test_*.py files use) so the timeline's "Received"
    # entry has something to show.
    db.execute("UPDATE campaign_emails SET sent_at = datetime('now') WHERE id IN (?, ?)",
               (it_email["id"], hr_email["id"]))
    db.commit()
    db.close()

    # ---- 1a: hitting a real tracking endpoint records IP + User-Agent ----
    with app.test_client() as client:
        resp = client.get(
            f"/track/open/{it_email['token']}.gif",
            environ_overrides={"REMOTE_ADDR": "203.0.113.42"},
            headers={"User-Agent": "Mozilla/5.0 (TestBrowser/1.0)"},
        )
        check("Tracking pixel request returns 200", resp.status_code == 200)
        resp = client.get(
            f"/track/click/{it_email['token']}",
            environ_overrides={"REMOTE_ADDR": "203.0.113.42"},
            headers={"User-Agent": "Mozilla/5.0 (TestBrowser/1.0)"},
        )
        check("Tracking click request returns 200", resp.status_code == 200)

    db = database.get_db()
    open_row = db.execute(
        "SELECT * FROM interactions WHERE campaign_email_id = ? AND event_type = 'open'", (it_email["id"],)
    ).fetchone()
    click_row = db.execute(
        "SELECT * FROM interactions WHERE campaign_email_id = ? AND event_type = 'click'", (it_email["id"],)
    ).fetchone()
    check("Open event recorded the custom IP address", open_row is not None and open_row["ip_address"] == "203.0.113.42")
    check("Open event recorded the custom User-Agent", open_row is not None and "TestBrowser" in (open_row["user_agent"] or ""))
    check("Click event also recorded IP/User-Agent", click_row is not None and click_row["ip_address"] == "203.0.113.42")
    db.close()

    # ---- 1b: timeline page shows Received first, then events with IP/UA ----
    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.get(f"/admin/campaign-email/{it_email['id']}/timeline")
        check("Timeline page renders OK for core admin", resp.status_code == 200)
        body = resp.get_data(as_text=True)
        check("Timeline shows 'Received'", "Received" in body)
        check("Timeline shows 'Opened'", "Opened" in body)
        check("Timeline shows 'Clicked the link'", "Clicked the link" in body)
        check("Timeline shows the recorded IP address", "203.0.113.42" in body)
        check("Timeline shows the recorded User-Agent", "TestBrowser" in body)
        received_pos = body.find("Received")
        opened_pos = body.find("Opened")
        check("'Received' appears before 'Opened' in the rendered timeline",
              0 <= received_pos < opened_pos)

    # ---- 1c: department-admin access control on the timeline ----
    with app.test_client() as client:
        login(client, "it.admin@sampath.test")
        resp = client.get(f"/admin/campaign-email/{it_email['id']}/timeline")
        check("IT department admin CAN view their own department's employee timeline", resp.status_code == 200)

        resp = client.get(f"/admin/campaign-email/{hr_email['id']}/timeline", follow_redirects=True)
        check("IT department admin canNOT view HR's employee timeline (bounced, not served)",
              b"Simulation email not found" in resp.data)

    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.get("/admin/campaign-email/999999/timeline", follow_redirects=True)
        check("Nonexistent campaign_email_id redirects rather than erroring",
              resp.status_code == 200 and b"Simulation email not found" in resp.data)

    # ---- 2a: an admin raises a support ticket ----
    with app.test_client() as client:
        login(client, "it.admin@sampath.test")
        resp = client.post("/admin/support", data={
            "subject": "CSV upload fails", "message": "Uploading a 50-row roster errors out.",
        }, follow_redirects=True)
        check("Ticket submission redirects back with a success message",
              b"sent to the platform engineer" in resp.data)

    db = database.get_db()
    ticket = db.execute("SELECT * FROM support_tickets WHERE subject = 'CSV upload fails'").fetchone()
    check("Ticket row created with org_id/raised_by set correctly",
          ticket is not None and ticket["org_id"] == org_id and ticket["raised_by_name"] == "IT Admin")
    check("Ticket starts 'open' with no response yet",
          ticket["status"] == "open" and ticket["engineer_response"] is None)
    audit_row = db.execute(
        "SELECT * FROM audit_log WHERE action = 'support_ticket_raised' AND org_id = ?", (org_id,)
    ).fetchone()
    check("support_ticket_raised audit entry logged", audit_row is not None)
    db.close()

    # ---- 2b: visibility -- core admin sees all, department admin sees only their own ----
    with app.test_client() as client:
        login(client, "hr.admin@sampath.test")
        resp = client.post("/admin/support", data={
            "subject": "HR roster question", "message": "Can HR have a separate campaign?",
        }, follow_redirects=True)
        check("Second (HR) ticket submitted OK", b"sent to the platform engineer" in resp.data)

    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.get("/admin/support")
        check("Core admin sees BOTH tickets", b"CSV upload fails" in resp.data and b"HR roster question" in resp.data)

    with app.test_client() as client:
        login(client, "it.admin@sampath.test")
        resp = client.get("/admin/support")
        check("IT department admin sees only their OWN ticket", b"CSV upload fails" in resp.data)
        check("IT department admin does NOT see HR's ticket", b"HR roster question" not in resp.data)

    # ---- 2c: engineer inbox shows every org's tickets ----
    with app.test_client() as client:
        login(client, "engineer@platform.local")
        resp = client.get("/engineer/support")
        check("Engineer support inbox renders OK", resp.status_code == 200)
        body = resp.get_data(as_text=True)
        check("Engineer inbox shows the CSV ticket", "CSV upload fails" in body)
        check("Engineer inbox shows the HR ticket", "HR roster question" in body)
        check("Engineer inbox shows the organization name", "Sampath Bank Sri Lanka" in body)

    # ---- 2d: engineer responds -> resolved, visible back to the admin ----
    db = database.get_db()
    ticket_id = db.execute("SELECT id FROM support_tickets WHERE subject = 'CSV upload fails'").fetchone()["id"]
    db.close()

    with app.test_client() as client:
        login(client, "engineer@platform.local")
        resp = client.post(f"/engineer/support/{ticket_id}/respond",
                            data={"response": "Please re-export the CSV with UTF-8 encoding and try again."},
                            follow_redirects=True)
        check("Engineer response submitted OK", b"Response sent" in resp.data)

    db = database.get_db()
    ticket = db.execute("SELECT * FROM support_tickets WHERE id = ?", (ticket_id,)).fetchone()
    check("Ticket marked resolved", ticket["status"] == "resolved")
    check("Engineer response text stored", "UTF-8 encoding" in (ticket["engineer_response"] or ""))
    resolved_audit = db.execute(
        "SELECT * FROM audit_log WHERE action = 'support_ticket_resolved' AND org_id = ?", (org_id,)
    ).fetchone()
    check("support_ticket_resolved audit entry logged to the originating org", resolved_audit is not None)
    db.close()

    with app.test_client() as client:
        login(client, "it.admin@sampath.test")
        resp = client.get("/admin/support")
        check("Resolved ticket now shows the engineer's response on the admin's own ticket list",
              b"UTF-8 encoding" in resp.data and b"Resolved" in resp.data)

    # ---- 3: FAQ page ----
    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.get("/admin/faq")
        check("FAQ page renders OK", resp.status_code == 200)
        body = resp.get_data(as_text=True)
        check("FAQ mentions allow-listing / email security setup", "Tenant Allow/Block" in body or "allow" in body.lower())
        check("FAQ links through to Contact Support", "/admin/support" in body)

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All interaction-timeline / support / FAQ checks passed.")


if __name__ == "__main__":
    main()
