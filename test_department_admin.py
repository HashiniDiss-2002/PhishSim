"""
test_department_admin.py
-------------------------
Integration test harness for the core-admin / department-admin RBAC feature,
built the same way every other security boundary in this project was tested
(see test_flow.py for the original engineer/tenant-isolation test): a
throwaway Flask app + a fresh schema + seeded org/employees/users, exercised
through Flask's test client rather than asserted by reading the code.

Runs entirely in MOCK MODE (no GROQ_API_KEY / SMTP_* env vars needed), using
a temporary SQLite file so it never touches instance/phishsim.db.

What this specifically verifies:
  1. A department admin only sees their own department's employees on the
     admin dashboard, not another department's.
  2. A department admin cannot view another department's employee profile
     (404-equivalent redirect with flash, same as "not found").
  3. Uploading a CSV as a department admin forces every row into their own
     department, even if the CSV says otherwise.
  4. Creating a campaign as a department admin only includes their own
     department's employees, and the campaign is tagged with that
     department.
  5. A department admin CAN view (but not manage: no delete/send/test-send)
     an org-wide campaign created by the core admin.
  6. A department admin CANNOT delete, send, or test-send another
     department's — or the core admin's org-wide — campaign, even by
     guessing the URL directly.
  7. The core admin retains full visibility (sees all employees and all
     campaigns across departments) and full action rights everywhere.
  8. /admin/department-admins is reachable by the core admin and can create
     a new department-admin account; a department admin hitting the same
     route is bounced with a permission error, not served the form.

Run with:  python test_department_admin.py
Exits non-zero (and prints which assertion failed) on any failure.
"""

import os
import sys
import tempfile

# Force mock mode regardless of the real environment this happens to run in.
for var in ("GROQ_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
            "SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD"):
    os.environ.pop(var, None)

# MFA (services/totp.py) is mandatory for every real login, but this test
# file only exercises other features, so the login helper below is allowed
# to skip the MFA step via this test-only bypass (see auth.py's
# _MFA_TEST_BYPASS_ENV) rather than deriving a TOTP code for every login.
os.environ["PHISHSIM_DISABLE_MFA_FOR_TESTS"] = "1"

# Use a scratch DB file for this test run only.
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

    def mkuser(email, full_name, role, department=None):
        db.execute(
            "INSERT INTO users (org_id, email, password_hash, role, full_name, department) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (org_id, email, generate_password_hash("password123"), role, full_name, department),
        )
        return db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()["id"]

    core_admin_id = mkuser("core@sampath.test", "Core Admin", "admin", None)
    it_admin_id = mkuser("it@sampath.test", "IT Admin", "admin", "IT")
    hr_admin_id = mkuser("hr@sampath.test", "HR Admin", "admin", "HR")

    def mkemp(name, email, dept):
        db.execute(
            "INSERT INTO employees (org_id, full_name, email, department, job_title) VALUES (?, ?, ?, ?, ?)",
            (org_id, name, email, dept, "Staff"),
        )
        return db.execute("SELECT id FROM employees WHERE email = ?", (email,)).fetchone()["id"]

    it_emp_id = mkemp("IT Person", "itperson@sampath.test", "IT")
    hr_emp_id = mkemp("HR Person", "hrperson@sampath.test", "HR")

    # An org-wide campaign created by the core admin, touching both depts.
    cur = db.execute(
        "INSERT INTO campaigns (org_id, name, condition, pretext_context, department, created_by, status) "
        "VALUES (?, 'Org Wide Q1', 'generic', 'n/a', NULL, ?, 'draft')",
        (org_id, core_admin_id),
    )
    org_campaign_id = cur.lastrowid
    for emp_id in (it_emp_id, hr_emp_id):
        db.execute(
            "INSERT INTO campaign_emails (campaign_id, employee_id, token, subject, html_body) "
            "VALUES (?, ?, ?, 'Subj', '<p>body</p>')",
            (org_campaign_id, emp_id, f"tok-org-{emp_id}"),
        )

    # An IT-only campaign created by the IT dept admin.
    cur = db.execute(
        "INSERT INTO campaigns (org_id, name, condition, pretext_context, department, created_by, status) "
        "VALUES (?, 'IT Only Campaign', 'generic', 'n/a', 'IT', ?, 'draft')",
        (org_id, it_admin_id),
    )
    it_campaign_id = cur.lastrowid
    db.execute(
        "INSERT INTO campaign_emails (campaign_id, employee_id, token, subject, html_body) "
        "VALUES (?, ?, 'tok-it-1', 'Subj', '<p>body</p>')",
        (it_campaign_id, it_emp_id),
    )

    db.commit()
    db.close()

    return {
        "org_id": org_id,
        "it_admin_id": it_admin_id,
        "hr_admin_id": hr_admin_id,
        "it_emp_id": it_emp_id,
        "hr_emp_id": hr_emp_id,
        "org_campaign_id": org_campaign_id,
        "it_campaign_id": it_campaign_id,
    }


def login(client, email):
    resp = client.post("/login", data={"email": email, "password": "password123"}, follow_redirects=True)
    assert resp.status_code == 200, f"login failed for {email}: {resp.status_code}"


def main():
    ids = setup_data()
    app = create_app()
    app.config["TESTING"] = True

    # ---- 1 & 7: dashboard visibility ----
    with app.test_client() as client:
        login(client, "it@sampath.test")
        body = client.get("/admin").get_data(as_text=True)
        check("IT dept admin dashboard shows IT Person", "IT Person" in body)
        check("IT dept admin dashboard hides HR Person", "HR Person" not in body)
        # Org-wide campaign should be visible (view access)...
        check("IT dept admin sees org-wide campaign on dashboard", "Org Wide Q1" in body)
        check("IT dept admin sees their own IT campaign on dashboard", "IT Only Campaign" in body)

    with app.test_client() as client:
        login(client, "core@sampath.test")
        body = client.get("/admin").get_data(as_text=True)
        check("Core admin dashboard shows IT Person", "IT Person" in body)
        check("Core admin dashboard shows HR Person", "HR Person" in body)
        check("Core admin dashboard shows org-wide campaign", "Org Wide Q1" in body)
        check("Core admin dashboard shows IT-only campaign", "IT Only Campaign" in body)

    # ---- 2: cross-department employee_detail blocked ----
    with app.test_client() as client:
        login(client, "it@sampath.test")
        resp = client.get(f"/admin/employee/{ids['hr_emp_id']}", follow_redirects=True)
        body = resp.get_data(as_text=True)
        check(
            "IT dept admin blocked from HR employee profile",
            "Employee not found" in body or "HR Person" not in body,
        )
        resp_own = client.get(f"/admin/employee/{ids['it_emp_id']}")
        check("IT dept admin CAN view their own department's employee", resp_own.status_code == 200)

    # ---- 3: CSV upload forces department ----
    with app.test_client() as client:
        login(client, "it@sampath.test")
        csv_content = (
            "full_name,email,department,job_title\r\n"
            "Sneaky Person,sneaky@sampath.test,HR,Analyst\r\n"
        )
        from io import BytesIO
        data = {"csv_file": (BytesIO(csv_content.encode()), "upload.csv")}
        client.post("/admin/upload", data=data, content_type="multipart/form-data")

    db = database.get_db()
    row = db.execute("SELECT department FROM employees WHERE email = ?", ("sneaky@sampath.test",)).fetchone()
    check(
        "CSV-specified department ('HR') overridden to dept admin's own department ('IT')",
        row is not None and row["department"] == "IT",
    )
    db.close()

    # ---- 4: campaign creation scoping ----
    with app.test_client() as client:
        login(client, "it@sampath.test")
        client.post("/admin/campaign/new", data={"name": "IT Second Campaign", "condition": "generic"})

    db = database.get_db()
    new_campaign = db.execute(
        "SELECT * FROM campaigns WHERE name = 'IT Second Campaign'"
    ).fetchone()
    check("Dept-admin-created campaign is tagged with their department", new_campaign["department"] == "IT")
    recipient_depts = {
        row["department"] for row in db.execute(
            """SELECT e.department FROM campaign_emails ce
               JOIN employees e ON e.id = ce.employee_id
               WHERE ce.campaign_id = ?""",
            (new_campaign["id"],),
        ).fetchall()
    }
    check("Dept-admin-created campaign only emailed IT employees", recipient_depts == {"IT"})
    db.close()

    # ---- 5 & 6: view vs action access on campaigns ----
    with app.test_client() as client:
        login(client, "it@sampath.test")
        # View access to the org-wide campaign should succeed.
        resp = client.get(f"/admin/campaign/{ids['org_campaign_id']}")
        check("IT dept admin can VIEW the org-wide campaign", resp.status_code == 200)
        view_body = resp.get_data(as_text=True)
        check("View-only campaign page shows 'View only' / no manage controls", "View only" in view_body)

        # Action access to the org-wide campaign should be denied.
        resp = client.post(f"/admin/campaign/{ids['org_campaign_id']}/delete", follow_redirects=True)
        body = resp.get_data(as_text=True)
        check("IT dept admin CANNOT delete the org-wide campaign", "Campaign not found" in body)

        resp = client.post(f"/admin/campaign/{ids['org_campaign_id']}/send", follow_redirects=True)
        body = resp.get_data(as_text=True)
        check("IT dept admin CANNOT send the org-wide campaign", "Campaign not found" in body)

        resp = client.post(f"/admin/campaign/{ids['org_campaign_id']}/test-send", follow_redirects=True)
        body = resp.get_data(as_text=True)
        check("IT dept admin CANNOT test-send the org-wide campaign", "Campaign not found" in body)

    # Cross-department action denial: HR admin trying to touch the IT campaign.
    with app.test_client() as client:
        login(client, "hr@sampath.test")
        resp = client.get(f"/admin/campaign/{ids['it_campaign_id']}", follow_redirects=True)
        body = resp.get_data(as_text=True)
        check("HR dept admin CANNOT even view the IT-only campaign", "Campaign not found" in body)

        resp = client.post(f"/admin/campaign/{ids['it_campaign_id']}/delete", follow_redirects=True)
        body = resp.get_data(as_text=True)
        check("HR dept admin CANNOT delete the IT-only campaign", "Campaign not found" in body)

    # Verify nothing was actually deleted/sent by any of the above denied attempts.
    db = database.get_db()
    still_there = db.execute(
        "SELECT * FROM campaigns WHERE id IN (?, ?)", (ids["org_campaign_id"], ids["it_campaign_id"])
    ).fetchall()
    check("Both campaigns survive all denied delete/send attempts intact", len(still_there) == 2)
    check("Org-wide campaign status is still 'draft' (send was blocked)",
          [c for c in still_there if c["id"] == ids["org_campaign_id"]][0]["status"] == "draft")
    db.close()

    # ---- Core admin CAN manage everything ----
    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.get(f"/admin/campaign/{ids['it_campaign_id']}")
        check("Core admin can view the IT-only campaign", resp.status_code == 200)
        body = resp.get_data(as_text=True)
        check("Core admin sees manage controls (not 'view only') on dept campaign", "View only" not in body)

    # ---- 8: /admin/department-admins gating ----
    with app.test_client() as client:
        login(client, "it@sampath.test")
        resp = client.get("/admin/department-admins", follow_redirects=True)
        body = resp.get_data(as_text=True)
        check(
            "Department admin blocked from /admin/department-admins",
            "do not have permission" in body.lower() or "Manage Department Admins" not in body,
        )

    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.get("/admin/department-admins")
        check("Core admin CAN reach /admin/department-admins", resp.status_code == 200)

        resp = client.post(
            "/admin/department-admins",
            data={
                "full_name": "Finance Admin",
                "email": "finance@sampath.test",
                "password": "password123",
                "department": "Finance",
            },
            follow_redirects=True,
        )
        check("Core admin's new department-admin creation succeeds (flash)",
              "created for Finance" in resp.get_data(as_text=True))

    db = database.get_db()
    new_admin = db.execute("SELECT * FROM users WHERE email = ?", ("finance@sampath.test",)).fetchone()
    check("New department-admin account exists with role=admin", new_admin is not None and new_admin["role"] == "admin")
    check("New department-admin account has department='Finance'", new_admin["department"] == "Finance")
    db.close()

    # New department admin can log in and sees an empty (correctly scoped) dashboard.
    with app.test_client() as client:
        login(client, "finance@sampath.test")
        body = client.get("/admin").get_data(as_text=True)
        check("New Finance dept admin sees neither IT nor HR employees",
              "IT Person" not in body and "HR Person" not in body)

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All department-admin RBAC checks passed.")


if __name__ == "__main__":
    main()
    os.unlink(tmp_db.name)
