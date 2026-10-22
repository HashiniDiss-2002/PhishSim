"""
test_delete_organization.py
------------------------------
Verifies the core-admin-only "delete organization" feature (admin.py:
delete_organization()) — the GDPR Art. 17 / Sri Lanka PDPA right-to-erasure
control this project previously only described, not implemented.

Same throwaway-app + fresh-schema + test-client pattern as every other
test_*.py here. Runs in MOCK MODE with a temporary SQLite file.

Covers:
  1. GET renders the confirmation page without deleting anything.
  2. A department admin is bounced (cannot even reach the page) —
     @core_admin_required, not @role_required('admin').
  3. POSTing with a WRONG typed confirmation name deletes nothing.
  4. POSTing with the CORRECT typed name deletes the organization and
     every dependent row: employees, campaigns, campaign_emails,
     interactions, audit_log (org-scoped rows), support_tickets,
     password_reset_tokens.
  5. A permanent record of the deletion survives (org_id=NULL), even
     though the org's own audit_log rows are gone.
  6. The acting admin's session is cleared and they land on the login
     page, not a now-nonexistent dashboard.
  7. threat_intel_sources/scenarios (engineer-owned, shared resources)
     are NOT touched by deleting an unrelated org.

Run with:  python test_delete_organization.py
"""

import os
import sys
import tempfile

for var in ("GROQ_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
            "SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD"):
    os.environ.pop(var, None)

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

    cur = db.execute("INSERT INTO organizations (name) VALUES (?)", ("Acme Corp",))
    org_id = cur.lastrowid

    def mkuser(email, full_name, role, org, department=None):
        db.execute(
            "INSERT INTO users (org_id, email, password_hash, role, full_name, department) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (org, email, generate_password_hash("password123"), role, full_name, department),
        )
        return db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()["id"]

    core_admin_id = mkuser("core@acme.test", "Core Admin", "admin", org_id, None)
    dept_admin_id = mkuser("dept@acme.test", "Dept Admin", "admin", org_id, "IT")
    engineer_id = mkuser("engineer@phishsim.test", "Platform Engineer", "engineer", None, None)

    cur = db.execute(
        "INSERT INTO employees (org_id, full_name, email, department, job_title) "
        "VALUES (?, 'Jane Doe', 'jane@acme.test', 'IT', 'Engineer')",
        (org_id,),
    )
    emp_id = cur.lastrowid

    cur = db.execute(
        "INSERT INTO campaigns (org_id, name, condition, pretext_context, department, created_by, status) "
        "VALUES (?, 'Q1 Campaign', 'generic', 'n/a', NULL, ?, 'draft')",
        (org_id, core_admin_id),
    )
    campaign_id = cur.lastrowid
    cur = db.execute(
        "INSERT INTO campaign_emails (campaign_id, employee_id, token, subject, html_body) "
        "VALUES (?, ?, 'tok-1', 'Subj', '<p>body</p>')",
        (campaign_id, emp_id),
    )
    campaign_email_id = cur.lastrowid

    db.execute(
        "INSERT INTO interactions (campaign_email_id, event_type) VALUES (?, 'open')",
        (campaign_email_id,),
    )

    db.execute(
        "INSERT INTO support_tickets "
        "(org_id, raised_by_user_id, raised_by_name, raised_by_role, org_name, subject, message) "
        "VALUES (?, ?, 'Core Admin', 'admin', 'Acme Corp', 'Help', 'Something broke')",
        (org_id, core_admin_id),
    )

    db.execute(
        "INSERT INTO password_reset_tokens (user_id, token, requested_by, expires_at) "
        "VALUES (?, 'reset-tok-1', ?, datetime('now', '+1 hour'))",
        (dept_admin_id, core_admin_id),
    )

    db.execute(
        "INSERT INTO audit_log (org_id, actor_user_id, actor_role, actor_name, action, description) "
        "VALUES (?, ?, 'admin', 'Core Admin', 'campaign_created', 'Created Q1 Campaign')",
        (org_id, core_admin_id),
    )

    # An unrelated, engineer-owned threat-intel source — must survive.
    db.execute(
        "INSERT INTO threat_intel_sources (url, added_by) VALUES ('https://example.com/feed', ?)",
        (engineer_id,),
    )

    db.commit()
    db.close()

    return {
        "org_id": org_id,
        "core_admin_id": core_admin_id,
        "dept_admin_id": dept_admin_id,
        "campaign_id": campaign_id,
        "campaign_email_id": campaign_email_id,
    }


def login(client, email):
    resp = client.post("/login", data={"email": email, "password": "password123"}, follow_redirects=True)
    assert resp.status_code == 200, f"login failed for {email}: {resp.status_code}"


def count(table, where="1=1"):
    db = database.get_db()
    row = db.execute(f"SELECT COUNT(*) AS c FROM {table} WHERE {where}").fetchone()
    db.close()
    return row["c"]


def main():
    app = create_app()
    app.config["TESTING"] = True

    # --- 1 & 2: GET renders for a core admin; a dept admin is bounced ---
    ids = setup_data()
    with app.test_client() as client:
        login(client, "dept@acme.test")
        r = client.get("/admin/organization/delete", follow_redirects=True)
        check(
            "Department admin cannot reach the delete-organization page",
            b"permission" in r.data.lower() or b"delete" not in r.data.lower(),
        )
    check(
        "Org still exists after a department admin merely visited the page",
        count("organizations", f"id = {ids['org_id']}") == 1,
    )

    with app.test_client() as client:
        login(client, "core@acme.test")
        r = client.get("/admin/organization/delete")
        check("Core admin's GET request renders the confirmation page (200)", r.status_code == 200)
        check("Confirmation page shows the org's real name", b"Acme Corp" in r.data)
    check(
        "Nothing deleted by a plain GET",
        count("organizations", f"id = {ids['org_id']}") == 1,
    )

    # --- 3: wrong typed confirmation deletes nothing ---
    with app.test_client() as client:
        login(client, "core@acme.test")
        client.post(
            "/admin/organization/delete",
            data={"confirm_name": "Not The Right Name"},
            follow_redirects=True,
        )
    check(
        "Wrong confirmation text leaves the organization untouched",
        count("organizations", f"id = {ids['org_id']}") == 1,
    )
    check(
        "Wrong confirmation text leaves employees untouched",
        count("employees", f"org_id = {ids['org_id']}") == 1,
    )

    # --- 4, 5, 6, 7: correct confirmation performs the full cascade ---
    with app.test_client() as client:
        login(client, "core@acme.test")
        r = client.post(
            "/admin/organization/delete",
            data={"confirm_name": "Acme Corp"},
            follow_redirects=True,
        )
        check("Correct deletion redirects to the login page", b"log in" in r.data.lower() or b"login" in r.data.lower())

    check("Organization row is gone", count("organizations", f"id = {ids['org_id']}") == 0)
    check("Users (core admin + dept admin) are gone", count("users", f"org_id = {ids['org_id']}") == 0)
    check("Employees are gone", count("employees", f"org_id = {ids['org_id']}") == 0)
    check("Campaigns are gone", count("campaigns", f"org_id = {ids['org_id']}") == 0)
    check(
        "Campaign emails are gone",
        count("campaign_emails", f"id = {ids['campaign_email_id']}") == 0,
    )
    check(
        "Interactions are gone",
        count("interactions", f"campaign_email_id = {ids['campaign_email_id']}") == 0,
    )
    check("Support tickets are gone", count("support_tickets", f"org_id = {ids['org_id']}") == 0)
    check(
        "Password reset tokens for this org's users are gone",
        count("password_reset_tokens", "token = 'reset-tok-1'") == 0,
    )
    check(
        "This org's OWN prior audit_log rows are gone",
        count("audit_log", f"org_id = {ids['org_id']}") == 0,
    )
    check(
        "A permanent org_id=NULL deletion record exists instead",
        count("audit_log", "action = 'organization_deleted' AND org_id IS NULL") == 1,
    )
    check(
        "Unrelated, engineer-owned threat_intel_sources are NOT touched",
        count("threat_intel_sources") == 1,
    )

    # --- The permanent record is visible to the engineer ---
    with app.test_client() as client:
        db = database.get_db()
        eng = db.execute("SELECT password_hash FROM users WHERE email = 'engineer@phishsim.test'").fetchone()
        db.close()
        login(client, "engineer@phishsim.test")
        r = client.get("/engineer/audit-log")
        check(
            "Engineer's audit log shows the organization was deleted",
            b"Acme Corp" in r.data and b"deleted" in r.data.lower(),
        )

    if failures:
        print(f"\n{len(failures)} check(s) FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("\nAll delete-organization checks passed.")


if __name__ == "__main__":
    main()
