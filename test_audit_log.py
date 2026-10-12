"""
test_audit_log.py
--------------------
Verifies the admin-facing audit trail (services/audit.py, the audit_log
table, and the admin.audit_log / admin.engineer_audit_log routes).

Covers:
  1. Uploading employees, creating a campaign, sending it, and deleting a
     campaign each log a distinctly-actioned audit_log row for the
     correct organization.
  2. Creating a department-admin account logs an audit entry.
  3. An engineer suspending/reactivating an organization logs an entry
     against THAT organization, even though the actor is the engineer.
  4. /admin/audit-log (core-admin only) shows every action type for the
     admin's own org, and is blocked for a department admin.
  5. /engineer/audit-log shows ONLY the platform-level actions
     (organization_registered, org_suspended, org_reactivated) across
     every org, and NEVER a campaign-level action or its description
     (which could contain a campaign name) — preserving the "engineer has
     no tenant data access" boundary.
  6. A core admin's own /admin/audit-log never shows another
     organization's rows.

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

    db.execute(
        "INSERT INTO users (org_id, email, password_hash, role, full_name) VALUES (NULL, ?, ?, 'engineer', ?)",
        ("engineer@platform.local", generate_password_hash("password123"), "Platform Engineer"),
    )

    cur = db.execute("INSERT INTO organizations (name) VALUES (?)", ("Sampath Bank Sri Lanka",))
    org_a = cur.lastrowid
    db.execute(
        "INSERT INTO users (org_id, email, password_hash, role, full_name, department) "
        "VALUES (?, ?, ?, 'admin', ?, NULL)",
        (org_a, "core@sampath.test", generate_password_hash("password123"), "Core Admin"),
    )

    cur = db.execute("INSERT INTO organizations (name) VALUES (?)", ("Shadowy Client Inc",))
    org_b = cur.lastrowid
    db.execute(
        "INSERT INTO users (org_id, email, password_hash, role, full_name, department) "
        "VALUES (?, ?, ?, 'admin', ?, NULL)",
        (org_b, "core@shadowy.test", generate_password_hash("password123"), "Shadowy Admin"),
    )

    db.execute(
        "INSERT INTO employees (org_id, full_name, email, department, job_title) VALUES (?, ?, ?, ?, ?)",
        (org_a, "Jane Employee", "jane@sampath.test", "Finance", "Analyst"),
    )

    db.commit()
    db.close()
    return org_a, org_b


def login(client, email):
    return client.post("/login", data={"email": email, "password": "password123"}, follow_redirects=True)


def main():
    org_a, org_b = setup_data()
    app = create_app()
    app.config["TESTING"] = True

    # ---- 1: campaign/employee-level actions logged ----
    with app.test_client() as client:
        login(client, "core@sampath.test")
        client.post("/admin/campaign/new", data={"name": "Q3 Test", "condition": "personalized"},
                    follow_redirects=True)

    db = database.get_db()
    campaign_id = db.execute("SELECT id FROM campaigns WHERE name = 'Q3 Test'").fetchone()["id"]
    created_entry = db.execute(
        "SELECT * FROM audit_log WHERE org_id = ? AND action = 'campaign_created'", (org_a,)
    ).fetchone()
    check("campaign_created audit entry logged", created_entry is not None)
    check("campaign_created description mentions the campaign name",
          created_entry is not None and "Q3 Test" in created_entry["description"])
    db.close()

    with app.test_client() as client:
        login(client, "core@sampath.test")
        client.post(f"/admin/campaign/{campaign_id}/send", follow_redirects=True)

    db = database.get_db()
    check("campaign_sent audit entry logged",
          db.execute(
              "SELECT * FROM audit_log WHERE org_id = ? AND action = 'campaign_sent'", (org_a,)
          ).fetchone() is not None)
    db.close()

    with app.test_client() as client:
        login(client, "core@sampath.test")
        client.post(f"/admin/campaign/{campaign_id}/delete", follow_redirects=True)

    db = database.get_db()
    check("campaign_deleted audit entry logged",
          db.execute(
              "SELECT * FROM audit_log WHERE org_id = ? AND action = 'campaign_deleted'", (org_a,)
          ).fetchone() is not None)
    db.close()

    import io
    with app.test_client() as client:
        login(client, "core@sampath.test")
        csv_content = b"full_name,email,department,job_title\nNew Person,new.person@sampath.test,IT,Engineer\n"
        client.post("/admin/upload", data={"csv_file": (io.BytesIO(csv_content), "test.csv")},
                    content_type="multipart/form-data", follow_redirects=True)

    db = database.get_db()
    check("employees_uploaded audit entry logged",
          db.execute(
              "SELECT * FROM audit_log WHERE org_id = ? AND action = 'employees_uploaded'", (org_a,)
          ).fetchone() is not None)
    db.close()

    # ---- 2: department-admin creation logged ----
    with app.test_client() as client:
        login(client, "core@sampath.test")
        client.post("/admin/department-admins", data={
            "full_name": "Finance Admin", "email": "finance.admin@sampath.test",
            "password": "password123", "department": "Finance",
        }, follow_redirects=True)

    db = database.get_db()
    dept_entry = db.execute(
        "SELECT * FROM audit_log WHERE org_id = ? AND action = 'department_admin_created'", (org_a,)
    ).fetchone()
    check("department_admin_created audit entry logged", dept_entry is not None)
    db.close()

    # ---- 3: engineer suspend/reactivate logged against the TARGET org ----
    with app.test_client() as client:
        login(client, "engineer@platform.local")
        client.post(f"/engineer/org/{org_b}/toggle-suspend", follow_redirects=True)

    db = database.get_db()
    suspend_entry = db.execute(
        "SELECT * FROM audit_log WHERE org_id = ? AND action = 'org_suspended'", (org_b,)
    ).fetchone()
    check("org_suspended audit entry logged against the target org", suspend_entry is not None)
    check("org_suspended actor is the engineer, not the target org's own admin",
          suspend_entry is not None and suspend_entry["actor_role"] == "engineer")
    db.close()

    with app.test_client() as client:
        login(client, "engineer@platform.local")
        client.post(f"/engineer/org/{org_b}/toggle-suspend", follow_redirects=True)

    db = database.get_db()
    check("org_reactivated audit entry logged",
          db.execute(
              "SELECT * FROM audit_log WHERE org_id = ? AND action = 'org_reactivated'", (org_b,)
          ).fetchone() is not None)
    db.close()

    # ---- 4: core-admin audit log page shows everything for own org; dept admin blocked ----
    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.get("/admin/audit-log")
        check("Core admin can reach /admin/audit-log", resp.status_code == 200)
        body = resp.get_data(as_text=True)
        check("Shows campaign_created", "campaign_created" in body)
        check("Shows employees_uploaded", "employees_uploaded" in body)
        check("Shows department_admin_created", "department_admin_created" in body)

    with app.test_client() as client:
        login(client, "finance.admin@sampath.test")
        resp = client.get("/admin/audit-log", follow_redirects=True)
        body = resp.get_data(as_text=True)
        check("Department admin is blocked from /admin/audit-log",
              "do not have permission" in body.lower())

    # ---- 6: no cross-org leakage on the core-admin's own log ----
    with app.test_client() as client:
        login(client, "core@sampath.test")
        body = client.get("/admin/audit-log").get_data(as_text=True)
        check("Sampath's own audit log never mentions the other org's name",
              "Shadowy Client Inc" not in body)

    # ---- 5: engineer audit log is filtered to platform-level actions only ----
    with app.test_client() as client:
        login(client, "engineer@platform.local")
        resp = client.get("/engineer/audit-log")
        check("Engineer can reach /engineer/audit-log", resp.status_code == 200)
        body = resp.get_data(as_text=True)
        check("Shows org_suspended", "org_suspended" in body)
        check("Shows org_reactivated", "org_reactivated" in body)
        check("Shows the target organization's NAME (not tenant content, just which org)",
              "Shadowy Client Inc" in body)
        check("Never shows campaign_created", "campaign_created" not in body)
        check("Never shows employees_uploaded", "employees_uploaded" not in body)
        check("Never shows department_admin_created", "department_admin_created" not in body)
        check("Never shows report_exported", "report_exported" not in body)
        check("Never leaks the campaign name 'Q3 Test' created in Sampath's tenant",
              "Q3 Test" not in body)

    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.get("/engineer/audit-log", follow_redirects=True)
        body = resp.get_data(as_text=True)
        check("A client admin cannot reach /engineer/audit-log",
              "do not have permission" in body.lower())

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All audit-log checks passed.")


if __name__ == "__main__":
    main()
    os.unlink(tmp_db.name)
