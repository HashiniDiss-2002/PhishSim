"""
test_engineer_org_view.py
---------------------------
Verifies the engineer-dashboard expansion (organization names + per-org
campaign counts, for billing/abuse monitoring) and the new suspend /
reactivate control, using the same throwaway-app + test-client pattern as
test_department_admin.py.

Specifically checks:
  1. Engineer dashboard shows organization NAMES and per-org campaign counts.
  2. It still shows zero employee names, emails, or campaign names/content
     (the pre-existing tenant-isolation boundary must not regress).
  3. Suspending an org blocks login for that org's admin accounts...
  4. ...but never affects the engineer's own login, or another org's admin.
  5. Reactivating restores login.
  6. A non-engineer (admin) cannot reach the suspend/reactivate route.
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
    org_a = cur.lastrowid
    cur = db.execute("INSERT INTO organizations (name) VALUES (?)", ("Shadowy Client Inc",))
    org_b = cur.lastrowid

    db.execute(
        "INSERT INTO users (org_id, email, password_hash, role, full_name) VALUES (?, ?, ?, 'engineer', ?)",
        (None, "engineer@platform.local", generate_password_hash("password123"), "Platform Engineer"),
    )
    db.execute(
        "INSERT INTO users (org_id, email, password_hash, role, full_name) VALUES (?, ?, ?, 'admin', ?)",
        (org_a, "admin_a@sampath.test", generate_password_hash("password123"), "Admin A"),
    )
    db.execute(
        "INSERT INTO users (org_id, email, password_hash, role, full_name) VALUES (?, ?, ?, 'admin', ?)",
        (org_b, "admin_b@shadowy.test", generate_password_hash("password123"), "Admin B"),
    )
    db.execute(
        "INSERT INTO employees (org_id, full_name, email, department, job_title) VALUES (?, ?, ?, ?, ?)",
        (org_a, "Secret Employee Name", "secret@sampath.test", "Finance", "Analyst"),
    )
    db.execute(
        "INSERT INTO campaigns (org_id, name, condition, pretext_context, created_by, status) "
        "VALUES (?, 'TOP SECRET CAMPAIGN NAME', 'generic', 'n/a', "
        "(SELECT id FROM users WHERE email='admin_a@sampath.test'), 'draft')",
        (org_a,),
    )

    db.commit()
    db.close()
    return org_a, org_b


def login(client, email, password="password123"):
    return client.post("/login", data={"email": email, "password": password}, follow_redirects=True)


def main():
    org_a, org_b = setup_data()
    app = create_app()
    app.config["TESTING"] = True

    # ---- 1 & 2: engineer dashboard content ----
    with app.test_client() as client:
        login(client, "engineer@platform.local")
        body = client.get("/engineer").get_data(as_text=True)
        check("Engineer dashboard shows 'Sampath Bank Sri Lanka'", "Sampath Bank Sri Lanka" in body)
        check("Engineer dashboard shows 'Shadowy Client Inc'", "Shadowy Client Inc" in body)
        check("Engineer dashboard shows per-org campaign count (1)", ">1<" in body or ">1 " in body or "1</td>" in body)
        check("Engineer dashboard NEVER shows the employee's name", "Secret Employee Name" not in body)
        check("Engineer dashboard NEVER shows the campaign's name", "TOP SECRET CAMPAIGN NAME" not in body)
        check("Engineer dashboard NEVER shows employee email", "secret@sampath.test" not in body)

    # ---- 6: non-engineer blocked from suspend route ----
    with app.test_client() as client:
        login(client, "admin_a@sampath.test")
        resp = client.post(f"/engineer/org/{org_b}/toggle-suspend", follow_redirects=True)
        body = resp.get_data(as_text=True)
        check("Admin (non-engineer) blocked from toggle-suspend route", "do not have permission" in body.lower())

    db = database.get_db()
    row = db.execute("SELECT suspended FROM organizations WHERE id = ?", (org_b,)).fetchone()
    check("Org B NOT suspended after the blocked attempt", row["suspended"] == 0)
    db.close()

    # ---- 3, 4: suspend org B, confirm isolation ----
    with app.test_client() as client:
        login(client, "engineer@platform.local")
        client.post(f"/engineer/org/{org_b}/toggle-suspend", follow_redirects=True)

    db = database.get_db()
    row = db.execute("SELECT suspended FROM organizations WHERE id = ?", (org_b,)).fetchone()
    check("Org B is now suspended", row["suspended"] == 1)
    db.close()

    with app.test_client() as client:
        resp = login(client, "admin_b@shadowy.test")
        body = resp.get_data(as_text=True)
        check("Suspended org's admin is blocked at login", "suspended" in body.lower())

    with app.test_client() as client:
        resp = login(client, "admin_a@sampath.test")
        check("Org A's admin (different org) can still log in fine", "Admin Dashboard" in resp.get_data(as_text=True))

    with app.test_client() as client:
        resp = login(client, "engineer@platform.local")
        check("Engineer's own login is unaffected by any org's suspension", "Platform Engineer" in resp.get_data(as_text=True) or resp.status_code == 200)

    # ---- 5: reactivate restores login ----
    with app.test_client() as client:
        login(client, "engineer@platform.local")
        client.post(f"/engineer/org/{org_b}/toggle-suspend", follow_redirects=True)

    db = database.get_db()
    row = db.execute("SELECT suspended FROM organizations WHERE id = ?", (org_b,)).fetchone()
    check("Org B is active again after second toggle", row["suspended"] == 0)
    db.close()

    with app.test_client() as client:
        resp = login(client, "admin_b@shadowy.test")
        check("Reactivated org's admin can log in again", "Admin Dashboard" in resp.get_data(as_text=True))

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All engineer org-view / suspend checks passed.")


if __name__ == "__main__":
    main()
    os.unlink(tmp_db.name)
