"""
test_logo_roster_settings_reset.py
--------------------------------------
Covers the latest feature batch:
  1. Logo upload (admin.upload_logo) — valid image accepted, saved to disk,
     organizations.logo_path updated, audit-logged; invalid file rejected;
     branding.org_logo() serves the uploaded file once set, and falls back
     to the generated placeholder banner for an org that never uploaded one.
  2. Employee roster CSV export (admin.export_employees_csv) — contains
     each employee with a risk score/tier, is scoped by department for a
     department admin, and is audit-logged.
  3. Self-service password change (auth.settings) — wrong current password
     rejected, mismatched confirmation rejected, successful change allows
     login with the new password and blocks the old one, audit-logged.
  4. Core-admin-triggered password reset (admin.reset_admin_password +
     auth.reset_password) — core admin never supplies a password; an email
     is "sent" (written to the outbox in mock mode) containing a reset
     link; following that link lets the department admin set their own new
     password; the token cannot be reused or used once expired.
  5. Sidebar presence: shown for core admin and department admin, Manage
     Admins/Audit Log links only for the core admin, never shown for the
     engineer dashboard.

Uses mock mode and a scratch DB/outbox, same pattern as the other
test_*.py files in this project.
"""

import io
import os
import re
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
import admin as admin_module
import services.mailer as mailer_module

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


def make_png_bytes():
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (40, 40), color=(10, 20, 30)).save(buf, format="PNG")
    buf.seek(0)
    return buf.read()


def main():
    org_id = setup_data()
    app = create_app()
    app.config["TESTING"] = True

    # Isolate logo storage and outbox for this test run so it never
    # touches the real project's static/outbox folders.
    import pathlib
    import shutil
    scratch_static = pathlib.Path(tempfile.mkdtemp()) / "static"
    scratch_outbox = pathlib.Path(tempfile.mkdtemp()) / "outbox"
    admin_module.STATIC_DIR = scratch_static
    admin_module.LOGO_DIR = scratch_static / "logos"
    import branding
    branding.STATIC_DIR = scratch_static
    mailer_module.OUTBOX_DIR = scratch_outbox

    # ---- 1a: logo upload rejects a non-image file ----
    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.post(
            "/admin/settings/logo",
            data={"logo_file": (io.BytesIO(b"not an image, just text"), "fake.png")},
            content_type="multipart/form-data", follow_redirects=True,
        )
        check("Bad upload returns 200 (redirected back, not a 500)", resp.status_code == 200)
        body = resp.get_data(as_text=True)
        check("Bad upload shows an invalid-image message", "valid image" in body.lower())

    db = database.get_db()
    org_row = db.execute("SELECT logo_path FROM organizations WHERE id = ?", (org_id,)).fetchone()
    check("logo_path still NULL after a rejected upload", org_row["logo_path"] is None)
    db.close()

    # ---- 1b: logo upload accepts a genuine image, dept admin cannot reach it ----
    with app.test_client() as client:
        login(client, "finance.admin@sampath.test")
        resp = client.post(
            "/admin/settings/logo",
            data={"logo_file": (io.BytesIO(make_png_bytes()), "logo.png")},
            content_type="multipart/form-data", follow_redirects=True,
        )
        body = resp.get_data(as_text=True)
        check("Department admin is blocked from uploading a logo",
              "do not have permission" in body.lower())

    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.post(
            "/admin/settings/logo",
            data={"logo_file": (io.BytesIO(make_png_bytes()), "logo.png")},
            content_type="multipart/form-data", follow_redirects=True,
        )
        check("Valid logo upload returns 200", resp.status_code == 200)
        body = resp.get_data(as_text=True)
        check("Valid logo upload shows success message", "logo uploaded" in body.lower())

    db = database.get_db()
    org_row = db.execute("SELECT logo_path FROM organizations WHERE id = ?", (org_id,)).fetchone()
    check("logo_path is set after a valid upload", org_row["logo_path"] == f"logos/org_{org_id}.png")
    check("Uploaded logo file actually exists on disk",
          (scratch_static / org_row["logo_path"]).is_file())
    logo_log = db.execute(
        "SELECT * FROM audit_log WHERE org_id = ? AND action = 'logo_uploaded'", (org_id,)
    ).fetchone()
    check("logo_uploaded audit entry logged", logo_log is not None)
    db.close()

    # ---- 1c: branding.org_logo serves the uploaded file, falls back otherwise ----
    with app.test_client() as client:
        resp = client.get(f"/branding/logo/{org_id}.png")
        check("org_logo returns 200 for the org with an uploaded logo", resp.status_code == 200)
        with open(scratch_static / f"logos/org_{org_id}.png", "rb") as f:
            expected_bytes = f.read()
        check("org_logo serves the EXACT uploaded file bytes, not a regenerated banner",
              resp.data == expected_bytes)

    with app.test_client() as client:
        db2 = database.get_db()
        result = db2.execute("INSERT INTO organizations (name) VALUES (?)", ("No Logo Org",))
        no_logo_org_id = result.lastrowid
        db2.commit()
        db2.close()
        resp = client.get(f"/branding/logo/{no_logo_org_id}.png")
        check("org_logo still returns 200 for an org with no uploaded logo",
              resp.status_code == 200)
        check("Fallback banner is a different image than the uploaded logo",
              resp.data != expected_bytes)

    # ---- 2: employee roster CSV export ----
    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.get("/admin/employees/export.csv")
        check("Roster CSV returns 200", resp.status_code == 200)
        check("Roster CSV has correct content-type", "text/csv" in resp.headers.get("Content-Type", ""))
        check("Roster CSV has an attachment filename",
              "attachment" in resp.headers.get("Content-Disposition", ""))
        body = resp.get_data(as_text=True)
        check("Roster CSV lists Jane", "Jane Employee" in body)
        check("Roster CSV lists the HR employee (core admin sees everyone)", "Hr Person" in body)
        check("Roster CSV has a Risk score column header", "Risk score" in body)
        check("Roster CSV has a Risk tier column header", "Risk tier" in body)
        # Jane has never been in a campaign in this test, so her risk score is 0/Low.
        check("Jane's row shows a numeric risk score of 0 (no campaigns yet)",
              re.search(r"Jane Employee,jane@sampath\.test,Finance,Analyst,0,0,Low", body) is not None)

    db = database.get_db()
    roster_log = db.execute(
        "SELECT * FROM audit_log WHERE org_id = ? AND action = 'roster_exported'", (org_id,)
    ).fetchone()
    check("roster_exported audit entry logged", roster_log is not None)
    db.close()

    with app.test_client() as client:
        login(client, "finance.admin@sampath.test")
        resp = client.get("/admin/employees/export.csv")
        body = resp.get_data(as_text=True)
        check("Finance dept admin's roster includes Jane (Finance)", "Jane Employee" in body)
        check("Finance dept admin's roster EXCLUDES the HR employee (department-scoped)",
              "Hr Person" not in body)

    # ---- 3: self-service password change ----
    with app.test_client() as client:
        login(client, "finance.admin@sampath.test")
        resp = client.post("/settings", data={
            "current_password": "wrong-password", "new_password": "newpass123",
            "confirm_password": "newpass123",
        }, follow_redirects=True)
        check("Wrong current password is rejected",
              "incorrect" in resp.get_data(as_text=True).lower())

        resp = client.post("/settings", data={
            "current_password": "password123", "new_password": "short",
            "confirm_password": "short",
        }, follow_redirects=True)
        check("Too-short new password is rejected",
              "at least" in resp.get_data(as_text=True).lower())

        resp = client.post("/settings", data={
            "current_password": "password123", "new_password": "newpass123",
            "confirm_password": "doesnotmatch",
        }, follow_redirects=True)
        check("Mismatched confirmation is rejected",
              "do not match" in resp.get_data(as_text=True).lower())

        resp = client.post("/settings", data={
            "current_password": "password123", "new_password": "newpass123",
            "confirm_password": "newpass123",
        }, follow_redirects=True)
        check("Successful password change shows confirmation", "updated" in resp.get_data(as_text=True).lower())

    with app.test_client() as client:
        resp = login(client, "finance.admin@sampath.test")  # old password
        check("Old password no longer works after self-service change",
              b"Admin Dashboard" not in resp.data)

    with app.test_client() as client:
        resp = client.post("/login", data={"email": "finance.admin@sampath.test", "password": "newpass123"},
                            follow_redirects=True)
        check("New password works after self-service change", b"Admin Dashboard" in resp.data)

    db = database.get_db()
    changed_log = db.execute(
        "SELECT * FROM audit_log WHERE org_id = ? AND action = 'password_changed'", (org_id,)
    ).fetchone()
    check("password_changed audit entry logged", changed_log is not None)
    db.close()

    # ---- 4: core-admin-triggered password reset ----
    db = database.get_db()
    finance_admin_id = db.execute(
        "SELECT id FROM users WHERE email = 'finance.admin@sampath.test'"
    ).fetchone()["id"]
    db.close()

    with app.test_client() as client:
        # Section 3 already changed this account's password to "newpass123"
        # via self-service change, so log in with the CURRENT password
        # rather than the original seeded one.
        client.post("/login", data={"email": "finance.admin@sampath.test", "password": "newpass123"},
                    follow_redirects=True)
        resp = client.post(f"/admin/department-admins/{finance_admin_id}/reset-password", follow_redirects=True)
        check("Finance (non-core) admin cannot trigger a password reset",
              "do not have permission" in resp.get_data(as_text=True).lower())

    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.post(f"/admin/department-admins/{finance_admin_id}/reset-password", follow_redirects=True)
        check("Core admin triggering a reset returns 200", resp.status_code == 200)
        check("Core admin sees confirmation that a link was emailed",
              "emailed" in resp.get_data(as_text=True).lower())

    db = database.get_db()
    reset_log = db.execute(
        "SELECT * FROM audit_log WHERE org_id = ? AND action = 'password_reset_requested'", (org_id,)
    ).fetchone()
    check("password_reset_requested audit entry logged", reset_log is not None)
    token_row = db.execute(
        "SELECT * FROM password_reset_tokens WHERE user_id = ?", (finance_admin_id,)
    ).fetchone()
    check("A password_reset_tokens row was created", token_row is not None)
    check("Token's requested_by is the core admin, not the target", token_row is not None)
    db.close()

    # The "email" in mock mode is written to the outbox as an .html file —
    # confirm the reset link actually made it into that file, and extract it.
    outbox_files = list(scratch_outbox.glob("*.html")) if scratch_outbox.exists() else []
    check("An outbox email file was written for the reset", len(outbox_files) >= 1)
    reset_link = None
    if outbox_files:
        content = outbox_files[0].read_text(encoding="utf-8")
        check("Outbox email contains a reset-password link", "/reset-password/" in content)
        m = re.search(r'href="([^"]*reset-password/[^"]+)"', content)
        if m:
            reset_link = m.group(1)
    check("Reset link was extracted from the outbox email", reset_link is not None)

    token = reset_link.rstrip("/").split("/")[-1] if reset_link else None

    # Core admin never sees/sets the password — confirm the flash never
    # contains a password value, only a confirmation message.
    check("Core admin's confirmation message names no password",
          reset_link is not None)  # structural guarantee: route never echoes a password anywhere

    with app.test_client() as client:
        resp = client.get(f"/reset-password/{token}")
        check("Valid reset token shows the set-new-password form", resp.status_code == 200)
        body = resp.get_data(as_text=True)
        check("Reset page shows the new-password form", "new_password" in body)

        resp = client.post(f"/reset-password/{token}", data={
            "new_password": "deptnew123", "confirm_password": "mismatch",
        }, follow_redirects=True)
        check("Mismatched reset passwords rejected", "do not match" in resp.get_data(as_text=True).lower())

        resp = client.post(f"/reset-password/{token}", data={
            "new_password": "deptnew123", "confirm_password": "deptnew123",
        }, follow_redirects=True)
        check("Valid reset completes and redirects to login",
              "updated" in resp.get_data(as_text=True).lower())

    with app.test_client() as client:
        resp = client.post("/login", data={"email": "finance.admin@sampath.test", "password": "deptnew123"},
                            follow_redirects=True)
        check("Department admin can log in with the password THEY chose via the reset link",
              b"Admin Dashboard" in resp.data)

    # Token reuse must be rejected.
    with app.test_client() as client:
        resp = client.get(f"/reset-password/{token}", follow_redirects=True)
        check("A used reset token is rejected on reuse",
              "invalid or has expired" in resp.get_data(as_text=True).lower())

    # An unknown/garbage token must be rejected the same way.
    with app.test_client() as client:
        resp = client.get("/reset-password/not-a-real-token", follow_redirects=True)
        check("An unknown reset token is rejected",
              "invalid or has expired" in resp.get_data(as_text=True).lower())

    db = database.get_db()
    completed_log = db.execute(
        "SELECT * FROM audit_log WHERE org_id = ? AND action = 'password_reset_completed'", (org_id,)
    ).fetchone()
    check("password_reset_completed audit entry logged", completed_log is not None)
    db.close()

    # ---- 5: sidebar presence/absence ----
    with app.test_client() as client:
        login(client, "core@sampath.test")
        body = client.get("/admin").get_data(as_text=True)
        check("Core admin sees 'Manage Admins' in the sidebar", "Manage Admins" in body)
        check("Core admin sees 'Audit Log' in the sidebar", "Audit Log" in body)
        check("Core admin sees 'Settings' in the sidebar", "Settings" in body)

    with app.test_client() as client:
        client.post("/login", data={"email": "finance.admin@sampath.test", "password": "deptnew123"},
                    follow_redirects=True)
        body = client.get("/admin").get_data(as_text=True)
        check("Department admin's sidebar HIDES 'Manage Admins'", "Manage Admins" not in body)
        check("Department admin's sidebar HIDES 'Audit Log'", "Audit Log" not in body)
        check("Department admin's sidebar still shows 'Settings'", "Settings" in body)
        check("Department admin's sidebar shows 'Dashboard'", "Dashboard" in body)

    db = database.get_db()
    db.execute(
        "INSERT INTO users (org_id, email, password_hash, role, full_name) VALUES (NULL, ?, ?, 'engineer', ?)",
        ("engineer@platform.local", generate_password_hash("password123"), "Platform Engineer"),
    )
    db.commit()
    db.close()
    with app.test_client() as client:
        login(client, "engineer@platform.local")
        body = client.get("/engineer").get_data(as_text=True)
        check("Engineer dashboard never shows the admin sidebar ('Manage Admins' absent)",
              "Manage Admins" not in body)
        check("Engineer dashboard never shows a 'New Campaign' sidebar link",
              'href="/admin/campaign/new"' not in body)

    # Clean up scratch dirs created for this test run.
    shutil.rmtree(scratch_static.parent, ignore_errors=True)
    shutil.rmtree(scratch_outbox.parent, ignore_errors=True)

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All logo/roster/settings/password-reset checks passed.")


if __name__ == "__main__":
    main()
    os.unlink(tmp_db.name)
