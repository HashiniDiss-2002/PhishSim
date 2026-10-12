"""
test_registration_and_ethics.py
----------------------------------
Verifies the self-service organization registration flow, its mandatory
email-OTP verification step, and the Responsible Use declaration gate
(auth.py: register(), register_verify_email(), register_ethics()).

Covers:
  1. GET /register renders the form.
  2. Mismatched passwords / too-short password are rejected with no
     organization or user row created, and no pending registration staged.
  3. Valid submission stages a pending_registration in the session,
     emails a one-time code, and redirects to /register/verify-email —
     not straight to the ethics declaration — with no DB row created yet.
  4. Visiting /register/ethics with no pending registration bounces back
     to /register rather than showing a declaration for nothing.
  5. Rejecting the declaration (after verifying email) creates NOTHING
     (no organization, no user) and the submitted email cannot
     subsequently log in.
  6. Accepting the declaration (after verifying email) creates the
     organization (with ethics_accepted_at set) and a core-admin user,
     logs an 'organization_registered' audit_log entry, logs the new
     admin in immediately, and lands them on the employee-upload page.
  7. Registering with an organization name or email that already exists
     is rejected at the form stage, before any OTP is even sent.

Dedicated, fine-grained coverage of the OTP mechanics themselves (wrong
code, expired code, resend, skip-ahead attempts) lives in
test_email_otp_verification.py — this file only exercises the OTP step
as a normal part of the end-to-end registration flow.

Uses mock mode and a scratch DB, same pattern as the other test_*.py
files in this project.
"""

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

from app import create_app
from services.mailer import OUTBOX_DIR

failures = []


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}")
    if not condition:
        failures.append(label)


def get_otp_code(email):
    """
    Mock mode (no SMTP_HOST) writes each sent email to outbox/ as an
    .html file — see services/mailer.py. The OTP template embeds the
    plaintext code in an HTML comment (<!-- OTP_CODE:123456 -->) purely
    so tests can read it back deterministically; it's never shown to a
    real recipient any other way than the visible, styled code in the
    email body itself.
    """
    safe_name = email.replace("@", "_at_").replace(".", "_")
    path = OUTBOX_DIR / f"{safe_name}.html"
    if not path.exists():
        return None
    content = path.read_text(encoding="utf-8")
    m = re.search(r"OTP_CODE:(\d{6})", content)
    return m.group(1) if m else None


def main():
    database.init_db()
    app = create_app()
    app.config["TESTING"] = True

    # ---- 1: form renders ----
    with app.test_client() as client:
        resp = client.get("/register")
        check("GET /register renders OK", resp.status_code == 200)
        check("Form mentions organization name field", b"org_name" in resp.data)

    # ---- 2: validation rejects bad input, nothing staged or created ----
    with app.test_client() as client:
        resp = client.post("/register", data={
            "org_name": "Contoso Ltd", "full_name": "Pat Admin", "email": "pat@contoso.test",
            "password": "short", "confirm_password": "short",
        }, follow_redirects=True)
        check("Too-short password rejected (stays on register page)", b"at least 8" in resp.data)

        resp = client.post("/register", data={
            "org_name": "Contoso Ltd", "full_name": "Pat Admin", "email": "pat@contoso.test",
            "password": "longenough1", "confirm_password": "different1",
        }, follow_redirects=True)
        check("Mismatched passwords rejected", b"do not match" in resp.data)

        with client.session_transaction() as sess:
            check("No pending registration staged after validation failures",
                  "pending_registration" not in sess)

    db = database.get_db()
    check("No organization created after failed validation",
          db.execute("SELECT * FROM organizations WHERE name = 'Contoso Ltd'").fetchone() is None)
    db.close()

    # ---- 3: valid submission stages pending registration, emails an OTP,
    #         and redirects to email verification (not straight to ethics) ----
    with app.test_client() as client:
        resp = client.post("/register", data={
            "org_name": "Contoso Ltd", "full_name": "Pat Admin", "email": "pat@contoso.test",
            "password": "longenough1", "confirm_password": "longenough1",
        })
        check("Valid submission redirects to email verification",
              resp.status_code == 302 and "/register/verify-email" in resp.headers["Location"])

        with client.session_transaction() as sess:
            pending = sess.get("pending_registration")
            check("Pending registration staged in session", pending is not None)
            check("Pending registration never stores the plaintext password",
                  pending is not None and "password" not in pending and "password_hash" in pending)
            check("Email not yet marked verified",
                  not sess.get("pending_registration_email_verified"))

        check("A verification code was emailed to the registrant",
              get_otp_code("pat@contoso.test") is not None)

    db = database.get_db()
    check("No organization row created yet (only staged, not committed)",
          db.execute("SELECT * FROM organizations WHERE name = 'Contoso Ltd'").fetchone() is None)
    check("An email_verification_otps row was created for the registrant",
          db.execute(
              "SELECT 1 FROM email_verification_otps WHERE email = 'pat@contoso.test'"
          ).fetchone() is not None)
    db.close()

    # ---- 4: ethics page unreachable without a pending registration ----
    with app.test_client() as client:
        resp = client.get("/register/ethics", follow_redirects=True)
        check("GET /register/ethics with nothing pending bounces to /register",
              b"Organization name" in resp.data or b"org_name" in resp.data)

    # ---- 5: rejecting (after verifying email) creates nothing ----
    with app.test_client() as client:
        client.post("/register", data={
            "org_name": "Rejected Co", "full_name": "Rex Reject", "email": "rex@rejected.test",
            "password": "longenough1", "confirm_password": "longenough1",
        })
        code = get_otp_code("rex@rejected.test")
        check("OTP retrievable for the reject-path registrant", code is not None)
        resp = client.post("/register/verify-email", data={"action": "verify", "code": code})
        check("Correct OTP code advances to the ethics declaration",
              resp.status_code == 302 and "/register/ethics" in resp.headers["Location"])

        resp = client.post("/register/ethics", data={"action": "reject"}, follow_redirects=True)
        check("Rejecting redirects to login with an explanatory message",
              b"must accept" in resp.data.lower())

        with client.session_transaction() as sess:
            check("Pending registration cleared after rejection", "pending_registration" not in sess)
            check("Email-verified flag cleared after rejection",
                  "pending_registration_email_verified" not in sess)

    db = database.get_db()
    check("No organization created after rejection",
          db.execute("SELECT * FROM organizations WHERE name = 'Rejected Co'").fetchone() is None)
    check("No user created after rejection",
          db.execute("SELECT * FROM users WHERE email = 'rex@rejected.test'").fetchone() is None)
    db.close()

    with app.test_client() as client:
        resp = client.post("/login", data={"email": "rex@rejected.test", "password": "longenough1"},
                            follow_redirects=True)
        check("Rejected registration's email cannot subsequently log in",
              b"Invalid email or password" in resp.data)

    # ---- 6: accepting (after verifying email) creates org + admin, logs in,
    #         audits, redirects ----
    with app.test_client() as client:
        client.post("/register", data={
            "org_name": "Contoso Ltd", "full_name": "Pat Admin", "email": "pat@contoso.test",
            "password": "longenough1", "confirm_password": "longenough1",
        })
        code = get_otp_code("pat@contoso.test")
        client.post("/register/verify-email", data={"action": "verify", "code": code})

        resp = client.post("/register/ethics", data={"action": "accept"}, follow_redirects=True)
        check("Accepting redirects somewhere successfully", resp.status_code == 200)
        check("Welcome message shown", b"Welcome" in resp.data)
        check("Lands on the employee-upload page next", b"csv" in resp.data.lower())

        with client.session_transaction() as sess:
            check("New admin is logged in immediately", sess.get("role") == "admin")
            check("New admin is a CORE admin (department is None)", sess.get("department") is None)
            check("Pending registration cleared after acceptance", "pending_registration" not in sess)
            check("Email-verified flag cleared after acceptance",
                  "pending_registration_email_verified" not in sess)

    db = database.get_db()
    org = db.execute("SELECT * FROM organizations WHERE name = 'Contoso Ltd'").fetchone()
    check("Organization row created", org is not None)
    check("ethics_accepted_at is set", org is not None and org["ethics_accepted_at"] is not None)

    user = db.execute("SELECT * FROM users WHERE email = 'pat@contoso.test'").fetchone()
    check("Core admin user row created", user is not None)
    check("Created user has role=admin, department=NULL",
          user is not None and user["role"] == "admin" and user["department"] is None)

    audit_row = db.execute(
        "SELECT * FROM audit_log WHERE action = 'organization_registered' AND org_id = ?",
        (org["id"],),
    ).fetchone()
    check("organization_registered audit entry logged", audit_row is not None)
    db.close()

    # The new admin can actually log in normally afterwards too.
    with app.test_client() as client:
        resp = client.post("/login", data={"email": "pat@contoso.test", "password": "longenough1"},
                            follow_redirects=True)
        check("Newly registered admin can log in with their chosen password",
              b"Admin Dashboard" in resp.data)

    # ---- 7: duplicate org name / email rejected before any OTP is sent ----
    with app.test_client() as client:
        resp = client.post("/register", data={
            "org_name": "Contoso Ltd", "full_name": "Someone Else", "email": "someone@else.test",
            "password": "longenough1", "confirm_password": "longenough1",
        }, follow_redirects=True)
        check("Duplicate organization name rejected", b"already registered" in resp.data)
        check("No OTP emailed for a rejected duplicate-org submission",
              get_otp_code("someone@else.test") is None)

        resp = client.post("/register", data={
            "org_name": "Another New Co", "full_name": "Someone Else", "email": "pat@contoso.test",
            "password": "longenough1", "confirm_password": "longenough1",
        }, follow_redirects=True)
        check("Duplicate email rejected", b"already in use" in resp.data)

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All registration/ethics-declaration checks passed.")


if __name__ == "__main__":
    main()
    os.unlink(tmp_db.name)
