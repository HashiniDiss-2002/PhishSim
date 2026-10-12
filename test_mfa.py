"""
test_mfa.py
-----------
Verifies mandatory TOTP-based MFA on admin/engineer login (auth.py's
login(), mfa_setup(), mfa_verify(), backed by services/totp.py).

Unlike every other test_*.py here, this file deliberately does NOT set
PHISHSIM_DISABLE_MFA_FOR_TESTS — it exists specifically to exercise the
real, enforced MFA flow end to end, using services/totp.py's own
current_code() to generate valid codes exactly as a real authenticator
app would from the same secret.

Covers:
  1. A correct password alone does NOT grant a session — it only stages
     "pending_mfa_user_id" and redirects to /mfa/setup for an account that
     has never completed MFA enrollment (mfa_enabled = 0, true for every
     account straight out of migrate_add_mfa.py / seed_demo_data.py).
  2. /mfa/setup shows a QR code (the otpauth:// URI) and a manual-entry
     secret fallback; submitting a WRONG code does not enable MFA and does
     not grant a session.
  3. Submitting the CORRECT current code for the shown secret enables MFA
     (mfa_secret/mfa_enabled committed to the DB), grants a full session,
     and logs an mfa_enabled audit entry.
  4. Logging out and back in with the same account now goes to /mfa/verify
     instead of /mfa/setup (mfa_enabled = 1), and a wrong code there is
     rejected without granting a session.
  5. The correct current code at /mfa/verify grants a session and reaches
     the dashboard.
  6. Visiting /mfa/setup or /mfa/verify directly, with no prior correct
     password (no "pending_mfa_user_id" in session), bounces to /login
     rather than leaking any MFA state.
  7. services/totp.py's TOTP implementation matches the RFC 6238 Appendix
     B SHA1 test vector exactly — i.e. this is a standards-correct
     implementation, not just internally self-consistent.

Run with:  python test_mfa.py
Exits non-zero (and prints which assertion failed) on any failure.
"""

import base64
import os
import re
import sys
import tempfile

# Force mock mode regardless of the real environment this happens to run in.
for var in ("GROQ_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
            "SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD"):
    os.environ.pop(var, None)
# Intentionally NOT setting PHISHSIM_DISABLE_MFA_FOR_TESTS here — this file
# is the one that must exercise the real MFA gate.
os.environ.pop("PHISHSIM_DISABLE_MFA_FOR_TESTS", None)

tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
tmp_db.close()

import database
database.DB_PATH = __import__("pathlib").Path(tmp_db.name)

from werkzeug.security import generate_password_hash

from app import create_app
from services import totp as totp_service

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
        (org_id, "mfa.admin@sampath.test", generate_password_hash("password123"), "MFA Admin"),
    )
    db.commit()
    db.close()


def extract_secret_and_uri(html_bytes):
    html = html_bytes.decode("utf-8")
    secret_match = re.search(r'<div class="value">([A-Z2-7]+)</div>', html)
    uri_match = re.search(r'data=([^"&]+(?:&amp;[^"&]+)*)"', html)
    secret = secret_match.group(1) if secret_match else None
    return secret, uri_match.group(1) if uri_match else None


def main():
    setup_data()
    app = create_app()
    app.config["TESTING"] = True

    # ---- 7: RFC 6238 Appendix B SHA1 test vector ----
    rfc_secret_b32 = base64.b32encode(b"12345678901234567890").decode()
    code_at_59s = totp_service._hotp(rfc_secret_b32, int(59 // 30))
    check("services/totp.py matches RFC 6238 Appendix B SHA1 test vector (T=59s -> 287082)",
          code_at_59s == "287082")

    # ---- 1: password alone does not grant a session ----
    with app.test_client() as client:
        resp = client.post("/login", data={"email": "mfa.admin@sampath.test", "password": "password123"})
        check("Correct password redirects to /mfa/setup (first-time enrollment), not the dashboard",
              resp.status_code == 302 and "/mfa/setup" in resp.headers["Location"])

        with client.session_transaction() as sess:
            check("Session has pending_mfa_user_id, not user_id, after password-only login",
                  sess.get("pending_mfa_user_id") is not None and "user_id" not in sess)

        # ---- 2: setup page shows a QR code + manual secret; wrong code rejected ----
        resp = client.get("/mfa/setup")
        check("GET /mfa/setup renders OK", resp.status_code == 200)
        check("Setup page embeds a QR code image referencing the otpauth URI",
              b"qrserver.com" in resp.data and b"otpauth" in resp.data)

        secret, _ = extract_secret_and_uri(resp.data)
        check("Setup page shows the manual-entry secret as a fallback", bool(secret))

        resp = client.post("/mfa/setup", data={"code": "000000"}, follow_redirects=True)
        check("Wrong code at setup is rejected (stays on setup page with an error)",
              b"didn" in resp.data.lower() or b"match" in resp.data.lower())

        with client.session_transaction() as sess:
            check("Wrong code does not grant a session", "user_id" not in sess)

    db = database.get_db()
    row = db.execute("SELECT * FROM users WHERE email = 'mfa.admin@sampath.test'").fetchone()
    check("mfa_enabled is still 0 after a wrong setup code", row["mfa_enabled"] == 0)
    db.close()

    # ---- 3: correct code enables MFA and grants a session ----
    with app.test_client() as client:
        client.post("/login", data={"email": "mfa.admin@sampath.test", "password": "password123"})
        resp = client.get("/mfa/setup")
        secret, _ = extract_secret_and_uri(resp.data)

        correct_code = totp_service.current_code(secret)
        resp = client.post("/mfa/setup", data={"code": correct_code}, follow_redirects=True)
        check("Correct setup code reaches the admin dashboard", b"Admin Dashboard" in resp.data)

        with client.session_transaction() as sess:
            check("Correct setup code grants a full session", sess.get("role") == "admin")
            check("pending_mfa_user_id cleared after successful setup", "pending_mfa_user_id" not in sess)

    db = database.get_db()
    row = db.execute("SELECT * FROM users WHERE email = 'mfa.admin@sampath.test'").fetchone()
    check("mfa_enabled = 1 after successful setup", row["mfa_enabled"] == 1)
    check("mfa_secret stored matches the enrolled secret", row["mfa_secret"] == secret)
    audit_row = db.execute(
        "SELECT * FROM audit_log WHERE action = 'mfa_enabled' AND actor_user_id = ?", (row["id"],)
    ).fetchone()
    check("mfa_enabled audit entry logged", audit_row is not None)
    db.close()

    # ---- 4 & 5: subsequent login goes to /mfa/verify, wrong then right code ----
    with app.test_client() as client:
        resp = client.post("/login", data={"email": "mfa.admin@sampath.test", "password": "password123"})
        check("Second login (MFA already enabled) redirects to /mfa/verify, not /mfa/setup",
              resp.status_code == 302 and "/mfa/verify" in resp.headers["Location"])

        resp = client.post("/mfa/verify", data={"code": "000000"}, follow_redirects=True)
        check("Wrong code at verify is rejected", b"incorrect" in resp.data.lower())
        with client.session_transaction() as sess:
            check("Wrong verify code does not grant a session", "user_id" not in sess)

        correct_code = totp_service.current_code(secret)
        resp = client.post("/mfa/verify", data={"code": correct_code}, follow_redirects=True)
        check("Correct verify code reaches the admin dashboard", b"Admin Dashboard" in resp.data)
        with client.session_transaction() as sess:
            check("Correct verify code grants a full session", sess.get("role") == "admin")

    # ---- 6: /mfa/setup and /mfa/verify unreachable without a pending login ----
    with app.test_client() as client:
        resp = client.get("/mfa/setup", follow_redirects=True)
        check("GET /mfa/setup with no pending login bounces to /login",
              b"Sign in" in resp.data or b"Welcome back" in resp.data)
    with app.test_client() as client:
        resp = client.get("/mfa/verify", follow_redirects=True)
        check("GET /mfa/verify with no pending login bounces to /login",
              b"Sign in" in resp.data or b"Welcome back" in resp.data)

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All MFA checks passed.")


if __name__ == "__main__":
    main()
