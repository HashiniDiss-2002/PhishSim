"""
test_email_otp_verification.py
---------------------------------
Fine-grained coverage of the self-registration email-OTP verification
step (auth.py: register_verify_email(), _generate_and_send_otp()),
added so a new registrant must prove they control the email address
they signed up with before PhishSim creates their organization/admin
account.

Covers:
  1. A wrong code is rejected, increments attempts, and does NOT advance
     past verification.
  2. A correct code advances to /register/ethics and marks the session
     as email-verified.
  3. Hitting /register/ethics directly (skipping verify-email) bounces
     back to /register/verify-email, even with a valid pending
     registration in session — i.e. a password alone is never enough to
     reach account creation.
  4. An expired code is rejected even though it's the right code.
  5. Too many wrong attempts on one code locks it out (further guesses
     — even the correct one — are rejected) until a new code is sent.
  6. "Resend" emails a brand-new code and invalidates guessing against
     the stale one's row by issuing a fresh row to check against.
  7. /register/verify-email with no pending registration at all bounces
     to /register.
  8. Sending rate limit: at most 3 codes (the initial send plus two
     resends) go out to one email address within 24 hours; a 4th
     "resend" attempt is blocked with a "try again in 24 hours" message
     and does NOT email another code. The same limit also blocks a
     brand-new /register submission for an email address that has
     already hit it.

Uses mock mode and a scratch DB, same pattern as the other test_*.py
files in this project. Directly manipulates email_verification_otps
rows (expires_at, attempts) via raw SQL where the real flow would
otherwise require waiting out a real clock or guessing 5 times by hand
— the project's existing tests for time-based features (e.g.
password_reset_tokens expiry) use the same approach.
"""

import os
import re
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

from app import create_app
from services.mailer import OUTBOX_DIR

failures = []


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}")
    if not condition:
        failures.append(label)


def get_otp_code(email):
    safe_name = email.replace("@", "_at_").replace(".", "_")
    path = OUTBOX_DIR / f"{safe_name}.html"
    if not path.exists():
        return None
    content = path.read_text(encoding="utf-8")
    m = re.search(r"OTP_CODE:(\d{6})", content)
    return m.group(1) if m else None


def register(client, org_name, full_name, email):
    return client.post("/register", data={
        "org_name": org_name, "full_name": full_name, "email": email,
        "password": "longenough1", "confirm_password": "longenough1",
    })


def main():
    database.init_db()
    app = create_app()
    app.config["TESTING"] = True

    # ---- 1: wrong code rejected, increments attempts, doesn't advance ----
    with app.test_client() as client:
        register(client, "Umbra Inc", "Uma Admin", "uma@umbra.test")
        resp = client.post("/register/verify-email", data={"action": "verify", "code": "000000"},
                            follow_redirects=True)
        check("Wrong code shows an error, not the ethics page",
              b"Incorrect code" in resp.data)
        check("Wrong code keeps us on the verify-email page, not ethics",
              b"Verification code" in resp.data or b"verify" in resp.data.lower())

        with client.session_transaction() as sess:
            check("Email NOT marked verified after a wrong code",
                  not sess.get("pending_registration_email_verified"))

    db = database.get_db()
    row = db.execute(
        "SELECT * FROM email_verification_otps WHERE email = 'uma@umbra.test' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    check("Wrong-code attempt is recorded on the OTP row", row is not None and row["attempts"] == 1)
    db.close()

    # ---- 2: correct code advances to ethics and marks session verified ----
    with app.test_client() as client:
        register(client, "Zenith Co", "Zoe Admin", "zoe@zenith.test")
        code = get_otp_code("zoe@zenith.test")
        check("A code was emailed", code is not None)

        resp = client.post("/register/verify-email", data={"action": "verify", "code": code})
        check("Correct code redirects to /register/ethics",
              resp.status_code == 302 and "/register/ethics" in resp.headers["Location"])

        with client.session_transaction() as sess:
            check("Session marked email-verified after correct code",
                  sess.get("pending_registration_email_verified") is True)

        resp = client.get("/register/ethics")
        check("Ethics page now actually renders (not bounced)", resp.status_code == 200)

    db = database.get_db()
    verified_row = db.execute(
        "SELECT * FROM email_verification_otps WHERE email = 'zoe@zenith.test'"
    ).fetchone()
    check("OTP row marked verified_at", verified_row is not None and verified_row["verified_at"] is not None)
    db.close()

    # ---- 3: /register/ethics directly (skipping verify-email) bounces back ----
    with app.test_client() as client:
        register(client, "Skipper LLC", "Sam Skip", "sam@skipper.test")
        with client.session_transaction() as sess:
            check("Pending registration is present (password step already done)",
                  sess.get("pending_registration") is not None)
            check("But email is NOT yet verified", not sess.get("pending_registration_email_verified"))

        resp = client.get("/register/ethics", follow_redirects=True)
        check("Visiting /register/ethics without verifying email bounces to verify-email page",
              b"Verification code" in resp.data or b"verify" in resp.data.lower())

        resp_noredirect = client.get("/register/ethics")
        check("The bounce is a real redirect to /register/verify-email",
              resp_noredirect.status_code == 302 and "/register/verify-email" in resp_noredirect.headers["Location"])

    # ---- 4: expired code rejected even if correct ----
    with app.test_client() as client:
        register(client, "Old Code Co", "Ollie Admin", "ollie@oldcode.test")
        code = get_otp_code("ollie@oldcode.test")

        # Force-expire the row that was just created, then verify with the
        # SAME client (same session, same pending_registration) so this
        # exercises an expired code rather than accidentally creating a
        # second, still-valid OTP row for the same email.
        db = database.get_db()
        db.execute(
            "UPDATE email_verification_otps SET expires_at = datetime('now', '-1 minutes') "
            "WHERE email = 'ollie@oldcode.test'"
        )
        db.commit()
        db.close()

        resp = client.post("/register/verify-email", data={"action": "verify", "code": code},
                            follow_redirects=True)
        check("Expired code is rejected even though it's the right code",
              b"expired" in resp.data.lower())

    # ---- 5: too many wrong attempts locks the code out ----
    with app.test_client() as client:
        register(client, "Locked Out Ltd", "Lex Admin", "lex@lockedout.test")
        code = get_otp_code("lex@lockedout.test")

        for _ in range(5):
            client.post("/register/verify-email", data={"action": "verify", "code": "999999"})

        resp = client.post("/register/verify-email", data={"action": "verify", "code": code},
                            follow_redirects=True)
        check("Even the CORRECT code is rejected after too many wrong attempts",
              b"too many" in resp.data.lower())

    # ---- 6: resend emails a new code; the new code works ----
    with app.test_client() as client:
        register(client, "Fresh Start Inc", "Fiona Admin", "fiona@freshstart.test")
        old_code = get_otp_code("fiona@freshstart.test")

        resp = client.post("/register/verify-email", data={"action": "resend"}, follow_redirects=True)
        check("Resend redirects back to the verify-email page with a success message",
              b"new verification code" in resp.data.lower())

        new_code = get_otp_code("fiona@freshstart.test")
        check("Resend actually emailed a (likely different) code", new_code is not None)

        resp = client.post("/register/verify-email", data={"action": "verify", "code": new_code})
        check("The freshly resent code is accepted",
              resp.status_code == 302 and "/register/ethics" in resp.headers["Location"])

    # ---- 7: no pending registration at all bounces to /register ----
    with app.test_client() as client:
        resp = client.get("/register/verify-email", follow_redirects=True)
        check("GET /register/verify-email with nothing pending bounces to /register",
              b"org_name" in resp.data or b"Organization name" in resp.data)

    # ---- 8: send-rate limit — 3 per email per 24h, then blocked ----
    with app.test_client() as client:
        # Send #1: the initial send from register() itself.
        register(client, "Ratelimited Co", "Rae Admin", "rae@ratelimited.test")
        check("Send #1 (initial) actually emailed a code",
              get_otp_code("rae@ratelimited.test") is not None)

        # Send #2 and #3: two resends, both should still go through. All
        # four sends below stay within this ONE client/session — calling
        # register() again partway through would itself immediately hit
        # the same limit (see the separate check further down) rather
        # than exercising the "resend" path specifically.
        resp = client.post("/register/verify-email", data={"action": "resend"}, follow_redirects=True)
        check("Send #2 (first resend) succeeds",
              b"new verification code" in resp.data.lower())
        resp = client.post("/register/verify-email", data={"action": "resend"}, follow_redirects=True)
        check("Send #3 (second resend) succeeds",
              b"new verification code" in resp.data.lower())

        db = database.get_db()
        sent_count = db.execute(
            "SELECT COUNT(*) AS c FROM email_verification_otps WHERE email = 'rae@ratelimited.test'"
        ).fetchone()["c"]
        check("Exactly 3 OTP rows exist for this email after 3 sends", sent_count == 3)
        db.close()

        # Send #4 (a resend, the 4th send overall) must be blocked.
        before_mtime = (OUTBOX_DIR / "rae_at_ratelimited_test.html").stat().st_mtime
        resp = client.post("/register/verify-email", data={"action": "resend"}, follow_redirects=True)
        check("4th send is blocked with a 'try again' message",
              b"try again" in resp.data.lower() and b"24 hours" in resp.data)
        after_mtime = (OUTBOX_DIR / "rae_at_ratelimited_test.html").stat().st_mtime
        check("Blocked send did NOT actually email another code (outbox file untouched)",
              before_mtime == after_mtime)

    db = database.get_db()
    sent_count = db.execute(
        "SELECT COUNT(*) AS c FROM email_verification_otps WHERE email = 'rae@ratelimited.test'"
    ).fetchone()["c"]
    check("Still exactly 3 OTP rows after the blocked 4th send attempt", sent_count == 3)
    db.close()

    # A brand-new /register submission for the same already-limited email
    # is blocked too (register() itself hits the same per-email cap),
    # before anything is staged in the session.
    with app.test_client() as client:
        resp = client.post("/register", data={
            "org_name": "Ratelimited Retry Co", "full_name": "Rae Admin", "email": "rae@ratelimited.test",
            "password": "longenough1", "confirm_password": "longenough1",
        }, follow_redirects=True)
        check("A fresh /register submission for an already-limited email is also blocked",
              b"try again" in resp.data.lower() and b"24 hours" in resp.data)

        with client.session_transaction() as sess:
            check("Nothing is staged in session when the rate limit blocks registration",
                  "pending_registration" not in sess)

    db = database.get_db()
    check("Blocked re-registration created no organization row",
          db.execute(
              "SELECT 1 FROM organizations WHERE name = 'Ratelimited Retry Co'"
          ).fetchone() is None)
    db.close()

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All email-OTP-verification checks passed.")


if __name__ == "__main__":
    main()
    os.unlink(tmp_db.name)
