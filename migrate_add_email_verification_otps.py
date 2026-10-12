"""
migrate_add_email_verification_otps.py
----------------------------------------
One-time migration for existing installations: adds the
`email_verification_otps` table behind the self-registration email-OTP
verification step (auth.py: register() / register_verify_email() /
register_ethics(), templates/verify_email.html) -- a registrant must
enter a code emailed to them before their organization/admin account is
actually created.

See schema.sql's comment on this table for why it's keyed by email
rather than user_id, and why only a hash of the code is ever stored.

Safe to run more than once -- uses CREATE TABLE IF NOT EXISTS.

Run once:
    python migrate_add_email_verification_otps.py
"""

from database import get_db

DDL = """
CREATE TABLE IF NOT EXISTS email_verification_otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    otp_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    verified_at TEXT
);
"""


def migrate():
    db = get_db()
    try:
        db.executescript(DDL)
        db.commit()
        print("email_verification_otps table is present — migration complete.")
    finally:
        db.close()


if __name__ == "__main__":
    migrate()
