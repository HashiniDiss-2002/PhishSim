"""
migrate_add_mfa.py
-------------------
One-time migration for existing installations: adds `mfa_secret` (nullable
TEXT, the base32 TOTP secret from services/totp.py) and `mfa_enabled`
(INTEGER, default 0) columns to `users`.

MFA is mandatory for every admin/engineer account in this MVP (there is no
opt-out and no "user"-role login in the MVP, so this only ever affects
admin/engineer rows in practice). `mfa_enabled = 0` on every existing row
after this migration is exactly the right default: it means "has not set
up MFA yet", which is what every pre-existing seeded/demo account is in
truth. auth.py's login() checks this flag and routes such an account to
/mfa/setup (first time) instead of straight into the dashboard — so
existing accounts (e.g. admin@acme.test) will be walked through MFA
enrollment the next time they log in, rather than being silently exempted.

Safe to run more than once — it checks for each column before adding it.

Run once, before using the new MFA code:
    python migrate_add_mfa.py
"""

from database import get_db


def _column_exists(db, table, column):
    rows = db.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


def migrate():
    db = get_db()
    try:
        changed = False

        if not _column_exists(db, "users", "mfa_secret"):
            db.execute("ALTER TABLE users ADD COLUMN mfa_secret TEXT")
            print("Added users.mfa_secret")
            changed = True
        else:
            print("users.mfa_secret already exists — skipped")

        if not _column_exists(db, "users", "mfa_enabled"):
            db.execute("ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0")
            print("Added users.mfa_enabled")
            changed = True
        else:
            print("users.mfa_enabled already exists — skipped")

        db.commit()
        if changed:
            print("Migration complete. Existing accounts have mfa_enabled = 0, so each "
                  "will be walked through MFA setup on its next login.")
        else:
            print("Nothing to do — database was already migrated.")
    finally:
        db.close()


if __name__ == "__main__":
    migrate()
