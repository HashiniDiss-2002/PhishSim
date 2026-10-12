"""
migrate_add_logo_and_password_reset.py
------------------------------------------
One-time migration for existing installations: adds the two pieces behind
real logo upload and the core-admin-triggered password reset flow:
  - organizations.logo_path: relative path to an uploaded logo image, set
    via admin.upload_logo(). NULL means branding.py falls back to its
    generated placeholder banner, exactly as before this feature existed.
  - password_reset_tokens: single-use, expiring tokens for
    auth.py's reset_password() route. See that table's comment in
    schema.sql for the "core admin never sets the password" design note.

Safe to run more than once — column add is guarded, table creation uses
CREATE TABLE IF NOT EXISTS.

Run once:
    python migrate_add_logo_and_password_reset.py
"""

from database import get_db

PASSWORD_RESET_TOKENS_DDL = """
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    requested_by INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    used_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (requested_by) REFERENCES users(id)
);
"""


def _column_exists(db, table, column):
    rows = db.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


def migrate():
    db = get_db()
    try:
        if not _column_exists(db, "organizations", "logo_path"):
            db.execute("ALTER TABLE organizations ADD COLUMN logo_path TEXT")
            db.commit()
            print("Added organizations.logo_path.")
        else:
            print("organizations.logo_path already exists — nothing to do.")

        db.executescript(PASSWORD_RESET_TOKENS_DDL)
        db.commit()
        print("password_reset_tokens table is present — migration complete.")
    finally:
        db.close()


if __name__ == "__main__":
    migrate()
