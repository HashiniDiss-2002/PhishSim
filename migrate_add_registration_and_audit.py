"""
migrate_add_registration_and_audit.py
----------------------------------------
One-time migration for existing installations: adds the two pieces behind
self-service organization registration and the admin-facing audit trail:
  - organizations.ethics_accepted_at: timestamp the registering admin
    accepted the Responsible Use declaration (see auth.py's
    register()/register_ethics()). Existing rows (e.g. seeded demo data)
    get NULL, which is expected — they predate this flow.
  - audit_log: a new table recording admin/engineer actions (campaign
    created/sent/deleted, employees uploaded, department-admin created,
    organization suspended/reactivated/registered). See services/audit.py.

Safe to run more than once — column add is guarded, table creation uses
CREATE TABLE IF NOT EXISTS.

Run once:
    python migrate_add_registration_and_audit.py
"""

from database import get_db

AUDIT_LOG_DDL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER,
    actor_user_id INTEGER,
    actor_role TEXT,
    actor_name TEXT,
    action TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (org_id) REFERENCES organizations(id),
    FOREIGN KEY (actor_user_id) REFERENCES users(id)
);
"""


def _column_exists(db, table, column):
    rows = db.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


def migrate():
    db = get_db()
    try:
        if not _column_exists(db, "organizations", "ethics_accepted_at"):
            db.execute("ALTER TABLE organizations ADD COLUMN ethics_accepted_at TEXT")
            db.commit()
            print("Added organizations.ethics_accepted_at.")
        else:
            print("organizations.ethics_accepted_at already exists — nothing to do.")

        db.executescript(AUDIT_LOG_DDL)
        db.commit()
        print("audit_log table is present — migration complete.")
    finally:
        db.close()


if __name__ == "__main__":
    migrate()
