"""
migrate_add_org_suspended.py
-----------------------------
One-time migration for existing installations: adds a `suspended` column to
`organizations` (0 = active, 1 = suspended by the platform engineer), used
by the engineer dashboard's billing/abuse-monitoring view and the new
suspend/reactivate control.

Safe to run more than once — checks for the column before adding it.
Existing rows get 0 (active), which is the correct default.

Run once, before using the new engineer-dashboard code:
    python migrate_add_org_suspended.py
"""

from database import get_db


def _column_exists(db, table, column):
    rows = db.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


def migrate():
    db = get_db()
    try:
        if not _column_exists(db, "organizations", "suspended"):
            db.execute("ALTER TABLE organizations ADD COLUMN suspended INTEGER NOT NULL DEFAULT 0")
            db.commit()
            print("Added organizations.suspended — migration complete.")
        else:
            print("organizations.suspended already exists — nothing to do.")
    finally:
        db.close()


if __name__ == "__main__":
    migrate()
