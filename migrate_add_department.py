"""
migrate_add_department.py
--------------------------
One-time migration for existing installations: adds a nullable `department`
column to `users` (so an admin account can optionally be scoped to one
department — NULL means "core admin", a value means "department admin") and
to `campaigns` (so a campaign created by a department admin is tagged with
that department; NULL means an org-wide campaign created by a core admin).

Safe to run more than once — it checks for the column before adding it, so
re-running it on an already-migrated database is a no-op rather than an
error. Existing rows get NULL for the new column, which is exactly the
"core admin" / "org-wide campaign" default we want for data that pre-dates
this feature.

Run once, before using the new department-admin code:
    python migrate_add_department.py
"""

from database import get_db


def _column_exists(db, table, column):
    rows = db.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


def migrate():
    db = get_db()
    try:
        changed = False

        if not _column_exists(db, "users", "department"):
            db.execute("ALTER TABLE users ADD COLUMN department TEXT")
            print("Added users.department")
            changed = True
        else:
            print("users.department already exists — skipped")

        if not _column_exists(db, "campaigns", "department"):
            db.execute("ALTER TABLE campaigns ADD COLUMN department TEXT")
            print("Added campaigns.department")
            changed = True
        else:
            print("campaigns.department already exists — skipped")

        db.commit()
        if changed:
            print("Migration complete.")
        else:
            print("Nothing to do — database was already migrated.")
    finally:
        db.close()


if __name__ == "__main__":
    migrate()
