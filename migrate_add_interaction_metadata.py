"""
migrate_add_interaction_metadata.py
------------------------------------
One-time migration for existing installations: adds `ip_address` and
`user_agent` (both nullable TEXT) columns to `interactions`, so every
tracked event (open/click/submit/download/report/called) can record the
requesting browser's IP address and User-Agent string alongside its
existing timestamp — see tracking.py's _log_event() and the new
admin.interaction_timeline route / templates/interaction_timeline.html.

Existing interaction rows get NULL for both new columns, which is exactly
right: that metadata was genuinely never captured for them, so showing
"not recorded" is honest where a backfilled guess would not be.

Safe to run more than once — it checks for each column before adding it.

Run once, before using the new interaction-timeline feature:
    python migrate_add_interaction_metadata.py
"""

from database import get_db


def _column_exists(db, table, column):
    rows = db.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


def migrate():
    db = get_db()
    try:
        changed = False

        if not _column_exists(db, "interactions", "ip_address"):
            db.execute("ALTER TABLE interactions ADD COLUMN ip_address TEXT")
            print("Added interactions.ip_address")
            changed = True
        else:
            print("interactions.ip_address already exists — skipped")

        if not _column_exists(db, "interactions", "user_agent"):
            db.execute("ALTER TABLE interactions ADD COLUMN user_agent TEXT")
            print("Added interactions.user_agent")
            changed = True
        else:
            print("interactions.user_agent already exists — skipped")

        db.commit()
        if changed:
            print("Migration complete. Existing rows have NULL ip_address/user_agent "
                  "(never captured) -- only new events going forward will record them.")
        else:
            print("Nothing to do — database was already migrated.")
    finally:
        db.close()


if __name__ == "__main__":
    migrate()
