"""
migrate_add_stage2_reference.py
---------------------------------
One-time migration for existing installations: adds a `stage2_reference`
column to `campaigns` — a nullable text field holding a researcher-written
summary of a real, publicly reported phishing campaign's STRUCTURAL
features (pretext category, urgency/authority framing, delivery vector),
used to inform generation for the Stage 2 proof-of-concept. NULL means an
ordinary Stage 1 campaign, unaffected by this feature.

See services/pretext_generator.py and methodology 3.2.4 for why this is
never the real campaign's literal content, domains, or links — only an
abstracted structural summary.

Safe to run more than once — checks for the column before adding it.

Run once, before using the Stage 2 field on campaign creation:
    python migrate_add_stage2_reference.py
"""

from database import get_db


def _column_exists(db, table, column):
    rows = db.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


def migrate():
    db = get_db()
    try:
        changed = False
        if not _column_exists(db, "campaigns", "stage2_reference"):
            db.execute("ALTER TABLE campaigns ADD COLUMN stage2_reference TEXT")
            print("Added campaigns.stage2_reference")
            changed = True
        else:
            print("campaigns.stage2_reference already exists — skipped")

        if not _column_exists(db, "campaigns", "stage2_source_url"):
            db.execute("ALTER TABLE campaigns ADD COLUMN stage2_source_url TEXT")
            print("Added campaigns.stage2_source_url")
            changed = True
        else:
            print("campaigns.stage2_source_url already exists — skipped")

        db.commit()
        print("Migration complete." if changed else "Nothing to do — already migrated.")
    finally:
        db.close()


if __name__ == "__main__":
    migrate()
