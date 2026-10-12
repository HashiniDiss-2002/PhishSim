"""
migrate_add_threat_trend_tags.py
-----------------------------------
One-time migration for existing installations: adds
threat_intel_scenarios.delivery_channel and .pretext_category_tag — a
second, fixed-vocabulary classification of each discovered article,
alongside the existing free-text 'summary' (see services/threat_intel.py's
DELIVERY_CHANNELS / PRETEXT_CATEGORY_TAGS and services/threat_trends.py,
which groups/counts by these two columns to answer "what's trending
across our sources right now").

Both are simple guarded ADD COLUMNs with no CHECK constraint (the
application layer already falls back to 'other' for any value outside
the fixed vocabulary — see extract_structural_features() — so there's
nothing here that needs a table rebuild, unlike the vector/event_type
CHECK-widening migrations elsewhere in this project).

Safe to run more than once — every step is guarded.

Run once:
    python migrate_add_threat_trend_tags.py
"""

from database import get_db


def _column_exists(db, table, column):
    rows = db.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


def migrate():
    db = get_db()
    try:
        if not _column_exists(db, "threat_intel_scenarios", "delivery_channel"):
            db.execute("ALTER TABLE threat_intel_scenarios ADD COLUMN delivery_channel TEXT")
            db.commit()
            print("Added threat_intel_scenarios.delivery_channel.")
        else:
            print("threat_intel_scenarios.delivery_channel already exists — nothing to do.")

        if not _column_exists(db, "threat_intel_scenarios", "pretext_category_tag"):
            db.execute("ALTER TABLE threat_intel_scenarios ADD COLUMN pretext_category_tag TEXT")
            db.commit()
            print("Added threat_intel_scenarios.pretext_category_tag.")
        else:
            print("threat_intel_scenarios.pretext_category_tag already exists — nothing to do.")
    finally:
        db.close()


if __name__ == "__main__":
    migrate()
