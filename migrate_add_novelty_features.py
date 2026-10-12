"""
migrate_add_novelty_features.py
------------------------------------
One-time migration for existing installations: adds the four novelty-angle
features intended to demonstrate a genuine research contribution beyond
"an LLM writes emails" —
  - campaign_emails.persuasion_principle / difficulty_level: drive the
    susceptibility-profiling and adaptive-difficulty features.
  - campaigns.vector: 'email_link' (original) or 'callback_toad'
    (callback phishing / TOAD simulation).
  - interactions.dwell_ms + a widened event_type CHECK (adds 'called'):
    drives the click-timing behavioural signal and TOAD tracking.

SQLite cannot widen a CHECK constraint with a plain ALTER TABLE, so the
interactions table is rebuilt using the standard 12-step SQLite pattern
(create replacement table, copy rows, drop original, rename) — this is
the one part of this migration that is NOT a simple guarded ADD COLUMN,
and it is wrapped in its own transaction with foreign keys off, exactly
as SQLite's own documentation prescribes for this situation.

Safe to run more than once — every step is guarded.

Run once:
    python migrate_add_novelty_features.py
"""

from database import get_db


def _column_exists(db, table, column):
    rows = db.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


def _interactions_allows_called(db):
    """
    True once the interactions table's event_type CHECK already allows
    'called' — detected by trying to find 'called' in the table's own
    CREATE TABLE SQL (sqlite_master), rather than trying an INSERT and
    catching the error, which would leave a (rolled-back) write attempt
    in the journal for no reason.
    """
    row = db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='interactions'"
    ).fetchone()
    return row is not None and "'called'" in row["sql"]


def migrate():
    db = get_db()
    try:
        # ---- campaign_emails: two simple guarded ADD COLUMNs ----
        if not _column_exists(db, "campaign_emails", "persuasion_principle"):
            db.execute("ALTER TABLE campaign_emails ADD COLUMN persuasion_principle TEXT")
            db.commit()
            print("Added campaign_emails.persuasion_principle.")
        else:
            print("campaign_emails.persuasion_principle already exists — nothing to do.")

        if not _column_exists(db, "campaign_emails", "difficulty_level"):
            db.execute(
                "ALTER TABLE campaign_emails ADD COLUMN difficulty_level TEXT NOT NULL DEFAULT 'standard'"
            )
            db.commit()
            print("Added campaign_emails.difficulty_level.")
        else:
            print("campaign_emails.difficulty_level already exists — nothing to do.")

        # ---- campaigns: one simple guarded ADD COLUMN ----
        if not _column_exists(db, "campaigns", "vector"):
            db.execute(
                "ALTER TABLE campaigns ADD COLUMN vector TEXT NOT NULL DEFAULT 'email_link'"
            )
            db.commit()
            print("Added campaigns.vector.")
        else:
            print("campaigns.vector already exists — nothing to do.")

        # ---- interactions.dwell_ms: simple guarded ADD COLUMN ----
        if not _column_exists(db, "interactions", "dwell_ms"):
            db.execute("ALTER TABLE interactions ADD COLUMN dwell_ms INTEGER")
            db.commit()
            print("Added interactions.dwell_ms.")
        else:
            print("interactions.dwell_ms already exists — nothing to do.")

        # ---- interactions.event_type CHECK: needs a table rebuild ----
        if _interactions_allows_called(db):
            print("interactions.event_type already allows 'called' — nothing to do.")
        else:
            db.execute("PRAGMA foreign_keys=off")
            db.execute("BEGIN TRANSACTION")
            try:
                db.execute("""
                    CREATE TABLE interactions_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        campaign_email_id INTEGER NOT NULL,
                        event_type TEXT NOT NULL CHECK (event_type IN
                            ('open', 'click', 'submit', 'download', 'report', 'called')),
                        dwell_ms INTEGER,
                        occurred_at TEXT NOT NULL DEFAULT (datetime('now')),
                        FOREIGN KEY (campaign_email_id) REFERENCES campaign_emails(id)
                    )
                """)
                db.execute("""
                    INSERT INTO interactions_new
                        (id, campaign_email_id, event_type, dwell_ms, occurred_at)
                    SELECT id, campaign_email_id, event_type, dwell_ms, occurred_at
                    FROM interactions
                """)
                db.execute("DROP TABLE interactions")
                db.execute("ALTER TABLE interactions_new RENAME TO interactions")
                db.execute("COMMIT")
                print("Rebuilt interactions table — event_type now allows 'called'.")
            except Exception:
                db.execute("ROLLBACK")
                raise
            finally:
                db.execute("PRAGMA foreign_keys=on")
    finally:
        db.close()


if __name__ == "__main__":
    migrate()
