"""
migrate_add_attack_spoofing_bitb.py
---------------------------------------
One-time migration for existing installations: adds the three new
cybersecurity-technique features requested after panel feedback that the
project leaned too heavily on "AI" and not enough on demonstrable
security engineering —
  - campaign_emails.has_attachment: drives MITRE ATT&CK technique tagging
    (services/attack_mapping.py).
  - campaigns.spoofed_sender_name / spoofed_domain / spoofed_address:
    drives the sender/domain spoofing simulation (services/domain_spoofing.py).
  - campaigns.fake_login_style: 'standard' or 'bitb' (Browser-in-the-Browser),
    chosen at campaign creation (templates/create_campaign.html).

Safe to run more than once — every column add is guarded.

Run once:
    python migrate_add_attack_spoofing_bitb.py
"""

from database import get_db


def _column_exists(db, table, column):
    rows = db.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


def migrate():
    db = get_db()
    try:
        if not _column_exists(db, "campaign_emails", "has_attachment"):
            db.execute(
                "ALTER TABLE campaign_emails ADD COLUMN has_attachment INTEGER NOT NULL DEFAULT 0"
            )
            db.commit()
            print("Added campaign_emails.has_attachment.")
        else:
            print("campaign_emails.has_attachment already exists — nothing to do.")

        for column, ddl in [
            ("spoofed_sender_name", "ALTER TABLE campaigns ADD COLUMN spoofed_sender_name TEXT"),
            ("spoofed_domain", "ALTER TABLE campaigns ADD COLUMN spoofed_domain TEXT"),
            ("spoofed_address", "ALTER TABLE campaigns ADD COLUMN spoofed_address TEXT"),
        ]:
            if not _column_exists(db, "campaigns", column):
                db.execute(ddl)
                db.commit()
                print(f"Added campaigns.{column}.")
            else:
                print(f"campaigns.{column} already exists — nothing to do.")

        # SQLite's ALTER TABLE ADD COLUMN cannot attach a CHECK constraint,
        # so the default here matches schema.sql's default ('standard')
        # without the CHECK — acceptable for an existing-install migration,
        # since the app itself only ever writes 'standard' or 'bitb'.
        if not _column_exists(db, "campaigns", "fake_login_style"):
            db.execute(
                "ALTER TABLE campaigns ADD COLUMN fake_login_style TEXT NOT NULL DEFAULT 'standard'"
            )
            db.commit()
            print("Added campaigns.fake_login_style.")
        else:
            print("campaigns.fake_login_style already exists — nothing to do.")
    finally:
        db.close()


if __name__ == "__main__":
    migrate()
