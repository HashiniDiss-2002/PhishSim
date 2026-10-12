"""
migrate_add_support_tickets.py
--------------------------------
One-time migration for existing installations: adds the `support_tickets`
table behind the admin "Contact Support" feature (admin.py:
contact_support() / support_inbox(), templates/support.html /
engineer_support.html) — a client admin's free-text support request to
the platform engineer, with the engineer able to see and respond to it.

See schema.sql's comment on this table for why it is deliberately a
separate, non-tenant-isolated channel from everything else the platform
engineer is normally walled off from.

Safe to run more than once — uses CREATE TABLE IF NOT EXISTS.

Run once:
    python migrate_add_support_tickets.py
"""

from database import get_db

DDL = """
CREATE TABLE IF NOT EXISTS support_tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    raised_by_user_id INTEGER NOT NULL,
    raised_by_name TEXT NOT NULL,
    raised_by_role TEXT NOT NULL,
    org_name TEXT NOT NULL,
    subject TEXT NOT NULL,
    message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    engineer_response TEXT,
    responded_by_name TEXT,
    responded_at TEXT,
    FOREIGN KEY (org_id) REFERENCES organizations(id),
    FOREIGN KEY (raised_by_user_id) REFERENCES users(id)
);
"""


def migrate():
    db = get_db()
    try:
        db.executescript(DDL)
        db.commit()
        print("support_tickets table is present — migration complete.")
    finally:
        db.close()


if __name__ == "__main__":
    migrate()
