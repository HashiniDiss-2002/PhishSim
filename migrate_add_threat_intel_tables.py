"""
migrate_add_threat_intel_tables.py
-------------------------------------
One-time migration for existing installations: adds the two tables behind
automated Stage 2 discovery:
  - threat_intel_sources: trusted CTI listing/category/RSS pages the
    platform ENGINEER curates.
  - threat_intel_scenarios: real-world phishing campaigns the system
    discovered and extracted structural features from automatically.

See services/threat_source_crawler.py and services/threat_intel.py.

Safe to run more than once — uses CREATE TABLE IF NOT EXISTS.

Run once:
    python migrate_add_threat_intel_tables.py
"""

from database import get_db

DDL = """
CREATE TABLE IF NOT EXISTS threat_intel_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    label TEXT,
    added_by INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (added_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS threat_intel_scenarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER,
    article_url TEXT NOT NULL UNIQUE,
    article_title TEXT,
    summary TEXT NOT NULL,
    discovered_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (source_id) REFERENCES threat_intel_sources(id) ON DELETE SET NULL
);
"""


def migrate():
    db = get_db()
    try:
        db.executescript(DDL)
        db.commit()
        print("threat_intel_sources / threat_intel_scenarios tables are present — migration complete.")
    finally:
        db.close()


if __name__ == "__main__":
    migrate()
