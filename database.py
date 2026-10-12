"""
database.py
-----------
Small helper module that manages the SQLite connection for the app.

Why raw sqlite3 instead of an ORM (e.g. SQLAlchemy)?
This project intentionally avoids extra dependencies so it is easy to install
and easy to explain in a viva: every query is plain, readable SQL in this file
or in the blueprint that uses it. That is a deliberate scoping decision for a
final-year MVP, not an oversight.
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "instance" / "phishsim.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def get_db():
    """Open a new database connection with rows returned as dict-like objects.

    timeout=10 means: if another process briefly holds a write lock (e.g. a
    second script touching the file at nearly the same moment), this
    connection will wait up to 10 seconds and retry automatically instead of
    immediately raising "database is locked" — the default SQLite behaviour,
    with no timeout at all, fails instantly on any overlap however brief.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Create the database from schema.sql. Wipes any existing data."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_db()
    with open(SCHEMA_PATH, "r") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    print(f"Database initialized at {DB_PATH}")


if __name__ == "__main__":
    # Run `python database.py` to (re)create a fresh, empty database.
    init_db()
