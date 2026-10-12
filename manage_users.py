"""
manage_users.py
----------------
Lets you change a login's email, password, and/or display name, or create
a brand-new account, WITHOUT wiping your existing database (unlike
re-running database.py + seed_demo_data.py).

Run it from inside your phishsim folder (same place as app.py):

    python manage_users.py

Then follow the on-screen prompts.
"""

from werkzeug.security import generate_password_hash
from database import get_db


def list_users():
    db = get_db()
    users = db.execute("SELECT id, email, role, full_name FROM users ORDER BY id").fetchall()
    db.close()
    if not users:
        print("No users found yet. Run seed_demo_data.py first, or choose 'create' below.")
        return
    print("\nExisting accounts:")
    for u in users:
        print(f"  [{u['id']}] {u['email']}  (role: {u['role']}, name: {u['full_name']})")
    print()


def change_credentials():
    db = get_db()
    email = input("Email of the account to update: ").strip().lower()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if user is None:
        print(f"No account found with email '{email}'.")
        db.close()
        return

    new_email = input(f"New email (press Enter to keep '{user['email']}'): ").strip().lower()
    new_password = input("New password (press Enter to keep the current one): ").strip()
    new_name = input(f"New display name (press Enter to keep '{user['full_name']}'): ").strip()

    updates = {}
    if new_email:
        updates["email"] = new_email
    if new_password:
        updates["password_hash"] = generate_password_hash(new_password)
    if new_name:
        updates["full_name"] = new_name

    if not updates:
        print("Nothing changed.")
        db.close()
        return

    set_clause = ", ".join(f"{k} = ?" for k in updates)
    db.execute(f"UPDATE users SET {set_clause} WHERE id = ?", (*updates.values(), user["id"]))
    db.commit()
    db.close()
    print(f"Updated account [{user['id']}] successfully.")
    print("Note: if you're logged into the app right now, log out and back in to see the name change reflected in the navbar.")


def create_user():
    db = get_db()
    print("\nCreate a new account.")
    print("Role must be exactly: engineer, admin, or user")
    role = input("Role: ").strip().lower()
    if role not in ("engineer", "admin", "user"):
        print("Invalid role. Must be 'engineer', 'admin', or 'user'.")
        db.close()
        return

    full_name = input("Full name: ").strip()
    email = input("Email: ").strip().lower()
    password = input("Password: ").strip()

    org_id = None
    if role != "engineer":
        org_id = input("Organization ID (see 'list organizations' in your admin DB, or leave blank if unsure): ").strip()
        org_id = int(org_id) if org_id else None

    try:
        db.execute(
            "INSERT INTO users (org_id, email, password_hash, role, full_name) VALUES (?, ?, ?, ?, ?)",
            (org_id, email, generate_password_hash(password), role, full_name),
        )
        db.commit()
        print(f"Created new {role} account: {email}")
    except Exception as e:
        print(f"Could not create account: {e}")
    finally:
        db.close()


def main():
    print("=== PhishSim Account Manager ===")
    list_users()
    print("What would you like to do?")
    print("  1) Change an existing account's email/password/name")
    print("  2) Create a new account")
    print("  3) Quit")
    choice = input("Choice [1/2/3]: ").strip()

    if choice == "1":
        change_credentials()
    elif choice == "2":
        create_user()
    else:
        print("No changes made.")


if __name__ == "__main__":
    main()
