"""
seed_demo_data.py
------------------
Populates the (already-initialized) database with demo accounts so you can
log in and test immediately. Run:  python database.py  first, then this.

Demo logins created:
  engineer@platform.local   / password123   (role: engineer)
  admin@acme.test           / password123   (role: admin, core admin, org: Acme Corp)
  it.admin@acme.test        / password123   (role: admin, department admin — IT only)
"""

from werkzeug.security import generate_password_hash

from database import get_db, init_db

DEMO_PASSWORD = "password123"


def seed():
    init_db()  # fresh database each time this script is run
    db = get_db()

    # Platform engineer — note org_id is NULL, so they belong to no tenant.
    db.execute(
        "INSERT INTO users (org_id, email, password_hash, role, full_name) VALUES (?, ?, ?, ?, ?)",
        (None, "engineer@platform.local", generate_password_hash(DEMO_PASSWORD), "engineer", "Platform Engineer"),
    )

    # Demo organization + core admin (department IS NULL -> full org access).
    # ethics_accepted_at is set here too, as if this org had gone through
    # the real /register -> /register/ethics flow (auth.py) — keeps seeded
    # demo data consistent with what every organization created from here
    # on will look like.
    cur = db.execute(
        "INSERT INTO organizations (name, ethics_accepted_at) VALUES (?, datetime('now'))",
        ("Acme Corp",),
    )
    org_id = cur.lastrowid

    db.execute(
        "INSERT INTO users (org_id, email, password_hash, role, full_name, department) "
        "VALUES (?, ?, ?, ?, ?, NULL)",
        (org_id, "admin@acme.test", generate_password_hash(DEMO_PASSWORD), "admin", "Hashini"),
    )

    # Demo department admin, scoped to IT only — created the same way the
    # core admin would create one, via /admin/department-admins.
    db.execute(
        "INSERT INTO users (org_id, email, password_hash, role, full_name, department) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (org_id, "it.admin@acme.test", generate_password_hash(DEMO_PASSWORD), "admin", "IT Dept Admin", "IT"),
    )

    # A handful of demo employees so create_campaign has something to work with.
    demo_employees = [
        ("Jamie Chen", "jamie.chen@acme.test", "Finance", "Accounts Payable Clerk"),
        ("Priya Nair", "priya.nair@acme.test", "IT", "Systems Administrator"),
        ("Sam Okafor", "sam.okafor@acme.test", "Sales", "Account Executive"),
        ("Taylor Novak", "taylor.novak@acme.test", "HR", "HR Coordinator"),
    ]
    for name, email, dept, title in demo_employees:
        db.execute(
            "INSERT INTO employees (org_id, full_name, email, department, job_title) VALUES (?, ?, ?, ?, ?)",
            (org_id, name, email, dept, title),
        )

    # One demo Stage 2 source + a pre-discovered scenario, so the dropdown
    # in Create Campaign isn't empty on a fresh install. In real use, the
    # engineer adds sources via /engineer/threat-sources and runs "Scan All
    # Sources" to populate this list automatically — this is just a
    # same-shaped placeholder so the admin-side flow is demoable right away.
    src_cur = db.execute(
        "INSERT INTO threat_intel_sources (url, label, added_by) VALUES (?, ?, (SELECT id FROM users WHERE email = ?))",
        ("https://example-cti-source.test/category/phishing/", "Demo CTI source (seed data)", "engineer@platform.local"),
    )
    db.execute(
        "INSERT INTO threat_intel_scenarios (source_id, article_url, article_title, summary) VALUES (?, ?, ?, ?)",
        (
            src_cur.lastrowid,
            "https://example-cti-source.test/articles/demo-quishing-campaign",
            "[Demo] Quishing campaign targets accounts-payable teams",
            "Pretext category: routine business (invoice/payment).\n"
            "Urgency framing: low, blends with fiscal year-end traffic.\n"
            "Authority framing: impersonates an internal finance department.\n"
            "Delivery vector: PDF attachment with embedded QR code (quishing).\n"
            "Target sector: finance / accounts payable.\n"
            "Notable technique: QR code redirects to credential-harvesting page.",
        ),
    )

    db.commit()
    db.close()
    print("Seed complete.")
    print("  Engineer login:        engineer@platform.local / password123")
    print("  Core admin login:      admin@acme.test / password123")
    print("  Department admin login: it.admin@acme.test / password123  (IT only)")
    print("  Demo Stage 2 scenario seeded — pick it from the dropdown in Create Campaign,")
    print("  or add real sources via Engineer Dashboard > Manage Stage 2 Threat Sources.")


if __name__ == "__main__":
    seed()
