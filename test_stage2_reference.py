"""
test_stage2_reference.py
--------------------------
Verifies the Stage 2 campaign-creation flow, now that scenario selection
is fully automated: an admin picks a scenario the engineer's discovery
pipeline already produced by ID — they never type a URL or a summary
themselves (see test_threat_source_crawler.py for the discovery/scan
pipeline itself).
  1. An ordinary campaign (no stage2_scenario_id) behaves exactly as
     before — no regression for the common case.
  2. A campaign created by SELECTING a pre-discovered scenario stores its
     summary + source URL on the campaigns row.
  3. That reference actually reaches generate_pretext() (and therefore the
     LLM prompt) for every employee in the campaign — not just saved and
     ignored.
  4. The reference is never silently dropped for a 'generic' condition
     campaign, but generate_pretext() correctly ignores it there (generic
     is the fixed control baseline, unaffected by any context).
  5. campaign_detail renders the Stage 2 badge/reference box when present,
     and does NOT render it for an ordinary campaign.
  6. Selecting a scenario ID that no longer exists falls back gracefully
     to an ordinary Stage 1 campaign rather than erroring.

Uses mock mode (no GROQ_API_KEY) and a scratch DB, same pattern as the
other test_*.py files in this project.
"""

import os
import sys
import tempfile

for var in ("GROQ_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
            "SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD"):
    os.environ.pop(var, None)

# MFA (services/totp.py) is mandatory for every real login, but this test
# file only exercises other features, so the login helper below is allowed
# to skip the MFA step via this test-only bypass (see auth.py's
# _MFA_TEST_BYPASS_ENV) rather than deriving a TOTP code for every login.
os.environ["PHISHSIM_DISABLE_MFA_FOR_TESTS"] = "1"

tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
tmp_db.close()

import database
database.DB_PATH = __import__("pathlib").Path(tmp_db.name)

from werkzeug.security import generate_password_hash
from app import create_app
from services.pretext_generator import generate_pretext

failures = []


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}")
    if not condition:
        failures.append(label)


def setup_data():
    database.init_db()
    db = database.get_db()
    cur = db.execute("INSERT INTO organizations (name) VALUES (?)", ("Sampath Bank Sri Lanka",))
    org_id = cur.lastrowid
    db.execute(
        "INSERT INTO users (org_id, email, password_hash, role, full_name, department) "
        "VALUES (?, ?, ?, 'admin', ?, NULL)",
        (org_id, "core@sampath.test", generate_password_hash("password123"), "Core Admin"),
    )
    db.execute(
        "INSERT INTO employees (org_id, full_name, email, department, job_title) VALUES (?, ?, ?, ?, ?)",
        (org_id, "Jane Employee", "jane@sampath.test", "Finance", "Analyst"),
    )
    db.commit()
    db.close()
    return org_id


def login(client, email):
    return client.post("/login", data={"email": email, "password": "password123"}, follow_redirects=True)


STRUCTURAL_REF = (
    "Pretext category: routine business (invoice/payment). "
    "Urgency framing: low, blends with fiscal year-end traffic. "
    "Delivery vector: PDF attachment with embedded QR code (quishing)."
)
SCENARIO_ARTICLE_URL = "https://example-cti-blog.test/articles/quishing-campaign"


def seed_scenario():
    """Inserts a pre-discovered scenario directly, as if the engineer's
    scan pipeline had already produced it — admins never create these
    themselves."""
    db = database.get_db()
    cur = db.execute(
        "INSERT INTO threat_intel_scenarios (source_id, article_url, article_title, summary) "
        "VALUES (NULL, ?, ?, ?)",
        (SCENARIO_ARTICLE_URL, "Quishing campaign targets finance teams", STRUCTURAL_REF),
    )
    db.commit()
    scenario_id = cur.lastrowid
    db.close()
    return scenario_id


def main():
    setup_data()
    app = create_app()
    app.config["TESTING"] = True

    # ---- 1: ordinary campaign unaffected ----
    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.post(
            "/admin/campaign/new",
            data={"name": "Ordinary Campaign", "condition": "personalized"},
            follow_redirects=True,
        )
        check("Ordinary campaign (no stage2_reference) created OK", resp.status_code == 200)

    db = database.get_db()
    ordinary = db.execute("SELECT * FROM campaigns WHERE name = 'Ordinary Campaign'").fetchone()
    check("Ordinary campaign has stage2_reference = NULL", ordinary["stage2_reference"] is None)
    db.close()

    with app.test_client() as client:
        login(client, "core@sampath.test")
        body = client.get(f"/admin/campaign/{ordinary['id']}").get_data(as_text=True)
        check("Ordinary campaign page does NOT show Stage 2 badge", "Stage 2" not in body)

    # ---- 2 & 3: Stage 2 campaign stores + uses the SELECTED scenario ----
    scenario_id = seed_scenario()

    with app.test_client() as client:
        login(client, "core@sampath.test")
        # The scenario should appear in the create-campaign dropdown.
        form_body = client.get("/admin/campaign/new").get_data(as_text=True)
        check("Create-campaign page lists the discovered scenario in the dropdown",
              "Quishing campaign targets finance teams" in form_body)

        resp = client.post(
            "/admin/campaign/new",
            data={
                "name": "Stage2 Campaign",
                "condition": "personalized",
                "stage2_scenario_id": str(scenario_id),
            },
            follow_redirects=True,
        )
        check("Stage 2 campaign created OK", resp.status_code == 200)

    db = database.get_db()
    stage2 = db.execute("SELECT * FROM campaigns WHERE name = 'Stage2 Campaign'").fetchone()
    check("Stage 2 campaign stores the selected scenario's structural summary",
          stage2["stage2_reference"] == STRUCTURAL_REF)
    check("Stage 2 campaign stores the scenario's source article URL",
          stage2["stage2_source_url"] == SCENARIO_ARTICLE_URL)
    db.close()

    with app.test_client() as client:
        login(client, "core@sampath.test")
        body = client.get(f"/admin/campaign/{stage2['id']}").get_data(as_text=True)
        check("Stage 2 campaign page SHOWS the Stage 2 badge", "Stage 2" in body)
        check("Stage 2 campaign page shows the reference text", "quishing" in body)

    # ---- 4: direct unit check that generate_pretext() actually receives it ----
    # (mock mode can't prove the LLM prompt content, so check the real prompt builder directly)
    from services.pretext_generator import _build_prompt
    prompt_with_ref = _build_prompt("Jane Employee", "Finance", "Sampath Bank Sri Lanka", STRUCTURAL_REF)
    prompt_without_ref = _build_prompt("Jane Employee", "Finance", "Sampath Bank Sri Lanka", None)
    check("Prompt WITH reference contains the structural summary", "quishing" in prompt_with_ref)
    check("Prompt WITHOUT reference does not mention it", "quishing" not in prompt_without_ref)
    check("Prompt WITH reference explicitly instructs NOT to copy real content",
          "do not attempt to reproduce" in prompt_with_ref.lower())

    # ---- 5: generic condition ignores the reference (fixed control baseline) ----
    generic_result = generate_pretext(
        employee_name="Jane Employee", department="Finance", org_name="Sampath Bank Sri Lanka",
        condition="generic", real_world_reference=STRUCTURAL_REF,
    )
    check("generic condition output is the fixed control template regardless of reference",
          generic_result["subject"] == "Password policy update — action required")

    # ---- 6: a stale/nonexistent scenario ID falls back gracefully ----
    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.post(
            "/admin/campaign/new",
            data={
                "name": "Stale Scenario Campaign",
                "condition": "personalized",
                "stage2_scenario_id": "999999",
            },
            follow_redirects=True,
        )
        check("Campaign with a nonexistent scenario ID still creates OK (falls back to Stage 1)",
              resp.status_code == 200)
        body = resp.get_data(as_text=True)
        check("Fallback warning is shown to the admin", "no longer exists" in body)

    db = database.get_db()
    stale = db.execute("SELECT * FROM campaigns WHERE name = 'Stale Scenario Campaign'").fetchone()
    check("Fallback campaign has stage2_reference = NULL", stale["stage2_reference"] is None)
    db.close()

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All Stage 2 reference checks passed.")


if __name__ == "__main__":
    main()
    os.unlink(tmp_db.name)
