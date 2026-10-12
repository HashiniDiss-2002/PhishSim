"""
test_novelty_features.py
--------------------------
Covers the four "novelty" features added on top of the cybersecurity-
technique batch, aimed at a genuine research contribution beyond "an LLM
writes emails":

  1. Persuasion-principle tagging + susceptibility profiling
     (services/pretext_generator.py's persuasion_principle output key,
     services/compliance_mapper.py's compute_persuasion_profile()).
  2. Adaptive difficulty engine (services/compliance_mapper.py's
     difficulty_for_tier(), admin.py's create_campaign() mapping an
     employee's prior risk tier to a difficulty level).
  3. Callback phishing (TOAD) simulation (services/pretext_generator.py's
     generate_toad_pretext(), tracking.py's track_call(), campaigns.vector).
  4. Click-timing behavioural signal (interactions.dwell_ms,
     services/compliance_mapper.py's classify_click_speed()).

Uses mock mode (no GROQ_API_KEY) and a scratch DB/outbox, same pattern as
every other test_*.py file in this project.
"""

import os
import re
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
from services.pretext_generator import (
    generate_pretext, generate_toad_pretext, PERSUASION_PRINCIPLES, DIFFICULTY_LEVELS,
)
from services.compliance_mapper import (
    compute_persuasion_profile, classify_click_speed, difficulty_for_tier, compute_metrics,
)

failures = []


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}")
    if not condition:
        failures.append(label)


def setup_data():
    database.init_db()
    db = database.get_db()

    cur = db.execute("INSERT INTO organizations (name) VALUES (?)", ("Novelty Test Org",))
    org_id = cur.lastrowid
    db.execute(
        "INSERT INTO users (org_id, email, password_hash, role, full_name, department) "
        "VALUES (?, ?, ?, 'admin', ?, NULL)",
        (org_id, "core@novelty.test", generate_password_hash("password123"), "Core Admin"),
    )
    db.execute(
        "INSERT INTO employees (org_id, full_name, email, department, job_title) VALUES (?, ?, ?, ?, ?)",
        (org_id, "Pat Repeat Clicker", "pat@novelty.test", "Finance", "Analyst"),
    )
    db.execute(
        "INSERT INTO employees (org_id, full_name, email, department, job_title) VALUES (?, ?, ?, ?, ?)",
        (org_id, "Sam Vigilant", "sam@novelty.test", "Finance", "Analyst"),
    )
    db.commit()
    db.close()
    return org_id


def login(client, email="core@novelty.test"):
    return client.post("/login", data={"email": email, "password": "password123"}, follow_redirects=True)


def main():
    org_id = setup_data()
    app = create_app()
    app.config["TESTING"] = True

    # =========================================================
    # 1. Pure unit tests — pretext_generator.py
    # =========================================================
    generic = generate_pretext("Jane", "Finance", "Acme Corp", condition="generic")
    check("Generic template tags persuasion_principle", generic["persuasion_principle"] == "authority")

    mock_personalized = generate_pretext("Jane", "Finance", "Acme Corp", condition="personalized")
    check("Mock-mode personalized output tags a valid persuasion_principle",
          mock_personalized["persuasion_principle"] in PERSUASION_PRINCIPLES)

    toad = generate_toad_pretext("Jane", "Finance", "Acme Corp")
    check("TOAD pretext has no attachment", toad["attachment_filename"] is None)
    check("TOAD pretext tags persuasion_principle='urgency'", toad["persuasion_principle"] == "urgency")
    check("TOAD pretext body contains the {call_link} placeholder", "{call_link}" in toad["html_body"])
    check("TOAD pretext body does NOT contain a {tracking_link} placeholder",
          "{tracking_link}" not in toad["html_body"])
    check("TOAD phone number is in the reserved, non-routable 555-01XX range",
          re.search(r"555-01\d{2}", toad["phone_display"]) is not None)
    toad2 = generate_toad_pretext("Jane", "Finance", "Acme Corp")
    check("TOAD phone number is deterministic for the same org name",
          toad["phone_display"] == toad2["phone_display"])

    # =========================================================
    # 2. Pure unit tests — compliance_mapper.py
    # =========================================================
    check("difficulty_for_tier maps Critical -> reinforcement", difficulty_for_tier("Critical") == "reinforcement")
    check("difficulty_for_tier maps High -> reinforcement", difficulty_for_tier("High") == "reinforcement")
    check("difficulty_for_tier maps Medium -> standard", difficulty_for_tier("Medium") == "standard")
    check("difficulty_for_tier maps Low -> advanced", difficulty_for_tier("Low") == "advanced")
    check("difficulty_for_tier falls back to standard for an unknown tier", difficulty_for_tier("???") == "standard")

    check("classify_click_speed(None) returns None", classify_click_speed(None) is None)
    check("classify_click_speed(1000) is Impulsive", "Impulsive" in classify_click_speed(1000))
    check("classify_click_speed(5000) is Quick", "Quick" in classify_click_speed(5000))
    check("classify_click_speed(15000) is Deliberate", "Deliberate" in classify_click_speed(15000))

    profile = compute_persuasion_profile([
        {"persuasion_principle": "urgency", "fell_for_it": True},
        {"persuasion_principle": "urgency", "fell_for_it": False},
        {"persuasion_principle": "authority", "fell_for_it": False},
        {"persuasion_principle": None, "fell_for_it": True},  # skipped — untagged
    ])
    by_principle = {p["principle"]: p for p in profile}
    check("Persuasion profile skips untagged rows", len(profile) == 2)
    check("Persuasion profile: urgency exposed=2, fell_for_it=1",
          by_principle["urgency"]["exposed"] == 2 and by_principle["urgency"]["fell_for_it"] == 1)
    check("Persuasion profile: urgency rate is 0.5", abs(by_principle["urgency"]["rate"] - 0.5) < 1e-9)
    check("Persuasion profile sorted highest-rate first", profile[0]["principle"] == "urgency")

    metrics = compute_metrics({"total": 10, "called": 3})
    check("compute_metrics includes called_rate", abs(metrics["called_rate"] - 0.3) < 1e-9)

    # =========================================================
    # 3. End-to-end: callback phishing (TOAD) campaign
    # =========================================================
    with app.test_client() as client:
        login(client)
        resp = client.post("/admin/campaign/new", data={
            "name": "TOAD Campaign", "condition": "personalized",
            "stage2_scenario_id": "", "fake_login_style": "standard",
            "vector": "callback_toad",
        }, follow_redirects=True)
        check("TOAD campaign created OK", resp.status_code == 200)

    db = database.get_db()
    toad_campaign = db.execute("SELECT * FROM campaigns WHERE name = 'TOAD Campaign'").fetchone()
    toad_campaign_id = toad_campaign["id"]
    check("Campaign stores vector='callback_toad'", toad_campaign["vector"] == "callback_toad")
    toad_emails = db.execute(
        "SELECT * FROM campaign_emails WHERE campaign_id = ?", (toad_campaign_id,)
    ).fetchall()
    check("TOAD campaign generated an email per employee", len(toad_emails) == 2)
    check("TOAD campaign emails are never marked has_attachment",
          all(e["has_attachment"] == 0 for e in toad_emails))
    check("TOAD campaign emails are tagged persuasion_principle='urgency'",
          all(e["persuasion_principle"] == "urgency" for e in toad_emails))
    check("TOAD campaign emails never contain a raw {tracking_link}/{call_link} placeholder",
          all("{call_link}" not in e["html_body"] and "{tracking_link}" not in e["html_body"] for e in toad_emails))
    check("TOAD campaign emails DO contain a /track/call/ link",
          all("/track/call/" in e["html_body"] for e in toad_emails))
    toad_token = toad_emails[0]["token"]
    db.close()

    with app.test_client() as client:
        login(client)
        body = client.get(f"/admin/campaign/{toad_campaign_id}").get_data(as_text=True)
        check("Campaign page shows the Callback phishing (TOAD) badge", "Callback phishing" in body)
        check("Campaign page shows a Called (TOAD) count card", "Called (TOAD)" in body)

    with app.test_client() as client:
        resp = client.get(f"/track/call/{toad_token}")
        body = resp.get_data(as_text=True)
        check("track_call() renders the education/debrief page directly", resp.status_code == 200)
        check("TOAD debrief explains the technique by name", "Telephone-Oriented" in body or "TOAD" in body)
        check("TOAD debrief states the number was never reachable",
              "never a real" in body.lower() or "never reachable" in body.lower() or "could never connect" in body.lower())

    db = database.get_db()
    called_logged = db.execute(
        "SELECT * FROM interactions i JOIN campaign_emails ce ON i.campaign_email_id = ce.id "
        "WHERE ce.token = ? AND i.event_type = 'called'", (toad_token,)
    ).fetchone()
    check("'called' interaction event was logged", called_logged is not None)
    db.close()

    with app.test_client() as client:
        login(client)
        resp = client.get(f"/admin/campaign/{toad_campaign_id}/report.csv")
        body = resp.get_data(as_text=True)
        check("CSV report includes a 'Called (TOAD)' metrics row", "Called (TOAD)" in body)

    # =========================================================
    # 4. End-to-end: ordinary email-link campaign — persuasion tag +
    #    difficulty stored, employee_detail shows the new sections, and
    #    click-timing (dwell_ms) is recorded + classified correctly.
    # =========================================================
    with app.test_client() as client:
        login(client)
        client.post("/admin/campaign/new", data={
            "name": "Standard Novelty Test", "condition": "personalized",
            "stage2_scenario_id": "", "fake_login_style": "standard",
            "vector": "email_link",
        }, follow_redirects=True)

    db = database.get_db()
    std_campaign = db.execute("SELECT * FROM campaigns WHERE name = 'Standard Novelty Test'").fetchone()
    std_campaign_id = std_campaign["id"]
    check("Standard campaign stores vector='email_link' (the default)", std_campaign["vector"] == "email_link")
    std_emails = db.execute(
        "SELECT ce.*, e.full_name FROM campaign_emails ce JOIN employees e ON ce.employee_id = e.id "
        "WHERE campaign_id = ?", (std_campaign_id,)
    ).fetchall()
    check("Standard campaign emails are tagged with a persuasion_principle",
          all(e["persuasion_principle"] for e in std_emails))
    # Both employees already have one prior (TOAD) campaign with no risky
    # interactions recorded, so their risk tier is 'Low' -> difficulty
    # 'advanced', not the no-history 'standard' default (only a true
    # zero-campaigns employee gets 'standard').
    check("Employees with a clean prior campaign get difficulty_level='advanced'",
          all(e["difficulty_level"] == "advanced" for e in std_emails))
    pat_email = next(e for e in std_emails if e["full_name"] == "Pat Repeat Clicker")
    pat_employee_id = db.execute(
        "SELECT id FROM employees WHERE full_name = 'Pat Repeat Clicker'"
    ).fetchone()["id"]
    pat_token = pat_email["token"]
    db.close()

    # Pat clicks and submits with a fast (impulsive) dwell time, simulating
    # the fake-login page's hidden timing field.
    with app.test_client() as client:
        client.get(f"/track/click/{pat_token}")
        resp = client.post(f"/track/submit/{pat_token}", data={
            "username": "pat", "password": "whatever", "dwell_ms": "1500",
        })
        check("Submit with dwell_ms still renders the debrief page", resp.status_code == 200)

    db = database.get_db()
    submit_row = db.execute(
        "SELECT * FROM interactions i JOIN campaign_emails ce ON i.campaign_email_id = ce.id "
        "WHERE ce.token = ? AND i.event_type = 'submit'", (pat_token,)
    ).fetchone()
    check("dwell_ms was stored on the submit interaction", submit_row["dwell_ms"] == 1500)
    db.close()

    with app.test_client() as client:
        login(client)
        body = client.get(f"/admin/employee/{pat_employee_id}").get_data(as_text=True)
        check("Employee page shows the Susceptibility Profile section", "Susceptibility Profile" in body)
        check("Employee page shows the Response Speed section", "Response Speed" in body)
        check("Employee page classifies Pat's quick submission as Impulsive", "Impulsive" in body)
        check("Employee page shows a Called (TOAD) count card", "Called (TOAD)" in body)

    # A submit with no dwell_ms field at all (e.g. JS disabled) must store
    # NULL, not 0 — verified directly against a second, isolated token.
    std_emails_fresh = [e for e in std_emails if e["full_name"] != "Pat Repeat Clicker"]
    other_token = std_emails_fresh[0]["token"]
    with app.test_client() as client:
        client.get(f"/track/click/{other_token}")
        client.post(f"/track/submit/{other_token}", data={"username": "x", "password": "y"})

    db = database.get_db()
    no_dwell_row = db.execute(
        "SELECT * FROM interactions i JOIN campaign_emails ce ON i.campaign_email_id = ce.id "
        "WHERE ce.token = ? AND i.event_type = 'submit'", (other_token,)
    ).fetchone()
    check("Missing dwell_ms field stores NULL, not 0", no_dwell_row["dwell_ms"] is None)
    db.close()

    # =========================================================
    # 5. Adaptive difficulty: after Pat's click+submit above (High/Critical
    #    risk from a single campaign depending on weights — verify via the
    #    actual risk tier rather than assuming), a SECOND campaign for the
    #    same roster should give Pat a different difficulty than a
    #    never-interacted employee.
    # =========================================================
    with app.test_client() as client:
        login(client)
        client.post("/admin/campaign/new", data={
            "name": "Second Novelty Campaign", "condition": "personalized",
            "stage2_scenario_id": "", "fake_login_style": "standard",
            "vector": "email_link",
        }, follow_redirects=True)

    db = database.get_db()
    second_campaign = db.execute("SELECT * FROM campaigns WHERE name = 'Second Novelty Campaign'").fetchone()
    pat_second_email = db.execute(
        "SELECT * FROM campaign_emails WHERE campaign_id = ? AND employee_id = ?",
        (second_campaign["id"], pat_employee_id),
    ).fetchone()
    check("Pat (who clicked+submitted before) gets a non-'advanced' difficulty next time",
          pat_second_email["difficulty_level"] in ("reinforcement", "standard"))
    db.close()

    if failures:
        print(f"\n{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print(f" - {f}")
        sys.exit(1)
    print("\nAll novelty-feature checks passed.")


if __name__ == "__main__":
    main()
