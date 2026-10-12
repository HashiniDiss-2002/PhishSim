# PhishSim — Context-Aware Phishing Simulation & Compliance Platform (MVP)

A final-year research prototype: generates personalized, LLM-driven phishing
simulation emails, tracks engagement, and maps results to data-protection
compliance obligations for a dashboard.

This is the **Stage 1 MVP** as scoped in the accompanying build guide —
CSV-based roster import (not live AD sync), a curated context list (not
live news scraping), and manual Stage 2 campaign recreation. See the
methodology document for the full architecture and the justification for
this scope.

## 1. Install prerequisites

- Python 3.10+ installed and on PATH
- (Optional) An Anthropic API key from console.anthropic.com, for real
  LLM-generated pretexts. Without it, the app runs in **mock mode**
  automatically — fully functional for building/testing/demoing.

## 2. Set up the project

```bash
cd phishsim
python -m venv venv

# Activate the virtual environment:
# macOS/Linux:
source venv/bin/activate
# Windows:
venv\Scripts\activate

pip install -r requirements.txt
```

## 3. Configure environment variables (optional but recommended)

Copy `.env.example` to `.env` and fill in `ANTHROPIC_API_KEY` if you want
real LLM generation instead of mock mode. On macOS/Linux you can instead
just export variables directly:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export FLASK_SECRET_KEY=some-long-random-string
```

## 4. Initialize the database and demo data

```bash
python database.py          # creates instance/phishsim.db from schema.sql
python seed_demo_data.py    # adds demo org, users, and employees
```

Demo logins created:
- `engineer@platform.local` / `password123` (platform engineer — no tenant access)
- `admin@acme.test` / `password123` (client admin for demo org "Acme Corp")

If you're updating an existing install rather than starting fresh, run every
migration script in this folder at least once (each is safe to re-run):
`migrate_add_department.py`, `migrate_add_org_suspended.py`,
`migrate_add_stage2_reference.py`, `migrate_add_threat_intel_tables.py`,
`migrate_add_registration_and_audit.py`, `migrate_add_logo_and_password_reset.py`,
`migrate_add_attack_spoofing_bitb.py`, `migrate_add_novelty_features.py`.

## 5. Run the app

```bash
python app.py
```

Visit **http://localhost:5000** and log in with one of the demo accounts.

## 6. Run the automated smoke test (optional but recommended)

Verifies the entire flow — login, CSV upload, campaign generation, tracking,
compliance dashboard, and role-based access control — without needing a
browser:

```bash
python test_flow.py
```

## Typical walkthrough as admin

1. Log in as `admin@acme.test`.
2. **Upload Employees** → upload a CSV with columns `full_name,email,department` (an example is shown on that page; demo employees are already seeded).
3. **New Campaign** → choose "personalized" or "generic" condition and a context snippet → Generate Emails.
4. Open the campaign → review generated subject lines/content per employee.
5. Click **Send Campaign** — by default this writes each email to `outbox/*.html` instead of really sending (safe for development). See `services/mailer.py` to wire up real SMTP/Mailtrap.
6. Manually visit a tracking link from one of the outbox files (or copy a token from the database) to simulate an employee opening/clicking, and watch the dashboard's compliance findings update.

## Project structure

```
phishsim/
├── app.py                        Flask entry point
├── database.py / schema.sql      SQLite setup
├── auth.py                       Login, sessions, role-based access control
├── admin.py                      CSV upload, campaign creation, dashboards
├── tracking.py                   Open/click/submit/report capture endpoints
├── services/
│   ├── pretext_generator.py      LLM prompt, moderation filter, mock mode
│   ├── compliance_mapper.py      Rules linking metrics to regulations
│   └── mailer.py                 Safe-by-default email sending
├── templates/                    All HTML pages (Bootstrap)
├── seed_demo_data.py             Creates demo login accounts
├── test_flow.py                  End-to-end smoke test
└── requirements.txt
```

## Important ethical/safety notes (do not remove before real use)

- **Never** point `send_campaign` at a real SMTP server with real employee
  emails until your institutional ethics approval and the target
  organization's informed consent are in place.
- The fake login form (`templates/fake_login.html`) never reads or stores
  submitted field values by design (see `tracking.py: track_submit`) —
  only the fact that a submission occurred is logged.
- The pretext generator refuses to reference sensitive personal topics
  (see `BLOCKED_TOPICS` in `services/pretext_generator.py`).
