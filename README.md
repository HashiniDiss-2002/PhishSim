PhishSim -  An Automated Phishing Drill Management Platform for Compliance Impact Analysis under Personal Data Protection Acts 

The final-year research: A platform targeting small and medium-sized organizations that provides 
behavior-adaptive and threat intel aware spear phishing and general phishing simulations with a privacy
preserving, near-zero technical knowledge architecture while mapping user interactions to the 
compliance requirements of the Personal Data Protection Acts and recommending appropriate 
corrective actions.


 1. Install prerequisites

- Python 3.10+ installed and on PATH


 2. Set up the project

bash
cd phishsim
python -m venv venv

Activate the virtual environment:
macOS/Linux,
source venv/bin/activate
Windows,
venv\Scripts\activate

pip install -r requirements.txt


3. Configure environment variables (optional but recommended)

Copy `.env.example` to `.env` and fill in the required LLM's API key if you want
real LLM generation instead of mock mode. On macOS/Linux you can instead
just export variables directly.


4. Initialize the database and demo data

bash
python database.py          # creates instance/phishsim.db from schema.sql
python seed_demo_data.py    # adds demo org, users, and employees


Demo logins created:
- `engineer@platform.local` / `password123` (platform engineer)
- `admin@acme.test` / `password123` (client admin for demo organization, "Acme Corp")

If you're updating an existing install rather than starting fresh, run every
migration script in this folder at least once (each is safe to re-run):
`migrate_add_department.py`, `migrate_add_org_suspended.py`,
`migrate_add_stage2_reference.py`, `migrate_add_threat_intel_tables.py`,
`migrate_add_registration_and_audit.py`, `migrate_add_logo_and_password_reset.py`,
`migrate_add_attack_spoofing_bitb.py`, `migrate_add_novelty_features.py`.

5. Run the app

bash
python app.py


Visit "http://localhost:5000" and log in with one of the demo accounts.

6. Run the automated smoke test (optional but recommended)

Verifies the entire flow - login, CSV upload, campaign generation, tracking,
compliance dashboard and role-based access control - without needing a
browser,

bash
python test_flow.py


Typical walkthrough as admin

1. Log in as `admin@acme.test`.
2. Upload the employees details as a CSV(upload a CSV with columns `full_name,email,department`).
3. Create a new campaign → choose "personalized" or "generic" condition and a context snippet → Generate Emails.
4. Open the campaign → review generated subject lines/content per employee.
5. Click the "Send Campaign".
6. Manually visit a tracking link from one of the outbox files (or copy a token from the database) to simulate an employee opening/clicking and watch the dashboard's compliance findings update.

The Project structure is as follows,


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



