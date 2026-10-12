"""
test_roster_template.py
-------------------------
Verifies the downloadable employee-roster CSV template
(admin.download_roster_template(), linked from templates/upload.html).

Covers:
  1. GET /admin/upload/template.csv returns 200, the right content-type
     and attachment filename, and a CSV body with exactly the four
     columns upload_employees() reads (full_name, email, department,
     job_title) plus two example rows.
  2. The downloaded template, with its example rows replaced by real
     data, uploads successfully through the real /admin/upload flow —
     i.e. the template's column names/order are genuinely compatible
     with the upload parser, not just cosmetically similar.
  3. The route requires login (an anonymous request is redirected to
     /login, never served the file).

Uses mock mode and a scratch DB, same pattern as the other test_*.py
files in this project.
"""

import io
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
    db.commit()
    db.close()


def login(client, email):
    return client.post("/login", data={"email": email, "password": "password123"}, follow_redirects=True)


def main():
    setup_data()
    app = create_app()
    app.config["TESTING"] = True

    # ---- 3: anonymous request is bounced, not served the file ----
    with app.test_client() as client:
        resp = client.get("/admin/upload/template.csv", follow_redirects=True)
        check("Anonymous request to the template is bounced to login, not served",
              b"Sign in" in resp.data or b"Welcome back" in resp.data)

    # ---- 1: logged-in admin downloads the template ----
    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.get("/admin/upload/template.csv")
        check("Template download returns 200", resp.status_code == 200)
        check("Template has CSV content-type", "text/csv" in resp.headers.get("Content-Type", ""))
        check("Template has an attachment filename",
              "attachment" in resp.headers.get("Content-Disposition", "")
              and "phishsim_employee_roster_template.csv" in resp.headers.get("Content-Disposition", ""))

        body = resp.get_data(as_text=True)
        header_line = body.splitlines()[0]
        check("Template header has exactly the four expected columns, in order",
              header_line.strip() == "full_name,email,department,job_title")
        check("Template includes two example data rows",
              len(body.strip().splitlines()) == 3)

    # ---- 2: the template, edited, round-trips through the real upload flow ----
    edited_csv = (
        "full_name,email,department,job_title\r\n"
        "Nimal Perera,nimal.perera@sampath.test,Finance,Loan Officer\r\n"
        "Amara Silva,amara.silva@sampath.test,IT,Network Admin\r\n"
    ).encode("utf-8")

    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.post(
            "/admin/upload",
            data={"csv_file": (io.BytesIO(edited_csv), "phishsim_employee_roster_template.csv")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        check("Edited template uploads successfully", b"Imported 2 employees" in resp.data)

    db = database.get_db()
    nimal = db.execute("SELECT * FROM employees WHERE email = 'nimal.perera@sampath.test'").fetchone()
    amara = db.execute("SELECT * FROM employees WHERE email = 'amara.silva@sampath.test'").fetchone()
    check("First templated employee row landed correctly",
          nimal is not None and nimal["full_name"] == "Nimal Perera" and nimal["department"] == "Finance")
    check("Second templated employee row landed correctly",
          amara is not None and amara["full_name"] == "Amara Silva" and amara["department"] == "IT")
    db.close()

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All roster-template checks passed.")


if __name__ == "__main__":
    main()
