"""
Quick smoke test of the full user flow, using Flask's test client
(no real server/network needed). Run: python test_flow.py
"""
import io
import os

# MFA (services/totp.py) is mandatory for every real login, but this smoke
# test only exercises other features, so it skips the MFA step via this
# test-only bypass (see auth.py's _MFA_TEST_BYPASS_ENV) rather than
# deriving a TOTP code for every login.
os.environ["PHISHSIM_DISABLE_MFA_FOR_TESTS"] = "1"

from app import app

client = app.test_client()

def check(label, resp, expect_status=200):
    ok = resp.status_code == expect_status
    print(f"{'OK ' if ok else 'FAIL'} [{resp.status_code}] {label}")
    if not ok:
        print(resp.data[:500])
    return ok

# 1. Login as admin
r = client.post("/login", data={"email": "admin@acme.test", "password": "password123"}, follow_redirects=True)
check("Admin login", r)
assert b"Admin Dashboard" in r.data, "Did not land on admin dashboard"

# 2. Upload employees CSV
csv_content = b"full_name,email,department,job_title\nTest User,test.user@acme.test,IT,Engineer\n"
r = client.post("/admin/upload", data={"csv_file": (io.BytesIO(csv_content), "test.csv")},
                 content_type="multipart/form-data", follow_redirects=True)
check("CSV upload", r)

# 3. Create a personalized campaign (mock mode - no API key set)
r = client.post("/admin/campaign/new", data={
    "name": "Test Campaign",
    "condition": "personalized",
    "context": "The company recently rolled out a new VPN client to all staff.",
}, follow_redirects=True)
check("Create campaign", r)
assert b"Test Campaign" in r.data

# 4. Find the campaign id and get one tracking token from the DB
from database import get_db
db = get_db()
campaign = db.execute("SELECT * FROM campaigns WHERE name='Test Campaign'").fetchone()
email_row = db.execute("SELECT * FROM campaign_emails WHERE campaign_id=?", (campaign["id"],)).fetchone()
db.close()
print(f"OK   Campaign id={campaign['id']}, sample token={email_row['token'][:10]}...")
print(f"OK   Sample generated subject: {email_row['subject']}")

# 5. Simulate an employee opening and clicking the email
r = client.get(f"/track/open/{email_row['token']}.gif")
check("Track open (pixel)", r)

r = client.get(f"/track/click/{email_row['token']}")
check("Track click -> fake login form", r)
# Debrief now happens on submit, not immediately on click (see tracking.py);
# clicking lands on the fake credential-entry form instead.
assert b"form" in r.data.lower()

# 6. View campaign results as admin
r = client.get(f"/admin/campaign/{campaign['id']}")
check("View campaign results", r)
assert b"Compliance Findings" in r.data

# 7. Confirm engineer cannot see tenant data
client.get("/logout")
r = client.post("/login", data={"email": "engineer@platform.local", "password": "password123"}, follow_redirects=True)
check("Engineer login", r)
r = client.get(f"/admin/campaign/{campaign['id']}", follow_redirects=True)
check("Engineer blocked from tenant campaign (redirected + no leak)", r, expect_status=200)
assert b"Compliance Findings" not in r.data, "SECURITY BUG: engineer could see tenant data!"
assert b"permission" in r.data, "Expected a permission-denied flash message"

print("\nAll smoke tests passed.")
