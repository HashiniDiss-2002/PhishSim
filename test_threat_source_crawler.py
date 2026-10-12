"""
test_threat_source_crawler.py
-------------------------------
Verifies the fully-automated Stage 2 discovery pipeline:
  1. discover_candidate_articles extracts links from an HTML listing page,
     filters by keyword, dedupes, and resolves relative URLs.
  2. discover_candidate_articles parses an RSS 2.0 feed.
  3. discover_candidate_articles parses an Atom feed.
  4. discover_candidate_articles raises ThreatIntelError when the listing
     page itself can't be fetched, but returns an empty list (not an
     error) when it fetches fine with no matching candidates.
  5. The engineer-only /engineer/threat-sources route: add a source,
     delete a source, and — the main integration — run "Scan All
     Sources" end-to-end (discovery + extraction both mocked) and confirm
     a new threat_intel_scenarios row is created only for a candidate the
     (mocked) LLM confirms is an actual phishing write-up, with dedup
     against already-known article URLs on a second scan.
  6. A client admin (not an engineer) cannot reach /engineer/threat-sources.

Uses mock mode and mocked network calls throughout — fully offline, same
pattern as every other test_*.py in this project.
"""

import os
import sys
import tempfile
from unittest.mock import patch, Mock

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
from services import threat_source_crawler as crawler
from services.threat_intel import ThreatIntelError

failures = []


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}")
    if not condition:
        failures.append(label)


HTML_LISTING = """
<html><body>
<nav><a href="/">Home</a></nav>
<article>
  <a href="/articles/new-phishing-campaign-targets-banks">New phishing campaign targets banks</a>
  <a href="/articles/unrelated-product-update">Unrelated product update</a>
  <a href="https://other-site.test/articles/phishing-wave-hits-retailers">Phishing wave hits retailers</a>
  <a href="#">just an anchor</a>
  <a href="mailto:editor@example.com">Email us</a>
</article>
</body></html>
"""

RSS_FEED = """<?xml version="1.0"?>
<rss version="2.0"><channel>
  <item><title>Phishing kit targets SaaS logins</title><link>https://example.test/rss/phishing-kit-saas</link></item>
  <item><title>Unrelated roundup</title><link>https://example.test/rss/roundup</link></item>
</channel></rss>
"""

ATOM_FEED = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>Phishing campaign abuses QR codes</title>
    <link href="https://example.test/atom/phishing-qr"/>
  </entry>
  <entry>
    <title>Something else entirely</title>
    <link href="https://example.test/atom/other"/>
  </entry>
</feed>
"""


def _resp(text):
    r = Mock(text=text, status_code=200)
    r.raise_for_status = lambda: None
    return r


def test_discover_html_listing():
    with patch("services.threat_source_crawler.requests.get", return_value=_resp(HTML_LISTING)):
        results = crawler.discover_candidate_articles("https://example.test/category/phishing/")
    urls = [r["url"] for r in results]
    check("Finds the phishing-relevant relative-link article", any("new-phishing-campaign" in u for u in urls))
    check("Finds the phishing-relevant absolute-link article", any("phishing-wave-hits-retailers" in u for u in urls))
    check("Excludes the unrelated article", not any("unrelated-product-update" in u for u in urls))
    check("Excludes '#' and mailto: links entirely", all(not u.startswith(("#", "mailto:")) for u in urls))
    check("Relative link is resolved against the listing URL",
          any(u.startswith("https://example.test/articles/") for u in urls))


def test_discover_rss_feed():
    with patch("services.threat_source_crawler.requests.get", return_value=_resp(RSS_FEED)):
        results = crawler.discover_candidate_articles("https://example.test/feed.rss")
    urls = [r["url"] for r in results]
    check("RSS: finds the phishing-relevant item", "https://example.test/rss/phishing-kit-saas" in urls)
    check("RSS: excludes the unrelated item", "https://example.test/rss/roundup" not in urls)


def test_discover_atom_feed():
    with patch("services.threat_source_crawler.requests.get", return_value=_resp(ATOM_FEED)):
        results = crawler.discover_candidate_articles("https://example.test/feed.atom")
    urls = [r["url"] for r in results]
    check("Atom: finds the phishing-relevant entry", "https://example.test/atom/phishing-qr" in urls)
    check("Atom: excludes the unrelated entry", "https://example.test/atom/other" not in urls)


def test_discover_fetch_failure_and_empty_result():
    import requests
    with patch("services.threat_source_crawler.requests.get",
               side_effect=requests.exceptions.ConnectionError("boom")):
        try:
            crawler.discover_candidate_articles("https://example.test/down")
            check("Raises ThreatIntelError when the listing page can't be fetched", False)
        except ThreatIntelError:
            check("Raises ThreatIntelError when the listing page can't be fetched", True)

    no_match_html = "<html><body><a href='/about'>About us</a></body></html>"
    with patch("services.threat_source_crawler.requests.get", return_value=_resp(no_match_html)):
        results = crawler.discover_candidate_articles("https://example.test/about-page")
    check("Returns an empty list (not an error) when nothing matches", results == [])


def setup_app_data():
    database.init_db()
    db = database.get_db()
    db.execute(
        "INSERT INTO users (org_id, email, password_hash, role, full_name, department) "
        "VALUES (NULL, ?, ?, 'engineer', ?, NULL)",
        ("engineer@platform.local", generate_password_hash("password123"), "Platform Engineer"),
    )
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


def test_engineer_source_management_and_scan():
    setup_app_data()
    app = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        login(client, "engineer@platform.local")

        resp = client.post(
            "/engineer/threat-sources",
            data={"action": "add_source", "url": "https://example.test/category/phishing/", "label": "Example CTI"},
            follow_redirects=True,
        )
        check("Engineer can add a threat source", resp.status_code == 200)
        body = resp.get_data(as_text=True)
        check("Added source appears in the page", "Example CTI" in body)

    db = database.get_db()
    source = db.execute("SELECT * FROM threat_intel_sources WHERE url = 'https://example.test/category/phishing/'").fetchone()
    check("Source row exists in the DB", source is not None)
    db.close()

    fake_features = {
        "source_url": None,  # set per-call below
        "summary": "Pretext category: business lure. Delivery vector: email with link.",
        "raw": {},
    }

    def mock_extract(url):
        return {**fake_features, "source_url": url}

    with patch("services.threat_source_crawler.requests.get", return_value=_resp(HTML_LISTING)), \
         patch("admin.extract_structural_features", side_effect=mock_extract):
        with app.test_client() as client:
            login(client, "engineer@platform.local")
            resp = client.post("/engineer/threat-sources", data={"action": "scan"}, follow_redirects=True)
            check("Scan request succeeds", resp.status_code == 200)
            body = resp.get_data(as_text=True)
            check("Scan reports new scenarios discovered", "new scenario" in body.lower())

    db = database.get_db()
    scenarios = db.execute("SELECT * FROM threat_intel_scenarios").fetchall()
    check("Scan inserted scenario rows for the phishing-relevant candidates", len(scenarios) == 2)
    check("Stored scenario summary carries structural features, not raw article text",
          all("Pretext category" in s["summary"] for s in scenarios))
    db.close()

    # Second scan with the same source: everything found is already known,
    # so dedup means nothing new gets inserted.
    with patch("services.threat_source_crawler.requests.get", return_value=_resp(HTML_LISTING)), \
         patch("admin.extract_structural_features", side_effect=mock_extract):
        with app.test_client() as client:
            login(client, "engineer@platform.local")
            client.post("/engineer/threat-sources", data={"action": "scan"}, follow_redirects=True)

    db = database.get_db()
    scenarios_after = db.execute("SELECT * FROM threat_intel_scenarios").fetchall()
    check("Re-scanning the same source does not duplicate scenarios", len(scenarios_after) == 2)

    source_id = db.execute(
        "SELECT id FROM threat_intel_sources WHERE url = 'https://example.test/category/phishing/'"
    ).fetchone()["id"]
    db.close()

    with app.test_client() as client:
        login(client, "engineer@platform.local")
        resp = client.post(
            "/engineer/threat-sources",
            data={"action": "delete_source", "source_id": source_id},
            follow_redirects=True,
        )
        check("Engineer can delete a threat source", resp.status_code == 200)

    db = database.get_db()
    remaining = db.execute("SELECT * FROM threat_intel_sources WHERE id = ?", (source_id,)).fetchone()
    check("Deleted source is gone from threat_intel_sources", remaining is None)
    scenarios_kept = db.execute("SELECT * FROM threat_intel_scenarios").fetchall()
    check("Deleting a source keeps its already-discovered scenarios (campaigns may reference them)",
          len(scenarios_kept) == 2)
    db.close()


def test_client_admin_cannot_reach_threat_sources_page():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        login(client, "core@sampath.test")
        resp = client.get("/engineer/threat-sources", follow_redirects=True)
        body = resp.get_data(as_text=True)
        check("A client admin is redirected away from /engineer/threat-sources, not shown it",
              "Registered Sources" not in body)


def main():
    test_discover_html_listing()
    test_discover_rss_feed()
    test_discover_atom_feed()
    test_discover_fetch_failure_and_empty_result()
    test_engineer_source_management_and_scan()
    test_client_admin_cannot_reach_threat_sources_page()

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All threat-source discovery/scan checks passed.")


if __name__ == "__main__":
    main()
    os.unlink(tmp_db.name)
