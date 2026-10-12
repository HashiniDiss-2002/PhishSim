"""
test_threat_intel.py
----------------------
Verifies the single-article extraction module (services/threat_intel.py)
in isolation, using mocked network calls so this stays fully
offline/deterministic like every other test_*.py here.

This module only ever fetches and extracts ONE article given its URL — it
doesn't decide which article to look at. That's the discovery half
(services/threat_source_crawler.py) and the engineer-facing scan route
(admin.manage_threat_sources) that wires the two together end-to-end; see
test_threat_source_crawler.py for coverage of that pipeline, and
test_stage2_reference.py for the admin-side scenario-selection flow.

Covers:
  1. _TextExtractor pulls readable text out of HTML and skips
     script/style/nav content.
  2. fetch_article_text raises a clear ThreatIntelError for a bad URL
     scheme, a network failure, and a page with too little text.
  3. _sanitize strips URL-shaped substrings from extracted text.
  4. extract_structural_features in MOCK MODE (no GROQ_API_KEY) returns an
     obviously-labelled placeholder rather than silently looking real.
  5. extract_structural_features raises ThreatIntelError when the (mocked)
     LLM says the article isn't actually about a phishing campaign.
"""

import os
import sys
from unittest.mock import patch, Mock

for var in ("GROQ_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
            "SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD"):
    os.environ.pop(var, None)

from services import threat_intel

failures = []


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}")
    if not condition:
        failures.append(label)


SAMPLE_HTML = """
<html><head><title>x</title><script>var x=1;</script><style>.a{}</style></head>
<body>
<nav>Home | About</nav>
<header>Site Header</header>
<article>
<p>Attackers sent fake invoice emails with a PDF attachment containing a
QR code that led victims to a credential harvesting page impersonating a
finance portal. The campaign targeted accounts-payable staff across
several mid-size companies during the fiscal year-end period.</p>
<p>More filler text to push this past the minimum-length check so the
extractor has enough content to work with reliably in this test case.</p>
</article>
<footer>Copyright 2026</footer>
</body></html>
"""


def test_text_extractor():
    parser = threat_intel._TextExtractor()
    parser.feed(SAMPLE_HTML)
    text = parser.get_text()
    check("Extractor includes article body text", "credential harvesting" in text)
    check("Extractor excludes <script> content", "var x=1" not in text)
    check("Extractor excludes <nav> content", "Home | About" not in text)
    check("Extractor excludes <footer> content", "Copyright 2026" not in text)


def test_fetch_article_text():
    try:
        threat_intel.fetch_article_text("not-a-url")
        check("Rejects non-http(s) URL", False)
    except threat_intel.ThreatIntelError:
        check("Rejects non-http(s) URL", True)

    import requests
    with patch("services.threat_intel.requests.get", side_effect=requests.exceptions.ConnectionError("boom")):
        try:
            threat_intel.fetch_article_text("https://example.com/article")
            check("Raises on network failure", False)
        except threat_intel.ThreatIntelError as e:
            check("Raises on network failure", "Could not fetch" in str(e))

    short_resp = Mock(text="<html><body><p>too short</p></body></html>", status_code=200)
    short_resp.raise_for_status = lambda: None
    with patch("services.threat_intel.requests.get", return_value=short_resp):
        try:
            threat_intel.fetch_article_text("https://example.com/thin-page")
            check("Raises on too-little-text page", False)
        except threat_intel.ThreatIntelError as e:
            check("Raises on too-little-text page", "almost no readable text" in str(e))

    good_resp = Mock(text=SAMPLE_HTML, status_code=200)
    good_resp.raise_for_status = lambda: None
    with patch("services.threat_intel.requests.get", return_value=good_resp):
        text = threat_intel.fetch_article_text("https://example.com/real-article")
        check("Successfully extracts text from a good page", "credential harvesting" in text)


def test_sanitize():
    dirty = "Delivery via https://evil.example.com/login and also www.another-bad.test/path"
    clean = threat_intel._sanitize(dirty)
    check("_sanitize strips https:// URLs", "https://" not in clean)
    check("_sanitize strips www. URLs", "www.another-bad.test" not in clean)
    check("_sanitize leaves a redaction marker", "[redacted-link]" in clean)


def test_extract_mock_mode():
    good_resp = Mock(text=SAMPLE_HTML, status_code=200)
    good_resp.raise_for_status = lambda: None
    with patch("services.threat_intel.requests.get", return_value=good_resp):
        result = threat_intel.extract_structural_features("https://example.com/real-article")
        check("Mock-mode extraction is obviously labelled [MOCK]", "[MOCK]" in result["summary"])
        check("Mock-mode extraction still carries the source URL", result["source_url"] == "https://example.com/real-article")


def test_extract_rejects_non_phishing_article():
    good_resp = Mock(text=SAMPLE_HTML, status_code=200)
    good_resp.raise_for_status = lambda: None
    fake_llm_result = {"is_phishing_campaign": False}
    with patch("services.threat_intel.requests.get", return_value=good_resp), \
         patch.dict(os.environ, {"GROQ_API_KEY": "fake-key-for-test"}), \
         patch("services.threat_intel._call_llm", return_value=fake_llm_result):
        try:
            threat_intel.extract_structural_features("https://example.com/not-phishing")
            check("Rejects article the LLM says isn't a phishing campaign", False)
        except threat_intel.ThreatIntelError as e:
            check("Rejects article the LLM says isn't a phishing campaign",
                  "doesn't appear to describe" in str(e))


def main():
    test_text_extractor()
    test_fetch_article_text()
    test_sanitize()
    test_extract_mock_mode()
    test_extract_rejects_non_phishing_article()

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All single-article Stage 2 extraction checks passed.")


if __name__ == "__main__":
    main()
