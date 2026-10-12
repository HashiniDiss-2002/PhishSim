"""
threat_source_crawler.py
--------------------------
Stage 2 automation, discovery half: given a trusted CTI listing page
(a site's category/tag page, e.g. "...com/category/phishing/", or an
RSS/Atom feed URL) that the platform ENGINEER has curated, finds candidate
article links that look like they're about phishing.

Deliberately bounded, by design, not by accident:
- This only reads the ONE listing page the engineer gave it. It does not
  follow links recursively, does not crawl the wider site, and does not
  search the open web on its own. The engineer still decides which sites
  are trustworthy CTI sources by choosing which listing URLs to add —
  the system only automates "find today's phishing articles on a source
  I already trust," not "find phishing articles anywhere."
- Filtering is a simple keyword match (default "phishing") on the link
  text/title and URL — not a guarantee of relevance. Each candidate is
  still run through services.threat_intel.extract_structural_features(),
  which itself asks the LLM to confirm the article actually describes a
  phishing campaign before anything is stored (see is_phishing_campaign
  in that module) — so a false-positive link from this keyword filter is
  caught and discarded at the next stage, not silently accepted.

No new dependency: HTML link extraction uses the standard library's
html.parser (same approach as threat_intel.py's text extractor), and
RSS/Atom parsing uses the standard library's xml.etree.ElementTree.
"""

from html.parser import HTMLParser
from urllib.parse import urljoin
import xml.etree.ElementTree as ET

import requests

from services.threat_intel import ThreatIntelError, FETCH_TIMEOUT

MAX_CANDIDATES_DEFAULT = 5
_SKIP_HREF_PREFIXES = ("#", "mailto:", "javascript:", "tel:")


class _LinkExtractor(HTMLParser):
    """Collects (href, visible_text) for every <a> tag on the page."""

    def __init__(self):
        super().__init__()
        self.links = []
        self._current_href = None
        self._current_text_parts = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self._current_href = href
                self._current_text_parts = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text_parts.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._current_href is not None:
            text = " ".join("".join(self._current_text_parts).split())
            self.links.append((self._current_href, text))
            self._current_href = None
            self._current_text_parts = []


def _parse_feed(xml_text: str):
    """Parses RSS 2.0 or Atom feed XML into [{'url', 'title'}, ...].
    Namespace-tolerant: matches on tag suffix (e.g. '...}entry' or
    'entry') rather than requiring exact namespace declarations, since
    different feeds declare Atom's namespace differently."""
    results = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return results

    # RSS 2.0: <rss><channel><item><title/><link/></item>...
    for item in root.iter("item"):
        title_el = item.find("title")
        link_el = item.find("link")
        link = (link_el.text or "").strip() if link_el is not None else ""
        title = (title_el.text or "").strip() if title_el is not None else ""
        if link:
            results.append({"url": link, "title": title})

    if results:
        return results

    # Atom: <feed><entry><title/><link href="..."/></entry>...
    for entry in root.iter():
        if entry.tag.endswith("entry"):
            title, link = "", ""
            for child in entry:
                if child.tag.endswith("title"):
                    title = (child.text or "").strip()
                elif child.tag.endswith("link"):
                    link = child.get("href", "") or (child.text or "")
            if link:
                results.append({"url": link.strip(), "title": title})
    return results


def _fetch_raw(url: str) -> str:
    try:
        resp = requests.get(
            url,
            timeout=FETCH_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (compatible; PhishSimResearchBot/1.0)"},
        )
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise ThreatIntelError(f"Could not fetch source listing: {type(e).__name__}: {e}")
    return resp.text


def discover_candidate_articles(listing_url: str, keyword: str = "phishing",
                                 max_results: int = MAX_CANDIDATES_DEFAULT) -> list:
    """
    Fetches `listing_url` (an HTML category/tag page, or an RSS/Atom feed)
    and returns up to `max_results` candidate articles whose link text,
    title, or URL mentions `keyword`, as [{'url': ..., 'title': ...}, ...].

    Raises ThreatIntelError if the listing page itself can't be fetched.
    Returns an empty list (not an error) if the page fetches fine but no
    candidates match — that's a normal "nothing new today" outcome.
    """
    raw = _fetch_raw(listing_url)

    sniff = raw.lstrip()[:300].lower()
    is_feed = sniff.startswith("<?xml") or "<rss" in sniff or "<feed" in sniff

    if is_feed:
        candidates = _parse_feed(raw)
    else:
        parser = _LinkExtractor()
        try:
            parser.feed(raw)
        except Exception:
            candidates = []
        else:
            candidates = []
            for href, text in parser.links:
                if href.startswith(_SKIP_HREF_PREFIXES):
                    continue
                candidates.append({"url": urljoin(listing_url, href), "title": text})

    keyword_lower = keyword.lower()
    seen_urls = set()
    filtered = []
    for c in candidates:
        url = c["url"].strip()
        title = (c["title"] or "").strip()
        if not url or url == listing_url or url in seen_urls:
            continue
        if keyword_lower in url.lower() or keyword_lower in title.lower():
            seen_urls.add(url)
            filtered.append({"url": url, "title": title})
        if len(filtered) >= max_results:
            break

    return filtered
