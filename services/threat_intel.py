"""
threat_intel.py
----------------
Stage 2 automation: given a URL to a real, publicly reported phishing
campaign write-up (a CTI blog post, vendor disclosure, etc.), this module
fetches the article and uses the LLM to extract its STRUCTURAL features
only — pretext category, urgency/authority framing, delivery vector,
target sector, notable technique — never its literal content.

This replaces the manual "researcher reads the article and types a
summary" step with an automated one, while keeping the methodological
safeguard from methodology 3.2.4 ("defanging") intact: the extraction
prompt explicitly forbids the model from echoing real domains, URLs, IP
addresses, or file hashes, and a regex pass strips any URL-shaped text
from the output as defense-in-depth, the same layered approach already
used for pretext moderation (prompt constraint + keyword filter).

TREND AGGREGATION: alongside the free-text fields, each article is also
classified into two FIXED, closed vocabularies — delivery_channel
(DELIVERY_CHANNELS) and pretext_category_tag (PRETEXT_CATEGORY_TAGS),
below. The free-text fields read well on a scenario-selection dropdown
but can't be reliably grouped or counted (an LLM describing "invoice
lure" one week and "unpaid-invoice pretext" the next is the same real
trend, but different strings). The two tagged columns let
services/threat_trends.py answer "what's trending across our sources
right now" — e.g. surfacing that messaging-app-delivered phishing has
spiked this month across several registered sources — which is the
difference between "one article the admin happened to click a link
into" and genuine multi-source threat intelligence informing which
scenarios are worth building a campaign around.

This module only ever fetches and extracts ONE article at a time — it
does not decide which article to look at. That decision is split two
ways elsewhere, so a human is always in the loop at the point that
matters most (which sites to trust), while the repetitive part (reading
today's articles on a trusted site and summarizing the ones that are
actually phishing write-ups) is automated:
  - services/threat_source_crawler.py discovers candidate article URLs
    from a listing/RSS page the platform ENGINEER curated.
  - admin.manage_threat_sources() calls extract_structural_features()
    (this module) on each new candidate, and only stores a scenario when
    is_phishing_campaign comes back true — so a low-quality or off-topic
    link from the crawler's keyword match is caught and discarded here,
    never silently accepted.
Client admins never pick an article or a source themselves — they only
ever select from the scenarios this pipeline has already produced.
"""

import re
from html.parser import HTMLParser

import requests

from services.pretext_generator import _call_llm

FETCH_TIMEOUT = 15
MAX_ARTICLE_CHARS = 6000  # keep the extraction prompt a reasonable size

# Strips anything that looks like a URL from extracted text, as a
# defense-in-depth backstop to the prompt instruction below — belt and
# braces, same layering as the pretext moderation filter.
_URL_PATTERN = re.compile(r"\b(?:https?://|www\.)\S+", re.IGNORECASE)


class ThreatIntelError(Exception):
    pass


# Fixed vocabularies for the SECOND classification pass described in this
# module's docstring update below — distinct from the free-text
# pretext_category/delivery_vector fields, which read well to a human but
# can't be reliably grouped. Deliberately short, closed lists (same
# design reasoning as pretext_generator.py's ALLOWED_CATEGORIES /
# PERSUASION_PRINCIPLES): a trend-aggregation signal is only useful if
# "messaging-app phishing" always lands in the same bucket, which free
# text from an LLM run article-by-article cannot guarantee.
DELIVERY_CHANNELS = [
    "email", "sms_text", "messaging_app", "phone_call", "social_media",
    "malicious_ad", "other",
]

PRETEXT_CATEGORY_TAGS = [
    "it_password_vpn", "invoice_payment", "hr_payroll", "delivery_shipping",
    "internal_event_announcement", "software_tool_update",
    "account_security_alert", "other",
]


class _TextExtractor(HTMLParser):
    """Minimal HTML-to-text extractor using only the standard library —
    no BeautifulSoup dependency needed for this scoped use (pulling rough
    article body text, not precise structured scraping)."""

    def __init__(self):
        super().__init__()
        self._chunks = []
        self._skip_depth = 0  # inside <script>/<style>/<nav>/<header>/<footer>

    SKIP_TAGS = {"script", "style", "nav", "header", "footer", "noscript"}

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag):
        if tag in self.SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data):
        if self._skip_depth == 0:
            text = data.strip()
            if text:
                self._chunks.append(text)

    def get_text(self):
        return "\n".join(self._chunks)


def fetch_article_text(url: str) -> str:
    """Fetches a URL and returns rough plain-text content. Raises
    ThreatIntelError with a human-readable reason on any failure, so the
    caller can flash it and let the admin fall back to pasting a manual
    summary instead."""
    if not url.lower().startswith(("http://", "https://")):
        raise ThreatIntelError("That doesn't look like a valid http(s) URL.")

    try:
        resp = requests.get(
            url,
            timeout=FETCH_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (compatible; PhishSimResearchBot/1.0)"},
        )
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise ThreatIntelError(f"Could not fetch that URL: {type(e).__name__}: {e}")

    parser = _TextExtractor()
    try:
        parser.feed(resp.text)
    except Exception as e:
        raise ThreatIntelError(f"Could not parse that page's HTML: {e}")

    text = parser.get_text()
    if len(text) < 200:
        raise ThreatIntelError(
            "That page returned almost no readable text — it may be JavaScript-rendered, "
            "paywalled, or blocked this request. Try a different article, or paste a "
            "structural summary manually instead."
        )
    return text[:MAX_ARTICLE_CHARS]


def _build_extraction_prompt(article_text: str) -> str:
    delivery_channels = ", ".join(DELIVERY_CHANNELS)
    pretext_category_tags = ", ".join(PRETEXT_CATEGORY_TAGS)
    return f"""You are helping a security researcher extract STRUCTURAL
features from a real, publicly published article describing a phishing
campaign, for use in academic security-awareness research. You must
extract PATTERNS only — never literal identifying details.

STRICT RULES:
- Do NOT include any real domain names, URLs, IP addresses, file hashes,
  email addresses, or company names used as attacker infrastructure.
- Do NOT quote the article's exact wording — describe the pattern in
  your own words.
- If the article doesn't clearly describe a phishing campaign at all,
  set "is_phishing_campaign" to false and leave the other fields empty.

Extract these free-text fields from the article text below:
- pretext_category: what the email/lure claims to be about (a short phrase)
- urgency_framing: how much urgency/pressure is used, and how (a short phrase)
- authority_framing: what authority or trust is impersonated or implied (a short phrase)
- delivery_vector: how the attack is delivered (e.g. "email with PDF attachment",
  "malicious search ads to a spoofed login page", "QR code in a PDF") (a short phrase)
- target_sector: who/what sector is targeted (a short phrase)
- notable_technique: any distinctive technique mentioned (a short phrase)

Additionally, classify the article into exactly ONE value from each of
these two FIXED lists (pick the closest fit — never invent a new value):
- delivery_channel: exactly one of {delivery_channels}
- pretext_category_tag: exactly one of {pretext_category_tags}

ARTICLE TEXT:
---
{article_text}
---

Output ONLY valid JSON with exactly these keys: "is_phishing_campaign" (boolean),
"pretext_category", "urgency_framing", "authority_framing", "delivery_vector",
"target_sector", "notable_technique" (all strings, empty string if not applicable
or is_phishing_campaign is false), "delivery_channel" (one of the fixed list
above), "pretext_category_tag" (one of the fixed list above).
Respond with JSON only, no other text, no markdown code fences."""


def _sanitize(text: str) -> str:
    """Defense-in-depth: strip anything URL-shaped even though the prompt
    already forbids it, mirroring the layered prompt+filter approach used
    for pretext moderation elsewhere in this project."""
    return _URL_PATTERN.sub("[redacted-link]", text)


def extract_structural_features(url: str) -> dict:
    """
    Fetches `url` and returns a dict:
      {"source_url": url, "summary": "<human-readable structural summary>",
       "delivery_channel": one of DELIVERY_CHANNELS,
       "pretext_category_tag": one of PRETEXT_CATEGORY_TAGS,
       "raw": {...the individual extracted fields...}}
    Raises ThreatIntelError on any failure (fetch, parse, or — if the
    article plainly isn't about a phishing campaign — a clear message
    saying so, rather than silently fabricating fields).
    """
    import os

    article_text = fetch_article_text(url)

    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        # MOCK MODE — mirrors pretext_generator.py's approach: obviously
        # labelled placeholder so it's never mistaken for a real extraction.
        # The two tagged fields deliberately rotate deterministically by
        # URL (not a fixed constant) so offline/mock testing of the trend
        # aggregation feature (services/threat_trends.py) has more than
        # one bucket to actually aggregate across, without needing a real
        # GROQ_API_KEY to exercise it.
        import hashlib
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
        mock_channel = DELIVERY_CHANNELS[int(digest[:4], 16) % len(DELIVERY_CHANNELS)]
        mock_category = PRETEXT_CATEGORY_TAGS[int(digest[4:8], 16) % len(PRETEXT_CATEGORY_TAGS)]
        fields = {
            "is_phishing_campaign": True,
            "pretext_category": "[MOCK] business-themed lure",
            "urgency_framing": "[MOCK] low — set GROQ_API_KEY for a real extraction",
            "authority_framing": "[MOCK] impersonates an internal department",
            "delivery_vector": "[MOCK] email with link",
            "target_sector": "[MOCK] general",
            "notable_technique": "[MOCK] none — this is placeholder output",
            "delivery_channel": mock_channel,
            "pretext_category_tag": mock_category,
        }
    else:
        prompt = _build_extraction_prompt(article_text)
        fields = _call_llm(prompt)

    if not fields.get("is_phishing_campaign", True):
        raise ThreatIntelError(
            "That article doesn't appear to describe a phishing campaign — "
            "try a different source, or paste a structural summary manually."
        )

    # Defensive handling, same pattern as pretext_generator.py's
    # persuasion_principle fallback: an unexpected/missing model response
    # falls back to 'other' rather than raising or polluting the fixed
    # vocabulary services/threat_trends.py relies on for grouping.
    delivery_channel = fields.get("delivery_channel")
    if delivery_channel not in DELIVERY_CHANNELS:
        delivery_channel = "other"
    pretext_category_tag = fields.get("pretext_category_tag")
    if pretext_category_tag not in PRETEXT_CATEGORY_TAGS:
        pretext_category_tag = "other"

    summary_lines = [
        f"Pretext category: {fields.get('pretext_category', '')}",
        f"Urgency framing: {fields.get('urgency_framing', '')}",
        f"Authority framing: {fields.get('authority_framing', '')}",
        f"Delivery vector: {fields.get('delivery_vector', '')}",
        f"Target sector: {fields.get('target_sector', '')}",
        f"Notable technique: {fields.get('notable_technique', '')}",
    ]
    summary = _sanitize("\n".join(line for line in summary_lines if line.split(": ", 1)[-1]))

    return {
        "source_url": url,
        "summary": summary,
        "delivery_channel": delivery_channel,
        "pretext_category_tag": pretext_category_tag,
        "raw": fields,
    }
