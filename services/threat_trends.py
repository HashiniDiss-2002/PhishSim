"""
threat_trends.py
-------------------
Aggregates ALREADY-DISCOVERED threat_intel_scenarios (see
services/threat_intel.py's fixed delivery_channel / pretext_category_tag
classification, and services/threat_source_crawler.py for how multiple
registered sources feed into the same scenario table) into a simple
"what's trending across our sources right now" view.

This is the piece that turns Stage 2 from "one admin happened to pick one
article" into actual multi-source threat intelligence: if several
registered CTI sources have recently reported, say, messaging-app-style
phishing, that shows up here as a trending channel — the same kind of
signal a real security-awareness vendor's threat-intel team would use to
decide which pretexts are worth building a simulation campaign around
this month, grounded in this platform's own discovered data rather than
the engineer's hunch about what's current.

Deliberately simple and inspectable (same "transparent, not opaque"
design philosophy as compliance_mapper.py's RULES table): a plain
recency window plus a count/distinct-source tally, not a bespoke trend
score dressed up as an algorithm. It can be defended on its own terms in
a viva: "a tag reported by 3 different sources in the last 30 days
outranks one reported 5 times by a single source," not "a model decided
this was trending."
"""

from datetime import datetime, timedelta, timezone

TREND_WINDOW_DAYS = 30


def _parse_discovered_at(value):
    """
    threat_intel_scenarios.discovered_at is stored via sqlite's
    datetime('now') — "YYYY-MM-DD HH:MM:SS", UTC, naive (no offset). This
    parses that format defensively, returning None for anything else
    (e.g. a NULL/malformed row) rather than raising and aborting the
    whole aggregation over one bad row.
    """
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _rank_tag_counts(rows, key, window_start):
    """
    rows: scenario dicts/Rows, each with at least 'discovered_at',
    'source_id', and `key` (a tag column — 'delivery_channel' or
    'pretext_category_tag').
    Returns a list of {"tag": str, "count": int, "distinct_sources": int},
    restricted to rows discovered on/after window_start, sorted by
    distinct_sources first (a trend several different sources agree on
    outranks the same count from one prolific source), then by count,
    both descending. Rows with no tag (NULL — pre-dates this feature) or
    tag == 'other' are excluded: 'other' is a catch-all, not a trend.
    """
    buckets = {}
    for row in rows:
        discovered_at = _parse_discovered_at(row["discovered_at"])
        if discovered_at is None or discovered_at < window_start:
            continue
        tag = row[key] if key in row.keys() else None
        if not tag or tag == "other":
            continue
        bucket = buckets.setdefault(tag, {"count": 0, "sources": set()})
        bucket["count"] += 1
        bucket["sources"].add(row["source_id"])

    ranked = [
        {"tag": tag, "count": b["count"], "distinct_sources": len(b["sources"])}
        for tag, b in buckets.items()
    ]
    ranked.sort(key=lambda r: (r["distinct_sources"], r["count"]), reverse=True)
    return ranked


def compute_trends(scenarios, window_days: int = TREND_WINDOW_DAYS) -> dict:
    """
    scenarios: every row from threat_intel_scenarios (sqlite3.Row or
    dict-like, supporting both [] access and .keys()) — this function
    does its own date filtering, so callers don't need to pre-filter.

    Returns:
        {"window_days": int,
         "total_in_window": int,
         "channels": [{"tag", "count", "distinct_sources"}, ...],
         "categories": [{"tag", "count", "distinct_sources"}, ...]}
    "channels" ranks delivery_channel, "categories" ranks
    pretext_category_tag — both over the same recency window, both
    excluding 'other' and untagged (pre-feature) rows, both already
    sorted most-significant first (see _rank_tag_counts()).
    """
    window_start = datetime.now(timezone.utc) - timedelta(days=window_days)
    total_in_window = sum(
        1 for row in scenarios
        if (parsed := _parse_discovered_at(row["discovered_at"])) is not None and parsed >= window_start
    )
    return {
        "window_days": window_days,
        "total_in_window": total_in_window,
        "channels": _rank_tag_counts(scenarios, "delivery_channel", window_start),
        "categories": _rank_tag_counts(scenarios, "pretext_category_tag", window_start),
    }


# Human-readable labels for the fixed vocabularies in services/threat_intel.py
# — kept here, not there, since this is purely a display concern for the
# trend panel/dropdown, not part of extraction itself.
CHANNEL_LABELS = {
    "email": "Email",
    "sms_text": "SMS / text message",
    "messaging_app": "Messaging app (e.g. WhatsApp, Telegram)",
    "phone_call": "Phone call / voice",
    "social_media": "Social media",
    "malicious_ad": "Malicious search/display ad",
    "other": "Other",
}

CATEGORY_LABELS = {
    "it_password_vpn": "IT / password / VPN",
    "invoice_payment": "Invoice / payment",
    "hr_payroll": "HR / payroll",
    "delivery_shipping": "Delivery / shipping",
    "internal_event_announcement": "Internal event / announcement",
    "software_tool_update": "Software / tool update",
    "account_security_alert": "Account security alert",
    "other": "Other",
}
