"""
domain_spoofing.py
---------------------
Generates a SYNTHETIC look-alike sender identity for a campaign — the
"sender/domain spoofing" technique real phishing kits use (display-name
spoofing plus a typosquatted/look-alike domain), reproduced here in a
safe, simulation-only form for security-awareness training.

ETHICAL SAFEGUARD (read before changing this file): this module NEVER
uses the client organization's real external domain, and never uses any
genuine third-party domain. It only ever derives a synthetic string from
the organization's own name using well-documented typosquatting
substitutions (see SUBSTITUTIONS below) plus a generic suffix — the
result does not resolve anywhere and cannot be mistaken for a real
domain belonging to anyone else. This is the same constraint the rest of
the platform applies to its other simulated-attack surfaces (see
tracking.py's note on attachment tracking: never a real malware
mechanism, only a disclosed simulation).

The generated identity is deterministic per organization name (seeded by
a hash of it), so the same organization gets a stable look-alike domain
across campaigns — useful because the post-click education page
(templates/landing_educate.html) references the exact value the
recipient actually saw.
"""

import hashlib
import re

# Character substitutions documented in real-world typosquatting /
# homoglyph phishing campaigns (e.g. "rn" standing in for "m", "0" for
# "o", "1" for "l"/"i") — applied once, so the result stays readable
# enough to pass a quick glance, which is the whole point of the
# technique being taught here.
SUBSTITUTIONS = [("rn", "m"), ("o", "0"), ("l", "1"), ("i", "1"), ("a", "4")]

LOOKALIKE_SUFFIXES = ["-portal", "-secure", "-support", "-online", "-sso"]

SENDER_TEMPLATES = [
    "{org} IT Support",
    "{org} Helpdesk",
    "{org} HR Team",
    "{org} Security Team",
]


def _seed(org_name: str) -> int:
    return int(hashlib.sha256(org_name.encode("utf-8")).hexdigest(), 16)


def _slugify(org_name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "", org_name.lower())
    return slug or "yourorg"


def generate_lookalike_domain(org_name: str) -> str:
    """
    A synthetic domain string derived from the organization's own name —
    never a real domain, never resolving anywhere. Deterministic per
    org_name so the same organization always gets the same value.
    """
    seed = _seed(org_name)
    slug = _slugify(org_name)
    suffix = LOOKALIKE_SUFFIXES[seed % len(LOOKALIKE_SUFFIXES)]

    substituted = slug
    for real, fake in SUBSTITUTIONS:
        if real in substituted:
            # One substitution is enough to be deceptive on a quick glance
            # without becoming unreadable — applying every possible match
            # would make the string obviously garbled rather than realistic.
            substituted = substituted.replace(real, fake, 1)
            break

    return f"{substituted}{suffix}.com"


def generate_spoofed_sender(org_name: str) -> dict:
    """
    Returns a dict with:
      - display_name: the plausible internal-looking sender name shown in
        the recipient's email client (e.g. "Acme Corp IT Support").
      - lookalike_domain: the synthetic domain (see generate_lookalike_domain).
      - spoofed_address: the full "local-part@lookalike_domain" address.
      - link_display_text: a lookalike-domain-styled string suitable for
        showing as a link's VISIBLE text when its real href still points
        at this platform's own tracking endpoint — the classic "link text
        doesn't match where it actually goes" indicator.
    Deterministic per org_name — the same organization always gets the
    same simulated identity, so repeat campaigns and the education page
    stay consistent.
    """
    seed = _seed(org_name)
    template = SENDER_TEMPLATES[seed % len(SENDER_TEMPLATES)]
    display_name = template.format(org=org_name)
    lookalike_domain = generate_lookalike_domain(org_name)
    local_part = "no-reply" if "Team" not in template else "updates"
    spoofed_address = f"{local_part}@{lookalike_domain}"

    return {
        "display_name": display_name,
        "lookalike_domain": lookalike_domain,
        "spoofed_address": spoofed_address,
        "link_display_text": f"https://{lookalike_domain}/verify-account",
    }
