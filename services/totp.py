"""
totp.py
-------
Time-based One-Time Password (TOTP) implementation for admin/engineer
login MFA, built from Python's standard library alone (hmac, hashlib,
struct, base64, time, secrets) — deliberately NOT using a third-party
package such as pyotp. Two reasons, both worth stating in the
dissertation if asked:

  1. This environment's package installs go through an organisation-
     policy-enforced proxy that does not allow arbitrary PyPI installs,
     so a new third-party dependency here would be a real deployment
     risk, not just a style preference.
  2. TOTP (RFC 6238, built on HOTP from RFC 4226) is a short, fully
     published, deterministic algorithm — exactly the kind of thing this
     project already prefers to implement directly and transparently
     (see compliance_mapper.py's "transparent, not opaque" rules table,
     and threat_source_crawler.py's stdlib-only HTML/feed parsing) rather
     than pull in a library for.

This module is intentionally the FULL algorithm, not a stripped-down
approximation: it is interoperable with any standard authenticator app
(Google Authenticator, Authy, 1Password, etc.), which all implement the
same RFC. A thesis appendix or viva question about "did you implement
this yourself or use a library" has an honest, specific answer either
way — this file IS the implementation, and its correctness can be
demonstrated against the RFC 6238 Appendix B test vectors (see
test_mfa.py).
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time

# Standard TOTP parameters — the same defaults pyotp, Google Authenticator,
# and every other mainstream TOTP implementation use, so a secret enrolled
# here scans and verifies identically in a real authenticator app.
_DIGITS = 6
_PERIOD_SECONDS = 30
_DIGEST = hashlib.sha1  # RFC 6238's default; what authenticator apps expect


def generate_secret() -> str:
    """
    A fresh, random 160-bit (20-byte) shared secret, base32-encoded (the
    format every authenticator app's QR-code scanner and manual-entry
    field expect). Generated with `secrets`, not `random` — this is a
    credential, not a simulation artefact.
    """
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def _hotp(secret_b32: str, counter: int) -> str:
    """
    RFC 4226 HOTP: secret + a counter -> a 6-digit code. TOTP (below) is
    just HOTP with the counter derived from the current time instead of
    an incrementing counter.
    """
    key = base64.b32decode(secret_b32.upper())
    counter_bytes = struct.pack(">Q", counter)  # 8-byte big-endian counter
    mac = hmac.new(key, counter_bytes, _DIGEST).digest()
    # Dynamic truncation (RFC 4226 §5.3): use the low nibble of the last
    # byte as an offset into the HMAC output, take 4 bytes from there,
    # mask off the top bit, then reduce mod 10^digits.
    offset = mac[-1] & 0x0F
    truncated = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** _DIGITS)).zfill(_DIGITS)


def current_code(secret_b32: str, at: float = None) -> str:
    """The 6-digit code valid right now (or at the given unix timestamp)."""
    t = _PERIOD_SECONDS and int((at if at is not None else time.time()) // _PERIOD_SECONDS)
    return _hotp(secret_b32, t)


def verify_code(secret_b32: str, code: str, valid_window: int = 1) -> bool:
    """
    Checks `code` against the secret, tolerating +/- `valid_window` steps
    of 30 seconds (the standard allowance for clock drift between the
    server and the admin's phone — this is what every TOTP implementation
    does; without it, a phone even a few seconds slow would be locked
    out). Uses hmac.compare_digest for a constant-time comparison so a
    timing side-channel can't be used to brute-force the code digit by
    digit.
    """
    if not code or not code.isdigit() or len(code) != _DIGITS:
        return False
    now_step = int(time.time() // _PERIOD_SECONDS)
    for offset in range(-valid_window, valid_window + 1):
        expected = _hotp(secret_b32, now_step + offset)
        if hmac.compare_digest(expected, code):
            return True
    return False


def provisioning_uri(secret_b32: str, account_name: str, issuer: str = "PhishSim") -> str:
    """
    The otpauth:// URI an authenticator app's QR scanner expects —
    standard format, RFC-adjacent (documented by Google Authenticator's
    "Key URI Format"). Rendered as a QR code client-side (see
    templates/mfa_setup.html) by handing this URI to a QR-image endpoint
    in the admin's own browser — this module only builds the URI; it
    does not render any image itself, keeping this file dependency-free.
    """
    import urllib.parse
    label = urllib.parse.quote(f"{issuer}:{account_name}")
    params = urllib.parse.urlencode({
        "secret": secret_b32,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": str(_DIGITS),
        "period": str(_PERIOD_SECONDS),
    })
    return f"otpauth://totp/{label}?{params}"
