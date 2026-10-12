"""
mailer.py
---------
Sends (or, by default, safely simulates sending) campaign emails.

SAFE BY DEFAULT: unless SMTP_HOST is set in the environment, this writes
each email to outbox/ as an .html file and prints a summary line instead
of sending anything — so you cannot accidentally email a real inbox while
building/testing the app.

To send real emails during your approved, consented evaluation study,
set these environment variables (Mailtrap's sandbox is recommended for
development — it captures emails without delivering them anywhere real):
    SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM_ADDRESS
"""

import os
import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr
from pathlib import Path

OUTBOX_DIR = Path(__file__).parent.parent / "outbox"


def send_email(to: str, subject: str, html_body: str, from_name: str = None, from_address: str = None):
    """
    from_name / from_address (both optional): the campaign's simulated
    sender identity from services/domain_spoofing.py — a synthetic
    display name + look-alike domain, never a real third-party domain
    (see that module's docstring). When provided, the "From" header shown
    to the recipient's email client reads exactly as a real spoofed-sender
    phishing email would (e.g. "Acme Corp IT Support
    <no-reply@acme-c0rp-portal.com>"), which is the whole point of the
    sender/domain-spoofing simulation feature. Falls back to the
    platform's own configured SMTP_FROM_ADDRESS when not given — the
    original, pre-spoofing behaviour (a test-send preview, say, uses this
    fallback deliberately, since the admin IS the recipient there).
    """
    default_from = os.environ.get("SMTP_FROM_ADDRESS", "training@example.com")
    display_from = formataddr((from_name, from_address)) if (from_name and from_address) else default_from

    smtp_host = os.environ.get("SMTP_HOST")

    if not smtp_host:
        OUTBOX_DIR.mkdir(exist_ok=True)
        safe_name = to.replace("@", "_at_").replace(".", "_")
        out_path = OUTBOX_DIR / f"{safe_name}.html"
        # Explicit utf-8: emails commonly contain non-ASCII characters (e.g.
        # the 📎 attachment icon in admin.py), and Path.write_text()'s
        # default encoding is the OS's locale-preferred one — cp1252 on
        # Windows, which can't represent most emoji and raises
        # UnicodeEncodeError ("'charmap' codec can't encode character...").
        # Always writing utf-8 here matches what a real mail send would use
        # and makes mock mode behave the same on every OS.
        out_path.write_text(html_body, encoding="utf-8")
        print(f"[MOCK SEND] From: {display_from} | To: {to} | Subject: {subject} | Saved to {out_path}")
        return

    msg = MIMEText(html_body, "html")
    msg["Subject"] = subject
    msg["From"] = display_from
    msg["To"] = to

    with smtplib.SMTP(smtp_host, int(os.environ.get("SMTP_PORT", 587))) as server:
        server.starttls()
        server.login(os.environ["SMTP_USERNAME"], os.environ["SMTP_PASSWORD"])
        server.send_message(msg)
    print(f"[SENT] From: {display_from} | To: {to} | Subject: {subject}")
