"""
tracking.py
-----------
Public (no-login) endpoints embedded inside simulation emails. Each
recipient's email contains a unique token, so every request here tells us
exactly which employee/campaign-email triggered which event — without
ever transmitting or storing any real password or personal data the
employee might type into the fake form (see /submit below: we log only
the fact that a submission happened, and explicitly discard any posted
form fields).

FLOW: click -> fake login form -> if submitted -> debrief page. An
employee who clicks but never submits is never shown the debrief — a
documented, deliberate limitation (see methodology/limitations).

ATTACHMENT TRACKING: the "attachment" in a generated email is never a
real file embedded in the email (that would require document-level
tracking techniques — e.g. a macro or remote-template injection — which
are genuine malware mechanisms and are deliberately NOT implemented
here, even for a benign training purpose). Instead, the attachment is a
styled link pointing at /track/download/<token>, the same pattern as the
click-tracking link: the platform logs the event, THEN serves a small,
harmless file whose content itself discloses the simulation.
"""

import base64
import io

from flask import Blueprint, request, send_file, render_template, Response

from database import get_db

tracking_bp = Blueprint("tracking", __name__)

# A 1x1 transparent GIF, used as the tracking pixel for "open" events.
PIXEL_GIF = base64.b64decode(
    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBTAA7"
)


MAX_USER_AGENT_LENGTH = 500  # generous for a real UA string; just a sanity cap, never truncating silently-wrong data


def _log_event(token: str, event_type: str, dwell_ms=None):
    """
    dwell_ms (click-timing behavioural signal, novelty feature): only ever
    meaningful for a 'submit' event — see schema.sql's column comment.
    Left as the column default (NULL) for every other event type.

    Also records the requesting browser's IP address (request.remote_addr)
    and User-Agent header for every event type — the same two fields a
    real web server access log would show, surfaced per-event on the
    interaction timeline (see admin.interaction_timeline) rather than
    buried in a server log an admin can't reach. Both are exactly what the
    request itself reports: never geolocated, never cross-referenced
    against anything else, and left NULL if genuinely absent (e.g. no
    User-Agent header sent) rather than defaulted to an empty string that
    could be mistaken for "recorded as blank".
    """
    db = get_db()
    row = db.execute(
        "SELECT id FROM campaign_emails WHERE token = ?", (token,)
    ).fetchone()
    if row is not None:
        ip_address = request.remote_addr
        user_agent = request.headers.get("User-Agent")
        if user_agent:
            user_agent = user_agent[:MAX_USER_AGENT_LENGTH]
        db.execute(
            "INSERT INTO interactions (campaign_email_id, event_type, dwell_ms, ip_address, user_agent) "
            "VALUES (?, ?, ?, ?, ?)",
            (row["id"], event_type, dwell_ms, ip_address, user_agent),
        )
        db.commit()
    db.close()
    return row is not None


def _get_org_name(token: str):
    """Looks up the client organization's name for a given tracking token,
    so the landing/login pages can display real branding instead of a
    placeholder."""
    db = get_db()
    row = db.execute(
        """SELECT o.name FROM campaign_emails ce
           JOIN campaigns c ON ce.campaign_id = c.id
           JOIN organizations o ON c.org_id = o.id
           WHERE ce.token = ?""",
        (token,),
    ).fetchone()
    db.close()
    return row["name"] if row else None


def _get_campaign_info(token: str):
    """
    Looks up the campaign-level context a tracking token belongs to:
    the organization name, which fake-login page style to render
    ('standard' or 'bitb' — see templates/bitb_login.html), and the
    synthetic spoofed-sender identity (services/domain_spoofing.py) used
    to reveal, on the post-click education page, exactly what the
    recipient was shown. Returns None if the token doesn't match anything
    (e.g. a stale/garbage link).
    """
    db = get_db()
    row = db.execute(
        """SELECT o.name AS org_name, c.fake_login_style, c.spoofed_sender_name,
                  c.spoofed_domain, c.spoofed_address
           FROM campaign_emails ce
           JOIN campaigns c ON ce.campaign_id = c.id
           JOIN organizations o ON c.org_id = o.id
           WHERE ce.token = ?""",
        (token,),
    ).fetchone()
    db.close()
    return row


@tracking_bp.route("/track/open/<token>.gif")
def track_open(token):
    _log_event(token, "open")
    return send_file(io.BytesIO(PIXEL_GIF), mimetype="image/gif")


@tracking_bp.route("/track/click/<token>")
def track_click(token):
    """
    Renders the fake-login page the recipient sees after clicking — either
    the 'standard' plain embedded form, or the 'bitb' (Browser-in-the-
    Browser) style that draws a fake browser window chrome around the
    same form, per the campaign's fake_login_style (chosen at creation,
    see admin.py: create_campaign()). Falls back to 'standard' for a
    stale/garbage token with no matching campaign.
    """
    _log_event(token, "click")
    info = _get_campaign_info(token)
    org_name = info["org_name"] if info else None
    style = info["fake_login_style"] if info else "standard"
    template = "bitb_login.html" if style == "bitb" else "fake_login.html"
    return render_template(
        template, token=token, org_name=org_name,
        spoofed_domain=info["spoofed_domain"] if info else None,
    )


@tracking_bp.route("/track/submit/<token>", methods=["GET", "POST"])
def track_submit(token):
    """
    Simulates a credential-harvesting form for measurement purposes only.
    Any POSTed field values are intentionally never read or stored — only
    the fact that a submission occurred is logged.
    """
    info = _get_campaign_info(token)
    org_name = info["org_name"] if info else None
    style = info["fake_login_style"] if info else "standard"
    template = "bitb_login.html" if style == "bitb" else "fake_login.html"

    if request.method == "POST":
        # Click-timing behavioural signal: the form includes a hidden field
        # (populated by a small inline script in fake_login.html /
        # bitb_login.html) recording milliseconds between page-load and
        # submit. Never trusted as anything beyond a rough client-reported
        # timing signal — it's a training-insight metric, not a security
        # control — and left as NULL if missing/unparseable (e.g. JS
        # disabled) rather than coerced to 0, which would misleadingly
        # read as "instant".
        dwell_ms = None
        raw_dwell = request.form.get("dwell_ms", "").strip()
        if raw_dwell.isdigit():
            dwell_ms = int(raw_dwell)

        _log_event(token, "submit", dwell_ms=dwell_ms)
        return render_template(
            "landing_educate.html", found=True, token=token, just_submitted=True, org_name=org_name,
            fake_login_style=style,
            spoofed_sender_name=info["spoofed_sender_name"] if info else None,
            spoofed_address=info["spoofed_address"] if info else None,
        )
    return render_template(
        template, token=token, org_name=org_name,
        spoofed_domain=info["spoofed_domain"] if info else None,
    )


@tracking_bp.route("/track/download/<token>")
def track_download(token):
    """
    Logs the 'download' event, then serves a small, harmless text file as
    the "attachment" — never a real document with embedded tracking, and
    never anything that could execute. The file's own content discloses
    the simulation, since (like the submit flow) there is no page redirect
    after a browser download — the employee only sees this if/when they
    actually open the downloaded file.
    """
    found = _log_event(token, "download")
    org_name = _get_org_name(token) or "your organization"

    disclosure_text = (
        "This was a simulated phishing attachment.\r\n\r\n"
        f"You downloaded this file as part of an authorised security-awareness "
        f"training exercise run by {org_name}.\r\n\r\n"
        "No real attachment, macro, or executable content was ever present in "
        "this file — it contains only this message.\r\n\r\n"
        "What to look for next time:\r\n"
        "- Unexpected attachments from internal senders\r\n"
        "- File names creating urgency (e.g. 'Overdue_Invoice', 'Account_Suspended')\r\n"
        "- Attachments you weren't expecting, even from a colleague\r\n"
    )

    buf = io.BytesIO(disclosure_text.encode("utf-8"))
    return send_file(
        buf,
        mimetype="text/plain",
        as_attachment=True,
        download_name="Document.txt",
    )


@tracking_bp.route("/track/call/<token>")
def track_call(token):
    """
    Callback-phishing / TOAD simulation (novelty feature): logs the
    'called' event, then shows the training debrief immediately — the
    same disclosure landing page used after a fake-login submission (see
    track_submit above), rather than a separate "now dial this number"
    step. See services/pretext_generator.py's TOAD_TEMPLATE docstring for
    why this click is used as the behavioural proxy for "would have
    called the fraudulent number" in the absence of real telephony
    tracking.
    """
    info = _get_campaign_info(token)
    org_name = info["org_name"] if info else None
    _log_event(token, "called")
    return render_template(
        "landing_educate.html", found=True, token=token, just_submitted=False,
        just_called=True, org_name=org_name,
        fake_login_style=info["fake_login_style"] if info else None,
        spoofed_sender_name=info["spoofed_sender_name"] if info else None,
        spoofed_address=info["spoofed_address"] if info else None,
    )


@tracking_bp.route("/track/report/<token>", methods=["POST"])
def track_report(token):
    """Called by the 'Report This to IT' button on the educational landing page."""
    _log_event(token, "report")
    return Response("Thank you for reporting this simulation.", mimetype="text/plain")
