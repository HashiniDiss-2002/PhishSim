"""
admin.py
--------
Routes used by the client admin role:
  - upload employee CSV
  - create and "send" (simulated) a campaign
  - view results dashboard with compliance findings (campaign-level)
  - view a single employee's risk dashboard (employee-level)

Also includes the (very limited) engineer dashboard, which deliberately
shows infrastructure-level info only, never tenant employee data or
campaign content — this is the enforced version of the "engineer has no
access to client data" claim from the proposal.
"""

import csv
import io
import os
import secrets
import sqlite3
import traceback

import requests
from datetime import datetime
from pathlib import Path

import pandas as pd
from flask import (
    Blueprint, render_template, request, redirect, url_for, flash, session, Response,
)
from PIL import Image
from werkzeug.security import generate_password_hash

from auth import role_required, core_admin_required
from database import get_db
from services.audit import log_action, ENGINEER_VISIBLE_ACTIONS
from services.pretext_generator import generate_pretext, generate_toad_pretext, ModerationError
from services.compliance_mapper import (
    get_compliance_findings, compute_employee_risk, compute_employee_overall_risk,
    difficulty_for_tier, compute_persuasion_profile, classify_click_speed, compute_metrics,
    peak_click_period,
)
from services.report_generator import build_csv_report, build_pdf_report, build_roster_csv
from services.threat_intel import extract_structural_features, ThreatIntelError
from services.threat_source_crawler import discover_candidate_articles
from services.threat_trends import compute_trends, CHANNEL_LABELS, CATEGORY_LABELS
from services.attack_mapping import get_campaign_attack_techniques
from services.domain_spoofing import generate_spoofed_sender

# Event types counted/iterated everywhere a campaign's or employee's
# interaction history is summarised — one shared constant so "called" (the
# TOAD/callback-phishing event) can never be added in one place and
# forgotten in another.
EVENT_TYPES = ["open", "click", "submit", "download", "report", "called"]

# Event types that count as "fell for it" for persuasion-profile purposes —
# i.e. the recipient actually acted on the pretext, as opposed to merely
# opening or (the desired behaviour) reporting it.
FELL_FOR_IT_EVENTS = {"click", "submit", "download", "called"}

# Plain-language label + icon for each point on a recipient's interaction
# timeline (admin.interaction_timeline / templates/interaction_timeline.html),
# including the one synthetic entry ("received") that isn't a row in
# `interactions` at all -- it's campaign_emails.sent_at, shown as the first
# point on the same timeline so "when was this even sent" never requires a
# separate lookup. Centralised here, next to EVENT_TYPES, so the timeline
# page and anything else that labels an event type agree.
TIMELINE_EVENT_LABELS = {
    "received": "Received",
    "open": "Opened",
    "click": "Clicked the link",
    "submit": "Submitted the form",
    "download": "Downloaded the attachment",
    "report": "Reported as suspicious",
    "called": "Called the number (TOAD)",
}
TIMELINE_EVENT_ICONS = {
    "received": "mail",
    "open": "inbox",
    "click": "alert-triangle",
    "submit": "key",
    "download": "download",
    "report": "flag",
    "called": "radio",
}

admin_bp = Blueprint("admin", __name__)

# ---------- Logo upload (admin.upload_logo) ----------
#
# Uploaded organization logos are normalized to PNG and stored under
# static/logos/, outside version control. STATIC_DIR mirrors Flask's own
# default static folder location (relative to this file, same as
# app.root_path) so branding.py can serve the same files via send_file.
STATIC_DIR = Path(__file__).parent / "static"
LOGO_DIR = STATIC_DIR / "logos"
MAX_LOGO_BYTES = 2 * 1024 * 1024  # 2 MB

# ---------- Password reset tokens (admin.reset_admin_password) ----------
PASSWORD_RESET_EXPIRY_HOURS = 24

# The links baked into a generated email (tracking pixel, click link,
# download link, logo image) must be reachable by whoever opens that
# email — an external mail client or a sandbox like Mailtrap — not just
# reachable from the admin's own machine. url_for(..., _external=True) by
# itself uses whatever host the ADMIN'S browser happened to use to load
# this page (e.g. "localhost:5000"), which is almost never what you want
# once you're sending through ngrok or deploying anywhere. Set
# PUBLIC_BASE_URL (e.g. "https://abcd-1234.ngrok-free.app", no trailing
# slash) to pin every generated link to that address regardless of how
# the admin is browsing the app. Falls back to the old per-request
# behaviour if it's not set.
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")


def _public_url(endpoint, **values):
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL + url_for(endpoint, **values)
    return url_for(endpoint, _external=True, **values)

# NOTE: there used to be an admin-selected CONTEXT_OPTIONS list here. That
# manual step has been removed — the LLM now chooses the pretext itself
# based on the organization's name and the employee's department, drawing
# on its own general knowledge rather than an admin-curated or live-
# searched context source. See services/pretext_generator.py for the full
# reasoning and the limitation this implies (no live fact verification).


# ---------- Department-admin scoping helpers ----------
#
# An admin account is a "department admin" when users.department is set
# (NOT NULL); a "core admin" when it is NULL. Both share the 'admin' role,
# so @role_required('admin') alone doesn't distinguish them — these helpers
# do, and every admin.py route below applies them consistently.
#
# Two separate checks, not one, because view access is deliberately
# broader than action access:
#   - view access:   a department admin can SEE an org-wide campaign (one
#     with department IS NULL, created by the core admin) because it may
#     include their department's employees, and they should be able to
#     check those employees' stats.
#   - action access: a department admin can only create/send/delete/test-send
#     a campaign that is scoped to their OWN department. They can never
#     modify a core admin's org-wide campaign, even though they can view it.
# A core admin always passes both checks for anything in their organization.

def _is_dept_admin():
    return session.get("department") is not None


def _campaign_view_accessible(campaign, dept):
    """dept is session.get('department'); None means core admin (sees all)."""
    if dept is None:
        return True
    return campaign["department"] is None or campaign["department"] == dept


def _campaign_action_accessible(campaign, dept):
    """Stricter than view access — see module docstring above."""
    if dept is None:
        return True
    return campaign["department"] == dept


# Department-wide persuasion-principle trend, used by the adaptive-content
# engine (create_campaign(), below) as one input into each employee's
# `behavior_profile` — distinct from an individual's own history, which
# compute_persuasion_profile() already covers. Scoped to one organization
# (and, if given, one department) and excludes the campaign currently being
# created, exactly like the per-employee prior_counts query it sits next to.
# Not cached beyond a single create_campaign() call — this is a training
# platform's campaign-creation path, not a hot loop, and dataset sizes here
# are classroom/evaluation-study scale, not production scale.
def _department_persuasion_trend(db, org_id, department, exclude_campaign_id):
    if department:
        rows = db.execute(
            "SELECT ce.id, ce.persuasion_principle FROM campaign_emails ce "
            "JOIN campaigns c ON ce.campaign_id = c.id "
            "JOIN employees e ON ce.employee_id = e.id "
            "WHERE c.org_id = ? AND e.department = ? AND c.id != ?",
            (org_id, department, exclude_campaign_id),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT ce.id, ce.persuasion_principle FROM campaign_emails ce "
            "JOIN campaigns c ON ce.campaign_id = c.id "
            "WHERE c.org_id = ? AND c.id != ?",
            (org_id, exclude_campaign_id),
        ).fetchall()

    persuasion_rows = []
    for row in rows:
        event_types = {
            r["event_type"] for r in db.execute(
                "SELECT DISTINCT event_type FROM interactions WHERE campaign_email_id = ?",
                (row["id"],),
            ).fetchall()
        }
        persuasion_rows.append({
            "persuasion_principle": row["persuasion_principle"],
            "fell_for_it": bool(event_types & FELL_FOR_IT_EVENTS),
        })

    profile = compute_persuasion_profile(persuasion_rows)
    return profile[0] if profile and profile[0]["rate"] > 0 else None


# ---------- Engineer views (no tenant data) ----------

@admin_bp.route("/engineer")
@role_required("engineer")
def engineer_dashboard():
    """
    Engineer-facing view for billing and abuse monitoring. Shows which
    organizations exist and how many campaigns each has run — enough to
    spot an account that's gone quiet (billing) or unusually active
    (possible misuse) — but deliberately stops there: no EMPLOYEE names,
    no campaign names/content, no interaction data. That line is the same
    "engineer has no tenant data access" boundary documented in the
    methodology (see 3.2.2) and enforced by test_flow.py; this just widens
    what counts as safe-to-show aggregate metadata from two numbers to a
    per-organization breakdown of the same kind of number.

    ONE deliberate, narrow exception to that boundary, added alongside
    this docstring: each organization's own CORE ADMIN account (name +
    email) is also shown here — not an employee, not tenant simulation
    data, but the one named, accountable point of contact for that
    organization's use of the platform. If an organization's campaigns
    are misused, or billing/abuse needs to be followed up, the engineer
    needs to know who to contact — the exact same "who do we reach"
    reasoning already applied to support tickets (support_inbox(), where
    the engineer legitimately sees the admin's name/email too). A
    department admin's email is NOT shown here — only the core admin
    (department IS NULL), since they're the one accountable for the
    whole organization's account.
    """
    db = get_db()
    try:
        org_count = db.execute("SELECT COUNT(*) c FROM organizations").fetchone()["c"]
        campaign_count = db.execute("SELECT COUNT(*) c FROM campaigns").fetchone()["c"]
        organizations = db.execute(
            """SELECT o.id, o.name, o.suspended, o.created_at,
                      COUNT(c.id) AS campaign_count,
                      core_admin.full_name AS core_admin_name,
                      core_admin.email AS core_admin_email
               FROM organizations o
               LEFT JOIN campaigns c ON c.org_id = o.id
               LEFT JOIN users core_admin
                      ON core_admin.org_id = o.id
                     AND core_admin.role = 'admin'
                     AND core_admin.department IS NULL
               GROUP BY o.id
               ORDER BY o.name""",
        ).fetchall()
    finally:
        db.close()
    # Per-org rows carry a name, a campaign count, a suspended flag, and
    # the core admin's own name/email (the one documented exception
    # above) — never employee names/emails, campaign names, or any
    # tenant-generated content.
    return render_template(
        "engineer_dashboard.html",
        org_count=org_count, campaign_count=campaign_count, organizations=organizations,
    )


@admin_bp.route("/engineer/org/<int:org_id>/toggle-suspend", methods=["POST"])
@role_required("engineer")
def toggle_org_suspend(org_id):
    """
    Suspends or reactivates an organization's account. A suspended org's
    admin/user accounts are blocked at login (see auth.py) — existing
    sessions aren't force-expired mid-request in this MVP, which is a
    documented limitation, not an oversight; a production version would
    also invalidate active sessions.
    """
    db = get_db()
    try:
        org = db.execute("SELECT * FROM organizations WHERE id = ?", (org_id,)).fetchone()
        if org is None:
            flash("Organization not found.", "danger")
            return redirect(url_for("admin.engineer_dashboard"))

        new_state = 0 if org["suspended"] else 1
        db.execute("UPDATE organizations SET suspended = ? WHERE id = ?", (new_state, org_id))
        log_action(
            db, org_id=org_id, actor_user_id=session["user_id"],
            actor_role=session.get("role"), actor_name=session.get("full_name"),
            action="org_suspended" if new_state else "org_reactivated",
            description=f"Platform engineer {'suspended' if new_state else 'reactivated'} this organization's account.",
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    action = "suspended" if new_state else "reactivated"
    flash(f"Organization '{org['name']}' {action}.", "success")
    return redirect(url_for("admin.engineer_dashboard"))


@admin_bp.route("/engineer/threat-sources", methods=["GET", "POST"])
@role_required("engineer")
def manage_threat_sources():
    """
    Stage 2 automation, engineer-facing half. The engineer is the only
    role that decides which CTI sites are trustworthy enough to scan (a
    listing/category page or an RSS/Atom feed URL) — client admins never
    see or choose a source, and never type a URL or a summary themselves
    (see services/threat_source_crawler.py and services/threat_intel.py).

    Three actions, all POSTed to this same route:
      - add_source: register a new listing/feed URL to scan.
      - delete_source: remove one (its already-discovered scenarios stay,
        since campaigns may already reference them).
      - scan: run discovery + extraction across every registered source,
        skipping articles already in threat_intel_scenarios, and insert a
        new scenario row for every candidate the LLM confirms is actually
        a phishing campaign.
    """
    db = get_db()
    try:
        if request.method == "POST":
            action = request.form.get("action")

            if action == "add_source":
                url = request.form.get("url", "").strip()
                label = request.form.get("label", "").strip() or None
                if not url:
                    flash("Please enter a source URL.", "danger")
                else:
                    try:
                        db.execute(
                            "INSERT INTO threat_intel_sources (url, label, added_by) VALUES (?, ?, ?)",
                            (url, label, session["user_id"]),
                        )
                        db.commit()
                        flash("Source added.", "success")
                    except Exception as e:
                        db.rollback()
                        flash(f"Could not add source (maybe already added?): {e}", "danger")

            elif action == "delete_source":
                source_id = request.form.get("source_id")
                db.execute("DELETE FROM threat_intel_sources WHERE id = ?", (source_id,))
                db.commit()
                flash("Source removed. Previously discovered scenarios from it are kept.", "success")

            elif action == "scan":
                sources = db.execute("SELECT * FROM threat_intel_sources").fetchall()
                existing_urls = {
                    row["article_url"]
                    for row in db.execute("SELECT article_url FROM threat_intel_scenarios").fetchall()
                }
                new_count, rejected_count, error_count, duplicate_count = 0, 0, 0, 0
                for source in sources:
                    try:
                        candidates = discover_candidate_articles(source["url"])
                    except ThreatIntelError as e:
                        error_count += 1
                        print(f"[manage_threat_sources] Scan failed for {source['url']}: {e}")
                        continue
                    for candidate in candidates:
                        if candidate["url"] in existing_urls:
                            continue
                        try:
                            features = extract_structural_features(candidate["url"])
                        except ThreatIntelError:
                            # Either the article couldn't be fetched, or the LLM
                            # judged it doesn't actually describe a phishing
                            # campaign — either way, skip it, not an error.
                            rejected_count += 1
                            continue
                        # existing_urls is only a snapshot taken once at the top
                        # of this request, so it can't see a row inserted by a
                        # second, concurrent "Scan" click (e.g. a double
                        # submit, or the same article reachable via two
                        # different registered sources within this same
                        # loop — handled above by the in-memory set, but not
                        # across two separate requests). Catch the DB's own
                        # UNIQUE constraint on article_url and treat it as
                        # "already discovered," not a crash.
                        try:
                            db.execute(
                                "INSERT INTO threat_intel_scenarios "
                                "(source_id, article_url, article_title, summary, "
                                "delivery_channel, pretext_category_tag) VALUES (?, ?, ?, ?, ?, ?)",
                                (source["id"], features["source_url"], candidate.get("title"),
                                 features["summary"], features.get("delivery_channel", "other"),
                                 features.get("pretext_category_tag", "other")),
                            )
                        except sqlite3.IntegrityError:
                            duplicate_count += 1
                            existing_urls.add(candidate["url"])
                            continue
                        existing_urls.add(candidate["url"])
                        new_count += 1
                db.commit()
                msg = f"Scan complete: {new_count} new scenario(s) discovered."
                if rejected_count:
                    msg += f" {rejected_count} candidate link(s) were skipped (not fetchable, or not confirmed as phishing write-ups)."
                if duplicate_count:
                    msg += f" {duplicate_count} already discovered (skipped)."
                if error_count:
                    msg += f" {error_count} source(s) could not be fetched (see terminal)."
                flash(msg, "success" if new_count else "warning")

            return redirect(url_for("admin.manage_threat_sources"))

        sources = db.execute(
            "SELECT * FROM threat_intel_sources ORDER BY created_at DESC"
        ).fetchall()
        scenarios = db.execute(
            "SELECT * FROM threat_intel_scenarios ORDER BY discovered_at DESC"
        ).fetchall()
    finally:
        db.close()

    # Multi-source trend aggregation (services/threat_trends.py): what's
    # trending ACROSS every registered source's discovered scenarios,
    # not just whichever single article is newest — see that module's
    # docstring for why this is the piece that makes Stage 2 genuine
    # threat intelligence rather than one-article-at-a-time browsing.
    trends = compute_trends(scenarios)

    return render_template(
        "manage_threat_sources.html", sources=sources, scenarios=scenarios,
        trends=trends, channel_labels=CHANNEL_LABELS, category_labels=CATEGORY_LABELS,
    )


# ---------- Admin dashboard aggregation helpers ----------
#
# The dashboard needs org-wide (or department-wide) numbers rather than one
# campaign's — "what's our overall click rate across every campaign we've
# run" — which none of the existing per-campaign helpers compute. These
# reuse the exact same distinct-event-per-recipient counting rule as
# _load_campaign_compliance_data (defined further below) so the dashboard
# and a single campaign's page can never disagree about what a "click"
# means, just at a different scope. No numbers here are invented: a
# campaign with no interactions yet simply contributes zeros, and an org
# with no campaigns gets an all-zero summary rather than a fabricated one.

def _campaign_counts_scoped(db, campaign_id, dept):
    """Same distinct-event-per-recipient counting as campaign_detail's
    _load_campaign_compliance_data, but only the counts dict (no per-email
    detail), and taking a campaign_id directly so it can be called in a
    loop across every campaign visible to this admin."""
    if dept:
        email_rows = db.execute(
            """SELECT ce.id FROM campaign_emails ce JOIN employees e ON ce.employee_id = e.id
               WHERE ce.campaign_id = ? AND e.department = ?""",
            (campaign_id, dept),
        ).fetchall()
    else:
        email_rows = db.execute(
            "SELECT id FROM campaign_emails WHERE campaign_id = ?", (campaign_id,)
        ).fetchall()

    counts = {"total": len(email_rows), **{et: 0 for et in EVENT_TYPES}}
    if email_rows:
        ids = [r["id"] for r in email_rows]
        placeholders = ",".join("?" for _ in ids)
        rows = db.execute(
            f"SELECT campaign_email_id, event_type FROM interactions WHERE campaign_email_id IN ({placeholders})",
            ids,
        ).fetchall()
        seen = set()
        for r in rows:
            key = (r["campaign_email_id"], r["event_type"])
            if key in seen:
                continue
            seen.add(key)
            counts[r["event_type"]] += 1
    return counts


def _dashboard_summary(db, campaigns, dept):
    """
    Builds everything the dashboard's KPI cards, compliance overview, and
    campaign-performance chart need:
      - org_counts: aggregated interaction counts across every campaign
        visible to this admin (dept-scoped where applicable)
      - findings: compliance findings run against those aggregated counts
      - per_campaign: one row per campaign with its own click/report rate,
        for the "performance over time" chart — real historical values
        only, ordered oldest-to-newest so a line chart reads left-to-right
        as a genuine trend, not an invented one
    A campaign with zero recipients (e.g. created but never had employees
    at the time) is skipped from per_campaign to avoid a meaningless 0%
    point, but still contributes (zero) to org_counts.
    """
    org_counts = {"total": 0, **{et: 0 for et in EVENT_TYPES}}
    per_campaign = []
    for c in sorted(campaigns, key=lambda c: c["created_at"]):
        counts = _campaign_counts_scoped(db, c["id"], dept)
        org_counts["total"] += counts["total"]
        for et in EVENT_TYPES:
            org_counts[et] += counts[et]
        if counts["total"] > 0:
            metrics = compute_metrics(counts)
            per_campaign.append({
                "name": c["name"],
                "click_rate": round(metrics["click_rate"] * 100, 1),
                "report_rate": round(metrics["report_rate"] * 100, 1),
                "submit_rate": round(metrics["submit_rate"] * 100, 1),
            })
    findings = get_compliance_findings(org_counts)
    return org_counts, findings, per_campaign


def _format_duration_seconds(seconds):
    """
    Human-readable elapsed time for the "quick responders" widget below —
    an admin reading the dashboard shouldn't have to do mental math on a
    raw second count. Deliberately coarse (no sub-second precision): this
    is a recognition metric ("who reports fastest"), not a forensic timer.
    """
    seconds = round(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, rem_seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {rem_seconds}s" if rem_seconds else f"{minutes}m"
    hours, rem_minutes = divmod(minutes, 60)
    return f"{hours}h {rem_minutes}m" if rem_minutes else f"{hours}h"


def _employee_risk_and_response_rankings(db, employees, org_id):
    """
    Builds the dashboard's two employee-level widgets:
      - top 5 RISKIEST employees, by the same overall (likelihood x
        impact) risk score employee_detail() shows for one person at a
        time (compute_employee_risk + compute_employee_overall_risk) —
        here computed for every employee in scope, so the dashboard can
        surface who most needs attention without an admin opening each
        profile one by one.
      - top 5 QUICKEST RESPONDERS: employees ranked by how fast they
        reported a simulation they recognised as phishing (the time
        between campaign_emails.sent_at and their 'report' interaction's
        occurred_at) — a positive recognition metric, the mirror image of
        the risk list, highlighting good security-awareness behaviour
        rather than only flagging bad behaviour.

    Deliberately a smaller, separate aggregation from employee_detail()'s
    (which also profiles persuasion principles and click-timing dwell_ms)
    so loading the dashboard across every employee in the organisation
    stays cheap, rather than reusing that richer per-employee query here.

    Only employees who've actually been part of at least one campaign are
    eligible for the risk ranking; only those who've reported at least one
    simulation are eligible for the response-speed ranking — an employee
    with no data in either respect is simply left out of both lists
    rather than shown with a fabricated zero.
    """
    summaries = []
    for employee in employees:
        campaign_emails = db.execute(
            """SELECT ce.id, ce.sent_at FROM campaign_emails ce
               JOIN campaigns c ON ce.campaign_id = c.id
               WHERE ce.employee_id = ? AND c.org_id = ?""",
            (employee["id"], org_id),
        ).fetchall()
        if not campaign_emails:
            continue  # never part of a campaign -- nothing to rank

        counts = {"total": len(campaign_emails), **{et: 0 for et in EVENT_TYPES}}
        response_seconds = []
        sent_at_by_id = {ce["id"]: ce["sent_at"] for ce in campaign_emails}
        ids = [ce["id"] for ce in campaign_emails]
        placeholders = ",".join("?" for _ in ids)
        # Ordered oldest-first so that, for an employee with more than one
        # 'report' row against the same email (shouldn't normally happen,
        # but not schema-enforced), the FIRST time they reported it is
        # what counts as their response time -- not whichever row the
        # database happens to return first.
        rows = db.execute(
            f"SELECT campaign_email_id, event_type, occurred_at FROM interactions "
            f"WHERE campaign_email_id IN ({placeholders}) ORDER BY occurred_at ASC",
            ids,
        ).fetchall()
        seen_events = set()
        reported_email_ids = set()
        for r in rows:
            key = (r["campaign_email_id"], r["event_type"])
            if key not in seen_events:
                seen_events.add(key)
                counts[r["event_type"]] += 1
            if r["event_type"] == "report" and r["campaign_email_id"] not in reported_email_ids:
                reported_email_ids.add(r["campaign_email_id"])
                sent_at = sent_at_by_id.get(r["campaign_email_id"])
                if sent_at:
                    try:
                        delta = (
                            datetime.fromisoformat(r["occurred_at"])
                            - datetime.fromisoformat(sent_at)
                        ).total_seconds()
                        if delta >= 0:
                            response_seconds.append(delta)
                    except ValueError:
                        pass  # malformed/legacy timestamp -- skip rather than guess

        likelihood = compute_employee_risk(counts)
        risk = compute_employee_overall_risk(likelihood, employee["department"])
        avg_response_seconds = (
            round(sum(response_seconds) / len(response_seconds)) if response_seconds else None
        )
        summaries.append({
            "employee": employee,
            "risk": risk,
            "avg_response_seconds": avg_response_seconds,
            "reported_count": len(response_seconds),
        })

    top_risky = sorted(summaries, key=lambda s: s["risk"]["score"], reverse=True)[:5]

    responders = [s for s in summaries if s["avg_response_seconds"] is not None]
    top_responders = sorted(responders, key=lambda s: s["avg_response_seconds"])[:5]
    for s in top_responders:
        s["avg_response_label"] = _format_duration_seconds(s["avg_response_seconds"])

    return top_risky, top_responders


# ---------- Admin views (own tenant only) ----------

@admin_bp.route("/admin")
@role_required("admin")
def admin_dashboard():
    db = get_db()
    try:
        org_id = session["org_id"]
        dept = session.get("department")

        if dept:
            # Department admin: only their own department's employees...
            employees = db.execute(
                "SELECT * FROM employees WHERE org_id = ? AND department = ?", (org_id, dept)
            ).fetchall()
            # ...and campaigns either scoped to their department, or org-wide
            # campaigns (department IS NULL) that touch at least one of
            # their department's employees — found via a join so a core
            # admin's org-wide campaign still shows up for visibility, even
            # though (per _campaign_action_accessible) it can't be managed
            # from here.
            campaigns = db.execute(
                """SELECT DISTINCT c.* FROM campaigns c
                   LEFT JOIN campaign_emails ce ON ce.campaign_id = c.id
                   LEFT JOIN employees e ON e.id = ce.employee_id
                   WHERE c.org_id = ?
                     AND (c.department = ? OR (c.department IS NULL AND e.department = ?))
                   ORDER BY c.created_at DESC""",
                (org_id, dept, dept),
            ).fetchall()
        else:
            # Core admin: everything in the organization.
            employees = db.execute("SELECT * FROM employees WHERE org_id = ?", (org_id,)).fetchall()
            campaigns = db.execute(
                "SELECT * FROM campaigns WHERE org_id = ? ORDER BY created_at DESC", (org_id,)
            ).fetchall()
        org_counts, findings, per_campaign = _dashboard_summary(db, campaigns, dept)
        top_risky, top_responders = _employee_risk_and_response_rankings(db, employees, org_id)
        org_name = db.execute(
            "SELECT name FROM organizations WHERE id = ?", (org_id,)
        ).fetchone()["name"]
    finally:
        db.close()
    actionable_campaign_ids = {
        c["id"] for c in campaigns if _campaign_action_accessible(c, dept)
    }
    org_metrics = compute_metrics(org_counts)
    # Recent activity: the most recently created campaigns this admin can
    # already see (campaigns is already dept-scoped above), newest first —
    # deliberately built from data already on this page rather than a
    # fresh audit_log query, so a department admin's dashboard can never
    # surface another department's or the core admin's actions (the full
    # audit_log table isn't dept-scoped; see audit_log()/manage_department_admins()
    # being core-admin-only for the same reason).
    recent_campaigns = sorted(campaigns, key=lambda c: c["created_at"], reverse=True)[:5]
    return render_template(
        "admin_dashboard.html", employees=employees, campaigns=campaigns,
        is_dept_admin=_is_dept_admin(), department=dept, org_name=org_name,
        actionable_campaign_ids=actionable_campaign_ids,
        org_counts=org_counts, org_metrics=org_metrics, findings=findings,
        per_campaign=per_campaign, recent_campaigns=recent_campaigns,
        top_risky=top_risky, top_responders=top_responders,
    )


@admin_bp.route("/admin/settings/logo", methods=["POST"])
@core_admin_required
def upload_logo():
    """
    Lets the core admin upload a real logo image to replace the generated
    placeholder banner (branding.py) used at the top of every simulation
    email. Gated core-admin-only, like manage_department_admins — a
    department admin never sees this form (see templates/settings.html).

    The uploaded file is validated as genuine image data — Image.open()
    then .verify() — and re-saved as PNG under a per-org filename rather
    than trusting the original bytes/extension/content-type. This both
    rejects a disguised non-image payload and means branding.py never has
    to branch on upload format.
    """
    file = request.files.get("logo_file")
    if not file or file.filename == "":
        flash("Please choose a logo image to upload.", "danger")
        return redirect(url_for("auth.settings"))

    raw = file.read()
    if len(raw) > MAX_LOGO_BYTES:
        flash("Logo file is too large (max 2 MB).", "danger")
        return redirect(url_for("auth.settings"))

    try:
        # verify() confirms this is genuinely image data, but leaves the
        # image object unusable for anything else afterwards — so the file
        # must be reopened from the same bytes to actually read/convert it.
        Image.open(io.BytesIO(raw)).verify()
        img = Image.open(io.BytesIO(raw)).convert("RGB")
    except Exception:
        flash("That file doesn't look like a valid image.", "danger")
        return redirect(url_for("auth.settings"))

    org_id = session["org_id"]
    LOGO_DIR.mkdir(parents=True, exist_ok=True)
    logo_filename = f"org_{org_id}.png"
    img.save(LOGO_DIR / logo_filename, format="PNG")

    db = get_db()
    try:
        db.execute(
            "UPDATE organizations SET logo_path = ? WHERE id = ?",
            (f"logos/{logo_filename}", org_id),
        )
        log_action(
            db, org_id=org_id, actor_user_id=session["user_id"],
            actor_role=session.get("role"), actor_name=session.get("full_name"),
            action="logo_uploaded",
            description="Uploaded a new organization logo, replacing the generated placeholder banner.",
        )
        db.commit()
    finally:
        db.close()

    flash("Logo uploaded — it will appear on all future campaign emails.", "success")
    return redirect(url_for("auth.settings"))


@admin_bp.route("/admin/employees/export.csv")
@role_required("admin")
def export_employees_csv():
    """
    Downloadable CSV of the current employee roster, including each
    employee's up-to-date risk score and tier (services/compliance_mapper.py)
    computed fresh from their full interaction history across every
    campaign in this organization — the same computation employee_detail()
    uses, not a stored/stale value. Scoped exactly like admin_dashboard():
    a department admin only ever gets their own department's employees.
    """
    org_id = session["org_id"]
    dept = session.get("department")
    db = get_db()
    try:
        if dept:
            employees = db.execute(
                "SELECT * FROM employees WHERE org_id = ? AND department = ?", (org_id, dept)
            ).fetchall()
        else:
            employees = db.execute("SELECT * FROM employees WHERE org_id = ?", (org_id,)).fetchall()

        rows = []
        for emp in employees:
            campaign_emails = db.execute(
                """SELECT ce.id FROM campaign_emails ce JOIN campaigns c ON ce.campaign_id = c.id
                   WHERE ce.employee_id = ? AND c.org_id = ?""",
                (emp["id"], org_id),
            ).fetchall()
            counts = {"total": len(campaign_emails), **{et: 0 for et in EVENT_TYPES}}
            for ce in campaign_emails:
                events = db.execute(
                    "SELECT DISTINCT event_type FROM interactions WHERE campaign_email_id = ?",
                    (ce["id"],),
                ).fetchall()
                event_types = {row["event_type"] for row in events}
                for et in EVENT_TYPES:
                    if et in event_types:
                        counts[et] += 1
            # Roster export shows the final RISK figure (likelihood x
            # department impact weight), not raw behavioural likelihood —
            # an admin deciding where to prioritise training should see
            # business risk, the same number shown on each employee's
            # profile page.
            likelihood = compute_employee_risk(counts)
            risk = compute_employee_overall_risk(likelihood, emp["department"])
            rows.append({
                "full_name": emp["full_name"], "email": emp["email"],
                "department": emp["department"], "job_title": emp["job_title"],
                "campaigns": counts["total"], "risk_score": risk["score"], "risk_tier": risk["tier"],
                "impact_weight": risk["impact_weight"],
            })

        log_action(
            db, org_id=org_id, actor_user_id=session["user_id"],
            actor_role=session.get("role"), actor_name=session.get("full_name"),
            action="roster_exported",
            description=f"Downloaded employee roster CSV ({len(rows)} employee(s)).",
        )
        db.commit()
    finally:
        db.close()

    csv_bytes = build_roster_csv(rows)
    return Response(
        csv_bytes, mimetype="text/csv",
        headers={"Content-Disposition": 'attachment; filename="phishsim_employee_roster.csv"'},
    )


@admin_bp.route("/admin/upload/template.csv")
@role_required("admin")
def download_roster_template():
    """
    A blank-to-fill CSV template matching exactly what upload_employees()
    below requires/reads: the three required columns (full_name, email,
    department) plus the one optional column it also reads (job_title),
    with the same two example rows shown on upload.html — so an admin can
    download this, replace the example rows with their real roster, and
    upload it straight back without guessing the expected column names or
    order. No DB access needed — this is static content, not a per-org
    export (compare export_employees_csv() above, which IS a live export
    of the org's actual roster).
    """
    template_csv = (
        "full_name,email,department,job_title\r\n"
        "Jordan Lee,jordan.lee@example.com,Finance,Analyst\r\n"
        "Morgan Diaz,morgan.diaz@example.com,IT,Support Engineer\r\n"
    )
    return Response(
        template_csv, mimetype="text/csv",
        headers={"Content-Disposition": 'attachment; filename="phishsim_employee_roster_template.csv"'},
    )


@admin_bp.route("/admin/upload", methods=["GET", "POST"])
@role_required("admin")
def upload_employees():
    if request.method == "POST":
        file = request.files.get("csv_file")
        if not file or file.filename == "":
            flash("Please choose a CSV file.", "danger")
            return redirect(url_for("admin.upload_employees"))

        try:
            df = pd.read_csv(file)
            required_cols = {"full_name", "email", "department"}
            if not required_cols.issubset(set(c.strip() for c in df.columns)):
                flash(f"CSV must contain columns: {', '.join(required_cols)}", "danger")
                return redirect(url_for("admin.upload_employees"))
        except Exception as e:
            flash(f"Could not read CSV: {e}", "danger")
            return redirect(url_for("admin.upload_employees"))

        db = get_db()
        try:
            org_id = session["org_id"]
            dept = session.get("department")
            added, skipped = 0, 0
            for _, row in df.iterrows():
                # A department admin can only ever add employees into their
                # own department — the CSV's own department column (if any)
                # is overridden rather than trusted, so there's no way to
                # smuggle another department's employees in through a CSV
                # that happens to say otherwise.
                row_department = dept if dept else row.get("department", "")
                try:
                    db.execute(
                        "INSERT INTO employees (org_id, full_name, email, department, job_title) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (org_id, row["full_name"], row["email"].strip().lower(),
                         row_department, row.get("job_title", "")),
                    )
                    added += 1
                except Exception:
                    skipped += 1  # likely a duplicate email for this org

            log_action(
                db, org_id=org_id, actor_user_id=session["user_id"],
                actor_role=session.get("role"), actor_name=session.get("full_name"),
                action="employees_uploaded",
                description=f"Uploaded employee CSV: {added} added, {skipped} duplicates skipped.",
            )
            db.commit()
        finally:
            db.close()

        flash(f"Imported {added} employees ({skipped} duplicates skipped).", "success")
        return redirect(url_for("admin.admin_dashboard"))

    return render_template("upload.html", is_dept_admin=_is_dept_admin(), department=session.get("department"))


@admin_bp.route("/admin/campaign/new", methods=["GET", "POST"])
@role_required("admin")
def create_campaign():
    org_id = session["org_id"]
    dept = session.get("department")
    db = get_db()

    if request.method == "POST":
        try:
            # A department admin's campaign can only ever target their own
            # department's employees, regardless of what the roster contains.
            if dept:
                employees = db.execute(
                    "SELECT * FROM employees WHERE org_id = ? AND department = ?", (org_id, dept)
                ).fetchall()
            else:
                employees = db.execute("SELECT * FROM employees WHERE org_id = ?", (org_id,)).fetchall()

            name = request.form["name"]
            condition = request.form["condition"]  # 'generic' or 'personalized'

            # Stage 2 (optional, fully automated): the admin picks from a
            # LIST of scenarios the platform engineer's system already
            # discovered and extracted — they never type a URL or a summary
            # themselves. See services/threat_source_crawler.py (discovery)
            # and services/threat_intel.py (LLM extraction), and the
            # engineer-only /engineer/threat-sources page that runs them.
            # Blank selection means an ordinary Stage 1 campaign.
            stage2_reference = None
            stage2_source_url = None
            stage2_scenario_id = request.form.get("stage2_scenario_id", "").strip()
            if stage2_scenario_id:
                scenario = db.execute(
                    "SELECT * FROM threat_intel_scenarios WHERE id = ?", (stage2_scenario_id,)
                ).fetchone()
                if scenario is not None:
                    stage2_reference = scenario["summary"]
                    stage2_source_url = scenario["article_url"]
                else:
                    flash(
                        "The selected Stage 2 scenario no longer exists — campaign was created "
                        "as an ordinary Stage 1 campaign instead.", "warning",
                    )

            org = db.execute("SELECT name FROM organizations WHERE id = ?", (org_id,)).fetchone()

            # Sender/domain spoofing simulation (services/domain_spoofing.py):
            # one synthetic look-alike identity generated per CAMPAIGN (not
            # per employee), so every recipient sees the same consistent
            # "From" across the whole campaign — exactly like a real
            # spoofed-sender phishing run would. Never a real third-party
            # domain; see that module's docstring.
            spoof = generate_spoofed_sender(org["name"])

            # Which fake-login page style this campaign's click-through link
            # renders — see tracking.py: track_click() and templates/
            # bitb_login.html. Defaults to 'standard' if the form field is
            # missing/garbage rather than erroring.
            fake_login_style = request.form.get("fake_login_style", "standard")
            if fake_login_style not in ("standard", "bitb"):
                fake_login_style = "standard"

            # Delivery vector (novelty feature: callback phishing / TOAD
            # simulation). 'email_link' is the original behaviour; when
            # 'callback_toad' is chosen, every email in this campaign uses
            # the fixed TOAD template (see services/pretext_generator.py)
            # instead of the LLM/generic pretext, and has no fake-login
            # link at all — just a fictional phone number.
            vector = request.form.get("vector", "email_link")
            if vector not in ("email_link", "callback_toad"):
                vector = "email_link"

            # pretext_context is kept as a column for backward compatibility
            # with the existing schema, but is no longer admin-supplied —
            # the LLM now chooses the pretext itself (see pretext_generator.py).
            # department is NULL for a core admin (org-wide campaign) or set
            # to the department admin's own department (scoped campaign).
            cur = db.execute(
                "INSERT INTO campaigns (org_id, name, condition, pretext_context, department, "
                "stage2_reference, stage2_source_url, spoofed_sender_name, spoofed_domain, "
                "spoofed_address, fake_login_style, vector, created_by, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft')",
                (org_id, name, condition, "LLM-selected per employee", dept, stage2_reference,
                 stage2_source_url, spoof["display_name"], spoof["lookalike_domain"],
                 spoof["spoofed_address"], fake_login_style, vector, session["user_id"]),
            )
            campaign_id = cur.lastrowid

            # Commit the campaign row right away, rather than leaving it
            # part of one long transaction spanning the whole generation
            # loop below. See the per-employee commit inside that loop for
            # the full reasoning — this is the same fix, applied one
            # statement earlier.
            db.commit()

            errors = 0
            api_failures = 0  # distinct from moderation `errors` — see the
            # requests.exceptions.RequestException handler below
            # Department-wide persuasion trend, used below as one input into
            # each employee's behavior_profile — computed once per
            # department actually present in this campaign's recipient
            # list, not once per employee (the result only depends on
            # department + org, so re-running it per employee would be
            # redundant N+1 work for no benefit).
            dept_trend_cache = {}

            # Pretext-generation pacing: a small pause between employees'
            # LLM calls, mirroring send_campaign()'s SEND_DELAY_SECONDS
            # pattern above. Only applied when a real GROQ_API_KEY is set
            # and the campaign actually calls the LLM per employee
            # (condition='generic' and vector='callback_toad' both use a
            # fixed template and never call the LLM, so pacing them would
            # only slow the campaign down for no benefit; mock mode makes
            # no real network call either). Prevents exactly the failure
            # this project hit in practice: Groq's free-tier per-minute
            # rate limit being exceeded by calling the LLM once per
            # employee back-to-back with no pause — see the
            # implementation-issues/departures table.
            import time  # local import, same style as send_campaign()'s pacing delay
            PRETEXT_DELAY_SECONDS = float(os.environ.get("PRETEXT_DELAY_SECONDS", "1"))
            _pace_llm_calls = (
                bool(os.environ.get("GROQ_API_KEY"))
                and condition != "generic"
                and vector != "callback_toad"
            )

            for emp_index, emp in enumerate(employees):
                if _pace_llm_calls and emp_index > 0:
                    time.sleep(PRETEXT_DELAY_SECONDS)
                # Adaptive difficulty engine: look at this employee's risk
                # tier from their history BEFORE this campaign (every
                # campaign_email created below is for the CURRENT campaign,
                # so this query only ever sees prior ones) and map it to a
                # difficulty level. No history yet -> 'standard' (the
                # mapping's own default for an unseen tier only kicks in if
                # 'total' is 0, which compute_employee_risk already handles
                # by scoring 0 / "Low" -> 'advanced'; new-employee handling
                # is deliberately the same as a clean-history employee,
                # since there's no evidence either way).
                #
                # The same query also now drives the adaptive-CONTENT engine
                # (behavior_profile, below): persuasion_principle per prior
                # email plus every interaction's event_type and occurred_at,
                # so the loop reads each prior email's interactions once and
                # reuses the result for difficulty, persuasion profiling,
                # click-speed, and peak-click-time — rather than querying
                # the same rows four separate times.
                prior_emails = db.execute(
                    "SELECT ce.id, ce.persuasion_principle FROM campaign_emails ce "
                    "JOIN campaigns c ON ce.campaign_id = c.id "
                    "WHERE ce.employee_id = ? AND c.org_id = ? AND c.id != ?",
                    (emp["id"], org_id, campaign_id),
                ).fetchall()
                prior_counts = {"total": len(prior_emails), "click": 0, "download": 0, "submit": 0, "report": 0}
                persuasion_rows = []
                click_timestamps = []
                dwell_samples = []
                for pe in prior_emails:
                    interaction_rows = db.execute(
                        "SELECT event_type, occurred_at, dwell_ms FROM interactions "
                        "WHERE campaign_email_id = ?",
                        (pe["id"],),
                    ).fetchall()
                    prior_events = {row["event_type"] for row in interaction_rows}
                    for et in ("click", "download", "submit", "report"):
                        if et in prior_events:
                            prior_counts[et] += 1
                    persuasion_rows.append({
                        "persuasion_principle": pe["persuasion_principle"],
                        "fell_for_it": bool(prior_events & FELL_FOR_IT_EVENTS),
                    })
                    for row in interaction_rows:
                        if row["event_type"] == "click":
                            click_timestamps.append(row["occurred_at"])
                        if row["event_type"] == "submit" and row["dwell_ms"] is not None:
                            dwell_samples.append(row["dwell_ms"])
                if prior_counts["total"] == 0:
                    difficulty = "standard"
                else:
                    # Deliberately the unweighted LIKELIHOOD score, not
                    # compute_employee_overall_risk()'s impact-weighted
                    # figure — how hard the next pretext should be depends
                    # only on how easily this person is actually fooled,
                    # never on their department's business-impact weight
                    # (see compliance_mapper.py's module docstring).
                    prior_risk = compute_employee_risk(prior_counts)
                    difficulty = difficulty_for_tier(prior_risk["tier"])

                # behavior_profile: the adaptive-CONTENT engine (as opposed
                # to the adaptive-DIFFICULTY engine above) — real signal
                # from this employee's own history (which persuasion
                # principle they've actually fallen for, when they tend to
                # click, how fast they submit) plus their department's
                # trend, folded into the LLM prompt by generate_pretext().
                # None of this changes anything for condition='generic'
                # (the fixed control template) or vector='callback_toad'
                # (also a fixed template) — generate_pretext()/
                # generate_toad_pretext() simply never receive it for those.
                emp_persuasion_profile = compute_persuasion_profile(persuasion_rows)
                top_principle = (
                    emp_persuasion_profile[0]
                    if emp_persuasion_profile and emp_persuasion_profile[0]["rate"] > 0
                    else None
                )
                peak_period = peak_click_period(click_timestamps)
                avg_dwell = round(sum(dwell_samples) / len(dwell_samples)) if dwell_samples else None
                click_speed_label = classify_click_speed(avg_dwell)

                emp_department = emp["department"] or "General"
                if emp_department not in dept_trend_cache:
                    dept_trend_cache[emp_department] = _department_persuasion_trend(
                        db, org_id, emp["department"], campaign_id
                    )
                dept_trend = dept_trend_cache[emp_department]

                behavior_profile = None
                if top_principle or peak_period or click_speed_label or dept_trend:
                    behavior_profile = {
                        "top_principle": top_principle["principle"] if top_principle else None,
                        "top_principle_rate": top_principle["rate"] if top_principle else None,
                        "peak_click_period": peak_period,
                        "click_speed_label": click_speed_label,
                        "dept_top_principle": dept_trend["principle"] if dept_trend else None,
                        "dept_top_principle_rate": dept_trend["rate"] if dept_trend else None,
                    }

                try:
                    if vector == "callback_toad":
                        content = generate_toad_pretext(
                            employee_name=emp["full_name"],
                            department=emp["department"] or "General",
                            org_name=org["name"],
                        )
                    else:
                        content = generate_pretext(
                            employee_name=emp["full_name"],
                            department=emp["department"] or "General",
                            org_name=org["name"],
                            condition=condition,
                            real_world_reference=stage2_reference,
                            difficulty=difficulty,
                            behavior_profile=behavior_profile,
                        )
                except ModerationError:
                    errors += 1
                    continue
                except requests.exceptions.RequestException as e:
                    # A persistent LLM-API failure (rate limit exhausted
                    # past all retries, timeout, outage) for ONE employee
                    # must not roll back every other employee's already-
                    # generated pretext in this same campaign — the same
                    # reasoning as send_campaign()'s per-recipient
                    # isolation (see that function's docstring): an error
                    # reaching us here means nothing has been written to
                    # the database for this employee yet (the
                    # campaign_emails INSERT happens further below, after
                    # a successful generate_pretext/generate_toad_pretext
                    # call), so skipping is safe — no partial row, no
                    # rollback needed, and the employees already processed
                    # keep their generated content.
                    print("=" * 70)
                    print("PRETEXT GENERATION FAILED FOR ONE EMPLOYEE — skipping, campaign continues:")
                    print(f"Employee: {emp['full_name']}, error type: {type(e).__name__}")
                    print(f"Error message: {e}")
                    traceback.print_exc()
                    print("=" * 70)
                    api_failures += 1
                    continue
                except Exception as e:
                    print("=" * 70)
                    print("CAMPAIGN GENERATION FAILED — full details below:")
                    print(f"Employee: {emp['full_name']}, error type: {type(e).__name__}")
                    print(f"Error message: {e}")
                    traceback.print_exc()
                    print("=" * 70)

                    # Note: this is no longer "nothing was saved" — the
                    # campaign row and every employee processed BEFORE this
                    # one were already committed individually above, so
                    # they remain in the database. db.rollback() here only
                    # discards whatever uncommitted work exists for the
                    # CURRENT employee (there is none, since generation
                    # failed before any INSERT for them was attempted).
                    db.rollback()
                    flash(
                        f"Campaign generation stopped partway through, after an unexpected error: "
                        f"{type(e).__name__}: {e} (see terminal for full details). "
                        f"Emails already generated for earlier employees in this campaign were saved "
                        f"— you can view the campaign and decide whether to retry the rest.",
                        "danger",
                    )
                    return redirect(url_for("admin.campaign_detail", campaign_id=campaign_id))

                token = secrets.token_urlsafe(16)
                tracking_pixel = _public_url("tracking.track_open", token=token)
                logo_url = _public_url("branding.org_logo", org_id=org_id)

                if vector == "callback_toad":
                    # No fake-login tracking link at all for this vector —
                    # only the phone-number "click to call" redirect (see
                    # services/pretext_generator.py's TOAD_TEMPLATE
                    # docstring for the honest limitation this represents).
                    call_link = _public_url("tracking.track_call", token=token)
                    html_body = content["html_body"].replace("{call_link}", call_link)
                else:
                    tracking_link = _public_url("tracking.track_click", token=token)
                    html_body = content["html_body"].replace("{tracking_link}", tracking_link)

                org_name_for_alt = org["name"]
                banner_html = (
                    f'<img src="{logo_url}" width="600" height="120" alt="{org_name_for_alt}" '
                    f'style="display:block; width:100%; max-width:600px; height:auto; '
                    f'border:0; margin-bottom:16px;">'
                )
                html_body = banner_html + html_body

                # If the LLM decided this pretext realistically includes an
                # attachment, add a styled attachment element linking to the
                # tracked download route — see tracking.py for why this is
                # never a real embedded file. (Never set for the TOAD
                # template — generate_toad_pretext() always returns None.)
                attachment_filename = content.get("attachment_filename")
                if attachment_filename:
                    download_link = _public_url("tracking.track_download", token=token)
                    attachment_html = (
                        f'<div style="margin-top:12px; padding:12px 16px; '
                        f'background:#f5f5f5; border:1px solid #ddd; border-radius:6px; '
                        f'display:flex; align-items:center; gap:10px; max-width:400px; '
                        f'font-family:Arial,sans-serif;">'
                        f'<span style="font-size:22px;">📎</span>'
                        f'<a href="{download_link}" style="color:#1a0dab; text-decoration:none; '
                        f'font-size:14px;">{attachment_filename}</a>'
                        f'</div>'
                    )
                    html_body += attachment_html

                html_body += (
                    f'<img src="{tracking_pixel}" width="1" height="1" alt="" '
                    f'style="display:none;">'
                )

                db.execute(
                    "INSERT INTO campaign_emails (campaign_id, employee_id, token, subject, html_body, "
                    "has_attachment, persuasion_principle, difficulty_level) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (campaign_id, emp["id"], token, content["subject"], html_body,
                     1 if attachment_filename else 0, content.get("persuasion_principle"),
                     difficulty if vector != "callback_toad" else "standard"),
                )
                # Commit after EACH employee, not once at the end of the
                # whole loop. With PRETEXT_DELAY_SECONDS pacing (needed to
                # stay under Groq's free-tier tokens-per-minute limit — see
                # services/pretext_generator.py), this loop can now run for
                # minutes on a multi-employee campaign. Holding one
                # uncommitted transaction open for that entire time blocks
                # every OTHER write to the database (a tracking pixel hit,
                # a login, an audit-log entry — anything), which is exactly
                # what produced the "database is locked" error hit in
                # practice. Committing per employee keeps each write's lock
                # duration down to roughly one INSERT, the same reasoning
                # as send_campaign()'s per-recipient commit.
                db.commit()

            stage_label = "Stage 2 (real-world-informed)" if stage2_reference else "Stage 1"
            log_action(
                db, org_id=org_id, actor_user_id=session["user_id"],
                actor_role=session.get("role"), actor_name=session.get("full_name"),
                action="campaign_created",
                description=(
                    f"Created campaign '{name}' ({condition}, {stage_label}) — "
                    f"{len(employees) - errors - api_failures} emails generated"
                    + (f", {errors} blocked by moderation" if errors else "")
                    + (f", {api_failures} skipped after an LLM-service error" if api_failures else "")
                    + "."
                ),
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

        msg = (
            f"Campaign '{name}' created with "
            f"{len(employees) - errors - api_failures} emails generated."
        )
        if errors:
            msg += f" {errors} were blocked by the moderation filter."
        if api_failures:
            msg += (
                f" {api_failures} employee(s) were skipped after the LLM service kept "
                f"returning errors (see terminal) — you can retry for just those employees."
            )
        flash(msg, "success" if not api_failures else "warning")
        return redirect(url_for("admin.campaign_detail", campaign_id=campaign_id))

    try:
        if dept:
            employees = db.execute(
                "SELECT * FROM employees WHERE org_id = ? AND department = ?", (org_id, dept)
            ).fetchall()
        else:
            employees = db.execute("SELECT * FROM employees WHERE org_id = ?", (org_id,)).fetchall()

        # Stage 2 scenarios available to pick from: discovered and
        # structurally extracted automatically by the platform engineer's
        # threat-source scan (see services/threat_source_crawler.py and
        # services/threat_intel.py). Admins only ever select one of these —
        # they never type a URL or a summary themselves.
        stage2_scenarios = db.execute(
            "SELECT * FROM threat_intel_scenarios ORDER BY discovered_at DESC"
        ).fetchall()
    finally:
        db.close()
    return render_template(
        "create_campaign.html", employees=employees, is_dept_admin=_is_dept_admin(),
        department=dept, stage2_scenarios=stage2_scenarios,
        channel_labels=CHANNEL_LABELS,
    )


def _load_campaign_compliance_data(db, campaign_id, org_id, dept):
    """
    Shared by campaign_detail() and the report-export routes below, so
    there is exactly one place that defines "what counts as this
    campaign's result" — the on-screen dashboard and the downloaded
    report can never silently drift apart.

    Returns (campaign, emails, counts, per_email_events) or
    (None, None, None, None) if the campaign doesn't exist or isn't
    accessible to this admin (the view-access check, same as
    campaign_detail — a department admin may still only ever see the
    rows for their own department's employees, even on an org-wide
    campaign).
    """
    campaign = db.execute(
        "SELECT * FROM campaigns WHERE id = ? AND org_id = ?", (campaign_id, org_id)
    ).fetchone()
    if campaign is None or not _campaign_view_accessible(campaign, dept):
        return None, None, None, None

    if dept:
        emails = db.execute(
            """SELECT ce.*, e.full_name, e.email, e.department
               FROM campaign_emails ce JOIN employees e ON ce.employee_id = e.id
               WHERE ce.campaign_id = ? AND e.department = ?""",
            (campaign_id, dept),
        ).fetchall()
    else:
        emails = db.execute(
            """SELECT ce.*, e.full_name, e.email, e.department
               FROM campaign_emails ce JOIN employees e ON ce.employee_id = e.id
               WHERE ce.campaign_id = ?""",
            (campaign_id,),
        ).fetchall()

    counts = {"total": len(emails), **{et: 0 for et in EVENT_TYPES}}
    per_email_events = {}
    for email in emails:
        events = db.execute(
            "SELECT DISTINCT event_type FROM interactions WHERE campaign_email_id = ?",
            (email["id"],),
        ).fetchall()
        event_types = {row["event_type"] for row in events}
        per_email_events[email["id"]] = event_types
        for et in EVENT_TYPES:
            if et in event_types:
                counts[et] += 1

    return campaign, emails, counts, per_email_events


@admin_bp.route("/admin/campaign/<int:campaign_id>")
@role_required("admin")
def campaign_detail(campaign_id):
    db = get_db()
    try:
        org_id = session["org_id"]
        dept = session.get("department")
        campaign, emails, counts, per_email_events = _load_campaign_compliance_data(
            db, campaign_id, org_id, dept
        )
        if campaign is None:
            flash("Campaign not found.", "danger")
            return redirect(url_for("admin.admin_dashboard"))
    finally:
        db.close()

    findings = get_compliance_findings(counts)
    attack_techniques = get_campaign_attack_techniques(
        any(e["has_attachment"] for e in emails)
    )

    return render_template(
        "campaign_results.html",
        campaign=campaign,
        emails=emails,
        counts=counts,
        per_email_events=per_email_events,
        findings=findings,
        can_manage=_campaign_action_accessible(campaign, dept),
        attack_techniques=attack_techniques,
    )


@admin_bp.route("/admin/campaign-email/<int:campaign_email_id>/timeline")
@role_required("admin")
def interaction_timeline(campaign_email_id):
    """
    Full per-recipient event timeline for one generated email: when it was
    sent ("received"), and every tracked interaction since (open/click/
    submit/download/report/called), each with its own timestamp, IP
    address, and User-Agent string (see tracking.py: _log_event()) — the
    same level of detail a raw web-server access log would show, but
    scoped to one recipient and presented in plain language rather than
    requiring server access. Linked from campaign_results.html (per
    recipient row) and employee_detail.html (per simulation-history row).

    View-access only (same _campaign_view_accessible rule as
    campaign_detail/_load_campaign_compliance_data) — a department admin
    can see this for their own department's employees (and an org-wide
    campaign that touches their department), never another department's.
    """
    db = get_db()
    try:
        org_id = session["org_id"]
        dept = session.get("department")

        row = db.execute(
            """SELECT ce.*, c.name AS campaign_name, c.org_id AS campaign_org_id,
                      c.department AS campaign_department,
                      e.full_name AS employee_full_name, e.id AS employee_id,
                      e.department AS employee_department
               FROM campaign_emails ce
               JOIN campaigns c ON ce.campaign_id = c.id
               JOIN employees e ON ce.employee_id = e.id
               WHERE ce.id = ?""",
            (campaign_email_id,),
        ).fetchone()

        if row is None or row["campaign_org_id"] != org_id:
            flash("Simulation email not found.", "danger")
            return redirect(url_for("admin.admin_dashboard"))

        # Two checks, not one: _campaign_view_accessible alone would let a
        # department admin view this page for ANY employee on an org-wide
        # campaign (the campaign-level view rule — see that function's
        # docstring), but this page is about one specific EMPLOYEE's
        # activity, which must stay scoped to the employee's own
        # department even on an org-wide campaign — the same stricter rule
        # employee_detail() enforces for the same reason.
        if (not _campaign_view_accessible({"department": row["campaign_department"]}, dept)
                or (dept and row["employee_department"] != dept)):
            flash("Simulation email not found.", "danger")
            return redirect(url_for("admin.admin_dashboard"))

        interaction_rows = db.execute(
            "SELECT * FROM interactions WHERE campaign_email_id = ? ORDER BY occurred_at ASC, id ASC",
            (campaign_email_id,),
        ).fetchall()
    finally:
        db.close()

    # One synthetic "received" entry — never itself a tracked interaction
    # (there's no client request to capture an IP/User-Agent from at send
    # time, so those two fields are blank for this entry only), shown
    # first so "when was this even sent" never requires a separate lookup
    # — followed by one entry per recorded interaction, in order.
    timeline = []
    if row["sent_at"]:
        timeline.append({
            "event_type": "received", "occurred_at": row["sent_at"],
            "ip_address": None, "user_agent": None, "dwell_ms": None,
        })
    for i in interaction_rows:
        timeline.append({
            "event_type": i["event_type"], "occurred_at": i["occurred_at"],
            "ip_address": i["ip_address"], "user_agent": i["user_agent"],
            "dwell_ms": i["dwell_ms"],
        })

    return render_template(
        "interaction_timeline.html",
        campaign_email=row,
        timeline=timeline,
        event_labels=TIMELINE_EVENT_LABELS,
        event_icons=TIMELINE_EVENT_ICONS,
    )


def _report_employee_rows(emails, per_email_events):
    return [
        {
            "full_name": e["full_name"], "email": e["email"], "department": e["department"],
            "events": per_email_events.get(e["id"], set()),
        }
        for e in emails
    ]


@admin_bp.route("/admin/campaign/<int:campaign_id>/report.csv")
@role_required("admin")
def campaign_report_csv(campaign_id):
    db = get_db()
    try:
        org_id = session["org_id"]
        dept = session.get("department")
        campaign, emails, counts, per_email_events = _load_campaign_compliance_data(
            db, campaign_id, org_id, dept
        )
        if campaign is None:
            flash("Campaign not found.", "danger")
            return redirect(url_for("admin.admin_dashboard"))
        org = db.execute("SELECT name FROM organizations WHERE id = ?", (org_id,)).fetchone()
        log_action(
            db, org_id=org_id, actor_user_id=session["user_id"],
            actor_role=session.get("role"), actor_name=session.get("full_name"),
            action="report_exported",
            description=f"Downloaded compliance report (CSV) for campaign '{campaign['name']}'.",
        )
        db.commit()
    finally:
        db.close()

    findings = get_compliance_findings(counts)
    attack_techniques = get_campaign_attack_techniques(
        any(e["has_attachment"] for e in emails)
    )
    csv_bytes = build_csv_report(
        org["name"], campaign, counts, findings, _report_employee_rows(emails, per_email_events),
        attack_techniques=attack_techniques,
    )
    safe_name = "".join(c if c.isalnum() else "_" for c in campaign["name"])
    return Response(
        csv_bytes, mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="phishsim_report_{safe_name}.csv"'},
    )


@admin_bp.route("/admin/campaign/<int:campaign_id>/report.pdf")
@role_required("admin")
def campaign_report_pdf(campaign_id):
    db = get_db()
    try:
        org_id = session["org_id"]
        dept = session.get("department")
        campaign, emails, counts, per_email_events = _load_campaign_compliance_data(
            db, campaign_id, org_id, dept
        )
        if campaign is None:
            flash("Campaign not found.", "danger")
            return redirect(url_for("admin.admin_dashboard"))
        org = db.execute("SELECT name FROM organizations WHERE id = ?", (org_id,)).fetchone()
        log_action(
            db, org_id=org_id, actor_user_id=session["user_id"],
            actor_role=session.get("role"), actor_name=session.get("full_name"),
            action="report_exported",
            description=f"Downloaded compliance report (PDF) for campaign '{campaign['name']}'.",
        )
        db.commit()
    finally:
        db.close()

    findings = get_compliance_findings(counts)
    attack_techniques = get_campaign_attack_techniques(
        any(e["has_attachment"] for e in emails)
    )
    pdf_bytes = build_pdf_report(
        org["name"], campaign, counts, findings, _report_employee_rows(emails, per_email_events),
        attack_techniques=attack_techniques,
    )
    safe_name = "".join(c if c.isalnum() else "_" for c in campaign["name"])
    return Response(
        pdf_bytes, mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="phishsim_report_{safe_name}.pdf"'},
    )


@admin_bp.route("/admin/campaign/<int:campaign_id>/delete", methods=["POST"])
@role_required("admin")
def delete_campaign(campaign_id):
    """
    Deletes a campaign and everything that depends on it (its generated
    emails, and the interaction events logged against those emails).
    Deleted in dependency order — interactions, then campaign_emails, then
    the campaign itself — since the schema enforces foreign keys and won't
    allow deleting a row that something else still references.
    """
    db = get_db()
    try:
        org_id = session["org_id"]
        dept = session.get("department")
        campaign = db.execute(
            "SELECT * FROM campaigns WHERE id = ? AND org_id = ?", (campaign_id, org_id)
        ).fetchone()
        if campaign is None or not _campaign_action_accessible(campaign, dept):
            flash("Campaign not found.", "danger")
            return redirect(url_for("admin.admin_dashboard"))

        email_ids = [
            row["id"] for row in
            db.execute("SELECT id FROM campaign_emails WHERE campaign_id = ?", (campaign_id,)).fetchall()
        ]
        for email_id in email_ids:
            db.execute("DELETE FROM interactions WHERE campaign_email_id = ?", (email_id,))
        db.execute("DELETE FROM campaign_emails WHERE campaign_id = ?", (campaign_id,))
        db.execute("DELETE FROM campaigns WHERE id = ?", (campaign_id,))
        campaign_name = campaign["name"]
        log_action(
            db, org_id=org_id, actor_user_id=session["user_id"],
            actor_role=session.get("role"), actor_name=session.get("full_name"),
            action="campaign_deleted",
            description=f"Deleted campaign '{campaign_name}'.",
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    flash(f"Campaign '{campaign_name}' deleted.", "success")
    return redirect(url_for("admin.admin_dashboard"))


@admin_bp.route("/admin/employee/<int:employee_id>")
@role_required("admin")
def employee_detail(employee_id):
    """
    Per-employee risk dashboard: one person's behaviour aggregated across
    every campaign they've been part of in this organization, with a
    transparent risk score, compliance findings, and recommendations —
    distinct from campaign_detail, which aggregates across all employees
    within one campaign.
    """
    db = get_db()
    try:
        org_id = session["org_id"]
        dept = session.get("department")

        employee = db.execute(
            "SELECT * FROM employees WHERE id = ? AND org_id = ?", (employee_id, org_id)
        ).fetchone()
        if employee is None or (dept and employee["department"] != dept):
            flash("Employee not found.", "danger")
            return redirect(url_for("admin.admin_dashboard"))

        # Every email this employee has ever received, across all campaigns,
        # joined with the campaign name so the history table can show it.
        campaign_emails = db.execute(
            """SELECT ce.*, c.name AS campaign_name, c.condition AS campaign_condition
               FROM campaign_emails ce JOIN campaigns c ON ce.campaign_id = c.id
               WHERE ce.employee_id = ? AND c.org_id = ?
               ORDER BY c.created_at DESC""",
            (employee_id, org_id),
        ).fetchall()

        counts = {"total": len(campaign_emails), **{et: 0 for et in EVENT_TYPES}}
        history = []
        persuasion_rows = []
        dwell_samples = []
        for ce in campaign_emails:
            events = db.execute(
                "SELECT * FROM interactions WHERE campaign_email_id = ?",
                (ce["id"],),
            ).fetchall()
            event_types = {row["event_type"] for row in events}
            for et in EVENT_TYPES:
                if et in event_types:
                    counts[et] += 1

            # Click-timing behavioural signal: collect every non-null
            # dwell_ms recorded against a 'submit' event for this email
            # (there's normally at most one, but this stays correct even
            # if a form were somehow submitted more than once).
            for row in events:
                if row["event_type"] == "submit" and row["dwell_ms"] is not None:
                    dwell_samples.append(row["dwell_ms"])

            # Persuasion-principle susceptibility profiling: this email
            # counts as "fell for it" if the recipient acted on it at all
            # (click/submit/download/called), regardless of which of those
            # specific actions happened.
            persuasion_rows.append({
                "persuasion_principle": ce["persuasion_principle"],
                "fell_for_it": bool(event_types & FELL_FOR_IT_EVENTS),
            })

            history.append({
                "campaign_email_id": ce["id"],
                "campaign_name": ce["campaign_name"],
                "condition": ce["campaign_condition"],
                "events": event_types,
                "difficulty_level": ce["difficulty_level"],
            })
    finally:
        db.close()

    # Two deliberately distinct figures shown on this page: `likelihood` is
    # pure behavioural susceptibility (compute_employee_risk, unchanged
    # from the MVP — also what drives the adaptive-difficulty engine
    # elsewhere); `risk` layers this employee's department impact weight
    # on top of it (likelihood x impact) for the final figure an admin
    # should actually act on. See compliance_mapper.py's module docstring.
    likelihood = compute_employee_risk(counts)
    risk = compute_employee_overall_risk(likelihood, employee["department"])
    findings = get_compliance_findings(counts)
    persuasion_profile = compute_persuasion_profile(persuasion_rows)

    # Response-speed indicator: classify the employee's AVERAGE submit
    # dwell time (not each individual submission) into one readable label,
    # so the page shows one consistent signal rather than a list of raw
    # millisecond figures. None if they've never submitted with timing
    # data recorded (e.g. no submissions yet, or JS was disabled each time).
    avg_dwell_ms = round(sum(dwell_samples) / len(dwell_samples)) if dwell_samples else None
    response_speed_label = classify_click_speed(avg_dwell_ms)

    return render_template(
        "employee_detail.html",
        employee=employee,
        counts=counts,
        risk=risk,
        likelihood=likelihood,
        findings=findings,
        history=history,
        persuasion_profile=persuasion_profile,
        avg_dwell_ms=avg_dwell_ms,
        response_speed_label=response_speed_label,
    )


@admin_bp.route("/admin/campaign/<int:campaign_id>/test-send", methods=["POST"])
@role_required("admin")
def test_send_campaign(campaign_id):
    """
    Sends ONE preview copy of this campaign's pretext to the logged-in
    admin's own email address, so they can review it before launching to
    the real employee roster — this was in the original proposal
    ("admin can send a test email to themselves before launching").

    Deliberately does NOT touch campaign_emails or interactions at all:
    this is a preview only, generated fresh and sent directly, so it can
    never be mistaken for real employee data or pollute the campaign's
    real compliance statistics. The tracking link is replaced with a
    clearly-labelled placeholder rather than a working link, since there
    is no real employee record for a test send to track against.
    """
    from services.mailer import send_email

    db = get_db()
    try:
        org_id = session["org_id"]
        dept = session.get("department")
        campaign = db.execute(
            "SELECT * FROM campaigns WHERE id = ? AND org_id = ?", (campaign_id, org_id)
        ).fetchone()
        if campaign is None or not _campaign_action_accessible(campaign, dept):
            flash("Campaign not found.", "danger")
            return redirect(url_for("admin.admin_dashboard"))

        org = db.execute("SELECT name FROM organizations WHERE id = ?", (org_id,)).fetchone()
        admin_user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    finally:
        db.close()

    try:
        if campaign["vector"] == "callback_toad":
            content = generate_toad_pretext(
                employee_name=admin_user["full_name"],
                department="Preview",
                org_name=org["name"],
            )
        else:
            content = generate_pretext(
                employee_name=admin_user["full_name"],
                department="Preview",
                org_name=org["name"],
                condition=campaign["condition"],
            )
    except ModerationError:
        flash("Test send failed: generated content was blocked by the moderation filter.", "danger")
        return redirect(url_for("admin.campaign_detail", campaign_id=campaign_id))
    except Exception as e:
        flash(f"Test send failed: {type(e).__name__}: {e}", "danger")
        return redirect(url_for("admin.campaign_detail", campaign_id=campaign_id))

    # No real tracking/call link for a preview — nothing to track against.
    html_body = content["html_body"].replace(
        "{tracking_link}", "#preview-only-no-tracking"
    ).replace(
        "{call_link}", "#preview-only-no-tracking"
    )
    html_body = (
        '<div style="background:#fff3cd; border:1px solid #ffecb5; padding:12px 16px; '
        'margin-bottom:16px; font-family:Arial,sans-serif; font-size:14px;">'
        '<strong>TEST PREVIEW</strong> — this is a preview copy, not a real campaign send. '
        'The link above is not functional.</div>'
    ) + html_body

    send_email(
        to=admin_user["email"],
        subject=f"[TEST PREVIEW] {content['subject']}",
        html_body=html_body,
        from_name=campaign["spoofed_sender_name"],
        from_address=campaign["spoofed_address"],
    )

    flash(f"Test email sent to {admin_user['email']}.", "success")
    return redirect(url_for("admin.campaign_detail", campaign_id=campaign_id))


@admin_bp.route("/admin/campaign/<int:campaign_id>/send", methods=["POST"])
@role_required("admin")
def send_campaign(campaign_id):
    """
    MVP 'send': marks emails as sent and prints them to the console / a local
    outbox file instead of using a real mail server, so nothing can
    accidentally reach a real inbox before Mailtrap/SMTP is configured.
    See services/mailer.py for where to plug in real sending.

    Two things deliberately NOT treated as "one transaction, all or nothing":
      - A small delay between sends (SEND_DELAY_SECONDS, default 1s) so a
        burst of recipients doesn't trip a provider's per-second rate limit
        (hit in practice on Mailtrap's free Testing plan: "550 Too many
        emails per second").
      - Each email is committed to the database right after it sends,
        instead of one big commit at the end. An email that has actually
        gone out over SMTP cannot be "un-sent" by a later database
        rollback — so if email #4 of 10 fails, #1-3 must still be recorded
        as sent rather than losing that record along with #4's failure.
        One recipient's failure (bad address, rate limit, timeout) no
        longer aborts the whole campaign; it's skipped and reported.
    """
    import time
    from services.mailer import send_email  # local import keeps this optional

    SEND_DELAY_SECONDS = float(os.environ.get("SEND_DELAY_SECONDS", "1"))

    db = get_db()
    try:
        org_id = session["org_id"]
        dept = session.get("department")
        campaign = db.execute(
            "SELECT * FROM campaigns WHERE id = ? AND org_id = ?", (campaign_id, org_id)
        ).fetchone()
        if campaign is None or not _campaign_action_accessible(campaign, dept):
            flash("Campaign not found.", "danger")
            return redirect(url_for("admin.admin_dashboard"))

        emails = db.execute(
            """SELECT ce.*, e.email as recipient_email FROM campaign_emails ce
               JOIN employees e ON ce.employee_id = e.id WHERE ce.campaign_id = ?""",
            (campaign_id,),
        ).fetchall()
    finally:
        db.close()

    sent_count = 0
    failures = []
    for i, email in enumerate(emails):
        if i > 0:
            time.sleep(SEND_DELAY_SECONDS)

        send_db = get_db()
        try:
            send_email(
                to=email["recipient_email"], subject=email["subject"], html_body=email["html_body"],
                from_name=campaign["spoofed_sender_name"], from_address=campaign["spoofed_address"],
            )
            send_db.execute(
                "UPDATE campaign_emails SET sent_at = datetime('now') WHERE id = ?", (email["id"],)
            )
            send_db.commit()
            sent_count += 1
        except Exception as e:
            send_db.rollback()
            failures.append((email["recipient_email"], f"{type(e).__name__}: {e}"))
            print(f"[send_campaign] Failed to send to {email['recipient_email']}: {type(e).__name__}: {e}")
        finally:
            send_db.close()

    status_db = get_db()
    try:
        # Mark 'launched' even on partial failure — some recipients did get
        # a real send, so this is no longer a draft, and the per-employee
        # 'sent_at' values already distinguish who actually received one.
        status_db.execute("UPDATE campaigns SET status = 'launched' WHERE id = ?", (campaign_id,))
        log_action(
            status_db, org_id=org_id, actor_user_id=session["user_id"],
            actor_role=session.get("role"), actor_name=session.get("full_name"),
            action="campaign_sent",
            description=(
                f"Sent campaign '{campaign['name']}' — {sent_count} of {len(emails)} "
                f"recipient(s) succeeded" + (f", {len(failures)} failed" if failures else "") + "."
            ),
        )
        status_db.commit()
    finally:
        status_db.close()

    if failures:
        flash(
            f"Campaign sent to {sent_count} of {len(emails)} recipients. "
            f"{len(failures)} failed (see terminal for details) — e.g. a provider rate limit "
            f"or an invalid address. Already-sent recipients were not affected.",
            "warning",
        )
    else:
        flash(f"Campaign sent to {sent_count} recipients.", "success")
    return redirect(url_for("admin.campaign_detail", campaign_id=campaign_id))


@admin_bp.route("/admin/department-admins", methods=["GET", "POST"])
@core_admin_required
def manage_department_admins():
    """
    Core-admin-only page for creating department-admin accounts. Gated by
    @core_admin_required rather than @role_required('admin'), so a
    department admin cannot reach this even though they share the 'admin'
    role — an attempt lands them back on their own dashboard with the
    standard "no permission" flash, same as hitting any other gated route.
    """
    org_id = session["org_id"]
    db = get_db()

    if request.method == "POST":
        try:
            full_name = request.form["full_name"].strip()
            email = request.form["email"].strip().lower()
            password = request.form["password"]
            department = request.form["department"].strip()

            if not full_name or not email or not password or not department:
                flash("All fields are required.", "danger")
                return redirect(url_for("admin.manage_department_admins"))

            try:
                db.execute(
                    "INSERT INTO users (org_id, email, password_hash, role, full_name, department) "
                    "VALUES (?, ?, ?, 'admin', ?, ?)",
                    (org_id, email, generate_password_hash(password), full_name, department),
                )
                log_action(
                    db, org_id=org_id, actor_user_id=session["user_id"],
                    actor_role=session.get("role"), actor_name=session.get("full_name"),
                    action="department_admin_created",
                    description=f"Created department-admin account '{full_name}' ({email}) for {department}.",
                )
                db.commit()
                flash(f"Department admin '{full_name}' created for {department}.", "success")
            except Exception:
                db.rollback()
                flash(f"Could not create account — email '{email}' may already be in use.", "danger")
        finally:
            db.close()
        return redirect(url_for("admin.manage_department_admins"))

    try:
        dept_admins = db.execute(
            "SELECT * FROM users WHERE org_id = ? AND role = 'admin' AND department IS NOT NULL "
            "ORDER BY department, full_name",
            (org_id,),
        ).fetchall()
    finally:
        db.close()

    return render_template("manage_dept_admins.html", dept_admins=dept_admins)


@admin_bp.route("/admin/department-admins/<int:user_id>/reset-password", methods=["POST"])
@core_admin_required
def reset_admin_password(user_id):
    """
    Core-admin-triggered password reset for ONE of their own department
    admins. This route never sets, sees, or even generates a password for
    the target account — it only creates a single-use, expiring token
    (password_reset_tokens) and emails the affected admin a link to
    auth.reset_password, where THEY alone choose their new password. The
    core admin's only control here is deciding WHO gets a reset link,
    never what the new password will be.
    """
    from services.mailer import send_email

    org_id = session["org_id"]
    db = get_db()
    try:
        target = db.execute(
            "SELECT * FROM users WHERE id = ? AND org_id = ? AND role = 'admin' AND department IS NOT NULL",
            (user_id, org_id),
        ).fetchone()
        if target is None:
            flash("Department admin not found.", "danger")
            return redirect(url_for("admin.manage_department_admins"))

        token = secrets.token_urlsafe(32)
        db.execute(
            "INSERT INTO password_reset_tokens (user_id, token, requested_by, expires_at) "
            f"VALUES (?, ?, ?, datetime('now', '+{PASSWORD_RESET_EXPIRY_HOURS} hours'))",
            (user_id, token, session["user_id"]),
        )
        reset_link = _public_url("auth.reset_password", token=token)
        log_action(
            db, org_id=org_id, actor_user_id=session["user_id"],
            actor_role=session.get("role"), actor_name=session.get("full_name"),
            action="password_reset_requested",
            description=f"Requested a password reset for '{target['full_name']}' ({target['email']}).",
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    send_email(
        to=target["email"],
        subject="PhishSim — reset your password",
        html_body=render_template(
            "email_password_reset.html",
            full_name=target["full_name"], reset_link=reset_link,
        ),
    )

    flash(f"A password reset link was emailed to {target['email']}.", "success")
    return redirect(url_for("admin.manage_department_admins"))


@admin_bp.route("/admin/audit-log")
@core_admin_required
def audit_log():
    """
    Core-admin-only, like manage_department_admins — this is the full
    governance history for this organization's own tenant, so every
    action type is shown here (unlike the engineer's filtered view below).
    A department admin hitting this route is bounced the same way as any
    other core-admin-only page.
    """
    org_id = session["org_id"]
    db = get_db()
    try:
        entries = db.execute(
            "SELECT * FROM audit_log WHERE org_id = ? ORDER BY created_at DESC, id DESC",
            (org_id,),
        ).fetchall()
    finally:
        db.close()
    return render_template("audit_log.html", entries=entries)


@admin_bp.route("/admin/support", methods=["GET", "POST"])
@role_required("admin")
def contact_support():
    """
    Lets any admin (core or department tier) raise a support ticket
    straight to the platform engineer, and see the status/response of
    tickets already raised — the one deliberate exception to "the
    engineer never sees tenant data" (see schema.sql's comment on
    support_tickets): this is free text the admin chose to write and
    send, the same as emailing a real support desk, so the form warns
    against pasting real employee data or credentials into it.

    Visibility of PAST tickets mirrors the rest of this project's
    department-admin scoping: a core admin sees every ticket raised by
    anyone in their organization (same "sees everything" rule as
    audit_log), while a department admin sees only the tickets they
    personally raised — not another department admin's.
    """
    org_id = session["org_id"]
    dept = session.get("department")

    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()
        errors = []
        if not subject:
            errors.append("Please give the ticket a subject.")
        if not message:
            errors.append("Please describe the issue or question.")
        if len(subject) > 200:
            errors.append("Subject is too long (max 200 characters).")

        if errors:
            for e in errors:
                flash(e, "danger")
        else:
            db = get_db()
            try:
                org_name = db.execute(
                    "SELECT name FROM organizations WHERE id = ?", (org_id,)
                ).fetchone()["name"]
                db.execute(
                    "INSERT INTO support_tickets "
                    "(org_id, raised_by_user_id, raised_by_name, raised_by_role, org_name, subject, message) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (org_id, session["user_id"], session.get("full_name"), session.get("role"),
                     org_name, subject, message),
                )
                log_action(
                    db, org_id=org_id, actor_user_id=session["user_id"],
                    actor_role=session.get("role"), actor_name=session.get("full_name"),
                    action="support_ticket_raised",
                    description=f"Raised a support ticket: '{subject}'.",
                )
                db.commit()
            finally:
                db.close()
            flash("Your support ticket has been sent to the platform engineer.", "success")
            return redirect(url_for("admin.contact_support"))

    db = get_db()
    try:
        if dept:
            tickets = db.execute(
                "SELECT * FROM support_tickets WHERE org_id = ? AND raised_by_user_id = ? "
                "ORDER BY created_at DESC",
                (org_id, session["user_id"]),
            ).fetchall()
        else:
            tickets = db.execute(
                "SELECT * FROM support_tickets WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
    finally:
        db.close()

    return render_template("support.html", tickets=tickets)


@admin_bp.route("/admin/faq")
@role_required("admin")
def faq():
    """Static setup guide + frequently asked questions for core/department
    admins — no DB access needed, purely a reference page (see
    templates/faq.html)."""
    return render_template("faq.html")


@admin_bp.route("/engineer/audit-log")
@role_required("engineer")
def engineer_audit_log():
    """
    Platform-engineer-facing audit log. Deliberately filtered to the
    ENGINEER_VISIBLE_ACTIONS allow-list (services/audit.py) — organization
    registration and suspend/reactivate events only, across every org.
    Never campaign/employee-level actions: those stay inside each
    organization's own /admin/audit-log, preserving the same "engineer has
    no tenant data access" boundary enforced on the rest of this
    dashboard (see engineer_dashboard()).
    """
    db = get_db()
    try:
        placeholders = ",".join("?" for _ in ENGINEER_VISIBLE_ACTIONS)
        entries = db.execute(
            f"""SELECT al.*, o.name AS org_name FROM audit_log al
                LEFT JOIN organizations o ON o.id = al.org_id
                WHERE al.action IN ({placeholders})
                ORDER BY al.created_at DESC, al.id DESC""",
            tuple(ENGINEER_VISIBLE_ACTIONS),
        ).fetchall()
    finally:
        db.close()
    return render_template("engineer_audit_log.html", entries=entries)


@admin_bp.route("/engineer/support")
@role_required("engineer")
def support_inbox():
    """
    Platform-engineer-facing support inbox — EVERY organization's tickets,
    deliberately unfiltered by org (unlike everything else on the engineer
    dashboard). This is the one intentional exception to "engineer has no
    tenant data access": a support ticket's subject/message is free text
    an admin chose to send to the platform operator, not tenant data the
    platform surfaces on its own — see schema.sql's comment on
    support_tickets for the full reasoning.
    """
    db = get_db()
    try:
        tickets = db.execute(
            "SELECT * FROM support_tickets ORDER BY (status = 'resolved') ASC, created_at DESC"
        ).fetchall()
    finally:
        db.close()
    return render_template("engineer_support.html", tickets=tickets)


@admin_bp.route("/engineer/support/<int:ticket_id>/respond", methods=["POST"])
@role_required("engineer")
def respond_support_ticket(ticket_id):
    """Records the engineer's reply and marks the ticket resolved. There is
    no further back-and-forth in this MVP — a resolved ticket with a new
    issue is a new ticket, which keeps the status model to the two values
    schema.sql's CHECK constraint allows."""
    response_text = request.form.get("response", "").strip()
    if not response_text:
        flash("Please write a response before sending.", "danger")
        return redirect(url_for("admin.support_inbox"))

    db = get_db()
    try:
        ticket = db.execute("SELECT * FROM support_tickets WHERE id = ?", (ticket_id,)).fetchone()
        if ticket is None:
            flash("Ticket not found.", "danger")
            return redirect(url_for("admin.support_inbox"))

        db.execute(
            "UPDATE support_tickets SET engineer_response = ?, responded_by_name = ?, "
            "responded_at = datetime('now'), status = 'resolved' WHERE id = ?",
            (response_text, session.get("full_name"), ticket_id),
        )
        log_action(
            db, org_id=ticket["org_id"], actor_user_id=session["user_id"],
            actor_role=session.get("role"), actor_name=session.get("full_name"),
            action="support_ticket_resolved",
            description=f"Platform engineer responded to support ticket: '{ticket['subject']}'.",
        )
        db.commit()
    finally:
        db.close()

    flash("Response sent.", "success")
    return redirect(url_for("admin.support_inbox"))
