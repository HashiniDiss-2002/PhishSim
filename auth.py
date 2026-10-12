"""
auth.py
-------
Handles login/logout and enforces the role access model:
  - engineer: platform maintainer, no tenant data access
  - admin:    client admin, manages their own organization's data.
              Split into two tiers by the (nullable) users.department column:
                - core admin   (department IS NULL): full visibility over the
                  whole organization, and the only tier that can create more
                  department-admin accounts.
                - department admin (department IS NOT NULL): scoped to their
                  own department's employees and campaigns only.
  - user:     client employee (does not log in to the platform in the MVP;
              included in the schema/roles for completeness and Stage 2 growth)

Access control approach:
Rather than a heavier library, we use Flask's built-in `session` (a signed
cookie) to store the logged-in user's id, role and department, plus two
decorator factories:
  - `role_required(...)`   — gate by role (engineer / admin), as before.
  - `core_admin_required`  — a stricter gate layered on top of 'admin' that
    additionally requires department IS NULL, for actions reserved for the
    core admin (e.g. creating department-admin accounts).
Both are simple enough to fully explain in a viva while still being a real,
enforced server-side check on every request (not just hiding UI elements).
"""

from functools import wraps

from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash

import os
import secrets

from database import get_db
from services.audit import log_action
from services import totp as totp_service

auth_bp = Blueprint("auth", __name__)

# MFA is mandatory for every real login — there is no in-app opt-out. The
# one exception is this env var, read only here, which lets the existing
# test_*.py suite keep testing everything ELSE (roles, campaigns, reports,
# etc.) without re-deriving a TOTP code in every one of those files' login
# helpers. It is never set outside a test process; test_mfa.py (the file
# that actually tests this feature) deliberately leaves it unset so it
# exercises the real, enforced flow.
_MFA_TEST_BYPASS_ENV = "PHISHSIM_DISABLE_MFA_FOR_TESTS"

# Minimum password length for both the demo/admin-created accounts and
# this self-registration flow — not configurable elsewhere in this MVP,
# so kept here as the one place register() checks it.
MIN_PASSWORD_LENGTH = 8

# Email-OTP verification settings for self-registration (register() /
# register_verify_email() / register_ethics()). A 6-digit numeric code,
# expiring quickly and capped on wrong attempts — the same shape as the
# TOTP codes MFA already uses, just emailed instead of app-generated.
OTP_LENGTH = 6
OTP_EXPIRY_MINUTES = 10
OTP_MAX_ATTEMPTS = 5            # wrong-code guesses allowed against ONE emailed code

# Separate cap on how many codes can be SENT to one email address at all
# (the initial send from register() plus every "resend" both count) —
# stops a registrant (or someone else abusing their address) from
# triggering unlimited emails. Checked against email_verification_otps
# rows created in the last OTP_RATE_LIMIT_HOURS, so the limit rolls
# forward rather than resetting at midnight.
OTP_MAX_SENDS_PER_DAY = 3
OTP_RATE_LIMIT_HOURS = 24
OTP_RATE_LIMIT_MESSAGE = (
    "Too many verification codes have been requested for this email address. "
    "Please try again in 24 hours."
)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped


def role_required(*allowed_roles):
    """Usage: @role_required('admin') or @role_required('admin', 'engineer')"""
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if session.get("role") not in allowed_roles:
                flash("You do not have permission to view that page.", "danger")
                return redirect(url_for("auth.dashboard_redirect"))
            return view(*args, **kwargs)
        return wrapped
    return decorator


def core_admin_required(view):
    """
    Stricter than @role_required('admin'): also requires that this admin has
    no department set (session["department"] is None), i.e. they are the
    core admin for their organization, not a department-scoped admin.

    Used for actions that must stay core-admin-only even though both tiers
    share the 'admin' role — right now, that's managing department-admin
    accounts. A department admin who hits this route is bounced with the
    same "no permission" message a role_required mismatch gives, so there's
    no way to distinguish "wrong role" from "wrong admin tier" by the
    response alone.
    """
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin" or session.get("department") is not None:
            flash("You do not have permission to view that page.", "danger")
            return redirect(url_for("auth.dashboard_redirect"))
        return view(*args, **kwargs)
    return wrapped


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            db.close()
            flash("Invalid email or password.", "danger")
            return render_template("login.html")

        # A suspended organization (set by the platform engineer — e.g. for
        # non-payment or suspected malicious use) blocks login for that
        # org's admin/user accounts. Engineers have org_id = NULL, so this
        # never affects them.
        if user["org_id"] is not None:
            org = db.execute("SELECT suspended FROM organizations WHERE id = ?", (user["org_id"],)).fetchone()
            if org is not None and org["suspended"]:
                db.close()
                flash("This organization's account has been suspended. Contact support.", "danger")
                return render_template("login.html")

        db.close()

        if os.environ.get(_MFA_TEST_BYPASS_ENV) == "1":
            _grant_session(user)
            return redirect(url_for("auth.dashboard_redirect"))

        # Password is correct, but the session is NOT granted yet — MFA is
        # mandatory for every admin/engineer account, with no opt-out, so a
        # verified password alone must never be enough to reach the
        # dashboard. Only a "pending" marker goes in the session here;
        # _grant_session() (called only after a correct TOTP code) is what
        # actually sets user_id/role/org_id/etc. A user whose account has
        # never completed MFA setup (mfa_enabled = 0 — true for every
        # pre-existing seeded/demo account right after migrate_add_mfa.py)
        # is routed to enroll first; everyone else is routed to verify a
        # fresh code.
        session["pending_mfa_user_id"] = user["id"]
        mfa_enabled = bool(user["mfa_enabled"]) if "mfa_enabled" in user.keys() else False
        if not mfa_enabled:
            return redirect(url_for("auth.mfa_setup"))
        return redirect(url_for("auth.mfa_verify"))

    return render_template("login.html")


def _grant_session(user):
    """
    The only place a full, authenticated session gets created. Called from
    mfa_verify() after a correct TOTP code — never from login() directly —
    so every admin/engineer session on this platform has passed MFA.
    """
    session.pop("pending_mfa_user_id", None)
    session["user_id"] = user["id"]
    session["role"] = user["role"]
    session["org_id"] = user["org_id"]
    session["full_name"] = user["full_name"]
    # "department" in user.keys() guards against a pre-migration database row
    # fetched by a stale schema; migrate_add_department.py removes the need
    # for this once run, but this keeps login from hard-erroring if someone
    # forgets that step.
    session["department"] = user["department"] if "department" in user.keys() else None


@auth_bp.route("/mfa/setup", methods=["GET", "POST"])
def mfa_setup():
    """
    First-time MFA enrollment, reached only via the "pending_mfa_user_id"
    session marker login() sets after a correct password — never directly
    reachable by a browser that hasn't just authenticated. Generates a new
    TOTP secret, shows it (as a scannable otpauth:// QR code rendered
    client-side, plus the raw secret as a manual-entry fallback — see
    templates/mfa_setup.html) and only commits mfa_secret/mfa_enabled to the
    database once the admin proves they've actually enrolled it, by
    entering one correct current code back.

    If this account has already completed setup (mfa_enabled = 1) but
    somehow lands here again, it's redirected to mfa_verify instead —
    setup is strictly a one-time step per account.
    """
    pending_user_id = session.get("pending_mfa_user_id")
    if not pending_user_id:
        return redirect(url_for("auth.login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (pending_user_id,)).fetchone()
    if user is None:
        db.close()
        session.pop("pending_mfa_user_id", None)
        return redirect(url_for("auth.login"))

    if bool(user["mfa_enabled"]) if "mfa_enabled" in user.keys() else False:
        db.close()
        return redirect(url_for("auth.mfa_verify"))

    # A secret is generated once per setup attempt and stashed in the
    # session (NOT the database) until it's verified — so a setup page
    # that's loaded but abandoned leaves no half-enrolled secret behind.
    secret = session.get("pending_mfa_secret")
    if not secret:
        secret = totp_service.generate_secret()
        session["pending_mfa_secret"] = secret

    error = None
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if totp_service.verify_code(secret, code):
            db.execute(
                "UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE id = ?",
                (secret, user["id"]),
            )
            log_action(
                db, org_id=user["org_id"], actor_user_id=user["id"],
                actor_role=user["role"], actor_name=user["full_name"],
                action="mfa_enabled",
                description="Completed mandatory MFA (TOTP) enrollment.",
            )
            db.commit()
            db.close()
            session.pop("pending_mfa_secret", None)
            _grant_session(user)
            flash("MFA is now set up on this account. You'll be asked for a code at every login.", "success")
            next_endpoint = session.pop("post_mfa_redirect", None)
            return redirect(url_for(next_endpoint) if next_endpoint else url_for("auth.dashboard_redirect"))
        else:
            error = "That code didn't match. Codes refresh every 30 seconds — check your authenticator app and try the latest one."

    db.close()
    uri = totp_service.provisioning_uri(secret, user["email"])
    return render_template("mfa_setup.html", secret=secret, provisioning_uri=uri, error=error)


@auth_bp.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify():
    """
    Every subsequent login for an account that has already completed MFA
    setup (mfa_enabled = 1). Reached only via the "pending_mfa_user_id"
    session marker login() sets after a correct password.
    """
    pending_user_id = session.get("pending_mfa_user_id")
    if not pending_user_id:
        return redirect(url_for("auth.login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (pending_user_id,)).fetchone()
    if user is None or not user["mfa_secret"]:
        db.close()
        session.pop("pending_mfa_user_id", None)
        return redirect(url_for("auth.login"))

    error = None
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if totp_service.verify_code(user["mfa_secret"], code):
            db.close()
            _grant_session(user)
            return redirect(url_for("auth.dashboard_redirect"))
        else:
            db.close()
            error = "Incorrect code. Check your authenticator app and try the latest 6-digit code."
            return render_template("mfa_verify.html", error=error)

    db.close()
    return render_template("mfa_verify.html", error=error)


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """
    Self-service signup for a NEW organization's core admin. This is the
    only way a new organization gets created in this MVP — there is no
    "create organization" button anywhere in the admin/engineer UI, by
    design: a platform engineer provisions tenants only in the sense of
    monitoring/suspending them (engineer_dashboard()), never creating
    their data.

    No account is created by this route. It only validates the submitted
    details and stages them in the session as "pending_registration" —
    the organization and admin user rows are only ever written in
    register_ethics() below, and only on explicit acceptance of the
    Responsible Use declaration. Rejecting that declaration leaves no
    trace of this organization in the database at all.
    """
    form = {"org_name": "", "full_name": "", "email": ""}

    if request.method == "POST":
        form["org_name"] = request.form.get("org_name", "").strip()
        form["full_name"] = request.form.get("full_name", "").strip()
        form["email"] = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        errors = []
        if not form["org_name"]:
            errors.append("Organization name is required.")
        if not form["full_name"]:
            errors.append("Your full name is required.")
        if not form["email"] or "@" not in form["email"]:
            errors.append("A valid email address is required.")
        if len(password) < MIN_PASSWORD_LENGTH:
            errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
        if password != confirm:
            errors.append("Passwords do not match.")

        if not errors:
            db = get_db()
            try:
                org_exists = db.execute(
                    "SELECT 1 FROM organizations WHERE name = ?", (form["org_name"],)
                ).fetchone()
                email_exists = db.execute(
                    "SELECT 1 FROM users WHERE email = ?", (form["email"],)
                ).fetchone()
            finally:
                db.close()
            if org_exists:
                errors.append("An organization with that name is already registered.")
            if email_exists:
                errors.append("That email is already in use.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("register.html", form=form)

        # Password is hashed now, before it ever sits in the session —
        # the session only ever holds a hash, never the plaintext password.
        pending_registration = {
            "org_name": form["org_name"],
            "full_name": form["full_name"],
            "email": form["email"],
            "password_hash": generate_password_hash(password),
        }
        if not _generate_and_send_otp(pending_registration):
            flash(OTP_RATE_LIMIT_MESSAGE, "danger")
            return render_template("register.html", form=form)

        session["pending_registration"] = pending_registration
        session.pop("pending_registration_email_verified", None)
        return redirect(url_for("auth.register_verify_email"))

    return render_template("register.html", form=form)


def _generate_and_send_otp(pending):
    """
    Generates a fresh 6-digit code, stores only its HASH (never the
    plaintext — see schema.sql's comment on email_verification_otps and
    the session-cookie-is-signed-not-encrypted reasoning in this file's
    module docstring) with an expiry, and emails the plaintext code to
    the registrant. Called once from register() on a valid submission,
    and again from register_verify_email() on an explicit "resend".

    Rate-limited to OTP_MAX_SENDS_PER_DAY sends per email address within
    OTP_RATE_LIMIT_HOURS — checked and enforced here, in the one place
    every send (initial or resend) goes through, rather than separately
    in each caller. Returns True if a code was generated and sent, or
    False if this email has already hit the limit (nothing is sent or
    inserted in that case) — the caller shows OTP_RATE_LIMIT_MESSAGE.
    """
    from services.mailer import send_email

    db = get_db()
    try:
        recent_sends = db.execute(
            "SELECT COUNT(*) AS c FROM email_verification_otps "
            f"WHERE email = ? AND created_at > datetime('now', '-{OTP_RATE_LIMIT_HOURS} hours')",
            (pending["email"],),
        ).fetchone()["c"]
        if recent_sends >= OTP_MAX_SENDS_PER_DAY:
            return False

        otp = f"{secrets.randbelow(10 ** OTP_LENGTH):0{OTP_LENGTH}d}"
        db.execute(
            "INSERT INTO email_verification_otps (email, otp_hash, expires_at) "
            f"VALUES (?, ?, datetime('now', '+{OTP_EXPIRY_MINUTES} minutes'))",
            (pending["email"], generate_password_hash(otp)),
        )
        db.commit()
    finally:
        db.close()

    send_email(
        to=pending["email"],
        subject="PhishSim — verify your email",
        html_body=render_template(
            "email_verify_otp.html",
            full_name=pending["full_name"], org_name=pending["org_name"],
            otp=otp, expiry_minutes=OTP_EXPIRY_MINUTES,
        ),
    )
    return True


@auth_bp.route("/register/verify-email", methods=["GET", "POST"])
def register_verify_email():
    """
    Email-ownership check inserted between register() (which only
    validates and stages the submission) and register_ethics() (which
    actually creates the organization/admin account). Reachable only
    after register() has staged a pending registration — same guard as
    register_ethics() uses.

    On a correct, unexpired code, sets
    session["pending_registration_email_verified"] — the ONE thing
    register_ethics() checks in addition to pending_registration being
    present, so there's no way to skip straight to account creation by
    navigating directly to /register/ethics after register().
    """
    pending = session.get("pending_registration")
    if not pending:
        flash("Please start registration again.", "warning")
        return redirect(url_for("auth.register"))

    error = None
    if request.method == "POST":
        action = request.form.get("action", "verify")

        if action == "resend":
            if _generate_and_send_otp(pending):
                flash("A new verification code has been sent to your email.", "success")
            else:
                flash(OTP_RATE_LIMIT_MESSAGE, "danger")
            return redirect(url_for("auth.register_verify_email"))

        code = request.form.get("code", "").strip()
        db = get_db()
        try:
            row = db.execute(
                "SELECT * FROM email_verification_otps WHERE email = ? AND verified_at IS NULL "
                "ORDER BY id DESC LIMIT 1",
                (pending["email"],),
            ).fetchone()

            if row is None:
                error = "No verification code is pending. Send a new one below."
            elif row["attempts"] >= OTP_MAX_ATTEMPTS:
                error = "Too many incorrect attempts on that code. Send a new one below."
            elif row["expires_at"] <= db.execute("SELECT datetime('now') AS n").fetchone()["n"]:
                error = "That code has expired. Send a new one below."
            elif not check_password_hash(row["otp_hash"], code):
                db.execute(
                    "UPDATE email_verification_otps SET attempts = attempts + 1 WHERE id = ?",
                    (row["id"],),
                )
                db.commit()
                error = "Incorrect code. Check your email and try again."
            else:
                db.execute(
                    "UPDATE email_verification_otps SET verified_at = datetime('now') WHERE id = ?",
                    (row["id"],),
                )
                db.commit()
                session["pending_registration_email_verified"] = True
                return redirect(url_for("auth.register_ethics"))
        finally:
            db.close()

    return render_template("verify_email.html", pending=pending, error=error)


@auth_bp.route("/register/ethics", methods=["GET", "POST"])
def register_ethics():
    """
    The Responsible Use declaration gate for self-registration. Reachable
    only after register() has staged a pending registration in the
    session — visiting this directly without that bounces back to the
    start of the flow rather than showing a declaration for nothing.

    Accepting creates the organization (with ethics_accepted_at recorded)
    and the core-admin account together, logs the registration to the
    audit trail, and logs the new admin straight in. Rejecting creates
    NOTHING — the pending registration is simply discarded.
    """
    pending = session.get("pending_registration")
    if not pending:
        flash("Please start registration again.", "warning")
        return redirect(url_for("auth.register"))

    # Email ownership must be confirmed (register_verify_email()) before
    # this page is shown at all — otherwise anyone could skip straight
    # from register() to account creation without ever proving they
    # control the address they registered with.
    if not session.get("pending_registration_email_verified"):
        return redirect(url_for("auth.register_verify_email"))

    if request.method == "POST":
        action = request.form.get("action")

        if action == "reject":
            session.pop("pending_registration", None)
            session.pop("pending_registration_email_verified", None)
            flash(
                "You must accept the Responsible Use declaration to use PhishSim. "
                "No account was created.",
                "danger",
            )
            return redirect(url_for("auth.login"))

        if action == "accept":
            db = get_db()
            try:
                cur = db.execute(
                    "INSERT INTO organizations (name, ethics_accepted_at) VALUES (?, datetime('now'))",
                    (pending["org_name"],),
                )
                org_id = cur.lastrowid
                cur = db.execute(
                    "INSERT INTO users (org_id, email, password_hash, role, full_name, department) "
                    "VALUES (?, ?, ?, 'admin', ?, NULL)",
                    (org_id, pending["email"], pending["password_hash"], pending["full_name"]),
                )
                user_id = cur.lastrowid
                log_action(
                    db, org_id=org_id, actor_user_id=user_id, actor_role="admin",
                    actor_name=pending["full_name"], action="organization_registered",
                    description=(
                        f"Organization '{pending['org_name']}' self-registered and accepted "
                        f"the Responsible Use declaration."
                    ),
                )
                db.commit()
            except Exception:
                db.rollback()
                db.close()
                flash(
                    "Could not complete registration (the organization name or email may "
                    "have just been taken). Please try again.",
                    "danger",
                )
                session.pop("pending_registration", None)
                session.pop("pending_registration_email_verified", None)
                return redirect(url_for("auth.register"))
            db.close()

            session.pop("pending_registration", None)
            session.pop("pending_registration_email_verified", None)

            if os.environ.get(_MFA_TEST_BYPASS_ENV) == "1":
                # See the comment on _MFA_TEST_BYPASS_ENV above — test-suite
                # only; grants the session the same way _grant_session()
                # would, without needing a freshly re-fetched user row.
                session["user_id"] = user_id
                session["role"] = "admin"
                session["org_id"] = org_id
                session["full_name"] = pending["full_name"]
                session["department"] = None
                flash(
                    f"Welcome, {pending['full_name']}! '{pending['org_name']}' is now registered. "
                    "Next, upload your employee roster to create your first campaign.",
                    "success",
                )
                return redirect(url_for("admin.upload_employees"))

            # MFA is mandatory for every admin account, with no exception
            # for a freshly self-registered one — so this new admin is
            # routed straight into MFA enrollment (mfa_setup), exactly like
            # an existing account's first post-migration login, rather than
            # being granted a session directly.
            session["pending_mfa_user_id"] = user_id
            # Consumed once by mfa_setup() on success, so a brand-new
            # organization still lands on the roster upload page after
            # enrolling MFA, instead of an empty dashboard.
            session["post_mfa_redirect"] = "admin.upload_employees"

            flash(
                f"Welcome, {pending['full_name']}! '{pending['org_name']}' is now registered. "
                "Before you continue, set up multi-factor authentication — it's required on every account.",
                "success",
            )
            return redirect(url_for("auth.mfa_setup"))

    return render_template("register_ethics.html", pending=pending)


@auth_bp.route("/settings", methods=["GET", "POST"])
@role_required("admin")
def settings():
    """
    Self-service "my account" page for any admin (core or department
    tier) to change their OWN password. Core admins additionally see an
    organization-logo-upload form here (posting to admin.upload_logo) —
    there's no other natural "organization settings" surface in this MVP,
    so it lives on the same page rather than a separate one.
    """
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        db = get_db()
        try:
            user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
            if not check_password_hash(user["password_hash"], current_password):
                flash("Current password is incorrect.", "danger")
            elif len(new_password) < MIN_PASSWORD_LENGTH:
                flash(f"New password must be at least {MIN_PASSWORD_LENGTH} characters.", "danger")
            elif new_password != confirm_password:
                flash("New passwords do not match.", "danger")
            else:
                db.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (generate_password_hash(new_password), user["id"]),
                )
                log_action(
                    db, org_id=user["org_id"], actor_user_id=user["id"],
                    actor_role=session.get("role"), actor_name=session.get("full_name"),
                    action="password_changed",
                    description="Changed their own password.",
                )
                db.commit()
                flash("Password updated.", "success")
                return redirect(url_for("auth.settings"))
        finally:
            db.close()

    return render_template(
        "settings.html",
        is_core_admin=(session.get("department") is None),
    )


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    """
    Public (unauthenticated) route reached only via the link emailed by
    admin.reset_admin_password(). The core admin who triggered the reset
    never sees this page or its contents — only the affected department
    admin, who alone chooses their new password here. A used or expired
    token is rejected outright, same as if it never existed.
    """
    db = get_db()
    reset_row = db.execute(
        "SELECT * FROM password_reset_tokens WHERE token = ? AND used_at IS NULL "
        "AND expires_at > datetime('now')",
        (token,),
    ).fetchone()

    if reset_row is None:
        db.close()
        flash("This password reset link is invalid or has expired. Ask your core admin to send a new one.", "danger")
        # If this browser is already logged in (e.g. the link was clicked a
        # second time after already being used, or opened in a tab where a
        # session is still active), there's no reason to detour through the
        # login page — send them straight back to their own dashboard. Only
        # an anonymous visitor (no session at all) actually needs to log in.
        if "user_id" in session:
            return redirect(url_for("auth.dashboard_redirect"))
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(new_password) < MIN_PASSWORD_LENGTH:
            db.close()
            flash(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.", "danger")
            return render_template("reset_password.html", token=token)
        if new_password != confirm_password:
            db.close()
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html", token=token)

        target_user = db.execute("SELECT * FROM users WHERE id = ?", (reset_row["user_id"],)).fetchone()
        try:
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(new_password), reset_row["user_id"]),
            )
            db.execute(
                "UPDATE password_reset_tokens SET used_at = datetime('now') WHERE id = ?",
                (reset_row["id"],),
            )
            log_action(
                db, org_id=target_user["org_id"], actor_user_id=target_user["id"],
                actor_role=target_user["role"], actor_name=target_user["full_name"],
                action="password_reset_completed",
                description="Set a new password via an emailed reset link.",
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

        flash("Your password has been updated. You can now log in.", "success")
        return redirect(url_for("auth.login"))

    db.close()
    return render_template("reset_password.html", token=token)


@auth_bp.route("/")
@login_required
def dashboard_redirect():
    """Send each role to the right home page after login."""
    role = session.get("role")
    if role == "engineer":
        return redirect(url_for("admin.engineer_dashboard"))
    elif role == "admin":
        return redirect(url_for("admin.admin_dashboard"))
    else:
        return redirect(url_for("auth.login"))
