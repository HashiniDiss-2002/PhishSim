-- Schema for the Phishing Simulation & Compliance Platform
-- SQLite database

DROP TABLE IF EXISTS email_verification_otps;
DROP TABLE IF EXISTS support_tickets;
DROP TABLE IF EXISTS password_reset_tokens;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS interactions;
DROP TABLE IF EXISTS campaign_emails;
DROP TABLE IF EXISTS campaigns;
DROP TABLE IF EXISTS employees;
DROP TABLE IF EXISTS threat_intel_scenarios;
DROP TABLE IF EXISTS threat_intel_sources;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS organizations;

-- A tenant / client organization
CREATE TABLE organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    suspended INTEGER NOT NULL DEFAULT 0,   -- 1 = platform engineer has suspended this org
                                            -- (e.g. non-payment, suspected malicious use);
                                            -- blocks login for that org's admin/user accounts.
    ethics_accepted_at TEXT,                -- timestamp the registering admin accepted the
                                            -- Responsible Use declaration (see auth.py
                                            -- register_ethics()). NULL for an organization
                                            -- that predates self-registration (e.g. seeded
                                            -- demo data) — never NULL for one created through
                                            -- the public /register flow, since rejecting the
                                            -- declaration there means no organization row is
                                            -- created at all.
    logo_path TEXT,                         -- relative path (under static/) to an uploaded
                                            -- logo image, set via admin.upload_logo(). NULL
                                            -- means no real logo was uploaded — branding.py
                                            -- falls back to its generated placeholder banner.
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Login accounts. role is one of: engineer, admin, user
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER,                       -- NULL for platform engineers (no tenant)
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('engineer', 'admin', 'user')),
    full_name TEXT NOT NULL,
    department TEXT,                      -- NULL = core admin (full org access);
                                           -- a value = department admin, scoped to it.
                                           -- Only meaningful when role = 'admin'.
    mfa_secret TEXT,                       -- base32 TOTP secret (services/totp.py).
                                           -- NULL until this account completes MFA
                                           -- setup for the first time.
    mfa_enabled INTEGER NOT NULL DEFAULT 0,-- 0/1. MFA is mandatory for every
                                           -- admin/engineer account in this MVP;
                                           -- this flag just tracks whether setup
                                           -- has been completed yet, so login()
                                           -- knows whether to route to
                                           -- /mfa/setup or /mfa/verify.
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (org_id) REFERENCES organizations(id)
);

-- Employee roster imported by an admin (via CSV in the MVP)
CREATE TABLE employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL,
    department TEXT,
    job_title TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (org_id) REFERENCES organizations(id),
    UNIQUE(org_id, email)
);

-- A simulation campaign (a single "wave" of simulated phishing emails)
CREATE TABLE campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    condition TEXT NOT NULL CHECK (condition IN ('generic', 'personalized')),
    pretext_context TEXT,                 -- the public/industry context fed to the LLM
    department TEXT,                      -- NULL = org-wide (created by core admin);
                                           -- a value = scoped to that department admin's dept.
    stage2_reference TEXT,                -- NULL = ordinary Stage 1 campaign. A value is a
                                           -- structural-feature summary of a real, publicly
                                           -- reported phishing campaign (never its literal
                                           -- content) used to inform generation — see
                                           -- services/pretext_generator.py and methodology 3.2.4.
    stage2_source_url TEXT,               -- the real article's URL, when stage2_reference was
                                           -- extracted automatically via services/threat_intel.py
                                           -- (NULL if stage2_reference was typed in manually).
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'test_sent', 'launched')),
    -- Sender/domain spoofing simulation (services/domain_spoofing.py):
    -- a SYNTHETIC look-alike sender identity generated once per campaign
    -- and reused for every email in it, so the "From" shown to recipients
    -- is consistent across the campaign. NEVER a real third-party domain —
    -- see domain_spoofing.py's ethical-safeguard docstring. NULL for a
    -- campaign created before this feature existed.
    spoofed_sender_name TEXT,
    spoofed_domain TEXT,
    spoofed_address TEXT,
    -- Which fake-login page style this campaign's click-through link
    -- renders: 'standard' (a plain embedded login form, the original
    -- behaviour) or 'bitb' (Browser-in-the-Browser — a fake OS/browser
    -- window chrome drawn in HTML/CSS around the same form, simulating
    -- the real 2022+ BITB phishing technique for awareness purposes).
    -- See tracking.py: track_click().
    fake_login_style TEXT NOT NULL DEFAULT 'standard' CHECK (fake_login_style IN ('standard', 'bitb')),
    -- Delivery vector: 'email_link' is the original behaviour (a tracked
    -- hyperlink). 'callback_toad' simulates callback phishing / TOAD
    -- (Telephone-Oriented Attack Delivery) — the email contains NO link
    -- at all, only a fictional, non-routable phone number to call (see
    -- services/pretext_generator.py's TOAD_TEMPLATE and its reserved
    -- NANP 555-01XX number range, and tracking.py: track_call()).
    vector TEXT NOT NULL DEFAULT 'email_link' CHECK (vector IN ('email_link', 'callback_toad')),
    created_by INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (org_id) REFERENCES organizations(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- One generated email per employee per campaign
CREATE TABLE campaign_emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    employee_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,            -- unique tracking token embedded in links/pixel
    subject TEXT NOT NULL,
    html_body TEXT NOT NULL,
    has_attachment INTEGER NOT NULL DEFAULT 0,  -- 1 if the LLM decided this pretext
                                                 -- realistically includes an attachment
                                                 -- (see pretext_generator.py). Drives the
                                                 -- MITRE ATT&CK technique tagging in
                                                 -- services/attack_mapping.py — a campaign
                                                 -- with at least one such email also maps to
                                                 -- T1566.001 (Spearphishing Attachment), not
                                                 -- only T1566.002 (Spearphishing Link).
    -- Which Cialdini persuasion principle this specific email's pretext
    -- relies on (authority, urgency, social_proof, scarcity, liking,
    -- reciprocity) — set by the LLM (personalized), fixed per template
    -- (generic/TOAD). Drives services/compliance_mapper.py's per-employee
    -- susceptibility profiling (which principles this person falls for).
    persuasion_principle TEXT,
    -- Which difficulty tier this email was generated at: 'reinforcement'
    -- (simpler/more obvious cues — chosen for an employee whose recent
    -- risk score is High/Critical), 'standard' (no history yet, or
    -- Medium risk), or 'advanced' (a more subtle, highly realistic
    -- pretext — chosen for a Low-risk/vigilant employee). See admin.py's
    -- adaptive-difficulty logic in create_campaign().
    difficulty_level TEXT NOT NULL DEFAULT 'standard',
    sent_at TEXT,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (employee_id) REFERENCES employees(id)
);

-- Every recorded interaction event
CREATE TABLE interactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_email_id INTEGER NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('open', 'click', 'submit', 'download', 'report', 'called')),
    -- Milliseconds between the fake-login page loading and the recipient
    -- submitting the form — a lightweight behavioural signal (never any
    -- keystroke content, only elapsed time) distinguishing an impulsive,
    -- near-instant submission from a hesitant one. NULL for any event
    -- type other than 'submit', and NULL when the submitting browser
    -- didn't run the timing script (e.g. JS disabled) rather than 0.
    -- See templates/fake_login.html / bitb_login.html and
    -- services/compliance_mapper.py: classify_click_speed().
    dwell_ms INTEGER,
    occurred_at TEXT NOT NULL DEFAULT (datetime('now')),
    -- The requesting browser's IP address (request.remote_addr) and
    -- User-Agent header, captured at the moment of the event (see
    -- tracking.py: _log_event()). Shown on the per-recipient interaction
    -- timeline (admin.interaction_timeline / templates/interaction_timeline.html)
    -- alongside the timestamp, so an admin can see not just THAT someone
    -- clicked/submitted/downloaded but roughly WHO/WHERE/WHAT FROM --
    -- useful for spotting e.g. a security scanner or proxy pre-fetching
    -- the link rather than the actual recipient. Nullable: NULL for any
    -- interaction recorded before this column existed (see
    -- migrate_add_interaction_metadata.py), never fabricated.
    ip_address TEXT,
    user_agent TEXT,
    FOREIGN KEY (campaign_email_id) REFERENCES campaign_emails(id)
);

-- Stage 2 automation: trusted CTI listing/category/RSS pages the platform
-- ENGINEER curates (never a client admin) — e.g. a site's "phishing" tag
-- page or RSS feed. The system scans these to discover candidate articles
-- itself; it never crawls the open web unsupervised. See
-- services/threat_source_crawler.py.
CREATE TABLE threat_intel_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    label TEXT,
    added_by INTEGER,                      -- engineer user id
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (added_by) REFERENCES users(id)
);

-- Auto-discovered, auto-extracted real-world phishing campaign scenarios.
-- 'summary' holds STRUCTURAL features only (pretext category, framing,
-- delivery vector) — never the real article's literal content, domains,
-- or links (see services/threat_intel.py, methodology 3.2.4 "defanging").
-- A client admin only ever SELECTS from these at campaign creation; they
-- cannot type a URL or a summary themselves.
--
-- delivery_channel / pretext_category_tag: a SECOND, fixed-vocabulary
-- classification of the same article, alongside (not instead of) the
-- free-text 'summary' — see services/threat_intel.py's DELIVERY_CHANNELS
-- / PRETEXT_CATEGORY_TAGS. The free-text summary reads well to a human
-- but can't be reliably grouped/counted (two articles about the same
-- real-world trend rarely use identical wording); these two columns let
-- services/threat_trends.py answer "what's trending across our sources
-- right now" (e.g. "messaging-app phishing is up this month") without
-- fragile text parsing. NULL for scenarios discovered before this
-- feature existed.
CREATE TABLE threat_intel_scenarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER,                     -- which source this was discovered from
    article_url TEXT NOT NULL UNIQUE,
    article_title TEXT,
    summary TEXT NOT NULL,
    delivery_channel TEXT,
    pretext_category_tag TEXT,
    discovered_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (source_id) REFERENCES threat_intel_sources(id) ON DELETE SET NULL
);

-- Admin-facing audit trail. actor_role/actor_name are SNAPSHOTS taken at
-- the time of the action (not a live join to users), so a log entry still
-- reads sensibly even if that account is later renamed or removed.
-- action is a short machine-readable code; description is the
-- human-readable detail shown on the audit log pages. See services/audit.py.
--
-- Visibility is enforced in admin.py, not here: a core admin sees every
-- row for their own org_id (their own tenant's full history); the
-- platform engineer sees only rows whose `action` is in the explicit
-- ENGINEER_VISIBLE_ACTIONS allow-list (organization_registered,
-- org_suspended, org_reactivated) across every org — never
-- campaign/employee-level actions, preserving the same "engineer has no
-- tenant data access" boundary enforced elsewhere (see admin.py,
-- engineer_dashboard()).
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER,                        -- which organization this action concerns
                                            -- (NULL only for a hypothetical platform-wide
                                            -- event with no single org — unused today)
    actor_user_id INTEGER,                 -- who performed the action (nullable: the account
                                            -- may since have been deleted)
    actor_role TEXT,                       -- snapshot of the actor's role at the time
    actor_name TEXT,                       -- snapshot of the actor's full name at the time
    action TEXT NOT NULL,                  -- short machine code, e.g. 'campaign_created'
    description TEXT NOT NULL,             -- human-readable detail for the log page
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (org_id) REFERENCES organizations(id),
    FOREIGN KEY (actor_user_id) REFERENCES users(id)
);

-- A client admin's support request to the platform engineer (see
-- admin.py: contact_support()/support_inbox() and templates/support.html /
-- engineer_support.html). Deliberately a SEPARATE channel from every other
-- tenant-isolation boundary in this project: unlike campaign/employee
-- data, a support ticket's subject/message is free text the admin chose
-- to write and send to the platform operator, the same as emailing a real
-- support desk -- so the engineer CAN read it, by design. The UI warns
-- the admin not to paste real employee data or credentials into one.
CREATE TABLE support_tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    raised_by_user_id INTEGER NOT NULL,
    raised_by_name TEXT NOT NULL,          -- snapshot, same reasoning as audit_log's actor_name
    raised_by_role TEXT NOT NULL,          -- 'admin' (core or department -- see description below)
    org_name TEXT NOT NULL,                -- snapshot of the organization's name at the time
    subject TEXT NOT NULL,
    message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    engineer_response TEXT,
    responded_by_name TEXT,
    responded_at TEXT,
    FOREIGN KEY (org_id) REFERENCES organizations(id),
    FOREIGN KEY (raised_by_user_id) REFERENCES users(id)
);

-- Single-use, expiring tokens for the core-admin-triggered password reset
-- flow (see auth.py: reset_password(); admin.py: reset_admin_password()).
-- The CORE ADMIN NEVER SETS OR SEES the new password — triggering a reset
-- only generates this token and emails a link to the affected admin, who
-- alone chooses their new password at /reset-password/<token>.
CREATE TABLE password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    requested_by INTEGER,                  -- the core admin who triggered this reset
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    used_at TEXT,                          -- set once the token has been used; a used or
                                            -- expired token is never accepted again
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (requested_by) REFERENCES users(id)
);

-- Email-ownership verification for self-registration (see auth.py:
-- register() / register_verify_email() / register_ethics()). Keyed by
-- EMAIL rather than user_id, because no `users` row exists yet at this
-- point in the flow -- the organization/admin account is only ever
-- created in register_ethics()'s "accept" branch, same as before this
-- feature existed.
--
-- otp_hash is a werkzeug password-hash of the 6-digit code, the same
-- convention used for password_hash elsewhere -- the plaintext code is
-- emailed to the registrant but NEVER stored (not here, and not in the
-- Flask session, which is a signed-but-NOT-encrypted cookie the browser
-- itself can read). attempts guards against brute-forcing a 6-digit
-- code; a row past OTP_MAX_ATTEMPTS (see auth.py) is treated as dead
-- without deleting it, so the audit trail of attempts is preserved.
CREATE TABLE email_verification_otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    otp_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    verified_at TEXT                       -- set once this code has been successfully
                                            -- entered; a verified or expired row is never
                                            -- accepted again (see _verify_otp() in auth.py)
);
