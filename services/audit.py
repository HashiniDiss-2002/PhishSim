"""
audit.py
--------
Thin logging helper for the admin-facing audit trail (see the audit_log
table in schema.sql).

log_action() takes an already-open db connection and does NOT commit -
the INSERT becomes part of whatever transaction the caller is already
managing, so an audit entry is never recorded for an action that itself
later gets rolled back (e.g. campaign creation failing partway through).
Call it right before the caller's own db.commit().

actor_role and actor_name are stored as plain-text SNAPSHOTS rather than
only a foreign key to users, so a log entry still reads sensibly even if
that account is later renamed, changed, or removed.

ENGINEER_VISIBLE_ACTIONS is the explicit allow-list enforced by the
engineer-facing audit log route in admin.py: only these action codes are
ever shown to a platform engineer, across every organization. Every other
action code (campaign/employee-level) is core-admin-only, scoped to that
admin's own org_id - preserving the same "engineer has no tenant data
access" boundary enforced elsewhere in this project.
"""

ENGINEER_VISIBLE_ACTIONS = {
    "organization_registered",
    "org_suspended",
    "org_reactivated",
}


def log_action(db, *, org_id, actor_user_id, actor_role, actor_name, action, description):
    db.execute(
        "INSERT INTO audit_log (org_id, actor_user_id, actor_role, actor_name, action, description) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (org_id, actor_user_id, actor_role, actor_name, action, description),
    )
