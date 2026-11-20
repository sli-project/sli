"""N01 channel metadata registry; secret import and delivery are separate stages."""

from __future__ import annotations

from server.sli.core import database
from server.sli.reporting.v2.access import resolve_access_scope
from server.sli.reporting.v2.definition import AccessRequirement

ACCESS = AccessRequirement("notifications.channels", required_fields=frozenset({"technical"}),
                           required_capabilities=frozenset({"access.manage"}),
                           required_role="admin", global_scope_only=True)
SECRET_REFS = {"smtp": "SLI_NOTIFY_SMTP_PASSWORD", "telegram": "SLI_NOTIFY_TELEGRAM_TOKEN"}
FIELDS = ("kind", "enabled", "tls_mode", "secret_ref", "state", "revision", "updated_at")
_SELECT = "select kind,enabled,tls_mode,secret_ref,state,revision,updated_at from notification_channels"


def require_access(access, *, action="view") -> None:
    """Installation metadata needs global grants, never a union of narrow scopes."""
    resolve_access_scope(access, ACCESS, action)


def _metadata(row):
    return {key: row[key] for key in FIELDS}


def list_channels(access):
    require_access(access)
    return [_metadata(row) for row in database.query_rows(_SELECT + " order by kind")]


def validate_update(kind, body):
    # Reject unknown fields without echoing user input (including credentials).
    if kind not in SECRET_REFS:
        raise LookupError("notification_channel_not_found")
    if not isinstance(body, dict) or set(body) != {"enabled", "tls_mode", "secret_ref", "revision"}:
        raise ValueError("invalid_notification_channel_metadata")
    modes = {"starttls", "tls"} if kind == "smtp" else {"tls"}
    if (type(body["enabled"]) is not bool or type(body["revision"]) is not int or not 1 <= body["revision"] < 2**63 - 1
            or not isinstance(body["tls_mode"], str) or body["tls_mode"] not in modes
            or body["secret_ref"] != SECRET_REFS[kind]):
        raise ValueError("invalid_notification_channel_metadata")
    return body


def update_channel(access, kind, body, *, audit):
    require_access(access, action="configure_channel")
    values = validate_update(kind, body)
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """update notification_channels set enabled=%s,tls_mode=%s,secret_ref=%s,
               revision=revision+1,updated_at=clock_timestamp()
               where kind=%s and revision=%s
               returning kind,enabled,tls_mode,secret_ref,state,revision,updated_at""",
            (values["enabled"], values["tls_mode"], values["secret_ref"], kind, values["revision"]),
        )
        row = cur.fetchone()
        if row is None:
            raise LookupError("notification_channel_revision_conflict")
        # Same transaction as metadata; values and secret material never enter audit.
        audit(cur, {"kind": kind, "revision": row["revision"],
                    "changed_fields": ["enabled", "tls_mode", "secret_ref"]})
        conn.commit()
    return _metadata(row)
