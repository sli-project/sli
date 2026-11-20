"""Owner-approved AD review checks; presentation lives in the shared i18n catalog."""
from __future__ import annotations

from server.sli.core.messages import message
from server.sli.reporting.v2.definition import Column

PREFIX = "reports.ad.checks."
FIELDS = frozenset({"identity_basic", "technical", "security", "privilege"})
COMPUTER_FIELDS = FIELDS - {"privilege"}
CATALOG = {
    "users": (
        ("disabled_logon", "high"), ("new_privileged", "high"),
        ("reversible_password", "high"), ("inactive_privileged", "high"),
        ("spn_privileged", "high"), ("privileged_password_never_expires", "high"),
        ("locked_out", "medium"), ("service_interactive_logon", "medium"),
        ("kerberos_no_preauth", "medium"), ("inactive_enabled", "low"),
        ("old_password", "low"), ("password_never_expires", "low"),
    ),
    "computers": (
        ("unconstrained_delegation", "high"), ("unsupported_os", "high"),
        ("new_computer", "medium"), ("laps", "medium"), ("rbcd", "medium"),
        ("no_sli_agent", "medium"),
        ("inactive_enabled", "low"), ("old_machine_password", "low"),
    ),
}


def presentation(kind, key):
    envelopes = {field: message(f"{PREFIX}{kind}.{key}.{field}")
                 for field in ("title", "why", "action", "remediation")}
    return {**{field: envelope["text"] for field, envelope in envelopes.items()},
            "presentation_messages": envelopes}


def columns(kind="users"):
    return tuple(Column("check_" + key, message(PREFIX + "column." + key)["text"], column_kind,
                        path="severity_text" if key == "severity" else key,
                        field_categories=COMPUTER_FIELDS if kind == "computers" else FIELDS)
                 for key, column_kind in (("severity", "text"), ("title", "text"),
                                   ("objects", "list"), ("status_text", "text"),
                                   ("new_count", "number"), ("total", "number"),
                                   ("why", "text"), ("action", "text"),
                                   ("remediation", "text")))
