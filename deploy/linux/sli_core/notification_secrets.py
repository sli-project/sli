"""Allowlisted notification credentials and value-free local diagnostics.

Only the delivery process may receive the file settings. Availability means
local readability/format, never successful authentication with a provider.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping

from deploy.linux.sli_core.secret_files import secret_value

NOTIFICATION_SECRET_SETTINGS = {
    "notification_smtp_password": "SLI_NOTIFICATION_SMTP_PASSWORD",
    "notification_telegram_token": "SLI_NOTIFICATION_TELEGRAM_TOKEN",
}
NOTIFICATION_DELIVERY_SERVICE = "notification-delivery"
MAX_SECRET_BYTES = 65536


class NotificationSecretError(ValueError):
    """Fixed codes only; no paths, credential material or provider responses."""


def validate_notification_secret(secret_ref: str, value: str) -> None:
    if secret_ref not in NOTIFICATION_SECRET_SETTINGS:
        raise NotificationSecretError("notification_secret_ref_invalid")
    if (not value or len(value.encode("utf-8")) > MAX_SECRET_BYTES
            or any(char in value for char in "\r\n\x00")):
        raise NotificationSecretError("notification_secret_invalid")
    if secret_ref == "notification_telegram_token" and not re.fullmatch(r"[1-9][0-9]*:[A-Za-z0-9_-]+", value):
        raise NotificationSecretError("notification_secret_invalid")


def read_notification_secret(secret_ref: str, *, environ: Mapping[str, str] | None = None) -> str:
    """Resolve a registry reference through the existing file-backed reader.

    Unlike legacy database credentials, notification credentials cannot fall
    back to a plaintext environment value. A reference is never a file path.
    """
    setting = NOTIFICATION_SECRET_SETTINGS.get(secret_ref)
    if setting is None:
        raise NotificationSecretError("notification_secret_ref_invalid")
    source = os.environ if environ is None else environ
    if source.get(setting):
        raise NotificationSecretError("notification_secret_file_required")
    if setting + "_FILE" not in source:
        raise NotificationSecretError("notification_secret_not_configured")
    try:
        value = secret_value(setting, environ=source)
    except ValueError:
        raise NotificationSecretError("notification_secret_unavailable") from None
    validate_notification_secret(secret_ref, value or "")
    return value


def notification_secret_status(secret_ref: str, *, environ: Mapping[str, str] | None = None) -> dict:
    """Return only safe metadata, suitable for an authorized channel row."""
    try:
        read_notification_secret(secret_ref, environ=environ)
    except NotificationSecretError as exc:
        code = str(exc)
        state = {"notification_secret_not_configured": "not_configured",
                 "notification_secret_unavailable": "unavailable"}.get(code, "invalid")
        return {"secret_status": state, "secret_error": code}
    return {"secret_status": "available", "secret_error": None}
