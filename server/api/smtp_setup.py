"""Write-only SMTP setup through existing admin grants and isolated writer."""
from contextlib import contextmanager

from server.sli.core import notification_channels as channels, notification_outbox as outbox, smtp_setup
from server.sli.core.postgres_runtime_pipeline import connect


@contextmanager
def _setup_connection(*, write):
    """A bounded session lock spans reserve/complete commits; context closes it.

    Shared status readers cannot observe the reservation gap. Generic metadata
    edits still advance revision and thereby invalidate the file generation.
    """
    suffix = "" if write else "_shared"
    with connect() as conn, conn.cursor() as cur:
        cur.execute(f"select pg_try_advisory_lock{suffix}(hashtext('sli_smtp_setup')) as locked")
        if not cur.fetchone()["locked"]:
            raise smtp_setup.SMTPSetupError("smtp_setup_conflict")
        try:
            yield conn, cur
        finally:
            # Clear an aborted transaction before unlock. If either fails, the
            # outer connection context closes the session and releases its lock.
            conn.rollback()
            cur.execute(f"select pg_advisory_unlock{suffix}(hashtext('sli_smtp_setup'))")


def _recipients(body, allowed, user):
    rows = body.get("recipients")
    if not isinstance(rows, list) or len(rows) != len(allowed):
        raise smtp_setup.SMTPSetupError("smtp_setup_invalid")
    mapping = {}
    seen = set()
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {"user_id", "mailbox"}
                or type(row["user_id"]) is not int or row["user_id"] not in allowed or row["user_id"] in seen
                or not isinstance(row["mailbox"], str)):
            raise smtp_setup.SMTPSetupError("smtp_setup_invalid")
        seen.add(row["user_id"])
        if row["mailbox"]:
            if not smtp_setup.mailbox(row["mailbox"]):
                raise smtp_setup.SMTPSetupError("smtp_setup_invalid")
            mapping[str(row["user_id"])] = row["mailbox"]
    if seen != allowed or str(user) not in mapping:
        raise smtp_setup.SMTPSetupError("smtp_setup_invalid")
    return mapping


def configure(handler, action, audit):
    access = handler._access_decision()
    channels.require_access(access, action="configure_channel")
    principal = getattr(handler, "_principal", None) or {}
    user = principal.get("id")
    if principal.get("type") != "session" or type(user) is not int or not 0 < user < 2**63:
        raise PermissionError("smtp_setup_denied")
    body = handler._read_json_body()
    expected = {"status": set(), "save": {"host", "port", "username", "sender", "password", "recipients", "revision", "tls_mode", "enabled"}}
    if action not in expected or not isinstance(body, dict) or set(body) != expected[action]:
        raise smtp_setup.SMTPSetupError("smtp_setup_invalid")
    subscriptions = [row for row in outbox.list_subscriptions(access) if row["channel"] == "smtp"]
    allowed = {user} | {row["recipient_user_id"] for row in subscriptions}
    if action == "status":
        # Pair file status with its channel revision under the same dispatch
        # fence. Otherwise old host metadata could acquire a newer revision.
        with _setup_connection(write=False) as (conn, cur):
            cur.execute("select enabled,revision,tls_mode from notification_channels where kind='smtp' for share")
            item = cur.fetchone()
            if item is None:
                raise smtp_setup.SMTPSetupError()
            result = smtp_setup.request("status", user, revision=item["revision"])
        keys = {"host", "port", "username", "sender", "recipients", "secret_set", "needs_save"}
        if (set(result) != keys or type(result["secret_set"]) is not bool or type(result["needs_save"]) is not bool
                or not isinstance(result["recipients"], dict)
                or not all(isinstance(result[key], str) for key in ("host", "username", "sender"))
                or type(result["port"]) is not int or not 1 <= result["port"] <= 65535):
            raise smtp_setup.SMTPSetupError()
        return {key: result[key] for key in ("host", "port", "username", "sender", "secret_set", "needs_save")} | {
            "self_user_id": user, "recipients": [{"user_id": target, "mailbox": result["recipients"].get(str(target), "")}
                                                for target in sorted(allowed)],
            "revision": item["revision"], "tls_mode": item["tls_mode"], "enabled": item["enabled"]}
    metadata = channels.validate_update("smtp", {key: body[key] for key in ("revision", "tls_mode", "enabled")} | {
        "secret_ref": channels.SECRET_REFS["smtp"]})
    recipients = _recipients(body, allowed, user)
    smtp_setup.validate_config({key: body[key] for key in ("host", "port", "username", "sender")} | {
        "recipients": recipients, "base_url": "https://validation.invalid/app"})
    if body["password"] != "":
        smtp_setup.validate_password(body["password"])
    for target in recipients:
        outbox.require_recipient(int(target))
    for subscription in subscriptions:
        if str(subscription["recipient_user_id"]) in recipients and subscription["enabled"]:
            outbox.require_recipient(subscription["owner_user_id"])
    # Commit the disable before touching files. The exclusive row lock waits for
    # in-flight delivery; its revision fences any concurrent settings edit.
    with _setup_connection(write=True) as (conn, cur):
        cur.execute("""update notification_channels set enabled=false,revision=revision+1,
            updated_at=clock_timestamp() where kind='smtp' and revision=%s returning revision""", (metadata["revision"],))
        row = cur.fetchone()
        if row is None:
            raise smtp_setup.SMTPSetupError("smtp_setup_conflict")
        revision = row["revision"]
        audit(cur, {"kind": "smtp", "operation": "save", "phase": "requested"})
        conn.commit()
        # First-run binding uses only the authenticated principal, not a caller ID.
        # Failure leaves the channel disabled; existing bindings are not rewritten.
        if not any(row["recipient_user_id"] == user and row["owner_user_id"] == user for row in subscriptions):
            outbox.save_subscription(access, user, {"recipient_user_id": user, "channel": "smtp", "enabled": True}, audit=audit)
        cur.execute("select enabled,revision from notification_channels where kind='smtp' for update")
        row = cur.fetchone()
        if not row or row["revision"] != revision or row["enabled"]:
            raise smtp_setup.SMTPSetupError("smtp_setup_conflict")
        result = smtp_setup.request("save", user, **{key: body[key] for key in ("host", "port", "username", "sender", "password")},
                                    recipients=recipients, previous_revision=metadata["revision"], revision=revision)
        if result != {"secret_set": True, "needs_save": False}:
            raise smtp_setup.SMTPSetupError()
        # Complete the reserved logical generation; never advance a second time.
        cur.execute("""update notification_channels set enabled=%s,tls_mode=%s,
            updated_at=clock_timestamp() where kind='smtp' returning revision""", (metadata["enabled"], metadata["tls_mode"]))
        final = cur.fetchone()
        audit(cur, {"kind": "smtp", "operation": "save", "phase": "completed"})
        conn.commit()
    return {"secret_set": True, "needs_save": False, "revision": final["revision"]}
