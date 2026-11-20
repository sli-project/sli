"""Write-only Telegram setup inside the existing admin/CSRF route boundary."""
from uuid import uuid4

from server.sli.core import database, notification_channels as channels, notification_outbox as outbox
from server.sli.core import telegram_setup
from server.sli.core.postgres_runtime_pipeline import connect


def configure(handler, action, audit):
    access = handler._access_decision()
    channels.require_access(access, action="configure_channel")
    principal = getattr(handler, "_principal", None) or {}
    user = principal.get("id")
    if principal.get("type") != "session" or type(user) is not int or user <= 0:
        raise PermissionError("telegram_setup_denied")
    body = handler._read_json_body()
    expected = {"token": {"token"}, "chats": set(), "bind": {"choice"}, "status": set(), "test": set()}
    if (action not in expected or not isinstance(body, dict)
            or not (set(body) == expected[action] or action == "token" and set(body) == {"token", "proxy_url"})):
        raise ValueError("telegram_setup_failed")
    if action == "token" and "proxy_url" in body:
        body["proxy_url"] = telegram_setup.validate_proxy_url(body["proxy_url"])
    # Persist an intent before crossing the file/DB boundary. A failed audit must
    # prevent all secret reads, network calls and file writes. No values in audit.
    if action != "status":
        with connect() as conn, conn.cursor() as cur:
            audit(cur, {"kind": "telegram", "operation": action, "phase": "requested"})
            conn.commit()
    if action == "token":
        # A mistyped token must not disable a working bot. Verify before taking
        # the channel lock, then fence delivery before publishing the replacement.
        telegram_setup.request("verify", user, **body)
        with connect() as conn, conn.cursor() as cur:
            cur.execute("""update notification_channels set enabled=false,revision=revision+1,
                updated_at=clock_timestamp() where kind='telegram'""")
            audit(cur, {"kind": "telegram", "operation": action, "phase": "verified"})
            conn.commit()
    if action == "test":
        telegram_setup.request("status", user)
        subscriptions = [s for s in outbox.list_subscriptions(access)
                         if s["recipient_user_id"] == user and s["owner_user_id"] == user
                         and s["channel"] == "telegram" and s["enabled"]]
        if not subscriptions:
            raise ValueError("telegram_setup_failed")
        job = outbox.enqueue_test_problem(access, subscriptions[0]["id"], {"problem_id": str(uuid4())}, audit=audit)
        return {"job_id": job["id"], "state": job["state"]}
    result = telegram_setup.request(action, user, **body)
    if action in {"token", "chats"}:
        with connect() as conn, conn.cursor() as cur:
            audit(cur, {"kind": "telegram", "operation": action, "phase": "completed"})
            conn.commit()
    if action == "bind":
        # Bind only the authenticated SLI user, never a user ID from the request.
        existing = [s for s in outbox.list_subscriptions(access)
                    if s["recipient_user_id"] == user and s["owner_user_id"] == user and s["channel"] == "telegram"]
        values = {"recipient_user_id": user, "channel": "telegram", "enabled": True}
        if existing:
            values["revision"] = existing[0]["revision"]
        outbox.save_subscription(access, user, values, audit=audit,
                                 subscription_id=existing[0]["id"] if existing else None)
        with connect() as conn, conn.cursor() as cur:
            cur.execute("""update notification_channels set enabled=true,revision=revision+1,
                updated_at=clock_timestamp() where kind='telegram'""")
            audit(cur, {"kind": "telegram", "operation": action, "phase": "completed"})
            conn.commit()
    if action == "status":
        rows = database.query_rows("""select id,state,updated_at from notification_outbox
            where channel='telegram' and recipient_user_id=? and object_kind='test_problem'
            order by created_at desc,id desc limit 1""", (user,))
        result["test_state"] = rows[0]["state"] if rows else None
        result["test_job_id"] = str(rows[0]["id"]) if rows else None
    return result
