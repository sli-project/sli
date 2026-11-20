"""Durable subscriptions and fenced delivery; real transports are opt-in."""

from __future__ import annotations

from uuid import UUID, uuid4

from server.sli.access.access_control_v4 import effective_access
from server.sli.core import database, notification_channels as channels
from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.reporting.v2.reports.security_problems import queue_access

SUBSCRIPTION_FIELDS = ("id", "owner_user_id", "recipient_user_id", "channel", "enabled", "revision", "updated_at")
JOB_FIELDS = ("id", "subscription_id", "object_id", "channel", "state", "attempts", "result_code", "created_at", "updated_at",
              "delivery_reason", "delay_minutes")
MAX_PENDING = 10000


def identifier(value):
    if isinstance(value, UUID):
        return str(value)
    try:
        return str(UUID(value))
    except (TypeError, ValueError, AttributeError):
        raise ValueError("invalid_notification_request") from None


def _positive(value):
    if type(value) is not int or not 0 < value < 2**63 - 1:
        raise ValueError("invalid_notification_request")
    return value


def _project(row, fields):
    return {key: str(row[key]) if isinstance(row[key], UUID) else row[key] for key in fields}


def recipient_access(user_id):
    """Resolve an active user's current grants, never the worker's service grants."""
    return effective_access(None, preview_user_id=user_id)


def require_recipient(user_id):
    # N03 test problems have no evidence scope. Require an explicit global queue
    # grant rather than treating a union of restricted scopes as installation access.
    if queue_access(recipient_access(user_id)).scope.mode != "all":
        raise PermissionError("notification_recipient_denied")


def list_subscriptions(access):
    channels.require_access(access)
    return [_project(row, SUBSCRIPTION_FIELDS) for row in database.query_rows(
        "select " + ",".join(SUBSCRIPTION_FIELDS) + " from notification_subscriptions order by id limit 1000",
    )]


def save_subscription(access, owner_user_id, body, *, audit, subscription_id=None):
    """An administrator approves a single user/channel binding; no address payload."""
    channels.require_access(access, action="configure_channel")
    owner_user_id = _positive(owner_user_id)
    expected = {"recipient_user_id", "channel", "enabled"} | ({"revision"} if subscription_id else set())
    if (not isinstance(body, dict) or set(body) != expected
            or not isinstance(body["channel"], str) or body["channel"] not in channels.SECRET_REFS
            or type(body["enabled"]) is not bool):
        raise ValueError("invalid_notification_request")
    recipient = _positive(body["recipient_user_id"])
    revision = _positive(body["revision"]) if subscription_id else None
    subscription_id = identifier(subscription_id) if subscription_id else str(uuid4())
    # Disabling must remain possible after the recipient or original owner loses
    # access. Enabling always checks the saved owner's and recipient's grants.
    if body["enabled"]:
        require_recipient(recipient)
        if revision is None:
            require_recipient(owner_user_id)
    with connect() as conn, conn.cursor() as cur:
        if revision is None:
            cur.execute(
                """insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled)
                   values(%s,%s,%s,%s,%s) returning *""",
                (subscription_id, owner_user_id, recipient, body["channel"], body["enabled"]),
            )
        else:
            cur.execute(
                """update notification_subscriptions set recipient_user_id=%s,channel=%s,enabled=%s,
                   revision=revision+1,updated_at=clock_timestamp()
                   where id=%s and revision=%s returning *""",
                (recipient, body["channel"], body["enabled"], subscription_id, revision),
            )
        row = cur.fetchone()
        if row is None:
            raise LookupError("notification_subscription_conflict")
        if body["enabled"] and revision is not None:
            require_recipient(row["owner_user_id"])
        # Revision changes invalidate pending and leased work. A stale worker's
        # completion cannot overwrite the cancellation because its token is cleared.
        if revision is not None:
            cur.execute(
                """update notification_outbox set state='cancelled',result_code='subscription_changed',
                   lease_token=null,lease_until=null,updated_at=clock_timestamp()
                   where subscription_id=%s and state in ('pending','sending','retry')""", (subscription_id,),
            )
        audit(cur, {"id": subscription_id, "revision": row["revision"]})
        conn.commit()
    return _project(row, SUBSCRIPTION_FIELDS)


def enqueue_test_problem(access, subscription_id, body, *, audit):
    """Explicit simulated problem, keyed by caller's stable UUID for replay."""
    channels.require_access(access, action="configure_channel")
    subscription_id = identifier(subscription_id)
    if not isinstance(body, dict) or set(body) != {"problem_id"}:
        raise ValueError("invalid_notification_request")
    problem_id = identifier(body["problem_id"])
    with connect() as conn, conn.cursor() as cur:
        cur.execute("select * from notification_subscriptions where id=%s for share", (subscription_id,))
        subscription = cur.fetchone()
        if not subscription or not subscription["enabled"]:
            raise LookupError("notification_subscription_unavailable")
        require_recipient(subscription["owner_user_id"])
        require_recipient(subscription["recipient_user_id"])
        job = enqueue_with_cursor(cur, subscription, problem_id=problem_id)
        audit(cur, {"id": str(job["id"]), "simulated": True})
        conn.commit()
    return _project(job, JOB_FIELDS)


def enqueue_with_cursor(cur, subscription, *, problem_id):
    """No commit: callers own the transaction, including publication in a later stage."""
    problem_id = identifier(problem_id)
    # Serialize admission, not the network. Enforce a bounded queue without
    # dropping an existing job when its replay arrives at the capacity boundary.
    cur.execute("select pg_advisory_xact_lock(hashtext('notification_outbox_admission'))")
    key = (problem_id, subscription["recipient_user_id"], subscription["channel"])
    cur.execute(
        """select * from notification_outbox where object_kind='test_problem'
           and object_id=%s and recipient_user_id=%s and channel=%s""", key,
    )
    existing = cur.fetchone()
    if existing:
        return existing
    cur.execute("select count(*) as total from notification_outbox where state in ('pending','sending','retry')")
    if cur.fetchone()["total"] >= MAX_PENDING:
        raise ValueError("notification_queue_full")
    cur.execute(
        """insert into notification_outbox(id,subscription_id,subscription_revision,object_kind,object_id,
           recipient_user_id,channel) values(%s,%s,%s,'test_problem',%s,%s,%s)
           on conflict do nothing returning *""",
        (str(uuid4()), subscription["id"], subscription["revision"], *key),
    )
    return cur.fetchone()


def claim_job(*, telegram=False, telegram_only=False, notification_only=False, include_reports=False):
    """SKIP LOCKED + fresh fencing token on each attempt, including expired leases."""
    if include_reports:
        if not telegram or not notification_only or telegram_only:
            raise ValueError('report_delivery_transports_required')
        # Fixed database policy serializes a persistent three-alert/one-report
        # burst across workers/restarts. Neither ready class monopolizes claims.
        with connect() as conn, conn.cursor() as cur:
            cur.execute("select pg_catalog.set_config('statement_timeout',%s,true), "
                        "pg_catalog.set_config('lock_timeout',%s,true)", ('2000ms', '500ms'))
            cur.execute('select * from public.notification_claim_fair()')
            row = cur.fetchone()
            conn.commit()
        return row
    cooldown = """and (channel<>'telegram' or exists (
        select 1 from notification_channels where kind='telegram' and next_delivery_at<=clock_timestamp()
    ))""" if telegram else ""
    if notification_only:
        kinds = "'test_problem','semantic_finding','report_schedule'" if include_reports else "'test_problem','semantic_finding'"
        cooldown += " and channel in ('telegram','smtp') and object_kind in (" + kinds + ")"
    elif telegram_only:
        cooldown += " and channel='telegram' and object_kind in ('test_problem','semantic_finding')"
    if not include_reports:
        cooldown += " and object_kind<>'report_schedule'"
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            f"""with candidate as (
                 select id from notification_outbox
                 where ((state in ('pending','retry') and available_at<=clock_timestamp())
                    or (state='sending' and lease_until<=clock_timestamp())) {cooldown}
                 order by created_at,id for update skip locked limit 1
               ) update notification_outbox j set state='sending',lease_token=%s,
                 lease_until=clock_timestamp()+interval '60 seconds',attempts=attempts+1,
                 updated_at=clock_timestamp()
               from candidate where j.id=candidate.id returning j.*""", (str(uuid4()),),
        )
        row = cur.fetchone()
        conn.commit()
    return row


def dry_run_transport(job):
    """No secret read, message body or provider acceptance, even on enabled channels."""
    return "dry_run"


def process_one(*, transport=dry_run_transport, smtp=False, telegram=False, telegram_only=False, notification_only=False, include_reports=False):
    """One bounded attempt. A restart reuses the durable job identity."""
    if include_reports and not (notification_only and smtp and telegram):
        raise ValueError("report_delivery_transports_required")
    job = (claim_job(telegram=True, notification_only=True, include_reports=True) if include_reports
           else claim_job(telegram=True, notification_only=True) if notification_only
           else claim_job(telegram=True, telegram_only=True) if telegram_only
           else claim_job(telegram=True) if telegram else claim_job())
    if job is None:
        return False
    with connect() as conn, conn.cursor() as cur:
        # Serialize subscription edits with permission checks and dispatch.
        prepared = None
        if job["object_kind"] == "report_schedule":
            from server.sli.core.report_schedule_delivery import load
            prepared = load(cur, job)
            subscription = prepared["subscription"] if prepared else None
        else:
            cur.execute("select * from notification_subscriptions where id=%s for share", (job["subscription_id"],))
            subscription = cur.fetchone()
        cur.execute(
            """select id from notification_outbox where id=%s and state='sending'
               and lease_token=%s and lease_until>clock_timestamp() for update""", (job["id"], job["lease_token"]),
        )
        if cur.fetchone() is None:
            return True
        state, code = "cancelled", "subscription_changed"
        if job["object_kind"] == "report_schedule" and prepared is None:
            state, code = "blocked", "recipient_denied"
        retry_after = 0
        if (subscription and subscription["enabled"] and subscription["revision"] == job["subscription_revision"]
                and subscription["recipient_user_id"] == job["recipient_user_id"] and subscription["channel"] == job["channel"]):
            try:
                dispatch_job = job
                if job["object_kind"] == "report_schedule":
                    from server.sli.core.report_schedules import prepare_delivery
                    dispatch_job = prepare_delivery(cur, job, subscription, prepared=prepared)
                else:
                    require_recipient(subscription["owner_user_id"])
                    require_recipient(job["recipient_user_id"])
            except (PermissionError, ValueError):
                state, code = "blocked", "recipient_denied"
            except Exception:
                state, code = "retry", "access_unavailable"
            else:
                try:
                    if job["object_kind"] == "semantic_finding":
                        if telegram_only or notification_only:
                            cur.execute("select finding_id,notification_kind from public.notification_finding_brief(%s)", (job["object_id"],))
                        else:
                            cur.execute("select public.notification_finding_object(%s) as finding_id", (job["object_id"],))
                        publication = cur.fetchone()
                        if not publication or not publication["finding_id"]:
                            raise ValueError("invalid_notification_object")
                        dispatch_job = {**job, "finding_id": int(publication["finding_id"]),
                                        "notification_kind": publication.get("notification_kind", "security")}
                    elif job["object_kind"] not in {"test_problem", "report_schedule"}:
                        raise ValueError("invalid_notification_object")
                    if smtp and job["channel"] == "smtp":
                        from server.sli.core import notification_smtp
                        # Hold the channel lock through dispatch too: an administrator's
                        # disable/TLS change must serialize with the current attempt.
                        cur.execute("select enabled,tls_mode,secret_ref,revision from notification_channels where kind=%s for share", ("smtp",))
                        channel = cur.fetchone()
                        if job["object_kind"] == "report_schedule" and (
                                not channel or channel["revision"] != dispatch_job["report_channel_revision"]):
                            raise PermissionError("notification_recipient_denied")
                        code = notification_smtp.send(dispatch_job, channel)
                        state = notification_smtp.RESULTS[code]
                    elif telegram and job["channel"] == "telegram":
                        from server.sli.core import notification_telegram
                        # One durable bot-wide limit across worker processes/restarts.
                        # The channel lock also serializes disable with dispatch.
                        cur.execute("""select enabled,tls_mode,secret_ref,revision,
                            next_delivery_at>clock_timestamp() as cooling_down
                            from notification_channels where kind=%s for update""", ("telegram",))
                        channel = cur.fetchone()
                        if job["object_kind"] == "report_schedule" and (
                                not channel or channel["revision"] != dispatch_job["report_channel_revision"]):
                            raise PermissionError("notification_recipient_denied")
                        if channel and channel["cooling_down"]:
                            # Another worker claimed before the previous send finished.
                            # Deferral is not a provider attempt and consumes no retry.
                            cur.execute("""update notification_outbox set state='retry',
                                result_code='telegram_rate_limited',attempts=attempts-1,
                                lease_token=null,lease_until=null,
                                available_at=(select next_delivery_at from notification_channels where kind='telegram'),
                                updated_at=clock_timestamp() where id=%s and lease_token=%s""",
                                (job["id"], job["lease_token"]))
                            conn.commit()
                            return True
                        outcome = notification_telegram.send(dispatch_job, channel)
                        code, retry_after = outcome.code, outcome.retry_after
                        state = notification_telegram.RESULTS[code]
                        cur.execute("""update notification_channels
                            set next_delivery_at=clock_timestamp()+(%s * interval '1 second') where kind='telegram'""",
                            (max(notification_telegram.MIN_INTERVAL, retry_after),))
                    else:
                        if transport(_project(job, JOB_FIELDS)) != "dry_run":
                            raise ValueError("invalid_simulated_transport_result")
                        state, code = "dry_run", "simulated"
                except PermissionError:
                    state, code = (("blocked", "recipient_denied") if job["object_kind"] == "report_schedule"
                                   else ("retry", "transport_unavailable"))
                except Exception:
                    state, code = "retry", "transport_unavailable"
        if state == "retry" and job["attempts"] >= 5:
            state = "failed"
        delays = (60, 300, 900, 3600)
        delay = max(delays[min(job["attempts"] - 1, len(delays) - 1)], retry_after)
        # We still hold the job's FOR UPDATE lock. No claimant can replace the
        # token here, even if the lease elapsed during dispatch; persist SMTP
        # acceptance rather than discard it and resend on the next attempt.
        cur.execute(
            """update notification_outbox set state=%s,result_code=%s,lease_token=null,lease_until=null,
               available_at=clock_timestamp()+(%s * interval '1 second'),updated_at=clock_timestamp()
               where id=%s and state='sending' and lease_token=%s
               returning id""", (state, code, delay, job["id"], job["lease_token"]),
        )
        completed = cur.fetchone()
        if completed:
            cur.execute(
                """insert into notification_attempts(job_id,attempt,state,result_code)
                   values(%s,%s,%s,%s)""", (job["id"], job["attempts"], state, code),
            )
        conn.commit()
    return True


def journal(access, *, before=None, limit=50):
    channels.require_access(access)
    return journal_rows(before=before, limit=limit)


def journal_rows(*, before=None, limit=50):
    """Internal reader; the v2 report resolves its own grant before calling."""
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError("invalid_notification_request")
    before = identifier(before) if before is not None else None
    rows = database.query_rows(
        "select " + ",".join(JOB_FIELDS) + ",object_kind from notification_outbox"
        + (" where id<?" if before else "") + " order by id desc limit ?",
        ((before,) if before else ()) + (limit + 1,),
    )
    run_ids = [row["object_id"] for row in rows[:limit] if row.get("object_kind") == "report_schedule"]
    runs = {str(row["id"]): row for row in database.query_rows(
        "select id,period_from,period_to,quality from report_schedule_runs where id=any(?::uuid[])", (run_ids,),
    )} if run_ids else {}
    return [{**_project(row, JOB_FIELDS), **{key: value for key, value in runs.get(str(row["object_id"]), {}).items() if key != "id"}}
            for row in rows[:limit]], len(rows) > limit


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Notification worker; one bounded batch, dry_run by default.")
    parser.add_argument("--limit", type=int, choices=range(1, 201), default=50)
    parser.add_argument("--smtp", action="store_true", help="Send enabled SMTP jobs using worker-local configuration and mounted SLI secrets.")
    parser.add_argument("--telegram", action="store_true", help="Send enabled Telegram jobs using worker-local configuration and mounted SLI secrets.")
    parser.add_argument("--schedules", action="store_true", help="Unsupported legacy option; report schedules require the separate producer.")
    args = parser.parse_args()
    try:
        if args.schedules:
            raise ValueError("report_schedules_require_separate_producer")
        for _ in range(args.limit):
            options = {key: True for key in ("smtp", "telegram") if getattr(args, key)}
            if not process_one(**options):
                break
    except Exception:
        # Never print DB/transport exception text, recipients or message values.
        print("notification_worker_unavailable")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

