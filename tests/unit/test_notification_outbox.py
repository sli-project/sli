"""N03 contracts with fake durable storage, clock, authorization and transport."""

from copy import deepcopy
from dataclasses import replace
from http import HTTPStatus
from uuid import uuid4

import pytest

from server.api.routes import notification_outbox as routes
from server.sli.core import notification_outbox as outbox
from server.sli.reporting.v2.definition import QueryContext
from server.sli.reporting.v2.reports.notification_deliveries import REPORT


def access(*, role="admin", scope=None, actions=("view", "configure_channel"), fields=("technical",)):
    return {"subject": {"coarse_role": role}, "capabilities": ["access.manage", "field.technical"],
            "reports": [{"report_key": key, "allowed": True, "allowed_actions": list(actions),
                         "grants": [{"allowed_actions": list(actions), "field_categories": list(fields),
                                     "scope": scope or {"kind": "all"}}]}
                        for key in ("notifications.channels", "notifications.deliveries")]}


def payload(**overrides):
    return {"recipient_user_id": 2, "channel": "smtp", "enabled": True, **overrides}


def test_database_uuid_values_use_the_same_metadata_contract_as_json():
    value = uuid4()
    assert outbox.identifier(value) == str(value)
    assert outbox._project({"id": value, "private": "synthetic-secret-value"}, ("id",)) == {"id": str(value)}


@pytest.fixture(autouse=True)
def no_database(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected database access")
    monkeypatch.setattr(outbox, "connect", forbidden)
    monkeypatch.setattr(outbox.database, "query_rows", forbidden)
    monkeypatch.setattr(outbox, "effective_access", forbidden)


class Store:
    """Transaction snapshots and a fake clock survive connection/worker replacement."""

    def __init__(self):
        self.subscriptions, self.jobs, self.attempts = {}, {}, []
        self.channels = {
            "smtp": {"enabled": True, "tls_mode": "starttls", "secret_ref": "SLI_NOTIFY_SMTP_PASSWORD", "revision": 1, "next_delivery_at": 0},
            "telegram": {"enabled": True, "tls_mode": "tls", "secret_ref": "SLI_NOTIFY_TELEGRAM_TOKEN", "revision": 1, "next_delivery_at": 0},
        }
        self.now = 100
        self.calls = []
        self.commits = 0
        self.audit = []
        self.publications = {}
        self.alert_streak = 0

    def connect(self):
        return Connection(self)

    def snapshot(self):
        return deepcopy((self.subscriptions, self.jobs, self.attempts, self.channels, self.alert_streak))

    def record_audit(self, cursor, details):
        self.audit.append(details)


class Connection:
    def __init__(self, store):
        self.store = store
        self.before = store.snapshot()
        self.rows = []
        self.committed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *_):
        if not self.committed:
            (self.store.subscriptions, self.store.jobs, self.store.attempts,
             self.store.channels, self.store.alert_streak) = self.before

    def cursor(self):
        # Separate cursor context: closing it does not roll back the connection.
        return Cursor(self)

    def commit(self):
        self.committed = True
        self.store.commits += 1


class Cursor:
    def __init__(self, conn):
        self.conn = conn
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def fetchone(self):
        return self.rows.pop(0) if self.rows else None

    def execute(self, sql, params=()):
        store = self.conn.store
        sql = " ".join(sql.split())
        store.calls.append((sql, params))
        self.rows = []
        if sql.startswith("insert into notification_subscriptions"):
            identifier, owner, recipient, channel, enabled = params
            row = dict(id=identifier, owner_user_id=owner, recipient_user_id=recipient, channel=channel,
                       enabled=enabled, revision=1, updated_at=store.now)
            store.subscriptions[identifier] = row
            self.rows = [deepcopy(row)]
        elif sql.startswith("update notification_subscriptions"):
            recipient, channel, enabled, identifier, revision = params
            row = store.subscriptions.get(identifier)
            if row and row["revision"] == revision:
                row.update(recipient_user_id=recipient, channel=channel, enabled=enabled, revision=revision + 1)
                self.rows = [deepcopy(row)]
        elif sql.startswith("select * from notification_subscriptions"):
            row = store.subscriptions.get(params[0])
            self.rows = [deepcopy(row)] if row else []
        elif sql.startswith("select enabled,tls_mode,secret_ref,revision from notification_channels"):
            self.rows = [deepcopy(store.channels[params[0]])]
        elif sql.startswith("select public.notification_finding_object("):
            self.rows = [{"finding_id": store.publications.get(params[0])}]
        elif sql.startswith("select finding_id,notification_kind from public.notification_finding_brief("):
            self.rows = [{"finding_id": store.publications.get(params[0]), "notification_kind": "remote_access"}]
        elif sql.startswith("select enabled,tls_mode,secret_ref,revision, next_delivery_at"):
            row = deepcopy(store.channels[params[0]])
            self.rows = [{**row, "cooling_down": row["next_delivery_at"] > store.now}]
        elif sql.startswith("update notification_channels set next_delivery_at="):
            store.channels["telegram"]["next_delivery_at"] = store.now + params[0]
        elif "pg_advisory_xact_lock" in sql:
            pass
        elif sql.startswith("select * from notification_outbox"):
            problem, recipient, channel = params
            self.rows = [deepcopy(row) for row in store.jobs.values()
                         if (row["object_id"], row["recipient_user_id"], row["channel"]) == (problem, recipient, channel)]
        elif sql.startswith("select count(*)"):
            self.rows = [{"total": sum(row["state"] in {"pending", "sending", "retry"} for row in store.jobs.values())}]
        elif sql.startswith("insert into notification_outbox"):
            identifier, subscription, revision, problem, recipient, channel = params
            row = dict(id=identifier, subscription_id=subscription, subscription_revision=revision,
                       object_kind="test_problem", object_id=problem, recipient_user_id=recipient, channel=channel,
                       state="pending", attempts=0, result_code=None, available_at=store.now, created_at=store.now,
                       updated_at=store.now, lease_token=None, lease_until=None, delivery_reason="live", delay_minutes=0)
            store.jobs[identifier] = row
            self.rows = [deepcopy(row)]
        elif sql.startswith("select pg_catalog.set_config("):
            pass
        elif sql.startswith("with candidate as") or sql == 'select * from public.notification_claim_fair()':
            fair = sql == 'select * from public.notification_claim_fair()'
            eligible = [row for row in store.jobs.values()
                        if (row["state"] in {"pending", "retry"} and row["available_at"] <= store.now)
                        or (row["state"] == "sending" and row["lease_until"] <= store.now)]
            if fair:
                eligible = [row for row in eligible if row['object_kind'] in {'test_problem', 'semantic_finding', 'report_schedule'}
                            and row['channel'] in {'smtp', 'telegram'}]
            if "object_kind<>'report_schedule'" in sql:
                eligible = [row for row in eligible if row['object_kind'] != 'report_schedule']
            if "next_delivery_at" in sql or fair:
                eligible = [row for row in eligible if row["channel"] != "telegram"
                            or store.channels["telegram"]["next_delivery_at"] <= store.now]
            if "and channel='telegram'" in sql:
                eligible = [row for row in eligible if row["channel"] == "telegram" and row["object_kind"] in {"test_problem", "semantic_finding"}]
            if eligible:
                def rank(item):
                    if not fair:
                        return 0
                    report = item['object_kind'] == 'report_schedule'
                    return int(not report) if store.alert_streak >= 3 else int(report)
                row = sorted(eligible, key=lambda item: (rank(item), item["created_at"], item["id"]))[0]
                row.update(state="sending", lease_token=str(uuid4()) if fair else params[0], lease_until=store.now + 60, attempts=row["attempts"] + 1)
                if fair:
                    store.alert_streak = 0 if row['object_kind'] == 'report_schedule' else min(3, store.alert_streak + 1)
                self.rows = [deepcopy(row)]
        elif sql.startswith("select id from notification_outbox"):
            row = store.jobs.get(params[0])
            if row and row["state"] == "sending" and row["lease_token"] == params[1] and row["lease_until"] > store.now:
                self.rows = [{"id": row["id"]}]
        elif sql.startswith("update notification_outbox set state='cancelled'"):
            for row in store.jobs.values():
                if row["subscription_id"] == params[0] and row["state"] in {"pending", "sending", "retry"}:
                    row.update(state="cancelled", result_code="subscription_changed", lease_token=None, lease_until=None)
        elif sql.startswith("update notification_outbox set state='retry'"):
            row = store.jobs[params[0]]
            assert row["lease_token"] == params[1]
            row.update(state="retry", result_code="telegram_rate_limited", attempts=row["attempts"] - 1,
                       lease_token=None, lease_until=None, available_at=store.channels["telegram"]["next_delivery_at"])
        elif sql.startswith("update notification_outbox set state="):
            state, code, delay, identifier, token = params
            row = store.jobs[identifier]
            if row["state"] == "sending" and row["lease_token"] == token:
                row.update(state=state, result_code=code, available_at=store.now + delay, lease_token=None, lease_until=None)
                self.rows = [{"id": identifier}]
        elif sql.startswith("insert into notification_attempts"):
            store.attempts.append(params)
        else:
            pytest.fail("unsupported fake query")


@pytest.fixture
def store(monkeypatch):
    store = Store()
    monkeypatch.setattr(outbox, "connect", store.connect)
    monkeypatch.setattr(outbox, "require_recipient", lambda user_id: None)
    return store


def subscribe(store, **overrides):
    return outbox.save_subscription(access(), 1, payload(**overrides), audit=store.record_audit)


def enqueue(store, subscription=None, problem=None):
    subscription = subscription or subscribe(store)
    return outbox.enqueue_test_problem(access(), subscription["id"], {"problem_id": problem or str(uuid4())}, audit=store.record_audit)


def test_problem_replay_after_dry_run_and_worker_restart_keeps_one_job(store):
    subscription = subscribe(store)
    problem = str(uuid4())
    first = enqueue(store, subscription, problem)
    assert enqueue(store, subscription, problem)["id"] == first["id"]
    assert len(store.jobs) == 1 and first["state"] == "pending"
    seen = []
    assert outbox.process_one(transport=lambda job: seen.append(job) or "dry_run")
    assert store.jobs[first["id"]]["state"] == "dry_run"
    assert store.jobs[first["id"]]["result_code"] == "simulated"
    # Each call opens a new connection; no worker-local deduplication cache.
    assert not outbox.process_one()
    assert enqueue(store, subscription, problem)["id"] == first["id"]
    assert len(store.jobs) == len(store.attempts) == len(seen) == 1
    assert set(seen[0]) == set(outbox.JOB_FIELDS)


def test_expired_lease_is_reclaimed_with_new_token_and_stable_job_id(store):
    first = enqueue(store)
    abandoned = outbox.claim_job()
    assert abandoned["id"] == first["id"]
    assert outbox.claim_job() is None
    store.now += 60
    assert outbox.process_one()
    row = store.jobs[first["id"]]
    assert row["state"] == "dry_run" and row["attempts"] == 2
    assert len(store.jobs) == len(store.attempts) == 1


def test_stale_worker_cannot_dispatch_or_finish_new_lease(store, monkeypatch):
    first = enqueue(store)
    old = outbox.claim_job()
    store.now += 60
    current = outbox.claim_job()
    assert current["lease_token"] != old["lease_token"]
    monkeypatch.setattr(outbox, "claim_job", lambda: old)
    assert outbox.process_one(transport=lambda _: pytest.fail("stale dispatch"))
    assert store.jobs[first["id"]]["lease_token"] == current["lease_token"]
    assert store.attempts == []


def test_audit_failure_rolls_back_subscription_and_enqueue(store):
    def broken(*_):
        raise RuntimeError("synthetic-secret-value")
    with pytest.raises(RuntimeError):
        outbox.save_subscription(access(), 1, payload(), audit=broken)
    assert store.subscriptions == {} and store.commits == 0
    subscription = subscribe(store)
    with pytest.raises(RuntimeError):
        outbox.enqueue_test_problem(access(), subscription["id"], {"problem_id": str(uuid4())}, audit=broken)
    assert store.jobs == {}


def test_two_overlapping_subscriptions_deduplicate_but_channels_and_recipients_are_independent(store):
    problem = str(uuid4())
    a = enqueue(store, subscribe(store), problem)
    b = enqueue(store, subscribe(store), problem)
    assert a["id"] == b["id"]
    enqueue(store, subscribe(store, channel="telegram"), problem)
    enqueue(store, subscribe(store, recipient_user_id=3), problem)
    assert len(store.jobs) == 3
    while outbox.process_one():
        pass
    assert len(store.attempts) == 3


def test_edit_cancels_queued_and_leased_work_and_replay_cannot_resend(store):
    subscription = subscribe(store)
    first = enqueue(store, subscription)
    outbox.claim_job()
    updated = outbox.save_subscription(access(), 1, payload(enabled=False, revision=1),
                                       subscription_id=subscription["id"], audit=store.record_audit)
    assert updated["revision"] == 2
    assert store.jobs[first["id"]]["state"] == "cancelled"
    assert not outbox.process_one()
    with pytest.raises(LookupError):
        enqueue(store, subscription, first["object_id"])
    with pytest.raises(LookupError):
        outbox.save_subscription(access(), 1, payload(revision=1), subscription_id=subscription["id"], audit=store.record_audit)


def test_admin_can_disable_subscription_after_recipient_access_is_revoked(store, monkeypatch):
    subscription = subscribe(store)
    first = enqueue(store, subscription)
    def denied(_):
        raise PermissionError("synthetic revoked access")
    monkeypatch.setattr(outbox, "require_recipient", denied)
    updated = outbox.save_subscription(access(), 1, payload(enabled=False, revision=1),
                                       subscription_id=subscription["id"], audit=store.record_audit)
    assert not updated["enabled"] and store.jobs[first["id"]]["state"] == "cancelled"


def test_update_checks_saved_owner_and_rolls_back_when_original_owner_is_revoked(store, monkeypatch):
    subscription = subscribe(store)
    def denied(user_id):
        if user_id == 1:
            raise PermissionError("synthetic revoked owner")
    monkeypatch.setattr(outbox, "require_recipient", denied)
    with pytest.raises(PermissionError):
        outbox.save_subscription(access(), 3, payload(revision=1),
                                 subscription_id=subscription["id"], audit=store.record_audit)
    assert store.subscriptions[subscription["id"]]["revision"] == 1


@pytest.mark.parametrize("user", [1, 2])
def test_revoked_owner_or_recipient_blocks_without_dispatch(store, monkeypatch, user):
    first = enqueue(store)
    def require(user_id):
        if user_id == user:
            raise PermissionError("synthetic-private-value")
    monkeypatch.setattr(outbox, "require_recipient", require)
    assert outbox.process_one(transport=lambda _: pytest.fail("revoked dispatch"))
    assert store.jobs[first["id"]]["state"] == "blocked"
    assert store.attempts[0][-1] == "recipient_denied"


@pytest.mark.parametrize("failure", ["transport", "access"])
def test_bounded_retries_and_fixed_error_codes_without_exception_text(store, monkeypatch, caplog, failure):
    first = enqueue(store)
    def broken(*_):
        raise RuntimeError("synthetic-secret-value")
    if failure == "access":
        monkeypatch.setattr(outbox, "require_recipient", broken)
    for delay in (60, 300, 900, 3600, 3600):
        assert outbox.process_one(transport=broken)
        row = store.jobs[first["id"]]
        assert row["result_code"] == ("access_unavailable" if failure == "access" else "transport_unavailable")
        assert not outbox.process_one(transport=broken)
        store.now += delay
    assert row["state"] == "failed" and row["attempts"] == 5
    assert "synthetic-secret-value" not in str(store.jobs) + str(store.attempts) + caplog.text


def test_one_channel_failure_does_not_stop_other_channel(store):
    problem = str(uuid4())
    enqueue(store, subscribe(store), problem)
    enqueue(store, subscribe(store, channel="telegram"), problem)
    def transport(job):
        if job["channel"] == "telegram":
            raise RuntimeError("synthetic-secret-value")
        return "dry_run"
    assert outbox.process_one(transport=transport)
    assert outbox.process_one(transport=transport)
    assert {row["channel"]: row["state"] for row in store.jobs.values()} == {"smtp": "dry_run", "telegram": "retry"}


def test_fake_transport_cannot_claim_provider_acceptance(store):
    first = enqueue(store)
    outbox.process_one(transport=lambda _: "accepted")
    assert store.jobs[first["id"]]["state"] == "retry"


def test_opt_in_smtp_acceptance_is_durable_and_other_channel_stays_simulated(store, monkeypatch):
    from server.sli.core import notification_smtp
    problem = str(uuid4())
    subscription = subscribe(store)
    first = enqueue(store, subscription, problem)
    enqueue(store, subscribe(store, channel="telegram"), problem)
    seen = []
    monkeypatch.setattr(notification_smtp, "send", lambda job, channel: seen.append((job, channel)) or "accepted")
    while outbox.process_one(smtp=True):
        pass
    assert {row["channel"]: row["state"] for row in store.jobs.values()} == {"smtp": "accepted", "telegram": "dry_run"}
    assert store.jobs[first["id"]]["result_code"] == "accepted"
    assert len(seen) == 1 and seen[0][0]["recipient_user_id"] == 2
    assert seen[0][1]["enabled"]
    assert enqueue(store, subscription, problem)["id"] == first["id"]
    assert not outbox.process_one(smtp=True)
    assert len(store.jobs) == len(store.attempts) == 2


def test_published_problem_is_resolved_only_after_access_checks_and_sent_by_reference(store, monkeypatch):
    from server.sli.core import notification_smtp
    first = enqueue(store)
    store.jobs[first["id"]]["object_kind"] = "semantic_finding"
    store.publications[first["object_id"]] = 17
    checked, sent = [], []
    monkeypatch.setattr(outbox, "require_recipient", lambda user: checked.append(user))
    def send(job, channel):
        assert checked == [1, 2]
        sent.append(job)
        return "accepted"
    monkeypatch.setattr(notification_smtp, "send", send)
    assert outbox.process_one(smtp=True)
    assert sent[0]["finding_id"] == 17 and sent[0]["object_id"] == first["object_id"]
    assert store.jobs[first["id"]]["state"] == "accepted"


def test_revoked_published_problem_does_not_resolve_metadata_or_dispatch(store, monkeypatch):
    first = enqueue(store)
    store.jobs[first["id"]]["object_kind"] = "semantic_finding"
    def denied(_):
        raise PermissionError("synthetic revoked access")
    monkeypatch.setattr(outbox, "require_recipient", denied)
    assert outbox.process_one(transport=lambda _: pytest.fail("revoked dispatch"))
    assert store.jobs[first["id"]]["state"] == "blocked"
    assert not any("notification_finding_object(" in sql for sql, _ in store.calls)


@pytest.mark.parametrize("code,state", [("smtp_not_configured", "blocked"), ("smtp_auth_failed", "blocked"),
    ("smtp_rejected", "failed"), ("smtp_unavailable", "retry"), ("smtp_outcome_unknown", "delivery_unknown")])
def test_smtp_failure_is_independent_and_safe(store, monkeypatch, code, state, caplog):
    from server.sli.core import notification_smtp
    first = enqueue(store)
    enqueue(store, subscribe(store, channel="telegram"))
    monkeypatch.setattr(notification_smtp, "send", lambda *_: code)
    while outbox.process_one(smtp=True):
        pass
    assert store.jobs[first["id"]]["state"] == state
    assert store.jobs[first["id"]]["result_code"] == code
    assert next(row for row in store.jobs.values() if row["channel"] == "telegram")["state"] == "dry_run"
    if state != "retry":
        store.now += 3600
        assert not outbox.process_one(smtp=True)
    assert not caplog.text


def test_smtp_retry_rechecks_recipient_before_reading_secret_or_sending(store, monkeypatch):
    from server.sli.core import notification_smtp
    first = enqueue(store)
    monkeypatch.setattr(notification_smtp, "send", lambda *_: "smtp_unavailable")
    assert outbox.process_one(smtp=True)
    store.now += 60
    def denied(_):
        raise PermissionError("synthetic-private-value")
    monkeypatch.setattr(outbox, "require_recipient", denied)
    monkeypatch.setattr(notification_smtp, "send", lambda *_: pytest.fail("revoked SMTP dispatch"))
    assert outbox.process_one(smtp=True)
    assert store.jobs[first["id"]]["state"] == "blocked"
    assert store.jobs[first["id"]]["result_code"] == "recipient_denied"


def test_smtp_worker_cli_explicitly_selects_real_delivery(monkeypatch):
    monkeypatch.setattr("sys.argv", ["notification_outbox", "--smtp", "--limit", "1"])
    calls = []
    monkeypatch.setattr(outbox, "process_one", lambda **kwargs: calls.append(kwargs) or True)
    assert outbox.main() == 0 and calls == [{"smtp": True}]


def test_smtp_receipt_survives_lease_expiry_while_holding_job_lock(store, monkeypatch):
    from server.sli.core import notification_smtp
    first = enqueue(store)
    def accepted(*_):
        store.now += 60
        return "accepted"
    monkeypatch.setattr(notification_smtp, "send", accepted)
    assert outbox.process_one(smtp=True)
    assert store.jobs[first["id"]]["state"] == "accepted"
    assert len(store.attempts) == 1
    assert not outbox.process_one(smtp=True)


def test_telegram_failure_is_independent_of_smtp_and_replay_keeps_job_identity(store, monkeypatch):
    from server.sli.core import notification_smtp, notification_telegram
    first = enqueue(store, subscribe(store, channel="telegram"))
    mail = enqueue(store, subscribe(store), first["object_id"])
    monkeypatch.setattr(notification_telegram, "send", lambda *_: notification_telegram.Outcome("telegram_chat_denied"))
    monkeypatch.setattr(notification_smtp, "send", lambda *_: "accepted")
    while outbox.process_one(smtp=True, telegram=True):
        pass
    assert store.jobs[first["id"]]["state"] == "blocked"
    assert store.jobs[mail["id"]]["state"] == "accepted"
    subscription = store.subscriptions[first["subscription_id"]]
    assert enqueue(store, subscription, first["object_id"])["id"] == first["id"]
    assert len(store.jobs) == len(store.attempts) == 2


def test_installed_telegram_worker_delivers_publication_and_preserves_smtp_queue(store, monkeypatch):
    from server.sli.core import notification_telegram
    mail = enqueue(store)
    first = enqueue(store, subscribe(store, channel="telegram"))
    store.jobs[first["id"]].update(object_kind="semantic_finding", object_severity="high")
    store.publications[first["object_id"]] = 17
    seen = []
    monkeypatch.setattr(notification_telegram, "send", lambda job, _: seen.append(job) or notification_telegram.Outcome("accepted"))
    assert outbox.process_one(telegram=True, telegram_only=True)
    assert store.jobs[first["id"]]["state"] == "accepted"
    assert store.jobs[mail["id"]]["state"] == "pending"
    assert seen[0]["finding_id"] == 17 and seen[0]["notification_kind"] == "remote_access"
    assert not outbox.process_one(telegram=True, telegram_only=True)


def test_telegram_retry_after_survives_worker_restart_and_does_not_starve_smtp(store, monkeypatch):
    from server.sli.core import notification_smtp, notification_telegram
    subscription = subscribe(store, channel="telegram")
    first = enqueue(store, subscription)
    calls = []
    def limited(*_):
        calls.append(1)
        return notification_telegram.Outcome("telegram_rate_limited", 1200)
    monkeypatch.setattr(notification_telegram, "send", limited)
    assert outbox.process_one(telegram=True)
    assert store.jobs[first["id"]]["available_at"] == store.now + 1200
    assert store.jobs[first["id"]]["state"] == "retry"
    second = enqueue(store, subscription)
    mail = enqueue(store)
    monkeypatch.setattr(notification_smtp, "send", lambda *_: "accepted")
    assert outbox.process_one(smtp=True, telegram=True)
    assert store.jobs[mail["id"]]["state"] == "accepted"
    assert not outbox.process_one(telegram=True)
    assert len(calls) == 1 and store.jobs[second["id"]]["attempts"] == 0
    store.now += 1200
    monkeypatch.setattr(notification_telegram, "send", lambda *_: notification_telegram.Outcome("accepted"))
    assert outbox.process_one(telegram=True)
    assert not outbox.process_one(telegram=True)
    store.now += 3
    assert outbox.process_one(telegram=True)
    assert all(row["state"] == "accepted" for row in store.jobs.values())


def test_telegram_racing_claim_is_deferred_without_consuming_an_attempt(store, monkeypatch):
    from server.sli.core import notification_telegram
    first = enqueue(store, subscribe(store, channel="telegram"))
    claimed = outbox.claim_job(telegram=True)
    store.channels["telegram"]["next_delivery_at"] = store.now + 300
    monkeypatch.setattr(outbox, "claim_job", lambda **_: claimed)
    monkeypatch.setattr(notification_telegram, "send", lambda *_: pytest.fail("cooldown bypassed"))
    assert outbox.process_one(telegram=True)
    row = store.jobs[first["id"]]
    assert row["state"] == "retry" and row["available_at"] == store.now + 300 and row["attempts"] == 0
    assert row["lease_token"] is None and not store.attempts


@pytest.mark.parametrize("code,state", [("telegram_unavailable", "failed"), ("telegram_outcome_unknown", "delivery_unknown")])
def test_telegram_retry_budget_and_unknown_submission_are_terminal(store, monkeypatch, code, state):
    from server.sli.core import notification_telegram
    first = enqueue(store, subscribe(store, channel="telegram"))
    monkeypatch.setattr(notification_telegram, "send", lambda *_: notification_telegram.Outcome(code))
    if state == "failed":
        for delay in (60, 300, 900, 3600):
            assert outbox.process_one(telegram=True)
            assert store.jobs[first["id"]]["available_at"] == store.now + delay
            store.now += delay
    assert outbox.process_one(telegram=True)
    assert store.jobs[first["id"]]["state"] == state
    store.now += 3600
    assert not outbox.process_one(telegram=True)


@pytest.mark.parametrize("change", ["revoked", "disabled", "subscription"])
def test_telegram_retry_rechecks_access_channel_and_subscription(store, monkeypatch, change):
    from server.sli.core import notification_telegram
    original = notification_telegram.send
    first = enqueue(store, subscribe(store, channel="telegram"))
    monkeypatch.setattr(notification_telegram, "send", lambda *_: notification_telegram.Outcome("telegram_unavailable"))
    assert outbox.process_one(telegram=True)
    store.now += 60
    if change == "revoked":
        def denied(_):
            raise PermissionError("synthetic-private-value")
        monkeypatch.setattr(outbox, "require_recipient", denied)
    elif change == "disabled":
        store.channels["telegram"]["enabled"] = False
    else:
        store.subscriptions[first["subscription_id"]]["revision"] += 1
    monkeypatch.setattr(notification_telegram, "send", lambda job, channel:
                        original(job, channel) if not channel["enabled"] else pytest.fail("unexpected network call"))
    assert outbox.process_one(telegram=True)
    assert store.jobs[first["id"]]["state"] == ("cancelled" if change == "subscription" else "blocked")


def test_worker_cli_explicitly_enables_both_transports(monkeypatch):
    monkeypatch.setattr("sys.argv", ["notification_outbox", "--smtp", "--telegram", "--limit", "1"])
    calls = []
    monkeypatch.setattr(outbox, "process_one", lambda **kwargs: calls.append(kwargs) or True)
    assert outbox.main() == 0 and calls == [{"smtp": True, "telegram": True}]


def test_capacity_rejects_new_work_but_allows_replay(store, monkeypatch):
    subscription = subscribe(store)
    first = enqueue(store, subscription)
    monkeypatch.setattr(outbox, "MAX_PENDING", 1)
    assert enqueue(store, subscription, first["object_id"])["id"] == first["id"]
    with pytest.raises(ValueError, match="^notification_queue_full$"):
        enqueue(store, subscription)
    assert len(store.jobs) == 1


@pytest.mark.parametrize("decision", [access(role="viewer"), access(scope={"kind": "domain", "ids": [1]}),
    access(scope={"kind": "domain", "ids": [2]}), access(fields=()), {**access(), "capabilities": []}])
def test_unprivileged_and_other_scopes_denied_before_database(decision, monkeypatch):
    monkeypatch.setattr(outbox, "connect", lambda: pytest.fail("unauthorized database access"))
    monkeypatch.setattr(outbox.database, "query_rows", lambda *_: pytest.fail("unauthorized read"))
    with pytest.raises(PermissionError):
        outbox.save_subscription(decision, 1, payload(), audit=lambda *_: None)
    with pytest.raises(PermissionError):
        outbox.enqueue_test_problem(decision, str(uuid4()), {"problem_id": str(uuid4())}, audit=lambda *_: None)
    with pytest.raises(PermissionError):
        outbox.list_subscriptions(decision)
    with pytest.raises(PermissionError):
        REPORT.query(QueryContext(access=decision, params={}))


@pytest.mark.parametrize("body", [None, [], {}, payload(token="synthetic-secret-value"), payload(channel=[]),
    payload(enabled=1), payload(recipient_user_id=True), payload(recipient_user_id=0), payload(recipient_user_id=2**63)])
def test_subscription_validation_rejects_unknown_fields_and_invalid_types_before_write(body, monkeypatch):
    monkeypatch.setattr(outbox, "connect", lambda: pytest.fail("invalid write"))
    with pytest.raises(ValueError, match="^invalid_notification_request$"):
        outbox.save_subscription(access(), 1, body, audit=lambda *_: None)


def test_recipient_requires_active_user_and_explicit_global_queue_scope(monkeypatch):
    monkeypatch.setattr(outbox, "recipient_access", lambda _: {})
    with pytest.raises(PermissionError):
        outbox.require_recipient(2)
    class QueueAccess:
        scope = type("Scope", (), {"mode": "restricted"})()
    monkeypatch.setattr(outbox, "queue_access", lambda _: QueueAccess())
    with pytest.raises(PermissionError):
        outbox.require_recipient(2)
    QueueAccess.scope.mode = "all"
    outbox.require_recipient(2)


class Handler:
    def __init__(self, *, decision=None, body=None, csrf=True):
        self.decision = decision if decision is not None else access()
        self.body = body
        self.csrf = csrf
        self.reads = 0
        self._principal = {"type": "session", "id": 1, "role": "admin"}

    def _access_decision(self):
        return self.decision

    def _authorize_mutation(self, *, required_role):
        assert required_role == "admin"
        return self.csrf

    def _read_json_body(self):
        self.reads += 1
        return self.body

    def _send_json(self, body, status=HTTPStatus.OK):
        self.response, self.status = body, status


def test_api_create_update_enqueue_replay_and_fixed_errors(store, monkeypatch, caplog):
    monkeypatch.setattr(routes, "record_access_audit_with_cursor", lambda **kwargs: store.record_audit(kwargs["cursor"], kwargs["details"]))
    handler = Handler(body=payload())
    assert routes.try_handle_post(handler, routes.PREFIX)
    assert handler.status == HTTPStatus.OK
    subscription = handler.response["item"]
    handler.body = {"problem_id": str(uuid4())}
    path = routes.PREFIX + "/" + subscription["id"] + "/test"
    routes.try_handle_post(handler, path)
    first = handler.response["item"]
    routes.try_handle_post(handler, path)
    assert first["id"] == handler.response["item"]["id"] and len(store.jobs) == 1
    handler.body = {"problem_id": "synthetic-secret-value"}
    routes.try_handle_post(handler, path)
    assert handler.status == HTTPStatus.BAD_REQUEST
    assert handler.response == {"error": "invalid_notification_request"}
    def broken(*_, **__):
        raise RuntimeError("synthetic-secret-value")
    monkeypatch.setattr(outbox, "connect", broken)
    handler.body = payload()
    routes.try_handle_post(handler, routes.PREFIX)
    assert handler.status == HTTPStatus.SERVICE_UNAVAILABLE
    assert handler.response == {"error": "notifications_unavailable"}
    assert "synthetic-secret-value" not in str(handler.response) + caplog.text
    assert not routes.try_handle_post(handler, "/unrelated")
    assert not routes.try_handle_get(handler, "/unrelated", {})


def test_api_csrf_and_grants_checked_before_reading_body(store):
    handler = Handler(csrf=False)
    assert routes.try_handle_post(handler, routes.PREFIX) and handler.reads == 0
    handler = Handler(decision=access(role="viewer"))
    routes.try_handle_post(handler, routes.PREFIX)
    assert handler.status == HTTPStatus.FORBIDDEN and handler.reads == 0
    handler = Handler(decision=access(actions=("view",)))
    routes.try_handle_post(handler, routes.PREFIX)
    assert handler.status == HTTPStatus.FORBIDDEN and handler.reads == 0


def test_subscription_get_projects_metadata_and_requires_view_grant(monkeypatch):
    row = {key: 1 for key in outbox.SUBSCRIPTION_FIELDS}
    monkeypatch.setattr(outbox.database, "query_rows", lambda *_: [{**row, "private": "synthetic-secret-value"}])
    handler = Handler()
    assert routes.try_handle_get(handler, routes.PREFIX, {})
    assert handler.status == HTTPStatus.OK and handler.response == {"items": [row]}
    handler.decision = access(role="viewer")
    routes.try_handle_get(handler, routes.PREFIX, {})
    assert handler.status == HTTPStatus.FORBIDDEN


def test_journal_allowlists_metadata_paginates_and_preserves_failures(monkeypatch):
    calls = []
    rows = [{key: str(uuid4()) if key in {"id", "subscription_id", "object_id"} else "synthetic"
             for key in outbox.JOB_FIELDS} for _ in range(2)]
    rows.sort(key=lambda row: row["id"], reverse=True)
    def query(sql, params):
        calls.append((sql, params))
        return [{**row, "private_value": "synthetic-secret-value"} for row in rows if len(params) == 1 or row["id"] < params[0]]
    monkeypatch.setattr(outbox.database, "query_rows", query)
    context = QueryContext(access=access(), params={}, limit=1)
    first = REPORT.query(context)
    assert first["state"] == "ok" and first["has_more"] and first["next_cursor"] == rows[0]["id"]
    assert set(first["items"][0]) == set(outbox.JOB_FIELDS)
    second = REPORT.query(replace(context, cursor=first["next_cursor"]))
    assert second["items"] == [rows[1]] and not second["has_more"]
    assert calls[-1][1] == (rows[0]["id"], 2)
    with pytest.raises(ValueError):
        REPORT.query(replace(context, cursor="synthetic-private-value"))
    def broken(*_):
        raise RuntimeError("synthetic-secret-value")
    monkeypatch.setattr(outbox.database, "query_rows", broken)
    result = REPORT.query(context)
    assert result["state"] == "error" and result["items"] == []
    assert "synthetic-secret-value" not in str(first) + str(result)


def test_routes_navigation_registry_and_intent_are_registered():
    from server.api.http_server import create_app
    from server.sli.access.access_control_v4 import route_capability
    from server.sli.reporting.navigation_registry import load_registry
    from server.sli.reporting.report_intent_contract import validate_report_intent
    from server.sli.reporting.v2.registry import get_report
    assert get_report(REPORT.key) is REPORT
    assert load_registry()[1][REPORT.key]["section_id"] == "admin"
    assert validate_report_intent(REPORT.intent_contract()) == REPORT.key
    assert route_capability(routes.PREFIX) == "access.manage"
    registry = create_app()
    assert routes in registry.candidates("POST", routes.PREFIX)
    assert routes in registry.candidates("POST", routes.PREFIX + "/" + str(uuid4()) + "/test")


def test_worker_cli_is_bounded_and_sanitizes_failures(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["notification_outbox", "--limit", "2"])
    calls = []
    monkeypatch.setattr(outbox, "process_one", lambda: calls.append(1) or True)
    assert outbox.main() == 0 and len(calls) == 2
    def broken():
        raise RuntimeError("synthetic-secret-value")
    monkeypatch.setattr(outbox, "process_one", broken)
    assert outbox.main() == 1
    assert capsys.readouterr().out == "notification_worker_unavailable\n"


@pytest.mark.parametrize("reason", ["historical_replay", "history_import"])
def test_terminal_history_suppression_is_journalled_without_claim_or_transport(store, reason, monkeypatch):
    from server.sli.core import notification_smtp, notification_telegram
    first = enqueue(store)
    row = store.jobs[first["id"]]
    row.update(object_kind="semantic_finding", delivery_reason=reason, state="cancelled", result_code=reason)
    monkeypatch.setattr(notification_smtp, "send", lambda *_: pytest.fail("historical SMTP dispatch"))
    monkeypatch.setattr(notification_telegram, "send", lambda *_: pytest.fail("historical Telegram dispatch"))
    assert not outbox.process_one(smtp=True, telegram=True)
    assert row["attempts"] == 0 and not store.attempts
    monkeypatch.setattr(outbox.database, "query_rows", lambda *_: [row])
    journal, more = outbox.journal_rows()
    assert not more and journal[0]["result_code"] == reason and journal[0]["delivery_reason"] == reason

