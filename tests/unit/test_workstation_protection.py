"""WR06 per-station projections with synthetic snapshots and transactional fakes."""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json

import pytest

from server.sli.plugins.workstations import projection, projection_jobs, protection as p
from server.sli.plugins.workstations.importer import digest
from sli_agent.workstations import PROTECTION_COMPONENTS

NOW = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)
STATION = "fixture-station"
FLAG = "real_time_protection_enabled"


def snapshot(value=True, *, at=NOW, state="available", **components):
    flags = {**dict.fromkeys(PROTECTION_COMPONENTS, value), **components}
    data = {"state": state, "components": flags}
    return {"id": "a" * 64, "agent_key": "fixture-agent", "observed_at": at,
            "state": data, "state_sha256": digest(data)}


def test_known_false_components_are_one_station_reason_and_null_is_not_false():
    result = p.evaluate(snapshot(real_time_protection_enabled=False, nis_enabled=False,
                                 tamper_protected=None), now=NOW)
    c01, c09 = result["checks"]
    assert c01.quality.status == "partial"
    assert c01.counts.stations.to_dict() == {"value": 1, "relation": "at_least"}
    assert len(c01.reasons) == 1
    assert c01.reasons[0].params == {"components": "real_time_protection_enabled, nis_enabled"}
    assert result["summary"]["unknown_components"] == ["tamper_protected"]
    assert c09.counts.stations.value == 0


@pytest.mark.parametrize("value,expected", [(True, "complete"), (None, "partial")])
def test_no_false_does_not_create_c01(value, expected):
    c01 = p.evaluate(snapshot(value), now=NOW)["checks"][0]
    assert not c01.reasons and c01.quality.status == expected
    assert c01.counts.stations.value == (0 if value is True else None)
    assert c01.counts.stations.relation == ("exact" if value is True else "unknown")
    assert c01.counts.new_since_previous_login.value is None


@pytest.mark.parametrize("source,expected", [(None, "not_collected"),
    (snapshot(None, state="unavailable"), "unavailable")])
def test_missing_or_unavailable_snapshot_is_unknown_not_healthy_or_stale(source, expected):
    result = p.evaluate(source, now=NOW)
    c01, c09 = result["checks"]
    assert c01.quality.status == expected and c01.counts.stations.value is None
    assert not c01.reasons and not c09.reasons
    if source is None:
        assert result["summary"]["observed_at"] is None
        assert c09.counts.stations.value is None


def test_exact_24_hour_boundary_and_old_false_are_not_current_disabled():
    source = snapshot(False, at=NOW - timedelta(hours=24))
    assert p.evaluate(source, now=NOW)["checks"][0].counts.stations.value == 1
    result = p.evaluate(source, now=NOW + timedelta(microseconds=1), station_type="server")
    c01, c09 = result["checks"]
    assert c01.quality.status == "stale" and c01.counts.stations.value is None
    assert c01.reasons == ()
    assert c09.counts.stations.value == 1 and c09.reasons[0].code == "protection_stale"
    assert result["severities"] == {"C01": "high", "C09": "medium"}
    assert set(result["summary"]["components"].values()) == {None}
    assert set(result["summary"]["last_known_components"].values()) == {False}
    assert result["summary"]["next_refresh_at"] is None
    assert p.evaluate(source, now=NOW + timedelta(seconds=1))["severities"]["C09"] == "low"


def test_old_unavailable_and_future_snapshot_do_not_confirm_disabled():
    old = p.evaluate(snapshot(None, state="unavailable", at=NOW - timedelta(days=2)), now=NOW)
    assert old["checks"][0].counts.stations.value is None
    assert old["checks"][1].counts.stations.value == 1
    future = p.evaluate(snapshot(False, at=NOW + timedelta(hours=1)), now=NOW)
    assert future["checks"][0].quality.status == "unavailable"
    assert future["checks"][1].counts.stations.value is None
    assert future["summary"]["next_refresh_at"] == (NOW + timedelta(hours=1)).isoformat()


@pytest.mark.parametrize("value", [0, 1, "false", "true"])
def test_only_native_boolean_values_are_accepted(value):
    with pytest.raises(ValueError, match="state_invalid"):
        p.evaluate(snapshot(value), now=NOW)


def test_corrupt_state_and_naive_time_are_rejected():
    source = snapshot()
    source["state_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="snapshot_conflict"):
        p.evaluate(source, now=NOW)
    with pytest.raises(ValueError, match="timestamp_invalid"):
        p.evaluate(None, now=NOW.replace(tzinfo=None))


@pytest.mark.parametrize("old,new,expected", [
    (False, True, "protection_enabled"), (True, False, "protection_disabled"),
    (None, True, None), (None, False, None), (False, None, None),
    (False, False, None), (True, True, None),
])
def test_only_confirmed_boolean_transitions_create_history(old, new, expected):
    before = snapshot(old, at=NOW - timedelta(minutes=1))
    changes = p.transitions(before, snapshot(new))
    assert [row["change_kind"] for row in changes] == ([expected] if expected else [])
    if changes:
        assert changes[0]["components"] == list(PROTECTION_COMPONENTS)


def test_first_true_equal_time_and_unavailable_gap_never_invent_enablement():
    assert p.transitions(None, snapshot(True)) == []
    assert p.transitions(snapshot(False), snapshot(True)) == []
    assert p.transitions(snapshot(None, state="unavailable", at=NOW - timedelta(minutes=1)), snapshot(True)) == []


class PG:
    def __init__(self, current=None, station_type="workstation"):
        self.current, self.station_type, self.now = current, station_type, NOW
        self.history, self.findings, self.changes, self.summary, self.calls = {}, {}, {}, None, []
        self.one, self.rows = None, []

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    @contextmanager
    def transaction(self):
        before = deepcopy((self.findings, self.changes, self.summary))
        try:
            yield
        except Exception:
            self.findings, self.changes, self.summary = before
            raise

    def execute(self, sql, params=()):
        sql = " ".join(sql.split())
        self.calls.append((sql, params))
        self.one, self.rows = None, []
        if sql == "select clock_timestamp() as now":
            self.one = {"now": self.now}
        elif sql == "select value from public.platform_settings where key=%s":
            # The shared projection job also loads C07; no policy is configured here.
            assert params == ("workstations.logon_policy",)
        elif sql.startswith("select payload from"):
            keys = list(self.history)
            index = keys.index(params[1])
            if index:
                self.one = {"payload": self.history[keys[index - 1]]}
        elif sql.startswith("select i.station_type"):
            self.one = {"station_type": self.station_type, "observed_at": None,
                        **(self.current or {})}
        elif sql.startswith("select * from sli_plugin_workstations.check_findings"):
            rows = [row for row in self.findings.values() if row["check_id"] == params[1]]
            self.one = deepcopy(rows[-1]) if rows else None
        elif sql.startswith("insert into sli_plugin_workstations.check_findings"):
            fields = ("id", "station_id", "check_id", "rule_version", "episode_id", "condition_sha256",
                      "severity", "fact_at", "first_detected_at", "last_observed_at", "materially_changed_at",
                      "reason_code", "reason_params", "quality", "evidence_refs")
            row = dict(zip(fields, params, strict=True))
            for key in ("reason_params", "quality", "evidence_refs"):
                row[key] = json.loads(row[key])
            row.update(status="active", revision=1, resolved_at=None)
            self.findings.setdefault(row["id"], row)
        elif sql.startswith("update sli_plugin_workstations.check_findings"):
            row = self.findings[params[-1]]
            if row["condition_sha256"] != params[0]:
                row["revision"] += 1
                row["materially_changed_at"] = params[2]
            row.update(condition_sha256=params[3], status=params[4], severity=params[5],
                       last_observed_at=params[6], resolved_at=params[7], reason_params=json.loads(params[8]),
                       quality=json.loads(params[9]), evidence_refs=json.loads(params[10]))
        elif sql.startswith("insert into sli_plugin_workstations.station_changes"):
            self.changes.setdefault(params[0], {"kind": params[2], "event_at": params[3],
                "params": json.loads(params[6]), "refs": json.loads(params[8])})
        elif sql.startswith("insert into sli_plugin_workstations.station_summary"):
            value = json.loads(params[1])
            revision = self.summary["revision"] if self.summary else 0
            revision += int(self.summary is None or value != self.summary["protection"])
            self.summary = {"protection": value, "revision": revision}
        elif sql.startswith("select i.station_id"):
            due_at = self.summary["protection"]["next_refresh_at"] if self.summary else None
            if not self.summary or due_at and p.timestamp(due_at) < params[0]:
                self.rows = [{"station_id": STATION}]
        else:
            raise AssertionError(sql)

    def fetchone(self):
        return self.one

    def fetchall(self):
        return self.rows

    def apply(self, source):
        return p.apply(self, STATION, {"kind": "protection_state", "source_id": source,
                                     "payload": self.history[source]})


def test_callback_backlog_creates_one_enable_row_replay_does_not_duplicate():
    before, after = snapshot(False, at=NOW - timedelta(minutes=5)), snapshot(True)
    pg = PG(after)
    pg.history = {"fixture-first": before, "fixture-second": after}
    pg.apply("fixture-first")
    pg.apply("fixture-second")
    pg.apply("fixture-second")
    assert len(pg.changes) == 1
    change = next(iter(pg.changes.values()))
    assert change["kind"] == "protection_enabled" and change["event_at"] == NOW
    assert change["refs"] == [p.snapshot_ref(before), p.snapshot_ref(after)]
    assert "actor" not in change and len(pg.findings) == 0
    assert pg.summary["revision"] == 1
    sql = next(sql for sql, _ in pg.calls if sql.startswith("select payload"))
    assert "order by work_id desc limit 1" in sql and "source_id=%s" in sql


def test_initial_true_and_native_events_do_not_create_transitions():
    pg = PG(snapshot())
    pg.history = {"fixture-first": pg.current}
    pg.apply("fixture-first")
    assert pg.changes == {} and pg.findings == {}
    pg.calls.clear()
    p.apply(pg, STATION, {"kind": "observations"})
    assert pg.calls == []


def test_component_change_revises_one_finding_polling_preserves_revision_and_fact_time():
    pg = PG(snapshot(real_time_protection_enabled=False))
    p.refresh(pg, STATION, now=NOW)
    initial = deepcopy(next(iter(pg.findings.values())))
    pg.current = snapshot(at=NOW + timedelta(minutes=1), real_time_protection_enabled=False)
    p.refresh(pg, STATION, now=NOW + timedelta(minutes=1))
    assert next(iter(pg.findings.values()))["revision"] == 1
    pg.current = snapshot(at=NOW + timedelta(minutes=2), real_time_protection_enabled=False, nis_enabled=False)
    p.refresh(pg, STATION, now=NOW + timedelta(minutes=2))
    finding = next(iter(pg.findings.values()))
    assert len(pg.findings) == 1 and finding["revision"] == 2
    assert finding["first_detected_at"] == initial["first_detected_at"]
    assert finding["fact_at"] == initial["fact_at"]
    assert finding["last_observed_at"] == NOW + timedelta(minutes=2)


def test_age_only_refresh_preserves_unresolved_c01_and_opens_one_c09_for_server():
    pg = PG(snapshot(False), station_type="server")
    p.refresh(pg, STATION, now=NOW)
    later = NOW + timedelta(hours=24, microseconds=1)
    assert p.due(pg, now=NOW + timedelta(hours=24)) == []
    assert p.due(pg, now=later) == [STATION]
    p.refresh(pg, STATION, now=later)
    c01, c09 = pg.findings.values()
    assert c01["check_id"] == "C01" and c01["status"] == "active"
    assert c01["resolved_at"] is None
    assert c01["quality"]["status"] == "stale"
    assert c09["check_id"] == "C09" and c09["status"] == "active" and c09["severity"] == "medium"
    assert p.due(pg, now=later) == []
    p.refresh(pg, STATION, now=later + timedelta(hours=1))
    assert len(pg.findings) == 2 and c09["revision"] == 1
    assert c01["revision"] == 2 and c01["resolved_at"] is None
    assert c01["last_observed_at"] == NOW
    assert c01["evidence_refs"] == [p.snapshot_ref(pg.current)]
    pg.current = snapshot(True, at=later + timedelta(hours=1))
    p.refresh(pg, STATION, now=later + timedelta(hours=1))
    assert c09["status"] == "resolved" and pg.changes == {}
    assert c01["status"] == "resolved"


def test_unknown_is_recorded_without_a_false_healthy_finding():
    pg = PG()
    p.refresh(pg, STATION, now=NOW)
    assert pg.findings == {}
    assert pg.summary["protection"]["quality"]["status"] == "not_collected"


def test_crash_after_transition_rolls_back_history_and_current_state(monkeypatch):
    pg = PG(snapshot(True))
    pg.history = {"fixture-first": snapshot(False, at=NOW - timedelta(minutes=1)), "fixture-second": pg.current}
    normal = p.refresh
    monkeypatch.setattr(p, "refresh", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("fixture-crash")))
    with pytest.raises(RuntimeError, match="fixture-crash"), pg.transaction():
        pg.apply("fixture-second")
    assert pg.changes == {} and pg.summary is None
    monkeypatch.setattr(p, "refresh", normal)
    with pg.transaction():
        pg.apply("fixture-second")
    assert len(pg.changes) == 1 and pg.summary is not None


def test_wr05_registers_protection_callback():
    registered = [rule for rule in projection.projectors() if rule.key == "workstations.protection"]
    assert [(rule.key, rule.version, rule.apply) for rule in registered] == [("workstations.protection", 1, p.apply)]


def test_job_stage_shares_finite_budget_between_inputs_and_age_refresh(monkeypatch):
    pg = PG()
    monkeypatch.setattr(projection_jobs, "_Rows", lambda conn: conn)
    pending_budgets = []
    monkeypatch.setattr(projection, "pending", lambda *_args, **kwargs: pending_budgets.append(kwargs["limit"]) or [1, 2])
    budgets = []
    monkeypatch.setattr(p, "due", lambda _cur, **kwargs: budgets.append(kwargs["limit"]) or [STATION])
    result = projection_jobs.stage(pg, {"source_instance_id": projection_jobs.SOURCE,
        "handler_id": projection_jobs.HANDLER_ID, "budget": {"max_records": 3}})
    assert budgets == [1] and pending_budgets == [2] and result["status"] == "partial"
    assert result["protection_refresh_ids"] == [STATION]


@pytest.mark.parametrize("acquired", [True, False])
def test_job_age_refresh_uses_publication_lock_and_caller_transaction(monkeypatch, acquired):
    pg, calls = PG(), []
    execute = pg.execute

    def fenced_execute(sql, params=()):
        if "set_config" in sql:
            calls.append("fence")
        elif "pg_try_advisory_xact_lock" in sql:
            pg.one = {"acquired": acquired}
        else:
            execute(sql, params)

    monkeypatch.setattr(pg, "execute", fenced_execute)
    monkeypatch.setattr(projection_jobs, "_Rows", lambda conn: conn)
    monkeypatch.setattr(projection_jobs.job_queue, "fence", lambda job: ("fixture-id", "fixture-token", 1))
    for name in ("prepare_consumers", "backfill_batch", "run_batch"):
        monkeypatch.setattr(projection, name, lambda *_args, _name=name, **_kwargs: calls.append(_name))
    monkeypatch.setattr(p, "refresh", lambda conn, station, **_kwargs: calls.append(station))
    job = {"source_instance_id": projection_jobs.SOURCE, "handler_id": projection_jobs.HANDLER_ID,
           "budget": {"max_records": 3}}
    projection_jobs.apply(pg, job, {"status": "success", "work_ids": [], "protection_refresh_ids": [STATION]})
    assert calls == (["fence", "prepare_consumers", "backfill_batch", "run_batch", STATION]
                     if acquired else ["fence"])


@pytest.mark.parametrize("limit", [0, True, 101])
def test_age_refresh_is_bounded_before_access(limit):
    with pytest.raises(ValueError, match="batch_invalid"):
        p.due(None, now=NOW, limit=limit)


@pytest.mark.parametrize("source,quality", [
    (None, "not_collected"),
    (snapshot(None, state="unavailable", at=NOW + timedelta(minutes=1)), "unavailable"),
    (snapshot(None, at=NOW + timedelta(minutes=1)), "partial"),
    (snapshot(tamper_protected=None, at=NOW + timedelta(minutes=1)), "partial"),
    (snapshot(False, at=NOW + timedelta(hours=1)), "unavailable"),
])
def test_inconclusive_refresh_preserves_unresolved_evidence_and_episode(source, quality):
    pg = PG(snapshot(real_time_protection_enabled=False))
    p.refresh(pg, STATION, now=NOW)
    initial = deepcopy(next(iter(pg.findings.values())))
    pg.current = source
    later = NOW + timedelta(minutes=1)
    result = p.refresh(pg, STATION, now=later)
    finding = next(iter(pg.findings.values()))
    assert finding["status"] == "active" and finding["resolved_at"] is None
    assert finding["quality"]["status"] == quality
    for key in ("id", "episode_id", "fact_at", "first_detected_at", "last_observed_at",
                "reason_params", "evidence_refs"):
        assert finding[key] == initial[key]
    assert finding["revision"] == 2 and finding["materially_changed_at"] == later
    assert not result["checks"][0].reasons
    assert result["checks"][0].counts.stations.relation != "exact"
    unchanged = deepcopy(finding)
    p.refresh(pg, STATION, now=later + timedelta(minutes=1))
    assert finding == unchanged


def test_clear_resolves_once_unknown_does_not_reopen_and_fresh_disabled_starts_episode():
    pg = PG(snapshot(False))
    p.refresh(pg, STATION, now=NOW)
    first = next(iter(pg.findings.values()))
    pg.current = snapshot(True, at=NOW + timedelta(minutes=1))
    p.refresh(pg, STATION, now=NOW + timedelta(minutes=1))
    assert first["status"] == "resolved"
    assert first["resolved_at"] == NOW + timedelta(minutes=1)
    assert first["quality"]["status"] == "complete"
    assert first["last_observed_at"] == pg.current["observed_at"]
    assert first["evidence_refs"] == [p.snapshot_ref(pg.current)]
    resolved = deepcopy(first)
    p.refresh(pg, STATION, now=NOW + timedelta(minutes=2))
    pg.current = snapshot(None, state="unavailable", at=NOW + timedelta(minutes=3))
    p.refresh(pg, STATION, now=NOW + timedelta(minutes=3))
    assert first == resolved and len(pg.findings) == 1
    pg.current = snapshot(at=NOW + timedelta(minutes=4), real_time_protection_enabled=False,
                          tamper_protected=None)
    p.refresh(pg, STATION, now=NOW + timedelta(minutes=4))
    assert len(pg.findings) == 2
    new = list(pg.findings.values())[-1]
    assert new["status"] == "active" and new["resolved_at"] is None
    assert new["episode_id"] != first["episode_id"] and new["revision"] == 1
    assert new["quality"]["status"] == "partial"
    assert new["reason_params"] == {"components": "real_time_protection_enabled"}


def test_fresh_disabled_after_unknown_updates_same_unresolved_episode():
    pg = PG(snapshot(False))
    p.refresh(pg, STATION, now=NOW)
    first = next(iter(pg.findings.values()))
    identifier = first["id"]
    pg.current = None
    p.refresh(pg, STATION, now=NOW + timedelta(minutes=1))
    pg.current = snapshot(at=NOW + timedelta(minutes=2), nis_enabled=False)
    p.refresh(pg, STATION, now=NOW + timedelta(minutes=2))
    assert len(pg.findings) == 1 and first["id"] == identifier
    assert first["status"] == "active" and first["quality"]["status"] == "complete"
    assert first["reason_params"] == {"components": "nis_enabled"}
    assert first["last_observed_at"] == pg.current["observed_at"]
    assert first["evidence_refs"] == [p.snapshot_ref(pg.current)]
    assert first["revision"] == 3
