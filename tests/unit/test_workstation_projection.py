"""WR05: committed inputs, versioned receipts and recovery, without a database."""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
from copy import deepcopy
from types import SimpleNamespace

import pytest

from server.sli.core.job_queue import digest
from server.sli.plugins.workstations import projection as p


class PG:
    def __init__(self):
        self.work = {}
        self.receipts = {}
        self.consumers = {}
        self.checkpoints = {}
        self.findings = []
        self.inventory = {"fixture-agent": "fixture-station"}
        self.sources = {name: {} for name in ("observations", "protection_state", "station_inventory")}
        self.calls = []
        self.acquired = True
        self.finish = True

    def cursor(self, **_kwargs):
        return nullcontext(self)

    @contextmanager
    def transaction(self):
        saved = deepcopy((self.work, self.receipts, self.consumers, self.checkpoints, self.findings))
        try:
            yield
        except Exception:
            self.work, self.receipts, self.consumers, self.checkpoints, self.findings = saved
            raise

    def add_fact(self, source_id, *, work_id=None, agent="fixture-agent", kind="observations", payload=None):
        if any(row["source_id"] == source_id and row["kind"] == kind for row in self.work.values()):
            return  # Source trigger is ON CONFLICT DO NOTHING, including replay/backfill.
        work_id = work_id if work_id is not None else max(self.work, default=0) + 1
        payload = payload or {"id": source_id, "agent_key": agent, "facts": {"fixture": True}}
        self.work[work_id] = {"kind": kind, "source_id": source_id, "payload": payload,
                              "payload_sha256": digest(payload), "agent": agent,
                              "station_id": payload.get("station_id")}
        for key, version in self.consumers:
            self.receipts[work_id, key, version] = {"payload_sha256": digest(payload), "applied": False}

    def execute(self, sql, params=()):
        sql = " ".join(sql.split())
        self.calls.append((sql, params))
        self.one, self.rows = None, []
        if "begin_core_job_result_v1" in sql:
            self.one = ("publish",)
        elif "finish_core_job_result_v1" in sql:
            self.one = (self.finish,)
        elif "set_config('sli.job_id'" in sql:
            pass
        elif sql.startswith("insert into fixture_findings"):
            self.findings.append(tuple(params))
        elif "pg_try_advisory_xact_lock" in sql:
            self.one = {"acquired": self.acquired}
        elif "register_projection_consumer" in sql:
            self.consumers.setdefault(tuple(params), {"position": 0, "complete": False})
        elif sql.startswith("select projector_key,projection_version,backfill_position"):
            self.one = next(({"projector_key": key, "projection_version": version,
                              "backfill_position": value["position"]}
                             for (key, version), value in sorted(self.consumers.items())
                             if not value["complete"]), None)
        elif sql.startswith("select work_id,payload_sha256"):
            self.rows = [{"work_id": key, "payload_sha256": row["payload_sha256"]}
                         for key, row in sorted(self.work.items()) if key > params[0]][:params[1]]
        elif sql.startswith("insert into sli_plugin_workstations.projection_receipts"):
            self.receipts.setdefault(tuple(params[:3]), {"payload_sha256": params[3], "applied": False})
        elif sql.startswith("update sli_plugin_workstations.projection_consumers"):
            self.consumers[tuple(params[2:])] = {"position": params[0], "complete": params[1]}
        elif sql.startswith("select distinct q.work_id") or sql.startswith("select q.work_id,s.station_id"):
            allowed = set(zip(params[0], params[1]))
            exact = params[2] if len(params) == 4 else None
            for (work_id, key, version), receipt in sorted(self.receipts.items()):
                fact = self.work[work_id]
                station = (fact["station_id"] if fact["kind"] == "station_inventory"
                           else self.inventory.get(fact["agent"]))
                if (not receipt["applied"] and (key, version) in allowed and station
                        and (exact is None or work_id in exact)):
                    self.rows.append({"work_id": work_id, "station_id": station, "projector_key": key,
                                      "projection_version": version, "payload_sha256": receipt["payload_sha256"]})
            if sql.startswith("select distinct"):
                self.rows = [{"work_id": key} for key in sorted({row["work_id"] for row in self.rows})]
            self.rows = self.rows[:params[-1]]
        elif sql.startswith("select kind,source_id,payload"):
            row = self.work[params[0]]
            self.one = {key: deepcopy(row[key]) for key in ("kind", "source_id", "payload", "payload_sha256")}
            self.one["actual_sha256"] = digest(row["payload"])
        elif sql.startswith("update sli_plugin_workstations.projection_receipts"):
            self.receipts[tuple(params)]["applied"] = True
        elif sql.startswith("insert into sli_plugin_workstations.projection_checkpoints"):
            if "workstations.backfill" in sql:
                self.checkpoints["backfill", params[0]] = {"last_key": params[1], "complete": params[2]}
            else:
                key, station, version = params
                old = self.checkpoints.get((key, station), {"processed_count": 0})
                self.checkpoints[key, station] = {"processed_count": old["processed_count"] + 1, "version": version}
        elif sql.startswith("select committed_position"):
            position = self.checkpoints.get(("backfill", params[0]))
            self.one = {"committed_position": position} if position else None
        elif "as source_key" in sql:
            table = next(name for name in self.sources if f"sli_plugin_workstations.{name} " in sql)
            self.rows = [{"source_key": key} for key in sorted(self.sources[table]) if key > params[0]][:params[1]]
        elif "backfill_projection_input" in sql:
            table, key = params
            self.add_fact(key, kind=table, payload=self.sources[table][key])
        else:
            raise AssertionError(sql)

    def fetchone(self):
        return self.one

    def fetchall(self):
        return self.rows


def evaluator(key="fixture-check", version=1, *, fail=False):
    def apply(conn, station_id, fact):
        with conn.cursor() as cur:
            cur.execute("insert into fixture_findings values(%s,%s,%s,%s)", (key, version, station_id, fact["source_id"]))
        if fail:
            raise RuntimeError("fixture-crash-after-finding")
    return p.Projector(key, version, apply)


def prepare(pg, evaluators, limit=100):
    with pg.transaction():
        return p.prepare_consumers(pg, evaluators=evaluators, limit=limit)


def run(pg, evaluators, **kwargs):
    with pg.transaction():
        return p.run_batch(pg, evaluators=evaluators, **kwargs)


def test_one_fact_one_finding_replay_and_lower_late_hash_and_commit_position():
    pg, rules = PG(), (evaluator(),)
    prepare(pg, rules)
    # Work 1 was allocated by another transaction but has not committed yet.
    pg.add_fact("f" * 64, work_id=2)
    assert run(pg, rules)["processed"] == 1
    pg.add_fact("f" * 64)  # Packet replay never schedules a second immutable input.
    assert run(pg, rules)["processed"] == 0
    pg.add_fact("0" * 64, work_id=1)  # Older fact, smaller hash AND lower work ID commit late.
    assert run(pg, rules)["processed"] == 1
    assert [item[-1] for item in pg.findings] == ["f" * 64, "0" * 64]
    assert run(pg, rules)["processed"] == 0
    assert pg.checkpoints["fixture-check", "fixture-station"]["processed_count"] == 2
    select = next(sql for sql, _ in pg.calls if sql.startswith("select q.work_id,s.station_id"))
    assert "for update of r skip locked" in select and "q.work_id>" not in select


def test_crash_rolls_back_finding_receipt_and_checkpoint_then_retry_finishes():
    pg, bad = PG(), (evaluator(fail=True),)
    prepare(pg, bad)
    pg.add_fact("fixture-input")
    with pytest.raises(RuntimeError, match="fixture-crash"):
        run(pg, bad)
    assert pg.findings == [] and pg.checkpoints == {}
    assert not pg.receipts[1, "fixture-check", 1]["applied"]
    assert run(pg, (evaluator(),))["processed"] == 1
    assert len(pg.findings) == 1 and pg.receipts[1, "fixture-check", 1]["applied"]


def test_mid_batch_failure_keeps_prior_committed_page_and_retries_the_entire_failed_page():
    pg, rules = PG(), (evaluator(),)
    prepare(pg, rules)
    for n in range(3):
        pg.add_fact(f"fixture-{n}")
    assert run(pg, rules, limit=1)["processed"] == 1
    normal = rules[0].apply
    def fail_on_last(conn, station, fact):
        normal(conn, station, fact)
        if fact["source_id"] == "fixture-2":
            raise RuntimeError("fixture-crash")
    with pytest.raises(RuntimeError, match="fixture-crash"):
        run(pg, (p.Projector("fixture-check", 1, fail_on_last),), limit=2)
    assert len(pg.findings) == 1
    assert pg.checkpoints["fixture-check", "fixture-station"]["processed_count"] == 1
    assert run(pg, rules, limit=2)["processed"] == 2
    assert len(pg.findings) == 3 and run(pg, rules)["processed"] == 0


def test_new_rule_and_version_have_independent_receipts_for_already_processed_facts():
    pg, first = PG(), (evaluator("fixture-C01"),)
    prepare(pg, first)
    pg.add_fact("fixture-input")
    run(pg, first)
    later = (*first, evaluator("fixture-C02"), evaluator("fixture-C01", 2))
    for _ in range(4):
        prepare(pg, later)
        run(pg, later)
    assert sorted((key, version) for key, version, *_ in pg.findings) == [
        ("fixture-C01", 1), ("fixture-C01", 2), ("fixture-C02", 1)]
    assert run(pg, later)["processed"] == 0


def test_no_inventory_does_not_acknowledge_input_and_later_inventory_unblocks_it():
    pg, rules = PG(), (evaluator(),)
    prepare(pg, rules)
    pg.inventory.clear()
    pg.add_fact("fixture-input")
    assert run(pg, rules)["processed"] == 0
    assert not any(row["applied"] for row in pg.receipts.values())
    pg.inventory["fixture-agent"] = "fixture-station"
    assert run(pg, rules)["processed"] == 1


def test_bounded_batches_resume_until_finished_and_busy_lock_preserves_pending():
    pg, rules = PG(), (evaluator(),)
    prepare(pg, rules)
    for n in range(5):
        pg.add_fact(f"fixture-{n}")
    pg.acquired = False
    assert run(pg, rules, limit=2) == {"status": "partial", "processed": 0}
    pg.acquired = True
    assert run(pg, rules, limit=2) == {"status": "partial", "processed": 2}
    assert run(pg, rules, limit=2) == {"status": "partial", "processed": 2}
    assert run(pg, rules, limit=2) == {"status": "success", "processed": 1}
    assert len(pg.findings) == 5


@pytest.mark.parametrize("target", ["fact", "receipt"])
def test_corrupt_input_or_receipt_cannot_produce_finding(target):
    pg, rules = PG(), (evaluator(),)
    prepare(pg, rules)
    pg.add_fact("fixture-input")
    if target == "fact":
        pg.work[1]["payload"]["facts"] = {"changed": True}
    else:
        pg.receipts[1, "fixture-check", 1]["payload_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="input_conflict"):
        run(pg, rules)
    assert pg.findings == [] and pg.checkpoints == {}


@pytest.mark.parametrize("limit", [0, -1, True, 101, "1"])
def test_invalid_batch_is_rejected_before_io(limit):
    with pytest.raises(ValueError, match="batch_invalid"):
        p.run_batch(SimpleNamespace(), evaluators=(evaluator(),), limit=limit)


def test_registered_evaluators_keep_independent_receipts_for_the_same_input():
    pg = PG()
    rules = p.projectors()
    assert any(rule.key == "workstations.protection" for rule in rules)
    assert any(rule.key == "workstations.C02" for rule in rules)
    assert any(rule.key == "workstations.C05" for rule in rules)
    prepare(pg, rules)
    pg.add_fact("fixture-input")
    assert set(pg.receipts) == {
        (1, "workstations.C02", 1), (1, "workstations.C05", 1), (1, "workstations.protection", 1),
        (1, "workstations.C07", 1), (1, "workstations.last-interactive-login", 1),
        (1, "workstations.C03", 1),
        (1, "workstations.C06", 1),
        (1, "workstations.C04", 1),
    }


def test_explicit_empty_evaluators_do_not_consume_or_claim_success():
    assert p.run_batch(SimpleNamespace(), evaluators=()) == {"status": "blocked", "processed": 0}


def test_backfill_pages_resume_after_crash_and_do_not_lose_concurrent_late_input():
    pg, rules = PG(), (evaluator(),)
    prepare(pg, rules)
    pg.sources["observations"] = {key: {"id": key, "agent_key": "fixture-agent"} for key in ("b", "d", "f")}
    with pg.transaction():
        assert p.backfill_batch(pg, limit=2)["enqueued"] == 2
    pg.add_fact("a")  # The installed trigger covers an insert below the backfill key.
    with pytest.raises(RuntimeError, match="fixture-crash"):
        with pg.transaction():
            assert p.backfill_batch(pg, limit=2)["enqueued"] == 1
            raise RuntimeError("fixture-crash")
    assert pg.checkpoints["backfill", "observations"] == {"last_key": "d", "complete": False}
    for _ in range(5):
        with pg.transaction():
            result = p.backfill_batch(pg, limit=2)
    assert result["status"] == "success" and len(pg.work) == 4
    assert run(pg, rules)["processed"] == 4
    assert sorted(item[-1] for item in pg.findings) == ["a", "b", "d", "f"]


def test_task_backfill_and_later_live_inputs_share_replay_fence():
    pg, rules = PG(), (evaluator(),)
    pg.add_fact("fixture-before-consumer")
    prepare(pg, rules, limit=1)
    pg.add_fact("fixture-after-consumer")
    prepare(pg, rules, limit=1)
    prepare(pg, rules, limit=1)
    assert run(pg, rules)["processed"] == 2
    assert len(pg.receipts) == 2 and len(pg.findings) == 2
