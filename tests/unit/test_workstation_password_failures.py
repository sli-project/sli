"""WR12 synthetic native failures and durable publication, without a database."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import re

import pytest

from server.sli.plugins.workstations import normalizers, password_failures as c03, projection
from server.sli.plugins.workstations.contracts import Workstation
from server.sli.plugins.workstations.importer import digest
from tests.unit.test_workstation_projection import PG as QueuePG, prepare

AT = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)
NOW = AT + timedelta(days=30)
STATION = "fixture-station"
AGENT = "fixture-agent"
TARGET = "S-1-5-21-100-200-300-1101"


def native(record=1, *, at=None, target=TARGET, source="192.0.2.10", agent=AGENT, number=4625, **fields):
    item = normalizers.normalize({"event_id": number, "channel": "Security",
                                 "provider_name": normalizers.SECURITY_PROVIDER},
                                {"TargetUserSid": target, "TargetUserName": "fixture-target",
                                 "TargetDomainName": "fixture-domain", "IpAddress": source,
                                 "LogonType": "3", "Status": "0xc000006d", "SubStatus": "0xc000006a", **fields},
                                Workstation(agent, 100))
    assert item is not None
    identifier = digest([agent, "Security", "fixture-generation", record])
    item.update({"channel": "Security", "provider_name": normalizers.SECURITY_PROVIDER,
                 "record_id": record, "generation": "fixture-generation", "source_sha256": digest(identifier)})
    return {"id": identifier, "agent_key": agent, "family": item["family"], "event_id": number,
            "observed_at": at if at is not None else AT + timedelta(seconds=record), "observation": item}


class PG(QueuePG):
    def __init__(self, *observations):
        super().__init__()
        self.observations = {row["id"]: row for row in observations}
        self.findings = {}
        self.now = NOW
        self.station_agent = AGENT
        self.fail_save = False

    def execute(self, sql, params=()):
        sql = " ".join(sql.split())
        if (sql.startswith("set local statement_timeout") or sql.startswith("select agent_key from")
                or sql.startswith("select id,agent_key,family,event_id")
                or sql == "select transaction_timestamp() as detected_at"
                or sql.startswith("insert into sli_plugin_workstations.check_findings")):
            self.calls.append((sql, params))
            self.one, self.rows = None, []
            if sql.startswith("select agent_key"):
                self.one = {"agent_key": self.station_agent}
            elif sql == "select transaction_timestamp() as detected_at":
                self.one = {"detected_at": self.now}
            elif sql.startswith("select id,agent_key"):
                agent, start, end, limit = params
                self.rows = sorted((deepcopy(row) for row in self.observations.values()
                                    if row["agent_key"] == agent and row["family"] == "logons"
                                    and row["event_id"] == 4625 and start < row["observed_at"] < end),
                                   key=lambda row: (row["observed_at"], row["id"]))[:limit]
            elif sql.startswith("insert into"):
                if self.fail_save:
                    raise RuntimeError("fixture publication failure")
                columns = re.match(r"insert into sli_plugin_workstations.check_findings \(([^)]+)\)", sql)[1]
                row = dict(zip(columns.split(","), params))
                for key in ("subject_ref", "reason_params", "quality", "evidence_refs"):
                    row[key] = json.loads(row[key])
                previous = self.findings.get(row["id"])
                if previous is None:
                    self.findings[row["id"]] = row | {"revision": 1}
                elif previous["condition_sha256"] != row["condition_sha256"]:
                    self.findings[row["id"]] = row | {"first_detected_at": previous["first_detected_at"],
                                                       "revision": previous["revision"] + 1}
        else:
            super().execute(sql, params)


def apply(pg, row):
    with pg.transaction():
        c03.apply(pg, STATION, {"kind": "observations", "payload": row})


def only(pg):
    assert len(pg.findings) == 1
    return next(iter(pg.findings.values()))


def test_19_failures_have_no_finding_20_have_one_and_replay_changes_nothing():
    rows = [native(record) for record in range(1, 21)]
    pg = PG(*rows[:19])
    apply(pg, rows[18])
    assert pg.findings == {}
    pg.observations[rows[19]["id"]] = rows[19]
    apply(pg, rows[19])
    finding = only(pg)
    assert finding["reason_params"]["count"] == 20
    assert finding["reason_params"]["threshold"] == 20
    assert finding["reason_params"]["window_minutes"] == 5
    assert finding["reason_params"]["direction"] == "on_station"
    assert finding["quality"]["status"] == "partial"
    assert finding["reason_params"]["count_relation"] == "at_least"
    assert finding["fact_at"] == rows[0]["observed_at"]
    assert finding["first_detected_at"] == NOW  # Old import is not today's native event.
    assert {ref["observation_id"] for ref in finding["evidence_refs"]} == {row["id"] for row in rows}
    assert finding["subject_ref"]["ad_entity_id"] is None
    assert c03.Reason(finding["reason_code"], finding["reason_params"]).to_dict()["code"] == "password_failures"
    saved = deepcopy(pg.findings)
    pg.now += timedelta(days=1)
    for row in reversed(rows):
        apply(pg, row)
    assert pg.findings == saved


def test_sliding_window_crosses_utc_bucket_boundary_and_excludes_exact_lower_boundary():
    rows = [native(record, at=AT + timedelta(minutes=4, seconds=record * 4)) for record in range(20)]
    pg = PG(*rows)
    apply(pg, rows[0])
    finding = only(pg)
    assert finding["reason_params"]["count"] == 20
    assert finding["reason_params"]["bucket_start"] == (AT + timedelta(minutes=5)).isoformat()
    assert finding["fact_at"] < c03.timestamp(finding["reason_params"]["bucket_start"])
    # Exactly 5 minutes apart belongs to different half-open windows.
    rows = [native(1, at=AT)] + [native(record, at=AT + timedelta(minutes=5)) for record in range(2, 21)]
    pg = PG(*rows)
    apply(pg, rows[0])
    apply(pg, rows[-1])
    assert not pg.findings
    row = native(21, at=AT + timedelta(minutes=5))
    pg.observations[row["id"]] = row
    apply(pg, row)
    assert only(pg)["reason_params"]["count"] == 20


def test_late_smaller_hash_reconciles_next_bucket_and_preserves_detection():
    rows = [native(record, at=AT + timedelta(minutes=4, seconds=record * 4)) for record in range(21)]
    rows[0]["id"] = "0" * 64
    pg = PG(*rows[1:])
    apply(pg, rows[-1])
    finding = only(pg)
    identifier = finding["id"]
    pg.now += timedelta(days=1)
    pg.observations[rows[0]["id"]] = rows[0]
    apply(pg, rows[0])
    finding = only(pg)
    assert finding["id"] == identifier and finding["revision"] == 2
    assert finding["first_detected_at"] == NOW and finding["materially_changed_at"] == pg.now
    assert finding["reason_params"]["count"] == 21
    assert finding["reason_params"]["evidence_sampled"] is True
    assert len(finding["evidence_refs"]) == c03.MAX_EVIDENCE
    assert finding["evidence_refs"][0]["observation_id"] == "0" * 64


@pytest.mark.parametrize("difference", ["target", "source", "agent"])
def test_accounts_sources_and_receiving_stations_are_not_pooled(difference):
    rows = [native(record) for record in range(1, 20)]
    extra = native(20, **{"target": "S-1-5-21-100-200-300-1102"} if difference == "target" else
                   {"source": "192.0.2.11"} if difference == "source" else {"agent": "fixture-other"})
    pg = PG(*rows, extra)
    apply(pg, rows[0])
    assert not pg.findings


def test_directions_have_independent_counts_buckets_and_ids():
    local = [c03.event(native(record)) for record in range(1, 21)]
    remote = [{**item, "id": digest(["fixture-remote", item["id"]]), "direction": "from_station"} for item in local]
    args = {"station_id": STATION, "start": AT, "detected_at": NOW}
    assert c03.buckets(local[:19] + remote[:19], **args) == []
    findings = c03.buckets(local + remote + local, **args)  # Repeated refs do not add attempts.
    assert len(findings) == 2
    assert {row["reason_params"]["direction"] for row in findings} == c03.DIRECTIONS
    assert len({row["id"] for row in findings}) == 2
    assert all(row["reason_params"]["count"] == 20 for row in findings)
    claimed = native()
    claimed["observation"]["facts"]["direction"] = "from_station"
    assert c03.event(claimed)["direction"] == "on_station"


@pytest.mark.parametrize("number", [4624, 4634, 4647])
def test_supplemental_or_successful_logons_do_not_count_as_attempts(number):
    pg = PG()
    apply(pg, native(number=number))
    assert not pg.findings and not pg.calls


@pytest.mark.parametrize("field,value", [("channel", "System"), ("provider_name", "fixture-provider")])
def test_native_identity_must_be_confirmed(field, value):
    row = native()
    row["observation"][field] = value
    pg = PG(row)
    apply(pg, row)
    assert not pg.calls


def test_missing_remote_source_or_target_is_not_pooled_and_local_interactive_is_explicit():
    row = native()
    del row["observation"]["roles"]["source_ip"]
    assert c03.event(row) is None
    row["observation"]["facts"]["logon_type"] = "2"
    assert c03.event(row)["source"] == "local"
    del row["observation"]["roles"]["affected_entity"]
    assert c03.event(row) is None


def test_ip_aliases_are_canonicalized_without_source_device_or_account_links():
    rows = [native(record, source="::ffff:192.0.2.10" if record % 2 else "192.0.2.10") for record in range(1, 21)]
    pg = PG(*rows)
    apply(pg, rows[0])
    finding = only(pg)
    assert finding["reason_params"]["source"] == "192.0.2.10"
    assert finding["subject_ref"]["station_id"] == STATION
    assert finding["subject_ref"]["ad_entity_id"] is None


def test_bounded_history_overflow_keeps_receipt_pending_and_has_no_xml(monkeypatch):
    monkeypatch.setattr(c03, "MAX_EVENTS", 20)
    rows = [native(record) for record in range(1, 22)]
    pg = PG(*rows)
    rules = (projection.Projector(c03.PROJECTOR, c03.RULE_VERSION, c03.apply),)
    prepare(pg, rules)
    pg.add_fact(rows[0]["id"], payload=rows[0] | {"observed_at": rows[0]["observed_at"].isoformat()})
    with pytest.raises(ValueError, match="window_too_large"), pg.transaction():
        projection.run_batch(pg, evaluators=rules)
    assert not pg.findings
    assert not pg.receipts[1, c03.PROJECTOR, c03.RULE_VERSION]["applied"]
    sql, params = next((sql, params) for sql, params in pg.calls if sql.startswith("select id,agent_key"))
    assert "source_xml" not in sql and "order by observed_at,id limit %s" in sql
    assert params == (AGENT, AT - c03.WINDOW, AT + 2 * c03.WINDOW, 21)


def test_registered_wr05_consumer_recovers_after_failed_publication_and_replay_is_fenced():
    rows = [native(record) for record in range(1, 21)]
    pg = PG(*rows)
    registered = next(rule for rule in projection.projectors() if rule.key == c03.PROJECTOR)
    assert registered.version == 1 and registered.apply is c03.apply
    rules = (registered,)
    prepare(pg, rules)
    pg.add_fact(rows[-1]["id"], payload=rows[-1] | {"observed_at": rows[-1]["observed_at"].isoformat()})
    pg.fail_save = True
    with pytest.raises(RuntimeError, match="fixture publication failure"), pg.transaction():
        projection.run_batch(pg, evaluators=rules)
    assert not pg.findings and not pg.receipts[1, c03.PROJECTOR, 1]["applied"]
    pg.fail_save = False
    with pg.transaction():
        assert projection.run_batch(pg, evaluators=rules)["processed"] == 1
    assert only(pg)["reason_params"]["count"] == 20
    saved = deepcopy(pg.findings)
    assert projection.run_batch(pg, evaluators=rules)["processed"] == 0
    assert pg.findings == saved and pg.receipts[1, c03.PROJECTOR, 1]["applied"]
    pg.station_agent = "fixture-other"
    with pytest.raises(ValueError, match="input_conflict"):
        apply(pg, rows[0])
    pg.calls.clear()
    c03.apply(pg, STATION, {"kind": "protection_state"})
    assert not pg.calls
