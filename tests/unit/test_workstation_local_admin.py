"""C02 episodes from synthetic native observations; no database or source I/O."""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import re

import pytest

from server.sli.plugins.workstations import local_admin as c02, normalizers, projection
from server.sli.plugins.workstations.contracts import Workstation
from server.sli.plugins.workstations.importer import digest

NOW = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)
OLD = NOW - timedelta(days=60)
MEMBER = "S-1-5-21-100-200-300-1101"
ACTOR = "S-1-5-21-100-200-300-1102"
STATION = "fixture-station"
AGENT = "fixture-agent"


def native(number=4732, *, at=OLD, record=10, member=MEMBER, actor=ACTOR,
           group=c02.ADMINISTRATORS, agent=AGENT, generation="fixture-generation", **data):
    fields = {"TargetSid": group, "MemberSid": member, "MemberName": "fixture-member",
              "SubjectUserSid": actor, "SubjectUserName": "fixture-actor",
              "SubjectDomainName": "fixture-domain", **data}
    item = normalizers.normalize({"event_id": number, "channel": "Security",
                                 "provider_name": normalizers.SECURITY_PROVIDER}, fields, Workstation(agent, 100))
    assert item is not None
    identifier = digest([agent, generation, record])
    item.update({"channel": "Security", "provider_name": normalizers.SECURITY_PROVIDER,
                 "generation": generation, "record_id": record, "source_sha256": digest(identifier)})
    return {"id": identifier, "agent_key": agent, "family": "protection", "event_id": number,
            "observed_at": at, "observation": item}


class PG:
    def __init__(self, *rows):
        self.rows = {row["id"]: row for row in rows}
        self.findings, self.changes = {}, {}
        self.now = NOW
        self.calls = []

    @contextmanager
    def cursor(self):
        yield self

    @contextmanager
    def transaction(self):
        saved = deepcopy((self.findings, self.changes))
        try:
            yield
        except Exception:
            self.findings, self.changes = saved
            raise

    def execute(self, sql, params=()):
        sql = " ".join(sql.split())
        self.calls.append((sql, params))
        self.one, self.result = None, []
        if sql.startswith("set local statement_timeout"):
            return
        if sql == "select transaction_timestamp() as detected_at":
            self.one = {"detected_at": self.now}
        elif sql.startswith("select id,agent_key,family,event_id,observed_at,observation"):
            agent, member, group, limit = params
            for row in self.rows.values():
                facts = row["observation"]["facts"]
                if (row["agent_key"] == agent and row["family"] == "protection"
                        and row["event_id"] in (4732, 4733)
                        and (facts.get("member_sid") or facts.get("member", "")).upper() == member
                        and (facts.get("group_sid") or facts.get("group")) == group):
                    self.result.append(deepcopy(row))
            self.result = sorted(self.result, key=lambda item: (item["observed_at"], item["id"]))[:limit]
        elif sql.startswith("insert into sli_plugin_workstations."):
            table, columns = re.match(r"insert into sli_plugin_workstations\.(\w+) \(([^)]+)\)", sql).groups()
            row = dict(zip(columns.split(","), params))
            for key in ("subject_ref", "actor_ref", "reason_params", "quality", "evidence_refs"):
                if key in row:
                    row[key] = json.loads(row[key])
            if table == "station_changes":
                self.changes.setdefault(row["id"], row)
            elif table == "check_findings":
                old = self.findings.get(row["id"])
                if old is None:
                    self.findings[row["id"]] = {**row, "revision": 1}
                elif old["condition_sha256"] != row["condition_sha256"]:
                    row["first_detected_at"] = old["first_detected_at"]
                    if old["status"] == row["status"] == "resolved":
                        row["resolved_at"] = old["resolved_at"]
                    self.findings[row["id"]] = {**row, "revision": old["revision"] + 1}
            else:
                raise AssertionError(table)
        else:
            raise AssertionError(sql)

    def fetchone(self):
        return self.one

    def fetchall(self):
        return self.result


def apply(pg, row):
    with pg.transaction():
        c02.apply(pg, STATION, {"kind": "observations", "source_id": row["id"], "payload": row})


def only_finding(pg):
    assert len(pg.findings) == 1
    return next(iter(pg.findings.values()))


def test_native_member_and_actor_are_independent_and_no_ad_link_is_inferred():
    row = native()
    facts = row["observation"]["facts"]
    assert facts["member_sid"] == MEMBER and facts["actor_sid"] == ACTOR
    pg = PG(row)
    apply(pg, row)
    finding = only_finding(pg)
    change = next(iter(pg.changes.values()))
    assert finding["subject_id"] == MEMBER
    assert finding["subject_ref"]["name"] == "fixture-member"
    assert finding["reason_params"]["actor_sid"] == change["actor_ref"]["sid"]
    assert finding["reason_params"]["actor_name"] == change["actor_ref"]["name"]
    assert change["actor_ref"]["sid"] == ACTOR
    assert change["actor_ref"]["name"] == "fixture-actor"
    assert finding["subject_ref"]["ad_entity_id"] is change["actor_ref"]["ad_entity_id"] is None
    assert finding["subject_ref"]["station_id"] == STATION
    assert finding["evidence_refs"] == [c02.event(row, STATION)["ref"]]
    assert c02.Reason(finding["reason_code"], finding["reason_params"]).to_dict()["code"] == "local_admin_added"


def test_old_journal_import_keeps_native_date_and_unknown_membership_baseline():
    row, pg = native(), PG()
    pg.rows[row["id"]] = row
    apply(pg, row)
    finding = only_finding(pg)
    change = next(iter(pg.changes.values()))
    assert finding["fact_at"] == change["event_at"] == OLD
    assert finding["first_detected_at"] == change["detected_at"] == NOW
    assert finding["reason_params"]["added_at"] == OLD.isoformat()
    assert finding["reason_params"]["history_start_at"] == OLD.isoformat()
    assert finding["reason_params"]["baseline_status"] == "unknown"
    assert finding["reason_params"]["current_membership"] == "unknown"
    assert finding["quality"]["status"] == "partial"
    assert finding["quality"]["reasons"][0]["code"] == "local_admin_baseline_unknown"


def test_removal_closes_episode_and_replay_preserves_detection_revision_and_changes():
    added = native()
    removed = native(4733, at=OLD + timedelta(hours=1), record=11)
    pg = PG(added)
    apply(pg, added)
    assert only_finding(pg)["status"] == "active"
    pg.rows[removed["id"]] = removed
    pg.now += timedelta(hours=1)
    apply(pg, removed)
    finding = only_finding(pg)
    assert finding["status"] == "resolved" and finding["revision"] == 2
    assert finding["first_detected_at"] == NOW and finding["resolved_at"] == pg.now
    assert finding["reason_params"]["removed_at"] == removed["observed_at"].isoformat()
    assert finding["last_observed_at"] == removed["observed_at"]
    assert {ref["observation_id"] for ref in finding["evidence_refs"]} == {added["id"], removed["id"]}
    saved = deepcopy((pg.findings, pg.changes))
    pg.now += timedelta(days=1)
    apply(pg, added)
    apply(pg, removed)
    assert (pg.findings, pg.changes) == saved
    assert len(pg.changes) == 2
    removal_change = next(item for item in pg.changes.values() if item["change_kind"] == "local_admin_removed")
    assert removal_change["subject_ref"]["sid"] == MEMBER


def test_removal_delivered_first_and_late_smaller_hash_addition_do_not_reopen_membership():
    added, removed = native(), native(4733, at=OLD + timedelta(hours=1), record=11)
    # Choose explicit valid hashes to prove import/hash order is irrelevant.
    added["id"], removed["id"] = "0" * 64, "f" * 64
    pg = PG(removed)
    apply(pg, removed)
    assert pg.findings == {}
    pg.rows[added["id"]] = added
    apply(pg, added)
    assert only_finding(pg)["status"] == "resolved"
    assert only_finding(pg)["fact_at"] == OLD


def test_remove_then_readd_creates_a_distinct_active_episode_with_its_own_actor():
    first = native()
    removed = native(4733, at=OLD + timedelta(hours=1), record=11)
    second = native(at=OLD + timedelta(hours=2), record=12, actor="S-1-5-18")
    pg = PG(first, removed, second)
    for row in (second, removed, first):
        apply(pg, row)
    assert len(pg.findings) == 2
    early, late = sorted(pg.findings.values(), key=lambda item: item["fact_at"])
    assert early["status"] == "resolved" and late["status"] == "active"
    assert late["reason_params"]["actor_sid"] == "S-1-5-18"
    assert len(pg.changes) == 3


def test_foreign_member_station_group_or_earlier_removal_cannot_close_episode():
    added = native()
    other_member = native(4733, at=OLD + timedelta(hours=1), record=11, member=ACTOR)
    other_station = native(4733, at=OLD + timedelta(hours=1), record=11, agent="fixture-other")
    other_group = native(4733, at=OLD + timedelta(hours=1), record=12)
    other_group["observation"]["facts"].update({"group_sid": "S-1-5-32-545", "group": "S-1-5-32-545"})
    earlier = native(4733, at=OLD - timedelta(hours=1), record=9)
    pg = PG(added, other_member, other_station, other_group, earlier)
    apply(pg, added)
    assert only_finding(pg)["status"] == "active"


@pytest.mark.parametrize("generation,record,expected", [
    ("fixture-generation", 11, "resolved"), ("fixture-generation", 9, "active"),
    ("fixture-other-generation", 11, "active"), (None, 11, "active"),
])
def test_equal_timestamps_use_native_record_order_only_within_same_generation(generation, record, expected):
    added, removed = native(), native(4733, record=record, generation=generation)
    pg = PG(added, removed)
    apply(pg, added)
    assert only_finding(pg)["status"] == expected


def test_late_earlier_removal_reconciles_original_episode_without_changing_detection():
    added = native()
    later = native(4733, at=OLD + timedelta(hours=2), record=12)
    earlier = native(4733, at=OLD + timedelta(hours=1), record=11)
    pg = PG(added, later)
    apply(pg, added)
    pg.rows[earlier["id"]] = earlier
    pg.now += timedelta(days=1)
    apply(pg, earlier)
    row = only_finding(pg)
    assert row["first_detected_at"] == row["resolved_at"] == NOW
    assert row["reason_params"]["removed_at"] == earlier["observed_at"].isoformat()
    assert row["evidence_refs"][-1]["observation_id"] == earlier["id"]
    assert row["revision"] == 2


def test_unknown_actor_is_explicit_and_never_substituted_with_member_or_last_login():
    row = native(actor="-", SubjectUserName="-", SubjectDomainName="-")
    row["observation"]["roles"]["actor"] = "sam:fixture-domain:fixture-provisional"
    row["observation"]["roles"]["last_login"] = ACTOR
    pg = PG(row)
    apply(pg, row)
    params = only_finding(pg)["reason_params"]
    assert params["actor_status"] == "unknown" and params["actor_sid"] is params["actor_name"] is None
    assert next(iter(pg.changes.values()))["actor_ref"]["ad_entity_id"] is None


@pytest.mark.parametrize("member", ["-", "S-1-0-0", "fixture-unresolved"])
def test_missing_member_sid_keeps_change_but_cannot_establish_or_close_exact_episode(member):
    added = native()
    removed = native(4733, at=OLD + timedelta(hours=1), record=11, member=member)
    pg = PG(added, removed)
    apply(pg, added)
    apply(pg, removed)
    assert only_finding(pg)["status"] == "active"
    assert len(pg.changes) == 2
    assert not any(item["subject_ref"]["sid"] == MEMBER for item in pg.changes.values()
                   if item["change_kind"] == "local_admin_removed")


def test_pre_wr08_normalized_member_and_actor_still_project_without_unsafe_name_resolution():
    row = native()
    for key in ("group_sid", "member_sid", "member_name", "actor_sid", "actor_name", "actor_domain"):
        del row["observation"]["facts"][key]
    row["observation"]["roles"]["actor"] = f"sid:{ACTOR.lower()}"
    pg = PG(row)
    apply(pg, row)
    finding = only_finding(pg)
    assert finding["subject_id"] == MEMBER
    assert finding["reason_params"]["actor_sid"] == ACTOR
    assert finding["subject_ref"]["name"] is None


@pytest.mark.parametrize("field,value", [("channel", "System"), ("provider_name", "fixture-provider")])
def test_unconfirmed_native_channel_or_provider_is_not_a_c02_change(field, value):
    row = native()
    row["observation"][field] = value
    pg = PG(row)
    apply(pg, row)
    assert not pg.findings and not pg.changes and not pg.calls


def test_history_read_is_bounded_no_xml_and_overflow_rolls_back_publication(monkeypatch):
    monkeypatch.setattr(c02, "MAX_MEMBER_EVENTS", 2)
    rows = [native(record=number) for number in (10, 11, 12)]
    pg = PG(*rows)
    with pytest.raises(ValueError, match="history_too_large"):
        apply(pg, rows[0])
    assert not pg.findings and not pg.changes
    sql, params = next((sql, params) for sql, params in pg.calls if sql.startswith("select id,agent_key"))
    assert "source_xml" not in sql and "limit %s" in sql
    assert params == (AGENT, MEMBER, c02.ADMINISTRATORS, 3)
    assert pg.calls[0][0] == "set local statement_timeout='5000ms'"


def test_c02_registers_with_wr05_versioned_receipts_and_ignores_unrelated_facts():
    registered = next(item for item in projection.projectors() if item.key == c02.PROJECTOR)
    assert registered.version == 1 and registered.apply is c02.apply
    pg = PG()
    registered.apply(pg, STATION, {"kind": "protection_state", "payload": {}})
    assert not pg.calls
