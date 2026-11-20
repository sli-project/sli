"""WR09 creation episodes from synthetic native inputs; no real database."""
from copy import deepcopy
from datetime import timedelta

import pytest

from server.sli.plugins.workstations import normalizers, projection, service_tasks as c05
from server.sli.plugins.workstations.contracts import Workstation
from server.sli.plugins.workstations.importer import digest
from server.sli.plugins.workstations.overview_contracts import Reason
from tests.unit.test_workstation_local_admin import PG as BasePG, NOW, OLD, STATION, AGENT, ACTOR


def native(number=4697, *, at=OLD, record=10, agent=AGENT, generation="fixture-generation", **data):
    channel, provider = ("System", "Service Control Manager") if number == 7045 else (
        "Security", normalizers.SECURITY_PROVIDER)
    fields = {"ServiceName": "fixture-service", "ServiceFileName": r"C:\fixture\service.exe",
              "ServiceAccount": "LocalSystem", "ServiceStartType": "2", "TaskName": "fixture-task",
              "TaskContent": "<Task><Actions>fixture</Actions></Task>",
              "SubjectUserSid": ACTOR, "SubjectUserName": "fixture-actor",
              "SubjectDomainName": "fixture-domain", **data}
    observation = normalizers.normalize({"event_id": number, "channel": channel, "provider_name": provider},
                                        fields, Workstation(agent, 100))
    assert observation is not None
    identifier = digest([agent, channel, generation, record])
    observation.update(channel=channel, provider_name=provider, generation=generation,
                       record_id=record, source_sha256=digest(identifier))
    return {"id": identifier, "agent_key": agent, "family": "processes", "event_id": number,
            "observed_at": at, "observation": observation}


class PG(BasePG):
    def execute(self, sql, params=()):
        flat = " ".join(sql.split())
        if flat.startswith("select payload from sli_plugin_workstations.projection_work"):
            self.calls.append((flat, params))
            agent, numbers, field, name, limit = params
            self.one = None
            self.result = [{"payload": deepcopy(row)} for row in self.rows.values()
                           if row["agent_key"] == agent and row["family"] == "processes"
                           and str(row["event_id"]) in numbers
                           and row["observation"]["facts"].get(field) == name][:limit]
        elif flat.startswith("update sli_plugin_workstations.check_findings set status='resolved'"):
            self.calls.append((flat, params))
            now, _, identifier = params
            row = self.findings.get(identifier)
            if row and row["status"] == "active":
                row.update(status="resolved", resolved_at=now, materially_changed_at=now,
                           revision=row["revision"] + 1)
                row["reason_params"]["superseded_by_native_episodes"] = True
        else:
            super().execute(sql, params)


def apply(pg, row):
    with pg.transaction():
        c05.apply(pg, STATION, {"kind": "observations", "source_id": row["id"], "payload": row})


def active(pg):
    return [row for row in pg.findings.values() if row["status"] == "active"]


@pytest.mark.parametrize("number,change", [(4697, "service_installed"), (7045, "service_installed"),
                                           (4698, "task_created")])
def test_creation_has_native_refs_event_date_and_unknown_inventory_baseline(number, change):
    row = native(number)
    pg = PG(row)
    apply(pg, row)
    finding, = active(pg)
    recorded, = pg.changes.values()
    assert finding["check_id"] == "C05" and finding["severity"] == "medium"
    assert finding["fact_at"] == recorded["event_at"] == OLD
    assert finding["first_detected_at"] == recorded["detected_at"] == NOW
    assert finding["reason_params"]["created_at"] == OLD.isoformat()
    assert finding["reason_params"]["history_start_at"] == OLD.isoformat()
    assert finding["reason_params"]["baseline_status"] == "unknown"
    assert finding["reason_params"]["current_presence"] == "unknown"
    assert finding["quality"]["status"] == "partial"
    assert finding["evidence_refs"] == recorded["evidence_refs"] == [c05.event(row, STATION)["ref"]]
    assert recorded["change_kind"] == change
    assert Reason(recorded["reason_code"]).to_dict()["message_key"].endswith(change)
    before = deepcopy((pg.findings, pg.changes))
    pg.now += timedelta(days=1)
    apply(pg, row)
    assert (pg.findings, pg.changes) == before


def test_7045_never_uses_run_as_roles_or_last_login_as_installer():
    row = native(7045)
    row["observation"]["facts"].update(process_user_sid=ACTOR, process_user_name="fixture-false-actor")
    row["observation"]["roles"].update(actor=f"sid:{ACTOR}", last_login="fixture-last-login")
    pg = PG(row)
    apply(pg, row)
    params = active(pg)[0]["reason_params"]
    assert params["run_as"] == "LocalSystem"
    assert params["actor_status"] == "unknown"
    assert params["actor_sid"] is params["actor_name"] is params["actor_domain"] is None
    assert next(iter(pg.changes.values()))["actor_ref"]["status"] == "unknown"


@pytest.mark.parametrize("first_number", [4697, 7045])
def test_unique_exact_native_pair_has_one_stable_episode_two_refs_and_security_actor(first_number):
    first = native(first_number)
    second = native(7045 if first_number == 4697 else 4697)
    second["id"] = "0" * 64  # Late lower hashes are not a cursor.
    pg = PG(first)
    apply(pg, first)
    identifier = active(pg)[0]["id"]
    pg.rows[second["id"]] = second
    pg.now += timedelta(hours=1)
    apply(pg, second)
    finding, = active(pg)
    assert len(pg.findings) == 1 and finding["id"] == identifier
    assert finding["first_detected_at"] == NOW and finding["revision"] == 2
    assert finding["reason_params"]["dedup_status"] == "exact_pair"
    assert finding["reason_params"]["actor_sid"] == ACTOR
    assert {ref["observation_id"] for ref in finding["evidence_refs"]} == {first["id"], second["id"]}
    assert len(pg.changes) == 2  # Append-only native changes retain each source.
    before = deepcopy((pg.findings, pg.changes))
    for row in (first, second):
        apply(pg, row)
    assert (pg.findings, pg.changes) == before


@pytest.mark.parametrize("change", [
    {"ServiceName": "fixture-other"}, {"ServiceFileName": r"C:\fixture\other.exe"},
    {"ServiceAccount": "fixture-service-account"}, {"ServiceStartType": "3"},
    {"ServiceAccount": "-"}, {"ServiceFileName": "-"}, {"ServiceStartType": "-"},
])
def test_name_alone_or_incomplete_or_different_configuration_cannot_deduplicate(change):
    first, second = native(), native(7045, **change)
    pg = PG(first, second)
    apply(pg, first)
    apply(pg, second)
    assert len(active(pg)) == 2
    assert all(len(row["evidence_refs"]) == 1 for row in active(pg))


def test_other_time_or_station_cannot_pair_and_reinstallation_is_another_episode():
    rows = [native(), native(7045, at=OLD + timedelta(seconds=1)),
            native(7045, agent="fixture-other-agent")]
    pg = PG(*rows)
    for row in rows[:2]:
        apply(pg, row)
    assert len(active(pg)) == 2
    assert {row["fact_at"] for row in active(pg)} == {OLD, OLD + timedelta(seconds=1)}
    assert all(ref["agent_key"] == AGENT for row in active(pg) for ref in row["evidence_refs"])


def test_late_ambiguous_pair_is_split_without_losing_evidence_or_replay_duplicates():
    first, system, extra = native(), native(7045), native(record=11)
    pg = PG(first, system)
    apply(pg, first)
    aggregate = active(pg)[0]["id"]
    pg.rows[extra["id"]] = extra
    pg.now += timedelta(hours=1)
    apply(pg, extra)
    assert len(active(pg)) == 3
    assert pg.findings[aggregate]["status"] == "resolved"
    assert pg.findings[aggregate]["reason_params"]["superseded_by_native_episodes"] is True
    assert all(row["reason_params"]["dedup_status"] == "ambiguous" for row in active(pg))
    assert {ref["observation_id"] for row in active(pg) for ref in row["evidence_refs"]} == {
        first["id"], system["id"], extra["id"]}
    before = deepcopy(pg.findings)
    for row in (first, system, extra):
        apply(pg, row)
    assert pg.findings == before


@pytest.mark.parametrize("number,change", [(4699, "deleted"), (4700, "enabled"),
                                           (4701, "disabled"), (4702, "updated")])
def test_update_delete_enable_disable_are_changes_never_new_creations(number, change):
    row = native(number)
    pg = PG(row)
    apply(pg, row)
    assert not pg.findings
    recorded, = pg.changes.values()
    assert recorded["change_kind"] == f"task_{change}"
    assert recorded["actor_ref"]["sid"] == ACTOR


def test_task_delete_delivered_before_create_closes_episode_and_recreate_is_separate():
    first, deleted, second = native(4698), native(4699, at=OLD + timedelta(hours=1), record=11), native(
        4698, at=OLD + timedelta(hours=2), record=12)
    pg = PG(deleted)
    apply(pg, deleted)
    assert not pg.findings
    pg.rows.update({row["id"]: row for row in (first, second)})
    for row in (second, first):
        apply(pg, row)
    assert len(pg.findings) == 2 and len(active(pg)) == 1
    early, late = sorted(pg.findings.values(), key=lambda row: row["fact_at"])
    assert early["status"] == "resolved" and late["status"] == "active"
    assert early["reason_params"]["deleted_at"] == deleted["observed_at"].isoformat()
    assert {ref["observation_id"] for ref in early["evidence_refs"]} == {first["id"], deleted["id"]}
    assert early["reason_params"]["actor_sid"] == ACTOR


@pytest.mark.parametrize("generation,record,resolved", [
    ("fixture-generation", 11, True), ("fixture-generation", 9, False),
    ("fixture-other-generation", 11, False), (None, 11, False),
])
def test_equal_task_times_require_native_order_for_deletion(generation, record, resolved):
    first = native(4698)
    deleted = native(4699, generation=generation, record=record)
    pg = PG(first, deleted)
    apply(pg, first)
    finding, = pg.findings.values()
    assert (finding["status"] == "resolved") is resolved


@pytest.mark.parametrize("number", [4697, 4698])
def test_common_cause_is_only_matching_configuration_and_is_independent_of_station_and_native_time(number):
    one = c05.event(native(number), STATION)
    other = c05.event(native(number, agent="fixture-other-agent", at=NOW, ServiceName="fixture-other-service",
                             TaskName="fixture-other-task"), "fixture-other-station")
    def cause(item, station):
        groups, _ = c05.episodes([item], station)
        identifier, items, status = groups[0]
        return c05.finding(identifier, items, status, [item], station, NOW)["reason_params"]
    left, right = cause(one, STATION), cause(other, "fixture-other-station")
    assert left["common_cause_id"] == right["common_cause_id"]
    assert left["common_cause_basis"] == right["common_cause_basis"] == "matching_configuration"
    changed = deepcopy(other)
    changed["program" if number == 4697 else "content_sha256"] = "fixture-changed"
    assert cause(changed, "fixture-other-station")["common_cause_id"] != left["common_cause_id"]


def test_oversized_program_prefixes_do_not_become_a_shared_exact_identity():
    first = native(ServiceFileName="x" * 2048 + "a")
    second = native(7045, ServiceFileName="x" * 2048 + "b")
    pg = PG(first, second)
    for row in (first, second):
        apply(pg, row)
    assert len(active(pg)) == 2
    assert all(row["reason_params"]["common_cause_id"] is None for row in active(pg))


@pytest.mark.parametrize("field,value", [("channel", "fixture-channel"), ("provider_name", "fixture-provider")])
def test_wrong_native_source_is_ignored(field, value):
    row = native()
    row["observation"][field] = value
    pg = PG(row)
    apply(pg, row)
    assert not pg.calls and not pg.findings and not pg.changes


def test_bounded_durable_history_overflow_does_not_publish_partial_findings(monkeypatch):
    monkeypatch.setattr(c05, "MAX_OBJECT_EVENTS", 2)
    rows = [native(record=record) for record in (10, 11, 12)]
    pg = PG(*rows)
    with pytest.raises(ValueError, match="history_too_large"):
        apply(pg, rows[0])
    assert not pg.findings and not pg.changes
    sql, params = next((sql, params) for sql, params in pg.calls if sql.startswith("select payload"))
    assert "projection_work" in sql and "limit %s" in sql and params[-1] == 3
    assert "source_xml" not in sql and "observations where" not in sql
    assert pg.calls[0][0] == "set local statement_timeout='5000ms'"


def test_publication_failure_rolls_back_changes_and_findings_before_retry(monkeypatch):
    row, original = native(), c05._save_finding
    pg = PG(row)
    def fail(*args):
        original(*args)
        raise RuntimeError("fixture-publication-failed")
    monkeypatch.setattr(c05, "_save_finding", fail)
    with pytest.raises(RuntimeError, match="fixture-publication-failed"):
        apply(pg, row)
    assert not pg.findings and not pg.changes
    monkeypatch.setattr(c05, "_save_finding", original)
    apply(pg, row)
    assert len(active(pg)) == len(pg.changes) == 1


def test_registers_versioned_wr05_consumer_and_ignores_unrelated_inputs():
    registered = next(item for item in projection.projectors() if item.key == c05.PROJECTOR)
    assert registered.version == 1 and registered.apply is c05.apply
    pg = PG()
    registered.apply(pg, STATION, {"kind": "station_inventory", "payload": {}})
    assert not pg.calls
