"""WR04 inventory contracts with synthetic identities and fake cursors only."""

from copy import deepcopy
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from server.sli.plugins.workstations import inventory, projection_jobs, registration

OBSERVED = datetime(2026, 10, 19, tzinfo=timezone.utc)


def agent(number):
    return {"agent_key": f"00000000-0000-4000-8000-{number:012d}",
            "source_instance_id": f"10000000-0000-4000-8000-{number:012d}"}


def device(number, entity_id=None):
    return {**agent(number), "entity_id": entity_id or number + 1000,
            "display_name": f"fixture-device-{number}"}


def computer(number, *, domain=11, **attributes):
    return {"ad_computer_id": number, "domain_id": domain,
            "display_name": f"fixture-station-{number}", "metadata_observed_at": OBSERVED,
            "attributes": {"operating_system": "Windows 11", "organizational_unit": "fixture-ou",
                           "ip_addresses": ["192.0.2.10"], **attributes}}


def association(source, target):
    return {"source_entity_id": source, "target_entity_id": target}


def test_inventory_100_unique_stations_including_ad_only_agent_only_and_ambiguous():
    directory = [computer(number, domain=11 if number <= 50 else 22) for number in range(1, 99)]
    agents = [agent(number) for number in [*range(1, 98), 99, 100]]
    devices = [device(number) for number in [*range(1, 98), 99, 100]]
    links = [association(number + 1000, number) for number in range(1, 98)]
    links += [association(1100, 1), association(1100, 2)]
    # Repeated identity observations/association evidence cannot multiply rows.
    rows = inventory.build_inventory(directory, agents, devices + devices, links + links)

    assert len(rows) == len({row["station_id"] for row in rows}) == 100
    ad_only = next(row for row in rows if row["ad_computer_id"] == 98)
    assert ad_only["agent_key"] is None and ad_only["association_status"] == "unlinked"
    agent_only = next(row for row in rows if row["agent_key"] == agent(99)["agent_key"])
    assert agent_only["ad_computer_id"] is None and agent_only["domain_id"] is None
    ambiguous = next(row for row in rows if row["agent_key"] == agent(100)["agent_key"])
    assert ambiguous["association_status"] == "ambiguous"
    assert ambiguous["ad_computer_id"] is ambiguous["domain_id"] is ambiguous["ou_entity_id"] is None
    assert ambiguous["metadata"]["ou_path"] is None
    assert ambiguous["metadata"]["operating_system"] is None
    assert ambiguous["metadata"]["ip_addresses"] == []
    assert ambiguous["quality"]["status"] == "partial"
    assert sum(row["association_status"] == "unique" for row in rows) == 97


def test_metadata_is_current_directory_only_with_observation_time_and_valid_deduplicated_ips():
    source = computer(1, operating_system="Windows Server 2025", operating_system_version="fixture-version",
                      ip_addresses=["192.0.2.10", "192.0.2.10", "2001:db8::1", "not-an-address", None],
                      password="fixture-private", description="fixture-private")
    rows = inventory.build_inventory([source], [agent(1)], [device(1)], [association(1001, 1)])
    row = rows[0]
    assert row["station_type"] == "server"
    assert row["metadata"] == {
        "display_name": "fixture-station-1", "ou_path": "fixture-ou",
        "operating_system": "Windows Server 2025", "operating_system_version": "fixture-version",
        "ip_addresses": ["192.0.2.10", "2001:db8::1"],
    }
    assert row["metadata_observed_at"] == OBSERVED
    assert "fixture-private" not in repr(rows)
    assert row["quality"]["status"] == "complete"


def test_name_and_ip_equality_never_merge_different_directory_identities_or_agents():
    first, second = computer(1), computer(2, domain=22)
    second["display_name"] = first["display_name"]
    rows = inventory.build_inventory([first, second], [agent(1)], [
        {**device(1), "display_name": first["display_name"]}], [])
    assert len(rows) == len({row["station_id"] for row in rows}) == 3
    assert {row["domain_id"] for row in rows} == {11, 22, None}


@pytest.mark.parametrize("devices,links", [
    ([device(1), device(1, 2001)], [association(1001, 1)]),
    ([device(1)], [association(1001, 1), association(1001, 2)]),
])
def test_multiple_devices_or_directory_targets_never_enrich_agent(devices, links):
    rows = inventory.build_inventory([computer(1), computer(2)], [agent(1)], devices, links)
    assert len(rows) == 3
    row = next(row for row in rows if row["agent_key"])
    assert row["association_status"] == "ambiguous" and row["ad_computer_id"] is None
    assert row["domain_id"] is None and row["station_type"] == "unknown"


def test_multiple_agents_for_one_directory_computer_do_not_arbitrarily_pick_an_agent():
    rows = inventory.build_inventory([computer(1)], [agent(1), agent(2)],
                                     [device(1), device(2)], [association(1001, 1), association(1002, 1)])
    assert len(rows) == 3
    assert rows[0]["station_id"] != rows[1]["station_id"]
    assert sum(row["association_status"] == "ambiguous" for row in rows) == 2
    assert next(row for row in rows if row["ad_computer_id"])["agent_key"] is None


def test_shared_device_identity_does_not_duplicate_inventory_unique_entity_id():
    rows = inventory.build_inventory([computer(1)], [agent(1), agent(2)],
                                     [device(1), device(2, 1001)], [association(1001, 1)])
    assert len(rows) == 3
    for row in rows:
        if row["agent_key"]:
            assert row["association_status"] == "ambiguous"
            assert row["entity_id"] is None and row["ad_computer_id"] is None


def test_ou_fallback_keeps_directory_parent_reference_without_translated_unknown_labels():
    source = computer(1, organizational_unit=None,
                      distinguished_name=r"CN=fixture-station,OU=fixture\,unit,DC=example,DC=test")
    rows = inventory.build_inventory([source], [], [], [])
    assert rows[0]["metadata"]["ou_path"] == r"OU=fixture\,unit,DC=example,DC=test"


def test_unregistered_or_foreign_host_device_and_non_directory_target_cannot_link():
    foreign = {**device(1), "source_instance_id": agent(2)["source_instance_id"]}
    rows = inventory.build_inventory([computer(1)], [agent(1)], [foreign, device(2)],
                                     [association(1001, 1), association(1002, 1)])
    assert len(rows) == 2 and all(row["association_status"] == "unlinked" for row in rows)
    rows = inventory.build_inventory([computer(1)], [agent(1)], [device(1)], [association(1001, 999)])
    assert len(rows) == 2 and all(row["ad_computer_id"] != 999 for row in rows)


def test_missing_snapshot_and_metadata_remain_unknown_not_healthy():
    source = {**computer(1), "attributes": None, "metadata_observed_at": None}
    rows = inventory.build_inventory([source], [agent(1)], [], [])
    assert len(rows) == 2
    for row in rows:
        assert row["station_type"] == "unknown" and row["metadata_observed_at"] is None
        assert row["metadata"]["operating_system"] is None and row["metadata"]["ip_addresses"] == []
        assert row["quality"]["status"] == "not_collected"


def test_station_id_survives_rename_ou_ip_and_unique_directory_enrichment():
    initial = inventory.build_inventory([], [agent(1)], [device(1)], [])
    rows = inventory.build_inventory([computer(1)], [agent(1)], [device(1)], [association(1001, 1)], initial)
    assert rows[0]["station_id"] == initial[0]["station_id"]
    changed = computer(1, organizational_unit="fixture-other-ou", ip_addresses=["192.0.2.20"])
    changed["display_name"] = "fixture-renamed"
    changed_rows = inventory.build_inventory([changed], [agent(1)], [device(1)], [association(1001, 1)], rows)
    assert changed_rows[0]["station_id"] == rows[0]["station_id"]
    assert changed_rows[0]["metadata"]["ou_path"] == "fixture-other-ou"


def test_existing_directory_id_wins_when_previously_separate_populations_join():
    initial = inventory.build_inventory([computer(1)], [agent(1)], [device(1)], [])
    ad_id = next(row["station_id"] for row in initial if row["ad_computer_id"])
    rows = inventory.build_inventory([computer(1)], [agent(1)], [device(1)], [association(1001, 1)], initial)
    assert len(rows) == 1 and rows[0]["station_id"] == ad_id
    assert rows[0]["agent_key"] == agent(1)["agent_key"]


def test_order_and_replayed_input_do_not_change_station_identity_or_metadata():
    directory, agents, devices = [computer(1), computer(2)], [agent(1), agent(2)], [device(1), device(2)]
    links = [association(1001, 1)]
    before = deepcopy((directory, agents, devices, links))
    rows = inventory.build_inventory(directory, agents, devices, links)
    assert inventory.build_inventory(directory[::-1], agents[::-1], devices[::-1], links * 2) == rows
    assert (directory, agents, devices, links) == before


def test_inventory_source_is_internal_bounded_and_reads_only_current_identity_metadata(monkeypatch):
    batches = [[computer(1)], [agent(1)], [device(1)], [association(1001, 1)], []]
    calls = []
    cur = SimpleNamespace(execute=lambda sql, params=(): calls.append((" ".join(sql.split()), params)),
                          fetchall=lambda: batches.pop(0))
    rows = inventory.inventory_source(cur)
    assert len(rows) == 1 and rows[0]["association_status"] == "unique"
    assert calls[0] == ("set local statement_timeout = '5000ms'", ())
    assert all(params[-1] == inventory.MAX_INPUT_ROWS + 1 for _, params in calls[1:])
    sql = " ".join(statement for statement, _ in calls)
    assert "entities_v2_active" in sql and "t.value='ad_computer'" in sql
    assert "v.valid_to_utc is null" in sql and "v.source_section='directory_accounts'" in sql
    assert "r.plugin_id='sli.workstations'" in sql and "r.resolution='resolved'" in sql
    assert "r.source_instance_id=a.source_instance_id" in sql and "r.natural_key=a.identity_key" in sql
    assert "relation='directory_computer'" in sql
    assert "observations" not in sql and "source_xml" not in sql and "certificates" not in sql
    # Registration contributes both inventory hooks and projection job handlers.
    contribution = SimpleNamespace(hooks={}, jobs={})
    monkeypatch.setattr(registration.retention, "register_jobs", lambda *args, **kwargs: None)
    registration.register(contribution)
    assert contribution.hooks["inventory_source"] is inventory.inventory_source
    assert contribution.jobs[projection_jobs.HANDLER_ID] == (projection_jobs.stage, projection_jobs.apply)


def test_overflow_never_returns_a_silently_truncated_union(monkeypatch):
    monkeypatch.setattr(inventory, "MAX_INPUT_ROWS", 1)
    cur = SimpleNamespace(execute=lambda *args: None, fetchall=lambda: [computer(1), computer(2)])
    with pytest.raises(ValueError, match="^workstation_inventory_too_large$"):
        inventory.inventory_source(cur)
