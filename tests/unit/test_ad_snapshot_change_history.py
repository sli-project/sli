from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from server.sli.sources.ad_snapshot_history_policy import history_days
from server.sli.storage import ad_snapshot_change_history as history

NOW = datetime(2026, 10, 7, tzinfo=timezone.utc)


def users(*rows, complete=True):
    return {"metadata": {"collection_status": "complete" if complete else "partial"},
            "users": list(rows), "groups": []}


def test_extracts_object_attribute_and_membership_changes_without_raw_values():
    previous = users({"objectGuid": "synthetic-1", "enabled": True,
                      "memberships": {"direct": [{"id": "group:1"}] }},
                     {"objectGuid": "synthetic-2"})
    current = users({"objectGuid": "synthetic-1", "enabled": False,
                     "memberships": {"direct": [{"id": "group:2"}] }},
                    {"objectGuid": "synthetic-3"})
    rows = history.extract_changes("users_v2", previous, current)
    assert {row["kind"] for row in rows} == {
        "object_added", "object_removed", "attribute_changed", "membership_added", "membership_removed"}
    assert next(row for row in rows if row["field"] == "enabled")["before_sha256"] != ""
    assert all("before" not in row and "after" not in row for row in rows)
    assert previous["users"][0]["enabled"] is True


def test_unknown_and_excluded_attributes_never_enter_history_even_as_hashes():
    previous = users({"objectGuid": "synthetic-1", "unicodePwd": "excluded-a", "unknown": 1})
    current = users({"objectGuid": "synthetic-1", "unicodePwd": "excluded-b", "unknown": 2})
    assert history.extract_changes("users_v2", previous, current) == []


def test_partial_snapshots_do_not_claim_removals_or_absent_memberships():
    before = users({"id": "synthetic-1", "memberships": {"direct": [{"id": "group:1"}] }})
    assert history.extract_changes("users_v2", before, users(complete=False)) == []
    after = users({"id": "synthetic-1", "memberships": {"direct": [], "state": "partial"}})
    assert history.extract_changes("users_v2", before, after) == []
    after["users"][0]["memberships"] = {"direct": [], "status": "partial"}
    assert history.extract_changes("users_v2", before, after) == []


@pytest.mark.parametrize("old_complete,new_complete", [(False, False), (True, False), (False, True)])
def test_partial_pair_retains_observed_membership_addition_without_claiming_removal(old_complete, new_complete):
    before = users({"objectGuid": "synthetic-1", "sourceStates": {"directory": {"status": "observed"}},
                    "memberships": {"status": "observed", "direct": [{"objectGuid": "group:1"}]}},
                   {"objectGuid": "synthetic-removed"}, complete=old_complete)
    after = users({"objectGuid": "synthetic-1", "sourceStates": {"directory": {"status": "observed"}},
                   "memberships": {"status": "observed", "direct": [{"objectGuid": "group:2"}]}},
                  {"objectGuid": "synthetic-added"}, complete=new_complete)
    assert history.extract_changes("users_v2", before, after) == [{
        "object_type": "ad_user", "object_id": "synthetic-1", "kind": "membership_added",
        "field": "direct", "related_object_id": "group:2", "before_sha256": "",
        "after_sha256": history._hash("group:2"),
    }]
    after["metadata"]["search_base"] = "different-scope"
    assert history.extract_changes("users_v2", before, after) == []


@pytest.mark.parametrize("side", ["before", "after"])
@pytest.mark.parametrize("unknown", ["memberships", "directory", "absent"])
def test_partial_pair_never_infers_membership_addition_from_unknown_object(side, unknown):
    before = users({"id": "synthetic-1", "sourceStates": {"directory": {"status": "observed"}},
                    "memberships": {"status": "observed", "direct": []}}, complete=False)
    after = deepcopy(before)
    after["users"][0]["memberships"]["direct"] = [{"id": "group:2"}]
    row = (before if side == "before" else after)["users"][0]
    if unknown == "absent":
        row.pop("memberships")
    elif unknown == "memberships":
        row["memberships"]["status"] = "partial"
    else:
        row["sourceStates"]["directory"]["status"] = "unavailable"
    assert history.extract_changes("users_v2", before, after) == []


@pytest.mark.parametrize("state_field", ["sourceStates", "sourceState", "source_state"])
def test_partial_pair_ignores_unobserved_group_membership(state_field):
    before = users(complete=False)
    before["groups"] = [{"id": "group:1", "parentGroupIds": []}]
    after = deepcopy(before)
    after["groups"][0]["parentGroupIds"] = ["group:2"]
    assert history.extract_changes("users_v2", before, after)[0]["kind"] == "membership_added"
    state = {"status": "unavailable"}
    after["groups"][0][state_field] = {"directory": state} if state_field == "sourceStates" else state
    assert history.extract_changes("users_v2", before, after) == []


def test_gpo_link_and_setting_changes_are_compact_and_redacted():
    before = {"collection_status": "complete", "gpos": [], "links": [
        {"id": "link-1", "enabled": True}], "settings": [
        {"id": "setting-1", "setting_name": "Synthetic setting", "value_display": "1"},
        {"id": "setting-2", "setting_name": "cpassword", "value_display": "excluded-a"}]}
    after = deepcopy(before)
    after["links"][0]["enabled"] = False
    after["settings"][0]["value_display"] = "2"
    after["settings"][1]["value_display"] = "excluded-b"
    rows = history.extract_changes("gpo_v2", before, after)
    assert {(row["object_type"], row["field"]) for row in rows} == {
        ("gpo_link", "enabled"), ("gpo_setting", "value_display")}


@pytest.mark.parametrize("value", ["6", "3651", "7.5", "True", "", "-7"])
def test_history_days_rejects_invalid_values(value):
    with pytest.raises(ValueError):
        history_days(value)


@pytest.mark.parametrize("value", ["7", "365", "3650"])
def test_history_days_accepts_bounds(value):
    assert history_days(value) == value


def test_publication_readback_is_required_before_confirmation(monkeypatch):
    batch = {"batch_id": "a" * 64, "records": [{"record_id": "b" * 64,
             "batch_id": "a" * 64, "payload_json": "{}", "domain_id": 1,
             "family": "users_v2", "observed_at": ch_time(NOW)}]}
    inserted = []
    monkeypatch.setattr(history.ch, "_http_insert_json_rows", lambda *args: inserted.append(args))
    monkeypatch.setattr(history.ch, "_rows", lambda *args, **kw: [])
    with pytest.raises(RuntimeError, match="readback"):
        history.publish_batch(8123, batch)
    assert len(inserted) == 1


def test_retention_purges_exact_cutoff_synchronously_and_reports_counts(monkeypatch):
    commands = []
    monkeypatch.setattr(history.ch, "_rows", lambda *a, **kw: [{"count": 3}] if not commands else [{"count": 0}])
    monkeypatch.setattr(history.ch, "_http_query", lambda *a, **kw: commands.append((a, kw)))
    result = history.purge_history(8123, days=365, now=NOW)
    assert result["deleted_records"] == 3
    assert result["cutoff_utc"] == (NOW - timedelta(days=365)).isoformat()
    assert "mutations_sync=2" in commands[0][0][1]
    assert "<" in commands[0][0][1]
    assert commands[0][1]["params"]["param_cutoff"] == ch_time(NOW - timedelta(days=365))


def ch_time(value):
    return value.strftime("%Y-%m-%d %H:%M:%S.%f")


def test_search_base_change_does_not_claim_object_additions_or_removals():
    before, after = users({"id": "synthetic-1"}), users({"id": "synthetic-2"})
    before["metadata"]["search_base"] = "scope-1"
    after["metadata"]["search_base"] = "scope-2"
    assert history.extract_changes("users_v2", before, after) == []


def test_nested_groups_and_gpo_versions_are_compared():
    before = users()
    before["groups"] = [{"id": "group:1", "parentGroupIds": ["group:2"]}]
    after = deepcopy(before)
    after["groups"][0]["parentGroupIds"] = ["group:3"]
    assert {row["kind"] for row in history.extract_changes("users_v2", before, after)} == {
        "membership_added", "membership_removed"}
    gpo = {"collection_status": "complete", "gpos": [{"id": "gpo:1", "computer": {"directory_version": 1}}]}
    changed = deepcopy(gpo)
    changed["gpos"][0]["computer"]["directory_version"] = 2
    assert history.extract_changes("gpo_v2", gpo, changed)[0]["field"] == "computer.directory_version"


def test_bootstrap_is_idempotent_and_does_not_set_fixed_ttl(monkeypatch):
    statements = []
    monkeypatch.setattr(history.ch, "_http_query", lambda port, sql: statements.append(sql))
    history.ensure_schema(8123)
    history.ensure_schema(8123)
    assert statements[:2] == statements[2:]
    assert all("IF NOT EXISTS" in statement for statement in statements)
    assert not any("TTL" in statement for statement in statements)


class PublicationConnection:
    def __init__(self, *, replay=False):
        self.sql = ""
        self.events = []
        self.replay = replay

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def execute(self, sql, params=()):
        self.sql = sql
        if "insert into public.ad_snapshot_history_confirmations" in sql:
            self.events.append(("confirm", params))

    def fetchone(self):
        if "select domain_id,slot_start_utc" in self.sql:
            return {"domain_id": 1, "slot_start_utc": NOW}
        if "select manifest_id from" in self.sql:
            return {"manifest_id": "previous"}
        if "select * from public.ad_snapshot_history_confirmations" in self.sql:
            return {"batch_id": "a" * 64} if self.replay else None
        raise AssertionError(self.sql)


def test_publication_confirms_each_verified_pair_including_zero_records(monkeypatch):
    connection = PublicationConnection()
    manifest = {"manifest_id": "current", "coverage_state": "complete", "members": [
        {"family": family} for family in history.FAMILIES]}
    monkeypatch.setattr(history, "load_projection_manifest", lambda *_: manifest)
    monkeypatch.setattr(history, "_payload", lambda _, m, family: (users(), "a" * 64))
    monkeypatch.setattr(history, "publish_batch", lambda *args: connection.events.append(("readback", args[1])))
    outcome = history.publish_manifest(connection, 8123, "current")
    assert outcome == {"status": "confirmed", "records_published": 0}
    assert [event[0] for event in connection.events] == ["readback", "confirm"] * 3
    for _, params in connection.events[1::2]:
        assert params[3:6] == ("previous", "a" * 64, "a" * 64)
        assert params[8] == 0


def test_partial_membership_addition_is_verified_and_confirmed_with_partial_coverage(monkeypatch):
    before = users({"id": "synthetic-1", "memberships": {"status": "observed", "direct": []}}, complete=False)
    after = deepcopy(before)
    after["users"][0]["memberships"]["direct"] = [{"id": "group:2"}]
    manifests = {name: {"manifest_id": name, "coverage_state": "partial", "members": [{"family": "users_v2"}]}
                 for name in ("previous", "current")}
    monkeypatch.setattr(history, "load_projection_manifest", lambda _, name: manifests[name])
    monkeypatch.setattr(history, "_payload", lambda _, m, family: (
        before if m["manifest_id"] == "previous" else after, "a" * 64))
    connection = PublicationConnection()
    monkeypatch.setattr(history, "publish_batch", lambda _, batch: connection.events.append(("readback", batch)))
    assert history.publish_manifest(connection, 8123, "current") == {"status": "confirmed", "records_published": 1}
    assert [event[0] for event in connection.events] == ["readback", "confirm"]
    record = connection.events[0][1]["records"][0]
    assert record["payload_json"] == history._json({
        "object_type": "ad_user", "object_id": "synthetic-1", "kind": "membership_added",
        "field": "direct", "related_object_id": "group:2", "before_sha256": "",
        "after_sha256": history._hash("group:2"),
    })
    params = connection.events[1][1]
    assert params[8:] == (1, NOW, "partial")
    assert params[7] == history._hash([(record["record_id"], record["payload_json"])])


def test_failed_publication_never_confirms_and_replay_does_not_need_expired_source(monkeypatch):
    manifest = {"manifest_id": "current", "coverage_state": "complete", "members": [
        {"family": family} for family in history.FAMILIES]}
    monkeypatch.setattr(history, "load_projection_manifest", lambda *_: manifest)
    monkeypatch.setattr(history, "_payload", lambda *a: (users(), "a" * 64))
    monkeypatch.setattr(history, "publish_batch", lambda *a: (_ for _ in ()).throw(RuntimeError("readback_failed")))
    connection = PublicationConnection()
    with pytest.raises(RuntimeError, match="readback_failed"):
        history.publish_manifest(connection, 8123, "current")
    assert connection.events == []
    monkeypatch.setattr(history, "_payload", lambda *a: pytest.fail("expired source loaded"))
    assert history.publish_manifest(PublicationConnection(replay=True), 8123, "current")["status"] == "confirmed"


@pytest.mark.parametrize("missing_in", ["current", "previous"])
def test_optional_gpo_absence_publishes_available_families_without_fabricating_confirmation(monkeypatch, missing_in):
    connection = PublicationConnection()
    manifests = {
        name: {"manifest_id": name, "coverage_state": "partial", "members": [
            {"family": family, "source_id": "synthetic", "payload_sha256": "a" * 64}
            for family in history.FAMILIES if name != missing_in or family != "gpo_v2"
        ]} for name in ("current", "previous")
    }
    monkeypatch.setattr(history, "load_projection_manifest", lambda _, name: manifests[name])
    payload = users()
    digest = history.canonical_output_sha256(payload)
    for manifest in manifests.values():
        for member in manifest["members"]:
            member["payload_sha256"] = digest
    monkeypatch.setattr(history, "load_exact_projection_source", lambda *a, **kw: payload)
    monkeypatch.setattr(history, "publish_batch", lambda *a: None)
    assert history.publish_manifest(connection, 8123, "current")["status"] == "confirmed"
    confirmations = {params[1]: params for _, params in connection.events}
    assert {"users_v2", "computers_v6"} <= confirmations.keys()
    if missing_in == "current":
        assert "gpo_v2" not in confirmations
    else:
        assert confirmations["gpo_v2"][3] is None  # New baseline after the gap.
        assert confirmations["gpo_v2"][5] is None
        assert confirmations["gpo_v2"][8:] == (0, NOW, "partial")


def test_storage_cycle_rolls_back_hash_mismatch_and_blocks_expiry(monkeypatch):
    from server.sli.core import postgres_runtime_pipeline
    from server.sli.storage import permanent_history_lifecycle as lifecycle

    class CycleConnection(PublicationConnection):
        rolled_back = False

        def fetchall(self):
            assert "select m.manifest_id" in self.sql
            return [{"manifest_id": "current"}]

        def fetchone(self):
            if "schema_migrations" in self.sql:
                return {"admitted": 'version=200' not in self.sql}
            return super().fetchone()

        def __exit__(self, error_type, *_):
            if error_type is not None:
                self.rolled_back = True
                self.events.clear()

        def commit(self):
            pytest.fail("unconfirmed publication committed")

    connection = CycleConnection()
    payload = users()
    manifest = {"coverage_state": "partial", "members": [
        {"family": family, "source_id": "synthetic",
         "payload_sha256": "b" * 64}
        for family in ("users_v2", "computers_v6")
    ]}
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: connection)
    monkeypatch.setattr(history, "ensure_schema", lambda *a: None)
    monkeypatch.setattr(history, "load_projection_manifest", lambda *a: manifest)
    monkeypatch.setattr(history, "load_exact_projection_source", lambda *a, **kw: payload)
    monkeypatch.setattr(history, "publish_batch", lambda *a: None)
    monkeypatch.setattr(history, "purge_history", lambda *a, **kw: pytest.fail("AD history deletion"))
    monkeypatch.setattr(lifecycle.history, "primary_read_enabled", lambda: True)
    monkeypatch.setattr(lifecycle.history, "configured_read_port", lambda: 8123)
    monkeypatch.setattr(lifecycle.history, "next_after_id", lambda *a: pytest.fail("event history copy"))
    monkeypatch.setattr(lifecycle.file_retention, "run_batch", lambda **kw: pytest.fail("file deletion"))
    monkeypatch.setattr(lifecycle, "_retain", lambda **kw: pytest.fail("hot deletion"))
    result = lifecycle.run_cycle(apply_retention=True, now=NOW)
    assert result["status"] == "blocked"
    assert result["reason"] == "snapshot_history_source_hash_mismatch"
    assert result["deleted_rows"] == 0
    assert connection.rolled_back and not connection.events


def test_clickhouse_retry_is_deterministic_and_checks_all_identity_columns(monkeypatch):
    record = {"batch_id": "a" * 64, "record_id": "b" * 64, "domain_id": 1, "family": "users_v2",
              "observed_at": ch_time(NOW), "payload_json": "{}"}
    inserts = []
    monkeypatch.setattr(history.ch, "_http_insert_json_rows", lambda *args: inserts.append(args[2]))
    monkeypatch.setattr(history.ch, "_rows", lambda *a, **kw: [record])
    for _ in range(2):
        history.publish_batch(8123, {"batch_id": "a" * 64, "records": [record]})
    assert inserts[0] == inserts[1]
    monkeypatch.setattr(history.ch, "_rows", lambda *a, **kw: [{**record, "domain_id": 2}])
    with pytest.raises(RuntimeError, match="identity_readback"):
        history.publish_batch(8123, {"batch_id": "a" * 64, "records": [record]})


def test_missing_composition_migration_blocks_before_publication_or_purge(monkeypatch):
    from server.sli.core import postgres_runtime_pipeline

    class Connection(PublicationConnection):
        def fetchone(self):
            assert "schema_migrations" in self.sql
            return {"admitted": False}

    monkeypatch.setattr(postgres_runtime_pipeline, "connect", Connection)
    monkeypatch.setattr(history, "ensure_schema", lambda *a: pytest.fail("schema before admission"))
    monkeypatch.setattr(history, "publish_manifest", lambda *a: pytest.fail("publish before admission"))
    monkeypatch.setattr(history, "purge_history", lambda *a, **kw: pytest.fail("purge before admission"))
    with pytest.raises(RuntimeError, match="^snapshot_history_migration_required$"):
        history.run_cycle(port=8123, apply_retention=True, now=NOW)


def test_retention_failed_readback_is_not_reported_as_deleted(monkeypatch):
    monkeypatch.setattr(history.ch, "_rows", lambda *a, **kw: [{"count": 3}])
    monkeypatch.setattr(history.ch, "_http_query", lambda *a, **kw: None)
    with pytest.raises(RuntimeError, match="retention_readback_failed"):
        history.purge_history(8123, days=7, now=NOW)


def test_storage_cycle_preserves_available_ad_families_then_copies_events(monkeypatch):
    from contextlib import nullcontext
    from server.sli.core import postgres_runtime_pipeline
    from server.sli.storage import permanent_history_lifecycle as lifecycle

    class Connection(PublicationConnection):
        commits = 0

        def fetchone(self):
            if "schema_migrations" in self.sql:
                return {"admitted": 'version=200' not in self.sql}
            if "as partial" in self.sql:
                return {"partial": True}
            if "platform_settings" in self.sql:
                return {"value": "7"}
            return super().fetchone()

        def fetchall(self):
            return [{"manifest_id": "current"}]

        def commit(self):
            self.commits += 1

    connection = Connection()
    payload = users()
    manifest = {"coverage_state": "partial", "members": [
        {"family": family, "source_id": "synthetic", "payload_sha256": history.canonical_output_sha256(payload)}
        for family in ("users_v2", "computers_v6")
    ]}
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: connection)
    monkeypatch.setattr(history, "ensure_schema", lambda *a: None)
    monkeypatch.setattr(history, "load_projection_manifest", lambda *a: manifest)
    monkeypatch.setattr(history, "load_exact_projection_source", lambda *a, **kw: payload)
    monkeypatch.setattr(history, "publish_batch", lambda *a: None)
    monkeypatch.setattr(history, "purge_history", lambda *a, **kw: pytest.fail("AD history purge"))
    monkeypatch.setattr(lifecycle.history, "primary_read_enabled", lambda: True)
    monkeypatch.setattr(lifecycle.history, "configured_read_port", lambda: 8123)
    monkeypatch.setattr(lifecycle, "session_advisory_lock", lambda *a: nullcontext(True))
    monkeypatch.setattr(lifecycle.history, "next_after_id", lambda *a: 0)
    copied = []
    monkeypatch.setattr(lifecycle.history, "copy_one_batch", lambda *a, **kw: copied.append(kw) or {"status": "complete"})
    monkeypatch.setattr(lifecycle.file_retention, "run_batch", lambda **kw: pytest.fail("file deletion"))
    monkeypatch.setattr(lifecycle, "_retain", lambda **kw: pytest.fail("hot deletion"))
    result = lifecycle.run_cycle(apply_retention=False, now=NOW)
    assert result["status"] == "ok" and result["warning_reason"] == "ad_snapshot_history_coverage_partial"
    assert result["ad_snapshot_history"]["manifests_published"] == 1
    assert {params[1] for _, params in connection.events} == {"users_v2", "computers_v6"}
    assert connection.commits == 2 and len(copied) == 1
    assert result["deleted_rows"] == 0 and result["copy_only_no_delete"] is True
