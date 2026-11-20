from copy import deepcopy
import gzip
import hashlib
import json
from pathlib import Path
from types import ModuleType

import pytest

from scripts.maintenance import ad_jobs_parity
from server.sli.sources import ad_gpo_jobs, ad_snapshot_projection


@pytest.fixture
def snapshot():
    families = ("ad_context_base", "users_v2", "computers_v6", "gpo_v2")
    sources = [
        {"family": family, "source_id": str(index), "payload_sha256": "b" * 64,
         "payload_json": {"items": [{"id": "synthetic-1"}, {"id": "synthetic-2"}],
                          "status": "completed"}}
        for index, family in enumerate(families, 1)
    ]
    return {
        "manifest": {"manifest_id": "00000000-0000-4000-8000-000000000501",
                     "manifest_sha256": "a" * 64, "domain_id": 1, "coverage_state": "complete",
                     "members": [{key: source[key] for key in
                                  ("family", "source_id", "payload_sha256")} for source in sources]},
        "sources": sources,
    }


def test_real_paths_match_all_four_outputs_without_mutating_input(snapshot, monkeypatch):
    monkeypatch.delenv(ad_gpo_jobs.FLAG, raising=False)
    before = deepcopy(snapshot)
    verdict = ad_jobs_parity.compare_snapshot(snapshot)
    assert verdict["status"] == "match"
    assert verdict["coverage_state"] == "complete"
    assert set(verdict["projections"]) == {"ad.state", "ad.users.v2", "ad.computers.v6", "ad.gpo.v2"}
    expected_payload_hash = hashlib.sha256(
        b'{"items":[{"id":"synthetic-1"},{"id":"synthetic-2"}],"status":"completed"}'
    ).hexdigest()
    for key, summary in verdict["projections"].items():
        assert summary["match"]
        assert summary["legacy"]["output_identity"] == (
            f"00000000-0000-4000-8000-000000000501:{key}:v1")
        assert summary["legacy"]["record_count"] == 2
        assert summary["legacy"]["output_sha256"] == expected_payload_hash
        assert summary["legacy"]["payload_sha256"] == expected_payload_hash
        assert summary["legacy"] == summary["queue"]
    table = verdict["tables"]["ad_snapshot_projection_outputs"]
    assert table["match"] and table["legacy"]["row_count"] == 4
    assert len(table["legacy"]["content_sha256"]) == 64
    assert table["legacy"] == table["queue"]
    assert snapshot == before
    assert "synthetic-1" not in json.dumps(verdict)
    assert not ad_gpo_jobs.enabled()


@pytest.mark.parametrize("field,value", [
    ("output_identity", "synthetic-changed-identity"),
    ("output_sha256", "c" * 64),
])
def test_queue_result_drift_is_a_mismatch(snapshot, monkeypatch, field, value):
    original = ad_gpo_jobs.stage

    def changed(conn, job):
        result = original(conn, job)
        if job["handler_id"] == "gpo-snapshot":
            result["projection_results"]["ad.gpo.v2"][field] = value
        return result

    monkeypatch.setattr(ad_gpo_jobs, "stage", changed)
    verdict = ad_jobs_parity.compare_snapshot(snapshot)
    assert verdict["status"] == "mismatch"
    assert not verdict["projections"]["ad.gpo.v2"]["match"]
    assert not verdict["tables"]["ad_snapshot_projection_outputs"]["match"]


def test_dropped_queue_output_changes_table_row_count(snapshot, monkeypatch):
    original = ad_gpo_jobs.stage

    def dropped(conn, job):
        result = original(conn, job)
        if job["handler_id"] == "gpo-snapshot":
            result["projection_results"] = {}
        return result

    monkeypatch.setattr(ad_gpo_jobs, "stage", dropped)
    verdict = ad_jobs_parity.compare_snapshot(snapshot)
    assert verdict["status"] == "mismatch"
    assert verdict["tables"]["ad_snapshot_projection_outputs"]["queue"]["row_count"] == 3


def test_queue_payload_row_loss_is_detected(snapshot, monkeypatch):
    original = ad_gpo_jobs.project_exact_manifest

    def changed(manifest, *, load_exact, projection_keys):
        def fewer_rows(*args):
            payload = load_exact(*args)
            payload["items"].pop()
            return payload

        return original(manifest, load_exact=fewer_rows, projection_keys=projection_keys)

    monkeypatch.setattr(ad_gpo_jobs, "project_exact_manifest", changed)
    verdict = ad_jobs_parity.compare_snapshot(snapshot)
    assert verdict["status"] == "mismatch"
    assert all(not row["match"] for row in verdict["projections"].values())
    assert all(row["queue"]["record_count"] == 1 for row in verdict["projections"].values())


@pytest.mark.parametrize("damage", ["missing_member", "hash", "duplicate", "empty"])
def test_incomplete_or_ambiguous_input_fails_closed(snapshot, damage):
    if damage == "missing_member":
        snapshot["manifest"]["members"].pop()
    elif damage == "hash":
        snapshot["sources"][0]["payload_sha256"] = "c" * 64
    elif damage == "duplicate":
        snapshot["manifest"]["members"].append(snapshot["manifest"]["members"][0])
    else:
        snapshot["sources"] = []
    assert ad_jobs_parity.compare_snapshot(snapshot)["status"] == "error"


def test_partial_coverage_stays_partial(snapshot):
    snapshot["manifest"]["coverage_state"] = "partial"
    verdict = ad_jobs_parity.compare_snapshot(snapshot)
    assert verdict["status"] == "match"
    assert verdict["coverage_state"] == "partial"


def test_empty_payloads_are_valid_but_still_have_four_output_rows(snapshot):
    for source in snapshot["sources"]:
        source["payload_json"] = {"items": []}
    verdict = ad_jobs_parity.compare_snapshot(snapshot)
    assert verdict["status"] == "match"
    assert verdict["tables"]["ad_snapshot_projection_outputs"]["legacy"]["row_count"] == 4
    assert all(row["legacy"]["record_count"] == 0 for row in verdict["projections"].values())


def test_disabled_plugin_cannot_get_a_green_verdict(snapshot, monkeypatch):
    monkeypatch.setattr(ad_gpo_jobs, "allowed_plugins", lambda: frozenset({"sli.ad"}))
    assert ad_jobs_parity.compare_snapshot(snapshot)["status"] == "error"


def test_queue_record_budget_is_preserved(snapshot):
    snapshot["sources"][0]["payload_json"]["items"] = [{"id": "synthetic-1"}] * 50001
    assert ad_jobs_parity.compare_snapshot(snapshot)["status"] == "error"


def test_handler_metadata_drift_cannot_disclose_private_fields(snapshot, monkeypatch):
    original = ad_gpo_jobs.stage

    def changed(conn, job):
        result = original(conn, job)
        for row in result["projection_results"].values():
            row["output_identity"] = "synthetic-private-field"
            row["output_sha256"] = "synthetic-private-field"
            row["diagnostic"] = "synthetic-private-field"
        return result

    monkeypatch.setattr(ad_gpo_jobs, "stage", changed)
    verdict = ad_jobs_parity.compare_snapshot(snapshot)
    assert verdict["status"] == "mismatch"
    assert "synthetic-private-field" not in json.dumps(verdict)


def test_read_only_adapter_refuses_dml(snapshot):
    conn = ad_jobs_parity.SnapshotConnection(snapshot)
    with conn.cursor() as cur, pytest.raises(ValueError, match="parity_read_only"):
        cur.execute("delete from ad_snapshot_projection_outputs")


def test_cli_json_exit_codes_and_private_error_redaction(snapshot, tmp_path, capsys, monkeypatch):
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    assert ad_jobs_parity.main(["--snapshot", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "match"

    with monkeypatch.context() as scoped:
        original = ad_gpo_jobs.stage

        def drift(conn, job):
            result = original(conn, job)
            for row in result["projection_results"].values():
                row["output_sha256"] = "c" * 64
            return result

        scoped.setattr(ad_gpo_jobs, "stage", drift)
        assert ad_jobs_parity.main(["--snapshot", str(path)]) == 1
        assert json.loads(capsys.readouterr().out)["status"] == "mismatch"

    def broken(*_args, **_kwargs):
        print("synthetic-private-field")
        raise RuntimeError("synthetic-private-field")

    monkeypatch.setattr(ad_snapshot_projection, "_pure_project", broken)
    assert ad_jobs_parity.main(["--snapshot", str(path)]) == 2
    captured = capsys.readouterr()
    assert json.loads(captured.out)["status"] == "error"
    assert "synthetic-private-field" not in captured.out + captured.err
    path.write_text("invalid-json", encoding="utf-8")
    assert ad_jobs_parity.main(["--snapshot", str(path)]) == 2
    assert json.loads(capsys.readouterr().out)["error_code"] == "snapshot_read_failed"


@pytest.fixture
def pre_relocation():
    """Execute the frozen pre-PR6 source independently of compatibility aliases."""
    root = Path(__file__).resolve().parents[2]
    with gzip.open(root / "tests/fixtures/ad_jobs_pr6_baseline.json.gz", "rt", encoding="utf-8") as stream:
        sources = json.load(stream)

    def load(path):
        module = ModuleType("pr6_baseline_" + Path(path).stem)
        module.__file__ = str(root / path)
        exec(compile(sources[path], module.__file__, "exec"), module.__dict__)
        return module

    return load


@pytest.mark.parametrize("handler_id", [
    "ad-snapshot-manifest-coordinator", "ad-snapshot-projection", "users-report-v2-snapshot", "gpo-snapshot",
    "ad-context-snapshot", "computers-v6-source", "gpo-acquisition",
])
@pytest.mark.parametrize("coverage", ["complete", "partial"])
def test_registered_handlers_match_independent_pr6_baseline(pre_relocation, handler_id, coverage, monkeypatch):
    from server.sli.core import job_queue
    from server.sli.plugins.registry import plugin_job_handlers
    from tests.unit.test_ad_gpo_core_jobs import SnapshotConnection, job

    monkeypatch.delenv("SLI_PLUGIN_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("SLI_PLUGIN_LOCK_DIR", raising=False)
    previous = pre_relocation("server/sli/sources/ad_gpo_jobs.py")
    assert ad_gpo_jobs.registry().handlers == previous.registry().handlers
    old, candidate = SnapshotConnection(), SnapshotConnection()
    old.manifest["coverage_state"] = candidate.manifest["coverage_state"] = coverage
    spec = job(handler_id)
    stage, apply = plugin_job_handlers(spec["plugin_id"], handler_id)
    expected = previous.stage(old, spec)
    actual = stage(candidate, spec)
    assert actual == expected
    assert old.outputs == candidate.outputs == {}
    assert job_queue.publish(old, spec, expected, previous.apply) == "committed"
    assert job_queue.publish(candidate, spec, actual, apply) == "committed"
    assert candidate.outputs == old.outputs
    assert candidate.receipts == old.receipts
    assert candidate.calls == old.calls


@pytest.mark.parametrize("handler_id", ["ad-context-snapshot", "computers-v6-source", "gpo-acquisition"])
@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_registered_acquisition_preserves_exact_blocked_result(pre_relocation, handler_id, platform, monkeypatch):
    from server.sli.plugins.registry import plugin_job_handlers
    from tests.unit.test_ad_gpo_core_jobs import job

    previous = pre_relocation("server/sli/sources/ad_gpo_jobs.py")
    assert ad_gpo_jobs.registry().handlers == previous.registry().handlers
    monkeypatch.setattr(ad_gpo_jobs.sys, "platform", platform)
    spec = job(handler_id)
    stage, _ = plugin_job_handlers(spec["plugin_id"], handler_id)
    assert stage(None, spec) == previous.stage(None, spec)


@pytest.mark.parametrize("plugin_id,profile", [("sli.ad", "heavy"), ("sli.gpo", "long")])
def test_schedule_specs_match_frozen_pin_scope_budget_and_keys(pre_relocation, plugin_id, profile, monkeypatch):
    from datetime import datetime, timezone

    from server.sli.core import job_registry
    from tests.unit.test_ad_gpo_core_jobs import MANIFEST_ID
    from tests.unit.test_core_job_queue import Connection

    previous = pre_relocation("server/sli/core/job_registry.py")
    source = {"plugin_id": plugin_id, "source_instance_id": "ad-domain:1", "domain_id": 1,
              "manifest_id": MANIFEST_ID, "snapshot_sha256": "a" * 64,
              "revision": "1", "access_scope": {"mode": "restricted"}}
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    old, candidate = [], []
    monkeypatch.setattr(previous, "enqueue", lambda _cur, spec: old.append(spec))
    monkeypatch.setattr(job_registry, "enqueue", lambda _cur, spec: candidate.append(spec))
    previous.schedule_jobs(Connection([now]), ad_gpo_jobs.registry(), profile, source)
    job_registry.schedule_jobs(Connection([now]), ad_gpo_jobs.registry(), profile, source)
    assert candidate == old
    assert candidate
    assert {spec["partition_key"] for spec in candidate} == {"ad-snapshot"}


def test_missing_gpo_part_and_disabled_ad_keep_old_result(pre_relocation, monkeypatch):
    from server.sli.plugins.registry import plugin_job_handlers
    from tests.unit.test_ad_gpo_core_jobs import SnapshotConnection, job

    previous = pre_relocation("server/sli/sources/ad_gpo_jobs.py")
    assert ad_gpo_jobs.registry().handlers == previous.registry().handlers
    monkeypatch.setattr(previous, "allowed_plugins", lambda: frozenset({"sli.gpo"}))
    monkeypatch.setattr(ad_gpo_jobs, "allowed_plugins", lambda: frozenset({"sli.gpo"}))
    spec = job("gpo-snapshot")
    stage, _ = plugin_job_handlers("sli.gpo", "gpo-snapshot")
    conn = SnapshotConnection()
    assert stage(conn, spec) == previous.stage(conn, spec)
    assert stage(conn, spec)["status"] == "success"
    conn.manifest["members"] = [row for row in conn.manifest["members"] if row["family"] != "gpo_v2"]
    assert stage(conn, spec) == previous.stage(conn, spec)
    assert stage(conn, spec)["error_code"] == "snapshot_part_not_collected"
    assert conn.outputs == {}


def test_retention_history_and_readers_remain_identical_with_acquisition_off(pre_relocation, monkeypatch):
    from datetime import datetime, timezone

    from server.sli.plugins.ad.snapshots import change_history, history_policy, retention
    from server.sli.sources import ad_snapshot_history_policy, ad_snapshot_retention
    from server.sli.storage import ad_snapshot_change_history

    monkeypatch.delenv(ad_gpo_jobs.FLAG, raising=False)
    assert ad_snapshot_change_history is change_history
    assert ad_snapshot_history_policy is history_policy
    assert ad_snapshot_retention is retention
    old = pre_relocation("server/sli/sources/ad_snapshot_retention.py")
    now = datetime(2026, 1, 8, tzinfo=timezone.utc)
    inventory = {relation: {"candidate_count": 3, "root_mapping_proven": True,
                           "anchor_proven": True, "owner_admitted": True, "shared_source": False,
                           "dependency_state": "safe", "whole_unit_admitted": True}
                 for relation in retention.REQUIRED_AD_RETENTION_RELATIONS}
    for values in (None, inventory):
        for due in (True, False):
            assert retention.plan_ad_snapshot_retention(now=now, inventory=values, due=due) == (
                old.plan_ad_snapshot_retention(now=now, inventory=values, due=due))
    old_history = pre_relocation("server/sli/storage/ad_snapshot_change_history.py")
    before = {"metadata": {"collection_status": "complete"},
              "users": [{"id": "synthetic-1", "enabled": True}], "groups": []}
    after = deepcopy(before)
    after["users"][0]["enabled"] = False
    assert change_history.extract_changes("users_v2", before, after) == old_history.extract_changes("users_v2", before, after)
    assert change_history.SCHEMA == old_history.SCHEMA
    statements = []
    monkeypatch.setattr(change_history.ch, "_http_query", lambda port, sql: statements.append(sql))
    old_history.ensure_schema(8123)
    expected = statements[:]
    statements.clear()
    change_history.ensure_schema(8123)
    assert statements == expected


@pytest.mark.parametrize("resolution", ["direct", "alias", "ambiguous", "absent"])
def test_entity_provider_preserves_exact_bounded_context_dto(pre_relocation, resolution, monkeypatch):
    from server.sli.plugins import registry
    from server.sli.plugins.ad.context import integration
    from tests.unit.test_ad_snapshot_plugin_libraries import _restore_entity_context_lookup_sql

    monkeypatch.delenv(ad_gpo_jobs.FLAG, raising=False)
    monkeypatch.delenv("SLI_PLUGIN_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("SLI_PLUGIN_LOCK_DIR", raising=False)
    old = pre_relocation("server/sli/plugins/ad/context/integration.py")
    evidence = {
        "context_evidence_id": 1, "evidence_type": "entity_observation",
        "source_pack_id": "sli.windows.ad-context", "source_run_id": "synthetic-run",
        "integrity_sha256": "a" * 64, "context_kind": "entity",
        "subject_entity_id": 42 if resolution == "direct" else 7, "source_section": "base",
        "attributes_json": {}, "valid_to_utc": None,
    }
    first = [evidence] if resolution == "direct" else []
    runtime = [] if resolution == "absent" else [
        {"id": 42, "domain_id": 1, "natural_key": "synthetic", "display_name": "synthetic",
         "attributes_json": {"sid": "S-1-5-21-1-2-3-42"}}]
    aliases = [{"entity_id": 7}] if resolution == "alias" else [{"entity_id": 7}, {"entity_id": 8}]

    def reader():
        calls = []
        responses = iter([first, runtime, aliases, [evidence]])

        def query(sql, params, **kwargs):
            calls.append((sql, params, kwargs))
            return deepcopy(next(responses))

        return query, calls

    query, expected_calls = reader()
    monkeypatch.setattr(old, "query_rows_bounded", query)
    expected = old.get_runtime_entity_context_evidence(42, limit=999)
    query, calls = reader()
    monkeypatch.setattr(integration, "query_rows_bounded", query)
    actual = registry.call_plugin("sli.ad", "get_runtime_entity_context_evidence", 42, limit=999)
    assert actual == expected
    # Permit only the exact history/participant lookup optimization, preserving the
    # frozen SQL reference, query order, parameters and timeout budgets.
    restored_calls = [
        (_restore_entity_context_lookup_sql(sql) if "from ad_context_entity_versions where" in sql else sql,
         params, kwargs)
        for sql, params, kwargs in calls
    ]
    assert restored_calls == expected_calls
    assert actual["bounded"] is True
    assert not actual.get("absence_closes_state", False)


def test_history_generation_keeps_core_schema_path(tmp_path):
    from server.sli.plugins.ad.snapshots import change_history

    relocated = ModuleType("pr6_relocated_history")
    relocated.__file__ = str(tmp_path / "versions" / ("a" * 64) / "backend/snapshots/change_history.py")
    source = Path(change_history.__file__).read_text("utf-8")
    exec(compile(source, relocated.__file__, "exec"), relocated.__dict__)
    assert relocated.SCHEMA == change_history.SCHEMA
    assert relocated.SCHEMA.is_file()
