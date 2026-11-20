from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pytest

from server.sli.storage.operations_storage import (
    SNAPSHOT_SCHEMA,
    load_operations_storage_snapshot,
)


def test_runtime_inventory_measures_direct_raw_batches_and_oldest_timestamp(tmp_path) -> None:
    from server.sli.storage.runtime_storage import get_runtime_storage_summary

    raw = tmp_path / "data" / "raw" / "pilot"
    old_batch = raw / "batch-old"
    new_batch = raw / "batch-new"
    old_batch.mkdir(parents=True)
    new_batch.mkdir()
    (old_batch / "Security.jsonl").write_bytes(b"x" * 7)
    (new_batch / "System.jsonl").write_bytes(b"x" * 5)
    old_timestamp = datetime(2026, 8, 30, 10, 0, tzinfo=timezone.utc).timestamp()
    new_timestamp = datetime(2026, 8, 31, 10, 0, tzinfo=timezone.utc).timestamp()
    os.utime(old_batch, (old_timestamp, old_timestamp))
    os.utime(new_batch, (new_timestamp, new_timestamp))

    result = get_runtime_storage_summary(tmp_path)

    assert result["raw_spool"]["status"] == "ok"
    assert result["raw_spool"]["bytes"] == 12
    assert result["raw_spool"]["batch_count"] == 2
    assert result["raw_spool"]["oldest_batch_at_utc"] == "2026-08-30T10:00:00+00:00"
    assert result["raw_spool"]["scan"]["complete"] is True
    assert result["raw_spool"]["thresholds"]["bytes_warning"] == 500 * 1024 * 1024


def test_runtime_inventory_missing_raw_spool_is_unavailable_not_zero(tmp_path) -> None:
    from server.sli.storage.runtime_storage import get_runtime_storage_summary

    result = get_runtime_storage_summary(tmp_path)

    assert result["raw_spool"]["status"] == "unavailable"
    assert result["raw_spool"]["bytes"] is None
    assert result["raw_spool"]["batch_count"] is None
    assert result["raw_spool"]["oldest_batch_at_utc"] is None
    assert result["raw_spool"]["scan"]["complete"] is False


def test_reader_rejects_wrong_schema_without_starting_measurement(tmp_path) -> None:
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps({"schema": "wrong", "components": []}), encoding="utf-8")

    result = load_operations_storage_snapshot(path)

    assert result["status"] == "unavailable"
    assert result["components"] == []
    assert result["snapshot"]["available"] is False


def test_reader_adds_freshness_to_valid_snapshot(tmp_path, monkeypatch) -> None:
    from server.sli.storage import operations_storage

    path = tmp_path / "snapshot.json"
    path.write_text(
        json.dumps(
            {
                "schema": SNAPSHOT_SCHEMA,
                "status": "ok",
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "components": [{"key": "project_root", "bytes": 10}],
                "totals": {"accounted_bytes": 10},
                "raw_spool": {
                    "status": "ok", "bytes": 10, "batch_count": 1,
                    "oldest_batch_at_utc": "2026-08-30T10:00:00+00:00",
                    "oldest_batch_age_seconds": 10,
                    "scan": {"complete": True, "errors": 0},
                    "thresholds": {"bytes_warning": 1, "bytes_critical": 2,
                                   "batch_count_warning": 1, "oldest_age_warning_seconds": 1},
                },
                "warnings": [],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(operations_storage, "_max_age_seconds", lambda: 3600)

    result = load_operations_storage_snapshot(path)

    assert result["status"] == "ok"
    assert result["snapshot"]["available"] is True
    assert result["snapshot"]["stale"] is False
    assert result["snapshot"]["age_seconds"] is not None


def test_reader_rejects_snapshot_that_turns_unavailable_raw_spool_into_zero(tmp_path) -> None:
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps({
        "schema": SNAPSHOT_SCHEMA,
        "status": "ok",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "components": [],
        "totals": {},
        "raw_spool": {
            "status": "unavailable", "bytes": 0, "batch_count": 0,
            "oldest_batch_at_utc": None, "oldest_batch_age_seconds": None,
            "scan": {"complete": False, "errors": 1}, "thresholds": {},
        },
    }), encoding="utf-8")

    result = load_operations_storage_snapshot(path)

    assert result["status"] == "unavailable"
    assert result["raw_spool"]["bytes"] is None


def test_reader_keeps_other_footprint_visible_when_raw_spool_is_honestly_unavailable(tmp_path) -> None:
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps({
        "schema": SNAPSHOT_SCHEMA,
        "status": "partial",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "components": [{"key": "project_root", "bytes": 10}],
        "totals": {"accounted_bytes": 10},
        "warnings": ["RAW spool is unavailable."],
        "raw_spool": {
            "status": "unavailable", "bytes": None, "human": None, "batch_count": None,
            "oldest_batch_at_utc": None, "oldest_batch_age_seconds": None,
            "scan": {"complete": False, "errors": 1},
            "thresholds": {"bytes_warning": 524288000, "bytes_critical": 1073741824,
                           "batch_count_warning": 1000, "oldest_age_warning_seconds": 172800},
        },
    }), encoding="utf-8")

    result = load_operations_storage_snapshot(path)

    assert result["status"] == "partial"
    assert result["totals"]["accounted_bytes"] == 10
    assert result["raw_spool"]["status"] == "unavailable"
    assert result["raw_spool"]["bytes"] is None


def test_producer_total_excludes_nested_rows_and_shared_images(tmp_path, monkeypatch) -> None:
    from scripts.maintenance import operations_storage_snapshot as producer

    sizes = {
        "project": {"bytes": 1000},
        "data": {"bytes": 500},
        "storage_v2_archives": {"bytes": 300},
        "backups": {"bytes": 100},
        "artifacts": {"bytes": 50},
        "venv": {"bytes": 200},
        "frontend_node_modules": {"bytes": 150},
    }
    monkeypatch.setattr(
        producer,
        "get_runtime_storage_summary",
        lambda root: {
            "sizes": sizes,
            "scan": {"complete_project_tree": True},
            "raw_spool": {
                "status": "partial", "bytes": 12, "batch_count": 2,
                "oldest_batch_at_utc": "2026-08-30T10:00:00+00:00",
                "scan": {"complete": False, "errors": 1},
                "thresholds": {"bytes_warning": 10, "bytes_critical": 20,
                               "batch_count_warning": 1000, "oldest_age_warning_seconds": 172800},
            },
        },
    )
    monkeypatch.setattr(
        producer,
        "get_postgres_operations_status",
        lambda table_limit: {
            "available": True,
            "status": "ok",
            "database": {"database_bytes": 400, "database_human": "400 Б"},
        },
    )
    monkeypatch.setattr(
        producer,
        "_clickhouse",
        lambda container: {
            "status": "ok",
            "volume_bytes": 600,
            "active_parts_bytes": 450,
            "method": "test",
            "databases": [],
        },
    )
    monkeypatch.setattr(producer, "_image_size", lambda image: {"image": image, "status": "ok", "bytes": 700})
    monkeypatch.setattr(
        producer,
        "disk_info",
        lambda root: {"total_bytes": 10_000, "free_bytes": 5_000, "free_percent": 50},
    )
    external = tmp_path / "external"
    evidence = tmp_path / "evidence"
    external.mkdir()
    evidence.mkdir()
    (external / "archive.bin").write_bytes(b"x" * 200)
    (evidence / "raw.bin").write_bytes(b"x" * 300)

    result = producer.build_snapshot(external_archive=external, evidence_root=evidence)

    assert result["totals"]["accounted_bytes"] == 2500
    assert result["totals"]["known_physical_bytes"] == 2100
    assert result["totals"]["docker_images_raw_sum_bytes"] == 2100
    assert result["totals"]["docker_images_included"] is False
    included = {item["key"] for item in result["components"] if item["included_in_accounted_total"]}
    assert included == {"project_root", "external_archive", "evidence_root", "postgres_database", "clickhouse_volume"}
    assert sum(1 for item in result["components"] if item["key"].startswith("docker_image:")) == 3
    assert result["raw_spool"]["status"] == "partial"
    assert isinstance(result["raw_spool"]["oldest_batch_age_seconds"], int)
    assert any("RAW spool scan is incomplete" in item for item in result["warnings"])


def test_writer_serializes_postgres_datetime_atomically(tmp_path) -> None:
    from scripts.maintenance.operations_storage_snapshot import _write_atomic

    path = tmp_path / "latest.json"
    _write_atomic(path, {"checked_at": datetime(2026, 8, 2, 1, 2, 3, tzinfo=timezone.utc)})

    assert json.loads(path.read_text(encoding="utf-8"))["checked_at"] == "2026-08-02T01:02:03+00:00"
    assert not path.with_suffix(".json.tmp").exists()


def test_producer_with_platform_deps_and_physical_postgres(tmp_path, monkeypatch) -> None:
    from scripts.maintenance import operations_storage_snapshot as producer

    monkeypatch.setattr(
        producer,
        "get_runtime_storage_summary",
        lambda root: {
            "sizes": {"project": {"bytes": 1000}, "data": {"bytes": 100}},
            "scan": {"complete_project_tree": True},
            "raw_spool": {"status": "ok", "scan": {"complete": True}, "bytes": 50, "batch_count": 1, "oldest_batch_at_utc": "2026-09-01T00:00:00Z"},
        },
    )
    monkeypatch.setattr(
        producer,
        "get_postgres_operations_status",
        lambda table_limit: {
            "available": True,
            "status": "ok",
            "database": {"database_bytes": 400, "database_human": "400 Б"},
        },
    )
    monkeypatch.setattr(
        producer,
        "_clickhouse",
        lambda container: {
            "status": "ok",
            "volume_bytes": 600,
            "volume_name": f"{container}-data",
            "active_parts_bytes": 450,
            "method": "test",
            "databases": [],
        },
    )
    monkeypatch.setattr(producer, "_image_size", lambda image: {"image": image, "status": "ok", "bytes": 700})
    monkeypatch.setattr(
        producer,
        "disk_info",
        lambda root: {"total_bytes": 100_000, "free_bytes": 50_000, "free_percent": 50},
    )

    external = tmp_path / "external"
    evidence = tmp_path / "evidence"
    deps = tmp_path / "deps"
    docker_data = deps / "docker-data"
    pg_data = tmp_path / "pg_data"
    pg_bin = tmp_path / "pg_bin"
    sli_data = tmp_path / "sli_data"
    sli_runtime = sli_data / "runtime"
    pnpm_store = tmp_path / "pnpm_store"

    for d in (external, evidence, deps, docker_data, pg_data, pg_bin, sli_data, sli_runtime, pnpm_store):
        d.mkdir(parents=True, exist_ok=True)

    (external / "archive.bin").write_bytes(b"x" * 200)
    (evidence / "raw.bin").write_bytes(b"x" * 300)
    (docker_data / "ext4.vhdx").write_bytes(b"x" * 5000)
    (pg_data / "base.bin").write_bytes(b"x" * 3000)
    (pg_bin / "postgres.exe").write_bytes(b"x" * 1500)
    (sli_runtime / "secrets.bin").write_bytes(b"x" * 250)
    (pnpm_store / "pkg.tar").write_bytes(b"x" * 800)

    result = producer.build_snapshot(
        external_archive=external,
        evidence_root=evidence,
        platform_deps=deps,
        postgres_data=pg_data,
        postgres_bin=pg_bin,
        sli_data_dir=sli_data,
        pnpm_store_dir=pnpm_store,
        clickhouse_history_container="sli-history",
    )

    included_keys = {item["key"] for item in result["components"] if item["included_in_accounted_total"]}
    # Top-level standalone components must be included
    expected_included = {
        "project_root",
        "external_archive",
        "evidence_root",
        "platform_dependencies",
        "postgres_physical_cluster",
        "postgres_server_install",
        "sli_data_root",
        "pnpm_store",
    }
    assert included_keys == expected_included

    # Child components must have parent set and included_in_accounted_total=False
    comp_map = {item["key"]: item for item in result["components"]}
    assert comp_map["postgres_database"]["included_in_accounted_total"] is False
    assert comp_map["postgres_database"]["parent"] == "postgres_physical_cluster"

    assert comp_map["clickhouse_volume"]["included_in_accounted_total"] is False
    assert comp_map["clickhouse_volume"]["parent"] == "deps_docker_data"

    assert comp_map["clickhouse_volume_history"]["included_in_accounted_total"] is False
    assert comp_map["clickhouse_volume_history"]["parent"] == "deps_docker_data"

    assert comp_map["sli_data_runtime"]["included_in_accounted_total"] is False
    assert comp_map["sli_data_runtime"]["parent"] == "sli_data_root"

    assert result["totals"]["accounting_quality"] == "measured"
    assert result["totals"]["postgres_proxy_included"] is False



def _history_snapshot(tmp_path, monkeypatch, *, failure=None, history='sli-history',
                      include_docker=True, with_deps=False):
    from scripts.maintenance import operations_storage_snapshot as producer

    monkeypatch.setenv('ADLOG_PG_DSN', 'synthetic-test-dsn')
    monkeypatch.setattr(producer, 'get_runtime_storage_summary', lambda root: {
        'sizes': {'project': {'bytes': 100}}, 'scan': {'complete_project_tree': True},
        'raw_spool': {'status': 'ok', 'bytes': 0, 'batch_count': 0,
                      'scan': {'complete': True},
                      'thresholds': {'bytes_warning': 100, 'bytes_critical': 200,
                                     'batch_count_warning': 100}},
    })
    monkeypatch.setattr(producer, 'get_postgres_operations_status', lambda **kw: {
        'available': True, 'database': {'database_bytes': 10}})
    monkeypatch.setattr(producer, '_image_size', lambda image: {'image': image, 'bytes': 0})
    monkeypatch.setattr(producer, 'disk_info', lambda root: {})
    monkeypatch.setattr(producer.subprocess, 'run', lambda *a, **kw: pytest.fail('process invoked'))
    calls = []

    def docker(argv, **kwargs):
        calls.append(argv)
        if argv[1] == 'sli-history' and argv[0] == failure:
            raise RuntimeError('credential=do-not-expose')
        if argv[0] == 'inspect':
            return json.dumps([{'State': {'Running': True}, 'Mounts': []}])
        if 'du' in argv:
            if failure == 'du' and argv[1] == 'sli-history':
                raise RuntimeError('credential=do-not-expose')
            return '600 /var/lib/clickhouse'
        if failure == 'query' and argv[1] == 'sli-history':
            raise RuntimeError('credential=do-not-expose')
        return '{"database":"synthetic","bytes":450}'

    monkeypatch.setattr(producer, '_docker', docker)
    pg = tmp_path / 'pg'
    pg.mkdir()
    (pg / 'data').write_bytes(b'x' * 10)
    deps = tmp_path / 'deps'
    if with_deps:
        deps.mkdir()
    result = producer.build_snapshot(external_archive=tmp_path / 'missing-external',
                                     evidence_root=tmp_path / 'missing-evidence',
                                     postgres_data=pg, platform_deps=deps if with_deps else None,
                                     clickhouse_history_container=history,
                                     include_docker=include_docker)
    return result, calls


@pytest.mark.parametrize('failure', ['inspect', 'du', 'query'])
@pytest.mark.parametrize('with_deps', [False, True])
def test_requested_history_probe_failure_remains_unknown(tmp_path, monkeypatch, failure, with_deps):
    result, _ = _history_snapshot(tmp_path, monkeypatch, failure=failure, with_deps=with_deps)
    components = {row['key']: row for row in result['components']}
    for key in ('clickhouse_volume_history', 'clickhouse_active_parts_history'):
        assert key in components
        assert components[key]['status'] == 'unavailable'
        assert components[key]['bytes'] is None
        assert components[key]['human'] is None
        assert components[key]['included_in_accounted_total'] is False
    assert result['status'] == 'partial'
    assert result['totals']['accounting_quality'] == 'partial'
    assert result['totals']['accounted_bytes'] == (110 if with_deps else 710)
    assert any('history' in warning.lower() for warning in result['warnings'])
    assert 'do-not-expose' not in json.dumps(result)


@pytest.mark.parametrize('history,include_docker', [(None, True), ('', True),
                                                   ('sli-warm-tier-step1', True), ('sli-history', False)])
def test_unconfigured_shared_or_skipped_history_is_not_failed(tmp_path, monkeypatch, history, include_docker):
    result, calls = _history_snapshot(tmp_path, monkeypatch, history=history, include_docker=include_docker)
    assert result['status'] == 'ok'
    assert result['totals']['accounting_quality'] == 'measured'
    assert not any(row['key'] == 'clickhouse_volume_history' for row in result['components'])
    assert not any('sli-history' in argv for argv in calls)


def test_successful_distinct_history_is_counted_once(tmp_path, monkeypatch):
    result, _ = _history_snapshot(tmp_path, monkeypatch)
    assert result['status'] == 'ok'
    assert result['totals']['accounting_quality'] == 'measured'
    assert result['totals']['accounted_bytes'] == 1310
    history = next(row for row in result['components'] if row['key'] == 'clickhouse_volume_history')
    assert history['bytes'] == 600
    assert history['included_in_accounted_total'] is True
