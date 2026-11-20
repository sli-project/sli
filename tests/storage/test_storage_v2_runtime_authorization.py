from datetime import datetime, timedelta, timezone
import importlib
import inspect
import re

import pytest

from server.sli.storage.storage_v2_transition_controller import issue_controller_authorization
from server.sli.storage import storage_v2_runtime_authorization as runtime_auth
from server.sli.storage import runtime_storage
from server.sli.storage.runtime_storage import (
    resolve_storage_route,
    StorageRouteConsumer,
)

importer = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")


def test_link_hydration_uses_manifest_without_a_configured_root(monkeypatch, tmp_path):
    from server.sli.entities import entity_details
    from server.sli.storage.storage_v2_archive import ArchivePublisher, InMemoryArchiveManifestStore

    manifest = InMemoryArchiveManifestStore()
    row = {"event_id": 10, "entity_id": 1, "link_role": "actor", "role_id": 2}
    ArchivePublisher(tmp_path.resolve(), manifest).publish_rows(
        archive_set_id="00000000-0000-4000-8000-000000000002",
        archive_kind="link_detail", block_index=0, event_id_field="event_id",
        rows=[row],
    )
    monkeypatch.setattr(entity_details, "PostgresArchiveManifestStore", lambda _connect: manifest)
    assert entity_details._read_v2_link_details([10], None) == {10: [row]}


def _authorization():
    return issue_controller_authorization("a" * 64)


class Cursor:
    def __init__(self, row=None):
        self.row = row
        self.calls = []

    def execute(self, sql, params=()):
        self.calls.append((" ".join(sql.lower().split()), params))

    def fetchone(self):
        return self.row


class Connection:
    def __init__(self, cursor):
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def cursor(self):
        cursor = self._cursor

        class CursorContext:
            def __enter__(self):
                return cursor

            def __exit__(self, *_args):
                return False

        return CursorContext()


def test_optional_loader_reads_persisted_authority_only_when_migration91_exists(monkeypatch) -> None:
    missing = Cursor({"available": False})
    monkeypatch.setattr(
        runtime_auth, "load_runtime_authorization",
        lambda _cur: (_ for _ in ()).throw(AssertionError("missing table must not be read")),
    )
    assert runtime_auth.load_runtime_authorization_if_available(
        lambda: Connection(missing)
    ) is None

    persisted = object()
    available = Cursor({"available": True})
    monkeypatch.setattr(runtime_auth, "load_runtime_authorization", lambda cur: persisted)
    assert runtime_auth.load_runtime_authorization_if_available(
        lambda: Connection(available)
    ) is persisted


def test_persisted_runtime_authorization_round_trips_and_is_tamper_evident(tmp_path) -> None:
    issued = datetime(2026, 8, 26, tzinfo=timezone.utc)
    expires = issued + timedelta(hours=24)
    cur = Cursor()

    persisted = runtime_auth.persist_runtime_authorization(
        cur,
        authorization=_authorization(),
        route="v2_primary_compat",
        archive_root=tmp_path,
        evidence={"backup_restore_verified": True},
        authorized_by="owner",
        issued_at=issued,
        expires_at=expires,
    )

    assert persisted.route == "v2_primary_compat"
    assert runtime_auth.is_persisted_runtime_authorization(persisted)
    assert "insert into storage_v2_runtime_authorizations" in cur.calls[-1][0]

    row = persisted.as_record()
    loaded = runtime_auth.load_runtime_authorization(Cursor(row), now=issued + timedelta(hours=1))
    assert loaded == persisted

    tampered = dict(row, archive_root=str(tmp_path / "tampered"))
    with pytest.raises(RuntimeError, match="digest mismatch"):
        runtime_auth.load_runtime_authorization(Cursor(tampered), now=issued + timedelta(hours=1))


def test_runtime_authorization_rejects_expired_or_revoked_rows(tmp_path) -> None:
    issued = datetime(2026, 8, 26, tzinfo=timezone.utc)
    persisted = runtime_auth.persist_runtime_authorization(
        Cursor(), authorization=_authorization(), route="v2", archive_root=tmp_path,
        evidence={}, authorized_by="owner", issued_at=issued,
        expires_at=issued + timedelta(hours=1),
    )

    with pytest.raises(RuntimeError, match="expired"):
        runtime_auth.load_runtime_authorization(Cursor(persisted.as_record()), now=issued + timedelta(hours=2))

    revoked = dict(persisted.as_record(), revoked_at=issued + timedelta(minutes=1))
    with pytest.raises(RuntimeError, match="revoked"):
        runtime_auth.load_runtime_authorization(Cursor(revoked), now=issued + timedelta(minutes=2))


def test_import_runtime_factory_refuses_the_v1_compatibility_route(tmp_path) -> None:
    issued = datetime(2026, 8, 26, tzinfo=timezone.utc)
    persisted = runtime_auth.persist_runtime_authorization(
        Cursor(), authorization=_authorization(), route="v2_primary_compat",
        archive_root=tmp_path, evidence={}, authorized_by="owner", issued_at=issued,
        expires_at=issued + timedelta(hours=1),
    )

    with pytest.raises(RuntimeError, match="unsupported authorized direct route"):
        importer.authorized_direct_import_runtime(
            authorization=persisted,
            repository=object(),
            publisher=object(),
            connect_factory=lambda: object(),
            normalized_at=issued.isoformat(),
        )


def test_runtime_router_accepts_only_sealed_persisted_authority(tmp_path) -> None:
    issued = datetime.now(timezone.utc)
    persisted = runtime_auth.persist_runtime_authorization(
        Cursor(), authorization=_authorization(), route="v2_primary_compat",
        archive_root=tmp_path, evidence={}, authorized_by="owner", issued_at=issued,
        expires_at=issued + timedelta(hours=1),
    )

    route = resolve_storage_route(
        authorization=persisted,
        consumer=StorageRouteConsumer.EVENTS,
    )

    assert route["route"] == "v2"
    assert route["authorization"] == "persisted-controller"
    assert runtime_storage.validate_storage_route_authorization(persisted) is persisted
    with pytest.raises(Exception, match="storage_transition_authorization_invalid"):
        runtime_storage.validate_storage_route_authorization(object())


@pytest.mark.parametrize("missing_directory", [False, True])
def test_database_loader_builds_one_direct_runtime_from_persisted_authority(monkeypatch, tmp_path, missing_directory) -> None:
    if missing_directory:
        tmp_path = tmp_path / "missing"
    issued = datetime(2026, 8, 26, tzinfo=timezone.utc)
    persisted = runtime_auth.persist_runtime_authorization(
        Cursor(), authorization=_authorization(), route="v2",
        archive_root=tmp_path, evidence={}, authorized_by="owner", issued_at=issued,
        expires_at=issued + timedelta(hours=1),
    )
    repository = object()
    manifest = object()
    publisher = object()
    semantic_publisher = object()
    repository_args = []
    connect_factory = object()
    monkeypatch.setattr(importer, "load_runtime_authorization", lambda _cur: persisted, raising=False)
    monkeypatch.setattr(
        importer,
        "semantic_publisher_for_runtime",
        lambda: semantic_publisher,
        raising=False,
    )

    def build_repository(connect, *, semantic_publisher=None):
        repository_args.append((connect, semantic_publisher))
        return repository

    monkeypatch.setattr(
        importer, "PostgresStorageV2Repository",
        build_repository,
        raising=False,
    )
    monkeypatch.setattr(
        importer, "PostgresArchiveManifestStore",
        lambda connect: manifest if connect is connect_factory else None,
        raising=False,
    )
    monkeypatch.setattr(
        importer, "ArchivePublisher",
        lambda archive_root, value: publisher
        if archive_root == tmp_path.resolve() and value is manifest else None,
        raising=False,
    )

    runtime = importer.load_authorized_direct_runtime(
        Cursor({"available": True}), connect_factory=connect_factory,
    )

    assert runtime.repository is repository
    assert runtime.publisher is publisher
    assert runtime.route == "v2"
    assert runtime.compatibility_mirror is None
    assert repository_args == [(connect_factory, semantic_publisher)]


def test_database_loader_preserves_v1_when_migration91_is_not_applied(monkeypatch) -> None:
    monkeypatch.setattr(
        importer, "load_runtime_authorization",
        lambda _cur: (_ for _ in ()).throw(AssertionError("missing table must not be read")),
    )

    assert importer.load_authorized_direct_runtime(
        Cursor({"available": False}), connect_factory=object(),
    ) is None


def test_agent_runtime_does_not_require_cancelled_archive(monkeypatch, tmp_path) -> None:
    issued = datetime(2026, 8, 26, tzinfo=timezone.utc)
    persisted = runtime_auth.persist_runtime_authorization(
        Cursor(), authorization=_authorization(), route="v2",
        archive_root=tmp_path / "absent", evidence={}, authorized_by="fixture-owner", issued_at=issued,
        expires_at=issued + timedelta(hours=1),
    )
    repository = object()
    monkeypatch.setattr(importer, "load_runtime_authorization", lambda _cur: persisted)
    monkeypatch.setattr(importer, "semantic_publisher_for_runtime", lambda: None)
    monkeypatch.setattr(importer, "PostgresStorageV2Repository", lambda *_args, **_kw: repository)

    def forbidden(*_args, **_kw):
        pytest.fail("agent publication must not require archive files or manifests")

    monkeypatch.setattr(importer, "ArchivePublisher", forbidden)
    monkeypatch.setattr(importer, "PostgresArchiveManifestStore", forbidden)
    runtime = importer.load_authorized_direct_runtime(
        Cursor({"available": True}), connect_factory=object(), publish_archive=False)
    assert importer.is_authorized_direct_runtime(runtime)
    assert runtime.repository is repository
    assert runtime.publisher is None


def test_agent_runtime_requires_persisted_authority_without_archive(monkeypatch) -> None:
    monkeypatch.setattr(importer, "load_runtime_authorization", lambda _cur: None)
    assert importer.load_authorized_direct_runtime(
        Cursor({"available": True}), connect_factory=object(), publish_archive=False) is None


def test_importer_main_loads_and_passes_persisted_direct_runtime() -> None:
    source = inspect.getsource(importer.main)

    assert "load_authorized_direct_runtime(" in source
    assert "connect_factory=connect_storage_v2_worker" in source
    assert "direct_runtime=direct_runtime" in source
    assert "commit_direct_metadata=conn.commit" in source


def test_web_cli_loads_and_passes_persisted_route_authorization(monkeypatch) -> None:
    web_cli = importlib.import_module("scripts.run_server")
    authorization = object()
    calls = []
    monkeypatch.setattr(
        web_cli, "_load_storage_route_authorization", lambda: authorization,
        raising=False,
    )
    monkeypatch.setattr(
        web_cli, "run_server",
        lambda host, port, *, storage_route_authorization=None: calls.append(
            (host, port, storage_route_authorization)
        ),
    )
    monkeypatch.setattr("sys.argv", ["run_server.py", "--host", "127.0.0.1", "--port", "18080"])
    # Without a DSN main() loads the protected runtime environment into this
    # process (production DSN, storage read mode); a test must never do that.
    monkeypatch.setenv("ADLOG_PG_DSN", "postgresql://test.invalid/none")

    assert web_cli.main() == 0
    assert calls == [("127.0.0.1", 18080, authorization)]


def test_database_summaries_execute_only_v2_sql_under_persisted_route(monkeypatch, tmp_path) -> None:
    database = importlib.import_module("server.sli.core.database")
    issued = datetime.now(timezone.utc)
    authorization = runtime_auth.persist_runtime_authorization(
        Cursor(), authorization=_authorization(), route="v2_primary_compat",
        archive_root=tmp_path, evidence={}, authorized_by="owner", issued_at=issued,
        expires_at=issued + timedelta(hours=1),
    )
    statements = []

    def query_rows(sql, params=()):
        normalized = " ".join(sql.lower().split())
        statements.append(normalized)
        return [{"count": 0}] if normalized.startswith("select count(*) as count from") else []

    monkeypatch.setattr(database, "query_rows", query_rows)
    monkeypatch.setattr(database, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(database, "_configured_domain_controllers", lambda: [])
    monkeypatch.setattr(database, "_security_24h_summary", lambda *_args, **_kwargs: {"important_total": 0})

    event_summary = database.get_event_summary(authorization=authorization)
    entity_summary = database.get_entity_summary(authorization=authorization)

    combined = "\n".join(statements)
    assert event_summary["total_events"] == 0
    assert entity_summary["total_entities"] == 0
    assert "events_v2_core" in combined
    assert "entities_v2" in combined
    assert "event_entity_links_v2" in combined
    assert "storage_v2_role" in combined
    assert "storage_v2_link_role" not in combined
    assert re.search(r"\bfrom events\b|\bjoin events\b", combined) is None
    assert "observed_entities" not in combined
    assert re.search(r"\bevent_entity_links\b(?!_v2)", combined) is None


def test_security_monitor_uses_v2_core_instead_of_unavailable_or_v1(monkeypatch, tmp_path) -> None:
    monitor = importlib.import_module("server.sli.events.security_events_monitor")
    issued = datetime.now(timezone.utc)
    authorization = runtime_auth.persist_runtime_authorization(
        Cursor(), authorization=_authorization(), route="v2_primary_compat",
        archive_root=tmp_path, evidence={}, authorized_by="owner", issued_at=issued,
        expires_at=issued + timedelta(hours=1),
    )
    statements = []

    def query_rows(sql, params=()):
        statements.append(" ".join(sql.lower().split()))
        return []

    monkeypatch.setattr(monitor, "query_rows", query_rows)
    data = monitor.get_security_events_monitor_data(
        authorization=authorization, limit=5,
    )

    combined = "\n".join(statements)
    assert data.get("status") != "unavailable"
    assert "events_v2_core" in combined
    assert re.search(r"\bfrom events\b|\bjoin events\b", combined) is None


def test_findings_v2_route_returns_canonical_rows_with_v2_evidence_sql(monkeypatch, tmp_path) -> None:
    findings = importlib.import_module("server.sli.semantic.findings")
    issued = datetime.now(timezone.utc)
    authorization = runtime_auth.persist_runtime_authorization(
        Cursor(), authorization=_authorization(), route="v2_primary_compat",
        archive_root=tmp_path, evidence={}, authorized_by="owner", issued_at=issued,
        expires_at=issued + timedelta(hours=1),
    )
    statements = []

    def query_rows(sql, params=()):
        normalized = " ".join(sql.lower().split())
        statements.append(normalized)
        if normalized.startswith("select * from findings_active"):
            return [{"id": 7, "severity": "high", "status": "new"}]
        if normalized.startswith("select id, fingerprint"):
            return [{"id": 8, "severity": "medium", "status": "active"}]
        return []

    monkeypatch.setattr(findings, "query_rows", query_rows)
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda **_kwargs: {"status": "ok"})

    data = findings.get_findings_data(
        authorization=authorization, limit=5,
    )
    dashboard = findings.get_findings_dashboard_data(
        authorization=authorization, limit=5,
    )

    combined = "\n".join(statements)
    assert data["status"] == "ok"
    assert data["items"][0]["id"] == 7
    assert dashboard["status"] == "ok"
    assert dashboard["items"][0]["id"] == 8
    assert "events_v2_core" in combined
    assert re.search(r"\bjoin events\b", combined) is None


def test_entity_detail_v2_route_executes_no_v1_sql(monkeypatch, tmp_path) -> None:
    details = importlib.import_module("server.sli.entities.entity_details")
    issued = datetime.now(timezone.utc)
    authorization = runtime_auth.persist_runtime_authorization(
        Cursor(), authorization=_authorization(), route="v2_primary_compat",
        archive_root=tmp_path, evidence={}, authorized_by="owner", issued_at=issued,
        expires_at=issued + timedelta(hours=1),
    )
    statements = []

    def query_rows(sql, params=()):
        normalized = " ".join(sql.lower().split())
        statements.append(normalized)
        if "from entities_v2 entity" in normalized and "where entity.id" in normalized:
            return [{"id": 7, "entity_type": "user", "natural_key": "example\\alice", "display_name": "Alice"}]
        if normalized.startswith("select count(*)"):
            return [{"count": 0}]
        return []

    monkeypatch.setattr(details, "query_rows", query_rows)
    monkeypatch.setattr(details, "is_postgres_runtime_db", lambda: True, raising=False)

    data = details.get_entity_detail_report_data(
        entity_id=7, authorization=authorization,
    )

    combined = "\n".join(statements)
    assert data["entity"]["id"] == 7
    assert "entities_v2" in combined
    assert "event_entity_links_v2" in combined
    assert "events_v2_core" in combined
    assert "observed_entities" not in combined
    assert re.search(r"\bevent_entity_links\b(?!_v2)|\bjoin events\b", combined) is None


def test_entity_detail_v2_hydrates_exact_link_evidence_from_archive(monkeypatch, tmp_path) -> None:
    details = importlib.import_module("server.sli.entities.entity_details")
    issued = datetime.now(timezone.utc)
    authorization = runtime_auth.persist_runtime_authorization(
        Cursor(), authorization=_authorization(), route="v2",
        archive_root=tmp_path, evidence={}, authorized_by="owner", issued_at=issued,
        expires_at=issued + timedelta(hours=1),
    )

    def query_rows(sql, params=()):
        normalized = " ".join(sql.lower().split())
        if "from entities_v2 entity" in normalized and "where entity.id" in normalized:
            return [{"id": 7, "entity_type": "user", "natural_key": "example\\alice", "display_name": "Alice"}]
        if normalized.startswith("select count(*)"):
            return [{"count": 1}]
        if "from event_entity_links_v2" in normalized:
            assert "link.confidence" not in normalized
            return [{
                "entity_id": 7, "link_role": "target", "event_db_id": 101,
                "server": "dc1", "channel": "Security", "event_id": 4624,
                "event_record_id": 55, "time_created_utc": "2026-08-26T00:00:00+00:00",
            }]
        return []

    monkeypatch.setattr(details, "query_rows", query_rows)
    monkeypatch.setattr(details, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(
        details, "_read_v2_link_details",
        lambda event_ids, archive_root: {
            101: [{
                "event_id": 101, "entity_id": 7, "link_role": "target",
                "confidence": 0.75, "extracted_from": "event_data",
                "attributes_json": {"normalized": True},
                "evidence_json": {"field": "TargetUserName"},
            }],
        },
        raising=False,
    )

    data = details.get_entity_detail_report_data(
        entity_id=7, authorization=authorization,
    )

    assert data["items"][0]["confidence"] == 0.75
    assert data["items"][0]["evidence"] == {"field": "TargetUserName"}
    assert data["items"][0]["link_attributes"] == {"normalized": True}


def test_investigation_workspace_forwards_persisted_authority(monkeypatch, tmp_path) -> None:
    investigation = importlib.import_module("server.sli.semantic.investigation")
    issued = datetime.now(timezone.utc)
    authorization = runtime_auth.persist_runtime_authorization(
        Cursor(), authorization=_authorization(), route="v2_primary_compat",
        archive_root=tmp_path, evidence={}, authorized_by="owner", issued_at=issued,
        expires_at=issued + timedelta(hours=1),
    )
    received = []
    monkeypatch.setattr(
        investigation, "get_event_search_data",
        lambda **kwargs: received.append(("search", kwargs.get("authorization"))) or {
            "items": [], "returned_count": 0, "has_more": False, "filters": {},
        },
    )
    monkeypatch.setattr(
        investigation, "get_findings_data",
        lambda **kwargs: received.append(("findings", kwargs.get("authorization"))) or {
            "items": [], "backend": "postgres",
        },
    )

    investigation.get_investigation_workspace_data(
        q="alice", authorization=authorization,
    )

    assert received == [("search", authorization), ("findings", authorization)]


def test_ai_redaction_preview_forwards_persisted_authority(monkeypatch, tmp_path) -> None:
    redaction = importlib.import_module("server.sli.access.data_redaction")
    issued = datetime.now(timezone.utc)
    authorization = runtime_auth.persist_runtime_authorization(
        Cursor(), authorization=_authorization(), route="v2_primary_compat",
        archive_root=tmp_path, evidence={}, authorized_by="owner", issued_at=issued,
        expires_at=issued + timedelta(hours=1),
    )
    received = []
    monkeypatch.setattr(
        redaction, "get_event_search_data",
        lambda **kwargs: received.append(kwargs.get("authorization")) or {
            "items": [], "filters": {}, "has_more": False, "truncated": False,
        },
    )

    redaction.build_ai_redaction_preview(
        q="alice", authorization=authorization,
    )

    assert received == [authorization]


def test_ai_prompt_builder_forwards_persisted_authority_to_redaction(monkeypatch, tmp_path) -> None:
    prompt_builder = importlib.import_module("server.sli.ai.ai_prompt_builder")
    issued = datetime.now(timezone.utc)
    authorization = runtime_auth.persist_runtime_authorization(
        Cursor(), authorization=_authorization(), route="v2_primary_compat",
        archive_root=tmp_path, evidence={}, authorized_by="owner", issued_at=issued,
        expires_at=issued + timedelta(hours=1),
    )

    class PreviewReached(Exception):
        pass

    def preview(**kwargs):
        assert kwargs.get("authorization") is authorization
        raise PreviewReached

    monkeypatch.setattr(prompt_builder, "build_ai_redaction_preview", preview)
    with pytest.raises(PreviewReached):
        prompt_builder.build_ai_prompt_from_filters(
            q="alice", authorization=authorization,
        )
