from __future__ import annotations

from datetime import datetime, timezone
from contextlib import contextmanager
import importlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.sources.test_computers_v6_source_contract import _production_snapshot


ROOT = Path(__file__).resolve().parents[2]
WORKER_PATH = ROOT / "scripts/runtime/computers_v6_source_worker.py"


def _worker_api():
    assert WORKER_PATH.is_file(), "V6 source capture worker is missing"
    return importlib.import_module("scripts.runtime.computers_v6_source_worker")


@pytest.mark.windows_only  # DPAPI mode resolves the native Windows PowerShell path.
@pytest.mark.parametrize("failure", [False, True])
def test_dpapi_production_runner_preserves_v6_scope_timeout_and_cleanup(monkeypatch, tmp_path, failure):
    from server.sli.sources import ad_source_process
    worker = _worker_api()
    monkeypatch.setenv("ADLOG_AD_SOURCE_CREDENTIAL_MODE", "dpapi_current_user")
    def forbidden(*args, **kwargs):
        pytest.fail("original subprocess must not run in DPAPI mode")
    monkeypatch.setattr(worker.subprocess, "run", forbidden)
    # Old code captured subprocess.run as a keyword default: isolate that too.
    if worker.capture_and_persist_once.__kwdefaults__["runner"] is not None:
        monkeypatch.setitem(worker.capture_and_persist_once.__kwdefaults__, "runner", forbidden)
    observed = []
    def source_run(command, *, server, cwd, timeout_seconds):
        assert Path(command[0]).is_absolute()
        assert Path(command[0]).name.lower() == "powershell.exe"
        assert server == "dc01.example.test" and cwd == ROOT
        assert timeout_seconds == 3600
        assert "-CollectAdSite" in command and "-CollectExactLastLogon" in command
        output = Path(command[command.index("-OutputPath") + 1])
        base = Path(command[command.index("-CoordinatorBaseInputPath") + 1])
        observed.extend((output, base))
        assert json.loads(base.read_text())["object_count"] == 1
        if failure:
            raise RuntimeError("ad_source_process_failed")
        output.write_text(json.dumps(_production_snapshot()), encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="saved", stderr="")
    monkeypatch.setattr(ad_source_process, "run_ad_source_process", source_run)
    def connect():
        assert not failure, "no DB access after source failure"
        return _Connection(_Cursor())
    kwargs = dict(connection_factory=connect, captured_at=NOW, powershell_executable="powershell.exe",
        server="dc01.example.test", search_base="DC=example,DC=test", skip_dns=False,
        collect_ad_site=True, collect_exact_last_logon=True,
        coordinator_base_rows=[{"ObjectGUID": "00000000-0000-4000-8000-000000000001"}],
        temp_directory=tmp_path)
    if failure:
        with pytest.raises(RuntimeError, match="ad_source_process_failed"):
            worker.capture_and_persist_once(**kwargs)
    else:
        assert worker.capture_and_persist_once(**kwargs)["status"] == "captured"
    assert observed and all(not path.exists() for path in observed)


def test_invalid_credential_mode_refuses_even_injected_runner(monkeypatch, tmp_path):
    worker = _worker_api()
    monkeypatch.setenv("ADLOG_AD_SOURCE_CREDENTIAL_MODE", "typo")
    with pytest.raises(RuntimeError, match="ad_source_credential_mode_invalid"):
        worker.capture_and_persist_once(connection_factory=lambda: pytest.fail("DB called"),
            captured_at=NOW, powershell_executable="powershell.exe", server="dc01.example.test",
            search_base=None, skip_dns=False, collect_ad_site=False, collect_exact_last_logon=False,
            runner=lambda *a, **k: pytest.fail("runner called"), temp_directory=tmp_path)


def test_worker_builds_bounded_dedicated_reference_collector_command() -> None:
    worker = _worker_api()
    output = ROOT / ".tmp/computers-v6-source.json"
    command = worker.build_collector_command(
        output_path=output,
        powershell_executable="powershell.exe",
        server="dc01.example.test",
        search_base="OU=Servers,DC=example,DC=test",
        skip_dns=False,
        collect_ad_site=True,
        collect_exact_last_logon=True,
    )

    assert worker.DEFAULT_CAPTURE_INTERVAL_SECONDS == 12 * 60 * 60
    assert worker.ALLOWED_CAPTURE_INTERVAL_SECONDS == frozenset(
        {12 * 60 * 60, 24 * 60 * 60}
    )
    assert 0 < worker.COLLECTOR_TIMEOUT_SECONDS <= 60 * 60
    assert command[0] == "powershell.exe"
    assert command[1:6] == [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
    ]
    assert command[6] == str(
        ROOT / "scripts/ad_context/Export-ComputersV6ReferenceSnapshot.ps1"
    )
    assert command[command.index("-OutputPath") + 1] == str(output)
    assert command[command.index("-Server") + 1] == "dc01.example.test"
    assert command[command.index("-SearchBase") + 1] == (
        "OU=Servers,DC=example,DC=test"
    )
    assert "-CollectAdSite" in command
    assert "-CollectExactLastLogon" in command
    assert "-SkipDns" not in command


def test_coordinator_mode_is_enrichment_only_and_requires_immutable_base_input(
    tmp_path: Path,
) -> None:
    worker = _worker_api()
    base_path = tmp_path / "base-computers.json"
    base_path.write_text("{}", encoding="utf-8")
    command = worker.build_collector_command(
        output_path=tmp_path / "out.json",
        powershell_executable="powershell.exe",
        server="dc01.example.test",
        search_base="DC=example,DC=test",
        collect_ad_site=True,
        collect_exact_last_logon=True,
        coordinator_base_input_path=base_path,
    )

    assert command[command.index("-CoordinatorBaseInputPath") + 1] == str(base_path)
    adapter = (ROOT / "scripts/ad_context/Export-ComputersV6ReferenceSnapshot.ps1").read_text(
        encoding="utf-8"
    )
    assert "CoordinatorBaseInputPath" in adapter
    assert "coordinator_base_identity_mismatch" in adapter
    assert "$BaseComputerGuidAllowlist.Contains" in adapter
    assert "$CoordinatorComputers = @($baseRowsJson | ConvertFrom-Json | ForEach-Object { $_ })" in adapter
    assert "Get-ADComputer @QueryParameters" in adapter  # dormant standalone rollback


def test_coordinator_capture_reuses_exact_base_identity_and_cleans_input(tmp_path: Path) -> None:
    worker = _worker_api()
    observed_base_paths: list[Path] = []

    def runner(command, **_kwargs):
        assert _kwargs.get("creationflags") == getattr(worker.subprocess, "CREATE_NO_WINDOW", 0)
        base_path = Path(command[command.index("-CoordinatorBaseInputPath") + 1])
        observed_base_paths.append(base_path)
        envelope = json.loads(base_path.read_text(encoding="utf-8"))
        assert envelope["schema_version"] == "sli.ad-computer-base/1.0"
        assert envelope["object_count"] == 1
        rows = json.loads(envelope["objects_json"])
        assert rows[0]["ObjectGUID"].endswith("0001")
        output = Path(command[command.index("-OutputPath") + 1])
        output.write_text(json.dumps(_production_snapshot()), encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="saved", stderr="")

    result = worker.capture_and_persist_once(
        connection_factory=lambda: _Connection(_Cursor()),
        captured_at=NOW,
        powershell_executable="powershell.exe",
        server="dc01.example.test",
        search_base=None,
        skip_dns=False,
        collect_ad_site=True,
        collect_exact_last_logon=True,
        coordinator_base_rows=[
            {
                "ObjectGUID": "00000000-0000-4000-8000-000000000001",
                "DNSHostName": "app-01.example.test",
            }
        ],
        runner=runner,
        temp_directory=tmp_path,
    )

    assert result["object_count"] == 1
    assert observed_base_paths and not observed_base_paths[0].exists()


def test_coordinator_mode_never_falls_back_when_standalone_lock_is_busy() -> None:
    worker = _worker_api()

    @contextmanager
    def busy_lock():
        yield False

    assert worker.run_coordinator_enrichment_cycle(
        lock_context_factory=busy_lock,
        capture_from_base=lambda: pytest.fail("must not run in parallel or fallback"),
        heartbeat=lambda _payload: None,
    ) == {"status": "blocked", "reason": "standalone_source_lock_busy"}


NOW = datetime(2026, 8, 30, 2, 0, tzinfo=timezone.utc)


class _Cursor:
    def __init__(
        self,
        *,
        inserted: bool = True,
        readback_matches: bool = True,
    ) -> None:
        self.inserted = inserted
        self.readback_matches = readback_matches
        self.phase = ""
        self.statements: list[tuple[str, tuple]] = []
        self.rowcount = 0
        self.expected_count = 0
        self.expected_hash = b""
        self.expected_uuid = ""

    def execute(self, sql: str, params: tuple = ()) -> None:
        self.statements.append((sql, params))
        normalized = " ".join(sql.casefold().split())
        if "select id from domains" in normalized:
            self.phase = "domain"
        elif "insert into computers_v6_source_snapshots" in normalized:
            self.phase = "insert"
            self.expected_uuid = str(params[1])
            self.expected_count = int(params[12])
            self.expected_hash = bytes(params[15])
        elif "select source_snapshot_id,object_count,payload_sha256,snapshot_uuid" in normalized:
            self.phase = "conflict_readback"
        elif "select object_count,payload_sha256,snapshot_uuid" in normalized:
            self.phase = "readback"
        elif "delete from computers_v6_source_snapshots" in normalized:
            self.phase = "delete"
            self.rowcount = 2

    def fetchone(self):
        if self.phase == "domain":
            return {"id": 7}
        if self.phase == "insert":
            return {"source_snapshot_id": 114} if self.inserted else None
        if self.phase in {"readback", "conflict_readback"}:
            row = {
                "object_count": (
                    self.expected_count
                    if self.readback_matches
                    else self.expected_count + 1
                ),
                "payload_sha256": self.expected_hash,
                "snapshot_uuid": self.expected_uuid,
            }
            if self.phase == "conflict_readback":
                row["source_snapshot_id"] = 114
            return row
        return None


class _Connection:
    def __init__(self, cursor: _Cursor) -> None:
        self.cursor_value = cursor

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def cursor(self):
        cursor = self.cursor_value

        class _Context:
            def __enter__(self):
                return cursor

            def __exit__(self, *_args):
                return False

        return _Context()


def _options() -> dict[str, object]:
    return {
        "server": "dc01.example.test",
        "search_base": None,
        "skip_dns": False,
        "collect_ad_site": True,
        "collect_exact_last_logon": True,
    }


def test_persistence_verifies_exact_readback_before_retention() -> None:
    worker = _worker_api()
    cursor = _Cursor()
    result = worker.persist_computers_v6_source_snapshot(
        _Connection(cursor),
        snapshot=_production_snapshot(),
        captured_at=NOW,
        capture_options=_options(),
        collector_exit_code=0,
    )

    assert not hasattr(worker, "RETENTION_DAYS")
    assert not hasattr(worker, "source_retention_cutoff")
    assert result == {
        "status": "captured",
        "source_snapshot_id": 114,
        "domain_id": 7,
        "snapshot_uuid": "00000000-0000-4000-8000-000000000114",
        "object_count": 1,
        "collection_status": "complete",
        "base_inventory_status": "observed",
        "retired_snapshots": 0,
    }
    statements = [" ".join(sql.casefold().split()) for sql, _ in cursor.statements]
    assert "select id from domains" in statements[0]
    assert "insert into computers_v6_source_snapshots" in statements[1]
    assert "select object_count,payload_sha256,snapshot_uuid" in statements[2]
    assert len(statements) == 3
    assert "delete from computers_v6_source_snapshots" not in "\n".join(statements)
    insert_params = cursor.statements[1][1]
    options_json = next(
        value
        for value in insert_params
        if isinstance(value, str) and '"collect_ad_site"' in value
    )
    assert json.loads(options_json) == _options()


def test_persistence_is_idempotent_and_never_retires_after_failed_readback() -> None:
    worker = _worker_api()
    duplicate = _Cursor(inserted=False)
    result = worker.persist_computers_v6_source_snapshot(
        _Connection(duplicate),
        snapshot=_production_snapshot(),
        captured_at=NOW,
        capture_options=_options(),
        collector_exit_code=0,
    )
    assert result["status"] == "already_captured"
    assert not any(
        "delete from computers_v6_source_snapshots" in sql.casefold()
        for sql, _ in duplicate.statements
    )

    mismatch = _Cursor(readback_matches=False)
    with pytest.raises(RuntimeError, match="readback"):
        worker.persist_computers_v6_source_snapshot(
            _Connection(mismatch),
            snapshot=_production_snapshot(),
            captured_at=NOW,
            capture_options=_options(),
            collector_exit_code=0,
        )
    assert not any(
        "delete from computers_v6_source_snapshots" in sql.casefold()
        for sql, _ in mismatch.statements
    )


def test_idempotent_conflict_verifies_existing_payload_identity() -> None:
    worker = _worker_api()
    conflict = _Cursor(inserted=False, readback_matches=False)

    with pytest.raises(RuntimeError, match="conflict.*mismatch"):
        worker.persist_computers_v6_source_snapshot(
            _Connection(conflict),
            snapshot=_production_snapshot(),
            captured_at=NOW,
            capture_options=_options(),
            collector_exit_code=0,
        )

    statements = [" ".join(sql.casefold().split()) for sql, _ in conflict.statements]
    assert "select source_snapshot_id,object_count,payload_sha256,snapshot_uuid" in statements[2]
    assert not any(
        "delete from computers_v6_source_snapshots" in sql
        for sql in statements
    )


def test_capture_once_uses_timeout_validates_then_removes_local_snapshot(
    tmp_path: Path,
) -> None:
    worker = _worker_api()
    calls: dict[str, object] = {}
    produced_paths: list[Path] = []

    def runner(command, **kwargs):
        calls["command"] = list(command)
        calls["kwargs"] = dict(kwargs)
        output = Path(command[command.index("-OutputPath") + 1])
        produced_paths.append(output)
        output.write_text(
            json.dumps(_production_snapshot(), ensure_ascii=False),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stdout="saved", stderr="")

    cursor = _Cursor()
    result = worker.capture_and_persist_once(
        connection_factory=lambda: _Connection(cursor),
        captured_at=NOW,
        powershell_executable="powershell.exe",
        server="dc01.example.test",
        search_base=None,
        skip_dns=False,
        collect_ad_site=True,
        collect_exact_last_logon=True,
        runner=runner,
        temp_directory=tmp_path,
        timeout_seconds=300,
    )

    assert result["status"] == "captured"
    assert result["collector_exit_code"] == 0
    assert calls["kwargs"] == {
        "creationflags": getattr(worker.subprocess, "CREATE_NO_WINDOW", 0),
        "check": False,
        "capture_output": True,
        "text": True,
        "errors": "replace",
        "timeout": 300,
    }
    assert produced_paths and not produced_paths[0].exists()
    assert produced_paths[0].parent == tmp_path


def test_capture_timestamp_is_taken_after_collector_finishes(tmp_path: Path) -> None:
    worker = _worker_api()
    collector_finished = False

    def runner(command, **_kwargs):
        nonlocal collector_finished
        output = Path(command[command.index("-OutputPath") + 1])
        output.write_text(
            json.dumps(_production_snapshot(), ensure_ascii=False),
            encoding="utf-8",
        )
        collector_finished = True
        return SimpleNamespace(returncode=0, stdout="saved", stderr="")

    def clock() -> datetime:
        assert collector_finished, "capture timestamp must follow collector completion"
        return NOW

    result = worker.capture_and_persist_once(
        connection_factory=lambda: _Connection(_Cursor()),
        captured_at=None,
        powershell_executable="powershell.exe",
        server=None,
        search_base=None,
        skip_dns=False,
        collect_ad_site=False,
        collect_exact_last_logon=False,
        runner=runner,
        temp_directory=tmp_path,
        clock=clock,
    )
    assert result["status"] == "captured"


def _failed_base_snapshot() -> dict:
    snapshot = _production_snapshot()
    snapshot["objects"] = []
    snapshot["metadata"]["object_count"] = 0
    snapshot["metadata"]["collection_status"] = "failed"
    snapshot["metadata"]["sources"] = [
        {
            "name": "ad",
            "status": "failed",
            "requested": True,
            "counts": {"failed": 0},
        }
    ]
    snapshot["metadata"]["errors"] = [
        {
            "source": "ad",
            "status": "failed",
            "code": "ad_query_failed",
            "message": "query failed",
            "target": "dc01.example.test",
        }
    ]
    return snapshot


def test_failed_base_snapshot_is_persisted_after_collector_nonzero_exit(
    tmp_path: Path,
) -> None:
    worker = _worker_api()

    def runner(command, **_kwargs):
        output = Path(command[command.index("-OutputPath") + 1])
        output.write_text(
            json.dumps(_failed_base_snapshot(), ensure_ascii=False),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=1, stdout="", stderr="AD query failed")

    cursor = _Cursor()
    result = worker.capture_and_persist_once(
        connection_factory=lambda: _Connection(cursor),
        captured_at=NOW,
        powershell_executable="powershell.exe",
        server="dc01.example.test",
        search_base=None,
        skip_dns=False,
        collect_ad_site=False,
        collect_exact_last_logon=False,
        runner=runner,
        temp_directory=tmp_path,
    )

    assert result["status"] == "captured"
    assert result["collector_exit_code"] == 1
    assert result["collection_status"] == "failed"
    assert result["base_inventory_status"] == "failed"
    assert result["object_count"] == 0


def test_capture_bounds_cannot_be_relaxed_by_runtime_arguments(tmp_path: Path) -> None:
    worker = _worker_api()
    called = False

    def runner(*_args, **_kwargs):
        nonlocal called
        called = True
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    with pytest.raises(ValueError, match="snapshot.*bound"):
        worker.capture_and_persist_once(
            connection_factory=lambda: _Connection(_Cursor()),
            captured_at=NOW,
            powershell_executable="powershell.exe",
            server=None,
            search_base=None,
            skip_dns=False,
            collect_ad_site=False,
            collect_exact_last_logon=False,
            runner=runner,
            temp_directory=tmp_path,
            max_snapshot_bytes=worker.MAX_SNAPSHOT_BYTES + 1,
        )
    assert called is False


def test_worker_cycle_is_lock_guarded_and_cli_allows_only_12_or_24_hours() -> None:
    worker = _worker_api()
    events: list[object] = []

    @contextmanager
    def acquired_lock():
        events.append("lock_enter")
        yield True
        events.append("lock_exit")

    result = worker.run_worker_cycle(
        lock_context_factory=acquired_lock,
        capture_once=lambda: {"status": "captured", "object_count": 1},
        heartbeat=lambda payload: events.append(("heartbeat", payload["status"])),
    )
    assert result == {"status": "captured", "object_count": 1}
    assert events == [
        "lock_enter",
        "lock_exit",
        ("heartbeat", "captured"),
    ]

    @contextmanager
    def busy_lock():
        yield False

    assert worker.run_worker_cycle(
        lock_context_factory=busy_lock,
        capture_once=lambda: pytest.fail("capture must not run while lock is busy"),
        heartbeat=lambda _payload: None,
    ) == {"status": "skipped", "reason": "lock_busy"}

    parser = worker.build_argument_parser()
    args = parser.parse_args(
        [
            "--once",
            "--interval-hours",
            "24",
            "--collect-ad-site",
            "--collect-exact-last-logon",
        ]
    )
    assert args.once is True
    assert args.interval_hours == 24
    assert args.collect_ad_site is True
    assert args.collect_exact_last_logon is True
    with pytest.raises(SystemExit):
        parser.parse_args(["--interval-hours", "6"])


def test_main_once_wires_lock_capture_and_heartbeat_without_sleep(
    tmp_path: Path,
) -> None:
    worker = _worker_api()
    heartbeats: list[dict] = []

    @contextmanager
    def acquired_lock():
        yield True

    def runner(command, **_kwargs):
        output = Path(command[command.index("-OutputPath") + 1])
        output.write_text(
            json.dumps(_production_snapshot(), ensure_ascii=False),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stdout="saved", stderr="")

    code = worker.main(
        [
            "--once",
            "--no-initial-delay",
            "--powershell",
            "powershell.exe",
            "--temp-directory",
            str(tmp_path),
        ],
        connection_factory=lambda: _Connection(_Cursor()),
        lock_context_factory=acquired_lock,
        heartbeat_recorder=heartbeats.append,
        runner=runner,
        sleep_fn=lambda _seconds: pytest.fail("--once must not sleep"),
    )
    assert code == 0
    assert heartbeats[-1]["status"] == "captured"
    assert heartbeats[-1]["expected_interval_seconds"] == 12 * 60 * 60


def test_source_snapshot_migration_and_rollback_match_worker_contract() -> None:
    apply_path = (
        ROOT / "config/postgres_migrations/114_computers_v6_source_snapshot.sql"
    )
    rollback_path = (
        ROOT
        / "config/postgres_migrations/114_computers_v6_source_snapshot.rollback.sql"
    )
    assert apply_path.is_file(), "V6 source snapshot migration is missing"
    assert rollback_path.is_file(), "V6 source snapshot rollback is missing"

    apply = " ".join(apply_path.read_text(encoding="utf-8").casefold().split())
    rollback = " ".join(
        rollback_path.read_text(encoding="utf-8").casefold().split()
    )
    assert "version=113 and name='computers_report_v6'" in apply
    assert "create table computers_v6_source_snapshots" in apply
    for column in (
        "snapshot_uuid",
        "source_started_at_utc",
        "source_completed_at_utc",
        "captured_at_utc",
        "collector_sha256",
        "collection_status",
        "base_inventory_status",
        "source_options_json",
        "payload_json",
        "payload_sha256",
        "collector_exit_code",
    ):
        assert column in apply
    assert "object_count between 0 and 250000" in apply
    assert "octet_length(payload_json::text) <= 67108864" in apply
    assert "computers_v6_source" in apply
    assert "values(114,'computers_v6_source_snapshot')" in apply
    assert "drop table computers_v6_source_snapshots" in rollback
    assert "version=114 and name='computers_v6_source_snapshot'" in rollback
    assert "computers_v6_source" not in rollback.split(
        "add constraint runtime_worker_heartbeats_name check", 1
    )[1].split(");", 1)[0]




def test_source_worker_can_be_launched_as_a_direct_script() -> None:
    worker_path = ROOT / "scripts/runtime/computers_v6_source_worker.py"
    source = worker_path.read_text(encoding="utf-8")
    bootstrap = source.index("sys.path.insert(0, str(ROOT))")
    app_import = source.index("from server.sli.sources.computers_v6_source import")
    assert bootstrap < app_import


def test_collector_adapter_keeps_reference_immutable_and_bounds_exact_logon_fix() -> None:
    adapter = (
        ROOT / "scripts/ad_context/Export-ComputersV6ReferenceSnapshot.ps1"
    ).read_text(encoding="utf-8")
    assert "Get-FileHash -LiteralPath $ReferenceCollector -Algorithm SHA256" in adapter
    assert "$ExactLogonCastCount -ne 1" in adapter
    assert "$RawLastLogon = @($Row.lastLogon)" in adapter
    assert "$ReferenceSource.Replace($UnsafeExactLogonCast" in adapter
    assert "$DomainControllersAnchorCount -ne 1" in adapter
    assert "$ReferenceSource.Replace($TypedDomainControllers" in adapter
    assert "$GenericListArrayAnchorCount -ne 1" in adapter
    assert "$SuccessfulDcs.ToArray()" in adapter
    assert "$SubnetParameterAnchorCount -ne 1" in adapter
    assert "[AllowEmptyCollection()][object[]]$SubnetRecords" in adapter
    assert "$ObservedAtAnchorCount -ne 1" in adapter
    assert "[Nullable[datetime]]$ObservedAt" in adapter
    assert "$SpnProjectionAnchorCount -ne 1" in adapter
    assert "ForEach-Object { [string]$_ }" in adapter
    assert "$ObjectErrorsAnchorCount -ne 1" in adapter
    assert "$GlobalErrorsAnchorCount -ne 1" in adapter
    assert "$ObjectsAnchorCount -ne 1" in adapter
    assert "Reference collector failed" in adapter
