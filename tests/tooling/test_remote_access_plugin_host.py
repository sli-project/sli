from contextlib import contextmanager
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from scripts.runtime import remote_access_plugin_host as host


@pytest.fixture(autouse=True)
def _acquisition_enabled(monkeypatch):
    # These tests exercise the active Windows host path with its Windows parts faked.
    # On Linux acquisition_disabled() is always true, and with time.sleep patched the
    # idle loop would spin forever (it exhausted 10 GB of memory in CI containers).
    monkeypatch.setattr(host, "acquisition_disabled", lambda: False)


@pytest.mark.parametrize("component", ["radius-acquisition", "radius-session-observation"])
def test_core_pilot_retires_old_host_before_identity_or_credentials(monkeypatch, component):
    monkeypatch.setenv("SLI_CORE_JOB_RADIUS_PILOT", "1")
    calls = []
    monkeypatch.setattr(host, "_write_heartbeat", lambda *args, **kwargs: calls.append(kwargs))
    monkeypatch.setattr(host, "load_supervisor_environment", lambda: pytest.fail("legacy broker started"))
    monkeypatch.setattr(host, "acquisition_disabled", lambda: pytest.fail("legacy path entered"))
    assert host.run_host(component, once=True) == 0
    assert calls[0]["phase"] == "core_executor_pilot"


@pytest.mark.parametrize("component,state,expected", [
    ("radius-acquisition", ("disabled", "draining", "closed"), False),
    ("radius-session-observation", ("disabled", "draining", "drain_only"), True),
    ("radius-session-observation", ("disabled", "stopped", "closed"), False),
    ("radius-acquisition", ("enabled_manual", "running", "open"), True),
    ("radius-acquisition", None, False),
])
def test_disabled_acquisition_cannot_start_new_work_but_consumer_drains(monkeypatch, component, state, expected):
    calls = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def cursor(self):
            return self

        def execute(self, sql, params=None):
            calls.append((sql, params))

        def fetchone(self):
            return state

    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(connect=lambda *_a, **_kw: Connection()))
    assert host._plugin_enabled("fixture-dsn", component) is expected
    if component == "radius-session-observation":
        assert calls[0] == ("select finish_remote_access_plugin_drain_v1()", None)
    assert calls[-1][1] == ("sli.remote-access", component)


@pytest.mark.parametrize("component,result,received", [
    ("radius-acquisition", {"worker_result": {"outbox_rows": 2}}, True),
    ("radius-acquisition", {"worker_result": {"outbox_rows": 0}}, False),
    ("radius-session-observation", {"worker_result": {"processed": 2}}, False),
])
def test_receiving_data_requires_new_committed_acquisition_data(monkeypatch, component, result, received):
    from server.sli.sources import plugin_state

    calls = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def cursor(self):
            return self

        def execute(self, sql, params):
            calls.append((sql, params))

    monkeypatch.setattr(plugin_state, "remote_access_configured", lambda: True)
    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(connect=lambda *_a, **_kw: Connection()))
    host._record_cycle_observation("fixture-dsn", component, result)
    assert calls == [("select observe_remote_access_plugin_v1(%s,%s)", (True, received))]


@pytest.mark.parametrize("component,states,cycle_count", [
    ("radius-acquisition", [False], 0),
    ("radius-session-observation", [True, False], 1),
])
def test_host_stops_after_drain_and_never_starts_disabled_acquisition(monkeypatch, component, states, cycle_count):
    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def cursor(self):
            return self

        def execute(self, *_args):
            return None

        def fetchone(self):
            return (True,)

    allowed = iter(states)
    cycles, heartbeats = [], []
    monkeypatch.setenv("ADLOG_PG_DSN", "fixture-dsn")
    monkeypatch.setattr(host, "load_supervisor_environment", lambda: None)
    monkeypatch.setattr(host, "expected_collection_identity", lambda: (r"EXAMPLE\operator", "fixture-sid"))
    monkeypatch.setattr(host, "current_windows_account", lambda: r"EXAMPLE\operator")
    monkeypatch.setattr(host, "_plugin_enabled", lambda *_a: next(allowed))
    monkeypatch.setattr(host, "_run_bounded_cycle", lambda value: cycles.append(value) or {"worker_result": {"processed": 1}})
    monkeypatch.setattr(host, "_record_cycle_observation", lambda *_a: None)
    monkeypatch.setattr(host, "_write_heartbeat", lambda _component, **values: heartbeats.append(values))
    monkeypatch.setattr(host.time, "sleep", lambda _seconds: None)
    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(connect=lambda *_a, **_kw: Connection()))
    assert host.run_host(component) == 0
    assert cycles == [component] * cycle_count
    assert heartbeats[-1]["status"] == "stopped"
    assert heartbeats[-1]["phase"] == "disabled"


def test_radius_acquisition_lease_remains_active_until_child_finishes(
    monkeypatch,
) -> None:
    lease_active = False

    @contextmanager
    def _admin():
        yield object()

    @contextmanager
    def _activation(_admin_connection):
        nonlocal lease_active
        lease_active = True
        try:
            yield object()
        finally:
            lease_active = False

    def _run_child(_component_id: str, plugin_dsn: str) -> dict[str, object]:
        assert lease_active is True
        assert plugin_dsn == "fixture-worker-dsn"
        return {"status": "passed"}

    monkeypatch.setattr(host, "connect_acquisition_admin", _admin)
    monkeypatch.setattr(host, "bounded_manual_activation", _activation)
    monkeypatch.setattr(
        host, "acquisition_worker_dsn", lambda _lease: "fixture-worker-dsn"
    )
    monkeypatch.setattr(host, "_run_bounded_cycle_with_dsn", _run_child)

    result = host._run_bounded_cycle("radius-acquisition")

    assert lease_active is False
    assert result == {"status": "passed", "credential_lease_released": True}


def test_cycle_child_reports_safe_failure_stage_and_numeric_os_code(
    monkeypatch, tmp_path
) -> None:
    captured: dict[str, object] = {}
    output = tmp_path / "plugin-cycle-test.json"
    monkeypatch.setattr(host, "TEMP_DIR", tmp_path)
    monkeypatch.setattr(host, "_child_plugin_dsn", lambda: "fixture-dsn")
    monkeypatch.setattr(
        host,
        "expected_collection_identity",
        lambda: (r"EXAMPLE\operator", "fixture-sid"),
    )
    monkeypatch.setattr(
        host, "current_windows_account", lambda: r"EXAMPLE\operator"
    )
    monkeypatch.setitem(
        host.COMPONENTS,
        "radius-acquisition",
        {
            **host.COMPONENTS["radius-acquisition"],
            "runner": lambda: (_ for _ in ()).throw(
                OSError(5, "secret-path-marker")
            ),
        },
    )
    monkeypatch.setattr(
        host,
        "_atomic_json",
        lambda _path, value: captured.update(value),
    )

    assert host.run_cycle_child("radius-acquisition", output) == 1
    assert captured == {
        "status": "failed",
        "component_id": "radius-acquisition",
        "failure_stage": "component_runner",
        "error_type": "OSError",
        "error_code": "os_error:5",
        "contains_secret_material": False,
    }
    assert "secret-path-marker" not in str(captured)


def test_parent_error_preserves_only_safe_child_failure_metadata(
    monkeypatch, tmp_path
) -> None:
    result_path = tmp_path / "plugin-cycle-result.json"

    class _Child:
        def wait(self, _timeout_ms: int) -> bool:
            return True

        def exit_code(self) -> int:
            return 1

    class _Job:
        def __init__(self, _limits) -> None:
            return None

        def start(self, *_args, **_kwargs) -> _Child:
            result_path.write_text(
                json.dumps(
                    {
                        "status": "failed",
                        "component_id": "radius-acquisition",
                        "failure_stage": "component_runner",
                        "error_type": "OSError",
                        "error_code": "os_error:5",
                        "contains_secret_material": False,
                    }
                ),
                encoding="utf-8",
            )
            return _Child()

        def status(self) -> dict[str, object]:
            return {}

        def close_job(self) -> None:
            return None

        def close_child_handles(self) -> None:
            return None

    monkeypatch.setattr(host, "_result_path", lambda _component_id: result_path)
    monkeypatch.setattr(host, "WindowsPluginJob", _Job)
    monkeypatch.setattr(host, "_child_environment", lambda _dsn, **kwargs: {})

    with pytest.raises(
        host.RemoteAccessPluginHostError,
        match=(
            "^plugin_component_cycle_failed:component_runner:"
            "OSError:os_error:5$"
        ),
    ):
        host._run_bounded_cycle_with_dsn(
            "radius-acquisition", "secret-dsn-marker"
        )

    assert result_path.exists() is False


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (
            host.RemoteAccessPluginHostError(
                "plugin_component_cycle_failed:component_runner:"
                "OSError:os_error:5"
            ),
            {
                "failure_stage": "component_runner",
                "error_type": "OSError",
                "error_code": "os_error:5",
            },
        ),
        (
            RuntimeError(r"secret path C:\source\sensitive.log"),
            {
                "failure_stage": "host_control",
                "error_type": "RuntimeError",
                "error_code": "host_control_failure",
            },
        ),
    ],
)
def test_failed_host_cycle_records_only_bounded_failure_metadata(
    monkeypatch,
    failure: Exception,
    expected: dict[str, str],
) -> None:
    class _Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def execute(self, *_args, **_kwargs) -> None:
            return None

        def fetchone(self) -> tuple[bool]:
            return (True,)

    class _Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def cursor(self) -> _Cursor:
            return _Cursor()

    heartbeats: list[dict[str, object]] = []
    monkeypatch.setenv("ADLOG_PG_DSN", "postgresql://secret-dsn-marker")
    monkeypatch.setattr(
        host,
        "expected_collection_identity",
        lambda: (r"EXAMPLE\operator", "fixture-sid"),
    )
    monkeypatch.setattr(
        host, "current_windows_account", lambda: r"EXAMPLE\operator"
    )
    monkeypatch.setattr(host, "load_supervisor_environment", lambda: None)
    monkeypatch.setattr(host, "_plugin_enabled", lambda *_args: True)
    monkeypatch.setattr(
        host,
        "_run_bounded_cycle",
        lambda _component_id: (_ for _ in ()).throw(failure),
    )
    monkeypatch.setattr(
        host,
        "_write_heartbeat",
        lambda component_id, **kwargs: heartbeats.append(
            {"component_id": component_id, **kwargs}
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda *_args, **_kwargs: _Connection()),
    )

    with pytest.raises(type(failure)):
        host.run_host("radius-acquisition", once=True)

    blocked = heartbeats[-1]
    assert blocked["status"] == "blocked"
    assert blocked["phase"] == "cycle_failed"
    assert blocked["failure"] == expected
    assert "secret" not in json.dumps(blocked).casefold()


def test_host_loads_protected_environment_before_identity_check(
    monkeypatch,
) -> None:
    class _Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def execute(self, *_args, **_kwargs) -> None:
            return None

        def fetchone(self) -> tuple[bool]:
            return (True,)

    class _Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def cursor(self) -> _Cursor:
            return _Cursor()

    order: list[str] = []

    def _load_environment() -> None:
        order.append("load")
        monkeypatch.setenv("ADLOG_PG_DSN", "postgresql://fixture")

    def _expected_identity() -> tuple[str, str]:
        order.append("identity")
        return r"EXAMPLE\operator", "fixture-sid"

    monkeypatch.delenv("ADLOG_PG_DSN", raising=False)
    monkeypatch.setattr(host, "load_supervisor_environment", _load_environment)
    monkeypatch.setattr(host, "expected_collection_identity", _expected_identity)
    monkeypatch.setattr(
        host, "current_windows_account", lambda: r"EXAMPLE\operator"
    )
    monkeypatch.setattr(host, "_plugin_enabled", lambda *_args: False)
    monkeypatch.setattr(host, "_write_heartbeat", lambda *_args, **_kwargs: None)
    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda *_args, **_kwargs: _Connection()),
    )

    assert host.run_host("radius-acquisition", once=True) == 0
    assert order[:2] == ["load", "identity"]


def test_failure_heartbeat_persists_only_allowlisted_fields(
    monkeypatch,
    tmp_path,
) -> None:
    target = tmp_path / "plugin-radius-acquisition.json"
    monkeypatch.setattr(host, "plugin_heartbeat_path", lambda _component_id: target)

    host._write_heartbeat(
        "radius-acquisition",
        status="blocked",
        phase="cycle_failed",
        interval_seconds=300,
        failure={
            "failure_stage": "component_runner",
            "error_type": "OSError",
            "error_code": "os_error:5",
            "raw_exception": "secret-marker",
        },
    )

    encoded = target.read_text(encoding="utf-8")
    payload = json.loads(encoded)
    assert payload["last_result"] == {
        "status": "failed",
        "failure_stage": "component_runner",
        "error_type": "OSError",
        "error_code": "os_error:5",
    }
    assert "secret-marker" not in encoded


def test_host_has_two_isolated_bounded_components() -> None:
    assert sorted(host.COMPONENTS) == [
        "radius-acquisition",
        "radius-session-observation",
    ]
    assert host.COMPONENTS["radius-acquisition"]["memory_bytes"] == 512 * 1024 * 1024
    assert host.COMPONENTS["radius-session-observation"]["memory_bytes"] == 256 * 1024 * 1024
    assert all(value["cpu_percent"] == 50 for value in host.COMPONENTS.values())


def test_contract_self_check_has_no_live_effects() -> None:
    value = host.contract_self_check()
    assert value["status"] == "contract_valid"
    assert value["ephemeral_login_per_cycle"] is True
    assert value["component_advisory_lock"] is True
    assert value["admin_environment_passed_to_handler"] is False
    assert value["source_contacted"] is False
    assert value["database_accessed"] is False
    assert value["process_started"] is False


def test_cycle_result_path_stays_under_runtime_temp(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(host, "TEMP_DIR", tmp_path)
    value = host._result_path("radius-acquisition")
    assert value.parent == tmp_path
    assert value.name.startswith("plugin-cycle-acquisition-")


def test_safe_cycle_result_never_contains_credentials() -> None:
    value = host._safe_cycle_result(
        "radius-acquisition",
        {
            "status": "committed",
            "records": 12,
            "password": "forbidden",
        },
    )
    assert value["worker_result"] == {"status": "committed", "records": 12}
    assert value["contains_secret_material"] is False
    assert "password" not in str(value).casefold()


def test_core_host_materializes_only_ephemeral_plugin_dsn_to_child() -> None:
    source = Path(host.__file__).read_text(encoding="utf-8")
    assert 'dsn = os.environ.get("ADLOG_PG_DSN"' in source
    assert '"SLI_PLUGIN_PG_DSN": plugin_dsn' in source
    assert "admin_database_environment_reached_plugin_child" in source
    assert "bounded_manual_activation(admin)" in source
    assert "consumer_ephemeral_login()" in source
    assert "execute as execute_acquisition" not in source
    assert "execute as execute_consumer" not in source
    assert "active_processes=2" in source
    assert "pg_try_advisory_lock" in source
    assert "read_plugin_component_runtime_guard_v1" in source
    assert 'component_id == "radius-session-observation"' in source
    assert '("disabled", "draining", "drain_only")' in source


@pytest.mark.windows_only  # builds SystemRoot paths with Windows filesystem semantics
def test_child_environment_passes_approved_identity_without_admin_credentials(
    monkeypatch,
) -> None:
    for name in ("LOGNAME", "USER", "LNAME", "USERNAME", "USERDOMAIN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ADLOG_COLLECTION_PRINCIPAL", r"EXAMPLE\operator")
    monkeypatch.setenv(
        "ADLOG_COLLECTION_PRINCIPAL_SID",
        "S-1-5-21-100000004-200000004-300000004-6995",
    )
    monkeypatch.setattr(host, "_child_python_path", lambda: "test-site-packages")

    environment = host._child_environment("postgresql://ephemeral")

    assert environment["SLI_PLUGIN_PG_DSN"] == "postgresql://ephemeral"
    assert environment["ADLOG_COLLECTION_PRINCIPAL"] == r"EXAMPLE\operator"
    assert environment["ADLOG_COLLECTION_PRINCIPAL_SID"] == (
        "S-1-5-21-100000004-200000004-300000004-6995"
    )
    assert environment["USERNAME"] == "operator"
    assert environment["USERDOMAIN"] == "EXAMPLE"
    assert "ADLOG_PG_DSN" not in environment
    assert "ADLOG_PG_ADMIN_USER" not in environment
    assert "ADLOG_PG_ADMIN_PASSWORD" not in environment


def test_child_rejects_admin_environment(monkeypatch) -> None:
    monkeypatch.setenv("SLI_PLUGIN_PG_DSN", "postgresql://ephemeral")
    monkeypatch.setenv("ADLOG_PG_ADMIN_PASSWORD", "forbidden")
    try:
        host._child_plugin_dsn()
    except host.RemoteAccessPluginHostError as exc:
        assert str(exc) == "admin_database_environment_reached_plugin_child"
    else:
        raise AssertionError("child accepted admin environment")
