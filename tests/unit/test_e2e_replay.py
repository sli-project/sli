"""Safety and failure contracts for the disposable replay command."""
import importlib.util
from pathlib import Path

import pytest


def runner():
    path = Path(__file__).resolve().parents[2] / "tools/e2e/replay.py"
    assert path.exists(), "disposable replay command is missing"
    spec = importlib.util.spec_from_file_location("replay_cli", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_project_is_fixed_and_cleanup_runs_after_failure():
    replay = runner()
    calls = []

    def command(args, **kwargs):
        calls.append(args)
        if "up" in args:
            raise replay.ReplayError("stack_start_failed")
        return ""

    with pytest.raises(replay.ReplayError, match="stack_start_failed"):
        replay.execute(mode="synthetic", hours=24, command=command)
    assert calls[-2][-3:] == ["down", "--volumes", "--remove-orphans"]
    assert calls[-1] == ["docker", "rm", "--force", replay.LOCK]
    assert all(args[args.index("--project-name") + 1] == "sli-e2e"
               for args in calls if "compose" in args)


def test_protection_replay_counts_attested_current_state_without_native_events(monkeypatch):
    import io
    import json
    from types import SimpleNamespace

    from tools.e2e import scenario

    state_id = "f" * 64
    def execute(sql, params):
        assert params[0] == "workstations"
        return [{"id": state_id}] if "from sli_plugin_workstations.protection_state" in sql else []

    def get(url, **kwargs):
        assert "/reports/workstations.protection/data?" in url
        return io.BytesIO(json.dumps({"state": "partial", "items": [{"id": state_id}], "has_more": False}).encode())

    monkeypatch.setattr(scenario, "urlopen", get)
    assert scenario.api_count(SimpleNamespace(execute=execute), "workstations",
        base_url="http://localhost", report_key="workstations.protection") == (1, None)


def test_synthetic_replay_emits_empty_defender_packet_with_measured_flags(monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace

    from sli_agent.workstations import DEFENDER_CHANNEL
    from tools.e2e import synthetic

    packets = []
    monkeypatch.setattr(synthetic, "store_agent_packet", lambda *_, **kw: packets.append(kw))
    monkeypatch.setattr("server.sli.storage.storage_v2_runtime_authorization.bootstrap_fresh_runtime_authorization",
                        lambda *_, **kw: None)
    class Cursor:
        def execute(self, *args):
            return self
        def fetchone(self):
            return {"id": 17, "entity_id": 17}
    cur = Cursor()
    conn = SimpleNamespace(transaction=nullcontext, cursor=lambda: nullcontext(cur))
    synthetic.seed(conn)
    state = next(p for p in packets if p["packet"]["header"]["channel"] == DEFENDER_CHANNEL)
    assert state["event_rows"] == [] and state["packet"]["records"] == []
    assert state["envelope"]["sequence"] == 2
    assert state["packet"]["context"]["workstations"]["protection_state"]["components"]["real_time_protection_enabled"] is False


def test_refuses_to_remove_an_existing_project():
    replay = runner()
    calls = []

    def command(args, **kwargs):
        calls.append(args)
        return "occupied" if "ls" in args else ""

    with pytest.raises(replay.ReplayError, match="project_already_exists"):
        replay.execute(mode="synthetic", hours=24, command=command)
    assert not any("down" in args or "up" in args for args in calls)


@pytest.mark.parametrize("project", ["sli-e2e-fsdata", "sli-e2e-addata"])
def test_named_replay_only_cleans_its_own_project(project):
    replay = runner()
    calls = []

    def command(args, **kwargs):
        calls.append(args)
        if "up" in args:
            raise replay.ReplayError("stack_start_failed")
        return ""

    with pytest.raises(replay.ReplayError, match="stack_start_failed"):
        replay.execute(mode="synthetic", hours=24, project=project, port=18445, command=command)
    assert calls[-1] == ["docker", "rm", "--force", project + "-replay-lock"]
    assert all(args[args.index("--project-name") + 1] == project
               for args in calls if "compose" in args)
    assert "label=com.docker.compose.project=" + project in calls[0]
    assert replay.os.environ["SLI_E2E_PORT"] == "18445"
    assert replay.os.environ["SLI_E2E_IMAGE"] == project + "-code:local"


@pytest.mark.parametrize("project", ["sli", "sli-dev", "SLI-e2e", "sli-e2e/unsafe"])
def test_replay_rejects_names_outside_disposable_namespace(project):
    replay = runner()
    with pytest.raises(replay.ReplayError, match="replay_project_invalid"):
        replay.execute(mode="synthetic", hours=24, project=project, command=lambda *_: pytest.fail("docker called"))


def test_file_family_selection_reaches_the_disposable_scenario():
    replay = runner()
    calls = []
    replay.execute(mode="synthetic", hours=24, family="file-audit", command=lambda args, **kwargs: calls.append((args, kwargs)) or "")
    scenario, options = next((args, kwargs) for args, kwargs in calls if "tools.e2e.scenario" in args)
    assert scenario[-2:] == ["--family", "file-audit"]
    assert options["timeout"] == 3600  # Production-sized historical link indexes.


@pytest.mark.parametrize("port", [443, 65536])
def test_invalid_port_never_touches_docker(port):
    replay = runner()
    with pytest.raises(replay.ReplayError, match="replay_port_invalid"):
        replay.execute(mode="clone", hours=24, project="sli-e2e-addata", port=port,
                       command=lambda *a, **k: pytest.fail("invalid isolation reached Docker"))


@pytest.mark.parametrize("report,category,reason", [
    ("events.journal", None, "no_core_events_in_domain_window"),
    ("security.events.chains", None, "no_significant_security_events_in_window"),
    ("security.events.chains", "authentication", "no_authentication_events_in_window"),
])
def test_report_zero_requires_an_empty_source_population(report, category, reason):
    from tools.e2e.ad_reports import zero_reason

    assert zero_reason(report, category, 0, "empty", None) == (reason, False)
    assert zero_reason(report, category, 1, "empty", None) == ("report_empty_with_source_rows", True)


def test_error_output_never_includes_subprocess_stderr():
    replay = runner()
    import subprocess
    from unittest.mock import patch

    with patch.object(replay.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 1, stdout="private payload", stderr="password=private")), pytest.raises(replay.ReplayError) as error:
        replay.command(["docker", "info"])
    assert "private" not in str(error.value)


def test_ctrl_c_still_removes_owned_resources():
    replay = runner()
    calls = []

    def command(args, **kwargs):
        calls.append(args)
        if "up" in args:
            raise KeyboardInterrupt
        return ""

    with pytest.raises(KeyboardInterrupt):
        replay.execute(mode="synthetic", hours=24, command=command)
    assert "down" in calls[-2] and calls[-1][-1] == replay.LOCK


def test_working_dsn_is_rejected_before_connecting():
    from tools.e2e.scenario import admin_connection

    with pytest.raises(ValueError, match="replay_target_not_disposable"):
        admin_connection("host=production dbname=sli user=postgres")


@pytest.mark.parametrize("version", [1, 2])
def test_ad_cohort_matches_preserved_and_new_publication_hashes(version):
    from contextlib import nullcontext

    from server.sli.storage.event_source_identity import (
        event_identity_hash,
        legacy_event_hash,
    )
    from server.sli.storage.storage_v2_models import parse_utc_timestamp
    from tests.unit.test_event_source_identity import source
    from tools.e2e.scenario import cohort_core_ids, select_cohort

    row = source()
    fingerprint = bytes.fromhex((legacy_event_hash if version == 1 else event_identity_hash)(row))
    if version == 2:
        row = {**row, "connect_address": "fixture-transport-address"}

    class Connection:
        def __init__(self):
            self.identities = []
            self.fetched = False

        def cursor(self, **kwargs):
            return nullcontext(self)

        def copy(self, sql):
            assert sql == "copy sli_e2e.native_identity from stdin"
            return nullcontext(self)

        def write_row(self, value):
            self.identities.append(value)

        def execute(self, sql, params=()):
            if sql.startswith("create table sli_e2e.native_identity"):
                assert "normalized_hashes bytea[]" in sql
            if "select distinct e.id" in sql:
                assert "e.normalized_hash=any(n.normalized_hashes)" in sql
                assert params == (1275,)
                return [{"id": 42}] if fingerprint in self.identities[0][-1] else []

        def fetchmany(self, limit):
            if self.fetched:
                return []
            self.fetched = True
            return [{"packet_id": "fixture-packet", "source_name": "fixture-dc", "event_rows": [row]}]

        def commit(self):
            pass

    conn = Connection()
    select_cohort(conn, hours=24, family="ad-dc")
    assert conn.identities[0][4] == parse_utc_timestamp(row["time_created"])
    assert cohort_core_ids(conn, "ad-dc") == [42]
    assert conn.identities[0][-1][0] != conn.identities[0][-1][1]
    fingerprint = bytes(32)
    assert cohort_core_ids(conn, "ad-dc") == []


def test_diagnostics_keep_fixed_reasons_but_drop_values():
    from tools.e2e.scenario import safe_error

    assert safe_error("import", RuntimeError("event 123 idempotency identity or hash mismatch")) == (
        "import_failed:storage_v2_event_idempotency_mismatch")
    assert safe_error("import", ValueError("file_audit_replay_conflict")) == "import_failed:file_audit_replay_conflict"
    assert safe_error("import", ValueError("file_audit_private_account")) == "import_failed:ValueError"


def test_diagnostics_identify_allocation_conflicts_without_source_values():
    from tools.e2e.scenario import safe_error

    assert safe_error("import", RuntimeError("source event allocation hash mismatch at ordinal 123")) == (
        "import_failed:immutable_source_identity_conflict")
    assert safe_error("import", RuntimeError("published source event allocation hash mismatch at ordinal 456")) == (
        "import_failed:immutable_source_identity_conflict")


def test_retained_conflicts_cannot_hide_unexplained_failures():
    from tools.e2e.scenario import is_retained_source_conflict

    reason = "agent_projection_failed:immutable_source_identity_conflict"
    row = dict.fromkeys(("imported", "facts", "normalized", "projection", "api"), 1)
    row.update(reason=reason, pending_reasons={reason: 2})
    assert is_retained_source_conflict(row)
    row["pending_reasons"]["agent_projection_failed:RuntimeError"] = 1
    assert not is_retained_source_conflict(row)
    row["pending_reasons"] = {reason: 2}
    row["api"] = 0
    assert not is_retained_source_conflict(row)
    row.update(api=1, reason="report_empty_with_source_rows")
    assert not is_retained_source_conflict(row)
