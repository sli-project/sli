from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
LIFECYCLE_SCRIPT = PROJECT_ROOT / "scripts" / "maintenance" / "control_center_lifecycle.py"


def test_cli_entrypoint_resolves_project_imports_outside_root(tmp_path: Path) -> None:
    for arguments, expected_action in (
        (("managed-workers",), "managed-workers"),
        (("project", "status"), "status"),
    ):
        completed = subprocess.run(
            [sys.executable, str(LIFECYCLE_SCRIPT), "--json", *arguments],
            cwd=tmp_path,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )

        assert completed.returncode == 0, completed.stderr
        assert "ModuleNotFoundError" not in completed.stderr
        result = json.loads(completed.stdout)
        assert result["contract_version"] == "control-center-lifecycle.v2"
        assert result["action"] == expected_action


def test_worker_mutation_requires_exact_action_and_worker_confirmation(tmp_path: Path) -> None:
    from scripts.maintenance import control_center_lifecycle as lifecycle
    from scripts.maintenance import worker_supervisor

    state_path = tmp_path / "control-center" / "lifecycle-intents.json"
    worker = next(iter(worker_supervisor.MANAGED))
    confirmation = lifecycle.confirmation_token("worker", "stop", worker)

    blocked = lifecycle.request_worker_action(
        "stop", worker, confirmation=None, state_path=state_path
    )

    assert blocked["status"] == "blocked"
    assert blocked["required_confirmation"] == confirmation
    assert not state_path.exists()

    accepted = lifecycle.request_worker_action(
        "stop", worker, confirmation=confirmation, state_path=state_path
    )

    assert accepted["status"] == "requested"
    assert accepted["effective"]["state"] == "pending_supervisor"
    assert lifecycle.read_worker_intent(worker, state_path=state_path)["desired_state"] == "stopped"


def test_worker_contract_allows_only_current_supervisor_managed_names(tmp_path: Path) -> None:
    from scripts.maintenance import control_center_lifecycle as lifecycle
    from scripts.maintenance import worker_supervisor

    state_path = tmp_path / "control-center" / "lifecycle-intents.json"
    current = next(iter(worker_supervisor.MANAGED))

    assert lifecycle.request_worker_action(
        "restart",
        current,
        confirmation=lifecycle.confirmation_token("worker", "restart", current),
        state_path=state_path,
    )["status"] == "requested"
    for forbidden in ("computers_v6_source", "manual-worker", "does-not-exist"):
        result = lifecycle.request_worker_action(
            "stop",
            forbidden,
            confirmation=lifecycle.confirmation_token("worker", "stop", forbidden),
            state_path=state_path,
        )
        assert result["status"] == "rejected"
        assert result["reason"] == "worker_not_supervised"


def test_supervisor_observes_durable_stop_request_for_its_owned_child(
    monkeypatch, tmp_path: Path
) -> None:
    from scripts.maintenance import control_center_lifecycle as lifecycle
    from scripts.maintenance import worker_supervisor

    worker = "collection"
    state_path = tmp_path / "control-center" / "lifecycle-intents.json"
    monkeypatch.setattr(lifecycle, "STATE_PATH", state_path)
    monkeypatch.setattr(worker_supervisor, "MANAGED", {worker: ("collection_worker.py", [])})
    monkeypatch.setattr(worker_supervisor, "START_ORDER", (worker,))
    monkeypatch.setattr(worker_supervisor, "verify_collection_identity", lambda: {"status": "ok"})
    monkeypatch.setattr(
        worker_supervisor.worker_guard,
        "evaluate_cycle",
        lambda names: {name: {"code": 9, "decision": "healthy_or_running"} for name in names},
    )
    monkeypatch.setattr(worker_supervisor, "_log", lambda *_args, **_kwargs: None)

    class OwnedChild:
        def __init__(self) -> None:
            self.terminated = 0

        def poll(self):
            return None

        def terminate(self) -> None:
            self.terminated += 1

    child = OwnedChild()
    monkeypatch.setattr(worker_supervisor, "OWNED_CHILDREN", {worker: child})
    request = lifecycle.request_worker_action(
        "stop",
        worker,
        confirmation=lifecycle.confirmation_token("worker", "stop", worker),
        state_path=state_path,
    )

    report = worker_supervisor.evaluate_once()
    intent = lifecycle.read_worker_intent(worker, state_path=state_path)

    assert request["status"] == "requested"
    assert child.terminated == 1
    assert report["workers"][worker]["action"] == "stop_requested"
    assert intent["effective"]["state"] == "stopping"


def test_project_status_never_promotes_web_only_health_to_project_success(monkeypatch) -> None:
    from scripts.maintenance import control_center_lifecycle as lifecycle

    monkeypatch.setattr(
        lifecycle,
        "web_runtime_status",
        lambda: {"state": "healthy", "evidence": "loopback health returned 200"},
    )

    result = lifecycle.project_status()

    assert result["web_runtime"]["state"] == "healthy"
    assert result["worker_supervision"]["scope"] == "all_current_supervisor_managed_workers"
    assert result["status"] != "ok"
    assert result["full_project_success"] is False
