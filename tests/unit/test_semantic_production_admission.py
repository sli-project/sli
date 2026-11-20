"""The manual production owner action writes lifecycle and admission together."""
from contextlib import nullcontext
import json

import pytest

from scripts.maintenance import semantic_production_control as control


class Cursor:
    def __init__(self):
        self.calls = []

    def execute(self, query, params=()):
        self.calls.append((query, params))


@pytest.mark.parametrize("enabled", [True, False])
def test_owner_action_updates_only_the_accepted_policy(monkeypatch, enabled):
    cur = Cursor()

    def transition(actual, **kwargs):
        assert actual is cur
        assert cur.calls == [("set local role adlog_storage_worker", ())]
        assert kwargs == {
            "policy_id": control.ENABLED_POLICY_ID,
            "policy_version": control.POLICY_VERSION,
            "target_status": "enabled" if enabled else "disabled",
        }

    monkeypatch.setattr(control, "transition_risk_policy", transition)
    control._set_production_policy_status(cur, enabled=enabled)
    assert cur.calls[1] == ("set local role adlog_user", ())
    query, params = cur.calls[2]
    assert params == (control.ENABLED_POLICY_ID, control.POLICY_VERSION, enabled)
    assert "insert into semantic_policy_admission" in query
    assert "on conflict(policy_id,policy_version) do update" in query
    assert "semantic-production-control" in query


def test_failed_lifecycle_transition_cannot_write_admission(monkeypatch):
    cur = Cursor()

    def fail(*args, **kwargs):
        raise RuntimeError("fixture lifecycle rejected")

    monkeypatch.setattr(control, "transition_risk_policy", fail)
    with pytest.raises(RuntimeError, match="fixture lifecycle rejected"):
        control._set_production_policy_status(cur, enabled=True)
    assert cur.calls == [("set local role adlog_storage_worker", ())]


@pytest.mark.parametrize("enabled", [True, False])
def test_controller_couples_admission_to_the_lifecycle_transaction(monkeypatch, tmp_path, enabled):
    cur = Cursor()

    class Connection:
        in_transaction = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.in_transaction = False

        def cursor(self):
            return nullcontext(cur)

        def transaction(self):
            self.in_transaction = True
            return nullcontext()

    conn = Connection()
    monkeypatch.setattr(control, "_connect_admin", lambda: conn)
    monkeypatch.setattr(control, "_load_environment", lambda: None)
    monkeypatch.setattr(control, "_apply_migration", lambda: False)
    monkeypatch.setattr(control, "_assert_calibration", lambda _snapshot: None)
    before = {"policies": [{"policy_id": control.ENABLED_POLICY_ID,
                           "policy_version": control.POLICY_VERSION,
                           "lifecycle_status": "shadow" if enabled else "enabled"}],
              "findings": 0, "max_event_id": 1, "semantic_worker_live": False}
    after = {**before, "policies": [{**before["policies"][0],
                                   "lifecycle_status": "enabled" if enabled else "disabled"}]}
    snapshots = iter([before, after])
    monkeypatch.setattr(control, "_snapshot", lambda _cur: next(snapshots))
    changes = []

    def update(actual, *, enabled):
        assert actual is cur and conn.in_transaction
        changes.append(enabled)

    monkeypatch.setattr(control, "_set_production_policy_status", update)
    state_path = tmp_path / "production-state.json"
    state_path.write_text(json.dumps({}), encoding="utf-8")
    monkeypatch.setattr(control, "STATE_PATH", state_path)
    monkeypatch.setattr(control, "_write_state", lambda _state: None)
    result = control.activate() if enabled else control.deactivate()
    assert changes == [enabled]
    assert result["continuous_worker_started"] is False
