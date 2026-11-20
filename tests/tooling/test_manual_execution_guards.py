"""Manual admission uses explicit approvals before any source or DB work."""
import importlib.util
import json
import runpy
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from scripts.maintenance import ad_snapshot_manifest_canary as canary
from scripts.maintenance import privileged_group_scope_plan as scope
from scripts.runtime import ad_snapshot_manifest_coordinator_worker as worker

NOW = datetime(2026, 10, 22, 11, 10, tzinfo=UTC)
SLOT = "2026-10-22T11:00:00Z"


@pytest.fixture(autouse=True)
def deny_effects(monkeypatch):
    def denied(*args, **kwargs):
        pytest.fail("unexpected source, database, bundle, or identity access")
    monkeypatch.setattr(worker, "connect", denied)
    monkeypatch.setattr(worker, "_collect", denied)
    monkeypatch.setattr(worker, "run_exact_manifest_projection_cycle", denied)
    monkeypatch.setattr(scope, "_identity", denied)
    monkeypatch.setattr(scope, "_latest_bundle", denied)
    monkeypatch.setattr(scope.subprocess, "run", denied)


def request(slot=SLOT):
    return {"account": r"EXAMPLE\operator", "slot_start_utc": slot,
            "window_start_utc": "2026-10-22T11:05:00Z",
            "window_end_utc": "2026-10-22T11:25:00Z", "domain_dns": "example.test"}


def test_validation_accepts_canonical_slot_without_execution():
    approved = request()
    result = canary.run(request=approved, request_hash=canary.request_sha256(approved),
                        execute=False, confirmation=None, current_account=r"example\OPERATOR",
                        coordinator=lambda **_: pytest.fail("validation executed"))
    assert result["slot_start_utc"] == SLOT
    assert result["status"] == "validated"


@pytest.mark.parametrize("slot", ["2026-10-22T00:00:00Z", "2026-10-22T12:00:00Z",
                                  "2026-10-22T11:00:01Z", "2026-10-21T23:00:00Z",
                                  "2026-10-22T23:00:00Z"])
def test_run_refuses_unapproved_schedule_before_coordinator(slot):
    approved = request(slot)
    with pytest.raises((ValueError, RuntimeError)):
        canary.run(request=approved, request_hash=canary.request_sha256(approved),
                   execute=True, confirmation=canary.EXECUTE_TOKEN,
                   current_account=r"EXAMPLE\operator", now=lambda: NOW,
                   coordinator=lambda **_: pytest.fail("unapproved slot executed"))


@pytest.fixture
def frozen_time(monkeypatch):
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW.astimezone(tz)
    monkeypatch.setattr(canary, "datetime", Clock)


@pytest.mark.parametrize("slot", ["2026-10-22T00:00:00Z", "2026-10-22T12:00:00Z",
                                  "2026-10-21T23:00:00Z", "2026-10-22T23:00:00Z"])
def test_real_adapter_refuses_invalid_or_noncurrent_slot_before_cycle(monkeypatch, frozen_time, slot):
    monkeypatch.setattr(canary, "_default_cycle", lambda *a, **k: pytest.fail("cycle reached"))
    with pytest.raises((ValueError, RuntimeError)):
        canary._coordinator(slot_start_utc=slot, domain_dns="example.test")


def test_real_adapter_passes_exact_scheduled_slot_and_actual_now(monkeypatch, frozen_time):
    result = {"slot_start_utc": SLOT, "domain_dns": "example.test"}
    cycle = Mock(return_value=result)
    monkeypatch.setattr(canary, "_default_cycle", cycle)
    assert canary._coordinator(slot_start_utc=SLOT, domain_dns="example.test") == result
    args, kwargs = cycle.call_args
    assert args == (NOW,)
    assert kwargs == {"domain_dns": "example.test",
                      "scheduled_slot": worker.scheduled_slot_from_utc(datetime.fromisoformat(SLOT))}


@pytest.mark.parametrize("readback", [{"slot_start_utc": "2026-10-21T23:00:00Z", "domain_dns": "example.test"},
                                     {"slot_start_utc": SLOT, "domain_dns": "other.test"}])
def test_real_adapter_retains_slot_and_domain_readback_guards(monkeypatch, frozen_time, readback):
    monkeypatch.setattr(canary, "_default_cycle", lambda *a, **k: readback)
    with pytest.raises(RuntimeError, match="coordinator_returned_unrequested"):
        canary._coordinator(slot_start_utc=SLOT, domain_dns="example.test")


def test_real_adapter_reaches_runtime_with_exact_schedule_and_mocked_effects(monkeypatch, frozen_time):
    from unittest.mock import MagicMock

    from server.sli.sources import ad_gpo_jobs
    monkeypatch.setattr(ad_gpo_jobs, "gpo_snapshot_enabled", lambda: True)
    connection = MagicMock()
    cursor = connection.__enter__.return_value.cursor.return_value.__enter__.return_value
    cursor.fetchall.return_value = [{"id": 7, "domain_sid": "S-1-5-21-1", "fqdn": "example.test"}]
    monkeypatch.setattr(worker, "connect", lambda: connection)
    monkeypatch.setenv("ADLOG_AD_CONTEXT_DOMAIN", "example.test")
    monkeypatch.setenv("SLI_LEGACY_COLLECTION_DISABLED", "0")
    projection = Mock(return_value={"status": "completed", "projection_results": []})
    monkeypatch.setattr(worker, "run_exact_manifest_projection_cycle", projection)
    calls = []

    def one_shot(**kwargs):
        calls.append(kwargs)
        return {"slot_start_utc": kwargs["slot_start_utc"], "domain_dns": "example.test",
                "status": "published", "manifest_id": "synthetic-manifest", "composition": {"parts": []}}

    monkeypatch.setattr(worker, "run_one_shot", one_shot)
    result = canary._coordinator(slot_start_utc=SLOT, domain_dns="example.test")
    assert result["slot_start_utc"] == SLOT
    assert len(calls) == 1
    assert calls[0]["schedule_timezone"] == "Asia/Novosibirsk"
    assert calls[0]["scheduled_local_at"] == "2026-10-22T18:00:00"
    assert calls[0]["contract_version"] == worker.V2_CONTRACT_VERSION
    assert calls[0]["execute"] is True
    cursor.execute.assert_called_once()
    projection.assert_called_once()
    assert result["retention_execution"]["reason"] == "retention_requires_full_composition"


@pytest.mark.parametrize("change,options", [({"account": "other"}, {}), ({}, {"request_hash": "0" * 64}),
                                          ({}, {"confirmation": "wrong"}),
                                          ({}, {"now": lambda: NOW.replace(minute=30)})])
def test_run_preserves_approval_guards_before_coordinator(change, options):
    approved = {**request(), **change}
    kwargs = {"request": approved, "request_hash": canary.request_sha256(approved),
              "execute": True, "confirmation": canary.EXECUTE_TOKEN,
              "current_account": r"EXAMPLE\operator", "now": lambda: NOW,
              "coordinator": lambda **_: pytest.fail("approval guard bypassed")}
    with pytest.raises(RuntimeError):
        canary.run(**{**kwargs, **options})


@pytest.mark.parametrize("expected", ["", " ", None])
def test_scope_requires_config_before_identity_or_bundle(expected):
    with pytest.raises(ValueError, match="expected_windows_identity_required"):
        scope.measure(expected_identity=expected)


def test_scope_refuses_mismatch_before_bundle(monkeypatch):
    monkeypatch.setattr(scope, "_identity", lambda: r"EXAMPLE\other")
    with pytest.raises(PermissionError, match="wrong_windows_identity"):
        scope.measure(expected_identity=r"EXAMPLE\operator")


def test_scope_normalizes_both_explicit_identities_before_bundle(monkeypatch, tmp_path):
    monkeypatch.setattr(scope, "_identity", lambda: r"example\OPERATOR")
    bundle_path = tmp_path / "synthetic.json"
    bundle_path.write_text("{}")
    bundle = {"domain": {"sid": "S-1-5-21-1", "dns_name": "example.test"},
              "sections": [{"name": "privileged_membership", "record_count": 1, "duration_ms": 1}],
              "scope": {"privileged_group_sids": []}}
    monkeypatch.setattr(scope, "_latest_bundle", lambda: (bundle_path, bundle))
    monkeypatch.setenv("WINDIR", "C:/Windows")
    live = {"domain_dns": "example.test", "directory_server": "dc.example.test",
            "groups": [{"requested_name": c["name"], "exists_in_domain": False} for c in scope.CANDIDATES]}
    monkeypatch.setattr(scope.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout=json.dumps(live)))
    result = scope.measure(expected_identity=r"EXAMPLE\operator")
    assert result["status"] == "measured"
    assert result["identity"] == r"example\operator"


def test_scope_cli_requires_explicit_identity_before_whoami(monkeypatch):
    monkeypatch.setattr(sys, "argv", [scope.__file__])
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(scope.__file__, run_name="__main__")
    assert exc.value.code == 2


def test_scope_cli_refuses_explicit_identity_mismatch(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", [scope.__file__, "--expected-identity", r"EXAMPLE\operator"])
    monkeypatch.setattr(scope.subprocess, "check_output", lambda *a, **k: r"EXAMPLE\other")
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(scope.__file__, run_name="__main__")
    assert exc.value.code == 1
    assert "wrong_windows_identity" in capsys.readouterr().out
