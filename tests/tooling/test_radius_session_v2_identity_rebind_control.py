from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/maintenance/radius_session_v2_identity_rebind.py"
SPEC = importlib.util.spec_from_file_location("radius_session_v2_identity_rebind", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_control_requires_exact_confirmation_and_plan_hash() -> None:
    with pytest.raises(MODULE.RadiusSessionV2IdentityRebindControlError, match="rebind_confirmation_required"):
        MODULE.validate_apply_request({}, confirmation="wrong")


def test_control_has_no_source_cursor_or_immutable_mutation_surface() -> None:
    source = SCRIPT.read_text(encoding="utf-8").lower()
    assert "update acquisition_stream_cursors" not in source
    assert "delete from radius_accounting_session_observations" not in source
    assert "update radius_accounting_session_observations" not in source
    assert "delete from radius_session_projection_receipts" not in source
    assert "update radius_session_projection_receipts" not in source
    assert "source_contacted\": false" in source
    assert "delete from radius_vpn_session_projection" in source
