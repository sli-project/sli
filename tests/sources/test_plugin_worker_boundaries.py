from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from server.sli.sources.plugin_worker_boundaries import (
    PluginWorkerBoundaryError,
    validate_plugin_worker_boundaries,
)


ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config" / "stage10_plugin_worker_boundaries_v1.json"


def _contract():
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def test_two_distinct_cells_are_required_and_not_live() -> None:
    result = validate_plugin_worker_boundaries(_contract())
    assert result["cell_count"] == 2
    assert result["ready_for_live_runtime"] is False
    assert {item["cell_id"] for item in result["cells"]} == {
        "radius-acquisition",
        "radius-session-observation",
    }


def test_consumer_has_no_source_network_capability() -> None:
    result = validate_plugin_worker_boundaries(_contract())
    consumer = next(
        item for item in result["cells"]
        if item["cell_id"] == "radius-session-observation"
    )
    assert consumer["network_capabilities"] == ["plugin_postgres_exact_endpoint"]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(runtime_enabled=True),
        lambda value: value["execution_cells"].pop(),
        lambda value: value["execution_cells"][1]["network_boundary"][
            "allowed_capabilities"
        ].append("radius_accounting_read_endpoint"),
        lambda value: value["execution_cells"][0]["windows_boundary"].update(
            must_be_distinct_from="radius-acquisition"
        ),
        lambda value: value["execution_cells"][0]["network_boundary"].update(
            administrative_share_allowed=True
        ),
        lambda value: value["execution_cells"][0]["postgres_boundary"].update(
            admin_environment_allowed=True
        ),
        lambda value: value["execution_cells"][0]["process_boundary"].update(
            normal_resource_profile_proven=True
        ),
    ],
)
def test_weaker_or_ambiguous_boundary_fails_closed(mutation) -> None:
    value = deepcopy(_contract())
    mutation(value)
    with pytest.raises(PluginWorkerBoundaryError):
        validate_plugin_worker_boundaries(value)


