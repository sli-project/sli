from scripts.maintenance.warm_tier_resource_guard import (
    GIB,
    PROJECTED_365_DAY_FOOTPRINT_BYTES,
    evaluate_resources,
)


def _measurements() -> dict[str, object]:
    return {
        "container_running": True,
        "container_memory_limit_bytes": 4 * GIB,
        "container_memory_swap_bytes": 6 * GIB,
        "container_memory_usage_ratio": 0.24,
        "docker_engine_memory_bytes": 13 * GIB,
        "host_root_free_bytes": 84 * GIB,
        "clickhouse_volume_free_bytes": 900 * GIB,
        "container_nano_cpus": 0,
        "container_restart_policy": "no",
    }


def test_resource_guard_accepts_current_bounded_isolated_shape() -> None:
    assessment = evaluate_resources(_measurements())

    assert assessment["ready_for_isolated_warm_tier"] is True
    assert assessment["ready_for_production_cutover"] is False
    assert assessment["blockers"] == []
    assert "container_cpu_is_not_hard_capped" in assessment["warnings"]
    assert "container_has_no_automatic_restart_policy" in assessment["warnings"]
    assert PROJECTED_365_DAY_FOOTPRINT_BYTES > 33 * GIB


def test_resource_guard_fails_closed_on_memory_and_disk_pressure() -> None:
    measurements = _measurements()
    measurements.update(
        {
            "container_memory_limit_bytes": 2 * GIB,
            "container_running": False,
            "container_memory_swap_bytes": 1 * GIB,
            "container_memory_usage_ratio": 0.9,
            "docker_engine_memory_bytes": 3 * GIB,
            "host_root_free_bytes": 40 * GIB,
            "clickhouse_volume_free_bytes": 40 * GIB,
        }
    )

    assessment = evaluate_resources(measurements)

    assert assessment["ready_for_isolated_warm_tier"] is False
    assert set(assessment["blockers"]) == {
        "container_memory_limit_below_4_gib",
        "container_is_not_running",
        "container_swap_limit_below_memory_limit",
        "container_memory_usage_above_70_percent",
        "docker_engine_headroom_below_2_gib",
        "host_root_free_space_below_365_day_reserve",
        "clickhouse_volume_free_space_below_365_day_reserve",
    }
