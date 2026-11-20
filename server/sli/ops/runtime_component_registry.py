"""Single canonical list of runtime components.

`scripts/maintenance/worker_supervisor.py` (`MANAGED`, `START_ORDER`),
`scripts/maintenance/worker_guard.py` (`WORKER_SCRIPTS`, `PLUGIN_WORKERS`) and
`server/sli/ops/runtime_workers.py` (`WORKER_SPECS`) used to keep three
independent literals describing the same runtime workers. They drifted:
`semantic` was missing from the supervisor's set on purpose (it is
admission-controlled, not auto-started) but nowhere declared as such, and
both RADIUS plugin components were entirely absent from the Operations
overview even though the supervisor already ran them.

This module is the one place that declares what a runtime component is. The
three call sites read it instead of keeping their own copy of the list.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Component:
    """One runtime component known to supervisor, guard and Operations.

    `is_plugin` distinguishes plugin-family components, which are addressed
    through a shared host script and a `--component <id>` argument, from
    regular workers, which each have their own entrypoint script.
    """

    name: str
    script: str
    expected_interval_seconds: int
    feature_enabled: bool
    is_plugin: bool
    plugin_component_id: str | None
    supervised: bool
    label: str
    visible_in_operations: bool = True


_COMPONENTS: tuple[Component, ...] = (
    Component(
        name="collection",
        script="collection_worker.py",
        expected_interval_seconds=600,
        feature_enabled=True,
        is_plugin=False,
        plugin_component_id=None,
        supervised=True,
        label="Сбор событий",
    ),
    Component(
        name="ad_context_snapshot",
        script="ad_context_snapshot_worker.py",
        expected_interval_seconds=1800,
        feature_enabled=False,
        is_plugin=False,
        plugin_component_id=None,
        supervised=False,
        label="Снимок Active Directory — retired (ручной rollback)",
        visible_in_operations=False,
    ),
    Component(
        name="ad_snapshot_manifest_coordinator",
        script="ad_snapshot_manifest_coordinator_worker.py",
        expected_interval_seconds=43200,
        feature_enabled=True,
        is_plugin=False,
        plugin_component_id=None,
        supervised=True,
        label="Canonical координатор manifest-снимка AD (06:00/18:00 Asia/Novosibirsk)",
    ),
    Component(
        name="ad_snapshot_projection",
        script="ad_snapshot_projection_worker.py",
        expected_interval_seconds=43200,
        feature_enabled=False,
        is_plugin=False,
        plugin_component_id=None,
        supervised=False,
        label="Теневые проекции exact manifest AD — retired (ручной rollback)",
        visible_in_operations=False,
    ),
    Component(
        name="computers_v5_snapshot",
        script="computers_report_v5_snapshot_worker.py",
        expected_interval_seconds=43200,
        feature_enabled=False,
        is_plugin=False,
        plugin_component_id=None,
        supervised=False,
        label="Снимок отчёта Компьютеры v5 — retired (ручной rollback)",
        visible_in_operations=False,
    ),
    Component(
        name="computers_v6_snapshot",
        script="computers_report_v6_snapshot_worker.py",
        expected_interval_seconds=43200,
        feature_enabled=False,
        is_plugin=False,
        plugin_component_id=None,
        supervised=False,
        label="Снимок отчёта Компьютеры — retired (ручной rollback)",
        visible_in_operations=False,
    ),
    Component(
        name="computers_v6_source",
        script="computers_v6_source_worker.py",
        expected_interval_seconds=43200,
        feature_enabled=False,
        is_plugin=False,
        plugin_component_id=None,
        supervised=False,
        label="Источник отчёта Компьютеры — retired (ручной rollback)",
        visible_in_operations=False,
    ),
    Component(
        name="users_v2_snapshot",
        script="users_report_v2_snapshot_worker.py",
        expected_interval_seconds=43200,
        feature_enabled=False,
        is_plugin=False,
        plugin_component_id=None,
        supervised=False,
        label="Снимок отчёта Пользователи — retired (ручной rollback)",
        visible_in_operations=False,
    ),
    Component(
        name="storage_v2_outbox",
        script="storage_v2_outbox_worker.py",
        expected_interval_seconds=30,
        feature_enabled=False,
        is_plugin=False,
        plugin_component_id=None,
        supervised=False,
        label="Публикация Storage V2 — retired: импорт пишет напрямую в V2 (план 6.5)",
        visible_in_operations=False,
    ),
    Component(
        name="storage_lifecycle",
        script="storage_lifecycle_worker.py",
        expected_interval_seconds=21600,
        feature_enabled=True,
        is_plugin=False,
        plugin_component_id=None,
        supervised=True,
        label="Жизненный цикл хранения",
    ),
    Component(
        name="post_collection",
        script="post_collection_worker.py",
        expected_interval_seconds=10,
        feature_enabled=True,
        is_plugin=False,
        plugin_component_id=None,
        supervised=True,
        label="Постобработка",
    ),
    Component(
        name="entity_state",
        script="entity_state_worker.py",
        expected_interval_seconds=30,
        feature_enabled=True,
        is_plugin=False,
        plugin_component_id=None,
        supervised=True,
        label="Состояния сущностей",
    ),
    Component(
        name="what_where_when_projection",
        script="what_where_when_projection_worker.py",
        expected_interval_seconds=30,
        feature_enabled=True,
        is_plugin=False,
        plugin_component_id=None,
        supervised=True,
        label="Проекция отчёта «что где когда»",
    ),
    Component(
        name="plugin_radius_acquisition",
        script="remote_access_plugin_host.py",
        expected_interval_seconds=300,
        feature_enabled=True,
        is_plugin=True,
        plugin_component_id="radius-acquisition",
        supervised=True,
        label="Сбор RADIUS-событий",
    ),
    Component(
        name="plugin_radius_session_observation",
        script="remote_access_plugin_host.py",
        expected_interval_seconds=30,
        feature_enabled=True,
        is_plugin=True,
        plugin_component_id="radius-session-observation",
        supervised=True,
        label="Наблюдение RADIUS-сессий",
    ),
    Component(
        name="semantic",
        script="semantic_production_worker.py",
        expected_interval_seconds=30,
        feature_enabled=True,
        is_plugin=False,
        plugin_component_id=None,
        supervised=True,
        label="Семантический анализ",
    ),
)

_BY_NAME: dict[str, Component] = {component.name: component for component in _COMPONENTS}


def list_components() -> tuple[Component, ...]:
    """Return every known runtime component, in canonical declaration order."""
    return _COMPONENTS


def get(name: str) -> Component:
    """Return the component named `name`. Raises `KeyError` if unknown."""
    return _BY_NAME[name]


def is_plugin(name: str) -> bool:
    """True when `name` addresses a plugin component via `--component <id>`."""
    component = _BY_NAME.get(name)
    return component is not None and component.is_plugin
