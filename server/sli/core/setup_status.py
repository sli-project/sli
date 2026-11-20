"""Status of the first-run setup checklist («Первичная настройка»); reading only.

Aggregates what already exists: the report domain from ``platform_settings``,
AD domains from the ``domains`` table, domain controller targets from
``domain_controller_targets`` (the file ``config/domain_controllers.json`` until
the table has rows), bundled source packs and the collection
runtime status. Nothing here writes, resolves DNS or starts collection; each
section degrades to ``unavailable`` on its own, without error text.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from server.sli.core import database
from server.sli.core.platform_settings import list_settings
from server.sli.core.messages import message
from server.sli.plugins.registry import plugin_hook

ADMIN_GUIDE = "docs/ADMIN_GUIDE.md"
SOURCE_GUIDE = "docs/HOW_TO_ADD_A_SOURCE.md"


def _safe(section) -> Any:
    try:
        return section()
    except Exception:  # noqa: BLE001 - each section degrades on its own
        return None


def _report_domain() -> dict[str, Any]:
    item = next((row for row in list_settings() if row["key"] == "reports.domain_fqdn"), None)
    if item is None:
        raise LookupError("reports.domain_fqdn")
    if item.get("effective_state") == "unavailable":
        raise LookupError("report_domain_metadata_unavailable")
    value = item.get("effective_value", item["value"]) or ""
    source = item["source"] if value == item["value"] else "default" if value else "not_configured"
    result = {"key": item["key"], "value": value, "source": source}
    if item["value"] and item["value"] != value:
        result["configured_value"] = item["value"]
        result["suggested_value"] = _safe(lambda: _report_domain_suggestion(item["value"]))
    return result


def _freshness_seconds(interval):
    return max(60, interval * 2 + 30) if interval is not None and interval > 0 else None


def _report_domain_suggestion(configured):
    from server.sli.core.report_domain import suggested_domain_fqdn

    hook = plugin_hook("sli.ad", "context_interval")
    return suggested_domain_fqdn(configured, _freshness_seconds(hook() if hook else None))


def _domains() -> list[dict[str, Any]]:
    from server.sli.core.setup_domains import list_domains

    return list_domains()


def _domain_controllers() -> dict[str, Any]:
    """Targets with their source (db/file) and enabled flag; never the confirmed IP."""
    hook = plugin_hook("sli.ad", "domain_controllers")
    return hook() if hook else None


def _sources() -> list[dict[str, Any]]:
    from server.source_packs.registry import list_source_packs

    return [
        {
            "pack_id": pack["pack_id"],
            "display_name": pack["display_name"],
            "version": pack["version"],
            "source_kind": pack["source_kind"],
            "channels": pack.get("channels", []),
        }
        for pack in list_source_packs()
    ]


def _source_configuration(pack, controllers, domains, collection) -> list[dict[str, Any]] | None:
    """Ask the owning plugin about configured instances."""
    if pack["pack_id"] in ("sli.windows.ad-dc", "sli.windows.ad-context"):
        hook = plugin_hook("sli.ad", "source_configuration")
        return hook(pack, controllers, domains, collection) if hook else None
    if pack["pack_id"] == "sli.windows.vpn-radius":
        hook = plugin_hook("sli.remote-access", "source_configuration")
        return hook() if hook else None
    return None


def _source_data(pack, instances) -> dict[str, Any]:
    """Arrival time of actual data; empty successful polls are not arrivals."""
    if not instances:
        return {}
    if pack["pack_id"] in ("sli.windows.ad-dc", "sli.windows.ad-context"):
        hook = plugin_hook("sli.ad", "source_data")
        return hook(pack, instances) if hook else {}
    ids = [item["source_instance_id"].casefold() for item in instances]
    if pack["source_kind"] == "context":
        hook = plugin_hook("sli.ad", "source_data")
        return hook(pack, instances) if hook else {}
    elif pack["pack_id"] == "sli.windows.vpn-radius":
        hook = plugin_hook("sli.remote-access", "source_data")
        return hook(pack, instances) if hook else {}
    else:
        rows = database.query_rows(
            """
            select lower(server) as source_instance_id, max(created_at) as last_data_utc
            from collector_channel_runs
            where lower(server) = any(?) and lower(channel) = any(?) and inserted > 0
            group by lower(server)
            """, (ids, [channel.casefold() for channel in pack.get("channels", [])]),
        )
    return {str(row["source_instance_id"]).casefold(): row["last_data_utc"] for row in rows}


def _timestamp(value) -> datetime | None:
    try:
        stamp = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return stamp.astimezone(timezone.utc) if stamp.tzinfo is not None else None
    except (ValueError, TypeError):
        return None


def _any_state(values: list[bool | None]) -> bool | None:
    return True if any(value is True for value in values) else None if None in values else False


def _source_status(pack, controllers, domains, collection, now) -> dict[str, Any]:
    from server.sli.core.app_config import load_config

    configured = _safe(lambda: _source_configuration(pack, controllers, domains, collection))
    agent_backed = (collection is not None and "agent_collection" in collection
                    and pack["pack_id"] in ("sli.windows.ad-dc", "sli.windows.ad-context"))
    if agent_backed:
        # Retained snapshot dates are historical evidence only. They never
        # establish an assignment, activation, or current agent collection.
        if pack["source_kind"] == "context" and configured:
            history = _safe(lambda: _source_data(pack, configured)) or {}
            for item in configured:
                historical = _timestamp(history.get(item["source_instance_id"].casefold()))
                if item["last_data_utc"] is None and historical is not None:
                    item["last_data_utc"] = historical.isoformat()
        return _agent_source_status(pack, configured)
    arrivals = _safe(lambda: _source_data(pack, configured)) if configured is not None else None
    config = _safe(load_config)
    if pack["source_kind"] == "context":
        hook = plugin_hook("sli.ad", "context_interval")
        interval = hook() if hook else None
    else:
        interval = config.collector_interval_seconds if config else None
    freshness_seconds = _freshness_seconds(interval)
    instances = []
    for item in configured or []:
        raw_stamp = (arrivals or {}).get(item["source_instance_id"].casefold())
        stamp = _timestamp(raw_stamp)
        if arrivals is None or (raw_stamp is not None and (stamp is None or freshness_seconds is None or stamp > now)):
            state = "unavailable"
        elif stamp is None:
            state = "never"
        else:
            state = "fresh" if (now - stamp).total_seconds() <= freshness_seconds else "stale"
        if item["configured"] is False:
            action = "configure"
        elif item["configured"] is None or item.get("activation_blocked") or item["enabled"] is None:
            action = "check_configuration"
        elif item["enabled"] is False:
            action = "enable"
        else:
            action = None if state == "fresh" else "collect" if state == "never" else "check_data"
        instances.append({
            "source_instance_id": item["source_instance_id"], "configured": item["configured"], "enabled": item["enabled"],
            "data_received": None if state == "unavailable" else state == "fresh", "data_state": state,
            "last_data_utc": stamp.isoformat() if stamp else None, "next_action": action,
        })
    activation = _any_state([item["enabled"] for item in instances]) if configured is not None else None
    received = _any_state([item["data_received"] for item in instances]) if arrivals is not None else None
    return {
        **{key: pack[key] for key in ("pack_id", "display_name", "version", "source_kind")},
        "installed": True, "configured": _any_state([item["configured"] for item in instances]) if configured is not None else None,
        "enabled": activation is True,
        "activation_state": "unavailable" if activation is None else "enabled" if activation else "disabled",
        "data_received": received,
        "data_state": "fresh" if received else "unavailable" if received is None else (
            "stale" if any(item["data_state"] == "stale" for item in instances) else "never"
        ),
        "freshness_seconds": freshness_seconds, "instances": instances,
    }


def _agent_source_status(pack, instances):
    """Keep current delivery, assignment and historical timestamps independent."""
    known = instances is not None
    instances = instances or []
    configured = _any_state([item["configured"] for item in instances]) if known else None
    activation = _any_state([item["enabled"] for item in instances]) if known else None
    received = _any_state([item["data_received"] for item in instances]) if known else None
    return {
        **{key: pack[key] for key in ("pack_id", "display_name", "version", "source_kind")},
        "installed": True, "configured": configured, "enabled": activation is True, "collection_basis": "agents",
        "activation_state": "unavailable" if activation is None else "enabled" if activation else "disabled",
        "data_received": received,
        "data_state": "fresh" if received else "unavailable" if received is None else (
            "stale" if any(item["last_data_utc"] for item in instances) else "never"
        ),
        "freshness_seconds": None, "instances": instances,
    }


def _collection() -> dict[str, Any]:
    from server.sli.agents.collection_health import get_agent_collection_health

    health = dict(get_agent_collection_health(include_setup_bindings=True))
    bindings = health.pop("_setup_bindings", [])
    checks = [check for agent in health["items"] for module in agent["modules"]
              for check in module["channels"] if check["state"] not in ("disabled", "paused")]
    imported = [check["last_import_at"] for check in checks if check.get("last_import_at")]
    return {
        # Compatibility fields describe agent policy, not legacy admission or
        # proof that data is current. The health DTO carries operational state.
        "collection_enabled": None if health["state"] == "unavailable" else health["active_agents"] > 0,
        "block_reason": None,
        "channels": len(checks),
        "last_success_utc": max(imported, default=None),
        "agent_collection": health,
        "_agent_source_bindings": bindings,
    }


def _step(step_id: str, title: str, state: str, summary: str, **extra: Any) -> dict[str, Any]:
    return {"id": step_id, "title": title, "state": state, "summary": summary, **extra}


def build_setup_status() -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    report_domain = _safe(_report_domain)
    domains = _safe(_domains)
    controller_info = _safe(_domain_controllers)
    controllers = None if controller_info is None else [item for item in controller_info["items"] if item["enabled"]]
    sources = _safe(_sources)
    collection = _safe(_collection)
    if sources is not None:
        sources = [_source_status(pack, controller_info, domains, collection, now) for pack in sources]
    instances = [item for pack in sources or [] for item in pack["instances"]]
    ready = [item for item in instances if item["configured"] is True and item["enabled"] is True]
    fresh = [item for item in ready if item["data_received"] is True]
    source_state = "done" if ready else "unavailable" if sources is None or any(
        pack["configured"] is None or pack["activation_state"] == "unavailable" for pack in sources
    ) else "todo"
    collection_state = "done" if fresh else "unavailable" if source_state == "unavailable" or any(
        item["data_received"] is None for item in ready
    ) else "todo"
    agent_health = collection.get("agent_collection") if collection else None
    if agent_health is not None:
        collection_state = ("unavailable" if agent_health.get("diagnostics")
                            or agent_health["state"] in ("unknown", "unavailable")
                            else "done" if agent_health["state"] == "current" else "todo")
    controller_state = "unavailable" if controllers is None or collection is None else "done" if controllers else "todo"
    if agent_health is not None:
        dc_pack = next((pack for pack in sources or [] if pack["pack_id"] == "sli.windows.ad-dc"), None)
        dc_instances = dc_pack["instances"] if dc_pack else []
        controller_state = ("unavailable" if dc_pack is None or dc_pack["configured"] is None
                            or any(item.get("collection_state") in (None, "unknown") for item in dc_instances)
                            else "done" if dc_instances and all(item.get("collection_state") == "current" for item in dc_instances)
                            else "todo")
    next_step = next(({
        "pack_id": pack["pack_id"], "source_instance_id": item["source_instance_id"], "action": item["next_action"],
    } for pack in sources or [] for item in pack["instances"] if item["next_action"]), None)
    if next_step is None:
        next_step = next(({
            "pack_id": pack["pack_id"], "source_instance_id": None,
            "action": "configure" if pack["configured"] is False else "check_configuration",
        } for pack in sources or [] if not pack["instances"]), None)

    collection_summary = ("Состояние поступления данных недоступно." if collection_state == "unavailable"
                          else f"Источников со свежими данными: {len(fresh)}. Проверьте состояние конкретного источника.")
    if agent_health is not None:
        summary_state = "unavailable" if agent_health.get("diagnostics") else agent_health["state"]
        collection_summary = message(f"setup.agentCollection.{summary_state}")["text"]
    steps = [
        _step(
            "report-domain", "Домен отчётов",
            "unavailable" if report_domain is None else "done" if report_domain["source"] != "not_configured" else "todo",
            "Значение недоступно." if report_domain is None else (
                f"Домен отчётов: {report_domain['value']}." if report_domain["source"] != "not_configured"
                else "Домен отчётов не задан: укажите его на странице «Настройки платформы»."
            ),
            link="/platform-settings",
        ),
        _step(
            "domains", "Домены Active Directory",
            "unavailable" if domains is None else "done" if domains else "todo",
            "Список доменов недоступен." if domains is None else (
                f"Найдено доменов: {len(domains)}." if domains else "Домены ещё не загружены."
            ),
            manual="Домен можно добавить на этой странице (администратору) или он появится при первой загрузке данных каталога. Удалять домены нельзя: на них ссылаются события.",
            doc=ADMIN_GUIDE,
        ),
        _step(
            "domain-controllers", "Контроллеры домена",
            controller_state,
            ("Состояние агентов контроллеров недоступно." if controller_state == "unavailable" else
             f"Контроллеров с работающим агентом: {sum(item.get('collection_state') == 'current' for item in dc_instances)}.")
            if agent_health is not None else "Список контроллеров недоступен." if controllers is None else (
                f"Настроено контроллеров: {len(controllers)}." if controllers
                else "Контроллеры домена не заданы или все отключены."
            ),
            manual=(
                "Контроллеры добавляются на этой странице (администратору). Пока список берётся из файла "
                "config/domain_controllers.json, его можно перенести в базу скриптом "
                "scripts/maintenance/import_domain_controllers_from_file.py."
            ),
            doc=ADMIN_GUIDE,
        ),
        _step(
            "sources", "Источники",
            source_state,
            "Состояние источников недоступно." if source_state == "unavailable" else f"Настроено и включено экземпляров источников: {len(ready)}.",
            manual="Новые пакеты источников подключаются по инструкции разработчика.",
            doc=SOURCE_GUIDE,
        ),
        _step(
            "first-collection", "Первый сбор",
            collection_state,
            collection_summary,
            link="/operations",
        ),
    ]
    return {
        "api_version": "v1",
        "generated_at_utc": now.isoformat(),
        "read_only": True,
        "steps": steps,
        "report_domain": report_domain,
        "domains": domains or [],
        "domain_controllers": [] if controller_info is None else controller_info["items"],
        "domain_controller_source": None if controller_info is None else controller_info["source"],
        "sources": sources or [],
        "next_step": next_step,
        "collection": ({key: value for key, value in collection.items()
                        if not key.startswith("_") and key != "agent_collection"} if collection else None),
        **({"agent_collection": agent_health} if agent_health is not None else {}),
    }
