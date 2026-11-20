"""Copy static UI declarations from the frozen Python reference; no database reads."""
import ast
import json
from pathlib import Path

from server.sli.reporting.navigation_registry import load_registry
from server.sli.reporting.v2.registry import SECTION_TITLES, registered_reports
from server.sli.reporting.dashboard_fast import _dashboard_risk_projection
from server.sli.events.event_catalog import all_event_catalog_entries

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
registry, owners = load_registry()
reports = []
for definition in registered_reports():
    owner = owners[definition.key]
    reports.append({
        "key": definition.key, "title": definition.title,
        "description": definition.description, "section": definition.section,
        "section_title": SECTION_TITLES[definition.section],
        "owner_id": owner.get("owner_id", "sli.core"),
        "navigation_section": owner.get("section_id", definition.section),
        "home_order": definition.home_order,
        "home_view": next((v.to_json() for v in definition.views if v.key == definition.home_view), None),
    })
risk = _dashboard_risk_projection()
sql = risk.case_sql
for index in range(len(risk.case_params)):
    sql = sql.replace("%s", f"@risk{index}", 1)
(HERE / "declarations.json").write_text(json.dumps({
    "reports": reports, "navigation": registry,
    "important_event_ids": sorted({int(e.get("event_id") or 0) for e in all_event_catalog_entries()
        if str(e.get("purpose_tier") or "").lower() in {"critical", "important"}
        or str(e.get("base_risk") or e.get("severity") or "").lower() in {"critical", "high", "medium", "important"}}),
    "risk": {"sql": sql, "params": risk.case_params, "exact": risk.exact},
}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
tree = ast.parse((ROOT / "server/sli/agents/collection_health.py").read_text(encoding="utf-8"))
for node in tree.body:
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
        name = node.targets[0].id
        if name in {"_AGENTS_SQL", "_STREAMS_SQL"}:
            (HERE / ("agents.sql" if name == "_AGENTS_SQL" else "streams.sql")).write_text(
                ast.literal_eval(node.value).replace("?::jsonb", "@requested::jsonb").strip() + "\n", encoding="utf-8")
