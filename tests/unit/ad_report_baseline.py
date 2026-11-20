"""Load the frozen pre-PR5 implementations in an independent namespace."""
from __future__ import annotations

import gzip
import importlib
import importlib.abc
import importlib.util
import json
import sys
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from report_passport_baseline import baseline_tree


REPORT_MODULES = (
    "active_directory_reporting", "ad_account_state_reporting", "ad_group_membership_reporting",
    "ad_hygiene_policy", "ad_snapshot_change_reporting", "dc_powershell_reporting",
    "users_v2_reporting", "users_v2_views", "users_reporting", "users_activity", "users_tabs",
    "computers_v6_reporting", "computers_v6_reporting_comparison", "computers_v6_reporting_items",
    "computers_v6_reporting_overlay", "computers_v5_reporting", "computers_reporting",
    "what_where_when_reporting", "new_logon_pairs_reporting",
)
DEFINITIONS = ("ad_state", "users", "computers", "computer_logons", "new_logon_pairs")
RELOCATIONS = {
    **{f"server.sli.reports.{name}": f"server.sli.plugins.ad.reports.{name}" for name in REPORT_MODULES},
    **{f"server.sli.reporting.v2.reports.{name}": f"server.sli.plugins.ad.reports.definitions.{name}"
       for name in DEFINITIONS},
    "server.sli.entities.users_v2_directory_projection": "server.sli.plugins.ad.directory_projection",
}
PREFIX = "_ad_report_baseline"
FIXTURE = Path(__file__).with_name("fixtures") / "ad_report_sources_baseline.json.gz"
SECURITY_DELTA = Path(__file__).with_name("fixtures") / "ad_user_security_delta_pr657.json"
COMPUTER_DELTA = Path(__file__).with_name("fixtures") / "ad_computer_security_delta_pr658.json"


def security_delta():
    """Load PR657's explicit delta from its immutable implementation commit."""
    capture = json.loads(SECURITY_DELTA.read_text("utf-8"))
    assert capture["commit"] == "44564005807c169121444ff400c0ee915266831a"
    return capture


def user_security_source(source, module):
    """Extend frozen code only at the reviewed user-security replacement sites.

    All other AST nodes remain pinned. Dedicated test_ad_user_security cases
    cover the new rules, UAC boundaries, exceptions and denied raw fields.
    """
    for before, after in security_delta()["replacements"].get(module, []):
        assert before and source.count(before) == 1, (module, before)
        source = source.replace(before, after, 1)
    return source


def computer_security_delta():
    """Load PR658's explicit delta from its immutable implementation commit."""
    capture = json.loads(COMPUTER_DELTA.read_text("utf-8"))
    assert capture["commit"] == "b7aefddb57aa4f9bad48c5affc66df882832688d"
    return capture


def computer_security_source(source, module):
    """Apply only PR658's reviewed replacements; keep other AST nodes pinned.

    test_computers_ad_security covers freshness, the 90-day boundary, OS
    lifecycle, DC classification and non-secret LAPS/delegation metadata.
    """
    for before, after in computer_security_delta()["replacements"].get(module, []):
        assert before and source.count(before) == 1, (module, before)
        source = source.replace(before, after, 1)
    return source


def report_locale_source(source, module):
    """Pin PR818's additive message envelopes without replacing frozen code.

    The immutable PR head supplies only these explicit replacement sites.
    Locale behavior and original observed values have independent assertions
    in test_report_locale_codes and test_ui_audit_i18n.
    """
    path = Path(__file__).with_name("fixtures") / "ad_report_locale_delta_pr818.json"
    capture = json.loads(path.read_text("utf-8"))
    assert capture["commit"] == "d449b320a3839affb96b2fa15b4c3c358116593e"
    for before, after in capture["replacements"].get(module, []):
        assert before and source.count(before) == 1, (module, before)
        source = source.replace(before, after, 1)
    return source


def directory_repair_source(source, name):
    """Apply PR653's explicit deltas without replacing the frozen relocation code.

    Name ownership, standard-group recognition and tab behavior have dedicated
    tests. Every other source node and report contract must still match exactly.
    """
    replacements = ()
    if name == "users_tabs":
        replacements = (
            ('Column("privilege_basis", "Основание прямых привилегий", "list")',
             'Column("privilege_basis", "Основание привилегий", "list")'),
            ('            direct = user.get("privilegedMemberships")',
             '            direct = user.get("privilegedMemberships")\n'
             '            effective = [group for group in (user.get("memberships") or {}).get("effective") or [] if group.get("watchGroup")]'),
            ('[group.get("name") for group in (user.get("memberships") or {}).get("effective") or [] if group.get("watchGroup") and group.get("relation") == "nested"]',
             '[group.get("name") for group in effective if group.get("relation") == "nested"]'),
            ('            included = bool(row["privilege_basis"])',
             '            row["privilege_basis"] += [group.get("name") or group.get("id") for group in effective if group.get("relation") in {"direct", "primary"} and group.get("name") not in row["privilege_basis"]]\n'
             '            included = bool(row["privilege_basis"] or row["nested_privilege_groups"])'),
            ('            if context.params.get("group"):',
             '            for group in effective:\n'
             '                group_id = str(group.get("id") or "")\n'
             '                if group_id:\n'
             '                    direct_ids.update({group_id, group_id.removeprefix("group:")})\n'
             '                    group_options[group_id] = group.get("name") or group_id\n'
             '            if context.params.get("group"):'),
            ('            unknown += "unknown" in {row["password_age_policy"], row["inactivity_policy"]}',
             '            if "unknown" in {row["password_age_policy"], row["inactivity_policy"]} and matches(user, row, match_params):\n'
             '                unknown += 1'),
            ('Полнота прямых privileged_membership связей не подтверждена; вложенное членство не является основанием включения.',
             'Полнота привилегированного членства не подтверждена; показаны известные прямые, основные и вложенные связи.'),
            ('                            "unknown_accounts": unknown, "hygiene_policy": policy, "truncated": truncated,',
             '                            "unknown_accounts": unknown, "hygiene_policy": policy, "truncated": truncated,\n'
             '                            **({"risk_accounts": len(selected)} if tab == "risk" else {}),'),
        )
    elif name == "users_v2_directory_projection":
        replacements = (
            ('import json\n', 'import json\nimport re\n'),
            ('def _mapping(value: Any) -> dict[str, Any]:',
             r'''STANDARD_ADMIN_DOMAIN_RIDS = frozenset({512, 518, 519, 520})
STANDARD_ADMIN_BUILTIN_RIDS = frozenset({544, 548, 549, 550, 551})


def _standard_admin_group(attrs: Mapping[str, Any], aliases: Mapping[str, str]) -> bool:
    sid = str(aliases.get("object_sid") or attrs.get("sid") or "").casefold()
    domain = re.fullmatch(r"s-1-5-21-\d+-\d+-\d+-(\d+)", sid)
    if domain:
        return int(domain[1]) in STANDARD_ADMIN_DOMAIN_RIDS or str(attrs.get("sam_account_name") or aliases.get("sam_account_name") or "").casefold() == "dnsadmins"
    builtin = re.fullmatch(r"s-1-5-32-(\d+)", sid)
    return bool(builtin and int(builtin[1]) in STANDARD_ADMIN_BUILTIN_RIDS)


def _mapping(value: Any) -> dict[str, Any]:'''),
            ('"watchGroup": watch_group,', '"watchGroup": watch_group or _standard_admin_group(attrs, aliases),'),
            ('            merged.update(version.get("attributes") or {})',
             '            incoming = dict(version.get("attributes") or {})\n'
             '            if section != "directory_accounts":\n'
             '                incoming.pop("display_name", None)\n'
             '            merged.update(incoming)'),
        )
    for before, after in replacements:
        assert source.count(before) == 1
        source = source.replace(before, after, 1)
    return source


def relocate_imports(source, mapping):
    for old, new in sorted(mapping.items(), key=lambda item: -len(item[0])):
        source = source.replace(old, new)
    return source.replace("from server.sli.reports import", f"from {PREFIX}.reports import")


def report_additions_source(source, module, *, synthetic=False):
    """Pin PR717's columns and grants without regenerating frozen captures.

    Parity readers have no DNS/workplace observations and an empty agent
    registry. Spell out those results independently; the supplement engine's
    matching, provenance and access behavior is tested in test_ad_report_additions.
    """
    if module == "server.sli.reporting.v2.reports.users":
        replacements = [
            ('ROW_CATEGORIES.update(users_tabs.ROW_CATEGORIES)',
             'ROW_CATEGORIES.update(users_tabs.ROW_CATEGORIES)\n'
             'ROW_CATEGORIES["last_workplace"] = frozenset({"security", "technical"})'),
            ('        Column("activity", "Последняя активность", "datetime", path="activity_at", sortable=True),',
             '        Column("activity", "Последняя активность", "datetime", path="activity_at", sortable=True),\n'
             '        Column("last_workplace", "Последнее рабочее место", component="ad.last-workplace"),'),
        ]
        if synthetic:
            replacements.append((
                'ROW_CATEGORIES["last_workplace"] = frozenset({"security", "technical"})',
                'ROW_CATEGORIES["last_workplace"] = frozenset({"security", "technical"})\n'
                'ROW_CATEGORIES["membership_paths"] = frozenset({"privilege"})',
            ))
            replacements.append((
                '    counts = {key: sum(1 for user, row in rows if _in_view(key, user, row, observed_at)) for key, _ in VIEWS}',
                '    for user, row in rows:\n'
                '        if allowed(ROW_CATEGORIES["membership_paths"]):\n'
                '            row["membership_paths"] = (user.get("memberships") or {}).get("paths")\n'
                '        if allowed(ROW_CATEGORIES["last_workplace"]):\n'
                '            row["last_workplace"] = None\n'
                '    counts = {key: sum(1 for user, row in rows if _in_view(key, user, row, observed_at)) for key, _ in VIEWS}',
            ))
        else:
            replacements.append((
                'from server.sli.reports import ad_hygiene_policy, review_catalog, review_checks, users_activity, users_tabs',
                'from server.sli.reports import ad_hygiene_policy, report_additions, review_catalog, review_checks, users_activity, users_tabs',
            ))
    elif module == "server.sli.reporting.v2.reports.computers":
        replacements = [(
            '        Column("ip_addresses", "IP-адреса", path="ip_text", sortable=True, optional=True),',
            '        Column("ip_addresses", "IP по DNS на дату снимка", path="dns_ip.addresses", component="ad.dns-ip"),\n'
            '        Column("sli_agent", "Агент SLI", component="ad.agent"),',
        )]
        if synthetic:
            replacements.append((
                '    items = [_row(item) for item in raw.get("items") or []]',
                '    items = [_row(item) for item in raw.get("items") or []]\n'
                '    for item in items:\n'
                '        item["dns_ip"] = {"state": "not_collected", "addresses": [], "observed_at_utc": None}\n'
                '        item["sli_agent"] = {"state": "absent", "version": None, "last_seen_utc": None,\n'
                '                             "age_seconds": None, "reason": "no_registry_match"}',
            ))
        else:
            replacements.append((
                'from server.sli.reports import review_catalog, review_checks',
                'from server.sli.reports import report_additions, review_catalog, review_checks',
            ))
    else:
        return source
    for before, after in replacements:
        assert source.count(before) == 1, (module, before)
        source = source.replace(before, after, 1)
    return source


def review_checks_source(source, module):
    """Pin PR703's integration delta; preserve every unrelated source node.

    The checks engine has separate synthetic behavior/access tests. These
    literal replacements describe its two adapters, never the candidate AST.
    """
    if module not in {"server.sli.reporting.v2.reports.users", "server.sli.reporting.v2.reports.computers"}:
        return source
    kind = module.rsplit(".", 1)[-1]
    replacements = [
        ('def _query(context: QueryContext) -> dict[str, Any]:',
         'def _query(context: QueryContext) -> dict[str, Any]:\n'
         '    if context.tab == "checks":\n'
         f'        return review_checks.query(REPORT, context, "{kind}")'),
    ]
    if kind == "users":
        replacements += [
            ('from server.sli.reports import ad_hygiene_policy, users_activity, users_tabs',
             'from server.sli.reports import ad_hygiene_policy, review_catalog, review_checks, users_activity, users_tabs'),
            ('from server.sli.core import ad_service_exceptions',
             'from server.sli.core import ad_service_exceptions\nfrom server.sli.core.messages import message'),
            ('                for key, title in users_tabs.TABS.items()),',
             '                for key, title in users_tabs.TABS.items()) + (\n'
             '                    View("table", "checks", message(review_catalog.PREFIX + "tab")["text"],\n'
             '                         source="checks", columns=review_catalog.columns(), access=AccessRule(REPORT_KEY, review_catalog.FIELDS)),\n'
             '                ),'),
        ]
    else:
        replacements += [
            ('from typing import Any\n', 'from typing import Any\n\nfrom dataclasses import replace\n\n'
             'from server.sli.core.messages import message\nfrom server.sli.reports import review_catalog, review_checks\n'),
            ('    ReportIntent,\n', '    ReportIntent,\n    View,\n'),
        ]
    for before, after in replacements:
        assert source.count(before) == 1, (module, before)
        source = source.replace(before, after, 1)
    if kind == "computers":
        source += '''
REPORT = replace(REPORT, views=(
    View("table", "computers", "Компьютеры"),
    View("table", "checks", message(review_catalog.PREFIX + "tab")["text"],
         source="checks", columns=review_catalog.columns("computers"), access=AccessRule(REPORT_KEY, review_catalog.COMPUTER_FIELDS)),
))
'''
    return source


def users_workspace_source(source, module):
    """Pin PR742's owner-approved workspace delta, keeping frozen sources intact.

    test_users_mockup_contract covers the new views, history and export behavior;
    every other AST node remains protected by the relocation comparison.
    _prepare already has its independently tested domain-selection exemption.
    """
    if module == "server.sli.reports.users_tabs":
        replacements = (
            ('from server.sli.reporting.v2.definition import Column, result, sort_rows',
             'from server.sli.reporting.v2.definition import AccessRule, Column, result, sort_rows'),
            ('TABS = {"active": "Активные",', 'TABS = {"all": "Все учётки", "active": "Активные",'),
            ('next(view.access for view in report.views if view.key == tab)', 'AccessRule("security.queue", scope="delegated")'),
            ('        included = user.get("enabled") is (tab == "active") if tab in {"active", "disabled"} else False',
             '        included = user.get("enabled") is (tab == "active") if tab in {"active", "disabled"} else tab == "all"\n'
             '        account_state = context.params.get("account_state")\n'
             '        if tab == "all" and account_state:\n'
             '            included = user.get("enabled") is {"enabled": True, "disabled": False, "unknown": None}[account_state]'),
            ('                            "unknown_accounts": unknown, "hygiene_policy": policy, "truncated": truncated,',
             '                            "as_of": context.params.get("as_of") if tab == "privileged" else None, "population": len(data["users"]),\n'
             '                            "unknown_accounts": unknown, "hygiene_policy": policy, "truncated": truncated,'),
        )
    elif module == "server.sli.reporting.v2.reports.users":
        replacements = (
            ('from dataclasses import replace\n', 'from dataclasses import replace\nfrom datetime import date, datetime, timedelta, timezone\n'),
            ('from typing import Any\n', 'from typing import Any\nfrom zoneinfo import ZoneInfo\n'),
            ('ROW_CATEGORIES["last_workplace"] = frozenset({"security", "technical"})',
             'ROW_CATEGORIES["last_workplace"] = frozenset({"security", "technical"})\n'
             'ROW_CATEGORIES["membership_paths"] = frozenset({"privilege"})'),
            ('"activity_type": frozenset({"security"})}',
             '"activity_type": frozenset({"security"}),\n'
             '                    "check": review_catalog.FIELDS, "as_of": frozenset({"security", "privilege"}),\n'
             '                    "account_state": frozenset({"security"})}'),
            ('    if context.tab == "checks":', '    if context.tab in {None, "checks"}:'),
            ('        collections["changes"] = compare(current, data["payload"].get("previous"))',
             '        collections["changes"] = [{**row, "observed_at_utc": metadata.get("observed_at")}\n'
             '                                  for row in compare(current, data["payload"].get("previous"))\n'
             '                                  if not context.params.get("q") or _fold(context.params["q"]) in _fold(f"{row.get(\'display_name\')} {row.get(\'sam\')}")]'),
            ('        filtered_count=len(data["selected"]),',
             '        filtered_count=len(collections["changes"]) if context.tab == "changes" else len(data["selected"]),'),
            ('        window={"from_utc": metadata.get("observed_at"), "to_utc_exclusive": metadata.get("completed_at")},',
             '        window={"from_utc": ((data["payload"].get("previous") or {}).get("metadata") or {}).get("observed_at") if context.tab == "changes" else metadata.get("observed_at"),\n'
             '                "to_utc": metadata.get("observed_at")},'),
            ('def _export(context: QueryContext) -> tuple[str, dict[str, Any]]:\n    if context.tab is None or context.tab in users_tabs.TABS:',
             'def _export(context: QueryContext) -> tuple[str, dict[str, Any]]:\n'
             '    if context.tab in {None, "checks", "changes"}:\n'
             '        payload = _query(replace(context, cursor=None, limit=100_000))\n'
             '        if payload["state"] in {"error", "not_collected", "denied"}:\n'
             '            raise PermissionError("report_access_denied")\n'
             '        view = next(view for view in REPORT.views if view.key == (context.tab or "checks"))\n'
             '        rows = [row for row in payload.get("collections", {}).get(view.source, payload["items"]) if row.get("section") != "not_evaluated"]\n'
             '        return csv_from_columns(view.columns, rows), {"rows": len(rows), "truncated": bool(payload["coverage"].get("truncated") or payload["coverage"].get("events_truncated"))}\n'
             '    if context.tab in users_tabs.TABS:'),
            ('''    views=tuple(View("table", key, title, access=AccessRule(REPORT_KEY, users_tabs.FIELDS[key]))
                if key != "semantic" else View("table", key, title, access=AccessRule("security.queue", scope="delegated"))
                for key, title in users_tabs.TABS.items()) + (
                    View("table", "checks", message(review_catalog.PREFIX + "tab")["text"],
                         source="checks", columns=review_catalog.columns(), access=AccessRule(REPORT_KEY, review_catalog.FIELDS)),
                ),''',
             '''    views=(View("table", "checks", message(review_catalog.PREFIX + "tab")["text"],
                source="checks", columns=review_catalog.columns(), access=AccessRule(REPORT_KEY, review_catalog.FIELDS)),
           View("table", "privileged", "Привилегированные", access=AccessRule(REPORT_KEY, users_tabs.FIELDS["privileged"])),
           replace(next(view for view in REPORT.views if view.key == "changes"),
                   columns=(Column("observed_at_utc", "Наблюдение снимка", "datetime"),
                            *next(view for view in REPORT.views if view.key == "changes").columns,
                            Column("actor", "Исполнитель"))),
           View("table", "all", "Все учётки", access=AccessRule(REPORT_KEY, users_tabs.FIELDS["all"]))),'''),
            ('"ou", "group", "relation"}),\n    presets=(),',
             '"ou", "group", "relation"}) + (\n'
             '        Param("check", "Проверка", "text", hidden=True), Param("as_of", "Состав на дату", "text", hidden=True),\n'
             '        Param.choice("account_state", "Состояние", (("enabled", "Включена"), ("disabled", "Отключена"), ("unknown", "Нет данных"))),\n'
             '    ),\n    default_limit=50,\n    presets=(),'),
            ('def _prepare(context: QueryContext) -> dict[str, Any]:', '''def _dated_snapshot(context: QueryContext) -> dict[str, Any]:
    """Use the accepted daily source at that date; never substitute current AD."""
    day = date.fromisoformat(str(context.params["as_of"]))
    zone = ZoneInfo(context.timezone)
    today = datetime.now(zone).date()
    if day > today or day < today - timedelta(days=365):
        raise ValueError("report_as_of_invalid")
    cutoff = (datetime.combine(day + timedelta(days=1), datetime.min.time(), zone) - timedelta(microseconds=1)).astimezone(timezone.utc)
    bundles = review_checks.load_snapshots("users", context.domain_ids, cutoff.isoformat())
    snapshots = [bundle.get("baseline") for bundle in bundles]
    if not any(snapshots):
        return {"state": "not_collected"}
    domains = [{"domain_id": bundle["domain_id"], "domain_name": bundle["domain_name"],
                "observed_at_utc": (bundle.get("baseline") or {}).get("observed_at"),
                "state": (bundle.get("baseline") or {}).get("state", "not_collected")} for bundle in bundles]
    complete = bool(bundles) and all(snapshot and snapshot.get("state") in review_checks.COMPLETE
                                     and review_checks._time(snapshot.get("observed_at")) for snapshot in snapshots)
    current = {"users": [{**obj, "domainId": bundle["domain_id"], "domainName": bundle["domain_name"],
                          "sourceStates": {**(obj.get("sourceStates") or {}), "directory": {
                              **((obj.get("sourceStates") or {}).get("directory") or {}),
                              "observed_at": bundle["baseline"]["observed_at"]}}}
                         for bundle in bundles if bundle.get("baseline") for obj in bundle["baseline"]["objects"]],
               "groups": [], "metadata": {"observed_at": min((str(domain["observed_at_utc"]) for domain in domains if domain["observed_at_utc"]), default=None),
                   "collection_status": "complete" if complete else "partial", "coverage": {
                       "state": "complete" if complete else "partial", "domains": domains,
                       "privilege_state": "complete" if complete else "partial"}}}
    return {"state": "ok", "current": current, "previous_state": "not_requested"}


def _prepare(context: QueryContext) -> dict[str, Any]:'''),
        )
    else:
        return source
    for before, after in replacements:
        assert source.count(before) == 1, (module, before)
        source = source.replace(before, after, 1)
    return source


def review_checks_definition(definition):
    """Add only PR703's independently declared view metadata to frozen code."""
    from server.sli.reporting.v2.definition import AccessRule, Column, Param, View

    if definition.key not in {"ad.users.v2", "ad.computers.v6"}:
        return definition
    fields = frozenset({"identity_basic", "technical", "security"})
    if definition.key == "ad.users.v2":
        fields |= {"privilege"}
        assert [view.key for view in definition.views] == ["all", "active", "disabled", "privileged", "risk", "semantic"]
        views = definition.views
    else:
        assert definition.views == (View("table"),)
        views = (View("table", "computers", "Компьютеры"),)
    columns = tuple(Column("check_" + key, label, kind, path=path, field_categories=fields)
                    for key, label, kind, path in (
                        ("severity", "Важность", "text", "severity_text"),
                        ("title", "Проверка", "text", "title"), ("objects", "Объекты", "list", "objects"),
                        ("status_text", "Статус", "text", "status_text"), ("new_count", "Новых", "number", "new_count"),
                        ("total", "Всего", "number", "total"), ("why", "Чем опасно", "text", "why"),
                        ("action", "Что сделать", "text", "action"), ("remediation", "Как исправить", "text", "remediation"),
                    ))
    check_view = View("table", "checks", "Требуют проверки", source="checks",
                      columns=columns, access=AccessRule(definition.key, fields))
    if definition.key == "ad.computers.v6":
        # adimpl4 intentionally replaces the computer views. Pin the accepted
        # metadata independently; the original captures/checksums stay immutable.
        roles = {"workstation": "Рабочая станция", "server": "Сервер",
                 "domain_controller": "Контроллер домена", "unknown": "Не определён"}
        changes = View("table", "changes", "Изменения", source="changes", columns=(
            Column("display_name", "Компьютер"), Column("computer_type", "Роль", "state", labels=roles),
            Column("observed_at_utc", "Наблюдение снимка", "datetime"),
            Column("change_type", "Изменение", "state", labels={
                "new_object": "Впервые обнаружен", "missing_current": "Отсутствует в текущем снимке",
                "enabled_changed": "Состояние учётной записи", "ou_changed": "Перенесён в OU",
                "os_changed": "Изменена ОС", "ip_changed": "Изменены адреса",
                "site_changed": "Изменён AD-сайт", "managed_by_changed": "Изменён управляющий",
                "classification_changed": "Изменена роль", "quality_changed": "Изменилось качество данных",
                "semantic_changed": "Изменились связанные находки",
                "delegation_changed": "Изменено делегирование", "laps_changed": "Изменены метаданные LAPS",
            }), Column("field", "Атрибут", "state", labels={
                "presence": "Наличие в снимке", "enabled": "Учётная запись включена", "ou_path": "OU",
                "operating_system": "ОС", "computer_type": "Роль", "laps_password_expiration_utc": "Срок LAPS",
                "unconstrained": "Неограниченное делегирование", "constrained": "Ограниченное делегирование",
                "resource_based": "Ресурсное делегирование (RBCD)",
            }), Column("before", "Было"), Column("after", "Стало"), Column("actor", "Исполнитель"),
            Column("limitation", "Ограничение", optional=True),
        ))
        return replace(definition, views=(check_view, changes, View("table", "computers", "Все компьютеры")),
                       params=tuple(replace(param, default="all", hidden=True) if param.key == "view" else param
                                    for param in definition.params),
                       columns=tuple(replace(column, link=None) if column.key == "display_name" else column
                                     for column in definition.columns))
    # adimpl3 replaces the user workspace. This literal delta preserves the
    # original captures and checksums independently of the candidate code.
    changes = View("table", "changes", "Изменения", source="changes",
                   note="Сравнение двух последних снимков; отсутствие объекта не доказывает его удаление.", columns=(
        Column("observed_at_utc", "Наблюдение снимка", "datetime"),
        Column("name", "Пользователь", path="display_name", link="/app/entities/{entity_id}"),
        Column("change", "Изменение", path="label"), Column("field", "Поле / связь", path="field"),
        Column("before", "Было", path="before"), Column("after", "Стало", path="after"),
        Column("group", "Категория", path="change_group"), Column("note", "Примечание", path="note"),
        Column("actor", "Исполнитель"),
    ))
    return replace(definition, views=(check_view, next(view for view in views if view.key == "privileged"),
                                     changes, View("table", "all", "Все учётки", access=AccessRule(definition.key, frozenset({"security"})))), default_limit=50,
                   row_categories={**definition.row_categories, "membership_paths": frozenset({"privilege"})},
                   params=(*definition.params,
                       Param("check", "Проверка", "text", hidden=True, field_categories=fields),
                       Param("as_of", "Состав на дату", "text", hidden=True, field_categories=frozenset({"security", "privilege"})),
                       replace(Param.choice("account_state", "Состояние", (("enabled", "Включена"), ("disabled", "Отключена"), ("unknown", "Нет данных"))),
                               field_categories=frozenset({"security"}))))


class BaselineLoader(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def __init__(self):
        self.capture = json.loads(gzip.decompress(FIXTURE.read_bytes()))
        self.mapping = {old: new.replace("server.sli.plugins.ad", PREFIX) for old, new in RELOCATIONS.items()}
        self.mapping["server.api.routes.reports"] = f"{PREFIX}.api.reports"
        self.mapping["server.sli.plugins.ad.reports.computer_security"] = f"{PREFIX}.reports.computer_security"
        self.sources = {self.mapping[name]: report_additions_source(computer_security_source(user_security_source(
                            directory_repair_source(source, name.rsplit(".", 1)[-1]), name), name), name, synthetic=True)
                        for name, source in self.capture["sources"].items()}
        state = "server.sli.reporting.v2.reports.ad_state"
        self.sources[self.mapping[state]] = report_locale_source(self.sources[self.mapping[state]], state)
        tabs = "server.sli.reports.users_tabs"
        self.sources[self.mapping[tabs]] = users_workspace_source(self.sources[self.mapping[tabs]], tabs)
        self.sources.update({f"{PREFIX}.{name}": source for name, source in security_delta()["sources"].items()})
        self.sources.update({f"{PREFIX}.{name}": source for name, source in computer_security_delta()["sources"].items()})

    def find_spec(self, fullname, path=None, target=None):
        if fullname in self.sources:
            return importlib.util.spec_from_loader(fullname, self)
        if fullname in {PREFIX, f"{PREFIX}.reports", f"{PREFIX}.reports.definitions", f"{PREFIX}.api"}:
            return importlib.util.spec_from_loader(fullname, self, is_package=True)
        return None

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        source = self.sources.get(module.__name__)
        if source is not None:
            source = relocate_imports(source, self.mapping)
            tree = baseline_tree(source, module.__name__.rsplit(".", 1)[-1])
            exec(compile(tree, f"<pre-PR5:{module.__name__}>", "exec"), module.__dict__)
            if module.__name__ in {f"{PREFIX}.reports.definitions.users", f"{PREFIX}.reports.definitions.computers"}:
                module.REPORT = review_checks_definition(module.REPORT)


@contextmanager
def baseline_modules():
    loader = BaselineLoader()
    sys.meta_path.insert(0, loader)
    try:
        yield lambda suffix: importlib.import_module(f"{PREFIX}.{suffix}")
    finally:
        sys.meta_path.remove(loader)
        for name in tuple(sys.modules):
            if name == PREFIX or name.startswith(PREFIX + "."):
                sys.modules.pop(name)
