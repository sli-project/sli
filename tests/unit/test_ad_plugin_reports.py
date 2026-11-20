"""PR5 relocation parity against independent, frozen pre-relocation code."""
from __future__ import annotations

import ast
import gzip
import hashlib
import importlib
import io
import json
import pkgutil
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ad_report_baseline import (
    DEFINITIONS, FIXTURE, RELOCATIONS, baseline_modules, computer_security_source,
    directory_repair_source, report_additions_source, report_locale_source, review_checks_source, user_security_source, users_workspace_source,
)
from new_logon_pairs_baseline import new_logon_pairs_source
from report_passport_baseline import baseline_tree, domain_selection_metadata
from server.sli.access import domain_scope
from server.api.routes import reports as legacy_routes
from server.api.routes import reports_v2 as routes
from server.sli.plugins import registry as plugins
from server.sli.plugins import update_runtime
from server.sli.reporting.v2 import registry
from server.sli.reporting.v2.access import ReportAccess
from server.sli.reporting.v2.definition import QueryContext
from server.sli.reporting.v2.definition import ReportDefinition


ROOT = Path(__file__).resolve().parents[2]
PERIOD = {"preset": "custom", "from_utc": "2026-10-09T10:00:00+00:00", "to_utc": "2026-10-09T11:00:00+00:00"}
KEYS = {"ad.infrastructure", "ad.users.v2", "ad.computers.v6", "ad.computer-logons", "ad.new-logon-pairs"}


@pytest.fixture(autouse=True)
def isolated_readers(monkeypatch):
    monkeypatch.delenv("SLI_PLUGIN_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("SLI_PLUGIN_LOCK_DIR", raising=False)
    monkeypatch.setattr(update_runtime, "_pinned", {})
    # PR657 adds this settings reader; keep the no-database guard below intact.
    monkeypatch.setattr("server.sli.core.ad_service_exceptions.configured", dict)
    # PR717 reads the agent registry in addition to the frozen inventory reader.
    # Keep the connection guard below and allow only this synthetic empty read.
    def empty_supplements(sql, params=(), **kwargs):
        assert "/* ad_report_agent_registry */" in sql
        return []
    monkeypatch.setattr("server.sli.plugins.ad.reports.report_additions.query_rows_bounded", empty_supplements)
    monkeypatch.setattr(domain_scope, "_domain_rows", lambda ids: [
        {"id": key, "fqdn": f"domain-{key}.example.test",
         "display_name": f"domain-{key}.example.test", "is_archived": False} for key in ids
    ])
    # T005 declaration metadata reads the saved preference; keep all real DB
    # entrypoints forbidden and admit only this synthetic settings read.
    def stored_preference(key):
        assert key == "reports.domain_fqdn"
        return {"value": "domain-1.example.test"}
    monkeypatch.setattr("server.sli.core.platform_settings._stored_row", stored_preference)
    plugins.registered_plugins.cache_clear()
    registry.registered_reports.cache_clear()
    def forbidden(*args, **kwargs):
        pytest.fail("AD report parity must use synthetic readers, never a database")
    for target in ("server.sli.core.postgres_runtime_pipeline.connect", "server.sli.core.database.query_rows",
                   "server.sli.core.database.query_rows_bounded"):
        monkeypatch.setattr(target, forbidden)
    yield
    plugins.registered_plugins.cache_clear()
    registry.registered_reports.cache_clear()


@pytest.fixture
def baseline():
    with baseline_modules() as load:
        yield load


def candidate(name):
    return importlib.import_module(f"server.sli.plugins.ad.reports.definitions.{name}")


def outcome(callback, *args):
    try:
        return {"value": callback(*args)}
    except (ValueError, PermissionError, LookupError) as exc:
        return {"error": type(exc).__name__, "message": str(exc)}


def test_plugin_owns_exactly_five_definitions_and_scanner_has_no_duplicates():
    contributed = plugins.registered_plugins()["sli.ad"].hooks["reports"]()
    assert {definition.key for definition in contributed} == KEYS
    assert set(DEFINITIONS) <= plugins.PLUGIN_REPORT_MODULES
    found = registry.registered_reports(validate_intents=True)
    assert [definition.key for definition in found if definition.key in KEYS].count("ad.infrastructure") == 1
    assert sorted(definition.key for definition in found if definition.key in KEYS) == sorted(KEYS)


def test_absent_plugin_does_not_discover_adapters(monkeypatch):
    monkeypatch.setattr(plugins, "BUNDLED", {key: value for key, value in plugins.BUNDLED.items() if key != "sli.ad"})
    assert not KEYS.intersection(definition.key for definition in registry.registered_reports())


def test_registry_preserves_pre_relocation_catalog_order(baseline):
    from server.sli.reporting.v2 import reports as package
    from server.sli.plugins.workstations.reports import REPORTS, make_report

    expected = []
    for info in sorted(pkgutil.iter_modules(package.__path__), key=lambda item: item.name):
        if info.name in {"vpn_audit", "vpn_connections", "nps_policy_denials"}:
            continue
        module = (baseline("reports.definitions." + info.name) if info.name in DEFINITIONS
                  else importlib.import_module(package.__name__ + "." + info.name))
        definition = getattr(module, "REPORT", None)
        if isinstance(definition, ReportDefinition):
            expected.append(definition.key)
    for plugin_id, contribution in plugins.registered_plugins().items():
        if plugin_id not in {"sli.ad", "sli.gpo"} and "reports" in contribution.hooks:
            expected.extend(definition.key for definition in contribution.hooks["reports"]())
    expected.extend(make_report(family).key for family in REPORTS)
    # The new product appends after every pre-existing catalog entry.
    expected.append("workstations.overview")
    assert [definition.key for definition in registry.registered_reports()] == expected


@pytest.mark.parametrize("old,new", RELOCATIONS.items())
def test_compatibility_import_shares_module_and_executable(old, new):
    assert importlib.import_module(old) is importlib.import_module(new)


def canonical_ast(value):
    """Keep semantic AST fields stable across Python's optional empty fields."""
    if isinstance(value, ast.AST):
        return {"node": type(value).__name__, "fields": {
            name: canonical_ast(field) for name, field in ast.iter_fields(value)
            if field is not None and field != []
        }}
    if isinstance(value, list):
        # Null placeholders (e.g. unpacked dictionary keys) retain position.
        return [canonical_ast(item) for item in value]
    if value is Ellipsis:
        return {"constant": "Ellipsis"}
    return value


def canonical_ast_sha256(node):
    payload = json.dumps(canonical_ast(node), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def test_t001_ast_pins_ignore_only_optional_empty_fields():
    absent = ast.parse("def sample() -> tuple[int, ...]: return {**source, 'key': None}").body[0]
    absent.__dict__.pop("type_params", None)
    present = deepcopy(absent)
    present.type_params = []
    # On older Python, register the optional field only on this test instance.
    present._fields = (*tuple(name for name in present._fields if name != "type_params"), "type_params")
    assert canonical_ast_sha256(absent) == canonical_ast_sha256(present)
    present.type_params = [ast.Name(id="T", ctx=ast.Load())]
    assert canonical_ast_sha256(absent) != canonical_ast_sha256(present)
    assert canonical_ast([None, ast.Constant(value=1)]) != canonical_ast([ast.Constant(value=1), None])
    assert canonical_ast(Ellipsis) == {"constant": "Ellipsis"}


def normalize_t001_nodes(actual, expected, old):
    """Pin reviewed T001 nodes; keep every unrelated AST node in parity.

    Literal hashes use canonical_ast_sha256 from PR852 head
    8382ab370a85b8bb95c75b895f91c0024d31aaaf, before any normalization.
    Independent cache and scoped-population tests cover the pinned behavior.
    """
    pins = {
        'server.sli.reports.users_v2_reporting': {
            '_directory_user_population': '411e3dc95bab4e3d554452766528a58ecfec9ccf4d5506451f245af7296dfc20',
            '_population_from_directory_rows': 'dd858ff940b20350cd1ab26779d51d486b32bdf203410bf0ae0369e768872c56',
            'build_users_v2_snapshot': 'ec4f3edae8a09825f4740a9e85e95a00b13fe7b11cd247bc379bf7c9f79c48e6',
        },
        'server.sli.reports.users_reporting': {
            'get_users_report': '0578b5e5575af6d3b553475e482bb08f7bf94308b1eaa3c333e995436193a0dc',
        },
        'server.sli.reporting.v2.reports.users': {
            '_condition': 'dfd6bcbcba567e21782796370546379e711cecb7cbe010c8f344c4dd9fa2a3f7',
            '_building': 'c7888a406b617c862093062ab0a64cac3bd91f7dbf2c5647a4786028a81097d2',
            '_snapshots': '117abdfa790ec0877a65135051f711962b5420ec6aa54ff3dd79ab1ca65b2e72',
        },
    }
    reviewed = pins.get(old, {})
    expected_nodes = {node.name: node for node in expected.body if isinstance(node, ast.FunctionDef)}
    normalized = []
    seen = set()
    for node in actual.body:
        name = (node.name if isinstance(node, ast.FunctionDef) else
                node.targets[0].id if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) else
                node.target.id if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) else None)
        if name not in reviewed:
            normalized.append(node)
            continue
        assert name not in seen
        seen.add(name)
        assert canonical_ast_sha256(node) == reviewed[name], "T001 reviewed AST drifted"
        if name in expected_nodes:
            normalized.append(deepcopy(expected_nodes[name]))
        else:
            # Only these reviewed new nodes have no frozen counterpart.
            assert name in {"_population_from_directory_rows", "_condition", "_building"}
    assert seen == set(reviewed), "T001 reviewed AST node missing"
    actual.body = normalized


# AD state presentation has changed since relocation. Native localization and
# observation preservation are covered by ReportLocaleCodesTests, not AST parity.
@pytest.mark.parametrize("old,new", [
    (old, new) for old, new in RELOCATIONS.items()
    if old != "server.sli.reporting.v2.reports.ad_state"
])
def test_relocation_changes_only_import_paths(old, new):
    capture = json.loads(gzip.decompress(FIXTURE.read_bytes()))
    assert capture["commit"] == "6f6daea654f0ee985c64bb0c292b54cd1514ebb4"
    source = ROOT.joinpath(*new.split(".")).with_suffix(".py").read_text("utf-8")
    for original, relocated in sorted(RELOCATIONS.items(), key=lambda item: -len(item[1])):
        source = source.replace(relocated, original)
    source = source.replace("from server.sli.plugins.ad.reports import", "from server.sli.reports import")
    # Apply only reviewed passport/behavior deltas to the frozen capture;
    # every remaining AST node must still be an import-only relocation.
    baseline_source = directory_repair_source(capture["sources"][old], old.rsplit(".", 1)[-1])
    baseline_source = user_security_source(baseline_source, old)
    baseline_source = computer_security_source(baseline_source, old)
    baseline_source = review_checks_source(baseline_source, old)
    baseline_source = report_additions_source(baseline_source, old)
    if old == "server.sli.reports.active_directory_reporting":
        # PR640 lets authorized domain IDs replace the installation-domain
        # filter and makes an empty explicit scope skip both stored reads.
        # test_active_directory_domain_scope covers these behavior changes.
        # Keep the frozen fixture and compare every other AST node unchanged.
        replacements = (
            ('domain_sql = " and report_domain.id=any(?)" if clean_domains else ""',
             '''domain_sql = "report_domain.id=any(?)" if domain_ids is not None else f"lower(report_domain.fqdn)='{report_domain_fqdn()}'"'''),
            ('entity_domain_sql = " and entity.domain_id=any(?)" if clean_domains else ""',
             '''entity_domain_sql = "entity.domain_id=any(?)" if domain_ids is not None else f"lower(report_domain.fqdn)='{report_domain_fqdn()}'"'''),
            ('coverage_rows = query_rows_bounded(',
             'coverage_rows = [] if domain_ids is not None and not clean_domains else query_rows_bounded('),
            ('    rows = query_rows_bounded(',
             '    rows = [] if domain_ids is not None and not clean_domains else query_rows_bounded('),
            ("where lower(report_domain.fqdn)='{report_domain_fqdn()}'{domain_sql}",
             "where {domain_sql}"),
            ("and lower(report_domain.fqdn)='{report_domain_fqdn()}'{entity_domain_sql}",
             "and {entity_domain_sql}"),
        )
        for before, after in replacements:
            assert baseline_source.count(before) == 1
            baseline_source = baseline_source.replace(before, after, 1)
    # F1/F4 add source clocks and domain attribution. Pin the exact reviewed
    # delta; keep the frozen capture and all unrelated AST nodes unchanged.
    if old == "server.sli.reports.active_directory_reporting":
        replacements = (
            ('        "entity_id": int(item["entity_id"]),',
             '        "entity_id": int(item["entity_id"]),\n        "domain_id": item.get("domain_id"),\n        "domain_name": item.get("domain_name"),'),
            ('    max_page_limit: int = 200,', '    max_page_limit: int = 200,\n    qualify_names: bool | None = None,'),
            ('select entity.id as entity_id,entity.domain_id,entity_type.value as entity_type,',
             'select entity.id as entity_id,entity.domain_id,report_domain.fqdn as domain_name,entity_type.value as entity_type,'),
            ('    all_items: list[dict[str, Any]] = []',
             '    all_items: list[dict[str, Any]] = []\n    qualified = qualify_names if qualify_names is not None else domain_ids is None or len(clean_domains) > 1'),
            ('        risks = evaluate_active_directory_risks(report_entity_type, attrs, snapshot_utc)',
             '''        risks = evaluate_active_directory_risks(report_entity_type, attrs, snapshot_utc)
        domain_name = raw.get("domain_name")
        display_name = str(raw.get("display_name") or raw.get("natural_key") or "—")
        if qualified:
            display_name = f"{domain_name or raw['domain_id']}\\\\{display_name}"'''),
            ('            "domain_id": int(raw["domain_id"]),',
             '            "domain_id": int(raw["domain_id"]),\n            "domain_name": domain_name,'),
            ('            "display_name": str(raw.get("display_name") or raw.get("natural_key") or "—"),',
             '            "display_name": display_name,'),
        )
    elif old == "server.sli.reporting.v2.reports.ad_state":
        replacements = (
            ('        {**finding, "entity_name": item.get("display_name"), "entity_id": item.get("entity_id")}',
             '        {**finding, "entity_name": item.get("display_name"), "entity_id": item.get("entity_id"),\n'
             '         "domain_id": item.get("domain_id"), "domain_name": item.get("domain_name")}'),
            ('def _query(context: QueryContext) -> dict[str, Any]:', '''def _read(context: QueryContext, **params: Any) -> dict[str, Any]:
    selection = context.runtime.get("domain_selection")
    return get_active_directory_report(
        domain_ids=context.domain_ids,
        **({"qualify_names": selection.domain_id is None} if selection is not None else {}),
        **params,
    )


def _query(context: QueryContext) -> dict[str, Any]:'''),
        )
        # Four existing calls now share the same server-sealed selection.
        assert baseline_source.count('get_active_directory_report(domain_ids=context.domain_ids, ') == 4
        baseline_source = baseline_source.replace('get_active_directory_report(domain_ids=context.domain_ids, ', '_read(context, ')
    elif old == "server.sli.reports.users_reporting":
        replacements = (
            ('        observed_candidates = [_utc(directory_row.get("observed_at_utc")), _utc(privilege_row.get("observed_at_utc"))]',
             '        directory_observed = _utc(directory_row.get("observed_at_utc"))\n'
             '        observed_candidates = [directory_observed, _utc(privilege_row.get("observed_at_utc"))]'),
            ('            "privilege_record_count": int(privilege_row.get("record_count") or 0),',
             '            "privilege_record_count": int(privilege_row.get("record_count") or 0),\n'
             '            "observed_at_utc": directory_observed.isoformat() if directory_observed else None,'),
        )
    else:
        replacements = ()
    for before, after in replacements:
        assert baseline_source.count(before) == 1
        baseline_source = baseline_source.replace(before, after, 1)
    baseline_source = users_workspace_source(baseline_source, old)
    baseline_source = report_locale_source(baseline_source, old)
    baseline_source = new_logon_pairs_source(baseline_source, old)
    expected = baseline_tree(baseline_source, old.rsplit(".", 1)[-1])
    actual = ast.parse(source)
    normalize_t001_nodes(actual, expected, old)
    if old == "server.sli.reports.active_directory_reporting":
        # T073 changes only LDAP qualification. Pin the exact reviewed nodes;
        # the frozen capture and every unrelated node stay checked below.
        # Native control/risk/CSV behavior has test_ad_ldap_qualification coverage.
        pins = {
            "_LDAP_QUALIFICATIONS": "6cd9efc8cb5db484ebebda9f24d91b1632cf6a5bbbd85f285cb5406d92459ff0",
            "_ldap_qualification": "b53e647676e9f7146a1c32bd3b19fbae22bfb1ed6d57c828105e6a1bd05e6f7e",
            "evaluate_active_directory_risks": "be404ce220a9a93c12fc6375c9e3dc928d723f3243ab5fc3588e9ba43d8d5504",
            "build_active_directory_controls": "9c801529003f708eaba3d86fb2f001664426f7a33c9e97bcb322c2070f93bbe4",
        }
        expected_functions = {node.name: node for node in expected.body if isinstance(node, ast.FunctionDef)}
        seen, normalized = set(), []
        for node in actual.body:
            name = (node.name if isinstance(node, ast.FunctionDef) else
                    node.targets[0].id if isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name) else None)
            if name in pins:
                assert name not in seen, "T073 reviewed node duplicated"
                assert canonical_ast_sha256(node) == pins[name], "T073 reviewed AST drifted"
                seen.add(name)
                if name in expected_functions:
                    normalized.append(deepcopy(expected_functions[name]))
            else:
                normalized.append(node)
        assert seen == set(pins), "T073 reviewed node missing"
        actual.body = normalized
    if old == "server.sli.reports.computers_v6_reporting_items":
        # T021 adds presentation envelopes only. Pin the two reviewed producer
        # functions; retain frozen parity for every unrelated inventory node.
        # Real producer/response behavior is tested in test_report_locale_codes.
        pins = {
            "_attention_reasons": "2278478799aa90171d46e0be1fed17ef286555921f8d4da65f1d7bf2cfa510ad",
            "_reason": "cb2378dd1ad88b64a7663dd87f403fc3b0ea23f11c45a7d0ca36db7250f3b8c0",
        }
        expected_functions = {node.name: node for node in expected.body if isinstance(node, ast.FunctionDef)}
        imports = {ast.dump(node) for node in ast.parse(
            "import re\nfrom server.sli.core.messages import catalog, message"
        ).body}
        seen_functions, seen_imports, normalized = set(), set(), []
        for node in actual.body:
            if isinstance(node, ast.FunctionDef) and node.name in pins:
                assert node.name not in seen_functions
                assert canonical_ast_sha256(node) == pins[node.name], "T021 reviewed AST drifted"
                seen_functions.add(node.name)
                normalized.append(deepcopy(expected_functions[node.name]))
            elif ast.dump(node) in imports:
                assert ast.dump(node) not in seen_imports
                seen_imports.add(ast.dump(node))
            else:
                normalized.append(node)
        assert seen_functions == set(pins) and seen_imports == imports
        actual.body = normalized
    if old == "server.sli.reports.users_v2_reporting":
        # The scoped agent population repair has its own PostgreSQL behavior
        # tests. Keep the frozen relocation check for every other reader.
        def unrelated(tree):
            tree.body = [node for node in tree.body if not (
                isinstance(node, ast.FunctionDef) and node.name in {"_directory_user_population", "_directory_user_rows", "snapshot_from_directory_projection"}
                or isinstance(node, ast.ImportFrom) and node.module == "server.sli.core.report_domain")]
            return tree
        actual, expected = unrelated(actual), unrelated(expected)
        # G02-003 intentionally adds this exact fail-closed comparison guard.
        # Pin its position and full AST; retain parity for every other node.
        # Reader and stale-grant API behavior have dedicated scope regressions.
        function = next(node for node in expected.body if isinstance(node, ast.FunctionDef)
                        and node.name == "load_users_v2_snapshots")
        scope_index = next(index for index, node in enumerate(function.body)
                           if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                           and node.targets[0].id == "clean_domains")
        guard = ast.parse('''if domain_ids is not None and not clean_domains:
    return {
        "contract_id": CONTRACT_ID, "report_key": REPORT_KEY,
        "state": "empty", "current": current, "previous": None,
        "saved_snapshot_count": 0, "previous_state": "none",
    }
''').body[0]
        function.body.insert(scope_index + 1, guard)
    if old == "server.sli.reports.computers_v6_reporting_comparison":
        # T004 extracts the reviewed row renderer from the already excluded
        # scoped loader. Pin its exact semantics before removing only that new
        # helper; all other comparison nodes still match the frozen capture.
        helpers = [node for node in actual.body if isinstance(node, ast.FunctionDef)
                   and node.name == "_snapshot_comparison_from_rows"]
        assert len(helpers) == 1, "T004 reviewed helper missing or duplicated"
        assert canonical_ast_sha256(helpers[0]) == (
            "657b8712143bdbc38c6dee72bef343c5857afc63d8c955490918e1f287065985"
        ), "T004 reviewed helper AST drifted"
        actual.body.remove(helpers[0])
    # Shared domain selection intentionally replaces these scoped readers.
    # Their behavior is covered with two-domain fakes in
    # test_ad_report_domain_selection; all other relocated nodes stay pinned.
    changed_readers = {
        "server.sli.reports.computers_v6_reporting": {"get_computers_v6_report"},
        "server.sli.reports.computers_v6_reporting_items": {"_coverage"},
        "server.sli.reports.computers_v6_reporting_comparison": {"_load_snapshot_comparison"},
        "server.sli.reports.computers_v6_reporting_overlay": {
            "_apply_computers_v6_source_overlay", "_load_computers_v6_source_overlay", "_source_overlay",
        },
        "server.sli.reporting.v2.reports.users": {"_prepare"},
        # adimpl4 tab dispatch and selected-view CSV have scoped fake/HTTP
        # tests in test_ad_computers_views; all other adapter nodes stay pinned.
        "server.sli.reporting.v2.reports.computers": {"_engine", "_query", "_export"},
    }
    for tree in (actual, expected):
        tree.body = [node for node in tree.body if not (
            isinstance(node, ast.FunctionDef) and node.name in changed_readers.get(old, set())
            or old.startswith("server.sli.reports.computers_v6")
            and isinstance(node, ast.ImportFrom) and node.module == "server.sli.core.report_domain"
        )]
    if old == "server.sli.reporting.v2.reports.computers":
        # Only the reviewed view declaration, hidden inventory selector and
        # overlay name action differ. Metadata has independent literal checks.
        for tree in (actual, expected):
            tree.body = [node for node in tree.body if not (
                isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name) and node.value.func.id == "replace"
                and any(keyword.arg == "views" for keyword in node.value.keywords))]
        for node in ast.walk(actual):
            if isinstance(node, ast.ImportFrom):
                node.names = [alias for alias in node.names if alias.name not in {"csv_from_columns", "computer_changes"}]
            if isinstance(node, ast.Tuple):
                for index, value in enumerate(node.elts):
                    if (isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "replace"
                            and value.args and isinstance(value.args[0], ast.Call)
                            and isinstance(value.args[0].func, ast.Attribute) and value.args[0].func.attr == "choice"):
                        choice = value.args[0]
                        assert choice.args[0].value == "view"
                        next(keyword for keyword in choice.keywords if keyword.arg == "default").value = ast.Constant("attention")
                        node.elts[index] = choice
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Column"
                    and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == "display_name"
                    and any(keyword.arg == "sortable" for keyword in node.keywords)):
                node.keywords.append(ast.keyword(arg="link", value=ast.Constant("/app/entities/{entity_id}")))
    if old in {"server.sli.reporting.v2.reports.users", "server.sli.reporting.v2.reports.computers", "server.sli.reporting.v2.reports.ad_state"}:
        added = {"domain_id", "domain"} if old.endswith(".users") else {"domain_id"}
        for node in ast.walk(actual):
            if isinstance(node, ast.Tuple):
                node.elts = [value for value in node.elts if not (
                    isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "Param"
                    and value.args and isinstance(value.args[0], ast.Constant) and value.args[0].value in added
                )]
            if isinstance(node, ast.Set) and old.endswith(".users") and any(
                isinstance(value, ast.Constant) and value.value == "domain_id" for value in node.elts
            ):
                node.elts = [value for value in node.elts if not isinstance(value, ast.Constant) or value.value not in added]
    if old in {"server.sli.entities.users_v2_directory_projection", "server.sli.reports.computers_v6_reporting_items"}:
        added = "domainId" if old.startswith("server.sli.entities.") else "domain_name"
        for node in ast.walk(actual):
            if isinstance(node, ast.Dict):
                pairs = [(key, value) for key, value in zip(node.keys, node.values, strict=True)
                         if not isinstance(key, ast.Constant) or key.value != added]
                node.keys, node.values = [key for key, _ in pairs], [value for _, value in pairs]
        if added == "domainId":
            function = next(node for node in actual.body if isinstance(node, ast.FunctionDef) and node.name == "build_directory_projection")
            assert isinstance(function.body[0], ast.If) and "requested_domain_ids" in ast.unparse(function.body[0].test)
            function.body.pop(0)
    if old == "server.sli.reports.dc_powershell_reporting":
        # G02-002 changes only eight outer SELECT labels. Keep the entire
        # reader, joins and composer pinned; boundary tests exercise the labels.
        for name in ("process_start", "process_stop", "session_start", "session_end"):
            for suffix in ("event_db_id", "boot_event_db_id"):
                column = f"{name}_{suffix}"
                before = f"origin.{column} as origin_{column}"
                matches = [node for node in ast.walk(actual)
                           if isinstance(node, ast.Constant) and isinstance(node.value, str)
                           and before in node.value]
                assert len(matches) == 1 and matches[0].value.count(before) == 1
                matches[0].value = matches[0].value.replace(before, f"origin.{column}", 1)
    assert ast.dump(actual) == ast.dump(expected)


@pytest.mark.parametrize("before,after", [
    ("if len(rows) < 2:", "if len(rows) < 1:"),
    ('"deletion_claim_allowed": False', '"deletion_claim_allowed": True'),
])
def test_t004_comparison_parity_rejects_helper_and_unrelated_drift(monkeypatch, before, after):
    old = "server.sli.reports.computers_v6_reporting_comparison"
    target = ROOT.joinpath(*RELOCATIONS[old].split(".")).with_suffix(".py")
    original_read = Path.read_text
    source = original_read(target, encoding="utf-8")
    assert before in source
    # The first deletion flag is in compare_computers_v6_snapshots, not in the
    # pinned helper: that mutation proves unrelated semantics remain checked.
    changed = source.replace(before, after, 1)

    def read(path, *args, **kwargs):
        return changed if path == target else original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(AssertionError):
        test_relocation_changes_only_import_paths(old, RELOCATIONS[old])


@pytest.mark.parametrize("before,after", [
    ("if domain_ids is not None and not clean_domains:\n        # An explicit empty authorized scope",
     "if domain_ids is None and not clean_domains:\n        # An explicit empty authorized scope"),
    ('"saved_snapshot_count": 0, "previous_state": "none",',
     '"saved_snapshot_count": 1, "previous_state": "none",'),
    ('"previous_state": "loaded" if previous else "none",',
     '"previous_state": "loaded" if previous else "unavailable",'),
])
def test_users_snapshot_parity_rejects_unreviewed_changes(monkeypatch, before, after):
    old = "server.sli.reports.users_v2_reporting"
    new = "server.sli.plugins.ad.reports.users_v2_reporting"
    target = ROOT.joinpath(*new.split(".")).with_suffix(".py")
    original_read = Path.read_text
    source = original_read(target, encoding="utf-8")
    assert source.count(before) == 1
    changed = source.replace(before, after, 1)

    def read(path, *args, **kwargs):
        return changed if path == target else original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(AssertionError):
        test_relocation_changes_only_import_paths(old, new)



@pytest.mark.parametrize("old,before,after", [
    ("server.sli.reports.users_v2_reporting", "len(rows) <= USERS_INPUT_LIMIT", "len(rows) < USERS_INPUT_LIMIT"),
    ("server.sli.reports.users_v2_reporting", '"state": "empty", "current": current', '"state": "available", "current": current'),
    ("server.sli.reports.users_reporting", 'not str(sam or "").endswith("$")', 'str(sam or "").endswith("$")'),
    ("server.sli.reports.users_reporting", 'clean_view not in {"active",', 'clean_view not in {"unexpected",'),
    ("server.sli.reporting.v2.reports.users", "_building.remove(key)", "_building.clear()"),
    ("server.sli.reporting.v2.reports.users", "CACHE_SECONDS = 120", "CACHE_SECONDS = 121"),
])
def test_t001_parity_rejects_reviewed_and_unrelated_drift(monkeypatch, old, before, after):
    target = ROOT.joinpath(*RELOCATIONS[old].split(".")).with_suffix(".py")
    original_read = Path.read_text
    source = original_read(target, encoding="utf-8")
    assert source.count(before) == 1
    changed = source.replace(before, after, 1)

    def read(path, *args, **kwargs):
        return changed if path == target else original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(AssertionError):
        test_relocation_changes_only_import_paths(old, RELOCATIONS[old])


def test_metadata_and_infrastructure_equal_pr1_baseline(monkeypatch):
    from test_ad_plugin_contract_equivalence import test_ad_contracts_equal_pre_registration_baseline

    test_ad_contracts_equal_pre_registration_baseline(monkeypatch)


@pytest.mark.parametrize("name", DEFINITIONS)
def test_full_metadata_matches_frozen_definition(baseline, name):
    before, after = baseline(f"reports.definitions.{name}").REPORT, candidate(name).REPORT
    assert domain_selection_metadata(before.to_json()) == after.to_json()
    for attribute in ("access", "metric_categories", "row_categories", "series_categories", "home_order", "home_view"):
        assert getattr(before, attribute) == getattr(after, attribute)


def install_readers(monkeypatch, load, name, state="available"):
    module = load(f"reports.definitions.{name}")
    if name == "ad_state":
        raw = {"state": state, "coverage": {"partial": ["synthetic-section"]},
               "summary": {"control_counts": {"failed": 1, "passed": 1}},
               "controls": [{"entity_id": index, "entity_name": f"synthetic-{index}", "entity_type": "domain_controller",
                             "control_id": f"synthetic-{index}", "label": "Synthetic control", "qualification": qualification,
                             "authority": "report_rule_v1", "actual_value": qualification == "passed",
                             "source_hash": "a" * 64, "object_context": {"is_global_catalog": True}}
                            for index, qualification in ((2, "passed"), (1, "failed"))]}
        monkeypatch.setattr(module, "get_active_directory_report", lambda **kwargs: deepcopy(raw))
    elif name == "computers":
        raw = {"state": state, "items": [{"entity_id": 1, "display_name": "synthetic-computer",
                "computer_type": "workstation", "account_state": "enabled", "reasons": [{"label": "Synthetic reason"}],
                "quality_issues": [], "object_guid": "00000000-0000-0000-0000-000000000001"}],
               "summary": {"total_computers": 1}, "coverage": {"latest_observed_at_utc": PERIOD["from_utc"]},
               "filter_options": {"operating_systems": ["Synthetic OS", "__missing__"]},
               "has_more": True, "next_cursor": "synthetic-cursor", "filtered_count": 2,
               "limitations": ["Synthetic partial coverage"]}
        monkeypatch.setattr(module, "get_computers_v6_report", lambda **kwargs: deepcopy(raw))
    elif name == "users":
        snapshot = {"metadata": {"observed_at": PERIOD["from_utc"], "completed_at": PERIOD["to_utc"]},
                    "users": [{"entityId": index, "id": str(index), "name": f"synthetic-user-{index}", "samAccountName": f"synthetic-{index}",
                               "enabled": True, "department": "synthetic-hr-marker", "mail": "synthetic-contact-marker",
                               "sourceStates": {"directory": {"status": "observed"}}} for index in (2, 1)], "groups": []}
        raw = {"state": state, "current": snapshot if state in {"available", "partial"} else None, "previous": deepcopy(snapshot)}
        monkeypatch.setattr(module, "_snapshots", lambda *args, **kwargs: deepcopy(raw))
        monkeypatch.setattr(load("reports.ad_hygiene_policy"), "thresholds", lambda: {"password_age": 90, "inactivity": 60})
    elif name == "computer_logons":
        monkeypatch.setattr(module, "logon_domain_scope", lambda *args, **kwargs: [1])
        raw = {"state": state, "items": [{"entity_id": 1, "display_name": "synthetic-computer"}],
               "coverage": {"observation_state": "partial", "inventory_state": "available", "limitations": ["Synthetic limitation"]},
               "has_more": True, "next_cursor": "synthetic-cursor"}
        monkeypatch.setattr(module, "get_computer_logon_computers", lambda **kwargs: deepcopy(raw))
        monkeypatch.setattr(module, "get_computer_logon_observations", lambda **kwargs: {
            "state": state, "items": [{"user_name": "synthetic-user", "user_display_name": "Synthetic user", "source_hash": "b" * 64}],
            "has_more": True, "next_cursor": "synthetic-detail-cursor", "limitations": ["Synthetic limitation"]})
    return module


@pytest.mark.parametrize("name", ["ad_state", "users", "computers", "computer_logons"])
@pytest.mark.parametrize("state", ["available", "partial", "not_collected", "unavailable", "not_authorized"])
def test_main_detail_filters_paging_and_exports_match_independent_baseline(monkeypatch, baseline, name, state):
    before = install_readers(monkeypatch, baseline, name, state)
    after = install_readers(monkeypatch, lambda suffix: importlib.import_module("server.sli.plugins.ad." + suffix), name, state)
    # Exercise the inventory reader, independently of the new default checks.
    tab = "all" if name == "users" else None
    if state in {"available", "partial"}:
        assert after.REPORT.query(QueryContext({}, {"period": PERIOD}, domain_ids=[1], tab=tab, limit=1))["items"]
    for params in ({}, {"q": "no-match"}, {"qualification": "failed"}, {"view": "all"}):
        context = QueryContext({}, {"period": PERIOD, **params}, domain_ids=[1], tab=tab, limit=1)
        for cursor in (None, "1", "invalid"):
            paged = replace(context, cursor=cursor)
            assert outcome(before.REPORT.query, paged) == outcome(after.REPORT.query, paged)
        if before.REPORT.export_csv:
            assert outcome(before.REPORT.export_csv, context) == outcome(after.REPORT.export_csv, context)
        if not isinstance(before.REPORT.detail, str) and before.REPORT.detail.query:
            for row_id in ("1", "invalid"):
                assert outcome(before.REPORT.detail.query, context, row_id) == outcome(after.REPORT.detail.query, context, row_id)


@pytest.mark.parametrize("state", ["ok", "partial", "not_collected", "unavailable"])
def test_snapshot_history_and_csv_match_baseline(monkeypatch, baseline, state):
    raw = {"state": state, "items": [{"id": "synthetic-record", "source_hash": "a" * 64}],
           "coverage": {"state": state, "reasons": ["history_starts_later", "history_truncated"]}, "truncated": True}
    for module in (baseline("reports.ad_snapshot_change_reporting"), importlib.import_module("server.sli.plugins.ad.reports.ad_snapshot_change_reporting")):
        monkeypatch.setattr(module, "read_changes", lambda **kwargs: deepcopy(raw))
    before, after = baseline("reports.definitions.ad_state").REPORT, candidate("ad_state").REPORT
    context = QueryContext({}, {"period": PERIOD}, domain_ids=[1], tab="changes")
    assert before.query(context) == after.query(context)
    assert outcome(before.export_csv, context) == outcome(after.export_csv, context)


@pytest.mark.parametrize("covered,truncated,partial", [(True, False, False), (False, False, False), (True, True, False), (True, False, True)])
def test_new_pairs_rows_filters_and_bound_cursor_match_baseline(monkeypatch, baseline, covered, truncated, partial):
    start = datetime.fromisoformat(PERIOD["from_utc"])
    sid = "S-1-5-21-1-2-3-1001"
    index = {"names": {"synthetic-pc-1": {"synthetic-guid-1"}, "synthetic-pc-2": {"synthetic-guid-2"}}, "ips": {},
             "computers": {f"synthetic-guid-{i}": {"computer_object_guid": f"synthetic-guid-{i}",
                                                   "computer_name": f"synthetic-pc-{i}"} for i in (1, 2)}}
    events = [{"id": i, "event_id": 4624, "server_id": 10, "domain_id": 1, "channel": "Security",
               "time_created_utc": start.isoformat(), "target_domain_name": "SYNTHETIC", "target_user_name": "synthetic-user",
               "target_user_sid": sid, "workstation_name": f"synthetic-pc-{i}", "computer": "synthetic-dc", "logon_type": "3",
               "source_core_sha256": bytes.fromhex("aa" * 32)} for i in (1, 2)]
    modules = [baseline("reports.definitions.new_logon_pairs"), candidate("new_logon_pairs")]
    for module in modules:
        monkeypatch.setattr(module, "logon_domain_scope", lambda *args: [1])
        monkeypatch.setattr(module.engine, "load_context", lambda domain: {
            "index": deepcopy(index), "accounts": {"synthetic-user": False}, "server_ids": [10], "partial": partial,
            "computers": {f"synthetic-guid-{i}": {"entity_id": i} for i in (1, 2)}})
        monkeypatch.setattr(module.engine, "load_history", lambda *args: {
            "baseline": [], "period": deepcopy(events), "baseline_covered": covered, "truncated": truncated,
            "period_covered": True, "history_from_utc": PERIOD["from_utc"], "history_to_utc": PERIOD["to_utc"]})
        monkeypatch.setattr(module.engine, "user_entities", lambda *args: {sid.casefold(): 3})
    context = QueryContext({}, {"period": PERIOD, "baseline_days": 30}, limit=1)
    first = [module.REPORT.query(context) for module in modules]
    assert first[0] == first[1]
    assert len(first[1]["items"]) == 1 and first[1]["has_more"]
    assert first[1]["state"] == ("ok" if covered and not truncated and not partial else "partial")
    paged = replace(context, cursor=first[1]["next_cursor"])
    second = [module.REPORT.query(paged) for module in modules]
    assert second[0] == second[1]
    assert len(second[1]["items"]) == 1 and not second[1]["has_more"]
    assert first[1]["items"][0]["id"] != second[1]["items"][0]["id"]
    for params in ({"q": "no-match"}, {"user": "synthetic"}, {"baseline_days": 0}):
        filtered = replace(context, params={**context.params, **params})
        assert outcome(modules[0].REPORT.query, filtered) == outcome(modules[1].REPORT.query, filtered)
    for cursor in ("invalid", first[1]["next_cursor"]):
        changed = replace(context, cursor=cursor, params={**context.params, "q": "changed"})
        errors = [outcome(module.REPORT.query, changed) for module in modules]
        assert errors[0] == errors[1]
        assert errors[1]["error"] == "ValueError"


@pytest.mark.parametrize("failure", ["inventory", "observations", "domain"])
def test_logon_reader_errors_match_baseline(monkeypatch, baseline, failure):
    values = []
    for module in (baseline("reports.definitions.computer_logons"), candidate("computer_logons")):
        monkeypatch.setattr(module, "logon_domain_scope", lambda *args: [1])
        def unavailable(**kwargs):
            if failure == "observations":
                raise module.ObservationsUnavailableError("synthetic")
            raise module.InventoryUnavailableError("report_domain_not_configured" if failure == "domain" else "synthetic")
        monkeypatch.setattr(module, "get_computer_logon_computers", unavailable)
        values.append(module.REPORT.query(QueryContext({}, {"period": PERIOD})))
    assert values[0] == values[1]
    assert values[1]["state"] == "error" and values[1]["limitations"]


@pytest.mark.parametrize("scope,fields,actions", [
    ({"kind": "domain", "ids": [1]}, ["computer_logon_observation"], ["view"]),
    ({"kind": "domain", "ids": [2]}, ["computer_logon_observation"], ["view"]),
    ({"kind": "all"}, [], ["view"]),
    ({"kind": "all"}, ["computer_logon_observation"], []),
])
def test_delegated_logon_scope_and_privileges_match_baseline(baseline, scope, fields, actions):
    decision = {"reports": [{"report_key": "ad.computer-logons", "allowed": True, "allowed_actions": actions,
                            "grants": [{"field_categories": fields, "allowed_actions": actions, "scope": scope}]}]}
    before, after = baseline("reports.definitions.computer_logons"), candidate("computer_logons")
    def resolve(module):
        return module.logon_domain_scope(decision, domain_id=1)
    assert outcome(resolve, before) == outcome(resolve, after)


class Handler:
    def __init__(self, decision):
        self.decision, self.sent, self.headers = decision, [], {}
        self.wfile = io.BytesIO()
        self.status = None

    def _access_decision(self):
        return self.decision

    def _send_json(self, payload, status=200):
        self.sent.append((payload, int(status)))

    def send_response(self, status):
        self.status = int(status)

    def send_header(self, key, value):
        self.headers[key] = value

    def end_headers(self):
        pass

    def response(self):
        return self.sent, self.status, self.headers, self.wfile.getvalue()


@pytest.mark.parametrize("fields", [[], ["identity_basic"], ["identity_basic", "technical", "security", "privilege"],
                                   ["identity_basic", "technical", "security", "privilege", "hr", "contact"]])
@pytest.mark.parametrize("suffix", ["", "/data", "/export.csv"])
def test_field_masking_and_denials_match_baseline(monkeypatch, baseline, fields, suffix):
    before = install_readers(monkeypatch, baseline, "users").REPORT
    after = install_readers(monkeypatch, lambda suffix: importlib.import_module("server.sli.plugins.ad." + suffix), "users").REPORT
    monkeypatch.setattr(routes, "report_plugin_state", lambda key: None)
    monkeypatch.setattr(routes, "annotate_plugin_report", lambda key, payload: payload)
    decision = {"reports": [{"report_key": "ad.users.v2", "allowed": True, "allowed_actions": ["view", "export"],
                            "grants": [{"allowed_actions": ["view", "export"], "field_categories": fields,
                                        "scope": {"kind": "domain", "ids": [1]}}]}]}
    responses = []
    for definition in (before, after):
        monkeypatch.setattr(routes, "get_report", lambda key: definition)
        handler = Handler(decision)
        assert routes.try_handle_get(handler, "/api/v2/reports/ad.users.v2" + suffix, {"tab": ["all"]})
        responses.append(handler.response())
    if not suffix and responses[0][0][0][1] == 200:
        payload, status = responses[0][0][0]
        assert payload["default_domain_id"] == 1
        assert payload["default_domain_state"] == "available"
        responses[0][0][0] = (domain_selection_metadata(payload), status)
    assert responses[0] == responses[1]
    if "hr" not in fields:
        assert "synthetic-hr-marker" not in repr(responses[1])
    if "contact" not in fields:
        assert "synthetic-contact-marker" not in repr(responses[1])


@pytest.mark.parametrize("name,function,event_id", [
    ("ad_account_state_reporting", "compose_ad_account_change_history", 4725),
    ("ad_group_membership_reporting", "compose_ad_group_membership_history", 4728),
    ("dc_powershell_reporting", "compose_dc_powershell_activity", 4104),
])
@pytest.mark.parametrize("sensitive", [False, True])
def test_history_evidence_transitions_and_sensitive_script_match_baseline(baseline, name, function, event_id, sensitive):
    event = {"event_db_id": 1, "event_record_id": 101, "event_id": event_id,
             "time_created_utc": datetime(2026, 10, 9, 10, 1, tzinfo=timezone.utc), "domain_controller": "synthetic.invalid",
             "target_user_sid": "S-1-5-21-1-2-3-1001", "target_user_name": "synthetic-user",
             "target_group_sid": "S-1-5-21-1-2-3-2001", "member_sid": "S-1-5-21-1-2-3-1001",
             "powershell_script_block_text": "synthetic-sensitive-marker",
             "source_core_sha256": bytes.fromhex("aa" * 32), "source_facts_sha256": bytes.fromhex("bb" * 32)}
    kwargs = {"source_domain_id": 1, "period_start": datetime.fromisoformat(PERIOD["from_utc"]),
              "period_end": datetime.fromisoformat(PERIOD["to_utc"]), "events": [event],
              "collection_coverage": {"history_event_present": True}}
    if name == "dc_powershell_reporting":
        kwargs["include_script_block_text"] = sensitive
    before = getattr(baseline("reports." + name), function)(**deepcopy(kwargs))
    after = getattr(importlib.import_module("server.sli.plugins.ad.reports." + name), function)(**deepcopy(kwargs))
    assert before == after
    assert after["items"]
    if name == "dc_powershell_reporting":
        assert ("synthetic-sensitive-marker" in repr(after)) is sensitive


def test_history_requires_privilege_in_same_domain_grant(baseline):
    decision = {"reports": [{"report_key": "ad.state", "allowed_actions": ["view"], "allowed": True,
                            "grants": [{"field_categories": ["identity_basic", "technical", "security"],
                                        "allowed_actions": ["view"], "scope": {"kind": "domain", "ids": [1]}}]}]}
    for definition in (baseline("reports.definitions.ad_state").REPORT, candidate("ad_state").REPORT):
        with pytest.raises(PermissionError, match="report_field_categories_not_allowed"):
            ReportAccess(definition, decision, "view").validate_request({}, {"tab": "changes"})


def test_security_event_account_history_hook_preserves_transitions(baseline):
    from server.sli.reports import security_event_reporting as security

    reader = baseline("reports.ad_account_state_reporting")
    event = {"event_id": 4725, "event_db_id": 1, "time_created_utc": PERIOD["from_utc"],
             "target_user_sid": "S-1-5-21-1-2-3-1001"}
    assert security.account_change_observation(event) == reader.account_change_observation(event)
    items = [{"event_id": event_id, "event_db_id": index, "time_created_utc": PERIOD["from_utc"],
              "account": {"target_user_sid": event["target_user_sid"]}, **reader.account_change_observation({"event_id": event_id})}
             for index, event_id in ((1, 4725), (2, 4722))]
    before, after = deepcopy(items), deepcopy(items)
    reader.apply_observed_account_history(before)
    security.apply_observed_account_history(after)
    assert before == after


def test_security_event_empty_account_history_needs_no_ad_plugin(monkeypatch):
    from server.sli.reports import security_event_reporting as security

    def forbidden(*args, **kwargs):
        pytest.fail("empty account history must not depend on the AD plugin")
    monkeypatch.setattr(security, "require_plugin", forbidden)
    security.apply_observed_account_history([])


def test_missing_ad_legacy_route_returns_not_installed(monkeypatch):
    monkeypatch.setattr(plugins, "BUNDLED", {key: value for key, value in plugins.BUNDLED.items() if key != "sli.ad"})
    handler = Handler({})
    assert legacy_routes.try_handle_get(handler, "/api/v1/reports/ad.state/account-changes", {})
    assert handler.sent == [({"state": "not_installed", "reason": "plugin_not_installed", "plugin_id": "sli.ad", "items": []}, 200)]


@pytest.mark.parametrize("path,reader", [
    ("/api/v1/reports/ad.state/account-change-sources", "get_ad_account_change_sources"),
    ("/api/v1/reports/ad.state/account-changes", "get_ad_account_change_history"),
    ("/api/v1/reports/ad.groups/membership-changes", "get_ad_group_membership_history"),
    ("/api/v1/reports/dc.powershell/activity", "get_dc_powershell_activity"),
    ("/api/v1/reports/ad.state/security-event-sources", "get_security_event_sources"),
    ("/api/v1/reports/ad.state/security-events", "get_security_events_report"),
    ("/api/v1/reports/ad.state/security-events.csv", "get_security_events_report"),
])
@pytest.mark.parametrize("query", [{}, {"domain_id": ["invalid"]}, {"limit": ["1"], "q": ["synthetic"]}])
def test_legacy_routes_responses_errors_and_csv_match_baseline(monkeypatch, baseline, path, reader, query):
    responses = []
    for module in (baseline("api.reports"), legacy_routes):
        def read(*args, **kwargs):
            return {"state": "available", "items": [], "arguments": kwargs}
        monkeypatch.setattr(module, reader, read)
        handler = Handler({})
        assert module.try_handle_get(handler, path, query)
        responses.append(handler.response())
    assert responses[0] == responses[1]


@pytest.mark.parametrize("old,before,after", [
    ("server.sli.reports.new_logon_pairs_reporting",
     'raise RuntimeError("logon_domain_controllers_missing")',
     'raise RuntimeError("unreviewed_reason")'),
    ("server.sli.reports.new_logon_pairs_reporting",
     "MAX_EVENTS = 50_000", "MAX_EVENTS = 50_001"),
    ("server.sli.reporting.v2.reports.new_logon_pairs",
     'state="empty" if history_empty else "partial"',
     'state="ok" if history_empty else "partial"'),
    ("server.sli.reporting.v2.reports.new_logon_pairs",
     "default_limit=50, max_limit=200", "default_limit=50, max_limit=201"),
])
def test_t002_parity_rejects_reviewed_and_unrelated_drift(monkeypatch, old, before, after):
    target = ROOT.joinpath(*RELOCATIONS[old].split(".")).with_suffix(".py")
    original_read = Path.read_text
    source = original_read(target, encoding="utf-8")
    assert source.count(before) == 1
    changed = source.replace(before, after, 1)

    def read(path, *args, **kwargs):
        return changed if path == target else original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(AssertionError):
        test_relocation_changes_only_import_paths(old, RELOCATIONS[old])


@pytest.mark.parametrize("before,after", [
    ('if code in _src.REASON_CATALOG:', 'if code not in _src.REASON_CATALOG:'),
    ('result["reasons"] = _src._attention_reasons(result, threshold_days)',
     'result["reasons"] = _src._attention_reasons(result, threshold_days + 1)'),
])
def test_t021_reason_parity_rejects_reviewed_and_unrelated_drift(monkeypatch, before, after):
    old = "server.sli.reports.computers_v6_reporting_items"
    target = ROOT.joinpath(*RELOCATIONS[old].split(".")).with_suffix(".py")
    original_read = Path.read_text
    source = original_read(target, encoding="utf-8")
    assert source.count(before) == 1
    changed = source.replace(before, after, 1)

    def read(path, *args, **kwargs):
        return changed if path == target else original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(AssertionError):
        test_relocation_changes_only_import_paths(old, RELOCATIONS[old])


@pytest.mark.parametrize("before,after", [
    ('"require_signing": "passed"', '"require_signing": "failed"'),
    ('return _LDAP_QUALIFICATIONS[field].get(value.strip().casefold(), "not_evaluated")',
     'return _LDAP_QUALIFICATIONS[field].get(value.strip().casefold(), "passed")'),
    ('results[risk_key] = _risk(risk_key, risk_qualification, actual)',
     'results[risk_key] = _risk(risk_key, "not_matched", actual)'),
    ('qualification = _ldap_qualification("ldap_signing_requirement", actual)',
     'qualification = "passed"'),
    ('writer = csv.writer(output, delimiter=";", lineterminator="\\r\\n")',
     'writer = csv.writer(output, delimiter=",", lineterminator="\\r\\n")'),
])
def test_t073_parity_rejects_ldap_and_unrelated_csv_drift(monkeypatch, before, after):
    old = "server.sli.reports.active_directory_reporting"
    new = RELOCATIONS[old]
    target = ROOT.joinpath(*new.split(".")).with_suffix(".py")
    original_read = Path.read_text
    source = original_read(target, encoding="utf-8")
    assert source.count(before) == 1
    changed = source.replace(before, after, 1)

    def read(path, *args, **kwargs):
        return changed if path == target else original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(AssertionError):
        test_relocation_changes_only_import_paths(old, new)
