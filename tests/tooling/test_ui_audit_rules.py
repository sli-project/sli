from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ui_audit_rules", ROOT / "scripts/dev/ui_audit/rules.py")
rules = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rules)


def record(**extra):
    return {"_source": "ru", "_line": 1, "id": "0001", "locale": "ru",
            "url": "/app/report/ad.computers.v6", "state": "page", **extra}


def findings(check, *records):
    out = rules.Findings()
    check(records, out)
    return out.items


def report_record(key="ad.computers.v6", query="", **extra):
    return record(url=f"/app/report/{key}{query}",
                  api_calls=[{"method": "GET", "url": f"/api/v2/reports/{key}/data{query}",
                              "status": 200, "rows": 44, "arrays": {"items": 44}}],
                  tables=[{"rows": 44, "total": 200, "footer": "200 of 200"}], **extra)


@pytest.mark.parametrize("query,total", [
    ("?view=attention", 786), ("?view=attention&reason_code=stale_activity", 9),
    ("?view=unknown_type", 8), ("?view=all&q=synthetic", 9),
    ("?view=all&enabled=disabled", 560), ("?view=all&type=unknown", 8),
])
def test_metric_table_does_not_compare_different_populations(query, total):
    rec = report_record(query=query, metrics=[
        {"key": "all", "label": "Всего в AD", "value": "1341"},
        {"key": "attention", "label": "Требуют внимания", "value": "786"},
        {"key": "unknown", "label": "Тип не определён (вкл.)", "value": "3"},
        {"key": "disabled", "label": "Отключены (все типы)", "value": "560"},
        {"key": "unknown_state", "label": "Состояние учётной записи не определено", "value": "0"},
    ])
    rec["tables"][0]["total"] = total
    assert findings(rules.check_metric_table, rec) == []


@pytest.mark.parametrize("key,query,metric_key,value", [
    ("ad.computers.v6", "?view=all&limit=50&tz=UTC", "all", "1341"),
    ("ad.computers.v6", "?view=attention", "attention", "786"),
    ("ad.computers.v6", "?view=all&type=unknown&enabled=enabled", "unknown", "3"),
    ("vpn.accounts", "?limit=200", "total_users", "438"),
])
def test_metric_table_checks_only_exact_population(key, query, metric_key, value):
    rec = report_record(key, query, metrics=[{"key": metric_key, "label": "Synthetic metric", "value": value}])
    result = findings(rules.check_metric_table, rec)
    assert len(result) == 1
    assert result[0]["metric_key"] == metric_key


@pytest.mark.parametrize("label", ["Всего VPN-пользователей", "Total VPN users"])
def test_legacy_vpn_total_is_detected_without_subgroup_false_positives(label):
    rec = report_record("vpn.accounts", "?limit=200", metrics=[
        {"label": label, "value": "438"}, {"label": "VPN и привилегии", "value": "12"},
        {"label": "Неактивные по входу", "value": "27"},
    ])
    assert [f["metric_key"] for f in findings(rules.check_metric_table, rec)] == ["total_users"]
    rec["url"] += "&activity=inactive"
    rec["api_calls"][0]["url"] += "&activity=inactive"
    assert findings(rules.check_metric_table, rec) == []


def test_metric_table_requires_matching_source_and_handles_zero_total():
    rec = report_record(query="?view=all", metrics=[{"key": "all", "label": "Total", "value": "1"}])
    rec["tables"][0]["total"] = 0
    assert len(findings(rules.check_metric_table, rec)) == 1
    rec["tables"][0]["source_url"] = "/api/v2/reports/ad.computers.v6/data?view=attention"
    assert findings(rules.check_metric_table, rec) == []
    rec["tables"][0].pop("source_url")
    rec["api_calls"][0]["url"] = "/api/v2/reports/ad.computers.v6/data?view=attention"
    assert findings(rules.check_metric_table, rec) == []


@pytest.mark.parametrize("unknown,expected", [(3, 0), (8, 1)])
def test_computer_partition_excludes_attention(unknown, expected):
    values = {"all": 1341, "ws": 727, "srv": 51, "unknown": unknown,
              "disabled": 560, "unknown_state": 0, "attention": 786}
    rec = record(metrics=[{"key": key, "label": "Synthetic", "value": str(value)} for key, value in values.items()])
    result = findings(rules.check_computer_partition, rec)
    assert len(result) == expected
    if expected:
        assert "attention" not in result[0]["metrics"]
    rec["metrics"] = [m for m in rec["metrics"] if m["key"] != "unknown_state"]
    assert findings(rules.check_computer_partition, rec) == []


@pytest.mark.parametrize("semantic,expected", [(0, 0), (2, 1)])
def test_placeholder_uses_active_array_not_largest_collection(semantic, expected):
    rec = report_record("ad.infrastructure", "?view=overview&tab=semantic", action="tab",
                        state="tab:Related findings", placeholders=[{"state": "empty", "title": "No records"}])
    rec["tables"] = []
    rec["api_calls"][0]["arrays"] = {"items": 44, "collections.semantic": semantic, "unrelated": 100}
    result = findings(rules.check_placeholder_data, rec)
    assert len(result) == expected
    if expected:
        assert "collections.semantic" in result[0]["message"]
    rec["api_calls"][0]["arrays"].pop("collections.semantic")
    assert findings(rules.check_placeholder_data, rec) == []


def test_placeholder_uses_explicit_view_source_and_ignores_metadata():
    rec = report_record("synthetic.report", "?tab=chart", active_collection="collections.points",
                        placeholders=[{"state": "empty", "title": "No records"}])
    rec["tables"] = []
    rec["api_calls"][0]["arrays"]["collections.points"] = 2
    assert len(findings(rules.check_placeholder_data, rec)) == 1
    rec["api_calls"][0]["url"] = "/api/v2/reports/synthetic.report"
    assert findings(rules.check_placeholder_data, rec) == []


def test_overview_entity_name_and_profile_do_not_prove_membership():
    parent = record(url="/app/entities/123", headings=["Тестовые группы"],
                    text="Тестовые группы\nТип объекта\nДата создания\nРасследование")
    tab = record(url=parent["url"], parent_url=parent["url"], state="tab:groups", action="tab",
                 tab_label="Группы", placeholders=[{"state": "empty", "title": "Нет данных"}],
                 api_calls=[{"url": "/api/v4/objects/entity/123", "status": 200,
                             "arrays": {"directory_context.items": 0}, "rows": 0}])
    assert findings(rules.check_placeholder_data, parent, tab) == []


@pytest.mark.parametrize("change,expected", [
    ({}, 1), ({"direction": "inbound"}, 0), ({"authorized": False}, 0),
    ({"relation_kind": "other"}, 0), ({"entity_id": "456"}, 0),
    ({"url": "/api/v4/objects/entity/456"}, 0), ({"rows": 0}, 0),
])
def test_overview_requires_same_authorized_relation_source(change, expected):
    source = {"url": "/api/v4/objects/entity/123", "collection": "directory_context.items",
              "relation_kind": "member_of", "direction": "outbound", "entity_id": "123", "authorized": True}
    parent = record(url="/app/entities/123", relation_evidence=[{**source, "rows": 2, **change}])
    tab = record(url=parent["url"], parent_url=parent["url"], state="tab:groups", action="tab",
                 tab_label="Groups", tab_source=source, placeholders=[{"state": "empty", "title": "No data"}])
    assert len(findings(rules.check_placeholder_data, parent, tab)) == expected


def test_static_stub_reads_full_detail_and_folds_filters():
    def empty(url, detail):
        return record(url=url, action="tab", state="tab:Related findings", tab_label="Related findings",
                      placeholders=[{"state": "empty", "title": "No records", "text": "", "detail": detail}])

    records = [empty(f"/app/report/synthetic?tab=semantic&q={i}", "Only exact published links are included.") for i in range(4)]
    records[0]["state"] = "page"
    records[0].pop("tab_label")
    records[1]["tab_label"] = "Population filter"
    assert findings(rules.check_static_stub, *records) == []
    records = [empty(f"/app/report/synthetic{i}", f"Source explanation {i}") for i in range(4)]
    assert findings(rules.check_static_stub, *records) == []
    for rec in records:
        rec["placeholders"][0]["detail"] = "Not connected"
    assert len(findings(rules.check_static_stub, *records)) == 1
    for rec in records:
        rec["placeholders"][0].pop("detail")
    assert findings(rules.check_static_stub, *records) == []


def test_cyrillic_checks_single_words_tables_and_aria_templates_by_origin():
    rec = record(locale="en", cyrillic=[
        {"text": "Закрытые", "in_table": False}, {"text": "Активные", "in_table": True},
        {"text": "Тестовый объект", "origin": "data", "source_path": "object.display_name"},
        {"text": "Pin Тестовый отчёт", "attr": "aria-label", "template": "Pin {data}"},
        {"text": "Закрепить Тестовый отчёт", "attr": "aria-label", "template": "Закрепить {data}"},
    ])
    result = findings(rules.check_cyrillic, rec)
    assert len(result) == 1
    assert set(result[0]["strings"]) == {"Закрытые", "Активные", "Закрепить {data}"}
    rec["locale"] = "ru"
    assert findings(rules.check_cyrillic, rec) == []


@pytest.mark.parametrize("structured", [False, True])
def test_console_resource_error_links_to_api_instead_of_duplicate(structured):
    text = "Failed to load resource: the server responded with a status of 500"
    rec = record(api_calls=[{"method": "GET", "url": "/api/synthetic", "status": 500}],
                 console_errors=[{"text": text, "url": "/api/synthetic"} if structured else text,
                                 "pageerror: synthetic exception"])
    out = rules.Findings()
    rules.check_api([rec], out)
    rules.check_console([rec], out)
    assert [f["type"] for f in out.items] == ["api_error", "console_error"]
    assert out.items[0]["console_messages"] == [text]
    assert "count" not in out.items[0]


def test_console_keeps_unmatched_and_ambiguous_resource_errors():
    text = "Failed to load resource: the server responded with a status of 404"
    rec = record(console_errors=[{"text": text, "url": "/static/synthetic.svg"}],
                 api_calls=[{"method": "GET", "url": "/api/synthetic", "status": 404}])
    assert len(findings(rules.check_console, rec)) == 1
    rec["console_errors"] = [text]
    rec["api_calls"].append({"method": "GET", "url": "/api/other", "status": 404})
    assert len(findings(rules.check_console, rec)) == 1


@pytest.mark.parametrize("timeout,busy,severity,completed", [
    (False, False, "info", True), (True, False, "medium", False), (False, True, "medium", False),
])
def test_timing_reports_measurement_without_regression_claim(timeout, busy, severity, completed):
    rec = record(settle_ms=10000, settle_timeout=timeout, still_busy=busy)
    result = findings(rules.check_timing, rec)
    assert len(result) == 1
    assert result[0]["classification"] == "measurement"
    assert result[0]["severity"] == severity
    assert result[0]["completed"] is completed
    assert "бесконечная" not in result[0]["message"]
    rec["settle_ms"] = 100
    rec["settle_timeout"] = rec["still_busy"] = False
    assert findings(rules.check_timing, rec) == []


def crawler_eval(expression, setup=""):
    """Execute only pure capture helpers with a fake DOM, without loading Playwright."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node is required to exercise crawler capture helpers")
    source = (ROOT / "scripts/dev/ui_audit/crawl.cjs").read_text(encoding="utf-8")
    helpers = source[source.index("function summarizeJson("):source.index("async function main()")]
    result = subprocess.run([node, "-e", helpers + "\n" + setup + f"\nprocess.stdout.write(JSON.stringify({expression}));"],
                            capture_output=True, text=True, encoding="utf-8", check=True)
    return json.loads(result.stdout)


def test_crawler_preserves_metric_keys_view_sources_and_relation_permissions():
    result = crawler_eval("summarizeJson({metrics:[{key:'all',value:3,filter:{view:'all'}}],"
                          "views:[{key:'links',source:'semantic'}],object:{object_id:'123'},state:'available',"
                          "tabs:[{id:'groups',available:true},{id:'privileges',available:false}],"
                          "directory_context:{items:[{context_kind:'entity'},"
                          "{context_kind:'relation',attributes:{relation_kind:'member_of'}},"
                          "{context_kind:'relation',attributes:{relation_kind:'member'}},"
                          "{context_kind:'relation',attributes:{relation_kind:'member_of',direction:'inbound'}}]}})")
    assert result["metrics"][0]["key"] == "all"
    assert result["views"] == [{"key": "links", "source": "semantic"}]
    assert result["relation_collections"][0]["rows"] == 1
    assert result["relation_collections"][0]["direction"] == "outbound"
    assert result["relation_collections"][1]["authorized"] is False


def test_crawler_counts_direct_membership_records_and_requires_available_source():
    result = crawler_eval("summarizeJson({object:{object_id:'123'},state:'forbidden',"
                          "tabs:[{id:'groups',available:true}],directory_context:{items:["
                          "{context_kind:'entity',attributes:{member_of:['Synthetic group']}}]}})")
    assert result["relation_collections"][0]["rows"] == 1
    assert result["relation_collections"][0]["authorized"] is False


def test_crawler_attaches_keys_and_active_collection_from_matching_report():
    result = crawler_eval("enrichSnapshot({metrics:[{label:'Synthetic metric',value:'1 341'}],tables:[{rows:2}]},"
                          "'/app/report/ad.computers.v6','?tab=links', ["
                          "{url:'/api/v2/reports/ad.computers.v6',status:200,views:[{key:'links',source:'semantic'}]},"
                          "{url:'/api/v2/reports/ad.computers.v6/data?tab=links',status:200,metrics:[{key:'all',value:1341}]},"
                          "{url:'/api/v2/reports/other/data',status:200,metrics:[{key:'wrong',value:1341}]}])")
    assert result["metrics"][0]["key"] == "all"
    assert result["tables"][0]["collection"] == "collections.semantic"
    assert result["active_collection"] == "collections.semantic"
    assert crawler_eval("enrichSnapshot({error:'synthetic'},'/app/report/ad.computers.v6','',"
                        "[{url:'/api/v2/reports/ad.computers.v6/data',status:200}])")["error"] == "synthetic"


def test_digest_supports_full_detail_and_structured_console_messages():
    rec = record(placeholders=[{"title": "No data", "detail": "Complete explanation " * 30}],
                 console_errors=[{"text": "synthetic exception", "url": "/api/synthetic"}])
    digest = rules.digest(rec)
    assert "Complete explanation " * 30 in digest
    assert "synthetic exception" in digest


def test_crawler_data_origin_does_not_hide_presentation_fields():
    result = crawler_eval("dataStrings({items:[{display_name:'Тестовый объект',description:'Тестовое описание',"
                          "activity:'Активные',reason_text:'Непереведённая причина'}],"
                          "semantic:{title:'Типовое объяснение'},report:{name:'Тестовый отчёт'}})")
    assert {r["path"] for r in result} == {"items.0.display_name", "items.0.description", "report.name"}
    assert crawler_eval("dataStrings({items:[{description:'Описание отчёта'}]}, '/api/v2/reports')") == []
    result = crawler_eval("dataStrings({items:[{title:'Тестовая должность',activity:'Активные',"
                          "observed_at_utc:'Повреждённая дата'}]}, '/api/v2/reports/vpn.accounts/data')")
    assert {r["path"] for r in result} == {"items.0.title", "items.0.observed_at_utc"}


FAKE_DOM = """
const element = (text='', options={}) => ({innerText:text,textContent:text,tagName:options.tag || 'DIV',
  className:'',children:[],getBoundingClientRect:()=>({width:100,height:50}),
  getAttribute:(a)=>options.attrs?.[a] || null,querySelector:(q)=>options.children?.[q] || null,
  closest:(q)=>q.startsWith('th,label,') ? (options.fixed ? {} : null) : q==='td,th' ? (options.table ? {} : null) : null});
const title=element('No records'); const detail=element('Complete explanation '.repeat(30));
const state=element('',{attrs:{'data-state':'empty'},children:{'.sli-ds-state__title':title,'.sli-ds-state__detail':detail}});
const dataElement=element('Тестовый объект',{tag:'TD',table:true});
const labelElement=element('Активные',{tag:'TH',table:true,fixed:true});
const aria=element('',{tag:'BUTTON',attrs:{'aria-label':'Закрепить Тестовый отчёт'}});
const nodes=[{nodeValue:dataElement.innerText,parentElement:dataElement},{nodeValue:labelElement.innerText,parentElement:labelElement}];
global.getComputedStyle=()=>({visibility:'visible',display:'block',opacity:'1'});
global.NodeFilter={SHOW_TEXT:4};
global.document={body:{innerText:''},title:'Synthetic',documentElement:{lang:'en'},
  querySelector:()=>null,
  querySelectorAll:(q)=>q==='.sli-ds-state' ? [state] : q==='[aria-label],[title],[placeholder]' ? [aria] : [],
  createTreeWalker:()=>({index:-1,nextNode(){this.index++;this.currentNode=nodes[this.index];return !!this.currentNode;}})};
"""


def test_crawler_captures_complete_detail_and_template_provenance():
    result = crawler_eval("pageSnapshot({locale:'en',data:[{text:'Тестовый объект',path:'object.display_name'},"
                          "{text:'Тестовый отчёт',path:'report.name'}]})", FAKE_DOM)
    assert result["placeholders"][0]["detail"] == "Complete explanation " * 29 + "Complete explanation"
    assert result["cyrillic"][0]["origin"] == "data"
    assert result["cyrillic"][1]["origin"] == "ui"
    assert result["cyrillic"][2]["template"] == "Закрепить {data}"
    rec = record(locale="en", cyrillic=result["cyrillic"])
    assert set(findings(rules.check_cyrillic, rec)[0]["strings"]) == {"Активные", "Закрепить {data}"}


def test_crawler_aria_substitution_does_not_hide_part_of_a_ui_word():
    setup = FAKE_DOM + "\naria.getAttribute=(a)=>a==='aria-label' ? 'Неактивные' : null;"
    result = crawler_eval("pageSnapshot({locale:'en',data:[{text:'активные',path:'object.name'}]})", setup)
    assert result["cyrillic"][-1]["text"] == "Неактивные"
    assert "template" not in result["cyrillic"][-1]
