"""Frozen pure report functions, with synthetic inputs and no runtime/database import."""
import ast
import collections.abc
import datetime as dt
import json
from pathlib import Path
import runpy
import types
from typing import Any

ROOT = Path(__file__).resolve().parents[4]
BASE = ROOT / "server/sli/plugins/ad/reports"
security = types.SimpleNamespace(**runpy.run_path(str(BASE / "users_security.py")))


def load(name, namespace):
    tree = ast.parse((BASE / (name + ".py")).read_text("utf-8"))
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.Assign, ast.AnnAssign)):
            exec(compile(ast.Module([node], type_ignores=[]), name, "exec"), namespace)
    return namespace


common = dict(datetime=dt.datetime, timezone=dt.timezone, timedelta=dt.timedelta,
              Mapping=collections.abc.Mapping, Iterable=collections.abc.Iterable,
              Sequence=collections.abc.Sequence, Any=Any, json=json)
hygiene = types.SimpleNamespace(**load("ad_hygiene_policy", dict(common)))
hygiene.thresholds = lambda: dict(password_age=90, inactivity=90)
ns = load("users_v2_views", dict(common, users_security=security, ad_hygiene_policy=hygiene))
observed = "2026-11-01T12:00:00Z"
user = dict(id="user:11", entityId=11, objectGuid="00000000-0000-0000-0000-000000000011",
            sid="S-1-5-21-100000001-200000002-300000003-1011", displayName="Example user",
            samAccountName="example", userPrincipalName="example@example.test", enabled=True,
            passwordLastSet="2026-10-31T12:00:00Z", lastLogonTimestamp="2026-10-31T12:00:00Z",
            sourceStates={"directory": {"status": "observed", "observed_at": observed}},
            memberships={"status": "observed", "direct": [], "effective": [], "paths": [], "unresolved": []})
vectors = []
cases = [user, {}, {**user, "lockedOut": True, "passwordExpired": True,
         "accountExpirationDate": "2026-01-01T00:00:00Z", "userAccountControl": 0x4100a0,
         "trustedForDelegation": True, "trustedToAuthForDelegation": True, "useDesKeyOnly": True,
         "servicePrincipalNames": ["HTTP/service.example.test"], "passwordLastSet": "2024-01-01T00:00:00Z",
         "lastLogonTimestamp": "2024-01-01T00:00:00Z", "memberships": {"status": "partial", "unresolved": ["unknown"],
             "effective": [{"id": "group:1", "name": "Example watch", "watchGroup": True, "relation": "nested"}]}},
         {**user, "passwordLastSet": "2027-01-01T00:00:00Z", "sourceStates": {"directory": {"status": "partial"}}},
         {**user, "exactLastLogon": "2026-11-01T01:00:00Z", "sourceStates": {"exact_last_logon": {"status": "partial"}}}]
for value in cases:
    vectors.append(dict(user=value, observed=observed, row=ns["user_row"](value, observed, dict(password_age=90, inactivity=90))))
templates = {}
for vector in vectors:
    for reason in vector["row"]["review_details"]:
        templates[reason["key"]] = {k: v for k, v in reason.items() if k not in {"category", "policy", "evidence", "password_evaluation", "flags"}}
templates["temporary_membership"] = ns["_reason"]("temporary_membership", "", "", "Наблюдались добавление и последующее удаление в выбранном коротком окне",
    "Наблюдаемая последовательность по точному SID участника и группы; неоднозначные удаления отмечены отдельно.",
    "Корреляция и вход внутри интервала не доказывают использование выданного права; полнота источника не подтверждена.",
    "Открыть вкладку краткого членства и проверить события, повторы и допустимость временного доступа.")
# Unknown and exceeded conditions have different source-generated text. Keep both.
for kind in ("password_age", "inactivity"):
    key = "password_age_unknown" if kind == "password_age" else "enabled_activity_unknown"
    if key not in templates:
        raise AssertionError(key)
(ROOT / "server-dotnet/src/Sli.Server/Ad/user-reasons.json").write_text(json.dumps(templates, ensure_ascii=False, indent=2) + "\n", "utf-8")
Path(__file__).with_name("inventory-reference.json").write_text(json.dumps(vectors, ensure_ascii=False, indent=2) + "\n", "utf-8")
(ROOT / "server-dotnet/src/Sli.Server/Ad/user-change-fields.json").write_text(json.dumps(dict(fields=ns["_SIMPLE_CHANGES"], groups=ns["CHANGE_GROUPS"]), ensure_ascii=False, indent=2) + "\n", "utf-8")
comparisons=[]
for current, previous in [(cases[2], user), (user, cases[3]), (cases[4], user)]:
    left,right=dict(users=[current]),dict(users=[previous])
    comparisons.append(dict(current=left,previous=right,rows=ns["compare"](left,right)))
Path(__file__).with_name("changes-reference.json").write_text(json.dumps(comparisons, ensure_ascii=False, indent=2) + "\n", "utf-8")
computer_templates={}
tree=ast.parse((BASE / "computers_v6_reporting_items.py").read_text("utf-8"))
for call in ast.walk(tree):
    if isinstance(call,ast.Call) and isinstance(call.func,ast.Attribute) and call.func.attr=="_reason" and isinstance(call.args[0],ast.Constant):
        code=call.args[0].value
        reason=dict(code=code,family=code,rule_version=1,source_sections=["directory_accounts"],threshold_days=None,requires_human_review=True)
        for field,arg in zip(("code","label","observed","condition","qualification","limitation","next_action"),call.args):
            if isinstance(arg,ast.Constant):
                reason[field]=arg.value
        computer_templates[code]=reason
(ROOT / "server-dotnet/src/Sli.Server/Ad/computer-reasons.json").write_text(json.dumps(computer_templates, ensure_ascii=False, indent=2) + "\n", "utf-8")
metadata={}
for path,names in [(BASE/"active_directory_reporting.py",["_CONTROL_CONTEXT_FIELDS"]),(BASE/"definitions/ad_state.py",["CONTEXT_LABELS","ENUM_LABELS"])]:
    for node in ast.parse(path.read_text("utf-8")).body:
        if isinstance(node,ast.Assign) and isinstance(node.targets[0],ast.Name) and node.targets[0].id in names:
            metadata[node.targets[0].id]=ast.literal_eval(node.value)
(ROOT / "server-dotnet/src/Sli.Server/Ad/control-context.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", "utf-8")
exports={}
for node in ast.parse((BASE/"computers_v6_reporting.py").read_text("utf-8")).body:
    if isinstance(node,ast.Assign) and isinstance(node.targets[0],ast.Name) and node.targets[0].id in {"COMPUTERS_V6_EXPORT_COLUMNS","COMPUTERS_V6_EXPORT_LABELS"}:
        exports[node.targets[0].id]=ast.literal_eval(node.value)
(ROOT / "server-dotnet/src/Sli.Server/Ad/computer-export.json").write_text(json.dumps(exports,ensure_ascii=False,indent=2)+"\n","utf-8")
failures={}
for node in ast.parse((BASE/"definitions/new_logon_pairs.py").read_text("utf-8")).body:
    if isinstance(node,ast.Assign) and isinstance(node.targets[0],ast.Name) and node.targets[0].id in {"_FAILURE_TEXT","_REASON_CODES"}:
        failures[node.targets[0].id]=ast.literal_eval(node.value)
(ROOT / "server-dotnet/src/Sli.Server/Ad/pair-failures.json").write_text(json.dumps(failures, ensure_ascii=False, indent=2) + "\n", "utf-8")

def pure(path,namespace):
    for node in ast.parse(path.read_text("utf-8")).body:
        if isinstance(node,(ast.FunctionDef,ast.Assign,ast.AnnAssign)):
            try:
                exec(compile(ast.Module([node],type_ignores=[]),str(path),"exec"),namespace)
            except NameError:
                pass
    return namespace

def utc(value):
    if not value:
        return None
    return value if isinstance(value,dt.datetime) else dt.datetime.fromisoformat(value.replace("Z","+00:00"))

catalog=json.loads((ROOT/"config/i18n/server.ru.json").read_text("utf-8"))
def message(code,params=None):
    return dict(code=code,params=params or {},text=catalog[code].format(**(params or {})))

active=pure(BASE/"active_directory_reporting.py",dict(common,parse_utc=utc,format_csv_cell=str))
definition=pure(BASE/"definitions/ad_state.py",dict(common,catalog=lambda _:catalog,message=message))
entities=[]
for kind in ("domain_controller","domain","replication_link","password_policy","domain_trust"):
    attrs={}
    for identity in json.loads((ROOT/"server-dotnet/src/Sli.Server/Ad/control-templates.json").read_text("utf-8")):
        owner,field=identity.split(":")
        if owner!=kind:
            continue
        attrs[field]="passed" if field.endswith("_state") else 0 if field in {"last_replication_result","consecutive_failure_count"} else "2026-11-01T01:00:00Z" if field=="last_replication_success_utc" else "unknown" if field.startswith("ldap_") else True
    attrs.update(dict(dns_host_name="dc.example.test",distinguished_name="DC=example,DC=test"))
    entity=dict(entity_id=100+len(entities),domain_id=7,domain_name="example.test",entity_type=kind,display_name="Example "+kind,source_section="domain_health",observed_at_utc=observed,attributes=attrs)
    entities.append(entity)
controls=[definition["_row"](row) for row in active["build_active_directory_controls"](entities)]
order={value:i for i,value in enumerate(("failed","not_evaluated","policy_not_defined","passed"))}
controls.sort(key=lambda row:(order[row["qualification"]],row["entity_name"],row["label"]))
input_rows=[]
for entity in entities:
    item={k:v for k,v in entity.items() if k!="attributes"}
    attrs=dict(entity["attributes"])
    if item["entity_type"]=="domain_controller":
        item["entity_type"]="ad_computer"
        attrs["infrastructure_role"]="domain_controller"
    item["record"]=json.dumps(dict(attributes=attrs))
    input_rows.append(item)
cursor_ns=pure(ROOT/"server/sli/core/keyset_cursor.py",dict(common,base64=__import__("base64"),sha256=__import__("hashlib").sha256))
context=dict(domain=7,q="пример",period="7d",baseline_days=30,user="")
position=dict(first_seen=observed,id="a"*64,start=observed,end="2026-11-02T12:00:00Z")
review=pure(BASE/"review_checks.py",dict(common,_dt=ns["_dt"],best_activity=ns["best_activity"],users_security=security))
checks=[dict(user=value,at=observed,previous=user,previous_complete=True,result=review["evaluate"]("users",value,utc(observed),user,True,[])) for value in cases]
from enum import Enum
result_ns=pure(ROOT/"server/sli/reporting/v2/definition.py",dict(common,message=message,ReportDefinition=types.SimpleNamespace,ResultState=Enum("ResultState",{key:key for key in ("ok","empty","partial","stale","denied","error","processing","not_collected")})))
results=[]
for coverage in [{},{"completeness":"not_proven"},{"state":"unavailable"},{"state":"not_collected"},{"state":"processing"},{"observed_at_utc":"2000-01-01T00:00:00Z","freshness_threshold_seconds":86400},{"domains":[{"domain_id":7,"domain_name":"example.test","section_name":"directory_accounts","section_status":"failed"}]},{"state":"partial","truncated":True}]:
    results.append(dict(coverage=coverage,result=result_ns["result"](types.SimpleNamespace(key="ad.users.v2"),state="ok",coverage=coverage)))
spn=pure(BASE.parent/"spn_collisions.py",dict(common,defaultdict=__import__("collections").defaultdict,parse_utc=utc,format_iso=lambda value:utc(value).isoformat().replace("+00:00","Z")))
spn_rows=[]
for index in (11,12):
    attrs=dict(enabled=index==11,trusted_for_delegation=index==12,trusted_to_auth_for_delegation=False,does_not_require_preauth=False,msds_supported_encryption_types=28,password_last_set_utc="2026-10-01T12:00:00Z",service_principal_names=["HTTP/service.example.test" if index==11 else "http/service.example.test"])
    spn_rows.append(dict(entity_id=index,entity_type="ad_user",domain_id=7,run_id="00000000-0000-0000-0000-000000000001",observed_at_utc=observed,attributes_json=dict(identity=dict(object_guid=f"00000000-0000-0000-0000-{index:012}"),attributes=attrs)))
spn_result=spn["analyze"](spn_rows,now=utc(observed))
spn_inputs=[{**row,"attributes_json":json.dumps(row["attributes_json"])} for row in spn_rows]
Path(__file__).with_name("control-reference.json").write_text(json.dumps(dict(entities=input_rows,rows=controls,checks=checks,results=results,spn_inputs=spn_inputs,spn_result=spn_result,cursor_context=context,cursor_position=position,cursor=cursor_ns["encode_cursor"](context,position)),ensure_ascii=False,indent=2)+"\n","utf-8")
