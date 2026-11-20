"""Execute only pure functions from the frozen reader sources; never import runtime."""
import ast
import collections.abc
import datetime as dt
import json
from pathlib import Path
import runpy
from typing import Any

ROOT = Path(__file__).resolve().parents[4]
CATALOG = runpy.run_path(str(ROOT / "server/sli/plugins/ad/windows_ad_dc/catalog.py"))


def utc(value):
    if value is None:
        return None
    parsed = value if isinstance(value, dt.datetime) else dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=parsed.tzinfo or dt.timezone.utc).astimezone(dt.timezone.utc)


def text(value):
    return str(value).strip() or None if value is not None else None


def source(module):
    ns = dict(CATALOG, Any=Any, Mapping=collections.abc.Mapping, Sequence=collections.abc.Sequence,
              datetime=dt.datetime, timedelta=dt.timedelta, timezone=dt.timezone,
              _utc=utc, _iso=lambda v: utc(v).isoformat().replace("+00:00", "Z"), _text=text,
              _sid=lambda v: None if text(v) == "-" else text(v),
              _public=lambda v: v.hex() if isinstance(v, bytes) else v,
              AD_GROUP_MEMBERSHIP_EVENT_IDS=frozenset(CATALOG["_GROUP_MEMBERSHIP_CHANGE_BY_EVENT_ID"]))
    tree = ast.parse((ROOT / f"server/sli/plugins/ad/reports/{module}.py").read_text("utf-8"))
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.Assign, ast.AnnAssign)):
            try:
                exec(compile(ast.Module([node], type_ignores=[]), "reference", "exec"), ns)
            except NameError:
                pass
    return ns


vectors = []
start, end = utc("2026-11-01T00:00:00Z"), utc("2026-11-02T00:00:00Z")
for kind, module, function in (
    ("account", "ad_account_state_reporting", "compose_ad_account_change_history"),
    ("membership", "ad_group_membership_reporting", "compose_ad_group_membership_history"),
    ("powershell", "dc_powershell_reporting", "compose_dc_powershell_activity"),
):
    ns = source(module)
    ids = ([4720, 4722, 4725, 4726, 4738, 4740, 4767, 4781, 4723, 4724] if kind == "account"
           else [4728, 4729, 4732, 4756, 4757] if kind == "membership" else [4103, 4104])
    events = []
    for index, event_id in enumerate(ids):
        row = dict(event_db_id=index + 1, event_record_id=100 + index, event_id=event_id,
                   time_created_utc=f"2026-11-01T01:{index:02}:00Z", domain_controller="dc.example.test",
                   subject_user_sid="S-1-5-21-100000001-200000002-300000003-1", subject_user_name="actor",
                   target_user_sid="S-1-5-21-100000001-200000002-300000003-2", target_user_name="target",
                   source_core_sha256="a" * 64, source_facts_sha256="b" * 64)
        if kind == "account":
            row.update(account_name_before="old" if event_id == 4781 else None,
                       account_name_after="new" if event_id == 4781 else None,
                       result_code="0x0" if event_id in (4723, 4724) else None)
        if kind == "membership":
            row.update(membership_member_sid="S-1-5-21-100000001-200000002-300000003-3", membership_member_name="member",
                       controlled_group_context_evidence_id=23,
                       controlled_group_context_observed_at_utc="2026-11-01T00:00:00Z")
        if kind == "powershell":
            row.update(powershell_command_name="Get-Process" if event_id == 4103 else None,
                       powershell_script_block_text="=synthetic" if event_id == 4104 else None)
        events.append(row)
    for selected, history in ((events, True), ([], True), ([], False)):
        args = dict(source_domain_id=1, period_start=start, period_end=end, events=selected,
                    collection_coverage={"history_event_present": history})
        if kind == "powershell":
            args["include_script_block_text"] = False
        vectors.append(dict(kind=kind, events=selected, history=history, expected=ns[function](**args)))
Path(__file__).with_name("reference.json").write_text(json.dumps(vectors, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"{len(vectors)} reference cases")
