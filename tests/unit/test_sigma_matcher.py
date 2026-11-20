from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from server.sli.sigma import matcher
from server.sli.sigma.compiler import CompiledRule, IRExpression, IRValue, PatternPart, compile_rule
from server.sli.sigma.matcher import MatchLimits, match_rule


def compare(value, name="CommandLine"):
    return IRExpression("compare", field=name, value=value)


def pattern(*parts):
    return IRValue("pattern", parts=tuple(
        PatternPart(part) if part in ("any", "one") else PatternPart("literal", part) for part in parts
    ))


def plan(expression):
    fields = set()

    def visit(node):
        if node.field:
            fields.add(node.field)
        for arg in node.args:
            visit(arg)

    visit(expression)
    return CompiledRule("00000000-0000-0000-0000-000000000001", "a" * 64, "security", expression,
                        tuple(sorted(fields)), "Fixture Team", "DRL-1.1", "", "b" * 40)


def compiled(selection, *, condition="selection", definitions=None):
    pytest.importorskip("sigma.rule", reason="Install isolated config/sigma/requirements.lock.txt")
    document = {
        "title": "Synthetic matcher fixture", "id": "00000000-0000-0000-0000-000000000001",
        "author": "Fixture Team", "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"selection": selection, **(definitions or {}), "condition": condition},
    }
    return compile_rule(yaml.safe_dump(document, sort_keys=False).encode())


@pytest.mark.parametrize("value,positive,negative", [
    (pattern("FiXtUrE"), "fixture", "fixture-extra"),
    (pattern("any", "fixture", "any"), "before FIXTURE after", "unrelated"),
    (pattern("fixture", "any"), "FIXTURE after", "before fixture"),
    (pattern("any", "fixture"), "before FIXTURE", "fixture after"),
    (pattern("a", "one", "c"), "a\nc", "ac"),
    (pattern("a", "any", "c"), "a\n\nc", "a\n\nd"),
    (pattern(r"C:\Fixture\literal*?[x].exe"), r"c:\fixture\literal*?[x].EXE", r"C:\Fixture\literalZZx.exe"),
    (pattern(), "", "fixture"),
    (IRValue("number", 9), "09", "0x9"),
    (IRValue("number", 9), 9, "9.0"),
    (IRValue("number", -9), "-09", "  -9"),
    (IRValue("null"), None, ""),
])
def test_primitive_positive_and_near_negative_corpus(value, positive, negative):
    rule = plan(compare(value))
    assert match_rule(rule, {"CommandLine": positive}).status == "matched"
    assert match_rule(rule, {"CommandLine": negative}).status == "not_matched"


@pytest.mark.parametrize("modifier,value,positive,negative", [
    ("contains", "fixture", "prefix FIXTURE suffix", "unrelated"),
    ("startswith", "fixture", "FIXTURE suffix", "prefix fixture"),
    ("endswith", "fixture", "prefix FIXTURE", "fixture suffix"),
    ("contains|all", ["fixture-a", "fixture-b"], "FIXTURE-B fixture-a", "fixture-a"),
    ("contains", ["fixture-a", "fixture-b"], "FIXTURE-B", "fixture-c"),
    ("", r"C:\Fixture\literal\*\?*?.exe", r"C:\Fixture\literal*?x.EXE", r"C:\Fixture\literalZZx.exe"),
])
def test_compiler_to_matcher_modifiers_and_escape(modifier, value, positive, negative):
    rule = compiled({"CommandLine" + ("|" + modifier if modifier else ""): value})
    assert match_rule(rule, {"CommandLine": positive}).status == "matched"
    assert match_rule(rule, {"CommandLine": negative}).status == "not_matched"


@pytest.mark.parametrize("dash", ["-", "/", "\u2013", "\u2014", "\u2015"])
def test_windash_and_all_expansions(dash):
    rule = compiled({"CommandLine|contains|all|windash": [" -fixture", " /second"]})
    assert match_rule(rule, {"CommandLine": f"tool {dash}fixture {dash}second"}).status == "matched"
    assert match_rule(rule, {"CommandLine": f"tool {dash}fixture"}).status == "not_matched"


def test_condition_lists_filters_and_negation():
    rule = compiled({"Image|endswith": [r"\fixture.exe", r"\alternate.exe"]},
                    condition=["selection and not 1 of filter_*", "fallback"], definitions={
                        "filter_one": {"CommandLine|contains": "benign"},
                        "filter_two": {"CommandLine|startswith": "allowed"},
                        "fallback": {"ParentImage|endswith": r"\fallback.exe"},
                    })
    fields = {"Image": r"C:\Fixture\FIXTURE.EXE", "CommandLine": "tool suspicious", "ParentImage": "fixture"}
    assert match_rule(rule, fields).status == "matched"
    assert match_rule(rule, {**fields, "CommandLine": "tool benign"}).status == "not_matched"
    assert match_rule(rule, {**fields, "CommandLine": "allowed tool"}).status == "not_matched"
    assert match_rule(rule, {**fields, "Image": "fixture", "ParentImage": r"C:\fallback.exe"}).status == "matched"
    # Unknown negated filters never become a positive match.
    del fields["CommandLine"]
    assert match_rule(rule, fields).status == "not_evaluable"


@pytest.mark.parametrize("fields,unavailable,expected,reason", [
    ({}, None, "not_evaluable", "field_missing"),
    ({"CommandLine": None}, None, "not_evaluable", "field_null"),
    ({"CommandLine": ""}, None, "matched", None),
    ({"CommandLine": "fixture"}, {"CommandLine": "not_in_event_version"}, "not_evaluable", "field_unavailable"),
    ({"CommandLine": ()}, None, "not_evaluable", "field_empty_collection"),
])
def test_absent_null_empty_and_unavailable_under_negation(fields, unavailable, expected, reason):
    rule = plan(IRExpression("not", (compare(pattern("fixture")),)))
    result = match_rule(rule, fields, unavailable=unavailable)
    assert result.status == expected
    assert result.reasons == ((reason,) if reason else ())


@pytest.mark.parametrize("op,known,expected", [("and", "different", "not_matched"), ("or", "fixture", "matched")])
def test_three_valued_logic_can_be_decided_by_known_branch(op, known, expected):
    rule = plan(IRExpression(op, (compare(pattern("fixture"), "Image"), compare(pattern("fixture")))))
    assert match_rule(rule, {"CommandLine": known}).status == expected


def test_multivalued_fields_are_any_and_native_values_not_mutated():
    rule = plan(compare(pattern("fixture")))
    fields = {"CommandLine": ("benign", "FIXTURE")}
    assert match_rule(rule, fields).status == "matched"
    assert match_rule(rule, {"CommandLine": ("benign", "other")}).status == "not_matched"
    assert fields == {"CommandLine": ("benign", "FIXTURE")}
    assert match_rule(rule, {"CommandLine": (None, "benign")}).status == "not_evaluable"


@pytest.mark.parametrize("native", [True, 9.0, {}, ["fixture"]])
def test_unadmitted_types_do_not_gain_matches_from_string_coercion(native):
    assert match_rule(plan(compare(pattern("any"))), {"CommandLine": native}).reasons == ("field_type_unsupported",)


@pytest.mark.parametrize("pattern_text,positive,negative", [
    (r"\bFiXtUrE\.exe\s+-a.*\?$", "tool FiXtUrE.exe -a arg?", "tool fixture.exe -a arg?"),
    (r"^fixture$", "fixture", "prefix fixture suffix"),
    (r"(?i)fixture", "prefix FIXTURE suffix", "unrelated"),
])
def test_regex_search_case_flags_and_escape(pattern_text, positive, negative):
    rule = plan(compare(IRValue("regex", pattern_text)))
    assert match_rule(rule, {"CommandLine": positive}).status == "matched"
    assert match_rule(rule, {"CommandLine": negative}).status == "not_matched"


def test_regex_compiler_to_matcher():
    rule = compiled({"CommandLine|re": r"fixture\.exe\s+-a"})
    assert match_rule(rule, {"CommandLine": "tool fixture.exe -a"}).status == "matched"
    assert match_rule(rule, {"CommandLine": "tool fixtureXexe -a"}).status == "not_matched"


def test_real_catastrophic_regex_is_killed_and_reaped_under_negation(monkeypatch):
    children = []
    popen = subprocess.Popen

    def track(*args, **kwargs):
        child = popen(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", track)
    rule = plan(IRExpression("not", (compare(IRValue("regex", r"(a+)+$")),)))
    limits = replace(MatchLimits(), regex_timeout_seconds=0.1)
    started = time.monotonic()
    result = match_rule(rule, {"CommandLine": "a" * 20000 + "!"}, limits=limits)
    assert result.status == "not_evaluable"
    assert result.reasons == ("regex_timeout",)
    assert time.monotonic() - started < 2
    assert children and all(child.returncode is not None and child.poll() is not None for child in children)


@pytest.mark.parametrize("text", ["[", "(?P<fixture>"])
def test_invalid_regex_cannot_turn_negation_into_match_or_disclose_input(text, capsys):
    rule = plan(IRExpression("not", (compare(IRValue("regex", text)),)))
    result = match_rule(rule, {"CommandLine": "private-fixture-value"})
    assert result.status == "not_evaluable"
    assert result.reasons == ("regex_invalid_or_resource_limit",)
    assert "private-fixture-value" not in repr(result)
    assert capsys.readouterr() == ("", "")


def test_regex_worker_failures_are_unknown(monkeypatch):
    rule = plan(compare(IRValue("regex", "fixture")))
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_kw: SimpleNamespace(returncode=-9, stdout=""))
    assert match_rule(rule, {"CommandLine": "fixture"}).reasons == ("regex_invalid_or_resource_limit",)

    def unavailable(*_a, **_kw):
        raise OSError("private-fixture-value")

    monkeypatch.setattr(subprocess, "run", unavailable)
    result = match_rule(rule, {"CommandLine": "fixture"})
    assert result.reasons == ("regex_worker_failed",)
    assert "private-fixture-value" not in repr(result)


def test_regex_worker_memory_limit_and_redacted_errors():
    worker = matcher._REGEX_WORKER
    # Repeated empty matches exhaust the child's backtracking allocation.
    # Neither compilation nor search runs in the main process.
    result = subprocess.run([sys.executable, "-I", str(worker)],
                            input=json.dumps([r"(?:a?){100000000}", ""]),
                            text=True, capture_output=True, timeout=2, check=False)
    assert result.returncode != 0
    assert result.stdout == result.stderr == ""


@pytest.mark.parametrize("fields,limits,reason", [
    ({"CommandLine": "fixture"}, replace(MatchLimits(), max_field_chars=3), "field_size_limit"),
    ({"CommandLine": ("a", "b")}, replace(MatchLimits(), max_values=1), "field_value_limit"),
    ({"CommandLine": 2 ** 65}, MatchLimits(), "field_size_limit"),
    ({"CommandLine": "a" * 100}, replace(MatchLimits(), max_steps=20), "work_limit"),
])
def test_field_and_work_budgets_never_truncate_to_clean(fields, limits, reason):
    result = match_rule(plan(compare(pattern("fixture"))), fields, limits=limits)
    assert result.status == "not_evaluable"
    assert result.reasons == (reason,)


def test_glob_backtracking_has_work_budget():
    rule = plan(compare(pattern("any", "a" * 100 + "b")))
    result = match_rule(rule, {"CommandLine": "a" * 10000}, limits=replace(MatchLimits(), max_steps=20000))
    assert result.status == "not_evaluable"
    assert result.reasons == ("work_limit",)


def test_time_and_regex_call_budgets(monkeypatch):
    ticks = iter((0.0, 3.0))
    monkeypatch.setattr(matcher.time, "monotonic", lambda: next(ticks))
    assert match_rule(plan(compare(pattern("fixture"))), {}).reasons == ("time_limit",)
    monkeypatch.undo()
    rule = plan(IRExpression("and", (compare(IRValue("regex", "fixture")),) * 2))
    result = match_rule(rule, {"CommandLine": "fixture"}, limits=replace(MatchLimits(), max_regex_calls=1))
    assert result.reasons == ("regex_call_limit",)


@pytest.mark.parametrize("expression", [
    IRExpression("unsupported"), IRExpression("not"), IRExpression("or"),
    IRExpression("compare", field="CommandLine", value=IRValue("unknown")),
    IRExpression("compare", field="CommandLine", value=IRValue("pattern", parts=(PatternPart("unknown"),))),
    IRExpression("compare", field="CommandLine", value=IRValue("number", True)),
])
def test_invalid_ir_is_rejected_even_in_unreached_branches(expression):
    rule = plan(IRExpression("or", (compare(pattern("fixture")), expression)))
    result = match_rule(rule, {"CommandLine": "fixture"})
    assert result.status == "not_evaluable"
    assert result.reasons == ("invalid_ir",)


def test_ir_versions_fields_depth_node_and_pattern_limits():
    rule = plan(compare(pattern("fixture")))
    for key in ("ir_version", "compiler_version", "parser_version", "mapping_version"):
        assert match_rule(replace(rule, **{key: "future"}), {}).reasons == ("ir_version_unsupported",)
    assert match_rule(replace(rule, required_fields=()), {}).reasons == ("invalid_ir",)
    nested = IRExpression("not", (rule.expression,))
    assert match_rule(plan(nested), {}, limits=replace(MatchLimits(), max_nodes=1)).reasons == ("ir_complexity_limit",)
    nested = IRExpression("not", (nested,))
    assert match_rule(plan(nested), {}, limits=replace(MatchLimits(), max_depth=1)).reasons == ("ir_complexity_limit",)
    assert match_rule(rule, {}, limits=replace(MatchLimits(), max_pattern_chars=3)).reasons == ("pattern_size_limit",)


@pytest.mark.parametrize("values", [
    {"max_steps": 0}, {"max_field_chars": -1}, {"max_values": True}, {"max_depth": 49},
    {"timeout_seconds": float("nan")}, {"regex_timeout_seconds": float("inf")}, {"timeout_seconds": 11},
])
def test_invalid_limits(values):
    with pytest.raises(ValueError, match="^sigma_match_limits_invalid$"):
        MatchLimits(**values)


def test_replay_hash_binds_plan_input_limits_and_result_but_not_field_order():
    rule = plan(IRExpression("and", (compare(pattern("fixture")), compare(IRValue("number", 9), "LogonType"))))
    fields = {"CommandLine": "fixture", "LogonType": "9"}
    first = match_rule(rule, fields)
    assert first == match_rule(rule, dict(reversed(list(fields.items()))))
    assert first == match_rule(rule, {**fields, "unused": "private-fixture-value"})
    assert first.replay_sha256 != match_rule(rule, {**fields, "CommandLine": "FiXtUrE"}).replay_sha256
    assert first.replay_sha256 != match_rule(replace(rule, source_sha256="c" * 64), fields).replay_sha256
    assert first.replay_sha256 != match_rule(rule, fields, limits=replace(MatchLimits(), max_steps=10000)).replay_sha256
    assert first.replay_sha256 != match_rule(rule, fields, unavailable={"LogonType": "missing"}).replay_sha256
    assert len(first.replay_sha256) == 64
    assert "fixture" not in repr(first)


# Synthetic native field values only. Each pair exercises the actual pinned
# rule with one nearby negative change, rather than generating a witness from
# the matcher's own interpretation. This is not historical LAB acceptance.
PROFILE_CORPUS = [
    ("d99b79d2-0a6f-4f46-ad8b-260b6e17f982",
     {"EventID": 1102, "Provider_Name": "Microsoft-Windows-Eventlog"}, {"EventID": 1103}),
    ("ab4561b1-6c7e-48a7-ad08-087cfb9ce8f1",
     {"EventID": 4719, "AuditPolicyChanges": "%%8448",
      "SubcategoryGuid": "{0CCE9210-69AE-11D9-BED3-505054503030}"}, {"AuditPolicyChanges": "%%8449"}),
    ("d04ae2b8-ad54-4de0-bd87-4bc1da66aa59",
     {"EventID": 4769, "Status": "0x0", "TicketEncryptionType": "0x17", "ServiceName": "fixture-service",
      "TargetUserName": "fixture-user"}, {"ServiceName": "krbtgt"}),
    ("3e2f1b2c-4d5e-11ee-be56-0242ac120002",
     {"EventID": 4768, "PreAuthType": "0", "ServiceName": "krbtgt", "TicketEncryptionType": "0x17"},
     {"PreAuthType": "2"}),
    ("496a0e47-0a33-4dca-b009-9e6ca3591f39",
     {"EventID": 4769, "TicketEncryptionType": "0x17", "TicketOptions": "0x40810000", "ServiceName": "fixture"},
     {"ServiceName": "fixture$"}),
    ("9eb99343-d336-4020-a3cd-67f3819e68ee",
     {"EventID": 4625, "Status": "0xC0000072", "SubStatus": "0x0", "SubjectUserSid": "S-1-5-21-1-2-3-1001"},
     {"SubjectUserSid": "S-1-0-0"}),
    ("192a0330-c20b-4356-90b6-7b7049ae0b87",
     {"EventID": 4624, "AuthenticationPackageName": "Negotiate", "LogonProcessName": "seclogo", "LogonType": "9"},
     {"LogonType": "3"}),
    ("8eef149c-bd26-49f2-9e5a-9b00e3af499b",
     {"EventID": 4624, "LogonProcessName": "seclogo", "LogonType": "9", "TargetUserName": "fixture-user"},
     {"TargetUserName": "ANONYMOUS LOGON"}),
    ("749c9f5e-b353-4b90-a9c1-05243357ca4b",
     {"EventID": 4624, "AuthenticationPackageName": "Kerberos", "IpAddress": "127.0.0.1", "LogonType": "3",
      "TargetUserSid": "S-1-5-21-1-2-3-500", "IpPort": "12345"}, {"IpPort": "0"}),
    ("7b449a5e-1db5-4dd0-a2dc-4e3a67282538",
     {"EventID": 4720, "TargetUserName": "fixture$"}, {"TargetUserName": "fixture"}),
    ("cfeed607-6aa4-4bbd-9627-b637deb723c8",
     {"EventID": 4720, "SamAccountName": "fixture$", "TargetUserName": "fixture"}, {"SamAccountName": "fixture"}),
    ("c265cf08-3f99-46c1-8d59-328247057d57",
     {"EventID": 4732, "TargetUserName": "Administrators", "TargetSid": "S-1-5-32-544",
      "SubjectUserName": "fixture-user"}, {"SubjectUserName": "fixture$"}),
    ("3a734d25-df5c-4b99-8034-af1ddb5883a4",
     {"EventID": 4698, "TaskContent": r"powershell C:\Temp\fixture.ps1"},
     {"TaskContent": r"powershell C:\Windows\System32\fixture.ps1"}),
    ("614cf376-6651-47c4-9dcc-6b9527f749f4",
     {"EventID": 4702, "TaskContentNew": r"powershell C:\Temp\fixture.ps1"},
     {"TaskContentNew": r"powershell C:\Windows\System32\fixture.ps1"}),
    ("2a926e6a-4b81-4011-8a96-e36cc8c04302",
     {"EventID": 4697, "ServiceFileName": "powershell -fixture"}, {"ServiceFileName": "fixture.exe"}),
    ("6fb63b40-e02a-403e-9ffd-3bcc1d749442",
     {"EventID": 4697, "ServiceFileName": r"%systemroot%\abcdefgh.exe", "ServiceName": "Abcd",
      "ServiceStartType": "3", "ServiceType": "0x10"}, {"ServiceStartType": "2"}),
    ("2afafd61-6aae-4df4-baed-139fa1f4c345",
     {"Image": r"C:\Fixture\ntdsutil.exe"}, {"Image": r"C:\Fixture\ntdsutil.exe.bak"}),
    ("8bc64091-6875-4881-aaf9-7bd25b5dda08",
     {"CommandLine": "tool ac i ntds create full", "Image": r"C:\Fixture\tool.exe",
      "ParentImage": r"C:\Fixture\parent.exe"}, {"CommandLine": "tool ac i ntds"}),
    ("5afee48e-67dd-4e03-a783-f74259dcf998",
     {"CommandLine": "tool -ma lsass"}, {"CommandLine": "tool -ma benign"}),
    ("ffa6861c-4461-4f59-8a41-578c39f3f23e",
     {"CommandLine": "tool lsass.dmp"}, {"CommandLine": "tool fixture.dmp"}),
    ("89ca78fd-b37c-4310-b3d3-81a023f83936",
     {"Image": r"C:\Fixture\schtasks.exe", "CommandLine": "tool /create /ru SYSTEM /tn fixture"},
     {"CommandLine": "tool /create /ru fixture-user /tn fixture"}),
    ("39019a4e-317f-4ce3-ae63-309a8c6b53c5",
     {"Image": r"C:\Fixture\schtasks.exe", "CommandLine": r"tool /create /sc once /tr C:\Temp\fixture.exe"},
     {"CommandLine": r"tool /create /sc daily /tr C:\Temp\fixture.exe"}),
    ("02b64f1b-3f33-4e67-aede-ef3b0a5a8fcf",
     {"CommandLine": '[Type]::GetTypeFromCLSID("00024500-0000-0000-C000-000000000046")'},
     {"CommandLine": '[Type]::GetTypeFromCLSID("00000000-0000-0000-0000-000000000001")'}),
    ("42c575ea-e41e-41f1-b248-8093c3e82a28",
     {"EventID": 7045, "Provider_Name": "Service Control Manager", "ServiceName": "PSEXESVC",
      "ImagePath": r"C:\Fixture\fixture.exe"}, {"ServiceName": "fixture"}),
    ("1d61f71d-59d2-479e-9562-4ff5f4ead16b",
     {"EventID": 7045, "Provider_Name": "Service Control Manager", "ImagePath": r"C:\Temp\fixture.exe"},
     {"ImagePath": r"C:\Fixture\fixture.exe"}),
]


@pytest.fixture(scope="module")
def pinned_profile():
    archive = os.environ.get("SLI_SIGMA_ARCHIVE")
    if not archive:
        pytest.skip("Set SLI_SIGMA_ARCHIVE to the separately obtained pinned ZIP")
    pytest.importorskip("sigma.rule", reason="Install isolated config/sigma/requirements.lock.txt")
    from scripts.dev.verify_sigma_package import verify_package

    rules = verify_package(Path(archive))
    assert [entry.id for entry in rules] == [entry[0] for entry in PROFILE_CORPUS]
    return {entry.id: compile_rule(entry.raw_yaml, source_uri=entry.source_uri,
                                   upstream_commit=entry.upstream_commit, license_id=entry.license)
            for entry in rules}


@pytest.mark.parametrize("rule_id,positive,negative_change", PROFILE_CORPUS, ids=[item[0] for item in PROFILE_CORPUS])
def test_all_25_pinned_rules_positive_and_near_negative(pinned_profile, rule_id, positive, negative_change):
    rule = pinned_profile[rule_id]
    fields = {**dict.fromkeys(rule.required_fields, "fixture"), **positive}
    positive_result = match_rule(rule, fields)
    negative_result = match_rule(rule, {**fields, **negative_change})
    assert positive_result.status == "matched"
    assert negative_result.status == "not_matched"
    assert positive_result.reasons == negative_result.reasons == ()
    assert positive_result == match_rule(rule, dict(reversed(list(fields.items()))))


def test_profile_replay_hash_survives_reversed_delivery_order(pinned_profile):
    def replay(corpus):
        hashes = []
        for rule_id, positive, negative_change in corpus:
            rule = pinned_profile[rule_id]
            fields = {**dict.fromkeys(rule.required_fields, "fixture"), **positive}
            for values in (fields, {**fields, **negative_change}):
                hashes.append(match_rule(rule, values).replay_sha256)
        return hashlib.sha256("".join(sorted(hashes)).encode()).hexdigest()

    assert replay(PROFILE_CORPUS) == replay(reversed(PROFILE_CORPUS))
