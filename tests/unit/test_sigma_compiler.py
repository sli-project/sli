from __future__ import annotations

import hashlib
import json
import os
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
import yaml

from scripts.dev import compile_sigma_profile as profile_compiler
from server.sli.sigma import compiler
from server.sli.sigma.compiler import IRExpression, IRValue, PatternPart, UnsupportedRule, compile_rule

RULE_ID = str(UUID(int=1))


@pytest.fixture(autouse=True)
def pinned_parser():
    pytest.importorskip("sigma.rule", reason="Install isolated config/sigma/requirements.lock.txt")


def rule_yaml(detection=None, *, logsource=None, **extra):
    document = {
        "title": "Synthetic compiler fixture",
        "id": RULE_ID,
        "author": "Fixture Team",
        "logsource": logsource or {"product": "windows", "service": "security"},
        "detection": detection or {"selection": {"EventID": 1}, "condition": "selection"},
        **extra,
    }
    return yaml.safe_dump(document, sort_keys=False).encode()


def number(value, name="EventID"):
    return IRExpression("compare", field=name, value=IRValue("number", value))


def string(value, name="TargetUserName"):
    return IRExpression("compare", field=name, value=IRValue("pattern", parts=(PatternPart("literal", value),)))


def process_rule(selection):
    return compile_rule(rule_yaml(
        {"selection": selection, "condition": "selection"},
        logsource={"product": "windows", "category": "process_creation"},
    ))


def test_condition_precedence_parentheses_and_double_negation():
    definitions = {"a": {"EventID": 1}, "b": {"EventID": 2}, "c": {"EventID": 3}}
    plan = compile_rule(rule_yaml({**definitions, "condition": "a or b and not c"}))
    assert plan.expression == IRExpression("or", (number(1), IRExpression("and", (
        number(2), IRExpression("not", (number(3),)),
    ))))
    grouped = compile_rule(rule_yaml({**definitions, "condition": "(a or b) and not not c"}))
    assert grouped.expression == IRExpression("and", (
        IRExpression("or", (number(1), number(2))),
        IRExpression("not", (IRExpression("not", (number(3),)),)),
    ))


def test_filter_wildcards_and_all_selection_are_not_dropped():
    plan = compile_rule(rule_yaml({
        "selection_a": {"EventID": 1}, "selection_b": {"LogonType": 9},
        "filter_main_a": {"TargetUserName": "fixture-a"},
        "filter_main_b": {"TargetUserName": "fixture-b"},
        "condition": "all of selection_* and not 1 of filter_main_*",
    }))
    assert plan.expression == IRExpression("and", (
        IRExpression("and", (number(1), number(9, "LogonType"))),
        IRExpression("not", (IRExpression("or", (string("fixture-a"), string("fixture-b"))),)),
    ))
    assert plan.required_fields == ("EventID", "LogonType", "TargetUserName")


@pytest.mark.parametrize("selector,op", [("1 of them", "or"), ("any of them", "or"), ("all of them", "and")])
def test_them_selector(selector, op):
    plan = compile_rule(rule_yaml({
        "selection_a": {"EventID": 1}, "selection_b": {"EventID": 2}, "condition": selector,
    }))
    assert plan.expression == IRExpression(op, (number(1), number(2)))


def test_condition_list_is_or_of_complete_conditions():
    plan = compile_rule(rule_yaml({
        "a": {"EventID": 1}, "b": {"EventID": 2}, "condition": ["a", "not b"],
    }))
    assert plan.expression == IRExpression("or", (number(1), IRExpression("not", (number(2),))))


def test_list_of_maps_preserves_alternative_field_groups_and_value_lists():
    plan = compile_rule(rule_yaml({
        "selection": [{"EventID": [1, 2], "LogonType": 9}, {"EventID": 3}],
        "condition": "selection",
    }))
    assert plan.expression == IRExpression("or", (
        IRExpression("and", (IRExpression("or", (number(1), number(2))), number(9, "LogonType"))),
        number(3),
    ))


@pytest.mark.parametrize("modifier,parts", [
    ("contains", (PatternPart("any"), PatternPart("literal", "FiXtUrE"), PatternPart("any"))),
    ("startswith", (PatternPart("literal", "FiXtUrE"), PatternPart("any"))),
    ("endswith", (PatternPart("any"), PatternPart("literal", "FiXtUrE"))),
])
def test_string_modifiers_lower_to_full_field_pattern(modifier, parts):
    plan = process_rule({f"CommandLine|{modifier}": "FiXtUrE"})
    assert plan.expression.value == IRValue("pattern", parts=parts)


def test_all_values_are_and_linked():
    plan = process_rule({"CommandLine|contains|all": ["fixture-a", "fixture-b"]})
    assert plan.expression.op == "and"
    assert [item.value.parts for item in plan.expression.args] == [
        (PatternPart("any"), PatternPart("literal", "fixture-a"), PatternPart("any")),
        (PatternPart("any"), PatternPart("literal", "fixture-b"), PatternPart("any")),
    ]


def test_wildcards_and_escaped_literals_remain_distinct():
    plan = process_rule({"Image": r"C:\Fixture\literal\*\?*?.exe"})
    assert plan.expression.value.parts == (
        PatternPart("literal", "C:\\Fixture\\literal*?"),
        PatternPart("any"), PatternPart("one"), PatternPart("literal", ".exe"),
    )


def test_null_empty_and_native_hex_string_remain_distinct():
    plan = compile_rule(rule_yaml({
        "selection": {"TargetUserName": None, "SubjectUserName": "", "Status": "0x17"},
        "condition": "selection",
    }))
    assert [item.value for item in plan.expression.args] == [
        IRValue("null"), IRValue("pattern"), IRValue("pattern", parts=(PatternPart("literal", "0x17"),)),
    ]


def test_regex_text_is_not_converted_to_glob_or_casefolded():
    pattern = r"\bFiXtUrE\.exe\s+-a.*\?$"
    plan = process_rule({"CommandLine|re": pattern})
    assert plan.expression.value == IRValue("regex", pattern)


def test_windash_expansions_stay_or_inside_all():
    plan = process_rule({"CommandLine|contains|all|windash": [" -fixture", " /second"]})
    assert plan.expression.op == "and"
    for branch, word in zip(plan.expression.args, ("fixture", "second")):
        assert branch.op == "or"
        assert {item.value.parts for item in branch.args} == {
            (PatternPart("any"), PatternPart("literal", f" {dash}{word}"), PatternPart("any"))
            for dash in ("-", "/", "\u2013", "\u2014", "\u2015")
        }


@pytest.mark.parametrize("condition,reason", [
    ("selection and not 1 of missing_*", "condition_selector_empty"),
    ("selection or all of missing_*", "condition_selector_empty"),
    ("missing", "condition_identifier_missing"),
    ("selection and missing", "condition_identifier_missing"),
    ("2 of selection_*", "invalid_rule"),
    ("selection | count() > 1", "invalid_rule"),
    ("selection trailing", "invalid_rule"),
])
def test_invalid_conditions_refuse_entire_rule(condition, reason):
    with pytest.raises(UnsupportedRule, match=f"^{reason}$"):
        compile_rule(rule_yaml({"selection": {"EventID": 1}, "condition": condition}))


@pytest.mark.parametrize("modifier", [
    "base64offset", "cidr", "fieldref", "expand", "exists", "cased", "re|i", "re|m", "re|s", "unknown",
])
def test_unadmitted_modifiers_are_explicitly_unsupported(modifier):
    with pytest.raises(UnsupportedRule, match="^modifier_unsupported$"):
        process_rule({f"CommandLine|{modifier}": "fixture"})


@pytest.mark.parametrize("modifier", ["contains|startswith", "contains|contains", "contains|re"])
def test_unadmitted_modifier_chains_are_not_simplified(modifier):
    with pytest.raises(UnsupportedRule, match="^modifier_chain_unsupported$"):
        process_rule({f"CommandLine|{modifier}": "fixture"})


@pytest.mark.parametrize("selection,reason", [
    (["fixture-keyword"], "keyword_unsupported"),
    ({"|contains": "fixture"}, "keyword_unsupported"),
    ({"Message": "fixture"}, "field_unsupported"),
    ({"EventID": []}, "empty_list_unsupported"),
    ({"EventID": True}, "value_unsupported"),
    ({"EventID": 1.25}, "value_unsupported"),
])
def test_unadmitted_detection_shapes(selection, reason):
    with pytest.raises(UnsupportedRule, match=f"^{reason}$"):
        compile_rule(rule_yaml({"selection": selection, "condition": "selection"}))


@pytest.mark.parametrize("source", [
    {"product": "linux", "service": "security"},
    {"product": "windows", "service": "powershell"},
    {"product": "windows", "service": "security", "category": "process_creation"},
    {"product": "windows", "service": "security", "custom": "fixture"},
])
def test_unsupported_logsources(source):
    with pytest.raises(UnsupportedRule, match="^logsource_unsupported$"):
        compile_rule(rule_yaml(logsource=source))


@pytest.mark.parametrize("extra,reason", [
    ({"taxonomy": "custom"}, "taxonomy_unsupported"),
    ({"correlation": {}}, "rule_type_unsupported"),
    ({"action": "global"}, "rule_type_unsupported"),
    ({"scope": "fixture"}, "rule_type_unsupported"),
])
def test_non_atomic_or_custom_taxonomy_not_silently_ignored(extra, reason):
    with pytest.raises(UnsupportedRule, match=f"^{reason}$"):
        compile_rule(rule_yaml(**extra))


@pytest.mark.parametrize("raw,reason", [
    (b"!!python/object:fixture {}", "invalid_rule"),
    (b"title: &fixture Synthetic\nauthor: *fixture", "yaml_alias_unsupported"),
    (b"title: fixture\ntitle: duplicate", "yaml_mapping_invalid"),
    (b"---\ntitle: first\n---\ntitle: second", "invalid_rule"),
    (b"a: {<<: {title: fixture}}", "invalid_rule"),
    (b"x: " + b"[" * 60 + b"1" + b"]" * 60, "complexity_limit"),
    (b"#" * (compiler.MAX_YAML_BYTES + 1), "yaml_size_limit"),
])
def test_unsafe_or_ambiguous_yaml_is_rejected(raw, reason):
    with pytest.raises(UnsupportedRule, match=f"^{reason}$"):
        compile_rule(raw)


@pytest.mark.parametrize("selection", [
    {"CommandLine": "x" * (compiler.MAX_VALUE_LENGTH + 1)},
    {"CommandLine|contains|windash": " -a -b -c -d -e"},
])
def test_expensive_values_are_rejected_before_pysigma_expansion(selection):
    with pytest.raises(UnsupportedRule, match="^complexity_limit$"):
        process_rule(selection)


def test_input_and_lowered_tree_node_budgets(monkeypatch):
    raw = rule_yaml({"selection": {"EventID": [1, 2, 3]}, "condition": "selection"})
    monkeypatch.setattr(compiler, "MAX_NODES", 10)
    with pytest.raises(UnsupportedRule, match="^complexity_limit$"):
        compile_rule(raw)
    # The source fits the YAML budget, but repeated conditions exceed the IR budget.
    monkeypatch.setattr(compiler, "MAX_NODES", 70)
    assert compile_rule(rule_yaml()).expression == number(1)
    repeated = rule_yaml({"selection": {"EventID": 1}, "condition": ["selection"] * 40})
    with pytest.raises(UnsupportedRule, match="^complexity_limit$"):
        compile_rule(repeated)


def test_aggregate_expansion_budget_is_checked_before_pysigma(monkeypatch):
    from sigma.rule import SigmaRule

    monkeypatch.setattr(SigmaRule, "from_dict", lambda *_: pytest.fail("expansion budget checked too late"))
    monkeypatch.setattr(compiler, "MAX_EXPANDED_BYTES", 64)
    with pytest.raises(UnsupportedRule, match="^complexity_limit$"):
        process_rule({"CommandLine|contains|windash": [" -fixture", " /second"]})


def test_parser_version_mismatch_is_refused(monkeypatch):
    monkeypatch.setattr(compiler, "version", lambda _: "0.0.0")
    with pytest.raises(UnsupportedRule, match="^parser_version_mismatch$"):
        compile_rule(rule_yaml())


def test_plan_preserves_attribution_versions_and_hashes_without_repr_disclosure():
    raw = rule_yaml()
    kwargs = {"source_uri": "https://example.invalid/pinned", "upstream_commit": "a" * 40, "license_id": "DRL-1.1"}
    plan = compile_rule(raw, **kwargs)
    assert plan.rule_id == RULE_ID
    assert plan.source_sha256 == hashlib.sha256(raw).hexdigest()
    assert plan.author == "Fixture Team"
    assert plan.license == "DRL-1.1"
    assert plan.source_uri == kwargs["source_uri"]
    assert plan.upstream_commit == kwargs["upstream_commit"]
    assert plan.mapping_version == compiler.MAPPING_VERSION
    assert plan.parser_version == "1.3.3"
    assert plan.ir_version == compiler.IR_VERSION
    assert plan.compiler_version == compiler.COMPILER_VERSION
    assert plan.plan_sha256 == compile_rule(raw, **kwargs).plan_sha256
    assert plan.plan_sha256 != replace(plan, mapping_version="fixture-other-mapping").plan_sha256
    assert plan.plan_sha256 != replace(plan, compiler_version="fixture-other-compiler").plan_sha256
    assert "Fixture Team" not in repr(plan)
    with pytest.raises(FrozenInstanceError):
        plan.expression.op = "not"


def test_license_mismatch_is_rejected():
    with pytest.raises(UnsupportedRule, match="^license_mismatch$"):
        compile_rule(rule_yaml(license="MIT"), license_id="DRL-1.1")


def test_profile_reports_unsupported_without_partial_rule_or_metadata_leak(monkeypatch):
    valid = rule_yaml()
    invalid = rule_yaml({"selection": {"EventID|exists": True}, "condition": "selection"}, id=str(UUID(int=2)))
    inputs = tuple(SimpleNamespace(id=str(UUID(int=index)), raw_yaml=raw,
                                  source_uri="https://example.invalid/pinned", upstream_commit="a" * 40,
                                  license="DRL-1.1") for index, raw in enumerate((valid, invalid), 1))
    monkeypatch.setattr(profile_compiler, "verify_package", lambda *_: inputs)
    result = profile_compiler.compile_profile(Path("fixture.zip"))
    assert [plan.rule_id for plan in result.compiled] == [RULE_ID]
    assert result.unsupported == (profile_compiler.UnsupportedEntry(str(UUID(int=2)), "modifier_unsupported"),)
    summary = result.summary()
    assert len(summary["compiled"]) + len(summary["unsupported"]) == 2
    assert "Fixture Team" not in json.dumps(summary)
    assert "https://example.invalid" not in json.dumps(summary)


def test_profile_verifies_archive_before_compiling(monkeypatch):
    def invalid_package(*_):
        raise ValueError("Synthetic integrity failure")

    monkeypatch.setattr(profile_compiler, "verify_package", invalid_package)
    monkeypatch.setattr(profile_compiler, "compile_rule", lambda *_a, **_kw: pytest.fail("unverified compilation"))
    with pytest.raises(ValueError, match="Synthetic integrity failure"):
        profile_compiler.compile_profile(Path("fixture.zip"))


def test_cli_has_redacted_errors_and_serializable_unsupported(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["compile", "--archive", "fixture.zip"])

    def fail(*_):
        raise ValueError("Fixture Team: private fixture value")

    monkeypatch.setattr(profile_compiler, "compile_profile", fail)
    assert profile_compiler.main() == 1
    assert capsys.readouterr().out == "Sigma stage 04: FAILED (package, manifest or parser mismatch)\n"
    result = profile_compiler.ProfileCompilation((), (profile_compiler.UnsupportedEntry(RULE_ID, "field_unsupported"),))
    monkeypatch.setattr(profile_compiler, "compile_profile", lambda *_: result)
    assert profile_compiler.main() == 0
    assert json.loads(capsys.readouterr().out)["unsupported"] == [{"rule_id": RULE_ID, "reason": "field_unsupported"}]


def test_all_25_pinned_rules_compile_without_evaluation():
    archive = os.environ.get("SLI_SIGMA_ARCHIVE")
    if not archive:
        pytest.skip("Set SLI_SIGMA_ARCHIVE to the separately obtained pinned ZIP")
    result = profile_compiler.compile_profile(Path(archive))
    assert len(result.compiled) == 25
    assert result.unsupported == ()
    assert len({plan.rule_id for plan in result.compiled}) == 25
    assert all(plan.author and plan.license == "DRL-1.1" for plan in result.compiled)
    assert [plan.logsource for plan in result.compiled].count("security") == 16
    assert [plan.logsource for plan in result.compiled].count("process_creation") == 7
    assert [plan.logsource for plan in result.compiled].count("system") == 2
