"""Stage-1 contracts use synthetic values and never connect to a database."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace

import pytest

from server.sli.access.scope import AccessScope, ScopeClause
from server.sli.plugins.file_audit.access import require_access
from server.sli.plugins.file_audit.contracts import EvidenceIdentity, FileObservation, RETENTION, report_contracts
from sli_agent.file_audit_policy import audit_command, audit_requirements, local_path, path_in_root, policy
from sli_agent.modules import RIGHTS_REGISTRY, configured_modules

AGENT = "00000000-0000-4000-8000-000000000001"


def settings():
    return {"roots": [{"collection_scope_id": "scope:one", "share_name": "synthetic",
                       "path": "C:\\synthetic", "important": False,
                       "sacl": {"trustee_sids": ["S-1-1-0"], "inherit_files": True, "inherit_directories": True}}]}


def test_defaults_preserve_owner_decisions_and_copy_input():
    original = settings()
    result = policy(original)
    assert result["mass_operation_files"] == 100 and result["mass_operation_seconds"] == 300
    assert result["roots"][0]["important"] is False and result["service_account_exclusions"] == []
    assert RETENTION == {"source_payload_days": 7, "facts": "permanent", "acl_history_days": 365,
                         "file_event_cleanup_enabled": False}
    result["roots"][0]["sacl"]["trustee_sids"].append("S-1-5-18")
    assert original == settings()


@pytest.mark.parametrize("path", ["relative", "C:relative", r"\\synthetic\share", r"\\?\C:\synthetic",
                                  "C:\\root\\..\\other", "C:\\root\\.\\item", "C:\\root\\file:stream",
                                  "C:\\root\\file.", "C:\\root\\item ", "C:\\root\\*", "C:\\root\nfile"])
def test_paths_reject_ambiguous_or_remote_names_without_exposing_them(path):
    with pytest.raises(ValueError, match="^file_audit_path_invalid$"):
        local_path(path)


def test_root_boundaries_are_case_insensitive_and_component_bound():
    assert path_in_root("c:/ROOT/file", "C:\\root")
    assert path_in_root("C:\\root", "C:\\root")
    assert path_in_root("C:\\root\\file", "C:\\")
    assert not path_in_root("C:\\root-other\\file", "C:\\root")
    assert not path_in_root("D:\\root\\file", "C:\\root")


@pytest.mark.parametrize("key,value", [("roots", []), ("roots", "synthetic"), ("max_events", True),
                                      ("max_events", 10001), ("max_bytes", 0), ("wall_seconds", 121),
                                      ("spool_bytes", -1), ("inventory_depth", 65), ("inventory_objects", 100001),
                                      ("mass_operation_files", 0), ("mass_operation_seconds", 86401),
                                      ("policy_revision", "0"), ("policy_revision", 1),
                                      ("policy_revision", "9007199254740992"), ("optional_events", 1),
                                      ("service_account_exclusions", ["synthetic"]),
                                      ("manage_windows_audit", True), ("follow_reparse_points", True)])
def test_policy_rejects_invalid_limits_and_implicit_write_authority(key, value):
    config = {**settings(), key: value}
    with pytest.raises(ValueError, match="file_audit_policy_invalid"):
        policy(config)


@pytest.mark.parametrize("mutation", [
    lambda root: root.update(important=1),
    lambda root: root.update(collection_scope_id=""),
    lambda root: root.update(collection_scope_id=[]),
    lambda root: root.update(share_name="a/b"),
    lambda root: root["sacl"].update(inherit_files=1),
    lambda root: root["sacl"].update(trustee_sids=[]),
    lambda root: root["sacl"].update(trustee_sids=["S-1-1-0", "S-1-1-0"]),
    lambda root: root["sacl"].update(trustee_sids=[[]]),
])
def test_root_selection_is_strict(mutation):
    config = settings()
    mutation(config["roots"][0])
    with pytest.raises(ValueError, match="file_audit_policy_invalid"):
        policy(config)


def test_overlapping_shares_keep_separate_context_but_not_duplicate_scope_ids():
    config = settings()
    config["roots"].append({**deepcopy(config["roots"][0]), "collection_scope_id": "scope:two", "share_name": "synthetic-two"})
    assert len(policy(config)["roots"]) == 2
    config["roots"][1]["collection_scope_id"] = "scope:one"
    with pytest.raises(ValueError, match="file_audit_policy_invalid"):
        policy(config)


def test_ag_audit_plan_read_success_only_for_important_roots():
    config = settings()
    requirements = audit_requirements(config)
    detailed = "0cce9244-69ae-11d9-bed3-505054503030"
    assert requirements[detailed] == 2
    assert requirements["0cce921d-69ae-11d9-bed3-505054503030"] == 3
    assert requirements["0cce9224-69ae-11d9-bed3-505054503030"] == 3
    assert requirements["0cce922f-69ae-11d9-bed3-505054503030"] == 1
    assert requirements["0cce9215-69ae-11d9-bed3-505054503030"] == 3
    config["roots"][0]["important"] = True
    assert audit_requirements(config)[detailed] == 3
    assert len(requirements) == 5
    config["optional_events"] = True
    assert audit_requirements(config)["0cce9223-69ae-11d9-bed3-505054503030"] == 1
    assert "0cce921e-69ae-11d9-bed3-505054503030" not in audit_requirements(config)


def command():
    return {"contract_id": "sli.file-audit.audit-command.v1", "command_id": "synthetic-command",
            "action": "check", "policy_revision": "1", "collection_scope_ids": ["scope:one"]}


@pytest.mark.parametrize("action", ["check", "apply", "restore"])
def test_ag_audit_command_is_pinned_to_selected_revision_and_scope(action):
    value = {**command(), "action": action}
    assert audit_command(value, settings()) == value


@pytest.mark.parametrize("key,value", [("policy_revision", "2"), ("action", "delete_plugin"),
                                      ("action", []), ("command_id", ""),
                                      ("collection_scope_ids", []), ("collection_scope_ids", ["scope:two"]),
                                      ("collection_scope_ids", ["scope:one", "scope:one"]),
                                      ("collection_scope_ids", [[]]), ("contract_id", "v2"), ("manage_audit", True)])
def test_ag_audit_command_rejects_drift_and_unknown_actions(key, value):
    with pytest.raises(ValueError, match="file_audit_command_invalid"):
        audit_command({**command(), key: value}, settings())


def test_evidence_identity_deduplicates_delivery_and_separates_source_generation_record():
    identity = EvidenceIdentity(AGENT, "synthetic-source", "generation-one", 42, 4663)
    assert identity.key == EvidenceIdentity(AGENT, "synthetic-source", "generation-one", 42, 4663).key
    # Event kind/version are payload properties, not another record identity.
    assert replace(identity, event_version=1).key == identity.key
    assert len({identity.key, replace(identity, generation="generation-two").key,
                replace(identity, source_instance_id="synthetic-source-two").key,
                replace(identity, record_id=43).key,
                replace(identity, agent_id="00000000-0000-4000-8000-000000000002").key}) == 5
    expected = [AGENT, "synthetic-source", "Security", "generation-one", 42]
    assert identity.key == hashlib.sha256(json.dumps(expected, separators=(",", ":")).encode()).hexdigest()


@pytest.mark.parametrize("key,value", [("agent_id", "synthetic"), ("record_id", True), ("record_id", 0),
                                      ("event_id", 4624), ("event_version", 256), ("channel", "System"),
                                      ("provider", "unknown"), ("generation", ""), ("source_instance_id", [])])
def test_evidence_identity_rejects_spoofing_and_missing_provenance(key, value):
    identity = EvidenceIdentity(AGENT, "synthetic-source", "generation", 42, 4663)
    with pytest.raises(ValueError, match="file_audit_evidence_identity_invalid"):
        replace(identity, **{key: value})


def test_observation_starts_with_explicit_unknown_quality():
    observation = FileObservation(EvidenceIdentity(AGENT, "synthetic-source", "generation", 42, 4660),
                                  "1", "scope:one", "a" * 64, "2026-01-01T00:00:00Z")
    assert observation.outcome == "unknown" and observation.correlation_state == "not_attempted"
    for key, value in (("payload_sha256", "x"), ("outcome", "deleted"), ("policy_revision", "0"),
                       ("collection_scope_id", ""), ("correlation_state", []),
                       ("observed_at_utc", "2026-01-01"), ("observed_at_utc", "2026-01-01T00:00:00+03:00")):
        with pytest.raises(ValueError, match="file_audit_observation_invalid"):
            replace(observation, **{key: value})


def scoped_access(capability="file-audit.view", scope_id="scope:one", effect="allow"):
    scope = AccessScope("restricted", (ScopeClause(plugin_ids=("sli.file-audit",), device_ids=(AGENT,),
                                                   source_instance_ids=("synthetic-source",), collection_scope_ids=(scope_id,)),))
    return {"capability_policies": [{"capability_key": capability, "effect": effect, "valid": True, "scope": scope.to_dict()}]}


def access_call(access, **kwargs):
    return require_access(access, agent_id=AGENT, source_instance_id="synthetic-source",
                          collection_scope_id="scope:one", action="view", **kwargs)


def test_scope_requires_all_dimensions_in_one_atomic_clause():
    assert access_call(scoped_access())["allowed"]
    for key, value in (("device_ids", ["synthetic-device"]), ("source_instance_ids", ["synthetic-other"]),
                       ("collection_scope_ids", ["scope:two"]), ("plugin_ids", ["sli.ad"])):
        access = scoped_access()
        access["capability_policies"][0]["scope"]["clauses"][0][key] = value
        with pytest.raises(PermissionError, match="file_audit_access_denied"):
            access_call(access)


def test_explicit_and_invalid_denies_win_over_global_allow():
    for valid in (True, False):
        access = scoped_access(effect="deny")
        access["capability_policies"][0]["valid"] = valid
        access["capabilities"] = ["file-audit.view"]
        with pytest.raises(PermissionError, match="file_audit_access_denied"):
            access_call(access)


def test_view_does_not_grant_export_or_audit_management():
    for action in ("export", "manage_audit"):
        with pytest.raises(PermissionError):
            require_access(scoped_access(), action=action, agent_id=AGENT, source_instance_id="synthetic-source",
                           collection_scope_id="scope:one", principal={"id": 1, "type": "session", "role": "admin"})


def test_management_requires_admin_and_its_own_scope():
    access = scoped_access("file-audit.audit.manage")
    kwargs = dict(action="manage_audit", agent_id=AGENT, source_instance_id="synthetic-source", collection_scope_id="scope:one")
    for principal in (None, [], {"id": True, "type": "session", "role": "admin"},
                      {"id": 1, "type": "session", "role": "viewer"}, {"id": 1, "type": "other", "role": "admin"}):
        with pytest.raises(PermissionError, match="file_audit_admin_required"):
            require_access(access, principal=principal, **kwargs)
    assert require_access(access, principal={"id": 1, "type": "session", "role": "admin"}, **kwargs)["allowed"]
    with pytest.raises(PermissionError, match="file_audit_resource_required"):
        require_access({"platform_owner": True}, action="view", agent_id=AGENT, source_instance_id="", collection_scope_id="scope:one")


def test_agent_enables_file_collection_only_with_explicit_assignment():
    assert RIGHTS_REGISTRY["sli.file-audit"].source_pack == "file_audit.json"
    config = SimpleNamespace(collection_enabled=False)
    assert len(configured_modules(config, AGENT, [{"module_id": "sli.file-audit", "enabled": True, "config": settings()}])) == 2
    assert len(configured_modules(config, AGENT, [{"module_id": "sli.file-audit", "enabled": False}])) == 1


def test_report_contracts_publish_eight_readers_without_grants():
    reports = report_contracts()
    assert len(reports) == 8 and len({item["report_key"] for item in reports}) == 8
    assert all(item["status"] == "published" and item["contract_id"] == "sli.report-result.v2" for item in reports)
    assert all(item["intent"]["result_limits"]["execution"]["default"] == 50 for item in reports)
