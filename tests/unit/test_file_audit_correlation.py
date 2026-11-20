"""Evidence-backed operations and conservative handle/IP correlation."""
from copy import deepcopy

from sli_agent.file_audit_policy import policy
from tests.unit.test_file_audit_collection import xml
from tests.unit.test_file_audit_contracts import AGENT, settings


def observation(record, event=4663, *, config=None, **fields):
    from server.sli.plugins.file_audit.correlation import observation_from_xml
    return observation_from_xml(xml(record, event, **fields), agent_id=AGENT,
        source_instance_id=AGENT, generation="synthetic-generation", policy_revision="1",
        core_evidence_ref=f"agent-event:synthetic:{record}",
        config=policy(settings() if config is None else config))


def actions(item, contexts=(), **kwargs):
    from server.sli.plugins.file_audit.correlation import project_actions
    return project_actions(item, contexts, **kwargs)


def test_access_check_does_not_claim_read_and_write_does_not_claim_creation():
    config = settings()
    config["roots"][0]["important"] = True
    item = observation(1, 5145, path="", mask="0x1", ShareName=r"\\*\synthetic",
                       ShareLocalPath=r"C:\synthetic", RelativeTargetName="item", config=config)
    assert actions(item)[0]["operation"] == "access_check"
    assert actions(observation(2))[0]["operation"] == "write"


def test_reads_require_important_scope_and_file_type():
    item = observation(1, mask="0x1")
    assert actions(item) == []
    item["scopes"][0]["important"] = True
    assert actions(item)[0]["object_type"] == "unknown"
    assert actions(item)[0]["correlation_state"] == "partial"
    assert actions(item, object_type="directory") == []
    assert actions(item, object_type="file")[0]["operation"] == "read"


def test_delete_right_and_4660_confirmation_keep_evidence_chain():
    context = observation(1, mask="0x10000")
    assert actions(context)[0]["operation"] == "delete_right"
    result = actions(observation(2, 4660, path=""), [context])[0]
    assert result["operation"] == "delete" and result["path"] == r"C:\synthetic\item"
    assert result["correlation_state"] == "complete"
    assert [e["role"] for e in result["evidence"]] == ["primary", "handle_context"]


def test_policy_change_does_not_reuse_old_handle_or_scope():
    old = observation(1, mask="0x10000")
    delete = observation(2, 4660, path="")
    delete["policy_revision"] = "2"
    assert actions(delete, [old]) == []


def test_ambiguous_zero_reused_or_other_source_handles_never_invent_delete_path():
    delete = observation(3, 4660, path="")
    context = observation(1, mask="0x10000")
    other = observation(2, path=r"C:\synthetic\other", mask="0x10000")
    assert actions(delete, [context, other]) == []
    for key in ("generation", "source_instance_id", "agent_id"):
        wrong = deepcopy(context)
        wrong[key] = "synthetic-other"
        assert actions(delete, [wrong]) == []
    assert actions(observation(3, 4660, path="", HandleId="0x0"), [context]) == []


def test_ntfs_and_smb_denials_have_native_failure_without_inferred_ip():
    failure = "0x8010000000000000"
    ntfs = actions(observation(1, 4656, keywords=failure))[0]
    assert ntfs["outcome"] == "failure" and ntfs["client_ip"] is None and ntfs["denial_layer"] == "ntfs"
    smb = actions(observation(2, 5145, path="", keywords=failure, ShareName=r"\\*\synthetic",
        ShareLocalPath=r"C:\synthetic", RelativeTargetName="item", IpAddress="192.0.2.10"))[0]
    assert smb["outcome"] == "failure" and smb["client_ip_source"] == "event:5145" and smb["denial_layer"] == "smb"


def test_network_logon_provides_ip_only_for_unambiguous_live_context():
    context = observation(1, 4624, path="", TargetUserSid="S-1-5-18", TargetLogonId="0x10",
                          LogonType="3", IpAddress="192.0.2.20")
    action = actions(observation(2), [context])[0]
    assert action["client_ip"] == "192.0.2.20" and action["client_ip_source"] == "event:4624"
    assert action["evidence"][-1]["role"] == "logon_context"
    conflicting = deepcopy(context)
    conflicting["facts"]["ip_address"] = "192.0.2.21"
    assert actions(observation(2), [context, conflicting])[0]["client_ip"] is None


def test_out_of_scope_handle_reuse_and_close_block_stale_delete_attribution():
    from server.sli.plugins.file_audit.correlation import delete_context
    context = observation(1)
    outside = observation(2, path=r"C:\other\item")
    assert delete_context(observation(3, 4660, path=""), [context, outside])[0] == "ambiguous"
    assert actions(observation(3, 4660, path=""), [context, outside]) == []
    closed = observation(2, 4658, path=r"C:\other\item", config={**settings(), "optional_events": True})
    assert actions(observation(3, 4660, path=""), [context, closed]) == []


def test_explicit_service_exclusion_preserves_denials_permissions_and_control():
    write = observation(1)
    write["excluded"] = True
    assert actions(write) == []
    permissions = observation(2, 4670)
    permissions["excluded"] = True
    assert actions(permissions)[0]["operation"] == "permissions"
    denied = observation(3, 4656, keywords="0x8010000000000000")
    denied["excluded"] = True
    assert actions(denied)[0]["outcome"] == "failure"


def test_boot_boundary_blocks_old_handle_and_logon_context():
    handle = observation(1)
    boot = observation(2, 4608, path="")
    assert actions(observation(3, 4660, path=""), [handle, boot]) == []


def test_permissions_and_rename_uncertainty_are_preserved():
    from server.sli.plugins.file_audit.normalizers import event_facts
    item = observation(1, 4670, OldSd="D:(A;;FR;;;SY)", NewSd="D:(A;;FA;;;SY)")
    assert actions(item)[0]["operation"] == "permissions"
    assert item["facts"]["old_sd"] != item["facts"]["new_sd"]
    assert event_facts(row={"channel": "Security", "provider_name": "unknown", "event_id": 4670}, event_data={}) == {}
    assert actions(observation(2, mask="0x10000"))[0]["operation"] == "delete_right"
    assert actions(observation(2, mask="0x10000"))[0]["correlation_state"] == "partial"


def test_rename_requires_two_names_in_one_live_handle_and_retains_both_witnesses():
    opened = observation(1, 4656, mask="0x10000")
    old = observation(2, mask="0x10000")
    new = observation(3, path=r"C:\synthetic\renamed", mask="0x2")
    row = actions(new, [opened, old])[0]
    assert row["operation"] == "rename" and row["path"] == new["path"]
    assert row["correlation_state"] == "complete"
    assert row["evidence"] == [
        {"evidence_key": new["evidence_key"], "core_evidence_ref": new["core_evidence_ref"], "role": "primary"},
        {"evidence_key": opened["evidence_key"], "core_evidence_ref": opened["core_evidence_ref"], "role": "handle_context"},
        {"evidence_key": old["evidence_key"], "core_evidence_ref": old["core_evidence_ref"], "role": "handle_context"},
    ]
    # Delete intent is never substituted for evidence of using that right.
    assert actions(new, [opened, observation(2, 4659)])[0]["operation"] == "write"
    assert actions(new, [old])[0]["operation"] == "write"
    opened["facts"]["access_mask"] = 0x80
    assert actions(new, [opened, old])[0]["operation"] == "write"


def test_rename_rejects_handle_reuse_boundaries_unknown_paths_and_other_scopes():
    opened = observation(1, 4656, mask="0x10000")
    old = observation(2, mask="0x10000")
    new = observation(4, path=r"C:\synthetic\renamed", mask="0x2")
    for event in (4656, 4658, 4660):
        boundary = observation(3, event, config={**settings(), "optional_events": True})
        assert actions(new, [opened, old, boundary])[0]["operation"] == "write"
    outside = observation(3, path=r"C:\outside\item")
    assert actions(new, [opened, old, outside])[0]["operation"] == "write"
    for field in ("generation", "source_instance_id", "agent_id", "policy_revision"):
        wrong = deepcopy(old)
        wrong[field] = "other"
        assert actions(new, [opened, wrong])[0]["operation"] == "write"
    old["scopes"][0]["collection_scope_id"] = "scope:other"
    assert actions(new, [opened, old]) == []
    old["scopes"] = new["scopes"]
    new["excluded"] = True
    assert actions(new, [opened, old]) == []


def test_versioned_file_facts_fit_core_write_shape_and_require_new_schema():
    import json
    import pytest
    from server.sli.plugins.file_audit.normalizers import event_facts
    from server.sli.storage.storage_v2_repository_columns import (
        EVENT_FACTS_V2_WRITE_COLUMNS, _normalized_historical_fact_values, _schema_compatible_fact_columns,
    )
    facts = event_facts(row={"channel": "Security", "provider_name": "Microsoft-Windows-Security-Auditing",
                            "event_id": 4670, "keywords": "0x8020000000000000"},
                        event_data={"OldSd": "D:(A;;FR;;;SY)", "NewSd": "D:(A;;FA;;;SY)", "AccessMask": "0x2"})
    nested = json.loads(facts["file_audit_facts_json"])
    assert nested["contract_id"] == "file-audit.facts.v1" and nested["access_mask"] == 2
    values = {"event_id": 1, **facts, "source_facts_sha256": b"a" * 32}
    assert set(values) == EVENT_FACTS_V2_WRITE_COLUMNS
    assert _schema_compatible_fact_columns(values, set(EVENT_FACTS_V2_WRITE_COLUMNS))
    with pytest.raises(RuntimeError, match="migration 186"):
        _schema_compatible_fact_columns(values, set(EVENT_FACTS_V2_WRITE_COLUMNS) - {"file_audit_facts_json"})
    old = {key: value for key, value in values.items() if key != "file_audit_facts_json"}
    assert _normalized_historical_fact_values(old)["file_audit_facts_json"] is None


def test_additive_file_column_preserves_published_history_hashes_and_keeps_new_facts():
    from server.sli.storage.permanent_fact_history import _fact_payload, _payload_sha
    old = {"event_id": 1, "process_name": None, "source_facts_sha256": "a" * 64}
    before = _fact_payload(old)
    after = _fact_payload({**old, "file_audit_facts_json": None})
    assert _payload_sha({"core": {}, "facts": before}) == _payload_sha({"core": {}, "facts": after})
    new = _fact_payload({**old, "file_audit_facts_json": '{"contract_id":"file-audit.facts.v1","access_mask":2}'})
    assert new["file_audit_facts_json"] == '{"contract_id":"file-audit.facts.v1","access_mask":2}'
