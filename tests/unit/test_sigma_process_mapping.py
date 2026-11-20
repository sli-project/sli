from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from server.sli.sigma.process_mapping import INTEGRITY_LEVELS
from server.sli.sigma.windows_mapping import SigmaMappingError, map_windows_event
from tests.unit.test_sigma_windows_mapping import SCOPE, event_xml, named_data


def process_xml(version=2, **overrides):
    values = dict(SubjectUserSid="S-1-5-18", SubjectUserName="fixture-creator", SubjectDomainName="FIXTURE",
                  SubjectLogonId="0x00000000000003E7", NewProcessId="0x2bc", ProcessId="0xe74",
                  NewProcessName=r"C:\Fixture\child.exe", TokenElevationType="%%1937")
    if version >= 1:
        values["CommandLine"] = '"C:\\Fixture\\child.exe" --fixture'
    if version >= 2:
        values.update(TargetUserSid="S-1-0-0", TargetUserName="-", TargetDomainName="-", TargetLogonId="0x0",
                      ParentProcessName=r"C:\Fixture\parent.exe", MandatoryLabel="S-1-16-8192")
    values.update(overrides)
    return event_xml(event_id=4688, version=version, payload=named_data(**values))


@pytest.mark.parametrize("version", [0, 1, 2])
def test_native_versions_map_only_available_process_fields(version):
    mapped = map_windows_event(process_xml(version), scope=SCOPE)
    assert mapped.fields["Image"] == r"C:\Fixture\child.exe"
    assert mapped.fields["ProcessId"] == 700
    assert mapped.fields["ParentProcessId"] == 3700
    assert mapped.fields["NativeProcessId"] == 12
    assert mapped.fields["CreatorProcessId"] == "0xe74"
    assert mapped.fields["NewProcessId"] == "0x2bc"
    assert mapped.provenance["NativeProcessId"] == "System/Execution/@ProcessID"
    assert "NewProcessId: hex -> uint32" in mapped.provenance["ProcessId"]
    assert "CreatorProcessId: hex -> uint32" in mapped.provenance["ParentProcessId"]
    assert mapped.fields["User"] == "FIXTURE\\fixture-creator"
    assert "Subject context" in mapped.provenance["User"]
    assert mapped.fields["LogonId"] == "0x00000000000003E7"
    assert mapped.fields["LogonIdNumeric"] == 999
    assert ("CommandLine" in mapped.fields) == (version >= 1)
    assert ("ParentImage" in mapped.fields) == (version == 2)
    assert ("IntegrityLevel" in mapped.fields) == (version == 2)
    if version < 2:
        assert mapped.unavailable["ParentImage"] == "not_in_event_version"
    for name in ("OriginalFileName", "Hashes", "CurrentDirectory", "ParentUser", "ParentCommandLine"):
        assert name not in mapped.fields
        assert mapped.unavailable[name] == "not_in_4688"


def test_valid_target_context_is_not_creator_and_logon_is_unsigned_64_bit():
    mapped = map_windows_event(process_xml(TargetUserSid="S-1-5-19", TargetUserName="fixture-target",
                                           TargetDomainName="TARGET", TargetLogonId="0xFFFFFFFFFFFFFFFF"), scope=SCOPE)
    assert mapped.fields["User"] == "TARGET\\fixture-target"
    assert mapped.fields["UserSid"] == "S-1-5-19"
    assert "Target context" in mapped.provenance["User"]
    assert mapped.fields["LogonId"] == "0xFFFFFFFFFFFFFFFF"
    assert mapped.fields["LogonIdNumeric"] == 2**64 - 1
    assert mapped.provenance["LogonId"] == mapped.provenance["TargetLogonId"]
    assert mapped.fields["SubjectUserName"] == "fixture-creator"


def test_same_sid_with_different_target_logon_uses_target():
    mapped = map_windows_event(process_xml(TargetUserSid="S-1-5-18", TargetUserName="fixture-target",
                                           TargetDomainName="TARGET", TargetLogonId="0x456"), scope=SCOPE)
    assert mapped.fields["User"] == "TARGET\\fixture-target"
    assert mapped.fields["LogonIdNumeric"] == 0x456


@pytest.mark.parametrize("changes", [
    {"TargetUserSid": "invalid-fixture-sid"}, {"TargetUserSid": "S-1-5-4294967296"},
    {"TargetUserName": "fixture-target"}, {"TargetLogonId": "0x456"},
])
def test_inconsistent_target_never_falls_back_to_creator(changes):
    mapped = map_windows_event(process_xml(**changes), scope=SCOPE)
    assert "User" not in mapped.fields
    assert "LogonId" not in mapped.fields
    assert mapped.unavailable["User"] == "subject_context_invalid"


def test_partial_valid_target_does_not_mix_subjects():
    mapped = map_windows_event(process_xml(TargetUserSid="S-1-5-19", TargetLogonId="0x456"), scope=SCOPE)
    assert "User" not in mapped.fields
    assert mapped.unavailable["User"] == "subject_name_missing"
    assert mapped.fields["LogonId"] == "0x456"
    assert mapped.fields["UserSid"] == "S-1-5-19"


@pytest.mark.parametrize(("sid", "level"), list(INTEGRITY_LEVELS.items()))
def test_mandatory_label_table_is_independent_of_elevation(sid, level):
    mapped = map_windows_event(process_xml(MandatoryLabel=sid, TokenElevationType="%%1938"), scope=SCOPE)
    assert mapped.fields["IntegrityLevel"] == level
    assert "MandatoryLabel SID table v1" in mapped.provenance["IntegrityLevel"]


@pytest.mark.parametrize("label", ["", "-", "S-1-16-9999", "%%1937"])
def test_unknown_integrity_is_not_inferred_from_elevation(label):
    mapped = map_windows_event(process_xml(MandatoryLabel=label), scope=SCOPE)
    assert "IntegrityLevel" not in mapped.fields
    assert mapped.unavailable["IntegrityLevel"] == "mandatory_label_unknown"


@pytest.mark.parametrize("version", [0, 1])
def test_newer_fields_cannot_override_version_or_supply_fabricated_enrichment(version):
    mapped = map_windows_event(process_xml(version, ParentProcessName="fixture-parent", MandatoryLabel="S-1-16-16384",
                                           TargetUserSid="S-1-5-19", TargetUserName="fixture-target",
                                           TargetDomainName="TARGET", TargetLogonId="0x456",
                                           IntegrityLevel="System", ParentImage="fixture-parent", User="fixture-spoof",
                                           LogonId="0x456", LogonIdNumeric="111", OriginalFileName="fixture.exe",
                                           ParentUser="fixture-spoof", NativeProcessId="111"), scope=SCOPE)
    assert "ParentImage" not in mapped.fields
    assert "IntegrityLevel" not in mapped.fields
    assert "OriginalFileName" not in mapped.fields
    assert "ParentUser" not in mapped.fields
    assert mapped.fields["User"] == "FIXTURE\\fixture-creator"
    assert mapped.fields["LogonIdNumeric"] == 999
    assert mapped.fields["NativeProcessId"] == 12


def test_v0_does_not_admit_injected_command_line():
    mapped = map_windows_event(process_xml(0, CommandLine="fixture-spoof"), scope=SCOPE)
    assert "CommandLine" not in mapped.fields
    assert mapped.unavailable["CommandLine"] == "not_in_event_version"


def test_empty_absent_and_full_command_lines_remain_distinct():
    empty = map_windows_event(process_xml(CommandLine=""), scope=SCOPE)
    xml = process_xml().replace('<Data Name="CommandLine">"C:\\Fixture\\child.exe" --fixture</Data>', '')
    absent = map_windows_event(xml, scope=SCOPE)
    full_text = "fixture " + "x" * 6000
    full = map_windows_event(process_xml(CommandLine=full_text), scope=SCOPE)
    assert empty.fields["CommandLine"] == ""
    assert "CommandLine" not in absent.fields
    assert empty.unavailable["CommandLine"] == absent.unavailable["CommandLine"] == "command_line_audit_not_proven"
    assert full.fields["CommandLine"] == full_text
    assert "CommandLine" not in full.unavailable


@pytest.mark.parametrize("value", ["invalid", "-", "", "-1", "0x10000000000000000"])
def test_invalid_logon_is_unknown_and_preserves_native(value):
    mapped = map_windows_event(process_xml(1, SubjectLogonId=value), scope=SCOPE)
    assert mapped.fields["SubjectLogonId"] == value
    assert "LogonId" not in mapped.fields
    assert "LogonIdNumeric" not in mapped.fields
    assert mapped.unavailable["LogonId"] == "native_logon_invalid_or_missing"


def test_invalid_pid_never_uses_header_or_parent_as_new_process():
    mapped = map_windows_event(process_xml(NewProcessId="0x100000000", ProcessId="bad"), scope=SCOPE)
    assert "ProcessId" not in mapped.fields
    assert "ParentProcessId" not in mapped.fields
    assert mapped.fields["NativeProcessId"] == 12
    assert mapped.fields["CreatorProcessId"] == "bad"


@pytest.mark.parametrize("kwargs", [{"version": 3}, {"channel": "System"}, {"provider": "fixture-provider"}])
def test_process_schema_identity_does_not_fall_back(kwargs):
    with pytest.raises(SigmaMappingError, match="^sigma_event_schema_unsupported$"):
        map_windows_event(event_xml(event_id=4688, **kwargs), scope=SCOPE)


def test_process_results_and_quality_are_immutable_without_repr_disclosure():
    mapped = map_windows_event(process_xml(), scope=SCOPE)
    with pytest.raises(TypeError):
        mapped.unavailable["CommandLine"] = "fixture"
    with pytest.raises(FrozenInstanceError):
        mapped.mapping_version = "fixture"
    assert "fixture-creator" not in repr(mapped)
