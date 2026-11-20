from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError, replace
from xml.sax.saxutils import escape

import pytest

from server.sli.sigma.windows_mapping import (
    AUDIT_PROVIDER,
    EVENTLOG_PROVIDER,
    MAPPING_VERSION,
    NS,
    SCM_PROVIDER,
    EventScope,
    SigmaMappingError,
    map_windows_event,
)

SCOPE = EventScope("fixture-installation", "fixture-source", "fixture-generation")


def event_xml(*, event_id=4624, version=0, provider=AUDIT_PROVIDER,
              channel="Security", payload="<EventData />", record_id=7,
              time="2026-01-02T03:04:05.1234567Z", execution='<Execution ProcessID="12" ThreadID="34" />',
              guid="", extra=""):
    """Synthetic native XML only; no external telemetry or database."""
    return (
        f'<Event xmlns="{NS}"><System><Provider Name="{provider}" {guid}/>'
        f'<EventID>{event_id}</EventID><Version>{version}</Version>'
        f'<TimeCreated SystemTime="{time}" /><EventRecordID>{record_id}</EventRecordID>'
        f'{execution}<Channel>{channel}</Channel><Computer>host.example.invalid</Computer>'
        f'</System>{payload}{extra}</Event>'
    )


def named_data(**values):
    return "<EventData>" + "".join(
        f'<Data Name="{name}">{escape(value)}</Data>' for name, value in values.items()
    ) + "</EventData>"


@pytest.fixture
def named_xml():
    return event_xml(version=2, payload=named_data(
        LogonType="9", SubjectUserSid="S-1-5-18", TargetUserName="fixture-account",
        IpAddress="192.0.2.10", IpPort="0", KeyLength="0", SubjectLogonId="0x123",
        AuthenticationPackageName="Negotiate", LogonProcessName="seclogo",
        ImpersonationLevel="%%1833", EmptyValue="", SpacedValue="  unchanged  ",
    ))


@pytest.fixture
def unnamed_xml():
    values = ("fixture-service", r"C:\Fixture\agent.exe", "%%16", "%%2", "LocalSystem")
    return event_xml(event_id=7045, provider=SCM_PROVIDER, channel="System",
                     payload="<EventData>" + "".join(f"<Data>{escape(value)}</Data>" for value in values) + "</EventData>")


def test_named_security_values_remain_exact_with_provenance(named_xml):
    mapped = map_windows_event(named_xml, scope=SCOPE)
    assert mapped.mapping_version == MAPPING_VERSION
    assert mapped.fields["EventID"] == 4624
    assert mapped.fields["Version"] == 2
    assert mapped.fields["Provider_Name"] == AUDIT_PROVIDER
    assert mapped.fields["LogonType"] == "9"
    assert mapped.fields["SubjectLogonId"] == "0x123"
    assert mapped.fields["ImpersonationLevel"] == "%%1833"
    assert mapped.fields["EmptyValue"] == ""
    assert mapped.fields["SpacedValue"] == "  unchanged  "
    assert "MissingValue" not in mapped.fields
    assert "SubStatus" not in mapped.fields
    assert mapped.provenance["LogonType"] == "EventData/Data[1]"
    assert mapped.identity.occurred_at == "2026-01-02T03:04:05.1234567Z"
    assert mapped.identity.source_xml_sha256 == hashlib.sha256(named_xml.encode()).hexdigest()


def test_named_and_unnamed_scm_installation(unnamed_xml):
    unnamed = map_windows_event(unnamed_xml, scope=SCOPE)
    expected = dict(zip(("ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName"), unnamed.fields["Data"]))
    named = map_windows_event(event_xml(event_id=7045, provider=SCM_PROVIDER, channel="System",
                                       payload=named_data(**expected)), scope=SCOPE)
    assert {key: unnamed.fields[key] for key in expected} == expected
    assert {key: named.fields[key] for key in expected} == expected
    assert unnamed.fields["ImagePath"] == r"C:\Fixture\agent.exe"
    assert unnamed.fields["ServiceType"] == "%%16"
    assert unnamed.provenance["ImagePath"] == "EventData/Data[2]"
    assert "ServiceFileName" not in unnamed.fields  # No cross-schema aliases.
    assert "ServiceStartType" not in unnamed.fields
    assert unnamed.identity.key != named.identity.key  # Different evidence bytes.


def test_native_eventlog_userdata_is_flattened_without_losing_subject():
    payload = ('<UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">'
               '<SubjectUserSid>S-1-5-18</SubjectUserSid><SubjectUserName>fixture-account</SubjectUserName>'
               '<SubjectDomainName>EXAMPLE</SubjectDomainName><SubjectLogonId>0x123</SubjectLogonId>'
               '</LogFileCleared></UserData>')
    mapped = map_windows_event(event_xml(event_id=1102, provider=EVENTLOG_PROVIDER, payload=payload), scope=SCOPE)
    assert mapped.fields["SubjectUserName"] == "fixture-account"
    assert mapped.fields["SubjectLogonId"] == "0x123"
    assert mapped.provenance["SubjectUserName"] == "UserData/LogFileCleared/SubjectUserName"
    assert mapped.fields["Provider_Name"] == EVENTLOG_PROVIDER


@pytest.mark.parametrize(("event_id", "values"), [
    (4719, {"AuditPolicyChanges": "%%8448", "SubcategoryGuid": "{00000000-0000-0000-0000-000000000001}"}),
    (4769, {"TicketEncryptionType": "0x17", "TicketOptions": "0x40810000", "Status": "0x0"}),
    (4768, {"PreAuthType": "0", "TicketEncryptionType": "0x17"}),
    (4625, {"Status": "0xc000006d", "SubStatus": "0xc0000064"}),
    (4776, {"Status": "0xc0000064", "Workstation": "fixture-host"}),
    (4720, {"SamAccountName": "fixture-account$", "TargetUserName": "fixture-account"}),
    (4781, {"NewTargetUserName": "fixture-account$"}),
    (4732, {"TargetSid": "S-1-5-32-544", "MemberSid": "S-1-5-18"}),
    (4698, {"TaskName": "fixture-task", "TaskContent": '<Task><Actions>fixture</Actions></Task>'}),
    (4702, {"TaskContentNew": '<Task><Actions>updated fixture</Actions></Task>'}),
    (4697, {"ServiceFileName": r"C:\Fixture\agent.exe", "ServiceStartType": "3"}),
])
def test_profile_security_fields_are_not_renamed_or_synthesized(event_id, values):
    mapped = map_windows_event(event_xml(event_id=event_id, payload=named_data(**values)), scope=SCOPE)
    assert {key: mapped.fields[key] for key in values} == values
    if event_id == 4776:
        assert "SubStatus" not in mapped.fields
        assert "SubjectUserSid" not in mapped.fields
    if event_id == 4702:
        assert "TaskContent" not in mapped.fields
    if event_id == 4781:
        assert "SamAccountName" not in mapped.fields


@pytest.mark.parametrize(("event_id", "version", "added_fields"), [
    (4624, 1, {"ImpersonationLevel": "%%1833"}),
    (4624, 2, {"TargetLinkedLogonId": "0x456", "ElevatedToken": "%%1842"}),
    (4698, 1, {"ClientProcessStartKey": "9007199254740993", "ClientProcessId": "123"}),
    (4702, 1, {"RpcCallClientLocality": "0", "FQDN": "host.example.invalid"}),
    (4768, 2, {"SessionKeyEncryptionType": "0x12", "PreAuthEncryptionType": "0x12"}),
    (4769, 2, {"RequestTicketHash": "fixture-request-hash", "ResponseTicketHash": "fixture-response-hash"}),
])
def test_versioned_native_fields_are_retained_but_never_backfilled(event_id, version, added_fields):
    old = map_windows_event(event_xml(event_id=event_id, version=0), scope=SCOPE)
    new = map_windows_event(event_xml(event_id=event_id, version=version,
                                     payload=named_data(**added_fields)), scope=SCOPE)
    assert new.identity.event_version == new.fields["Version"] == version
    assert old.identity.event_version == 0
    assert old.identity.key != new.identity.key
    assert not added_fields.keys() & old.fields.keys()
    assert {key: new.fields[key] for key in added_fields} == added_fields


@pytest.mark.parametrize("kwargs", [
    {"provider": SCM_PROVIDER}, {"provider": EVENTLOG_PROVIDER}, {"provider": "fixture-provider"},
    {"provider": AUDIT_PROVIDER.lower()}, {"channel": "System"},
    {"version": 3}, {"version": 255}, {"event_id": 4688, "version": 3},
    {"event_id": 4768, "version": 1}, {"event_id": 4625, "version": 1},
    {"event_id": 7045, "provider": AUDIT_PROVIDER, "channel": "System"},
    {"event_id": 1102, "provider": AUDIT_PROVIDER},
])
def test_wrong_provider_channel_or_unknown_version_never_falls_back(kwargs):
    with pytest.raises(SigmaMappingError, match="^sigma_event_schema_unsupported$"):
        map_windows_event(event_xml(**kwargs), scope=SCOPE)


@pytest.mark.parametrize("guid", ["not-a-guid", "00000000-0000-0000-0000-000000000001"])
def test_inconsistent_provider_guid_is_rejected(guid):
    with pytest.raises(SigmaMappingError, match="^sigma_event_provider_invalid$"):
        map_windows_event(event_xml(guid=f'Guid="{guid}"'), scope=SCOPE)


def test_provider_guid_is_canonicalized():
    mapped = map_windows_event(event_xml(guid='Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"'), scope=SCOPE)
    assert mapped.identity.provider_guid == "54849625-5478-4994-a5ba-3e3b0328c30d"
    assert mapped.fields["Provider_Guid"] == mapped.identity.provider_guid


def test_header_fields_cannot_come_from_eventdata_and_messages_are_unavailable():
    payload = named_data(EventID="999", Provider_Name="fixture-provider", ProcessId="999", ThreadId="999",
                         Message="fixture-rendered-text", message_text="fixture-rendered-text",
                         rendered_message="fixture-rendered-text")
    xml = event_xml(payload=payload, extra='<RenderingInfo><Message>fixture-rendered-text</Message></RenderingInfo>')
    mapped = map_windows_event(xml, scope=SCOPE)
    assert mapped.fields["EventID"] == 4624
    assert mapped.fields["Provider_Name"] == AUDIT_PROVIDER
    assert mapped.fields["ProcessId"] == 12
    assert mapped.fields["ThreadId"] == 34
    assert mapped.provenance["ProcessId"] == "System/Execution/@ProcessID"
    assert "fixture-rendered-text" not in str(dict(mapped.fields))
    assert not any("message" in name.casefold() for name in mapped.fields)
    missing = map_windows_event(event_xml(payload=payload, execution=""), scope=SCOPE)
    assert "ProcessId" not in missing.fields
    assert "ThreadId" not in missing.fields


@pytest.mark.parametrize("payload", [
    '<EventData><Data Name="SubjectUserName">first</Data><Data Name="SubjectUserName">second</Data></EventData>',
    '<EventData><Data Name="SubjectUserName">named</Data><Data>unnamed</Data></EventData>',
    '<EventData><Data Name=" spaced ">value</Data></EventData>',
    '<EventData /><EventData />', '<EventData /><UserData />',
    '<EventData><Data Name="TaskContent"><Task>nested</Task></Data></EventData>',
    '<EventData><Unexpected>fixture</Unexpected></EventData>',
    '<UserData><Unexpected /></UserData>',
])
def test_ambiguous_payloads_are_rejected(payload):
    with pytest.raises(SigmaMappingError):
        map_windows_event(event_xml(payload=payload), scope=SCOPE)


@pytest.mark.parametrize("count", [1, 4, 6])
def test_partial_or_changed_positional_scm_schema_is_rejected(count):
    with pytest.raises(SigmaMappingError, match="^sigma_event_positional_unsupported$"):
        map_windows_event(event_xml(event_id=7045, provider=SCM_PROVIDER, channel="System",
                                    payload="<EventData>" + "<Data>fixture</Data>" * count + "</EventData>"), scope=SCOPE)


def test_security_positional_data_never_borrows_scm_schema():
    with pytest.raises(SigmaMappingError, match="^sigma_event_positional_unsupported$"):
        map_windows_event(event_xml(payload="<EventData>" + "<Data>fixture</Data>" * 5 + "</EventData>"), scope=SCOPE)


@pytest.mark.parametrize("change", [
    {"record_id": 0}, {"record_id": -1}, {"record_id": 2**64}, {"record_id": "1.0"},
    {"version": ""}, {"version": -1}, {"version": 256},
    {"time": "2026-02-30T03:04:05Z"}, {"time": "2026-01-02T03:04:05"},
    {"time": "2026-01-02T03:04:05+01:00"}, {"execution": '<Execution ProcessID="invalid" />'},
])
def test_invalid_headers_are_rejected(change):
    with pytest.raises(SigmaMappingError, match="^sigma_event_header_invalid$"):
        map_windows_event(event_xml(**change), scope=SCOPE)


@pytest.mark.parametrize("replace_xml", [
    lambda xml: xml.replace('<Version>0</Version>', ''),
    lambda xml: xml.replace('<EventID>4624</EventID>', '<EventID>4624</EventID><EventID>4625</EventID>'),
    lambda xml: xml.replace('</System>', '</System><System />'),
    lambda xml: xml.replace(f'xmlns="{NS}"', ''),
    lambda xml: '<Wrapper>' + xml + '</Wrapper>',
    lambda xml: '<!DOCTYPE Event [<!ENTITY x "fixture-private-marker">]>' + xml,
    lambda xml: xml + '<unclosed-fixture-private-marker>',
])
def test_missing_duplicate_or_unsafe_xml_has_only_fixed_diagnostics(replace_xml):
    with pytest.raises(SigmaMappingError) as error:
        map_windows_event(replace_xml(event_xml()), scope=SCOPE)
    assert str(error.value).startswith("sigma_event_")
    assert "fixture-private-marker" not in str(error.value)


@pytest.mark.parametrize("name", ["installation_id", "source_instance_id", "source_generation"])
@pytest.mark.parametrize("value", [None, "", " ", 7])
def test_scope_is_required_without_name_or_generation_fallback(name, value):
    with pytest.raises(SigmaMappingError, match="^sigma_event_scope_invalid$"):
        replace(SCOPE, **{name: value})


def test_identity_is_replay_stable_but_scoped_and_content_bound(named_xml):
    first = map_windows_event(named_xml, scope=SCOPE)
    assert map_windows_event(named_xml, scope=SCOPE).identity.key == first.identity.key
    assert replace(first, mapping_version="fixture-next-mapping").identity.key == first.identity.key
    identities = [first.identity.key]
    for name in ("installation_id", "source_instance_id", "source_generation"):
        identities.append(map_windows_event(named_xml, scope=replace(SCOPE, **{name: "fixture-other"})).identity.key)
    for old, new in (
        ('<EventRecordID>7</EventRecordID>', '<EventRecordID>8</EventRecordID>'),
        ('1234567Z', '1234568Z'), ('fixture-account', 'fixture-account-other'),
        ('<Version>2</Version>', '<Version>1</Version>'),
    ):
        identities.append(map_windows_event(named_xml.replace(old, new), scope=SCOPE).identity.key)
    assert len(identities) == len(set(identities))
    # Each native identity dimension is encoded, beyond the source payload hash.
    for name, value in (("channel", "System"), ("provider_name", SCM_PROVIDER),
                        ("provider_guid", "fixture-guid"), ("computer", "other.example.invalid"), ("event_id", 4625)):
        assert replace(first.identity, **{name: value}).key != first.identity.key


def test_results_are_immutable_and_repr_does_not_disclose_fields(named_xml):
    mapped = map_windows_event(named_xml, scope=SCOPE)
    with pytest.raises(TypeError):
        mapped.fields["LogonType"] = "3"
    with pytest.raises(TypeError):
        mapped.provenance["LogonType"] = "fixture"
    with pytest.raises(FrozenInstanceError):
        mapped.identity.record_id = 8
    assert "fixture-account" not in repr(mapped)
    assert "fixture-source" not in repr(mapped.identity)
    assert "fixture-source" not in repr(SCOPE)
