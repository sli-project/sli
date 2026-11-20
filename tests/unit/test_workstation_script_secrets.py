"""Synthetic secrets only: server normalization must not retain literal values."""
import pytest

from server.sli.plugins.workstations.normalizers import new_projection
from sli_agent.workstations import POWERSHELL_CHANNEL


def project(script, **data):
    return new_projection(event_id=4104, channel=POWERSHELL_CHANNEL,
                          provider="Microsoft-Windows-PowerShell",
                          event_data={"ScriptBlockText": script, **data})


AWS_KEY = ''.join(('AKIA', 'IOSFODNN7EXAMPLE'))


@pytest.mark.parametrize("script,secret,visible,kind", [
    ('Connect-Fixture -Password "fixture password"', 'fixture password', '-Password', 'password'),
    ("Connect-Fixture -Password:'fixture''password'", "fixture''password", '-Password:', 'password'),
    ('Connect-Fixture -Credential "user:fixture-password"', 'user:fixture-password', '-Credential', 'credential'),
    ('ConvertTo-SecureString "fixture-password" -AsPlainText -Force', 'fixture-password', '-AsPlainText', 'plaintext'),
    ('ConvertTo-SecureString "fixture;password" -AsPlainText -Force', 'fixture;password', '-AsPlainText', 'plaintext'),
    ('ConvertTo-SecureString -AsPlainText -Force -String "fixture-password"', 'fixture-password', '-AsPlainText', 'plaintext'),
    ("'fixture-password' | ConvertTo-SecureString -AsPlainText -Force", 'fixture-password', 'ConvertTo-SecureString', 'plaintext'),
    ('Authorization: Bearer fixture.jwt.token', 'fixture.jwt.token', 'Authorization: Bearer', 'bearer'),
    ("@{Authorization = 'Basic Zml4dHVyZTpwYXNz'}", 'Zml4dHVyZTpwYXNz', 'Basic', 'basic'),
    ('"Server=fixture;Password=fixture-password;Database=test"', 'fixture-password', 'Password=', 'password'),
    ('"Server=fixture;Password=fixture password;Database=test"', 'fixture password', 'Password=', 'password'),
    ('$Password = "fixture-password"', 'fixture-password', '$Password', 'password'),
    ('$access_token = "fixture-token"', 'fixture-token', '$access_token', 'token'),
    ('$aws_secret_access_key = "fixture-aws-secret"', 'fixture-aws-secret', '$aws_secret_access_key', 'cloud_key'),
    ('"AccountName=fixture;AccountKey=Zml4dHVyZS1rZXk=;EndpointSuffix=example.invalid"', 'Zml4dHVyZS1rZXk=', 'AccountKey=', 'cloud_key'),
    ('$client_secret = "fixture-azure-secret"', 'fixture-azure-secret', '$client_secret', 'cloud_key'),
    (f'"{AWS_KEY}"', AWS_KEY, '"', 'aws_access_key'),
    ('-----BEGIN ' 'RSA PRIVATE KEY-----\nZml4dHVyZQ==\n-----END RSA PRIVATE KEY-----', 'Zml4dHVyZQ==', 'PRIVATE KEY', 'private_key'),
    ('-----BEGIN ' 'PRIVATE KEY-----\nZml4dHVyZQ==', 'Zml4dHVyZQ==', 'PRIVATE KEY', 'private_key'),
    ('Connect-Fixture -Password "fixture-cut-off', 'fixture-cut-off', '-Password', 'password'),
    ('ConvertTo-SecureString @"\nfixture-multiline\n"@ -AsPlainText', 'fixture-multiline', '-AsPlainText', 'plaintext'),
    ('ConvertTo-SecureString -AsPlainText "fixture;password"', 'fixture;password', '-AsPlainText', 'plaintext'),
    ('ConvertTo-SecureString -String "fixture`"password" -AsPlainText', 'fixture`"password', '-AsPlainText', 'plaintext'),
])
def test_normalizer_masks_literal_secret_values(script, secret, visible, kind):
    result = project(script)
    masked = result['facts']['script_block_text']
    assert secret not in masked
    assert visible in masked
    assert f'[скрыто:{kind}]' in masked
    assert masked == script.replace(secret, f'[скрыто:{kind}]')
    assert result['facts']['secrets_masked'] == 1


def test_multiple_secrets_keep_commands_and_count_values_once():
    script = ('Invoke-Mimikatz; $Password="fixture-password"; '
              "@{Authorization='Bearer fixture_token_123456'}; [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')")
    facts = project(script)['facts']
    assert facts['secrets_masked'] == 2
    assert 'fixture-password' not in facts['script_block_text']
    assert 'fixture_token_123456' not in facts['script_block_text']
    assert 'Invoke-Mimikatz' in facts['script_block_text']
    assert 'AmsiUtils' in facts['script_block_text']


@pytest.mark.parametrize('script', [
    'Get-Process', 'Connect-Fixture -Password $secure -Credential $credential',
    'ConvertTo-SecureString $value -AsPlainText -Force',
    'powershell -EncodedCommand ' + 'QQ==' * 3000,
])
def test_normalizer_keeps_commands_variables_and_encoded_payload(script):
    facts = project(script)['facts']
    assert facts['script_block_text'] == script.encode()[:8192].decode()
    assert facts['secrets_masked'] == 0


def test_redaction_expansion_is_bounded_and_existing_truncation_survives():
    script = 'Invoke-Mimikatz; ' + '-Password x; ' * 800
    facts = project(script, ScriptBlockTextTruncated='true')['facts']
    assert len(facts['script_block_text'].encode('utf-8')) <= 8192
    assert facts['script_block_text_truncated'] is True
    assert '-Password x' not in facts['script_block_text']
    assert facts['secrets_masked'] > 0
    assert 'Invoke-Mimikatz' in facts['script_block_text']


def test_expansion_alone_sets_truncation_and_utf8_boundary_is_valid():
    script = 'Invoke-Mimikatz; ' + '-Password x; ' * 220 + 'Я' * 1000
    assert len(script.encode()) < 8192
    facts = project(script)['facts']
    assert facts['script_block_text_truncated'] is True
    assert len(facts['script_block_text'].encode()) <= 8192
    assert facts['secrets_masked'] == 220


def test_absent_script_does_not_create_text():
    result = new_projection(event_id=4104, channel=POWERSHELL_CHANNEL,
                            provider='Microsoft-Windows-PowerShell', event_data={})
    assert 'script_block_text' not in result['facts']
    assert result['facts']['secrets_masked'] == 0


def test_masking_is_idempotent_and_does_not_mutate_event_data():
    data = {'ScriptBlockText': '-Password "fixture-password"'}
    first = new_projection(event_id=4104, channel=POWERSHELL_CHANNEL,
                           provider="Microsoft-Windows-PowerShell", event_data=data)['facts']
    second = project(first['script_block_text'])['facts']
    assert second['script_block_text'] == first['script_block_text']
    assert second['secrets_masked'] == 0
    assert data['ScriptBlockText'] == '-Password "fixture-password"'


@pytest.mark.parametrize('command', [
    'Invoke-Mimikatz', 'powershell -EncodedCommand QQBBAA==',
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
])
def test_sigma_matcher_still_matches_masked_script_block(command):
    script = f'{command}; Connect-Fixture -Password "fixture-password"'
    masked = project(script)['facts']['script_block_text']
    for value in (script, masked):
        assert_detected(value, command)


def assert_detected(script, command):
    from server.sli.sigma.compiler import IRExpression
    from server.sli.sigma.matcher import match_rule
    from server.sli.sigma.windows_mapping import map_windows_event
    from tests.unit.test_sigma_matcher import pattern, plan
    from tests.unit.test_sigma_windows_mapping import SCOPE, event_xml, named_data

    rule = plan(IRExpression('compare', field='ScriptBlockText',
                             value=pattern('any', command, 'any')))
    native = event_xml(event_id=4104, version=1, channel=POWERSHELL_CHANNEL,
                       provider='Microsoft-Windows-PowerShell', payload=named_data(ScriptBlockText=script))
    fields = map_windows_event(native, scope=SCOPE).fields
    assert match_rule(rule, fields).status == 'matched'
    assert match_rule(rule, {'ScriptBlockText': 'Get-Process'}).status == 'not_matched'


@pytest.mark.parametrize('agent_masked', [True, False])
def test_ingest_projects_masked_facts_without_changing_signed_input(agent_masked):
    from copy import deepcopy
    from types import SimpleNamespace

    from cryptography.hazmat.primitives.asymmetric import ec

    from server.sli.agents.workstation_ingest import workstation_rows
    from server.sli.plugins.workstations.contracts import Workstation
    from server.sli.sources.collection_packet_import import import_workstation_packet
    from sli_agent.envelope import make_packet, verify_packet
    from tests.unit.test_sli_agent_workstations import AGENT, HOST, NOW
    from tests.unit.test_workstation_tamper_collection import PS, fixture, samples
    from tests.unit.test_workstations_plugin import Cursor, connection

    raw = fixture(4104, 1, POWERSHELL_CHANNEL, PS,
                  {'ScriptBlockText': 'Invoke-Mimikatz -Password "fixture-password"',
                   'ScriptBlockTextTruncated': 'true'})
    sample = next(s for s in samples({POWERSHELL_CHANNEL: [(1, raw)]})
                  if s.payload['header']['channel'] == POWERSHELL_CHANNEL)
    if not agent_masked:
        # An older agent signs the native input; the server must still mask facts.
        from sli_collect.eventlog import parse_event_xml

        sample.payload['records'][0]['payload'] = parse_event_xml(
            raw, source_name=HOST, connect_address='localhost', channel=POWERSHELL_CHANNEL)
    key = ec.generate_private_key(ec.SECP256R1())
    signed = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    original = deepcopy(signed)
    identity = {'host_id': HOST, 'assigned_modules': [
        {'module_id': 'sli.workstations', 'enabled': True, 'config': {}}]}
    assert workstation_rows(identity, signed['envelope'], signed['payload'])
    cur = Cursor()
    result = import_workstation_packet(connection(cur), signed['payload'], agent_key=HOST,
        identity=SimpleNamespace(workstation=lambda *_: Workstation(HOST, 17)))
    assert result == {'observed': 1, 'inserted': 1, 'ignored': 0}
    facts = next(iter(cur.stored.values()))['observation']['facts']
    assert facts['script_block_text'] == 'Invoke-Mimikatz -Password "[скрыто:password]"'
    assert facts['secrets_masked'] == 1
    assert facts['script_block_text_truncated'] is True
    assert signed == original
    verify_packet(signed, key.public_key())


def test_python_collector_does_not_log_script_text(caplog, capsys):
    from tests.unit.test_workstation_tamper_collection import PS, fixture, samples

    raw = fixture(4104, 1, POWERSHELL_CHANNEL, PS,
                  {'ScriptBlockText': 'Invoke-Mimikatz -Password "fixture-local-log-secret"'})
    with caplog.at_level('DEBUG'):
        collected = list(samples({POWERSHELL_CHANNEL: [(1, raw)]}))
    assert any(sample.payload['records'] for sample in collected)
    captured = capsys.readouterr()
    assert 'fixture-local-log-secret' not in caplog.text + captured.out + captured.err
