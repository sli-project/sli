"""Shared synthetic vectors through the pre-signing workstation boundary."""
import json
import hashlib
import re
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from server.sli.agents.workstation_ingest import workstation_rows
from server.sli.plugins.workstations.script_secrets import mask_script_secrets
from server.sli.plugins.workstations.normalizers import new_projection
from sli_agent.envelope import EnvelopeError, make_packet, verify_packet
from sli_agent.workstations import POWERSHELL_CHANNEL
from sli_collect.eventlog import NS
from server.sli.storage.xml_safety import parse_bounded_xml
from tests.unit.test_sli_agent_workstations import AGENT, HOST, NOW
from tests.unit.test_workstation_tamper_collection import PS, fixture, samples
from tests.unit.test_agent_dotnet_vectors import load_generator


def load_vectors(repetition_divisor=1):
    vectors = json.loads((Path(__file__).resolve().parents[2] /
        'agent-dotnet/tests/vectors/script-secrets.json').read_text(encoding='utf-8'))
    for vector in vectors:
        expansions = {key: ''.join(parts) for key, parts in vector.pop('substitutions', {}).items()}
        # Keep doubled-quote escapes paired in the smaller hostile samples.
        expansions.update({key: chunk * (count if repetition_divisor == 1 else
                                         count // (2 * repetition_divisor) * 2)
                           for key, (chunk, count) in vector.pop('repetitions', {}).items()})
        for placeholder, value in expansions.items():
            for field in ('script', 'expected'):
                vector[field] = vector[field].replace(placeholder, value)
            vector['secrets'] = [secret.replace(placeholder, value) for secret in vector['secrets']]
    return vectors


VECTORS = load_vectors()


@pytest.mark.parametrize('vector', VECTORS, ids=lambda v: v['name'])
def test_shared_masking_vectors(vector):
    expected = vector['expected'], vector['count'], vector['truncated']
    assert mask_script_secrets(vector['script']) == expected
    assert mask_script_secrets(vector['expected']) == (vector['expected'], 0, False)


def masking_work(script, monkeypatch):
    """Count Python steps and regex subject characters, never wall-clock time."""
    import sli_agent.script_secrets as masking

    steps = regex_characters = 0

    class CountedPattern:
        def __init__(self, pattern):
            self.pattern = pattern

        def finditer(self, text):
            nonlocal regex_characters
            regex_characters += len(text)
            return self.pattern.finditer(text)

        def fullmatch(self, text, start, end):
            nonlocal regex_characters
            regex_characters += end - start
            return self.pattern.fullmatch(text, start, end)

    def trace(frame, event, arg):
        nonlocal steps
        if frame.f_code.co_filename == masking.__file__:
            if event == 'line':
                steps += 1
            return trace
        return None

    with monkeypatch.context() as patch:
        for name, value in vars(masking).copy().items():
            if isinstance(value, re.Pattern):
                patch.setattr(masking, name, CountedPattern(value))
        patch.setattr(masking, '_PATTERNS', [
            (kind, mode, CountedPattern(pattern)) for kind, mode, pattern in masking._PATTERNS])
        previous_trace = sys.gettrace()
        try:
            sys.settrace(trace)
            result = mask_script_secrets(script)
        finally:
            sys.settrace(previous_trace)
    return result, steps, regex_characters


@pytest.mark.parametrize('vector', [v for v in VECTORS if v['name'].startswith('hostile-')],
                         ids=lambda v: v['name'])
def test_hostile_vectors_have_linear_work(vector, monkeypatch):
    import sli_agent.script_secrets as masking

    # Python tracing cannot see inside the C regex engine. Pin the reviewed
    # context-only expressions AND flags so a new backtracking expression cannot
    # silently pass by making the same number of calls. On these hostile inputs,
    # prefixes fail in constant work or consume disjoint context tokens; literal
    # contents are resolved by the endpoint tables, not by regex backtracking.
    patterns = [(name, value.pattern, value.flags) for name, value in vars(masking).items()
                if isinstance(value, re.Pattern)]
    patterns.extend((kind, mode, pattern.pattern, pattern.flags)
                    for kind, mode, pattern in masking._PATTERNS)
    assert hashlib.sha256(json.dumps(patterns).encode()).hexdigest() == (
        '5294d98d3552916055087ab69b7092f24bd8cac165cf74a0e52964189dcf3540')

    work = []
    for divisor in (4, 2, 1):
        scaled = next(v for v in load_vectors(divisor) if v['name'] == vector['name'])
        result, steps, regex_characters = masking_work(scaled['script'], monkeypatch)
        assert result == (scaled['expected'], scaled['count'], scaled['truncated'])
        assert steps > len(scaled['script'])  # The Python loops were instrumented.
        assert regex_characters >= len(scaled['script'])
        work.append((len(scaled['script']), steps, regex_characters))

    # Work per character must not grow when doubling the hostile repetition.
    # Normalize by actual length to account for rounding and fixed suffixes.
    # This catches repeated suffix scans as well as quadratic Python loops.
    for smaller, larger in zip(work, work[1:]):
        assert larger[1] * smaller[0] <= smaller[1] * larger[0]
        assert larger[2] * smaller[0] <= smaller[2] * larger[0]


@pytest.mark.parametrize('vector', [v for v in VECTORS if 'detection' in v], ids=lambda v: v['name'])
def test_command_detection_survives_masking(vector):
    from tests.unit.test_workstation_script_secrets import assert_detected

    masked = mask_script_secrets(vector['script'])[0]
    assert masked == vector['script']
    assert_detected(masked, vector['detection'])


@pytest.mark.parametrize('error', [TimeoutError, RuntimeError])
def test_masking_failure_preserves_signed_event_and_failure_fact(monkeypatch, error, caplog, capsys):
    import sli_agent.script_secrets as masking
    from tests.unit.test_workstation_script_secrets import assert_detected

    class BrokenPattern:
        def finditer(self, _text):
            raise error('native input must never be logged')

    script = '$token = "' + ''.join(('fixture_', 'sensitive_123456')) + '"'
    raw_bytes = script.encode('utf-8')
    expected = f'{masking.MASK_FAILED} bytes={len(raw_bytes)} sha256={hashlib.sha256(raw_bytes).hexdigest()}'
    with monkeypatch.context() as patch:
        patch.setattr(masking, '_PATTERNS', [('token', 'value', BrokenPattern())])
        assert masking.mask_script_secrets(script) == (expected, 1, True)
        # Server-side failure also returns a projection instead of losing 4104.
        failed = new_projection(event_id=4104, channel=POWERSHELL_CHANNEL, provider=PS,
                                event_data={'ScriptBlockText': script})
        assert failed['facts']['script_masking_failed'] is True
        raw = fixture(4104, 1, POWERSHELL_CHANNEL, PS, {'ScriptBlockText': script})
        sample = next(s for s in samples({POWERSHELL_CHANNEL: [(1, raw)]})
                      if s.payload['header']['channel'] == POWERSHELL_CHANNEL)
    row = sample.payload['records'][0]['payload']
    data = {n.get('Name'): n.text or '' for n in parse_bounded_xml(row['xml']).findall('e:EventData/e:Data', NS)}
    assert data['ScriptBlockText'] == expected
    assert data['ScriptMaskingFailed'] == 'true'
    assert row['properties'][0] == expected
    assert row['event_id'] == 4104
    assert row['secrets_masked'] == 1
    key = ec.generate_private_key(ec.SECP256R1())
    packet = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    verify_packet(packet, key.public_key())
    identity = {'host_id': HOST, 'assigned_modules': [
        {'module_id': 'sli.workstations', 'enabled': True, 'config': {}}]}
    assert workstation_rows(identity, packet['envelope'], packet['payload'])
    facts = new_projection(event_id=4104, channel=POWERSHELL_CHANNEL, provider=PS, event_data=data)['facts']
    assert facts['script_masking_failed'] is True
    assert facts['script_block_text'] == expected
    from server.sli.plugins.workstations.contracts import Workstation
    from server.sli.sources.collection_packet_import import import_workstation_packet
    from tests.unit.test_workstations_plugin import Cursor, connection

    cur = Cursor()
    assert import_workstation_packet(connection(cur), sample.payload, agent_key=HOST,
        identity=SimpleNamespace(workstation=lambda *_: Workstation(HOST, 17))) == {
            'observed': 1, 'inserted': 1, 'ignored': 0}
    stored = next(iter(cur.stored.values()))['observation']['facts']
    assert stored['script_block_text'] == expected
    assert stored['script_masking_failed'] is True
    assert_detected(expected, masking.MASK_FAILED)
    assert script not in json.dumps(packet, ensure_ascii=False)
    captured = capsys.readouterr()
    assert not caplog.text + captured.out + captured.err


@pytest.mark.parametrize('vector', VECTORS, ids=lambda v: v['name'])
def test_only_masked_copies_are_signed(vector, caplog, capsys):
    raw = fixture(4104, 1, POWERSHELL_CHANNEL, PS, {'ScriptBlockText': vector['script']})
    with caplog.at_level('DEBUG'):
        sample = next(s for s in samples({POWERSHELL_CHANNEL: [(1, raw)]})
                      if s.payload['header']['channel'] == POWERSHELL_CHANNEL)
    row = sample.payload['records'][0]['payload']
    data = {n.get('Name'): n.text or '' for n in parse_bounded_xml(row['xml']).findall('e:EventData/e:Data', NS)}
    actual = data['ScriptBlockText']
    assert vector['expected'].startswith(actual)
    assert row['properties'][0] == (actual or None)
    assert row['secrets_masked'] == vector['count']
    assert data.get('SecretsMasked', '0') == str(vector['count'])
    assert (data.get('ScriptBlockTextTruncated') == 'true') is vector['truncated']
    key = ec.generate_private_key(ec.SECP256R1())
    packet = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    verify_packet(packet, key.public_key())
    identity = {'host_id': HOST, 'assigned_modules': [
        {'module_id': 'sli.workstations', 'enabled': True, 'config': {}}]}
    assert workstation_rows(identity, packet['envelope'], packet['payload'])
    if vector['count']:
        assert vector['script'] not in json.dumps(packet, ensure_ascii=False)
    for secret in vector['secrets']:
        assert secret not in json.dumps(packet, ensure_ascii=False)
    captured = capsys.readouterr()
    assert not caplog.text + captured.out + captured.err
    forged = deepcopy(packet)
    forged['payload']['records'][0]['payload']['properties'][0] = 'changed'
    with pytest.raises(EnvelopeError):
        verify_packet(forged, key.public_key())


@pytest.mark.parametrize('claimed', ['7', 'invalid', '-1', '99999', None, 7])
def test_agent_marker_never_bypasses_server_masking(claimed):
    facts = new_projection(event_id=4104, channel=POWERSHELL_CHANNEL, provider=PS,
        event_data={'ScriptBlockText': '-Password "fixture-secret"', 'SecretsMasked': claimed})['facts']
    assert facts['script_block_text'] == '-Password "[скрыто:password]"'
    assert facts['secrets_masked'] == (8 if claimed == '7' else 1)


def test_workstation_behavior_vectors_remain_current():
    path = Path(__file__).resolve().parents[2] / 'agent-dotnet/tests/vectors/workstations-scenarios.json'
    assert json.loads(path.read_text(encoding='utf-8')) == load_generator().workstations_scenarios()
