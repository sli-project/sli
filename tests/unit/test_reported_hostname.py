"""Display-only enrollment metadata: invalid names cannot break registration."""
import pytest

from server.sli.agents import agent_names


@pytest.mark.parametrize('value', [None, '', True, 42, {}, 'unknown', 'localhost', 'localhost.localdomain',
    '127.0.0.1', '2001:db8::1', '00000000-0000-4000-8000-000000000001',
    'host\nname', 'host\x00', ' host ', 'host/name', '<script>', 'host.example:443',
    '-host', 'host-', 'a' * 64, '.host', 'host..test', 'x.' * 127 + 'x', 'машина'])
def test_invalid_display_claim_is_absent(value):
    assert agent_names.reported_hostname(value) is None


@pytest.mark.parametrize('value', ['PC-01', 'pc.example.invalid', 'a', 'a' * 63, 'a.' * 125 + 'abc'])
def test_bounded_display_hostname_is_preserved(value):
    assert agent_names.reported_hostname(value) == value


def test_provenance_aware_reader_preserves_ad_precedence_and_plain_reader_semantics():
    class Cursor:
        def execute(self, sql, params):
            self.sql, self.params = sql, params
        def fetchall(self):
            return [dict(agent_id='a', enrolled_name='ad.example.invalid', registration_host_name='claim.example.invalid', assigned_modules=[]),
                    dict(agent_id='b', enrolled_name=None, registration_host_name='claim.example.invalid', assigned_modules=[])]
    cur = Cursor()
    assert agent_names.read_agent_name_details(cur, ['a','b']) == {
        'a': {'name':'ad.example.invalid', 'source':'ad_enrollment'},
        'b': {'name':'claim.example.invalid', 'source':'agent_reported'}}
    assert 'a.id::text = any(%s)' in cur.sql and cur.params == (['a','b'],)
    assert agent_names.read_agent_names(cur, ['a','b']) == {'a':'ad.example.invalid','b':None}
