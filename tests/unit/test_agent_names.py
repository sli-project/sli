"""Display names are not agent identities or authorization inputs."""
import unittest

from server.sli.agents.agent_names import human_host_name, read_agent_names


class AgentNamesTests(unittest.TestCase):
    def test_names_reject_technical_identifiers_and_placeholders(self):
        for value in (None, '', ' ', '00000000-0000-4000-8000-000000000001', 'localhost'):
            self.assertIsNone(human_host_name(value))
        self.assertEqual(human_host_name(' pc.example.invalid '), 'pc.example.invalid')

    def test_bounded_lookup_preserves_keys_and_uses_only_named_hosts(self):
        class Cursor:
            def execute(self, sql, params):
                self.sql, self.params = sql, params
            def fetchall(self):
                return [dict(agent_id='a', enrolled_name='pc.example.invalid', assigned_modules=[]),
                        dict(agent_id='b', enrolled_name=None, assigned_modules=[
                            {'module_id': 'sli.windows.ad-dc', 'config': {'source_name': 'dc.example.invalid'}}]),
                        dict(agent_id='c', enrolled_name=None, assigned_modules=[])]
        cur = Cursor()
        self.assertEqual(read_agent_names(cur, ['a', 'b', 'c']), {'a': 'pc.example.invalid', 'b': 'dc.example.invalid', 'c': None})
        self.assertEqual(cur.params, (['a', 'b', 'c'],))
        self.assertIn('a.id::text = any(%s)', cur.sql)
        self.assertEqual(read_agent_names(cur, []), {})
        with self.assertRaises(ValueError):
            read_agent_names(cur, list(map(str, range(501))))

    def test_conflicting_config_names_remain_unknown(self):
        class Cursor:
            def execute(self, *_): pass
            def fetchall(self):
                return [dict(agent_id='a', enrolled_name=None, assigned_modules=[
                    {'module_id': 'sli.workstations', 'config': {'source_name': 'one.example.invalid'}},
                    {'module_id': 'sli.windows.ad-dc', 'config': {'source_name': 'two.example.invalid'}}])]
        self.assertEqual(read_agent_names(Cursor(), ['a']), {'a': None})

    def test_both_locales_translate_display_and_technical_columns(self):
        from server.sli.core.messages import response_messages
        for family in ('logons', 'processes', 'usb', 'protection'):
            for locale, expected in (('ru', 'Компьютер'), ('en', 'Computer')):
                payload = response_messages({'key': 'workstations.' + family, 'columns': [
                    {'key': 'host_name', 'label': 'Компьютер'},
                    {'key': 'agent_key', 'label': 'Ключ агента', 'hidden_by_default': True}]}, locale)
                self.assertEqual(payload['columns'][0]['label'], expected)
                self.assertTrue(payload['columns'][1]['hidden_by_default'])
