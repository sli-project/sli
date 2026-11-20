"""Legacy SQL-cursor fallback cannot mistake carried historical hashes for anchors."""
from contextlib import nullcontext
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest

from server.source_packs.radius.accounting_postgres import load_runtime_state
from sli_collect.radius_tail import RadiusTailReadError, derive_file_generation
from tests.unit.test_sli_agent_nps import accounting_line


@pytest.mark.parametrize('current,previous,allowed', [(None, None, False), ('a' * 64, None, True),
    ('a' * 64, 'a' * 64, False), ('b' * 64, 'a' * 64, True)])
def test_sql_state_derives_conservative_recovery_anchor(current, previous, allowed):
    class Cursor:
        def execute(self, sql, params=()):
            self.sql = sql

        def fetchone(self):
            if 'select current_role' in self.sql:
                return ('adlog_radius_accounting_worker',)
            return ('fixture-radius', 'radius-accounting', 'fixture-tail', uuid4(), 'fixture-generation',
                    0, current, 1, 'manual_enabled', 'manual_enabled', previous)

        def fetchall(self):
            return []
    conn = SimpleNamespace(transaction=lambda: nullcontext(), cursor=lambda: nullcontext(Cursor()))
    state = load_runtime_state(conn, subscription_id='fixture-subscription')
    assert state.exact_boundary_recovery is allowed


def test_legacy_cycle_enforces_fence_only_on_generation_loss(tmp_path, monkeypatch):
    from hashlib import sha256

    from server.sli.sources import legacy_collection, vpn_source_auth
    from server.sli.sources import radius_plugin_runtime as radius
    from sli_collect.radius_contract import initial_cursor

    line = accounting_line().encode()
    path = tmp_path / 'IN-fixture.log'
    path.write_bytes(line + b'\n')
    generation = derive_file_generation(source_instance_id='fixture-radius', file_name=path.name,
                                       file_creation_time_ns=path.stat().st_ctime_ns)
    cursor = replace(initial_cursor(source_instance_id='fixture-radius', transport_binding='fixture-tail',
        file_generation='missing-empty-generation'), byte_offset=len(line) + 1,
        last_record_sha256=sha256(line).hexdigest())
    state = SimpleNamespace(cursor=cursor, exact_boundary_recovery=False)
    monkeypatch.setattr(legacy_collection, 'require_legacy_collection', lambda: None)
    monkeypatch.setattr(radius, 'verify_collection_identity', lambda: {'status': 'ok'})
    monkeypatch.setattr(radius, 'connect_acquisition_worker', lambda: nullcontext(object()))
    monkeypatch.setattr(radius, 'component_lease_scope', lambda *_a, **_kw: nullcontext())
    monkeypatch.setattr(radius, 'require_accounting_source', lambda: (tmp_path, 'UTC', 0))
    monkeypatch.setattr(radius, 'acquisition_subscription_id', lambda: 'fixture-subscription')
    monkeypatch.setattr(radius, 'load_runtime_state', lambda *_a, **_kw: state)
    monkeypatch.setattr(vpn_source_auth, 'accounting_source_identity', lambda *_a, **_kw: nullcontext())
    monkeypatch.setattr(vpn_source_auth, 'validate_vpn_source_credential_mode', lambda *_a: 'process')
    monkeypatch.setattr(radius, 'import_acquisition_packet', lambda _conn, packet, **_kw: packet)
    with pytest.raises(RadiusTailReadError, match='tail_cursor_generation_not_found'):
        radius.run_acquisition_cycle()
    # Even a conservatively unanchored state can read an existing exact file.
    state.cursor = replace(cursor, file_generation=generation, byte_offset=0)
    packet = radius.run_acquisition_cycle()
    assert packet['records'][0]['payload'].encode() == line
    # A real differing current-generation hash allows ordinary fallback again.
    state.cursor = cursor
    state.exact_boundary_recovery = True
    assert radius.run_acquisition_cycle()['context']['cursor_generation_recovered'] is True
