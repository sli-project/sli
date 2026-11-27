"""Actual253/current264 WATCH proof and whole271 on disposable PG.

Reuse guarded native fixture, not W02's fake resolver. Reduced core/directory
parents; actual249 registry/trigger,253 reader/checks,264 proof and270 upgrade.
Unrelated269 ledger marker explicitly stands in for ACL-only aggregation.
"""
import hashlib
import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT/'config/postgres_migrations/271_account_watch_source_prefilter.sql'
NAME = 'account_watch_source_prefilter'
READER = 'public.read_account_watch_events(uuid,text,text,text,text,uuid)'
GUID = '00000000-0000-4000-8000-000000000001'
pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


def candidate_sql():
    return MIGRATION.read_text('utf-8-sig').split('$reader$')[1]


def proc(admin, signature):
    return admin.execute('select to_jsonb(p) from pg_proc p where oid=%s::regprocedure',
                         (signature,)).fetchone()[0]


def table_authority(row):
    # VACUUM/ANALYZE maintain these statistics and transaction horizons independently
    # of the migration. Keep every other catalog field (including unknown future
    # fields), so ACL, owner, RLS and DDL drift still fails the authority guard.
    # https://www.postgresql.org/docs/18/catalog-pg-class.html
    bookkeeping = {'relpages', 'reltuples', 'relallvisible', 'relallfrozen',
                   'relfrozenxid', 'relminmxid'}
    return {key: value for key, value in row.items() if key not in bookkeeping}


def test_table_authority_ignores_vacuum_bookkeeping():
    before = dict(oid='48148', relowner='16401', relacl=['owner=arwdDxtm/owner'],
                  relpages=14, reltuples=1024, relallvisible=0, relallfrozen=0,
                  relfrozenxid='96471', relminmxid='17')
    after = before | dict(relpages=30, reltuples=1023, relallvisible=28,
                          relallfrozen=13, relfrozenxid='101638', relminmxid='18')
    original = before.copy()
    assert table_authority(before) == table_authority(after)
    assert before == original


@pytest.mark.parametrize('field', [
    'oid', 'relname', 'relnamespace', 'relowner', 'relacl', 'relrowsecurity',
    'relforcerowsecurity', 'relkind', 'relam', 'relfilenode', 'reltablespace',
    'relnatts', 'relchecks', 'relhasindex', 'relhasrules', 'relhastriggers',
    'relhassubclass', 'relpersistence', 'relreplident', 'relispartition',
    'reloptions', 'relpartbound', 'future_catalog_field',
])
def test_table_authority_retains_other_catalog_fields(field):
    assert table_authority({field: 'before'}) != table_authority({field: 'after'})
