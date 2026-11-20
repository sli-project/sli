"""Test-only restoration of report_rows while exercising predecessor migrations.

This is not a production rollback. Only a disposable database with the exact
reviewed 288 function and no later migrations can be altered.
Reapplication restores the version and name semantically, but does not retain
the deleted ledger row's id or applied_at timestamp.
"""
import hashlib
import json
import re
from contextlib import contextmanager
from pathlib import Path

from tests.migrations.migration_inventory import migration_inventory
from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2] / "config/postgres_migrations"
SIGNATURE = "sli_plugin_file_audit.report_rows(jsonb,text,timestamptz,timestamptz,text,boolean,text,text,jsonb,integer)"


def execute_script(conn, script):
    """Run attested online-index DDL separately, as psql -f does.

    Only the reviewed 324/325/326 scripts use these top-level statements. Sending
    their entire file as one simple-query message creates an implicit block,
    even on an autocommit connection, and CONCURRENTLY then fails.
    """
    parts = re.split(r"(?m)^((?:create|drop) index concurrently\b[^;]*;)", script)
    if len(parts) > 1 and not conn.autocommit:
        raise ValueError("t070_fixture_online_requires_autocommit")
    for part in parts:
        if part.strip():
            conn.execute(part)


@contextmanager
def without_successors(conn):
    """Temporarily unwind only reviewed, inventory-attested successors."""
    assert_disposable_database(conn)
    rows = conn.execute(
        "select version,name,sha256 from public.schema_migrations where version>288 order by version"
    ).fetchall()
    successors = [(row["version"], row["name"]) if isinstance(row, dict) else tuple(row[:2]) for row in rows]
    hashes = {(row["version"] if isinstance(row, dict) else row[0]):
              (row["sha256"] if isinstance(row, dict) else row[2]) for row in rows}
    known = migration_inventory(ROOT, starting_at=289)
    if successors != [item for item in known if item in successors]:
        raise ValueError("t070_fixture_successor_invalid")
    canonical = [item for item in successors if item[0] >= 301]
    if canonical and ((300, "owner_recovery") not in successors or
                      canonical != [item for item in known if 301 <= item[0] <= canonical[-1][0]]):
        raise ValueError("t070_fixture_successor_invalid")
    scripts = []
    if successors:
        try:
            manifest = json.loads((ROOT.parents[1] / "deploy/linux/native_pg_ledger.json").read_text("utf-8"))
            for version, name in successors:
                pair = []
                for suffix in (".sql", ".rollback.sql"):
                    path = ROOT / f"{version}_{name}{suffix}"
                    source = path.read_bytes().replace(b"\r\n", b"\n")
                    pinned = manifest["files"][f"config/postgres_migrations/{path.name}"]
                    if hashlib.sha256(source).hexdigest() != pinned:
                        raise ValueError("t070_fixture_successor_invalid")
                    if suffix == ".sql" and hashes[version] not in (None, pinned):
                        raise ValueError("t070_fixture_successor_invalid")
                    pair.append(source.decode("utf-8"))
                scripts.append((version, *pair))
        except (OSError, KeyError, UnicodeError, ValueError) as exc:
            raise ValueError("t070_fixture_successor_invalid") from exc
    predecessor_hash = _capture_predecessor_hash(conn)
    # SQL files commit separately. An uncertain predecessor blocks restoration;
    # the owned clone must then be retained for controlled discard/recovery.
    unwound = []
    entered = False
    original = None
    try:
        for version, forward, rollback in reversed(scripts):
            execute_script(conn, rollback)
            unwound.append((version, forward))
        entered = True
        preflight(conn)
        yield
    except Exception as exc:  # noqa: BLE001 - Restore attested successors after any fixture/body failure.
        original = exc
        try:
            conn.rollback()
        except Exception as rollback_error:  # noqa: BLE001 - Preserve both failures if cleanup also fails.
            raise ExceptionGroup("t070_restoration_uncertain", [exc, rollback_error]) from None
    try:
        if entered:
            preflight(conn)
            _restore_predecessor_hash(conn, predecessor_hash)
        for version, forward in reversed(unwound):
            execute_script(conn, forward)
            conn.execute("update public.schema_migrations set sha256=%s where version=%s",
                         (hashes[version], version))
    except Exception as restore_error:
        if original is not None:
            raise ExceptionGroup("t070_restoration_uncertain", [original, restore_error]) from None
        raise RuntimeError("t070_restoration_uncertain") from restore_error
    if original is not None:
        raise original
def _capture_predecessor_hash(conn):
    manifest = json.loads((ROOT.parents[1] / "deploy/linux/native_pg_ledger.json").read_text("utf-8"))
    path = ROOT / "288_file_audit_service_filter.sql"
    pinned = manifest["files"][f"config/postgres_migrations/{path.name}"]
    if hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest() != pinned:
        raise ValueError("t070_fixture_successor_invalid")
    row = conn.execute("select sha256 from public.schema_migrations where version=288 and name='file_audit_service_filter'").fetchone()
    if row is None:
        raise ValueError("t070_fixture_successor_invalid")
    value = _first(row)
    if value not in (None, pinned):
        raise ValueError("t070_fixture_successor_invalid")
    return value


def _restore_predecessor_hash(conn, saved):
    row = conn.execute("select sha256 from public.schema_migrations where version=288 and name='file_audit_service_filter'").fetchone()
    if row is None or _first(row) not in (None, saved):
        raise ValueError("t070_fixture_predecessor_hash_conflict")
    if _first(row) != saved:
        conn.execute("update public.schema_migrations set sha256=%s where version=288 and name='file_audit_service_filter' and sha256 is null", (saved,))
    row = conn.execute("select sha256 from public.schema_migrations where version=288 and name='file_audit_service_filter'").fetchone()
    if row is None or _first(row) != saved:
        raise ValueError("t070_fixture_predecessor_hash_conflict")

def _function(path):
    source = path.read_text("utf-8")
    start = source.index("create or replace function sli_plugin_file_audit.report_rows(")
    end = source.index("\nend $$;", start) + len("\nend $$;")
    return source[start:end]


def _body(definition):
    match = re.search(r"\bas \$\$(.*?)\$\$;\Z", definition, re.IGNORECASE | re.DOTALL)
    if match is None:
        raise ValueError("t070_fixture_definition_invalid")
    return match.group(1)


def _first(row):
    return next(iter(row.values())) if isinstance(row, dict) else row[0]


def _matches_catalog(catalog, expected_body):
    if not isinstance(catalog, dict):
        return False
    expected = {"version": True, "future": False, "owner": "adlog_file_audit_owner",
        "language": "plpgsql", "kind": "f", "security_definer": True, "strict": False,
        "leakproof": False, "volatility": "s", "parallel": "u", "returns_set": False,
        "returns_jsonb": True, "default_args": 0, "public_execute": False, "body": expected_body}
    config = catalog.get("config")
    return (all(catalog.get(key) == value for key, value in expected.items())
        and isinstance(config, list) and len(config) == 1 and isinstance(config[0], str)
        and "".join(config[0].split()) == "search_path=pg_catalog,pg_temp")


def preflight(conn):
    assert_disposable_database(conn)
    expected = _body(_function(ROOT / "288_file_audit_service_filter.sql"))
    catalog = _first(conn.execute("""select jsonb_build_object(
        'version',exists(select 1 from public.schema_migrations where version=288 and name='file_audit_service_filter'),
        'future',exists(select 1 from public.schema_migrations where version>288),
        'owner',pg_get_userbyid(p.proowner),'language',l.lanname,'kind',p.prokind,
        'security_definer',p.prosecdef,'strict',p.proisstrict,'leakproof',p.proleakproof,
        'volatility',p.provolatile,'parallel',p.proparallel,'returns_set',p.proretset,
        'returns_jsonb',p.prorettype='jsonb'::regtype,'default_args',p.pronargdefaults,
        'config',p.proconfig,'body',p.prosrc,
        'public_execute',exists(select 1 from aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            where a.grantee=0 and a.privilege_type='EXECUTE')) as catalog
        from (select 1) seed left join pg_catalog.pg_proc p on p.oid=to_regprocedure(%s)
        left join pg_catalog.pg_language l on l.oid=p.prolang""", (SIGNATURE,)).fetchone())
    if not _matches_catalog(catalog, expected):
        raise ValueError("t070_fixture_successor_invalid")


def remove(conn):
    """Restore exact 236 function in the disposable clone before older rollbacks."""
    with conn.transaction():
        preflight(conn)
        before = _first(conn.execute("select to_jsonb(proacl)::text from pg_catalog.pg_proc where oid=to_regprocedure(%s)",
                                     (SIGNATURE,)).fetchone())
        conn.execute("set local role adlog_file_audit_owner")
        conn.execute(_function(ROOT / "236_file_audit_evidence.sql"))
        conn.execute("reset role")
        conn.execute("set local role adlog_storage_owner")
        conn.execute("delete from public.schema_migrations where version=288 and name='file_audit_service_filter'")
        conn.execute("reset role")
        after = _first(conn.execute("select to_jsonb(proacl)::text from pg_catalog.pg_proc where oid=to_regprocedure(%s)",
                                    (SIGNATURE,)).fetchone())
        if before != after:
            raise ValueError("t070_fixture_acl_changed")
