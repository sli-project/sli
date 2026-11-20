"""VPN read views resolve bounded canonical keys through the entity primary key."""
import re
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/210_vpn_session_indexed_identity.sql"


def test_migration_preserves_the_reader_boundary_and_existing_columns():
    sql = PATH.read_text("utf-8")
    previous = (PATH.parent / "064_vpn_session_canonical_identity_read_boundary.sql").read_text("utf-8")
    pairs = [(item.version, item.name) for item in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((210, "vpn_session_indexed_identity")) - 1] == (
        209, "workstation_protection_state")
    assert len(pairs) == len({version for version, _ in pairs})
    assert "version=209 and name='workstation_protection_state'" in sql
    assert "where version>=210" in sql
    assert "pg_has_role(session_user,'adlog_vpn_session_reader_owner','MEMBER')" in sql
    assert "set local role adlog_vpn_session_reader_owner;" in sql
    assert sql.count("with (security_barrier=true)") == 2
    assert "grant select" not in sql.lower() and "grant all" not in sql.lower()
    assert "radius_vpn_session_projection" in sql and "values(210,'vpn_session_indexed_identity')" in sql
    assert not any(word in sql.lower() for word in ("drop ", "delete ", "update ", "insert into public.access"))
    # The indexed join is the only change to both published SELECT contracts.
    old_join = "projection.exact_principal_key='entity:' || entity_row.id::text"
    new_join = re.findall(r"entity_row.id=case.*?end\s+end", sql, re.S)
    assert len(new_join) == 2 and new_join[0] == new_join[1]
    body = sql[sql.index("create or replace view"):sql.index("reset role;")]
    old_body = previous[previous.index("create or replace view"):previous.index("reset role;")]
    assert body.replace(new_join[0], old_join) == old_body


def test_cast_is_guarded_against_noncanonical_and_overflowing_keys():
    sql = PATH.read_text("utf-8")
    assert sql.count("projection.exact_principal_key ~ '^entity:[1-9][0-9]{0,18}$'") == 2
    assert sql.count("substring(projection.exact_principal_key from 8)::numeric<=9223372036854775807") == 2
    assert sql.count("then substring(projection.exact_principal_key from 8)::bigint") == 2
    assert "'entity:' || entity_row.id::text" not in sql
