"""Additive native evidence schema/ACL contracts; no live PostgreSQL."""
from pathlib import Path
import re

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/219_finding_evidence_refs.sql"
SQL = PATH.read_text("utf-8")


def function(name):
    return SQL.split(f"create function public.{name}(", 1)[1].split("$$;", 1)[0]


def test_migration_is_new_transactional_and_exactly_ordered():
    pairs = [(m.version, m.name) for m in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((219, "finding_evidence_refs")) - 1] == (218, "sigma_registry")
    assert list(PATH.parent.glob("219_*.sql")) == [PATH]
    assert len(pairs) == len({version for version, _ in pairs})
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "version=218 and name='sigma_registry'" in SQL and "where version>=219" in SQL
    assert SQL.splitlines()[1] == "begin;" and SQL.strip().endswith("commit;")
    assert "pg_advisory_xact_lock(hashtext('sli_finding_evidence_refs_v219'))" in SQL
    assert "values(219,'finding_evidence_refs')" in SQL


def test_exact_native_keys_hashes_and_scope_survive_retention_without_fake_core_ids():
    table = SQL.split("create table public.finding_evidence_refs (", 1)[1].split("\n);", 1)[0]
    for name in ("installation_id", "plugin_id", "source_instance_id", "source_generation", "collection_scope_id",
                 "storage_kind", "native_id", "sha256", "evidence_role"):
        assert f"{name} " in table
    assert "sha256 ~ '^[a-f0-9]{64}$'" in table
    assert "native_id ~ '^[1-9][0-9]{0,18}$'" in table
    assert "native_id::numeric<9223372036854775808" in table
    assert table.count("native_id ~ '^[a-f0-9]{64}$'") == 2
    assert "references public.findings(id) on delete restrict" in table
    assert "on delete cascade" not in SQL
    assert not re.search(r"(?:alter|insert into)\s+(?:public\.)?(?:events|events_v2_core|normalized_events)\b", SQL, re.I)
    assert not re.search(r"alter table (?:public\.)?finding_evidence\s", SQL, re.I)


def test_binding_authority_is_login_bound_and_default_denies_every_scope():
    guard = function("finding_evidence_scope_allowed")
    resolver = function("resolve_finding_evidence_ref")
    for body in (guard, resolver):
        assert "security definer set search_path=pg_catalog,pg_temp" in body
        assert "r.rolname=session_user" in body and "principal_oid" in body and "principal_name" in body
        for predicate in ("installation_id=p_installation", "plugin_id=p_plugin", "source_instance_id=p_source",
                          "source_generation=p_generation", "collection_scope_id=p_collection", "storage_kind=p_kind"):
            assert predicate in body
        assert "current_user" not in body and "current_setting" not in body
    assert "if not found then return false" in resolver
    assert "insert into public.finding_evidence_source_bindings" not in SQL
    assert "revoke all on public.finding_evidence_source_bindings from public,adlog_user,adlog_semantic_worker" in SQL
    assert "grant select on public.finding_evidence_source_bindings" not in SQL


def test_each_native_store_checks_real_routing_generation_and_content_hash():
    resolver = function("resolve_finding_evidence_ref")
    core, rest = resolver.split("elsif p_kind='workstation_observation'", 1)
    ws, fs = rest.split("elsif p_kind='file_audit_observation'", 1)
    for predicate in ("e.id=p_native::bigint", "e.log_source_id=b.log_source_id",
                      "encode(e.normalized_hash,'hex')=p_sha256", "inbox.imported_at is not null",
                      "receipt.receipt->>'status'='committed'", "inbox.envelope=receipt.envelope",
                      "receipt.module_id=p_plugin", "inbox.envelope->>'agent_id'=b.agent_id::text",
                      "inbox.envelope->>'source_instance_id'=p_source", "inbox.envelope->>'generation'=p_generation"):
        assert predicate in core
    for predicate in ("o.id=p_native", "o.agent_key=b.agent_key", "o.observation_sha256=p_sha256",
                      "o.observation->>'generation'=p_generation", "o.observation->>'agent_key'=b.agent_key",
                      "sha256(convert_to(o.source_xml,'UTF8'))", "o.observation->>'source_sha256'"):
        assert predicate in ws
    for predicate in ("o.evidence_key=p_native", "o.agent_id=b.agent_id", "o.source_instance_id=p_source",
                      "o.generation=p_generation", "o.collection_scope_id=p_collection", "o.payload_sha256=p_sha256",
                      "o.normalized->>'payload_sha256'=p_sha256", "o.normalized->>'evidence_key'=p_native"):
        assert predicate in fs
    assert "::bigint" not in ws and "::bigint" not in fs
    assert "return false;" in fs


def test_only_checked_function_can_insert_and_links_are_immutable_scope_filtered():
    assert "set local role adlog_storage_owner;" in SQL
    assert "alter table public.finding_evidence_refs enable row level security" in SQL
    assert "for select to adlog_semantic_worker" in SQL
    assert "using(public.finding_evidence_scope_allowed(" in SQL
    assert "grant select on public.finding_evidence_refs to adlog_semantic_worker" in SQL
    assert not re.search(r"grant\s+(?:insert|update|delete|truncate|all)[^;]*finding_evidence_refs\b", SQL, re.I)
    assert "before update or delete on public.finding_evidence_refs" in SQL
    assert "before truncate on public.finding_evidence_refs" in SQL
    linker = function("link_finding_evidence_ref")
    assert linker.index("public.resolve_finding_evidence_ref(") < linker.index("insert into public.finding_evidence_refs")
    assert "is not true then" in linker and "evidence_unavailable_or_denied" in linker
    assert "on conflict do nothing" in linker and "v_existing is distinct from p_sha256" in linker
    assert "if p_kind='core_event' then" in linker
    assert "values(p_finding,p_native::bigint,'semantic_scenario'" in linker
    for name, signature in (
        ("resolve_finding_evidence_ref", "uuid,text,text,text,text,text,text,text"),
        ("link_finding_evidence_ref", "bigint,uuid,text,text,text,text,text,text,text"),
    ):
        assert f"revoke all on function public.{name}({signature}) from public;" in SQL
        assert f"grant execute on function public.{name}({signature}) to adlog_semantic_worker;" in SQL
    assert not re.search(r"grant[^;]+to (?:public|adlog_user)\b", SQL, re.I)
