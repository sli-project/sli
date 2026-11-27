"""N07 forward migration and disposable PostgreSQL publication/outbox tests."""
from dataclasses import replace
import json
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from tests.migrations.test_qw_semantic_input_migration228 import pg as pg

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/229_qw_finding_notifications.sql"
SQL = PATH.read_text("utf-8")


def test_forward_migration_is_additive_dormant_and_uses_the_next_number():
    pairs = [(m.version, m.name) for m in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((229, "qw_finding_notifications")) - 1] == (228, "qw_semantic_input")
    assert list(PATH.parent.glob("229_*.sql")) == [PATH]
    assert SQL.splitlines()[1] == "begin;" and SQL.strip().endswith("commit;")
    assert "version=228 and name='qw_semantic_input'" in SQL and "where version>=229" in SQL
    assert "values(229,'qw_finding_notifications')" in SQL
    assert "grant execute on function public.enqueue_qw_finding_notifications(uuid) to adlog_semantic_worker" in SQL
    assert "grant select,insert on public.notification" not in SQL
    assert "publication_scenario_id uuid references public.semantic_finding_publications(scenario_id) on delete restrict" in SQL
    assert SQL.count("qw_signal_id is null") == 8


@pytest.fixture
def publication_pg(pg):
    """Synthetic predecessor tables with actual scenario and link definitions."""
    import psycopg
    from psycopg.rows import dict_row

    def table(migration, name):
        source = (ROOT / "config/postgres_migrations" / migration).read_text("utf-8")
        return source[source.index("create table " + name):].split("\n);", 1)[0] + "\n);"

    with psycopg.connect(pg, autocommit=True, row_factory=dict_row) as conn:
        conn.execute("set role adlog_storage_owner")
        conn.execute("""
            alter table canonical_actions add primary key(canonical_action_id);
            alter table semantic_correlation_candidates add primary key(candidate_id);
            create table normalized_events(normalized_event_id uuid primary key,source_event_id bigint);
            alter table semantic_detection_matches add primary key(match_id);
            alter table semantic_detection_matches add column evidence_key text;
            create table findings(id bigserial primary key,fingerprint text unique,rule_code text,title text,severity text,
                confidence numeric,status text,first_seen_utc text,last_seen_utc text,actor text,target text,source text,
                summary text,why_it_matters text,recommended_action text,evidence_count bigint,status_reason text,
                repeat_count integer,last_evidence_event_id bigint,updated_at timestamptz);
            create table finding_evidence(id bigserial primary key,finding_id bigint references findings(id),event_id bigint,
                evidence_role text,note text,unique(finding_id,event_id,evidence_role));
            create table finding_entities(id bigserial primary key,finding_id bigint,entity_type text,display_name text,entity_role text);
            create table finding_status_history(id bigserial primary key,finding_id bigint,old_status text,new_status text,changed_by text,note text);
            create table notification_channels(kind text primary key);
            insert into notification_channels values('smtp'),('telegram');
        """)
        for name in ("semantic_security_scenarios", "semantic_scenario_steps", "semantic_scenario_evidence",
                     "semantic_risk_contributions", "semantic_scenario_coverage_history"):
            conn.execute(table("028_semantic_risk_scenarios.sql", "if not exists " + name))
        detection = (ROOT / "config/postgres_migrations/220_detection_match_risk.sql").read_text("utf-8")
        for name in ("semantic_scenario_steps", "semantic_risk_contributions"):
            conn.execute("alter table public." + name + "\n" + detection.split(
                "alter table public." + name + "\n", 1)[1].split(";", 1)[0])
        conn.execute(table("055_semantic_finding_publication.sql", "if not exists semantic_finding_publications"))
        conn.execute(table("219_finding_evidence_refs.sql", "public.finding_evidence_refs"))
        # Exercise the actual native linker, against the fake immutable source
        # resolver installed by N06's disposable fixture.
        native = (ROOT / "config/postgres_migrations/219_finding_evidence_refs.sql").read_text("utf-8")
        conn.execute("create function public.link_finding_evidence_ref(" + native.split(
            "create function public.link_finding_evidence_ref(", 1)[1].split("$$;", 1)[0] + "$$;")
        for name in ("notification_subscriptions", "notification_outbox", "notification_attempts"):
            conn.execute(table("225_notification_outbox.sql", "public." + name))
        conn.execute("""
            grant select,insert,update on semantic_security_scenarios,findings to adlog_semantic_worker;
            grant select,insert on semantic_scenario_steps,semantic_scenario_evidence,semantic_risk_contributions,
                semantic_scenario_coverage_history,semantic_finding_publications,finding_evidence,finding_entities,
                finding_status_history to adlog_semantic_worker;
            grant select on normalized_events,finding_evidence_refs to adlog_semantic_worker;
            grant usage,select on all sequences in schema public to adlog_semantic_worker;
            grant select,insert on notification_outbox,notification_subscriptions to adlog_user;
            grant update(state,attempts,lease_token,lease_until,available_at,result_code,updated_at) on notification_outbox to adlog_user;
            create function is_semantic_finding_published_v1(bigint) returns boolean language sql stable
                security definer set search_path=pg_catalog,pg_temp as $$
                select exists(select 1 from public.semantic_finding_publications where finding_id=$1) $$;
            reset role;
        """)
        conn.execute(SQL)
    return pg
