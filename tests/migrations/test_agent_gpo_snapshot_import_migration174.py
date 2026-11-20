"""Publication state and narrow grants; immutable predecessors remain intact."""
from pathlib import Path
import re

SQL = (Path(__file__).resolve().parents[2] / "config/postgres_migrations/174_agent_gpo_snapshot_import.sql").read_text("utf-8")


def test_gpo_publication_has_exact_source_reference_and_ad_constraint_is_retained():
    assert "version=172 and name='agent_ad_snapshot_import'" in SQL
    assert "version>=174" in SQL
    assert "values(174,'agent_gpo_snapshot_import')" in SQL
    assert "gpo_source_run_id uuid references public.ad_context_runs(run_id)" in SQL
    assert "module_id='sli.ad-snapshot' and manifest_id is not null" in SQL
    assert "module_id='sli.gpo-snapshot' and gpo_source_run_id is not null" in SQL
    assert "transport_state='complete'" in SQL
    assert "where module_id='sli.gpo-snapshot' and publication_state='pending'" in SQL


def test_only_worker_can_update_gpo_publication_and_no_activation():
    assert "grant update(gpo_source_run_id)" in SQL
    assert "to adlog_context_worker" in SQL
    assert not re.search(r"grant .*?to (?:public|adlog_user)\s*;", SQL, re.I | re.S)
    assert not re.search(r"grant (?:delete|truncate|all)|grant adlog_context_worker", SQL, re.I)
    assert not re.search(r"update .*sli_agent_snapshot_bindings|insert into .*sli_agents", SQL, re.I)
