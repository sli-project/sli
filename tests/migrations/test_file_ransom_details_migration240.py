"""R02 forward migration, scoped readback and durable suppression on disposable PG."""
from dataclasses import asdict, replace
import json
from pathlib import Path

import pytest

from tests.migrations.test_qw_finding_notifications_migration229 import publication_pg as publication_pg

from tests.migrations.test_qw_semantic_input_migration228 import pg as pg

PATH = Path(__file__).resolve().parents[2] / "config/postgres_migrations/240_file_ransom_details.sql"


def test_forward_migration_uses_main_predecessor_and_does_not_activate_sources():
    sql = PATH.read_text("utf-8")
    assert list(PATH.parent.glob("240_*.sql")) == [PATH]
    assert "version=237 and name='entity_context_health'" in sql
    assert "where version>=240" in sql and "values(240,'file_ransom_details')" in sql
    assert sql.splitlines()[1] == "begin;" and sql.strip().endswith("commit;")
    assert "insert into public.finding_evidence_source_bindings" not in sql
    assert "grant select on public.semantic_file_ransom_members to adlog_user" not in sql


def roots(selected):
    return json.dumps([{"agent_id": selected.agent_id, "source_instance_id": selected.scope.source_instance_id,
                        "collection_scope_id": selected.scope.collection_scope_id}])
