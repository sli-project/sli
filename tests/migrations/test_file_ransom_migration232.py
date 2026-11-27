"""R01 forward migration, native root admission, episodes and atomic publication."""
from dataclasses import asdict
from datetime import timedelta
import json
from pathlib import Path
from uuid import uuid4

import pytest

from tests.migrations.test_qw_finding_notifications_migration229 import publication_pg as publication_pg

from tests.migrations.test_qw_semantic_input_migration228 import pg as pg

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/232_file_ransom.sql"
SQL = PATH.read_text("utf-8")


def test_forward_migration_is_dormant_additive_and_unique():
    assert list(PATH.parent.glob("232_*.sql")) == [PATH]
    assert "version=231 and name='agent_gpo_plans'" in SQL
    assert "where version>=232" in SQL and "values(232,'file_ransom')" in SQL
    assert SQL.splitlines()[1] == "begin;" and SQL.strip().endswith("commit;")
    assert "insert into public.finding_evidence_source_bindings" not in SQL
    assert "insert into public.semantic_risk_policies" not in SQL
    assert "grant select on sli_plugin_file_audit.observations to adlog_semantic_worker" not in SQL
