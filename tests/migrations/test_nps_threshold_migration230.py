"""N08 forward migration and actual SQL against disposable PostgreSQL only."""
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from uuid import uuid4

import pytest

from tests.migrations.test_qw_finding_notifications_migration229 import publication_pg as publication_pg

from tests.migrations.test_qw_semantic_input_migration228 import pg as pg

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/230_nps_threshold.sql"
SQL = PATH.read_text("utf-8")
pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


def test_forward_migration_is_additive_dormant_and_exact():
    assert list(PATH.parent.glob("230_*.sql")) == [PATH]
    assert "version=229 and name='qw_finding_notifications'" in SQL
    assert "where version>=230" in SQL and "values(230,'nps_threshold')" in SQL
    assert SQL.splitlines()[1] == "begin;" and SQL.strip().endswith("commit;")
    assert "grant select on public.normalized_events to adlog_semantic_worker" not in SQL
    assert "insert into public.finding_evidence_source_bindings" not in SQL
    assert "insert into public.semantic_risk_policies" not in SQL


def seed_events(dsn, selected, now, *, count=20, previous=0, complete=False):
    import psycopg
    packet_id = uuid4()
    envelope = {"agent_id": "00000000-0000-0000-0000-000000000003", "source_instance_id": selected.scope.source_instance_id,
                "generation": selected.scope.source_generation}
    continuity = ({"status": "complete", "from_utc": (now - timedelta(minutes=10)).isoformat(), "to_utc": now.isoformat()}
                  if complete else {"status": "not_proven"})
    with psycopg.connect(dsn) as conn:
        conn.execute("insert into sli_agent_packet_inbox values(%s,%s::jsonb,%s::jsonb,now(),now())",
                     (packet_id, json.dumps(envelope), json.dumps({"header": {"observed_at_utc": now.isoformat()}, "continuity": continuity})))
        conn.execute("insert into sli_agent_receipts(packet_id,module_id,receipt,envelope) values(%s,%s,'{\"status\":\"committed\"}'::jsonb,%s::jsonb)",
                     (packet_id, selected.scope.plugin_id, json.dumps(envelope)))
        conn.execute("insert into raw_log_files values(1,%s)", ("agent-packet:" + str(packet_id),))
        for index in range(count + previous):
            stamp = now - timedelta(seconds=10 + index if index < count else 310 + index - count)
            conn.execute("insert into events_v2_core values(%s,6273,1,decode(%s,'hex'),1,%s)", (index + 1, "b" * 64, stamp))
            conn.execute("""insert into normalized_events(normalized_event_id,source_event_id,occurred_at_utc,facts_json,roles_json,
                quality_json,normalizer_id,semantic_contract_version,processing_status,semantic_type)
                values(%s,%s,%s,'{}','{}','{}','windows.named-eventdata',1,'normalized','remote_access.authentication.denied')""",
                (uuid4(), index + 1, stamp))
