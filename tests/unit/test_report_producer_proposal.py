"""Source guardrails only; these do not prove PostgreSQL grants or SQL execution."""
from pathlib import Path
import unittest

PROPOSAL = Path(__file__).resolve().parents[2] / "config/postgres_migrations/285_report_producer.sql"


class ProducerProposalTests(unittest.TestCase):
    def test_security_definer_has_referenced_columns_without_service_raw_grants(self):
        sql = PROPOSAL.read_text('utf-8')
        self.assertTrue('grant select(id,rule_code,severity,status,evidence_count,target,last_seen_utc,repeat_count)' in sql,
                        'security aggregate view columns must be available to its NOLOGIN definer owner')
        self.assertIn('grant select(id) on public.auth_users to adlog_storage_owner;', sql)
        self.assertIn('grant select(id,fqdn) on public.domains to adlog_storage_owner;', sql)
        self.assertIn('grant select(pipeline_name,last_status) on public.findings_refresh_state to adlog_storage_owner;', sql)
        self.assertIn('grant select(worker_name,status,heartbeat_at,expected_interval_seconds,details_json)', sql)

    def test_delivery_definer_has_only_column_update_needed_for_job_lock(self):
        sql = PROPOSAL.read_text('utf-8').lower()
        self.assertIn('grant update(id) on public.notification_outbox to adlog_report_producer_owner;', sql)
        self.assertNotRegex(sql, r'grant\s+update\s+on\s+public\.notification_outbox')
        self.assertNotRegex(sql, r'grant\s+update\s*\([^;]+\)\s+on\s+public\.notification_outbox\s+to\s+adlog_notification_worker')

    def test_leader_fence_is_locked_through_each_rpc(self):
        sql = PROPOSAL.read_text('utf-8')
        self.assertIn('l.principal_oid=v_principal and l.lease_until>clock_timestamp() for share', sql)
        self.assertIn('l.principal_oid=principal and l.lease_until>clock_timestamp() for share', sql)

    def test_file_population_is_read_only_after_python_acl_selection(self):
        aggregate = PROPOSAL.read_text('utf-8')
        file_helper = aggregate.split('create function public.report_file_candidate_roots', 1)[1].split('create function public.report_schedule_candidates', 1)[0]
        self.assertNotIn('report_rows(', file_helper)
        publication = PROPOSAL.read_text('utf-8')
        self.assertIn("'total',page->'filtered_count'", publication)
        self.assertIn("'has_more',page->'has_more'", publication)

    def test_fixed_lease_bound_fact_entry_and_no_producer_table_grants(self):
        self.assertTrue(PROPOSAL.exists(), "separate producer role/facts proposal is missing")
        sql = PROPOSAL.read_text(encoding="utf-8").lower()
        self.assertIn("function public.report_schedule_acl_facts(p_job uuid,p_lease uuid)", sql)
        self.assertIn("set search_path=pg_catalog,pg_temp", sql)
        self.assertIn("revoke all on function public.report_schedule_acl_facts", sql)
        self.assertIn("session_user", sql)
        self.assertNotRegex(sql, r"grant\s+(select|insert|update|delete|all)\b[^;]*\bto adlog_report_producer\s*;")

    def test_facts_exclude_ui_identity_data_and_preserve_invalid_denies(self):
        self.assertTrue(PROPOSAL.exists(), "separate producer role/facts proposal is missing")
        sql = PROPOSAL.read_text(encoding="utf-8").lower()
        for forbidden in ("username", "password_hash", "business_reason", "user_report_preferences", "report_access_requests_v4"):
            self.assertNotIn(forbidden, sql)
        self.assertIn("scope_json", sql)
        self.assertNotIn("normalize_capability_scope", sql)
        self.assertIn("security.queue", sql)
        self.assertIn("valid_until>p_at", sql)
        self.assertGreaterEqual(sql.count("limit 2049"), 8, "fact reads must cap before JSON aggregation")


if __name__ == "__main__":
    unittest.main()
