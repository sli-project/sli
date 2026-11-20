"""Source guards only; sustained-backlog behavior is a native PostgreSQL test."""
from pathlib import Path
import unittest

MIGRATION = Path(__file__).resolve().parents[2] / 'config/postgres_migrations/285_report_producer.sql'


class FairClaimPolicyTests(unittest.TestCase):
    def test_persisted_bounded_burst_and_fixed_actual_login_gate(self):
        text = MIGRATION.read_text('utf-8')
        self.assertIn('create table public.report_delivery_fairness', text)
        self.assertIn('check(alert_streak between 0 and 3)', text)
        self.assertIn('create function public.notification_claim_fair()', text)
        body = text.split('create function public.notification_claim_fair()', 1)[1].split('end $$;', 1)[0]
        self.assertIn('public.report_delivery_identity()', body)
        self.assertIn('where singleton for update', body)
        self.assertIn('when streak>=3 then', body)
        self.assertIn("when job.object_kind='report_schedule' then 0 else least(3,streak+1) end", body)
        self.assertNotIn('created_at<=', body)
        self.assertIn('for update skip locked limit 1', body)
        self.assertIn('grant execute on function public.notification_claim_fair() to adlog_notification_worker;', text)
        self.assertIn('revoke all on public.report_delivery_fairness from public,adlog_user,adlog_report_producer,adlog_notification_worker;', text)


if __name__ == '__main__':
    unittest.main()
