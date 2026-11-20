"""Real report policy against fixed-accessor metadata; no network/credentials."""
from uuid import uuid4
import unittest
from server.sli.core import report_schedule_delivery as delivery
from tests.unit.test_report_schedule_projection import access, definition, actual_report_access


def fixture():
    job = {"id": str(uuid4()), "lease_token": str(uuid4()), "object_id": str(uuid4()),
        "subscription_id": str(uuid4()), "recipient_user_id": 8, "channel": "smtp"}
    payload = {"owner_user_id": 7, "channel_revision": 5, "selection": {"variant": "cohorts"}, "root_scope": [],
        "subscription": {"id": job["subscription_id"], "owner_user_id": 7, "recipient_user_id": 8,
            "channel": "smtp", "enabled": True, "revision": 3},
        "run": {"id": job["object_id"], "report_key": "security.problems", "item_count": 1,
            "slot": "2026-10-25T09:00:00+00:00", "period_from": "2026-10-24T09:00:00+00:00",
            "period_to": "2026-10-25T09:00:00+00:00", "generated_at": "2026-10-25T09:00:00+00:00"}}
    return job, payload


class DeliveryTests(unittest.TestCase):
    def test_digest_without_csv_renderer_rechecks_owner_and_recipient_export(self):
        for denied_user in (None, 7, 8):
            job, payload = fixture()
            report = definition()
            report.export_csv = None
            actors = {user: access(export=user != denied_user) for user in (7, 8)}
            def dispatch():
                return delivery.authorize(job, payload, definition=report, actor_access=actors.__getitem__,
                                          authority_factory=actual_report_access())
            if denied_user is None:
                self.assertEqual(dispatch()['report_run']['item_count'], 1)
            else:
                with self.assertRaises(PermissionError):
                    dispatch()

    def authorize(self, payload, actors=None):
        job, _ = fixture()
        job.update(object_id=payload["run"]["id"], subscription_id=payload["subscription"]["id"])
        actors = actors or {7: access(), 8: access()}
        result = delivery.authorize(job, payload, definition=definition(), actor_access=actors.__getitem__,
                                    authority_factory=actual_report_access())
        self.assertIn("report_run", result)
        return result
    def test_prepared_digest_is_metadata_only(self):
        _, payload = fixture()
        result = self.authorize(payload)
        self.assertEqual(result["report_channel_revision"], 5)
        self.assertNotIn("root_scope", result["report_run"])
        self.assertNotIn("selection", result["report_run"])
        self.assertEqual(result["report_run"]["period_from"].year, 2026)
    def test_owner_recipient_export_and_grouping_revocations_block(self):
        _, payload = fixture()
        for actors in ({7: access(export=False), 8: access()}, {7: access(), 8: access(export=False)},
                       {7: access(identity=False), 8: access()}):
            with self.assertRaises(PermissionError):
                self.authorize(payload, actors)
    def test_countless_digest_still_checks_view(self):
        _, payload = fixture()
        payload["run"]["item_count"] = None
        denied = access()
        denied["reports"] = []
        with self.assertRaises(PermissionError):
            self.authorize(payload, {7: access(), 8: denied})
    def test_unlinked_recipient_or_job_run_rejected(self):
        job, payload = fixture()
        for changed in ({**job, "recipient_user_id": 99}, {**job, "object_id": str(uuid4())}):
            with self.assertRaises(PermissionError):
                delivery.authorize(changed, payload, definition=definition(), actor_access=lambda uid: access(),
                                   authority_factory=actual_report_access())


if __name__ == "__main__":
    unittest.main()
