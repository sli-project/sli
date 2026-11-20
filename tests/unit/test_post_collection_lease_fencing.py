"""Hermetic ownership contracts; also runnable with stdlib unittest."""
import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

from server.sli.core import postgres_runtime_pipeline as runtime
from server.sli.sources import post_collection_pipeline as pipeline


class LeaseFencingTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.cursor = MagicMock()
        self.cursor.rowcount = 1
        connection = MagicMock()
        connection.__enter__.return_value.cursor.return_value.__enter__.return_value = self.cursor
        self.stack.enter_context(patch.object(runtime, "connect", return_value=connection))
        self.stack.enter_context(patch.object(pipeline, "_require_postgres"))
        self.stack.enter_context(patch.object(pipeline, "ensure_post_collection_schema"))

    def mutations(self):
        return (
            (pipeline.update_post_collection_job, {"status": "completed"}),
            (pipeline.heartbeat_post_collection_job, {}),
            (pipeline.update_post_collection_findings, {"status": "completed"}),
        )

    def test_all_worker_writes_fence_identity_generation_status_and_expiry(self):
        for mutate, kwargs in self.mutations():
            with self.subTest(mutate=mutate.__name__):
                mutate("job-1", worker_id="worker-a", claim_attempt=2, **kwargs)
                sql, params = self.cursor.execute.call_args.args
                where = " ".join(sql.lower().split()).split("where", 1)[1]
                self.assertIn("worker_id = %s", where)
                self.assertIn("attempt_count = %s", where)
                self.assertIn("status = 'running'", where)
                self.assertIn("worker_lease_until > now()", where)
                self.assertEqual(params[-3:], ("job-1", "worker-a", 2))

    def test_rejected_mutations_raise_lease_loss(self):
        self.cursor.rowcount = 0
        for mutate, kwargs in self.mutations():
            with self.subTest(mutate=mutate.__name__), self.assertRaises(pipeline.PostCollectionLeaseLost):
                mutate("job-1", worker_id="worker-a", claim_attempt=1, **kwargs)

    def test_recovery_does_not_exhaust_unexpired_running_attempt(self):
        pipeline.recover_stale_post_collection_jobs()
        sql = " ".join(self.cursor.execute.call_args.args[0].split()).lower()
        self.assertIn("status = 'queued' or worker_lease_until is null or worker_lease_until <= now()", sql)


    def test_publication_guard_rejects_missing_owner(self):
        self.cursor.fetchone.return_value = None
        with self.assertRaises(pipeline.PostCollectionLeaseLost):
            with pipeline.post_collection_lease_guard("job-1", worker_id="worker-a", claim_attempt=1):
                self.fail("missing owner entered publication")

    def test_publication_guard_rejects_expiry_after_lock_acquisition(self):
        self.cursor.fetchone.side_effect = [
            {"worker_lease_until": "2026-10-21T00:00:00+00:00"}, {"lease_live": False},
        ]
        with self.assertRaises(pipeline.PostCollectionLeaseLost):
            with pipeline.post_collection_lease_guard("job-1", worker_id="worker-a", claim_attempt=1):
                self.fail("expired owner entered publication")
        self.assertIn("clock_timestamp()", self.cursor.execute.call_args.args[0])

    def test_publication_guard_allows_live_owner(self):
        self.cursor.fetchone.side_effect = [
            {"worker_lease_until": "2026-10-21T00:00:00+00:00"}, {"lease_live": True},
        ]
        entered = False
        with pipeline.post_collection_lease_guard("job-1", worker_id="worker-a", claim_attempt=2):
            entered = True
        self.assertTrue(entered)
        sql, params = self.cursor.execute.call_args_list[0].args
        self.assertIn("for update", sql)
        self.assertEqual(params, ("job-1", "worker-a", 2))


class WorkerLeaseTests(unittest.TestCase):
    def setUp(self):
        import importlib.util
        import itertools
        import sys
        import threading
        import uuid
        from pathlib import Path
        from types import SimpleNamespace

        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.src = SimpleNamespace(
            threading=threading, _lock=threading.Lock(), _jobs={},
            _post_collection_guard=threading.Lock(), _post_collection_active=set(),
            _counter=itertools.count(1), uuid=uuid, utc_now=lambda: "now",
            monotonic_ms=lambda: 1, log_event=MagicMock(),
            log_internal_error=MagicMock(return_value="ERR"), log_performance_stage=MagicMock(),
            PostCollectionLeaseLost=pipeline.PostCollectionLeaseLost,
            update_post_collection_job=MagicMock(),
            update_post_collection_findings=MagicMock(),
            heartbeat_post_collection_job=MagicMock(),
            legacy_findings_enabled=lambda: True,
            refresh_findings_from_events=MagicMock(return_value={}),
            _generate_report_with_heartbeat=MagicMock(),
            Job=lambda **kw: SimpleNamespace(**kw),
        )
        import server.jobs

        self.stack.enter_context(patch.object(server.jobs, "collector", self.src, create=True))
        self.stack.enter_context(patch.dict(sys.modules, {"server.jobs.collector": self.src}))
        from server.sli.sources import legacy_collection
        self.stack.enter_context(patch.object(legacy_collection, "require_legacy_collection"))
        root = Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location("lease_worker_under_test", root / "server/jobs/collector_post_collection.py")
        self.worker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.worker)
        self.src._heartbeat_post_collection_safely = self.worker._heartbeat_post_collection_safely
        spec = importlib.util.spec_from_file_location("lease_analysis_under_test", root / "server/jobs/collector_analysis.py")
        self.analysis = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.analysis)

    def test_findings_lease_loss_does_not_start_report_or_publish_failure(self):
        self.src.update_post_collection_findings.side_effect = [
            None, pipeline.PostCollectionLeaseLost("job-1"),
        ]
        self.worker._run_post_collection_job(1, [], "trace", "job-1", "worker-a", 1)
        self.src._generate_report_with_heartbeat.assert_not_called()
        self.assertEqual(self.src.update_post_collection_job.call_count, 1)
        self.assertEqual(self.src.update_post_collection_findings.call_count, 2)

    def test_initial_lease_loss_does_not_run_findings(self):
        self.src.update_post_collection_job.side_effect = pipeline.PostCollectionLeaseLost("job-1")
        self.worker._run_post_collection_job(1, [], "trace", "job-1", "worker-a", 1)
        self.src.refresh_findings_from_events.assert_not_called()
        self.assertEqual(self.src.update_post_collection_job.call_count, 1)

    def test_heartbeat_lease_loss_is_not_swallowed(self):
        self.src.heartbeat_post_collection_job.side_effect = pipeline.PostCollectionLeaseLost("job-1")
        with self.assertRaises(pipeline.PostCollectionLeaseLost):
            self.worker._heartbeat_post_collection_safely(
                durable_job_id="job-1", worker_id="worker-a",
                claim_attempt=1, phase="report_running", job_id=1,
            )

    def test_background_heartbeat_loss_prevents_report_result_publication(self):
        import threading

        detected = threading.Event()
        calls = []

        def heartbeat(*args, **kwargs):
            calls.append(kwargs)
            if len(calls) > 1:
                detected.set()
                raise pipeline.PostCollectionLeaseLost("job-1")

        def report(*args, **kwargs):
            self.assertTrue(detected.wait(2), "background heartbeat did not run")
            for thread in threading.enumerate():
                if thread.name == "post-collection-heartbeat-1":
                    thread.join(2)
                    self.assertFalse(thread.is_alive())
            return "unpublished-report"

        self.src.heartbeat_post_collection_job = heartbeat
        self.src.generate_recommendation_report = report
        self.src.POST_COLLECTION_HEARTBEAT_SECONDS = 0.001
        with self.assertRaises(pipeline.PostCollectionLeaseLost):
            self.analysis._generate_report_with_heartbeat(
                job_id=1, servers=[], durable_job_id="job-1", worker_id="worker-a", claim_attempt=2,
            )
        self.assertTrue(all(call["claim_attempt"] == 2 for call in calls))

    def test_resume_passes_exact_claim_owner_and_generation(self):
        self.src.claim_queued_post_collection_jobs = MagicMock(return_value=[
            {"durable_job_id": "job-1", "attempt_count": 2},
        ])
        self.src._post_collection_executor = MagicMock()
        self.src._run_post_collection_job = self.worker._run_post_collection_job
        self.assertEqual(self.worker.resume_persisted_post_collection_jobs(), {"claimed": 1, "resumed": 1})
        claimed_owner = self.src.claim_queued_post_collection_jobs.call_args.kwargs["worker_id"]
        submitted = self.src._post_collection_executor.submit.call_args.kwargs
        self.assertEqual(submitted["worker_id"], claimed_owner)
        self.assertEqual(submitted["claim_attempt"], 2)


if __name__ == "__main__":
    unittest.main()
