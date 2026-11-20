"""Operator recovery exception contracts; no Docker, network or database."""
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from pathlib import Path
from contextlib import nullcontext
import tempfile
import copy

from deploy.linux import sli_update as update


class BackupHealthWaiverTests(unittest.TestCase):
    def setUp(self):
        self.journal = {"services": ["api", "backup"], "status": "rolling_back",
                        "migration_started": False, "previous": {"image_digest": "sha256:" + "a" * 64}}
        self.rows = [{"ID": s, "Service": s, "State": "running", "Health": "healthy"}
                     for s in {"api", "backup", *update.INFRA}]
        next(r for r in self.rows if r["Service"] == "backup")["Health"] = "unhealthy"
        self.host = update.DockerHost([], "https://example.invalid/api/health/ready", None, timeout=1)
        self.actual_image = self.journal["previous"]["image_digest"]
        self.http_status = 200

    def health(self, **kwargs):
        response = SimpleNamespace(status=self.http_status)
        from contextlib import nullcontext
        with patch.object(self.host, "containers", return_value=self.rows), \
             patch.object(self.host, "command", return_value=self.actual_image), \
             patch.object(update.ssl, "create_default_context"), \
             patch.object(update, "urlopen", return_value=nullcontext(response)), \
             patch.object(update.time, "monotonic", side_effect=[0, 0, 2]), \
             patch.object(update.time, "sleep"):
            return self.host.health(self.journal, **kwargs)

    def test_backup_only_waiver_preserves_observed_unhealthy(self):
        evidence = self.health(backup_waiver="previous")
        self.assertEqual(evidence["backup_health"], "operator_waived")
        self.assertEqual(evidence["observed_health"], "unhealthy")

    def test_default_remains_strict(self):
        with self.assertRaisesRegex(update.UpdateError, "update_health_timeout"):
            self.health()

    def test_other_unhealthy_not_waived(self):
        next(r for r in self.rows if r["Service"] == "api")["Health"] = "unhealthy"
        with self.assertRaisesRegex(update.UpdateError, "update_health_timeout"):
            self.health(backup_waiver="previous")

    def test_previous_requires_explicit_false(self):
        for value in (True, None, 0):
            with self.subTest(value=value):
                self.journal["migration_started"] = value
                with self.assertRaisesRegex(update.UpdateError, "update_backup_waiver_not_allowed"):
                    self.health(backup_waiver="previous")

    def test_stopped_backup_not_waived(self):
        next(r for r in self.rows if r["Service"] == "backup")["State"] = "exited"
        with self.assertRaisesRegex(update.UpdateError, "update_health_timeout"):
            self.health(backup_waiver="previous")

    def test_wrong_image_not_waived(self):
        self.actual_image = "sha256:" + "b" * 64
        with self.assertRaisesRegex(update.UpdateError, "update_runtime_mismatch"):
            self.health(backup_waiver="previous")

    def test_https_non_200_not_waived(self):
        self.http_status = 503
        with self.assertRaisesRegex(update.UpdateError, "update_health_timeout"):
            self.health(backup_waiver="previous")

    def test_candidate_keeps_migration_true(self):
        self.journal.update(status="recovery_required", migration_started=True,
                            manifest={"image": {"digest": self.actual_image}})
        self.assertEqual(self.health(backup_waiver="candidate")["backup_health"], "operator_waived")
        self.journal["migration_started"] = False
        with self.assertRaisesRegex(update.UpdateError, "update_backup_waiver_not_allowed"):
            self.health(backup_waiver="candidate")

    def test_missing_and_duplicate_backup_are_not_waived(self):
        original = copy.deepcopy(self.rows)
        for mode in ("missing", "duplicate"):
            self.rows = copy.deepcopy(original)
            if mode == "missing":
                self.rows = [row for row in self.rows if row["Service"] != "backup"]
            else:
                self.rows.append(next(row.copy() for row in self.rows if row["Service"] == "backup"))
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(update.UpdateError, "update_health_timeout"):
                    self.health(backup_waiver="previous")

    def test_starting_backup_is_recorded_and_healthy_is_not_called_waived(self):
        backup = next(row for row in self.rows if row["Service"] == "backup")
        for state, expected in (("starting", "operator_waived"), ("healthy", "healthy")):
            backup["Health"] = state
            evidence = self.health(backup_waiver="previous")
            self.assertEqual(evidence["backup_health"], expected)
            self.assertEqual(evidence["observed_health"], state)

    def test_tls_failure_is_not_waived(self):
        with patch.object(self.host, "containers", return_value=self.rows), \
             patch.object(self.host, "command", return_value=self.actual_image), \
             patch.object(update.ssl, "create_default_context"), \
             patch.object(update, "urlopen", side_effect=update.ssl.SSLError("synthetic TLS rejection")), \
             patch.object(update.time, "monotonic", side_effect=[0, 0, 2]), \
             patch.object(update.time, "sleep"):
            with self.assertRaisesRegex(update.UpdateError, "update_health_timeout"):
                self.host.health(self.journal, backup_waiver="previous")


class RecoveryWaiverRoutingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.updater = update.Updater(Path(self.temp.name), Path(self.temp.name) / "trust", None)
        self.journal = {"component": "server", "operation": "a" * 32, "status": "recovery_required",
                        "phase": "checkpoint", "completed": ["stage"], "reason": "update_drain_service_timeout",
                        "migration_started": False, "previous": {"version": "1.0.0", "image_tag": "old",
                                                                   "image_digest": "sha256:" + "a" * 64}}

    def resume(self):
        with patch.object(update, "operation_lock", return_value=nullcontext()), \
             patch.object(self.updater, "require_volume_reconciled"), \
             patch.object(self.updater, "operation", return_value=self.journal), \
             patch.object(self.updater, "read_journal", return_value=self.journal), \
             patch.object(self.updater, "validate_resume"), \
             patch.object(self.updater, "rollback", return_value="rolled_back") as rollback:
            result = self.updater.resume(operation_id=self.journal["operation"], allow_unhealthy_backup=True)
            return result, rollback.call_args

    def test_resume_routes_explicit_waiver_only_to_rollback(self):
        result, args = self.resume()
        self.assertEqual(result, "rolled_back")
        self.assertTrue(args.kwargs["allow_unhealthy_backup"])

    def test_resume_waiver_accepts_server_journal_without_component_key(self):
        # Server update journals written by apply() carry no "component" key.
        del self.journal["component"]
        result, args = self.resume()
        self.assertEqual(result, "rolled_back")
        self.assertTrue(args.kwargs["allow_unhealthy_backup"])

    def test_resume_waiver_refuses_forward_run(self):
        self.journal["status"] = "running"
        with self.assertRaisesRegex(update.UpdateError, "update_backup_waiver_not_allowed"):
            self.resume()

    def test_resume_waiver_refuses_migration_and_plugins(self):
        for key, value in (("migration_started", True), ("migration_started", None), ("component", "plugin")):
            before = copy.deepcopy(self.journal)
            self.journal[key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaisesRegex(update.UpdateError, "update_backup_waiver_not_allowed"):
                    self.resume()
            self.journal = before

    def test_cli_refuses_waiver_for_apply(self):
        from contextlib import redirect_stdout, redirect_stderr
        import io
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(update.main(["apply", "--allow-unhealthy-backup"]), 1)

class AcceptanceWaiverAuditTests(unittest.TestCase):
    def setUp(self):
        from unittest.mock import Mock
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.host = SimpleNamespace(files=[], health=Mock(return_value={"backup_health": "operator_waived",
            "observed_health": "unhealthy", "image_digest": "sha256:" + "a" * 64}),
            runtime_matches=Mock(return_value={}), acceptance_preflight=Mock())
        self.updater = update.Updater(self.root, self.root / "trust", self.host)
        self.updater.state.mkdir(mode=0o700)
        self.archive = self.root / "package.zip"
        self.archive.write_bytes(b"synthetic")
        self.journal = {"operation": "a" * 32, "status": "recovery_required", "component": "server",
            "manifest": {"component": "server"}, "phase": "health", "completed": list(update.PHASES[:6]),
            "migration_started": True, "recovery_started": True, "backup_id": "update-checkpoints/" + "a" * 32 + "/20260101T000000.000000Z",
            "checkpoint_sha256": "b" * 64, "checkpoint_key": "c" * 64,
            "package": str(self.archive), "package_sha256": update.sha256(self.archive), "previous": {}}
        self.candidate = {"version": "1.2.3", "image_tag": "candidate", "image_digest": "sha256:" + "a" * 64}
        self.updater.save(self.journal)

    def accept(self, *, dry_run=False, crash=False):
        def publish(journal, candidate):
            durable = self.updater.read_journal(self.updater.journal_path)
            self.assertEqual(durable["candidate_acceptance"]["backup_health"], "operator_waived")
            self.assertEqual(durable["candidate_acceptance"]["status"], "pending")
            if crash:
                raise RuntimeError("simulated publication interruption")
            return {"migration_ledger_max": 1}
        with patch.object(self.updater, "verified", return_value=SimpleNamespace(manifest=self.journal["manifest"])), \
             patch.object(self.updater, "validate_resume"), patch.object(self.updater, "candidate", return_value=self.candidate), \
             patch.object(self.updater, "recovery_authority"), patch("deploy.linux.installed_state.validate"), \
             patch.object(update, "acceptance_compose_order", return_value=[]), patch.object(self.updater, "publish", side_effect=publish):
            return self.updater.accept_candidate(operation_id=self.journal["operation"], dry_run=dry_run,
                                                  allow_unhealthy_backup=True)

    def test_acceptance_audit_is_durable_before_publish(self):
        self.assertEqual(self.accept(), "committed")
        audit = self.updater.read_journal(self.updater.journal_path)["candidate_acceptance"]
        self.assertEqual(audit["backup_health"], "operator_waived")
        self.assertEqual(audit["backup_health_override"]["observed_health"], "unhealthy")
        self.assertEqual(audit["backup_health_override"]["reason"], "operator_allowed_unhealthy_backup")

    def test_dry_run_has_no_durable_audit(self):
        before = self.updater.journal_path.read_bytes()
        self.assertEqual(self.accept(dry_run=True), "dry_run")
        self.assertEqual(self.updater.journal_path.read_bytes(), before)

    def test_pending_retry_keeps_authorization_timestamp(self):
        with self.assertRaisesRegex(RuntimeError, "simulated"):
            self.accept(crash=True)
        pending = self.updater.read_journal(self.updater.journal_path)["candidate_acceptance"]
        self.assertEqual(self.accept(), "committed")
        final = self.updater.read_journal(self.updater.journal_path)["candidate_acceptance"]
        self.assertEqual(final["backup_health_override"]["requested_at_utc"],
                         pending["backup_health_override"]["requested_at_utc"])

    def test_false_migration_is_not_candidate_acceptance(self):
        self.journal["migration_started"] = False
        self.updater.save(self.journal)
        with self.assertRaisesRegex(update.UpdateError, "update_candidate_acceptance_required"):
            self.accept()
    def test_waiver_audit_tampering_fails_authentication(self):
        import json
        self.accept()
        value = json.loads(self.updater.journal_path.read_text())
        value["candidate_acceptance"]["backup_health"] = "healthy"
        self.updater.journal_path.write_text(json.dumps(value))
        with self.assertRaisesRegex(update.UpdateError, "update_journal_authentication_failed"):
            self.updater.read_journal(self.updater.journal_path)


class DrainFailureEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.host = update.DockerHost([], "https://example.invalid/api/health/ready", None)
        self.attempt = {"addressed_containers": [{"ID": "one", "Service": "api"},
                                                  {"ID": "two", "Service": "backup"}], "stop_pending": True}

    def test_timeout_names_only_still_running_service(self):
        rows = [{"ID": "one", "Service": "api", "State": "exited"},
                {"ID": "two", "Service": "backup", "State": "running"}]
        with patch.object(self.host, "containers", return_value=rows), patch.object(update.time, "monotonic", return_value=2):
            with self.assertRaisesRegex(update.UpdateError, "update_drain_service_timeout"):
                self.host.wait_stopped(self.attempt, 1)
        self.assertEqual(self.attempt["failed_services"], ["backup"])
        self.assertEqual(self.attempt["failure_reason"], "still_running")
        self.assertTrue(self.attempt["stop_pending"])

    def test_missing_container_is_unverified_not_claimed_running(self):
        rows = [{"ID": "one", "Service": "api", "State": "exited"}]
        with patch.object(self.host, "containers", return_value=rows):
            with self.assertRaisesRegex(update.UpdateError, "update_drain_service_timeout"):
                self.host.wait_stopped(self.attempt, 1)
        self.assertEqual(self.attempt["failed_services"], ["backup"])
        self.assertEqual(self.attempt["failure_reason"], "container_identity_unverified")

    def test_operation_projection_is_bounded_and_rejects_untrusted_names(self):
        updater = update.Updater("/unused", "/unused/trust", None)
        journal = {"status": "recovery_required", "operation": "a" * 32,
                   "drain_services": [{"failed_services": ["backup", "api", "x\nsecret", "api"], "failure_reason": "still_running"}]}
        self.assertEqual(updater.operation_result(journal)["drain_failed_services"], ["api", "backup"])
    def result(self, attempts):
        return update.Updater("/unused", "/unused/trust", None).operation_result({
            "status": "recovery_required", "operation": "a" * 32, "drain_services": attempts})

    def test_retry_reports_new_service_not_union_of_history(self):
        result = self.result([{"failed_services": ["api"], "failure_reason": "still_running"},
                              {"failed_services": ["backup"], "failure_reason": "still_running"}])
        self.assertEqual(result["drain_failed_services"], ["backup"])

    def test_latest_failure_after_128_attempts_is_visible(self):
        attempts = [{"failed_services": ["api"], "failure_reason": "still_running"}] * 140
        attempts.append({"failed_services": ["backup"], "failure_reason": "still_running"})
        self.assertEqual(self.result(attempts)["drain_failed_services"], ["backup"])

    def test_missing_identity_projects_unknown_not_failed_stop(self):
        result = self.result([{"failed_services": ["backup"], "failure_reason": "container_identity_unverified"}])
        self.assertNotIn("drain_failed_services", result)
        self.assertEqual(result["drain_unverified_services"], ["backup"])
        self.assertEqual(result["drain_failure_certainty"], "unknown")
        self.assertEqual(result["drain_failure_reason"], "container_identity_unverified")

    def test_successful_settlement_does_not_resurrect_historical_failure(self):
        self.attempt.update(failed_services=["backup"], failure_reason="still_running")
        rows = [{"ID": "one", "Service": "api", "State": "exited"},
                {"ID": "two", "Service": "backup", "State": "exited"}]
        with patch.object(self.host, "containers", return_value=rows):
            self.host.wait_stopped(self.attempt, 1)
        self.assertNotIn("drain_failed_services", self.result([
            {"failed_services": ["api"], "failure_reason": "still_running"}, self.attempt]))

    def test_new_successful_attempt_hides_old_failure(self):
        self.assertNotIn("drain_failed_services", self.result([
            {"failed_services": ["api"], "failure_reason": "still_running"},
            {"services": ["backup"], "stop_pending": False}]))

    def test_unavailable_readback_preserves_explicit_unknown_without_names(self):
        result = self.result([{"failure_reason": "readback_unavailable", "failed_services": []}])
        self.assertEqual(result["drain_failure_certainty"], "unknown")
        self.assertEqual(result["drain_failure_reason"], "readback_unavailable")
        self.assertNotIn("drain_failed_services", result)


class RollbackWaiverAuditTests(RecoveryWaiverRoutingTests):
    def rollback(self, mutate=False):
        from unittest.mock import Mock
        self.updater.state.mkdir(mode=0o700, exist_ok=True)
        self.journal["manifest"] = {}
        def stop(journal):
            durable = self.updater.read_journal(self.updater.journal_path)
            self.assertEqual(durable["backup_health_override"]["status"], "requested")
        def activate(journal, **kwargs):
            if mutate:
                journal["migration_started"] = True
        host = SimpleNamespace(stop_operation=stop, activate=activate,
            runtime_matches=Mock(return_value={"migration_ledger_max": 1}),
            health=Mock(return_value={"backup_health": "operator_waived", "observed_health": "unhealthy",
                                      "image_digest": "sha256:" + "a" * 64}))
        self.updater.host = host
        with patch.object(self.updater, "candidate", return_value={}), \
             patch.object(self.updater, "recovery_authority"), patch.object(update, "checked_override"), \
             patch.object(self.updater, "sync_notification_compose"), \
             patch.object(self.updater, "publish", return_value={"migration_ledger_max": 1}):
            result = self.updater.rollback(self.journal, "update_operator_rollback", allow_unhealthy_backup=True)
        return result, host

    def test_rollback_signed_intent_precedes_stop_and_health_evidence_is_durable(self):
        result, host = self.rollback()
        self.assertEqual(result, "rolled_back")
        journal = self.updater.read_journal(self.updater.journal_path)
        self.assertEqual(journal["backup_health_override"]["status"], "verified")
        self.assertEqual(journal["backup_health_override"]["backup_health"], "operator_waived")
        self.assertEqual(host.health.call_args.kwargs, {"backup_waiver": "previous"})

    def test_rollback_rechecks_migration_before_health(self):
        result, host = self.rollback(mutate=True)
        self.assertEqual(result, "recovery_required")
        self.assertEqual(self.journal["rollback_error"], "update_backup_waiver_not_allowed")
        host.health.assert_not_called()

    def test_rollback_guard_prevents_any_journal_write(self):
        self.journal["migration_started"] = True
        with self.assertRaisesRegex(update.UpdateError, "update_backup_waiver_not_allowed"):
            self.updater.rollback(self.journal, "update_operator_rollback", allow_unhealthy_backup=True)
        self.assertFalse(self.updater.journal_path.exists())

class WaiverCliTests(unittest.TestCase):
    def args(self, action):
        return [action, "--allow-unhealthy-backup", "--compose", "/synthetic/compose", "--ca-file", "/synthetic/ca",
                "--trust-store", "/synthetic/trust", "--operation-id", "a" * 32]

    def test_success_prints_specific_warning(self):
        import io
        from contextlib import redirect_stdout
        output = io.StringIO()
        with patch.object(update, "runtime_action", return_value={"status": "rolled_back", "backup_health": "operator_waived"}), redirect_stdout(output):
            self.assertEqual(update.main(self.args("rollback")), 0)
        self.assertIn("проверка восстановления не подтверждена", output.getvalue())

    def test_resume_dry_run_does_not_execute(self):
        import io
        from contextlib import redirect_stdout, redirect_stderr
        with patch.object(update, "runtime_action") as action, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(update.main(self.args("resume") + ["--dry-run"]), 1)
        action.assert_not_called()


if __name__ == "__main__":
    unittest.main()
