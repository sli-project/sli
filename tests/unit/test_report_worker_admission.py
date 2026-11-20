"""Real claim/guard source with synthetic cursor; no DB, secrets or transport."""
import ast
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4
import inspect
import unittest

ROOT = Path(__file__).resolve().parents[2]


def worker_functions():
    source = ROOT / "server/sli/core/notification_outbox.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    tree.body = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in {"claim_job", "process_one"}]
    calls = []
    cursor = SimpleNamespace(execute=lambda sql, params=(): calls.append((sql, params)), fetchone=lambda: None)
    conn = SimpleNamespace(cursor=lambda: nullcontext(cursor), commit=lambda: None)
    namespace = {"connect": lambda: nullcontext(conn), "uuid4": uuid4, "dry_run_transport": lambda job: "dry_run"}
    exec(compile(tree, str(source), "exec"), namespace)
    return namespace, calls


class AdmissionTests(unittest.TestCase):
    def test_explicit_report_admission_uses_only_fixed_fair_claim_api(self):
        functions, calls = worker_functions()
        self.assertIn("include_reports", inspect.signature(functions["claim_job"]).parameters)
        functions["claim_job"](telegram=True, notification_only=True, include_reports=True)
        self.assertEqual(calls[-1][0], 'select * from public.notification_claim_fair()')
        self.assertEqual(calls[-1][1], ())
    def test_fixed_fair_claim_has_explicit_read_and_lock_budget(self):
        functions, calls = worker_functions()
        functions['claim_job'](telegram=True, notification_only=True, include_reports=True)
        self.assertEqual(calls[0][1], ('2000ms', '500ms'))
    def test_default_never_consumes_report_jobs_as_dry_run(self):
        functions, calls = worker_functions()
        functions["claim_job"]()
        self.assertIn("object_kind<>'report_schedule'", calls[0][0])
    def test_admission_requires_both_existing_transports_enabled(self):
        functions, calls = worker_functions()
        self.assertIn("include_reports", inspect.signature(functions["process_one"]).parameters)
        with self.assertRaises(ValueError):
            functions["process_one"](notification_only=True, telegram=True, include_reports=True)
        self.assertEqual(calls, [])
    def test_persistent_worker_keeps_smtp_and_telegram(self):
        tree = ast.parse((ROOT / "deploy/linux/notification_delivery.py").read_text(encoding="utf-8"))
        call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == "process_one")
        self.assertEqual({keyword.arg: ast.literal_eval(keyword.value) for keyword in call.keywords},
                         {"smtp": True, "telegram": True, "notification_only": True, "include_reports": True})


if __name__ == "__main__":
    unittest.main()
