"""Source-only regression checks; never import or execute operational PowerShell."""
import io
import re
import runpy
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
# Microsoft [MS-GPAC] 2.2.1.2, Subcategory and SubcategoryGUID:
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d
AUDIT_IDS = {
    "Credential Validation": "923f",
    "Security Group Management": "9237",
    "User Account Management": "9235",
    "Computer Account Management": "9236",
    "Other Account Management Events": "923a",
    "Process Creation": "922b",
    "Process Termination": "922c",
    "Logon": "9215",
    "Logoff": "9216",
    "Other Logon/Logoff Events": "921c",
    "Special Logon": "921b",
    "Account Lockout": "9217",
    "File Share": "9224",
    "Removable Storage": "9245",
    "Audit Policy Change": "922f",
    "MPSSVC Rule-Level Policy Change": "9232",
    "Other Policy Change Events": "9234",
    "Authentication Policy Change": "9230",
    "Authorization Policy Change": "9231",
    "Security State Change": "9210",
    "Security System Extension": "9211",
    "System Integrity": "9212",
    "Directory Service Access": "923b",
    "Directory Service Changes": "923c",
    "Directory Service Replication": "923d",
    "Kerberos Authentication Service": "9242",
    "Kerberos Service Ticket Operations": "9240",
}


class WindowsAuditContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.setup = (ROOT / "scripts/manual_dc_audit/Invoke-DcAuditLoggingSetup.ps1").read_text()
        source = (ROOT / "scripts/ad_context/ActiveDirectoryContext.psm1").read_text()
        cls.dcdiag = source.split("function Invoke-SLIBoundedDcdiag {", 1)[1].split(
            "function ConvertTo-SLIReplicationRecord", 1
        )[0]

    def test_all_27_subcategories_match_microsoft(self):
        found = dict(re.findall(r'Name = "([^"]+)"; Guid = "\{([^}]+)\}"', self.setup))
        expected = {name: f"0cce{suffix}-69ae-11d9-bed3-505054503030" for name, suffix in AUDIT_IDS.items()}
        self.assertEqual(found, expected)

    def test_every_auditpol_call_checks_native_exit(self):
        self.assertNotRegex(self.setup, r"(?m)^\s*auditpol\s")
        wrapper = self.setup.split("function Invoke-CommandLine {", 1)[1].split("function Export-DcAuditState", 1)[0]
        self.assertRegex(wrapper, r"& \$FilePath @Arguments\s+if \(\$LASTEXITCODE -ne 0\)")
        self.assertIn('throw "$Description failed', wrapper)

    def test_validate_subcategory_before_mutation(self):
        body = self.setup.split("function Set-AuditPolicyItem {", 1)[1].split("function Install-Minimum", 1)[0]
        self.assertIn('"/get"', body)
        self.assertLess(body.index('"/get"'), body.index('"/set"'))
        self.assertIn("[guid]", body)

    def test_partial_application_cannot_reach_completed_message(self):
        body = self.setup.split("function Install-MinimumAuditPolicy {", 1)[1].split(
            "function Restore-AuditPolicyFromBackup", 1
        )[0]
        self.assertLess(body.index("Set-AuditPolicyItem -Setting $setting"),
                        body.index("Installation menu completed"))
        self.assertNotIn("catch", body)
        self.assertIn('$ErrorActionPreference = "Stop"', self.setup)

    def test_concurrent_fixed_size_drains_precede_wait(self):
        self.assertNotIn("ReadToEnd", self.dcdiag)
        self.assertIn("[char[]]::new(4096)", self.dcdiag)
        self.assertIn("$process.StandardOutput", self.dcdiag)
        self.assertIn("$process.StandardError", self.dcdiag)
        self.assertLess(self.dcdiag.index(".ReadAsync("), self.dcdiag.index(".WaitForExit("))
        self.assertIn("$read.IsCompleted", self.dcdiag)
        self.assertIn("$stream.Encoder.GetBytes(", self.dcdiag)
        self.assertNotIn("$stream.Encoder.GetByteCount(", self.dcdiag)
        self.assertIn("$clock.Elapsed.TotalSeconds", self.dcdiag)
        self.assertIn("$totalBytes -gt $MaxDiagnosticBytes", self.dcdiag)
        self.assertIn("$process.HasExited -and $streams[0].Done -and $streams[1].Done", self.dcdiag)
        self.assertLess(self.dcdiag.index("dcdiag_output_limit_exceeded"),
                        self.dcdiag.index("$process.ExitCode -eq 0"))

    def test_cleanup_and_result_states_remain_bounded_and_honest(self):
        self.assertNotIn("& taskkill", self.dcdiag)
        self.assertIn('$killInfo.FileName = "taskkill.exe"', self.dcdiag)
        self.assertIn("$killer.WaitForExit(1000)", self.dcdiag)
        self.assertIn("$killer.Dispose()", self.dcdiag)
        self.assertNotRegex(self.dcdiag, r"WaitForExit\(\)")
        self.assertIn("WaitForExit(1000)", self.dcdiag)
        self.assertIn("$process.Kill()", self.dcdiag)
        self.assertIn("$stream.Reader.Dispose()", self.dcdiag)
        self.assertIn("$stream.Read.IsFaulted", self.dcdiag)
        self.assertIn("$null = $stream.Read.Exception", self.dcdiag)
        self.assertIn("$process.Dispose()", self.dcdiag)
        for state in ("passed", "failed", "unavailable", "timeout"):
            self.assertIn(f'state = "{state}"', self.dcdiag)
        for code in ("dcdiag_timeout", "dcdiag_output_limit_exceeded", "dcdiag_unavailable"):
            self.assertIn(code, self.dcdiag)

    def test_windows_workflow_is_narrow_and_only_runs_portable_contracts(self):
        workflow = (ROOT / ".github/workflows/windows-audit-diagnostics.yml").read_text()
        paths = re.findall(r"^      - (.+)$", workflow.split("permissions:", 1)[0], re.MULTILINE)
        self.assertEqual(set(paths), {
            "scripts/manual_dc_audit/Invoke-DcAuditLoggingSetup.ps1",
            "scripts/ad_context/ActiveDirectoryContext.psm1",
            "tests/unit/test_windows_audit_diagnostics_contracts.py",
            "tests/unit/test_windows_audit_diagnostics_native.py",
            "tests/fixtures/windows_audit_diagnostics.ps1",
            ".github/workflows/windows-audit-diagnostics.yml",
        })
        self.assertEqual(len(paths), 6)
        self.assertIn("on:\n  pull_request:\n    paths:", workflow)
        self.assertIn("permissions:\n  contents: read\n", workflow)
        self.assertIn("runs-on: ubuntu-latest", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("python3 -m unittest discover -s tests/unit -p test_windows_audit_diagnostics_contracts.py -v", workflow)
        self.assertIn("WindowsOnly: deferred", workflow)
        self.assertIn("not executed on Linux", workflow)
        self.assertIn("python tests/unit/test_windows_audit_diagnostics_native.py", workflow)
        self.assertNotIn("shell: pwsh", workflow)
        self.assertNotIn("pattern=\"test_windows_audit_diagnostics_native.py\"", workflow)
        self.assertEqual(re.findall(r"uses: (.+)", workflow), ["actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4"])
        self.assertNotRegex(workflow, r"(?i)install|secrets\.|pull_request_target|continue-on-error")

    def test_manual_native_gate_rejects_skips_failures_and_missing_tests(self):
        native = runpy.run_path(str(ROOT / "tests/unit/test_windows_audit_diagnostics_native.py"))
        self.assertTrue(callable(native.get("main")), "Native CLI must preserve the strict Windows acceptance gate")
        native_class = native["WindowsAuditNative"]

        def run_shell(test, _shell):
            if outcome == "skip":
                test.skipTest("synthetic missing Windows prerequisite")
            if outcome == "fail":
                test.fail("synthetic native fixture failure")

        for outcome, count, expected in (
            ("pass", 2, 0), ("skip", 2, 1), ("fail", 2, 1),
            ("pass", 0, 1), ("pass", 1, 1), ("pass", 3, 1),
        ):
            with self.subTest(outcome=outcome, count=count):
                cases = list(unittest.defaultTestLoader.loadTestsFromTestCase(native_class))
                cases.append(native_class("test_powershell_7"))
                # Replace only the OS execution boundary; retain real unittest results.
                with patch.object(native_class, "run_shell", run_shell), redirect_stderr(io.StringIO()):
                    with patch.object(unittest.defaultTestLoader, "loadTestsFromTestCase",
                                      return_value=unittest.TestSuite(cases[:count])):
                        self.assertEqual(native["main"](), expected)


if __name__ == "__main__":
    unittest.main()
