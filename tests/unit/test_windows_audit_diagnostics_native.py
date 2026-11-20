"""WindowsOnly hermetic checks; direct execution requires both cases without skips."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HELPER_SOURCE = r'''
using System;
using System.IO;
using System.Text;
using System.Threading;
class FixtureTool {
    static int Main(string[] args) {
        // Even if the test host dies, this fixture-owned child cannot live forever.
        using (var deadline = new Timer(_ => Environment.Exit(99), null, 8000, Timeout.Infinite)) {
            Console.OutputEncoding = new UTF8Encoding(false);
            string mode = Environment.GetEnvironmentVariable("SLI_FIXTURE_MODE");
            if (args.Length > 0 && args[0] == "/PID") return 0; // harmless taskkill substitute
            if (mode == "flood") {
                var err = new Thread(() => Console.Error.Write(new string('e', 98304)));
                err.Start(); Console.Out.Write(new string('o', 98304)); err.Join(); return 0;
            }
            if (mode == "nonzero") { Console.Out.Write("small"); Console.Error.Write("small"); return 7; }
            if (mode == "timeout") { Thread.Sleep(7000); return 0; }
            if (mode == "boundary" || mode == "overflow") {
                Console.Out.Write(new string('\u00e9', 256));
                Console.Error.Write(new string('\u00e9', mode == "boundary" ? 256 : 257)); return 0;
            }
            if (mode == "audit") {
                string action = args[0];
                string log = Environment.GetEnvironmentVariable("SLI_FIXTURE_LOG");
                File.AppendAllText(log, action + "\n");
                string fail = Environment.GetEnvironmentVariable("SLI_FIXTURE_FAIL");
                int nth = int.Parse(Environment.GetEnvironmentVariable("SLI_FIXTURE_NTH") ?? "1");
                int count = 0; foreach (string line in File.ReadAllLines(log)) if (line == action) count++;
                return action == fail && count == nth ? 5 : 0;
            }
            return 0;
        }
    }
}
'''


class WindowsAuditNative(unittest.TestCase):
    def run_shell(self, shell_name):
        if os.name != "nt":
            self.skipTest("Requires Windows; no Windows process or policy command was executed")
        shell = shutil.which(shell_name)
        if shell is None:
            self.skipTest(f"{shell_name} is not installed")
        windir = Path(os.environ["WINDIR"])
        compilers = [windir / "Microsoft.NET" / framework / "v4.0.30319/csc.exe"
                     for framework in ("Framework64", "Framework")]
        compiler = next((path for path in compilers if path.is_file()), None)
        if compiler is None:
            self.skipTest("Existing .NET Framework csc.exe is absent; no compiler is installed by this test")
        with tempfile.TemporaryDirectory(prefix="sli-audit-fixture-") as temp:
            folder = Path(temp)
            source = folder / "FixtureTool.cs"
            helper = folder / "FixtureTool.exe"
            source.write_text(HELPER_SOURCE, encoding="utf-8")
            built = subprocess.run([str(compiler), "/nologo", "/target:exe", f"/out:{helper}", str(source)],
                                   capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run([
                shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
                str(ROOT / "tests/fixtures/windows_audit_diagnostics.ps1"),
                "-RepositoryRoot", str(ROOT), "-FixtureRoot", str(folder), "-HelperPath", str(helper),
                "-ExpectedMajor", "5" if shell_name == "powershell.exe" else "7",
            ], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=25, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("HERMETIC_WINDOWS_AUDIT_OK", result.stdout)

    def test_windows_powershell_51(self):
        self.run_shell("powershell.exe")

    def test_powershell_7(self):
        self.run_shell("pwsh.exe")


def main():
    """Win10 acceptance gate; Linux or missing native prerequisites must not pass."""
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(WindowsAuditNative)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() and not result.skipped and result.testsRun == 2 else 1


if __name__ == "__main__":
    raise SystemExit(main())
