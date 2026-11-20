"""Static wiring checks and native Windows path fixtures; never run a backup."""

import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ops/Backup-ProjectSource-NoDb.ps1"
SOURCE = SCRIPT.read_text(encoding="utf-8")
POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")


class SourceBackupContainmentTests(unittest.TestCase):
    def test_guard_uses_normalized_component_boundary_before_writes(self):
        self.assertNotIn("$dest.ToLowerInvariant().StartsWith", SOURCE)
        self.assertIn("[IO.Path]::GetFullPath($SourcePath)", SOURCE)
        self.assertIn("[IO.Path]::GetFullPath($DestinationPath)", SOURCE)
        self.assertIn("$destination.Equals($source, $comparison)", SOURCE)
        self.assertIn("$destination.StartsWith($source + [IO.Path]::DirectorySeparatorChar, $comparison)", SOURCE)
        guard = SOURCE.index("if (Test-SourceBackupContainment -SourcePath $ProjectRoot -DestinationPath $dest)")
        self.assertLess(guard, SOURCE.index("if ($ValidateOnly)"))
        self.assertLess(guard, SOURCE.index("New-Item -ItemType Directory"))

    def test_backup_root_is_resolved_without_requiring_it_to_exist(self):
        self.assertIn("$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BackupRoot, [ref]$backupProvider, [ref]$backupDrive)", SOURCE)
        self.assertIn("$dest        = [IO.Path]::GetFullPath((Join-Path $BackupRoot $stamp))", SOURCE)

    def test_non_filesystem_provider_is_rejected_before_path_use(self):
        resolver = SOURCE.index("GetUnresolvedProviderPathFromPSPath($BackupRoot,")
        guard = SOURCE.index('if ($backupProvider.Name -ne "FileSystem")')
        destination = SOURCE.index("$dest        = [IO.Path]::GetFullPath")
        self.assertLess(resolver, guard)
        self.assertLess(guard, destination)
        self.assertIn('throw "BackupRoot must use the FileSystem provider."', SOURCE[guard:destination])

    @unittest.skipUnless(os.name == "nt" and POWERSHELL, "requires native Windows PowerShell path semantics")
    def test_native_windows_path_fixtures(self):
        cases = [
            (r"C:\work\project", r"C:\work\project_backup\stamp", False),
            (r"C:\work\project", r"C:\work\project2\stamp", False),
            (r"C:\work\project", r"C:\work\project", True),
            (r"C:\work\project", "C:\\work\\project\\", True),
            (r"C:\work\project", r"C:\work\project\backup\stamp", True),
            ("C:\\work\\project\\", r"C:\work\project\backup", True),
            (r"C:\work\project", r"c:\WORK\PROJECT\backup", True),
            (r"C:\work\project", "C:/work/project/backup", True),
            (r"C:\work\project", r"C:\work\outside\..\project\backup", True),
            (r"C:\work\project", r"C:\work\project\..\project_backup\stamp", False),
            (r"C:\work\other\..\project", r"C:\work\project\backup", True),
            ("C:\\", r"C:\backup", True),
            ("C:\\", "C:\\", True),
            (r"C:\work\project", r"D:\work\project\backup", False),
            (r"\\server\share\project", r"\\server\share\project_backup\stamp", False),
            (r"\\server\share", r"\\server\share\backup", True),
            (r"\\server\share", r"\\server\share2\backup", False),
        ]
        # Parse the production function only. Never dot-source the operational script.
        harness = r"""
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($env:BACKUP_SCRIPT, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-SourceBackupContainment' }, $true)
if ($null -eq $function) { throw 'Containment function missing' }
. ([scriptblock]::Create($function.Extent.Text))
$cases = ConvertFrom-Json $env:BACKUP_CASES
foreach ($case in $cases) {
    $actual = Test-SourceBackupContainment -SourcePath $case[0] -DestinationPath $case[1]
    if ($actual -ne $case[2]) { throw ('Unexpected containment: ' + ($case | ConvertTo-Json -Compress)) }
}
"""
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", harness],
            env={**os.environ, "BACKUP_SCRIPT": str(SCRIPT), "BACKUP_CASES": json.dumps(cases)},
            text=True, capture_output=True, timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
