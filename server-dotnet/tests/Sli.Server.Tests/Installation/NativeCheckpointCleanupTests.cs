using System.Diagnostics;
using System.Runtime.CompilerServices;
using Xunit;

namespace Sli.Server.Tests.InstallationSetup;

// Native package transactions are shared with the Python installation helpers;
// the .NET server must keep their real retention guard covered by its CI gate.
public sealed class NativeCheckpointCleanupTests
{
    [Fact]
    public async Task Shared_installer_preserves_uncertain_checkpoints_and_verification_policy()
    {
        var ct = TestContext.Current.CancellationToken;
        string root = Repository();
        Directory.CreateDirectory(Path.Combine(root, ".net-local"));
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("SLI_TEST_PYTHON") ??
            (OperatingSystem.IsWindows() ? "python" : "python3"))
        {
            WorkingDirectory = root, UseShellExecute = false, CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden, RedirectStandardOutput = true, RedirectStandardError = true
        };
        var inherited = new[] { "PATH", "LD_LIBRARY_PATH", "SystemRoot", "WINDIR", "TEMP", "TMP" }
            .Select(key => (key, value: Environment.GetEnvironmentVariable(key))).ToArray();
        start.Environment.Clear();
        foreach (var (key, value) in inherited) if (value is not null) start.Environment[key] = value;
        foreach (string argument in new[] {
            "-B", "-m", "pytest", "-q",
            "tests/unit/test_linux_native_cleanup.py",
            "tests/unit/test_linux_native_upgrade_prepare.py::test_legacy_checkpoint_mode_keeps_full_restore_on_resume",
            "tests/unit/test_linux_native_upgrade_prepare.py::test_legacy_checkpoint_mode_requires_stopped_restore",
            "tests/unit/test_linux_native_upgrade_prepare.py::test_legacy_checkpoint_mode_rejects_integrity_receipt",
            "tests/unit/test_linux_native_upgrade_prepare.py::test_unknown_checkpoint_verification_mode_is_refused",
            "tests/unit/test_linux_native_upgrade_prepare.py::test_integrity_receipt_rejects_invalid_binding",
            "tests/unit/test_linux_native_upgrade_prepare.py::test_integrity_receipt_rechecks_current_manifest",
            "--basetemp", ".net-local/pytest-067-" + Guid.NewGuid().ToString("N")
        }) start.ArgumentList.Add(argument);
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync(ct);
        var stderr = process.StandardError.ReadToEndAsync(ct);
        try { await process.WaitForExitAsync(ct); }
        finally
        {
            if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); }
        }
        string output = await stdout, error = await stderr;
        Assert.True(process.ExitCode == 0, output + error);
        Assert.DoesNotContain(" skipped", output);
    }

    private static string Repository([CallerFilePath] string path = "") =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(path)!, "../../../.."));
}
