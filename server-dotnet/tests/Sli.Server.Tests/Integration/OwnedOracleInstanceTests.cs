using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json.Nodes;
using Xunit;

namespace Sli.Server.Tests.Integration;

public sealed class OwnedOracleInstanceTests
{
    [Fact]
    public void Marker_records_real_creation_identity_and_live_original_preserves_every_file()
    {
        using var run = new Run();
        using var process = Process.GetCurrentProcess();
        string instance = run.Record(process);
        var marker = JsonNode.Parse(File.ReadAllText(Path.Combine(instance, "instance-owner.json")))!;
        Assert.Equal(process.Id, marker["pid"]!.GetValue<int>());
        Assert.Equal(process.StartTime.ToUniversalTime().Ticks, marker["process_start_utc_ticks"]!.GetValue<long>());
        Assert.Equal(process.StartTime.ToUniversalTime().Ticks, OwnedOracleInstance.ReadProcessStart(process.Id));
        Assert.Throws<InvalidOperationException>(() => run.Cleanup());
        run.AssertPreserved(instance);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    public void Reused_pid_with_distinct_creation_identity_cleans_only_recorded_run_files(long delta)
    {
        using var run = new Run();
        using var process = Process.GetCurrentProcess();
        string instance = run.Record(process);
        run.Cleanup(pid => { Assert.Equal(process.Id, pid); return process.StartTime.ToUniversalTime().Ticks + delta; });
        run.AssertCleaned(instance);
        Assert.False(process.HasExited); // The different incarnation is never signalled.
        run.Cleanup(_ => null); // Completed cleanup is safe to repeat.
        run.AssertCleaned(instance);
    }

    [Fact]
    public async Task Real_exited_child_allows_cleanup_without_signals()
    {
        using var run = new Run();
        using var child = StartChild();
        string instance;
        try { instance = run.Record(child); }
        finally
        {
            child.StandardInput.Close(); // Child exits voluntarily on EOF; no kill, tree kill or PID signals.
            await child.WaitForExitAsync(CancellationToken.None);
        }
        Assert.Equal(0, child.ExitCode);
        Assert.Null(OwnedOracleInstance.ReadProcessStart(child.Id));
        run.Cleanup();
        run.AssertCleaned(instance);
    }

    [Fact]
    public void Missing_marker_preserves_files_and_never_probes_a_pid()
    {
        using var run = new Run();
        using var process = Process.GetCurrentProcess();
        string instance = run.Record(process);
        File.Delete(Path.Combine(instance, "instance-owner.json"));
        Assert.Throws<FileNotFoundException>(() => run.Cleanup(_ => throw new Exception("Missing marker must not reach process lookup")));
        foreach (string name in new[] { "runtime-password.txt", "ready.json", "ready.tmp", "foreign.keep" })
            Assert.Equal("synthetic-" + name, File.ReadAllText(Path.Combine(instance, name)));
    }

    [Theory]
    [InlineData("permission")]
    [InlineData("identity")]
    [InlineData("io")]
    [InlineData("zero")]
    [InlineData("negative")]
    public void Unknown_identity_preserves_all_files(string failure)
    {
        using var run = new Run();
        using var process = Process.GetCurrentProcess();
        string instance = run.Record(process);
        Assert.Throws<InvalidOperationException>(() => run.Cleanup(_ => failure switch
        {
            "permission" => throw new Win32Exception(5),
            "identity" => throw new InvalidOperationException(),
            "io" => throw new IOException(),
            "zero" => 0,
            _ => -1
        }));
        run.AssertPreserved(instance);
    }

    [Theory]
    [InlineData("json")]
    [InlineData("legacy")]
    [InlineData("run")]
    [InlineData("instance")]
    [InlineData("pid")]
    [InlineData("start")]
    [InlineData("extra")]
    [InlineData("duplicate")]
    public void Corrupt_or_unbound_marker_never_probes_or_deletes(string corruption)
    {
        using var run = new Run();
        using var process = Process.GetCurrentProcess();
        string instance = run.Record(process), path = Path.Combine(instance, "instance-owner.json");
        var marker = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        switch (corruption)
        {
            case "legacy": marker.Remove("process_start_utc_ticks"); break;
            case "run": marker["run_id"] = Guid.NewGuid().ToString("D"); break;
            case "instance": marker["instance_id"] = Guid.NewGuid().ToString("D"); break;
            case "pid": marker["pid"] = true; break;
            case "start": marker["process_start_utc_ticks"] = 0; break;
            case "extra": marker["unexpected"] = 1; break;
        }
        File.WriteAllText(path, corruption == "json" ? "{" : corruption == "duplicate"
            ? marker.ToJsonString().Replace("\"pid\":", "\"pid\":1,\"pid\":") : marker.ToJsonString());
        Assert.Throws<InvalidOperationException>(() => run.Cleanup(_ => throw new Exception("Invalid marker must not reach process lookup")));
        run.AssertPreserved(instance);
    }

    [Fact]
    public void Live_sibling_is_checked_before_any_instance_is_cleaned()
    {
        using var run = new Run();
        using var process = Process.GetCurrentProcess();
        string first = run.Record(process), second = run.Record(process);
        int calls = 0;
        Assert.Throws<InvalidOperationException>(() => run.Cleanup(_ => ++calls == 1 ? null : process.StartTime.ToUniversalTime().Ticks));
        run.AssertPreserved(first);
        run.AssertPreserved(second);
    }

    [Fact]
    public void Identity_is_rechecked_before_deletion()
    {
        using var run = new Run();
        using var process = Process.GetCurrentProcess();
        string instance = run.Record(process);
        int calls = 0;
        Assert.Throws<InvalidOperationException>(() => run.Cleanup(_ => ++calls == 1 ? null : throw new UnauthorizedAccessException()));
        run.AssertPreserved(instance);
    }

    [Fact]
    public void Marker_change_after_admission_refuses_deletion()
    {
        using var run = new Run();
        using var process = Process.GetCurrentProcess();
        string instance = run.Record(process);
        Assert.Throws<InvalidOperationException>(() => run.Cleanup(_ =>
        {
            File.WriteAllText(Path.Combine(instance, "instance-owner.json"), "{}");
            return null;
        }));
        run.AssertPreserved(instance);
    }

    [Fact]
    public void Non_file_cleanup_target_preserves_all_files()
    {
        using var run = new Run();
        using var process = Process.GetCurrentProcess();
        string instance = run.Record(process), target = Path.Combine(instance, "ready.tmp");
        File.Delete(target);
        Directory.CreateDirectory(target);
        Assert.Throws<InvalidOperationException>(() => run.Cleanup(_ => null));
        Assert.True(File.Exists(Path.Combine(instance, "runtime-password.txt")));
        Assert.True(File.Exists(Path.Combine(instance, "ready.json")));
        Assert.True(Directory.Exists(target));
    }

    private static Process StartChild()
    {
        string executable = OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell/v1.0/powershell.exe") : "/bin/sh";
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden, RedirectStandardInput = true };
        foreach (string arg in OperatingSystem.IsWindows()
            ? new[] { "-NoProfile", "-NonInteractive", "-Command", "[void][Console]::In.ReadToEnd()" }
            : new[] { "-c", "cat >/dev/null" }) start.ArgumentList.Add(arg);
        return Process.Start(start) ?? throw new InvalidOperationException("Cannot start owned test child");
    }

    private sealed class Run : IDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), "sli-oracle-" + Guid.NewGuid().ToString("N"));
        private readonly Guid runId = Guid.NewGuid();
        private readonly string side;
        internal Run()
        {
            side = Path.Combine(root, runId.ToString("D"), "dotnet");
            Directory.CreateDirectory(side);
            File.WriteAllText(Path.Combine(side, "foreign.keep"), "preserve");
        }
        internal string Record(Process process)
        {
            string instance = OwnedOracleInstance.Record(root, runId, "dotnet", Guid.NewGuid(), process);
            foreach (string name in new[] { "runtime-password.txt", "ready.json", "ready.tmp", "foreign.keep" })
                File.WriteAllText(Path.Combine(instance, name), "synthetic-" + name);
            return instance;
        }
        internal void Cleanup(Func<int, long?>? read = null) => OwnedOracleInstance.CleanupStopped(root, runId, "dotnet", read);
        internal void AssertPreserved(string instance)
        {
            foreach (string name in new[] { "runtime-password.txt", "ready.json", "ready.tmp" })
                Assert.Equal("synthetic-" + name, File.ReadAllText(Path.Combine(instance, name)));
            AssertForeignPreserved(instance);
        }
        internal void AssertCleaned(string instance)
        {
            foreach (string name in new[] { "runtime-password.txt", "ready.json", "ready.tmp" }) Assert.False(File.Exists(Path.Combine(instance, name)));
            AssertForeignPreserved(instance);
        }
        private void AssertForeignPreserved(string instance)
        {
            Assert.True(File.Exists(Path.Combine(instance, "instance-owner.json")));
            Assert.Equal("synthetic-foreign.keep", File.ReadAllText(Path.Combine(instance, "foreign.keep")));
            Assert.Equal("preserve", File.ReadAllText(Path.Combine(side, "foreign.keep")));
        }
        public void Dispose()
        {
            string path = Path.GetFullPath(root);
            if (!path.StartsWith(Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath())) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                || !Path.GetFileName(path).StartsWith("sli-oracle-", StringComparison.Ordinal)) throw new InvalidOperationException("Unexpected test root");
            Directory.Delete(path, recursive: true);
        }
    }
}
