using System.Diagnostics;
using System.Text.Json.Nodes;
using Sli.Server.Jobs;
using Xunit;

namespace Sli.Server.Tests.Jobs;

public class CoreJobPersistentProcessTests
{
    [Theory]
    [InlineData("handler")]
    [InlineData("publisher")]
    public async Task Real_child_protocol_handles_multiple_invalid_jobs_without_credentials(string purpose)
    {
        var job = CoreJobTests.Job("workstations.overview-project"); job["input_sha256"] = "tampered";
        string secretName = CoreJobIdentity.PasswordName("light", purpose == "handler" ? "executor" : "publisher") + "_FILE";
        var start = CoreJobProcess.StartInfo(job, purpose, key => key == secretName ? "synthetic-unused" : Environment.GetEnvironmentVariable(key),
            Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet", false);
        start.ArgumentList.Add("--persistent");
        using var process = Process.Start(start)!;
        var errors = process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        try
        {
            for (int i = 0; i < 2; i++)
            {
                await process.StandardInput.WriteLineAsync(job.ToJsonString());
                await process.StandardInput.FlushAsync(TestContext.Current.CancellationToken);
                var bytes = await CoreJobProcess.ReadFrame(process.StandardOutput.BaseStream, 65536, TestContext.Current.CancellationToken);
                Assert.Equal("permanent_error", JsonNode.Parse(bytes)!.Text("status"));
                Assert.False(process.HasExited);
            }
            process.StandardInput.Close();
            await process.WaitForExitAsync(TestContext.Current.CancellationToken);
            Assert.Equal(0, process.ExitCode);
            Assert.Equal("", await errors);
        }
        finally { CoreJobProcess.KillGroup(process); }
    }

    [Fact]
    public async Task Serial_jobs_reuse_separate_handler_and_publisher_processes()
    {
        var job = CoreJobTests.Job();
        await using var children = new CoreJobProcess.Persistent((_, purpose) => Probe(purpose));
        int? handler = null, publisher = null;
        for (int i = 0; i < 4; i++)
        {
            var staged = await children.RunAsync(job, "handler", TimeSpan.Zero, null, TestContext.Current.CancellationToken);
            var published = await children.RunAsync(job, "publisher", TimeSpan.Zero, null, TestContext.Current.CancellationToken);
            int nextHandler = staged["pid"]!.GetValue<int>(), nextPublisher = published["pid"]!.GetValue<int>();
            handler ??= nextHandler; publisher ??= nextPublisher;
            Assert.Equal(handler, nextHandler); Assert.Equal(publisher, nextPublisher);
            Assert.Equal("success", staged.Text("status")); Assert.Equal("committed", published.Text("status"));
        }
        Assert.NotEqual(handler, publisher);
    }

    [Fact]
    public async Task Changed_budget_or_handler_restarts_instead_of_reusing_an_incompatible_sandbox()
    {
        var pids = new HashSet<int>();
        await using var children = new CoreJobProcess.Persistent((_, purpose) => Probe(purpose));
        var job = CoreJobTests.Job();
        pids.Add((await children.RunAsync(job, "handler", TimeSpan.Zero, null, TestContext.Current.CancellationToken))["pid"]!.GetValue<int>());
        job["budget"]!["memory_bytes"] = 268435455L;
        pids.Add((await children.RunAsync(job, "handler", TimeSpan.Zero, null, TestContext.Current.CancellationToken))["pid"]!.GetValue<int>());
        job["handler_id"] = "radius-acquisition";
        pids.Add((await children.RunAsync(job, "handler", TimeSpan.Zero, null, TestContext.Current.CancellationToken))["pid"]!.GetValue<int>());
        Assert.Equal(3, pids.Count);
    }

    [Theory]
    [InlineData("oversized", "job_result_budget_exceeded")]
    [InlineData("invalid", "job_result_invalid")]
    [InlineData("memory", "job_child_memory_exceeded")]
    public async Task Broken_response_or_memory_budget_kills_child_and_next_request_starts_clean(string mode, string expected)
    {
        int starts = 0;
        await using var children = new CoreJobProcess.Persistent((_, purpose) => Probe(purpose, starts++ == 0 ? mode : "success"));
        var job = CoreJobTests.Job();
        // Only the memory case should trip the watchdog. The protocol cases exercise frame validation.
        job["budget"]!["memory_bytes"] = mode == "memory" ? 1L : long.MaxValue;
        var error = await Assert.ThrowsAnyAsync<Exception>(() => children.RunAsync(job, "handler", TimeSpan.Zero, null, TestContext.Current.CancellationToken));
        Assert.Equal(expected, error.Message);
        job["budget"]!["memory_bytes"] = long.MaxValue;
        Assert.Equal("success", (await children.RunAsync(job, "handler", TimeSpan.Zero, null, TestContext.Current.CancellationToken)).Text("status"));
        Assert.Equal(2, starts);
    }

    private static ProcessStartInfo Probe(string purpose, string mode = "success")
    {
        var start = new ProcessStartInfo(OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe") : "/bin/sh")
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        string status = purpose == "handler" ? "success" : "committed";
        if (OperatingSystem.IsWindows())
        {
            start.ArgumentList.Add("-NoProfile"); start.ArgumentList.Add("-NonInteractive"); start.ArgumentList.Add("-Command");
            start.ArgumentList.Add("while ($null -ne ($line = [Console]::In.ReadLine())) { "
                + (mode == "memory" ? "Start-Sleep -Seconds 30; " : "")
                + (mode == "oversized" ? "[Console]::Out.WriteLine('1000000'); [Console]::Out.Flush(); " :
                    "$reply = " + (mode == "invalid" ? "'[]'" : "'{\"status\":\"" + status + "\",\"pid\":' + $PID + '}'")
                    + "; [Console]::Out.WriteLine($reply.Length); "
                    + "[Console]::Out.WriteLine($reply); [Console]::Out.Flush(); ") + "}");
        }
        else
        {
            start.ArgumentList.Add("-c");
            start.ArgumentList.Add("while IFS= read -r line; do " + (mode == "memory" ? "sleep 30; " : "")
                + (mode == "oversized" ? "printf '1000000\\n'; " : "reply=" + (mode == "invalid" ? "'[]'" : "'{\"status\":\"" + status + "\",\"pid\":'$$'}'")
                    + "; printf '%s\\n%s\\n' \"${#reply}\" \"$reply\"; ") + "done");
        }
        return start;
    }
}
