using System.Diagnostics;
using System.Runtime.CompilerServices;
using Sli.Server.Jobs;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Jobs;

// Parity with tests/sources/test_windows_background_processes.py: no console at
// launch or cleanup boundaries. .NET terminates trees directly, without taskkill.
public sealed class WindowsBackgroundProcessTests
{
    [Theory]
    [InlineData("radius-session-observation", "handler")]
    [InlineData("radius-session-observation", "publisher")]
    [InlineData("ad-context-snapshot", "handler")]
    [InlineData("ad-context-snapshot", "publisher")]
    [InlineData("gpo-snapshot", "handler")]
    [InlineData("gpo-snapshot", "publisher")]
    public void Job_children_are_hidden_for_every_profile_and_purpose(string handler, string purpose)
    {
        var job = CoreJobTests.Job(handler);
        foreach (string executable in new[] { "dotnet", "dotnet.exe", "Sli.Server.exe" })
        {
            var start = CoreJobProcess.StartInfo(job, purpose, _ => "synthetic-file", executable, executable == "Sli.Server.exe");
            AssertHidden(start);
            Assert.Equal(executable, start.FileName);
            Assert.Contains("core-job-executor", start.ArgumentList);
            Assert.Equal(purpose, start.ArgumentList.Last());
        }
    }

    [Theory]
    [InlineData("dotnet")]
    [InlineData("dotnet.exe")]
    [InlineData("Sli.Server.exe")]
    public void Recurring_worker_child_is_hidden(string executable)
    {
        var start = RadiusObservationHost.StartInfo(executable, "synthetic-dsn", _ => null);
        AssertHidden(start);
        Assert.Equal(executable, start.FileName);
        string[] arguments = ["radius-session-observation", "--cycle-child"];
        Assert.Equal(executable == "Sli.Server.exe" ? arguments : new[] { typeof(RadiusObservationHost).Assembly.Location }.Concat(arguments), start.ArgumentList);
        Assert.Equal("synthetic-dsn", start.Environment["SLI_PLUGIN_PG_DSN"]);
    }

    [Theory]
    [InlineData("Install-SLIWorkerSupervisor.ps1")]
    [InlineData("Install-SLIWebServer-v1.ps1")]
    public void Background_tasks_install_hidden_noninteractive_powershell(string name)
    {
        string script = File.ReadAllText(Path.Combine(RepositoryRoot(), "scripts", "ops", name));
        Assert.Contains("-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File", script);
    }

    [Fact]
    public async Task Cleanup_terminates_child_and_descendant_without_a_console_command()
    {
        // An inherited stdout pipe stays open if the descendant survives tree cleanup.
        var start = new ProcessStartInfo(OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe")
            : "/bin/sh") {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        if (OperatingSystem.IsWindows())
        {
            start.ArgumentList.Add("-NoProfile"); start.ArgumentList.Add("-NonInteractive"); start.ArgumentList.Add("-Command");
            start.ArgumentList.Add("$s = [System.Diagnostics.ProcessStartInfo]::new((Join-Path $PSHOME 'powershell.exe')); " +
                "$s.UseShellExecute = $false; $s.CreateNoWindow = $true; $s.RedirectStandardInput = $true; " +
                "$s.Arguments = '-NoProfile -NonInteractive -Command [Console]::In.ReadToEnd()'; " +
                "$child = [System.Diagnostics.Process]::Start($s); [Console]::Out.WriteLine($child.Id); " +
                "[void][Console]::In.ReadToEnd(); $child.WaitForExit()");
        }
        else
        {
            start.ArgumentList.Add("-c");
            start.ArgumentList.Add("sleep 300 & child=$!; printf '%s\\n' \"$child\"; wait \"$child\"");
        }
        using var process = Process.Start(start)!;
        Process? descendant = null;
        try
        {
            string? line = await process.StandardOutput.ReadLineAsync(TestContext.Current.CancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(15), TestContext.Current.CancellationToken);
            Assert.True(int.TryParse(line, out int pid), line);
            descendant = Process.GetProcessById(pid);
            Assert.False(descendant.HasExited);
            CoreJobProcess.KillGroup(process);
            await process.WaitForExitAsync(TestContext.Current.CancellationToken).WaitAsync(TimeSpan.FromSeconds(15), TestContext.Current.CancellationToken);
            Assert.Equal("", await process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken).WaitAsync(TimeSpan.FromSeconds(15), TestContext.Current.CancellationToken));
            Assert.Equal("", await process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken).WaitAsync(TimeSpan.FromSeconds(15), TestContext.Current.CancellationToken));
        }
        finally
        {
            // Only disposable processes created above are eligible for cleanup.
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            if (descendant is not null)
            {
                if (!descendant.HasExited) descendant.Kill(entireProcessTree: true);
                descendant.Dispose();
            }
            await process.WaitForExitAsync(CancellationToken.None);
        }
    }

    private static void AssertHidden(ProcessStartInfo start)
    {
        Assert.True(start.CreateNoWindow);
        Assert.False(start.UseShellExecute); // Shell execution ignores CreateNoWindow.
        Assert.True(start.RedirectStandardInput);
        Assert.True(start.RedirectStandardOutput);
        Assert.True(start.RedirectStandardError);
    }

    private static string RepositoryRoot([CallerFilePath] string path = "") =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(path)!, "../../../.."));
}
