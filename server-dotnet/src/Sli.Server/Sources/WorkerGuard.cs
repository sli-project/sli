using System.Diagnostics;
using System.Globalization;

namespace Sli.Server.Sources;

internal sealed record WorkerProcessInventory(IReadOnlyList<int> Pids, string? Error)
{
    // A different live worker also forbids restart, even if the recorded PID disappeared.
    internal bool RecordedWorkerIsConfirmedGone(int? recordedPid) =>
        Error is null && recordedPid is > 0 && Pids.Count == 0;
}

internal sealed record WorkerProcessOutput(int ExitCode, string StandardOutput, string StandardError);

internal static class WorkerGuard
{
    internal static async Task<WorkerProcessInventory> RunningPidsForAsync(string scriptName, CancellationToken ct,
        Func<ProcessStartInfo, CancellationToken, Task<WorkerProcessOutput>>? run = null,
        bool? windows = null, int? currentPid = null)
    {
        if (!(windows ?? OperatingSystem.IsWindows())) return new([], null);
        // Script names are data, never PowerShell expressions or wildcard patterns.
        if (scriptName.Length == 0 || scriptName.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '_' and not '.' and not '-'))
            throw new ArgumentException("worker_script_name_invalid", nameof(scriptName));
        var start = new ProcessStartInfo("powershell") { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference='Stop'; Get-CimInstance Win32_Process | " +
            "Where-Object { $_.Name -like 'python*' } | " +
            "Where-Object { $_.CommandLine -like '*\\" + scriptName + "*' } | ForEach-Object { $_.ProcessId }" })
            start.ArgumentList.Add(arg);
        WorkerProcessOutput output;
        try { output = await (run ?? RunAsync)(start, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception error) { return new([], "process_inventory_failed:" + error.GetType().Name); }
        if (output.ExitCode != 0)
        {
            string detail = (string.IsNullOrEmpty(output.StandardError) ? output.StandardOutput : output.StandardError)
                .Trim().Replace('\r', ' ').Replace('\n', ' ');
            return new([], $"process_inventory_failed:exit_{output.ExitCode}:" + detail[..Math.Min(300, detail.Length)]);
        }
        var pids = new List<int>();
        foreach (string line in output.StandardOutput.Split('\n'))
            if (int.TryParse(line.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out int pid)
                && pid != (currentPid ?? Environment.ProcessId)) pids.Add(pid);
        return new(pids, null);
    }

    private static async Task<WorkerProcessOutput> RunAsync(ProcessStartInfo start, CancellationToken ct)
    {
        using var process = new Process { StartInfo = start };
        process.Start();
        var stdout = process.StandardOutput.ReadToEndAsync(ct);
        var stderr = process.StandardError.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct);
        return new(process.ExitCode, await stdout, await stderr);
    }
}
