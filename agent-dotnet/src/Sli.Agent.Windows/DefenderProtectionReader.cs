using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Core;

namespace Sli.Agent.Windows;

/// <summary>Fixed local read-only Defender query; no server text, file execution or diagnostic output in packets.</summary>
public static class DefenderProtectionReader
{
    private const int OutputLimit = 4096;
    private const string Query = "$ErrorActionPreference='Stop'; $s=Get-MpComputerStatus; [ordered]@{"
        + "antivirus_enabled=$s.AntivirusEnabled;real_time_protection_enabled=$s.RealTimeProtectionEnabled;"
        + "behavior_monitor_enabled=$s.BehaviorMonitorEnabled;ioav_protection_enabled=$s.IoavProtectionEnabled;"
        + "nis_enabled=$s.NISEnabled;tamper_protected=$s.IsTamperProtected} | ConvertTo-Json -Compress";

    [SupportedOSPlatform("windows")]
    public static JsonObject Read() => ReadAsync().GetAwaiter().GetResult();

    [SupportedOSPlatform("windows")]
    private static async Task<JsonObject> ReadAsync()
    {
        // Resolve the trusted Windows component rather than PATH/current-directory powershell.exe.
        var executable = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        using var process = new Process { StartInfo = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
        } };
        foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-Command", Query })
            process.StartInfo.ArgumentList.Add(argument);
        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var started = false;
        try
        {
            started = process.Start();
            if (!started) return ProtectionSnapshot.Unavailable();
            var output = ReadBounded(process.StandardOutput, budget.Token);
            var errors = ReadBounded(process.StandardError, budget.Token);
            await Task.WhenAll(output, errors, process.WaitForExitAsync(budget.Token)).WaitAsync(budget.Token).ConfigureAwait(false);
            return ProtectionSnapshot.FromDefenderOutput(process.ExitCode, await output.ConfigureAwait(false));
        }
        catch (Exception exception) when (exception is Win32Exception or IOException or UnauthorizedAccessException
            or InvalidOperationException or OperationCanceledException)
        {
            return ProtectionSnapshot.Unavailable();
        }
        finally
        {
            budget.Cancel();
            if (started)
            {
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
                catch (Exception exception) when (exception is Win32Exception or InvalidOperationException or NotSupportedException) { }
            }
        }
    }

    private static async Task<string> ReadBounded(StreamReader reader, CancellationToken cancellationToken)
    {
        var text = new StringBuilder();
        var buffer = new char[256];
        while (true)
        {
            var count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (count == 0) return text.ToString();
            if (text.Length + count > OutputLimit) throw new IOException("agent_workstations_protection_output_limit");
            text.Append(buffer, 0, count);
        }
    }
}
