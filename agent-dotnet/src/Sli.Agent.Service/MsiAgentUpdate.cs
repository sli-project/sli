using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Agent.Service;

internal sealed class MsiAgentUpdate(string stateDirectory, IDurableFiles files, TimeProvider clock)
{
    internal const string PackageName = "SliAgent.msi";
    private static readonly Version Running = new(typeof(MsiAgentUpdate).Assembly.GetName().Version!.ToString(3));
    private readonly string _directory = Path.Combine(stateDirectory, "update");
    private sealed record Attempt(string Hash, string Version, int Count, DateTimeOffset NextAttempt, string? Id,
        string? Reason, bool ReportPending);

    internal async Task CheckAsync(JsonObject? offer, AgentHttpClient http, CancellationToken ct)
    {
        string journal = Path.Combine(_directory, "attempt.json");
        Attempt? attempt = files.ReadAll(journal) is { } saved ? JsonSerializer.Deserialize<Attempt>(saved) : null;
        var now = clock.GetUtcNow();
        if (attempt?.Id is { } id)
        {
            if (!Guid.TryParseExact(id, "N", out _))
                throw new AgentException("agent_update_stage_failed");
            if (InstallerRunning())
                return;
            var packagePath = PackagePath(id);
            var resultPath = Path.ChangeExtension(packagePath, ".result");
            if (Running.ToString(3) == attempt.Version)
            {
                await ReportAsync(http, attempt.Hash, "updated", null, ct).ConfigureAwait(false);
                // The installed product can repair from this package. Only
                // discard prior sources after the new service is running.
                foreach (var directory in Directory.EnumerateDirectories(_directory))
                {
                    var previousId = Path.GetFileName(directory);
                    if (previousId != id && Guid.TryParseExact(previousId, "N", out _))
                        RemoveSource(PackagePath(previousId));
                }
                files.Delete(resultPath);
                files.Delete(journal);
                return;
            }
            var result = files.ReadAll(resultPath);
            if (now < attempt.NextAttempt && (result is null || result.AsSpan().SequenceEqual("success"u8)))
                return;
            string reason = result is not null && result.AsSpan().SequenceEqual("verification_failed"u8)
                ? "agent_update_verification_failed" : "agent_update_start_failed";
            attempt = Failed(attempt, reason, clock.GetUtcNow());
            Save(attempt);
            RemoveSource(packagePath);
        }

        if (attempt is { ReportPending: true })
        {
            await ReportAsync(http, attempt.Hash, "rejected", attempt.Reason, ct).ConfigureAwait(false);
            attempt = attempt with { ReportPending = false };
            Save(attempt);
        }
        if (offer is null || !JsonRead.TryString(offer["sha256"], out var hash) ||
            hash.Length != 64 || hash.Any(c => c is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
            return;
        if (!JsonRead.TryString(offer["format"], out var format) || format != "msi")
        {
            await ReportAsync(http, hash, "rejected", "agent_update_msi_required", ct).ConfigureAwait(false);
            return;
        }
        if (!JsonRead.TryString(offer["version"], out var version) || !Version.TryParse(version, out var target) ||
            target.Major > 255 || target.Minor > 255 || target.Build is < 0 or > 65535 || target.Revision != -1 ||
            target <= Running)
            return;
        if (attempt?.Hash == hash && now < attempt.NextAttempt)
            return;

        string attemptId = Guid.NewGuid().ToString("N");
        string path = PackagePath(attemptId);
        var previous = attempt;
        attempt = new(hash, target.ToString(3), attempt?.Hash == hash ? Math.Min(attempt.Count + 1, 5) : 1,
            now, null, null, false);
        try
        {
            // Own the staged file before writing it so a restart can clean
            // up an interrupted download as well as an interrupted install.
            Save(attempt with { Id = attemptId, NextAttempt = now.AddMinutes(5) });
            files.EnsureDirectory(Path.GetDirectoryName(path)!);
            await using (var package = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, useAsync: true))
            {
                await http.DownloadMsiAsync(hash, package, ct).ConfigureAwait(false);
                package.Flush(flushToDisk: true);
            }
            if (!OperatingSystem.IsWindows())
                throw new AgentException("agent_update_incompatible_platform");
            // Persist before handing off. Windows Installer stops this service
            // during the major upgrade, so completion is observed on restart.
            Save(attempt with { Id = attemptId, NextAttempt = clock.GetUtcNow().AddMinutes(5) });
            using var installer = StartInstaller(path, hash);
        }
        catch (Exception error) when (error is AgentException or IOException or UnauthorizedAccessException or Win32Exception)
        {
            RemoveSource(path);
            attempt = Failed(attempt, error is AgentException agent ? agent.Code : "agent_update_stage_failed", clock.GetUtcNow());
            Save(attempt);
            await ReportAsync(http, hash, "rejected", attempt.Reason, ct).ConfigureAwait(false);
            Save(attempt with { ReportPending = false });
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            RemoveSource(path);
            if (previous is null) files.Delete(journal);
            else Save(previous);
            throw;
        }

        void Save(Attempt value) => files.WriteAtomic(journal, JsonSerializer.SerializeToUtf8Bytes(value));
    }

    private string PackagePath(string id) => Path.Combine(_directory, id, PackageName);

    private void RemoveSource(string path)
    {
        var directory = Path.GetDirectoryName(path)!;
        if (!Directory.Exists(directory) || new DirectoryInfo(directory).LinkTarget is not null)
            return;
        var result = Path.ChangeExtension(path, ".result");
        files.Delete(path);
        files.Delete(result);
        files.Delete(result + ".tmp");
        if (!Directory.EnumerateFileSystemEntries(directory).Any())
            Directory.Delete(directory);
    }

    private static Attempt Failed(Attempt attempt, string reason, DateTimeOffset now) => attempt with
    {
        Id = null,
        Reason = reason,
        ReportPending = true,
        NextAttempt = now.AddMinutes(Math.Min(15, 1 << (attempt.Count - 1))),
    };

    private static async Task ReportAsync(AgentHttpClient http, string hash, string status, string? reason, CancellationToken ct)
    {
        try
        {
            await http.PostAsync("/api/v1/agent/update-result", new JsonObject
            {
                ["sha256"] = hash, ["status"] = status, ["reason"] = reason, ["version"] = Running.ToString(3)
            }, ct).ConfigureAwait(false);
        }
        catch (TransportException error) when (error.HttpStatus == 404)
        {
            // A restore can remove the assignment history entirely.
        }
    }

    private bool InstallerRunning()
    {
        try
        {
            using var gate = File.Open(Path.Combine(_directory, "installer.lock"), FileMode.OpenOrCreate,
                FileAccess.Write, FileShare.None);
            return false;
        }
        catch (IOException) { return true; }
    }

    [SupportedOSPlatform("windows")]
    internal static Process StartInstaller(string path, string hash)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Environment.SystemDirectory,
        };
        foreach (string arg in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", Installer })
            start.ArgumentList.Add(arg);
        start.Environment["SLI_UPDATE_MSI"] = path;
        start.Environment["SLI_UPDATE_HASH"] = hash;
        return Process.Start(start) ?? throw new AgentException("agent_update_start_failed");
    }

    // The fixed helper survives the SCM stopping the agent. It rechecks the
    // staged bytes, runs the transactional MSI upgrade and restarts the service
    // after rollback if Windows Installer left it stopped.
    private const string Installer = """
        $ErrorActionPreference = 'Stop'
        Import-Module -Name ([IO.Path]::Combine($PSHOME, 'Modules', 'Microsoft.PowerShell.Management'))
        $path = $env:SLI_UPDATE_MSI
        $directory = [IO.Path]::GetDirectoryName($path)
        $updateRoot = [IO.Path]::GetDirectoryName($directory)
        $gate = [IO.File]::Open([IO.Path]::Combine($updateRoot, 'installer.lock'), 'OpenOrCreate', 'Write', 'None')
        $reason = 'failed'
        try {
            $algorithm = [Security.Cryptography.SHA256]::Create()
            try {
                $package = [IO.File]::OpenRead($path)
                try { $digest = [BitConverter]::ToString($algorithm.ComputeHash($package)).Replace('-', '') }
                finally { $package.Dispose() }
            } finally { $algorithm.Dispose() }
            if ($digest -ine $env:SLI_UPDATE_HASH) {
                $reason = 'verification_failed'
            } else {
                $installer = [IO.Path]::Combine([Environment]::SystemDirectory, 'msiexec.exe')
                $arguments = '/i "' + $path + '" /qn /norestart'
                $result = Start-Process -FilePath $installer -ArgumentList $arguments -NoNewWindow -Wait -PassThru
                if ($result.ExitCode -in 0, 3010) { $reason = 'success' }
            }
        } finally {
            try {
                $service = Get-Service -Name 'SLIAgentNet'
                if ($service.Status -eq 'Stopped') { Start-Service -InputObject $service }
            } finally {
                $resultPath = [IO.Path]::ChangeExtension($path, '.result')
                [IO.File]::WriteAllText($resultPath + '.tmp', $reason)
                [IO.File]::Move($resultPath + '.tmp', $resultPath)
                # Windows Installer records this source path for maintenance.
                if ($reason -ne 'success') { [IO.File]::Delete($path) }
                $gate.Dispose()
            }
        }
        """;
}
