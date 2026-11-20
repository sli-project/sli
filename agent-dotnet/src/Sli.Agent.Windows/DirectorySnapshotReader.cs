using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Agent.Windows;

/// <summary>Service-identity AD/SYSVOL read boundary; portable tests replace the entire source.</summary>
public interface IDirectorySnapshotReader
{
    Task<JsonObject> ReadAsync(SnapshotPolicy policy, CancellationToken cancellationToken);
}

/// <summary>Ships the reference ADSI collectors inside the assembly; no Python, credentials or RSAT installation.</summary>
public sealed class DirectorySnapshotReader : IDirectorySnapshotReader
{
    internal static string Resource(string name)
    {
        using var stream = typeof(DirectorySnapshotReader).Assembly.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    public static JsonObject Request(SnapshotPolicy policy)
    {
        var script = Resource(policy.ModuleId == SnapshotPolicy.Ad ? "ad_snapshot.ps1" : "gpo_snapshot.ps1");
        // Load the shared GPO parser as an in-memory module. The embedded collector never needs a checkout path.
        const string import = "Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts/ad_context/GpoReportContract.psm1') -Force -ErrorAction Stop";
        if (policy.ModuleId == SnapshotPolicy.Gpo)
        {
            if (!script.Contains(import, StringComparison.Ordinal)) throw new AgentException("agent_snapshot_resource_invalid");
            script = script.Replace(import, "", StringComparison.Ordinal);
        }
        var config = (JsonObject)policy.Config.DeepClone();
        if (policy.ModuleId == SnapshotPolicy.Ad) config["ldap_attributes"] = JsonNode.Parse(Resource("ad-schema.json"))!["ldap_attributes"]!.DeepClone();
        return new JsonObject { ["policy"] = config, ["collector"] = script,
            ["contract"] = policy.ModuleId == SnapshotPolicy.Gpo ? Resource("GpoReportContract.psm1") +
                "\nExport-ModuleMember -Function ConvertTo-SLIGpoV2Settings,ConvertFrom-SLIGpoReportXml,ConvertFrom-SLIGpoPermissionObjects,Merge-SLIGpoGovernanceAttributes" : null };
    }

    public async Task<JsonObject> ReadAsync(SnapshotPolicy policy, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) throw new AgentException("agent_snapshot_reader_unavailable");
        const string bootstrap = """
            $ErrorActionPreference = 'Stop'
            [Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
            [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
            $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
            if ($request.contract) { Import-Module (New-Module -ScriptBlock ([ScriptBlock]::Create($request.contract))) -Force }
            [Console]::SetIn([IO.StringReader]::new(($request.policy | ConvertTo-Json -Depth 100 -Compress)))
            & ([ScriptBlock]::Create($request.collector))
            """;
        using var process = new Process { StartInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardInputEncoding = new UTF8Encoding(false), StandardOutputEncoding = new UTF8Encoding(false)
        } };
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(bootstrap)) }) process.StartInfo.ArgumentList.Add(arg);
        var prefix = policy.ModuleId == SnapshotPolicy.Ad ? "agent_ad" : "agent_gpo";
        try
        {
            if (!process.Start()) throw new AgentException(prefix + "_capture_failed");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(policy.Number("capture_seconds")));
            using var registration = timeout.Token.Register(() => { try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { } });
            var errors = process.StandardError.BaseStream.CopyToAsync(Stream.Null, timeout.Token);
            var output = ReadBoundedAsync(process.StandardOutput.BaseStream, timeout.Token);
            await process.StandardInput.WriteAsync(Request(policy).ToJsonString().AsMemory(), timeout.Token).ConfigureAwait(false);
            process.StandardInput.Close();
            var bytes = await output.ConfigureAwait(false);
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            await errors.ConfigureAwait(false);
            if (process.ExitCode != 0) throw new AgentException(prefix + "_capture_failed");
            timeout.Token.ThrowIfCancellationRequested();
            return JsonNode.Parse(Encoding.UTF8.GetString(bytes).TrimStart('\uFEFF'))!.AsObject();
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { throw new AgentException(prefix + "_capture_cancelled"); }
        catch (Exception e) when (e is IOException or System.ComponentModel.Win32Exception or System.Text.Json.JsonException or InvalidOperationException)
        { throw new AgentException(prefix + "_capture_failed"); }
        finally
        {
            try { if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false); } }
            catch (InvalidOperationException) { }
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var output = new MemoryStream(); var buffer = new byte[65536];
        while (true)
        {
            var count = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (count == 0) break;
            if (output.Length + count > 64 * 1024 * 1024) throw new AgentException("agent_snapshot_size_limit");
            output.Write(buffer, 0, count);
        }
        return output.ToArray();
    }
}
