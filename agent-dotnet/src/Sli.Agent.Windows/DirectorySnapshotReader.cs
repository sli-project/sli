using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Win32;
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
        return new JsonObject { ["policy"] = config, ["collector"] = script, ["local_dc"] = null, ["local_sysvol"] = null,
            ["contract"] = policy.ModuleId == SnapshotPolicy.Gpo ? Resource("GpoReportContract.psm1") +
                "\nExport-ModuleMember -Function ConvertTo-SLIGpoV2Settings,ConvertFrom-SLIGpoReportXml,ConvertFrom-SLIGpoPermissionObjects,Merge-SLIGpoGovernanceAttributes" : null };
    }

    public async Task<JsonObject> ReadAsync(SnapshotPolicy policy, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) throw new AgentException("agent_snapshot_reader_unavailable");
        var request = Request(policy);
        try
        {
            // Netlogon publishes the SYSVOL share root when this machine is a DC.
            // Honor a policy-selected DC and let the collector verify the domain SID and naming context.
            var sysvol = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters", "SysVol", null) as string;
            if (sysvol is { Length: > 3 } && sysvol[1] == ':' && Path.IsPathFullyQualified(sysvol))
            {
                var local = IPGlobalProperties.GetIPGlobalProperties();
                var domain = policy.Config["domain_dns"]!.GetValue<string>();
                var pinned = policy.Config["dc"]!.AsArray().FirstOrDefault()?.GetValue<string>();
                var fqdn = $"{local.HostName}.{local.DomainName}";
                if (string.Equals(pinned, fqdn, StringComparison.OrdinalIgnoreCase)
                    || pinned is null && string.Equals(local.DomainName, domain, StringComparison.OrdinalIgnoreCase))
                {
                    request["local_dc"] = fqdn;
                    request["local_sysvol"] = sysvol;
                }
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.Security.SecurityException or NetworkInformationException)
        {
            // The existing policy endpoint remains usable if local discovery is unavailable.
        }
        return await RunCollectorAsync(policy.ModuleId, request, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<JsonObject> RunCollectorAsync(string module, JsonObject input, CancellationToken cancellationToken)
    {
        const string bootstrap = """
            $ErrorActionPreference = 'Stop'
            $ProgressPreference = 'SilentlyContinue'
            [Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
            [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
            $captureStage = 'setup'
            try {
                $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
                $parameters = @{ Policy = $request.policy; LocalDc = $request.local_dc }
                if ($request.contract) {
                    Import-Module (New-Module -ScriptBlock ([ScriptBlock]::Create($request.contract))) -Force
                    $parameters.LocalSysvol = $request.local_sysvol
                }
                # Keep collector variables and its script-scoped helpers in the same scope.
                . ([ScriptBlock]::Create($request.collector)) @parameters
            } catch {
                $failure = $_.Exception
                while ($null -ne $failure.InnerException) { $failure = $failure.InnerException }
                $nativeError = $null
                if ($failure.GetType().FullName -eq 'System.DirectoryServices.DirectoryServicesCOMException' -and $failure.ExtendedError -ne 0) {
                    $nativeError = $failure.ExtendedError
                } elseif ($failure -is [ComponentModel.Win32Exception]) {
                    $nativeError = $failure.NativeErrorCode
                }
                @{ capture_error = @{
                    stage = $captureStage; exception_class = $failure.GetType().Name
                    hresult = $failure.HResult; native_error = $nativeError
                } } | ConvertTo-Json -Depth 3 -Compress
            }
            """;
        using var process = new Process { StartInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardInputEncoding = new UTF8Encoding(false), StandardOutputEncoding = new UTF8Encoding(false)
        } };
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(bootstrap)) }) process.StartInfo.ArgumentList.Add(arg);
        var stage = "start";
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!process.Start()) throw SnapshotCaptureException.Describe(module, stage);
            stage = "process";
            using var registration = cancellationToken.Register(() => { try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { } });
            var errors = process.StandardError.BaseStream.CopyToAsync(Stream.Null, cancellationToken);
            var output = ReadBoundedAsync(process.StandardOutput.BaseStream, cancellationToken);
            await process.StandardInput.WriteAsync(input.ToJsonString().AsMemory(), cancellationToken).ConfigureAwait(false);
            process.StandardInput.Close();
            var bytes = await output.ConfigureAwait(false);
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            await errors.ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (process.ExitCode != 0) throw SnapshotCaptureException.Describe(module, stage);
            stage = "decode";
            if (JsonNode.Parse(Encoding.UTF8.GetString(bytes).TrimStart('\uFEFF')) is not JsonObject result)
                throw SnapshotCaptureException.Describe(module, stage);
            if (result.TryGetPropertyValue("capture_error", out var diagnostic))
                throw SnapshotCaptureException.FromCollector(module, diagnostic);
            return result;
        }
        catch (Exception e) when (e is IOException or System.ComponentModel.Win32Exception or System.Text.Json.JsonException or InvalidOperationException or AgentException and not SnapshotCaptureException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw SnapshotCaptureException.Describe(module, e is AgentException { Code: "agent_snapshot_size_limit" } ? "size" : stage, e);
        }
        finally
        {
            try { if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false); } }
            catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { }
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
