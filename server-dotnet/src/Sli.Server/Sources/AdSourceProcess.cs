using System.ComponentModel;
using System.Diagnostics;

namespace Sli.Server.Sources;

public sealed record AdSourceProcessResult(IReadOnlyList<string> Command, int ReturnCode, string Stdout, string Stderr);

public sealed class AdSourceProcess
{
    private readonly Func<string, string> resolveEndpoint;
    private readonly Func<string, AdSourceLogin> loadCredentials;
    private readonly Func<IReadOnlyList<string>, AdSourceLogin, string, CancellationToken, Func<Task>?, Task<AdSourceProcessResult>> netonly;
    private readonly Func<IReadOnlyList<string>, string, CancellationToken, Func<Task>?, Task<AdSourceProcessResult>> process;

    public AdSourceProcess(Func<string, string> resolveEndpoint, Func<string, AdSourceLogin> loadCredentials)
        : this(resolveEndpoint, loadCredentials, AdSourceNative.RunAsync, RunProcessAsync) { }

    internal AdSourceProcess(Func<string, string> resolveEndpoint, Func<string, AdSourceLogin> loadCredentials,
        Func<IReadOnlyList<string>, AdSourceLogin, string, CancellationToken, Func<Task>?, Task<AdSourceProcessResult>> netonly,
        Func<IReadOnlyList<string>, string, CancellationToken, Func<Task>?, Task<AdSourceProcessResult>> process)
    {
        this.resolveEndpoint = resolveEndpoint; this.loadCredentials = loadCredentials;
        this.netonly = netonly; this.process = process;
    }

    public async Task<AdSourceProcessResult> RunAsync(IReadOnlyList<string> command, string server, string cwd,
        CancellationToken ct, Func<Task>? heartbeat = null)
    {
        // Never read a saved credential for an unadmitted endpoint, and never
        // allow an event-log/VPN profile setting to change the LDAP identity.
        try { if (string.IsNullOrEmpty(resolveEndpoint(server))) throw new ArgumentException(); }
        catch (Exception) { throw new InvalidOperationException("ad_source_endpoint_invalid"); }
        AdSourceLogin credentials;
        try { credentials = loadCredentials("ad"); }
        catch (Exception) { throw new InvalidOperationException("ad_source_credentials_unavailable"); }
        try { return await netonly(command, credentials, cwd, ct, heartbeat); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw new OperationCanceledException(ct); }
        catch (Exception error) { throw SafeError(error); }
    }

    // The coordinator's process mode deliberately does not resolve endpoints or
    // load credentials. Invalid explicit modes cannot fall back to this mode.
    public Task<AdSourceProcessResult> RunCollectorAsync(IReadOnlyList<string> command, string cwd,
        Func<string, string?> environment, CancellationToken ct, Func<Task>? heartbeat = null)
    {
        string mode = environment("ADLOG_AD_SOURCE_CREDENTIAL_MODE") ?? "process";
        return mode switch {
            "process" => process(command, cwd, ct, heartbeat),
            "dpapi_current_user" => RunAsync(command,
                (Nonempty(environment("ADLOG_AD_CONTEXT_DIRECTORY_SERVER"))
                 ?? environment("ADLOG_COLLECTION_PREFLIGHT_SERVER") ?? "").Trim(), cwd, ct, heartbeat),
            _ => throw new InvalidOperationException("ad_source_credential_mode_invalid")
        };
    }

    private static string? Nonempty(string? value) => value is { Length: > 0 } ? value : null;

    internal static InvalidOperationException SafeError(Exception error)
    {
        string code = error.Message is "ad_source_process_output_limit" or "ad_source_process_command_invalid"
            or "ad_source_process_command_too_long" ? error.Message : "ad_source_process_failed";
        if (error is Win32Exception native) code += $" winerror {native.NativeErrorCode}";
        return new InvalidOperationException(code); // No inner exception or native text.
    }

    internal static Dictionary<string, string> SourceEnvironment(Func<string, string?> environment)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string key in new[] { "SystemRoot", "WINDIR", "TEMP", "TMP", "PATH", "PATHEXT",
            "USERPROFILE", "LOCALAPPDATA", "APPDATA", "SystemDrive", "ComSpec" })
            if (environment(key) is { Length: > 0 } value) result[key] = value;
        return result;
    }

    private static async Task<AdSourceProcessResult> RunProcessAsync(IReadOnlyList<string> command, string cwd, CancellationToken ct, Func<Task>? heartbeat)
    {
        if (command.Count == 0) throw new InvalidOperationException("ad_source_process_command_invalid");
        var start = new ProcessStartInfo(command[0]) { WorkingDirectory = cwd, UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string argument in command.Skip(1)) start.ArgumentList.Add(argument);
        using var child = new Process { StartInfo = start };
        child.Start(); child.StandardInput.Close();
        try {
            var stdout = child.StandardOutput.ReadToEndAsync(ct); var stderr = child.StandardError.ReadToEndAsync(ct);
            Task exit = child.WaitForExitAsync(ct);
            var watch = Stopwatch.StartNew(); TimeSpan nextHeartbeat = TimeSpan.Zero;
            while (!exit.IsCompleted) {
                ct.ThrowIfCancellationRequested();
                if (heartbeat is not null && watch.Elapsed >= nextHeartbeat) {
                    await heartbeat(); nextHeartbeat = watch.Elapsed + TimeSpan.FromSeconds(10);
                }
                await Task.WhenAny(exit, Task.Delay(100, ct));
            }
            await exit;
            return new(command.ToArray(), child.ExitCode, await stdout, await stderr);
        }
        finally {
            if (!child.HasExited) child.Kill(entireProcessTree: true);
            await child.WaitForExitAsync(CancellationToken.None);
        }
    }
}
