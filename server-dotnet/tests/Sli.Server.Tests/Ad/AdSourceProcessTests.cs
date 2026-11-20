using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json.Nodes;
using Sli.Server.Sources;
using Xunit;

namespace Sli.Server.Tests.Ad;

public sealed class AdSourceProcessTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly string Cwd = Path.GetFullPath(".");
    private static readonly string Powershell = OperatingSystem.IsWindows()
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe")
        : "/synthetic/powershell.exe";
    private static AdSourceLogin Credentials(string profile) => new(profile + "@example.test", "synthetic-password");
    private static Task<AdSourceProcessResult> NoFallback(IReadOnlyList<string> command, string cwd, CancellationToken ct, Func<Task>? heartbeat)
        => throw new InvalidOperationException("implicit process fallback");

    [Fact]
    public async Task EventlogVpnProfileDoesNotChangeLdapProcessLogin()
    {
        var calls = new List<string>(); string[] command = ["powershell.exe", "-NoProfile"];
        var source = new AdSourceProcess(server => { calls.Add(server); return "dc.example.test"; },
            profile => { calls.Add(profile); return Credentials(profile); }, (args, login, cwd, ct, beat) => {
                Assert.Equal("ad@example.test", login.Username); Assert.Equal("synthetic-password", login.Password);
                Assert.Equal(command, args); Assert.Equal(Cwd, cwd); Assert.Equal(Ct, ct);
                return Task.FromResult(new AdSourceProcessResult(args, 0, "netonly-output", ""));
            }, NoFallback);
        string? Environment(string key) => key switch {
            "ADLOG_AD_SOURCE_CREDENTIAL_MODE" => "dpapi_current_user",
            "ADLOG_AD_CONTEXT_DIRECTORY_SERVER" => "DC",
            "ADLOG_AD_EVENTLOG_CREDENTIAL_PROFILE" => "vpn", _ => null
        };
        var result = await source.RunCollectorAsync(command, Cwd, Environment, Ct);
        Assert.Equal(0, result.ReturnCode); Assert.Equal("netonly-output", result.Stdout);
        Assert.Equal(new[] { "DC", "ad" }, calls);
    }

    [Fact]
    public void EnvironmentExcludesHostModuleResolutionAndDatabaseSecrets()
    {
        string? Environment(string key) => key switch {
            "PSModulePath" => "host-powershell7-modules", "ADLOG_PG_DSN" => "pg-secret-sentinel",
            "ADLOG_PG_ADMIN_PASSWORD" => "admin-secret-sentinel", "TEMP" => "", "TMP" => null,
            _ => "synthetic-" + key
        };
        var env = AdSourceProcess.SourceEnvironment(Environment);
        Assert.Equal(new[] { "APPDATA", "ComSpec", "LOCALAPPDATA", "PATH", "PATHEXT", "SystemDrive", "SystemRoot", "USERPROFILE", "WINDIR" }, env.Keys.Order(StringComparer.Ordinal).ToArray());
        Assert.Equal("synthetic-SystemRoot", env["SystemRoot"]);
        Assert.DoesNotContain(env.Values, value => value.Contains("sentinel"));
    }

    [Fact]
    public async Task EndpointRefusalPrecedesCredentialLoadingAndLaunch()
    {
        var source = new AdSourceProcess(_ => throw new Exception("private endpoint detail"),
            _ => throw new Exception("credential read before admission"),
            (_, _, _, _, _) => throw new Exception("native launch before admission"), NoFallback);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => source.RunAsync(["powershell.exe"], "unlisted", Cwd, Ct));
        Assert.Equal("ad_source_endpoint_invalid", error.Message); Assert.Null(error.InnerException);
    }

    [Fact]
    public async Task CredentialsStayOutOfCommandResultAndNativeFailure()
    {
        string[] command = ["powershell.exe", "-NoProfile"];
        var login = new AdSourceLogin("synthetic-user@example.test", "password-sentinel");
        var source = new AdSourceProcess(_ => "dc.example.test", _ => login, (args, credentials, _, _, _) => {
            Assert.Equal(command, args); Assert.Same(login, credentials);
            throw new Win32Exception(5, "password-sentinel synthetic-user");
        }, NoFallback);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => source.RunAsync(command, "DC", Cwd, Ct));
        Assert.Equal("ad_source_process_failed winerror 5", error.Message); Assert.Null(error.InnerException);
        Assert.DoesNotContain("sentinel", error.ToString()); Assert.DoesNotContain("synthetic-user", error.ToString());
        Assert.DoesNotContain("sentinel", login.ToString()); Assert.DoesNotContain("synthetic-user", login.ToString());
    }

    [Theory]
    [InlineData("ad_source_process_output_limit")]
    [InlineData("ad_source_process_command_invalid")]
    [InlineData("ad_source_process_command_too_long")]
    [InlineData("password-sentinel")]
    public async Task OnlyAllowlistedLaunchErrorsCrossBoundary(string message)
    {
        var source = new AdSourceProcess(_ => "dc.example.test", Credentials,
            (_, _, _, _, _) => throw new Exception(message), NoFallback);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => source.RunAsync(["powershell.exe"], "DC", Cwd, Ct));
        Assert.Equal(message == "password-sentinel" ? "ad_source_process_failed" : message, error.Message);
        Assert.Null(error.InnerException);
    }

    [Fact]
    public async Task CredentialReadFailureIsSanitizedAndCannotLaunch()
    {
        var source = new AdSourceProcess(_ => "dc.example.test", _ => throw new Exception("password-sentinel"),
            (_, _, _, _, _) => throw new Exception("must not launch"), NoFallback);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => source.RunAsync(["powershell.exe"], "DC", Cwd, Ct));
        Assert.Equal("ad_source_credentials_unavailable", error.Message); Assert.Null(error.InnerException);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("process")]
    public async Task CoordinatorDefaultProcessNeverLoadsCredentials(string? mode)
    {
        string[] command = ["original"];
        var source = new AdSourceProcess(_ => throw new Exception("endpoint resolution in process mode"),
            _ => throw new Exception("credentials in process mode"), (_, _, _, _, _) => throw new Exception("netonly fallback"),
            (args, cwd, ct, _) => {
                Assert.Equal(command, args); Assert.Equal(Cwd, cwd); Assert.Equal(Ct, ct);
                return Task.FromResult(new AdSourceProcessResult(args, 7, "original-output", "original-error"));
            });
        var result = await source.RunCollectorAsync(command, Cwd, _ => mode, Ct);
        Assert.Equal(7, result.ReturnCode); Assert.Equal(command, result.Command);
        Assert.Equal("original-output", result.Stdout); Assert.Equal("original-error", result.Stderr);
    }

    [Theory]
    [InlineData("DC", "fallback", "DC")]
    [InlineData(null, " fallback ", "fallback")]
    [InlineData("", "fallback", "fallback")]
    [InlineData("  ", "fallback", "")]
    public async Task CoordinatorNetonlyPreservesCommandDirectoryTokenAndHeartbeat(string? server, string fallback, string expected)
    {
        string[] command = ["original", "argument with spaces"];
        Func<Task> heartbeat = () => Task.CompletedTask;
        var source = new AdSourceProcess(target => { Assert.Equal(expected, target); return "dc.example.test"; }, Credentials,
            (args, _, cwd, ct, beat) => {
                Assert.Equal(command, args); Assert.Equal(Cwd, cwd); Assert.Equal(Ct, ct); Assert.Same(heartbeat, beat);
                return Task.FromResult(new AdSourceProcessResult(args, 0, "netonly-output", ""));
            }, NoFallback);
        var env = new Dictionary<string, string?> { ["ADLOG_AD_SOURCE_CREDENTIAL_MODE"] = "dpapi_current_user",
            ["ADLOG_AD_CONTEXT_DIRECTORY_SERVER"] = server, ["ADLOG_COLLECTION_PREFLIGHT_SERVER"] = fallback };
        Assert.Equal("netonly-output", (await source.RunCollectorAsync(command, Cwd, key => env.GetValueOrDefault(key), Ct, heartbeat)).Stdout);
    }

    [Theory]
    [InlineData("typo")]
    [InlineData("")]
    [InlineData(" process")]
    [InlineData("DPAPI_CURRENT_USER")]
    public async Task InvalidModeNeverFallsBack(string mode)
    {
        var source = new AdSourceProcess(_ => throw new Exception("endpoint read"), _ => throw new Exception("credential read"),
            (_, _, _, _, _) => throw new Exception("netonly launch"), NoFallback);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => source.RunCollectorAsync(["original"], Cwd, _ => mode, Ct));
        Assert.Equal("ad_source_credential_mode_invalid", error.Message);
    }

    [Fact]
    public void NativeCommandAdmissionPrecedesCredentialUseAndLaunch()
    {
        Assert.Equal("ad_source_process_command_invalid", Assert.Throws<InvalidOperationException>(() => AdSourceNative.CommandLine([])).Message);
        Assert.Equal("ad_source_process_command_invalid", Assert.Throws<InvalidOperationException>(() => AdSourceNative.CommandLine(["powershell.exe"])).Message);
        Assert.Equal("ad_source_process_command_invalid", Assert.Throws<InvalidOperationException>(() => AdSourceNative.CommandLine([Path.Combine(Cwd, "cmd.exe")])).Message);
        Assert.Equal("ad_source_process_command_invalid", Assert.Throws<InvalidOperationException>(() => AdSourceNative.CommandLine([Powershell, "\0"])).Message);
        Assert.Equal("ad_source_process_command_too_long", Assert.Throws<InvalidOperationException>(() => AdSourceNative.CommandLine([Powershell, new string('x', 1024)])).Message);
        string prefix = AdSourceNative.CommandLine([Powershell]) + " ";
        Assert.Equal(1023, AdSourceNative.CommandLine([Powershell, new string('x', 1023 - prefix.Length)]).Length);
        Assert.Equal("ad_source_process_command_too_long", Assert.Throws<InvalidOperationException>(() => AdSourceNative.CommandLine([Powershell, new string('x', 1024 - prefix.Length)])).Message);
    }

    [Fact]
    public void NativeCommandUsesWindowsArgumentQuotingAndUtf16Size()
    {
        string prefix = AdSourceNative.CommandLine([Powershell]) + " ";
        Assert.Equal(prefix + "\"\" \"a b\\\\\" x\\\"y", AdSourceNative.CommandLine([Powershell, "", "a b\\", "x\"y"]));
        Assert.Equal("ad_source_process_command_too_long", Assert.Throws<InvalidOperationException>(() => AdSourceNative.CommandLine([Powershell, string.Concat(Enumerable.Repeat("\U0001f600", 512))])).Message);
    }

    [Fact]
    public async Task OrdinaryProcessCapturesExitCodeAndOutputWithoutCredentialProvider()
    {
        var source = new AdSourceProcess(_ => throw new Exception("endpoint read"), _ => throw new Exception("credential read"));
        string[] command = OperatingSystem.IsWindows() ? [Powershell, "-NoProfile", "-NonInteractive", "-Command", "[Console]::Out.Write('original-output'); [Console]::Error.Write('original-error'); exit 7"]
            : ["/bin/sh", "-c", "printf original-output; printf original-error >&2; exit 7"];
        var result = await source.RunCollectorAsync(command, Cwd, _ => null, Ct);
        Assert.Equal(command, result.Command); Assert.Equal(7, result.ReturnCode);
        Assert.Equal("original-output", result.Stdout); Assert.Equal("original-error", result.Stderr);
    }

    [Fact]
    public async Task ExplicitStopRemainsCancellationWithoutLeakingNativeText()
    {
        using var stop = new CancellationTokenSource(); stop.Cancel();
        var source = new AdSourceProcess(_ => "dc.example.test", Credentials,
            (_, _, _, _, _) => throw new OperationCanceledException("password-sentinel"), NoFallback);
        var error = await Assert.ThrowsAsync<OperationCanceledException>(() => source.RunAsync(["original"], "DC", Cwd, stop.Token));
        Assert.Equal(stop.Token, error.CancellationToken); Assert.DoesNotContain("sentinel", error.ToString());
    }

    [Fact]
    public async Task DefaultProcessReportsHeartbeatAndStopsOnExplicitCancellation()
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(Ct); int beats = 0;
        var source = new AdSourceProcess(_ => throw new Exception("endpoint read"), _ => throw new Exception("credential read"));
        string[] command = OperatingSystem.IsWindows() ? [Powershell, "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 30"]
            : ["/bin/sh", "-c", "sleep 30"];
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => source.RunCollectorAsync(command, Cwd, _ => null, stop.Token,
            () => { beats++; stop.Cancel(); return Task.CompletedTask; }));
        Assert.Equal(1, beats);
    }
}

[CollectionDefinition("AD source native environment", DisableParallelization = true)]
public sealed class AdSourceNativeEnvironment;

[Collection("AD source native environment")]
public sealed class AdSourceNativeProcessTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static string Powershell => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
    private static AdSourceLogin Login => new(".\\sli-synthetic", "synthetic-not-a-real-password");
    private static string[] Command(string script) => [Powershell, "-NoProfile", "-NonInteractive", "-Command", script];

    // CI on non-Windows checks fail-closed platform admission instead of
    // skipping a security test. Windows executes the synthetic native vector.
    private static async Task NonWindowsRefusesNativeLaunch()
    {
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => AdSourceNative.RunAsync(
            ["/synthetic/powershell.exe"], null!, Path.GetFullPath("."), Ct, null,
            () => throw new Exception("native launch on unsupported platform")));
        Assert.Equal("ad_source_process_command_invalid", error.Message);
    }

    [Fact]
    public async Task Ps5ResolvesBuiltinsDespiteParentPs7PathAndHasNoDatabaseSecrets()
    {
        if (!OperatingSystem.IsWindows()) { await NonWindowsRefusesNativeLaunch(); return; }
        string? oldModules = Environment.GetEnvironmentVariable("PSModulePath"), oldDsn = Environment.GetEnvironmentVariable("ADLOG_PG_DSN");
        try {
            Environment.SetEnvironmentVariable("PSModulePath", "C:\\sli-synthetic-missing-ps7-modules");
            Environment.SetEnvironmentVariable("ADLOG_PG_DSN", "pg-secret-sentinel");
            string script = "$ErrorActionPreference='Stop'; $env:ADPS_LoadDefaultDrive='0'; $names='Get-FileHash','ConvertTo-Json','Get-Date','Import-Module','Get-Content','Set-Content','Export-Csv'; "
                + "$found=@(Get-Command $names -ErrorAction Stop); Import-Module ActiveDirectory -ErrorAction Stop; Import-Module GroupPolicy -ErrorAction Stop; "
                + "[pscustomobject]@{commands=$found.Count;ad=[bool](Get-Module ActiveDirectory);gpo=[bool](Get-Module GroupPolicy);pg=[bool]$env:ADLOG_PG_DSN}|ConvertTo-Json -Compress";
            var result = await AdSourceNative.RunAsync(Command(script), Login, Path.GetFullPath("."), Ct, null);
            Assert.Equal(0, result.ReturnCode); Assert.Equal("", result.Stderr);
            var json = JsonNode.Parse(result.Stdout)!; Assert.Equal(7, json["commands"]!.GetValue<int>()); Assert.False(json["pg"]!.GetValue<bool>());
            Assert.True(json["ad"]!.GetValue<bool>()); Assert.True(json["gpo"]!.GetValue<bool>());
        }
        finally { Environment.SetEnvironmentVariable("PSModulePath", oldModules); Environment.SetEnvironmentVariable("ADLOG_PG_DSN", oldDsn); }
    }

    [Fact]
    public async Task NetonlyCapturesNestedChildWhilePreservingLocalIdentityAndSession()
    {
        if (!OperatingSystem.IsWindows()) { await NonWindowsRefusesNativeLaunch(); return; }
        string script = "$child=[string](& $PSHOME/powershell.exe -NoProfile -NonInteractive -Command '[Security.Principal.WindowsIdentity]::GetCurrent().User.Value'); "
            + "[pscustomobject]@{sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;session=[Diagnostics.Process]::GetCurrentProcess().SessionId;child=$child;code=$LASTEXITCODE}|ConvertTo-Json -Compress";
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var result = await AdSourceNative.RunAsync(Command(script), Login, Path.GetFullPath("."), Ct, null);
        Assert.Equal(0, result.ReturnCode); Assert.Equal("", result.Stderr);
        var json = JsonNode.Parse(result.Stdout)!;
        Assert.Equal(identity.User!.Value, json["sid"]!.GetValue<string>()); Assert.Equal(identity.User.Value, json["child"]!.GetValue<string>());
        using var self = Process.GetCurrentProcess(); Assert.Equal(self.SessionId, json["session"]!.GetValue<int>()); Assert.Equal(0, json["code"]!.GetValue<int>());
    }

    [Fact]
    public async Task OutputLimitAndPreResumeJobFailureLeaveNoChildOrHandles()
    {
        if (!OperatingSystem.IsWindows()) { await NonWindowsRefusesNativeLaunch(); return; }
        // Warm up P/Invoke and capture before measuring resource cleanup.
        await AdSourceNative.RunAsync(Command("exit 0"), Login, Path.GetFullPath("."), Ct, null);
        using var self = Process.GetCurrentProcess(); int before = self.HandleCount;
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => AdSourceNative.RunAsync(Command("[Console]::Out.Write(('x'*1100000))"), Login, Path.GetFullPath("."), Ct, null));
        Assert.Equal("ad_source_process_output_limit", error.Message);
        string directory = Path.Combine(Path.GetTempPath(), "sli-ad-source-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        try {
            string marker = Path.Combine(directory, "must-not-run.txt");
            error = await Assert.ThrowsAsync<InvalidOperationException>(() => AdSourceNative.RunAsync(Command("Set-Content -LiteralPath '" + marker.Replace("'", "''") + "' -Value bad"), Login, directory, Ct, null,
                () => throw new InvalidOperationException("synthetic-job-refusal")));
            Assert.Equal("synthetic-job-refusal", error.Message); Assert.False(File.Exists(marker));
        }
        finally { Directory.Delete(directory, true); }
        self.Refresh(); Assert.True(self.HandleCount <= before + 2, $"Handle count before={before}, after={self.HandleCount}");
    }

    [Fact]
    public async Task ExplicitStopKillsDescendantsAndClosesHandles()
    {
        if (!OperatingSystem.IsWindows()) { await NonWindowsRefusesNativeLaunch(); return; }
        await AdSourceNative.RunAsync(Command("exit 0"), Login, Path.GetFullPath("."), Ct, null);
        using var self = Process.GetCurrentProcess(); int before = 0;
        string directory = Path.Combine(Path.GetTempPath(), "sli-ad-source-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        Task<AdSourceProcessResult>? run = null;
        try {
            string started = Path.Combine(directory, "child-started.txt"), survived = Path.Combine(directory, "must-not-survive.txt");
            string child = "Set-Content -LiteralPath '" + started.Replace("'", "''") + "' -Value $PID; Start-Sleep -Seconds 20; Set-Content -LiteralPath '" + survived.Replace("'", "''") + "' -Value bad";
            string encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(child));
            string script = Path.Combine(directory, "parent.ps1");
            await File.WriteAllTextAsync(script, "Start-Process -WindowStyle Hidden -FilePath $PSHOME/powershell.exe -ArgumentList '-NoProfile -EncodedCommand " + encoded + "'; Start-Sleep -Seconds 20", Ct);
            // Warm the CLR's shared asynchronous-file infrastructure before the
            // native handle baseline, just as Python preloads its Win32 DLLs.
            Assert.NotEmpty(await File.ReadAllTextAsync(script, Ct));
            self.Refresh(); before = self.HandleCount;
            run = AdSourceNative.RunAsync([Powershell, "-NoProfile", "-NonInteractive", "-File", script], Login, directory, stop.Token, null);
            while (!File.Exists(started) && !run.IsCompleted) await Task.Delay(20, Ct);
            // Surface native launch errors instead of reporting a missing marker.
            if (run.IsCompleted) await run;
            int pid = 0;
            while (pid == 0) {
                if (int.TryParse(await File.ReadAllTextAsync(started, Ct), out int parsed)) pid = parsed;
                else await Task.Delay(20, Ct);
            }
            stop.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
            try { using var descendant = Process.GetProcessById(pid); Assert.True(descendant.HasExited); }
            catch (ArgumentException) { /* The OS has already removed the PID. */ }
            Assert.False(File.Exists(survived));
        }
        finally {
            stop.Cancel();
            if (run is not null) try { await run; } catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            Directory.Delete(directory, true);
        }
        self.Refresh(); Assert.True(self.HandleCount <= before + 2, $"Handle count before={before}, after={self.HandleCount}");
    }
}
