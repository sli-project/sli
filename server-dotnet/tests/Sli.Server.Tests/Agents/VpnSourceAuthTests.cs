using Sli.Server.Agents.Radius;
using Sli.Server.Jobs;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed partial class VpnSourceAuthTests
{
    private const string Directory = @"\\nps.example.test\Accounting";
    private sealed class Token(List<string> events) : IDisposable
    { public void Dispose() => events.Add("close"); }
    private sealed class Windows(List<string> events, string? failure) : IVpnSourceWindows
    {
        internal (string User, string? Domain, string Password, int Type, int Provider)? Login;
        internal int? Exit;
        public IDisposable? OpenThreadToken()
        {
            events.Add("check");
            if (failure == "token_check") throw new IOException("private error");
            return failure == "existing" ? new Token(events) : null;
        }
        public IDisposable Logon(string user, string? domain, string password, int type, int provider)
        {
            events.Add("login"); Login = (user, domain, password, type, provider);
            if (failure == "login") throw new IOException("private password");
            return new Token(events);
        }
        public void Impersonate(IDisposable token)
        { events.Add("impersonate"); if (failure == "impersonate") throw new IOException("private error"); }
        public void Revert()
        { events.Add("revert"); if (failure == "revert") throw new IOException("private error"); }
        // Production exits the child. Throw here to observe the exit request without ending the runner.
        public void Terminate(int code) { Exit = code; throw new IOException("private exit"); }
    }

    [Fact]
    public void SourceMismatchAndInvalidRoutePrecedeSecretsWindowsAndReads()
    {
        foreach (bool invalidRoute in new[] { false, true })
        {
            var events = new List<string>(); var windows = new Windows(events, null);
            var error = Assert.Throws<VpnSourceAuthException>(() => VpnSourceAuth.Read<int>(@"\\other.example.test\Accounting", "dpapi_current_user",
                () => invalidRoute ? throw new IOException("private path") : Directory,
                () => throw new Exception("secret read"), () => throw new Exception("source contacted"), windows));
            Assert.Equal("vpn_source_endpoint_invalid", error.Message); Assert.Null(error.InnerException); Assert.Empty(events);
        }
    }

    [Theory]
    [InlineData(null)] [InlineData("read")] [InlineData("existing")] [InlineData("login")]
    [InlineData("impersonate")] [InlineData("revert")] [InlineData("token_check")] [InlineData("load")] [InlineData("upn")]
    public void IdentityScopeAndSanitizedFailuresMatchReference(string? failure)
    {
        var events = new List<string>(); var windows = new Windows(events, failure);
        int Run()
        {
            int value = VpnSourceAuth.Read(Directory, "dpapi_current_user", () => Directory, () =>
            {
                events.Add("load"); if (failure == "load") throw new IOException("private error");
                return new VpnSourceCredentials(failure == "upn" ? "vpn@example.test" : @"EXAMPLE\vpn", "fixture");
            }, () => { events.Add("read"); if (failure == "read") throw new IOException("private password"); return 42; }, windows);
            events.Add("local"); return value;
        }
        if (failure is null or "upn")
        {
            Assert.Equal(42, Run());
            Assert.Equal(new[] { "check", "load", "login", "impersonate", "read", "revert", "close", "local" }, events);
        }
        else
        {
            var error = Assert.Throws<VpnSourceAuthException>(() => Run());
            Assert.Equal(failure switch { "existing" => "vpn_source_thread_impersonation_forbidden", "token_check" => "vpn_source_thread_identity_unavailable", _ => "vpn_source_access_failed" }, error.Message);
            Assert.DoesNotContain("private", error.ToString()); Assert.Null(error.InnerException); Assert.DoesNotContain("local", events);
        }
        if (failure is "existing" or "token_check") Assert.DoesNotContain("load", events);
        if (failure == "existing") Assert.Equal(new[] { "check", "close" }, events);
        if (failure is "read" or "impersonate") Assert.Equal(new[] { "revert", "close" }, events.TakeLast(2));
        if (failure == "revert") Assert.Equal(74, windows.Exit); else Assert.Null(windows.Exit);
        if (failure is not ("existing" or "token_check" or "load"))
            Assert.Equal((failure == "upn" ? "vpn@example.test" : "vpn", failure == "upn" ? null : "EXAMPLE", "fixture", 9, 3), windows.Login!.Value);
    }

    [Fact]
    public void ProcessDoesNotReadSecretsOrInspectWindowsAndUnknownModeDoesNotReadSource()
    {
        var events = new List<string>(); var windows = new Windows(events, null);
        Assert.Equal(7, VpnSourceAuth.Read("fixture", "process", () => throw new Exception("route read"),
            () => throw new Exception("secret read"), () => 7, windows));
        Assert.Empty(events);
        Assert.Equal("vpn_source_credential_mode_invalid", Assert.Throws<VpnSourceAuthException>(() =>
            VpnSourceAuth.Read<int>("fixture", "unknown", () => "fixture", () => throw new Exception("secret read"), () => throw new Exception("source contacted"), windows)).Message);
    }

    [Fact]
    public void AcquisitionRevertsBeforeLocalConnectionCleanupAndPreservesProcessReadErrors()
    {
        foreach (string mode in new[] { "process", "dpapi_current_user" })
        {
            var events = new List<string>(); var windows = new Windows(events, null);
            void Run()
            {
                using var connection = new Cleanup(events);
                VpnSourceAuth.Read<int>(Directory, mode, () => Directory, () => new(@"EXAMPLE\vpn", "fixture"),
                    () => { events.Add("read"); throw new IOException("fixture source failure"); }, windows);
                events.Add("local");
            }
            if (mode == "process") Assert.Equal("fixture source failure", Assert.Throws<IOException>(Run).Message);
            else Assert.Throws<VpnSourceAuthException>(Run);
            Assert.Equal(mode == "process" ? new[] { "read", "local_cleanup" } : new[] { "check", "login", "impersonate", "read", "revert", "close", "local_cleanup" }, events);
        }
    }
    private sealed class Cleanup(List<string> events) : IDisposable { public void Dispose() => events.Add("local_cleanup"); }

    [Theory]
    [InlineData("radius-acquisition", "handler", "dpapi_current_user", "dpapi_current_user")]
    [InlineData("radius-acquisition", "handler", null, "process")]
    [InlineData("radius-session-observation", "handler", "dpapi_current_user", null)]
    [InlineData("radius-acquisition", "publisher", "dpapi_current_user", null)]
    [InlineData("radius-session-observation", "handler", "unknown", null)]
    public void PersistedModeReachesAcquisitionHandlerOnly(string handler, string purpose, string? mode, string? expected)
    {
        string? Get(string key) => key switch
        {
            "ADLOG_COLLECTION_PRINCIPAL" => @"EXAMPLE\owner",
            "ADLOG_COLLECTION_PRINCIPAL_SID" => "S-1-5-21-100000001-200000002-300000003-1001",
            VpnSourceAuth.ModeEnvironment => mode,
            _ => key.EndsWith("_FILE", StringComparison.Ordinal) ? "fixture-secret" : null
        };
        var env = CoreJobIdentity.ChildEnvironment(new("long", purpose, "sli.remote-access", handler), Get);
        Assert.Equal(expected, env.GetValueOrDefault(VpnSourceAuth.ModeEnvironment));
    }

    [Fact]
    public void ChildRejectsInvalidAcquisitionMode()
    {
        Assert.Equal("vpn_source_credential_mode_invalid", Assert.Throws<VpnSourceAuthException>(() => CoreJobIdentity.ChildEnvironment(
            new("long", "handler", "sli.remote-access", "radius-acquisition"), key => key.EndsWith("_FILE", StringComparison.Ordinal) ? "fixture-secret" : "unknown")).Message);
    }

    [Fact]
    public void ConfiguredRouteIsValidatedBeforeTheCredentialStoreIsOpened()
    {
        using var route = System.Text.Json.JsonDocument.Parse(RadiusCollectionRouteTests.Route);
        var env = new Dictionary<string, string?> { [VpnSourceAuth.ModeEnvironment] = "dpapi_current_user" };
        Assert.Equal("vpn_source_endpoint_invalid", Assert.Throws<VpnSourceAuthException>(() =>
            VpnSourceAuth.Read<int>(@"\\other.example.test\Accounting", "unused-store", route.RootElement, env, () => throw new Exception("source contacted"))).Message);
        env["ADLOG_RADIUS_ACCOUNTING_SHARE_UNC"] = @"\\wrong.example.test\Accounting";
        Assert.Equal("vpn_source_endpoint_invalid", Assert.Throws<VpnSourceAuthException>(() =>
            VpnSourceAuth.Read<int>(Directory, "unused-store", route.RootElement, env, () => throw new Exception("source contacted"))).Message);
        env[VpnSourceAuth.ModeEnvironment] = "process";
        Assert.Equal(5, VpnSourceAuth.Read("fixture", "unused-store", default, env, () => 5));
    }

    [Theory]
    [InlineData("radius-acquisition")] [InlineData("radius-session-observation")]
    public void WindowsChildrenUseOnlySystemPowershellPathAndIsolateCredentialMode(string component)
    {
        string root = Path.Combine(Path.GetTempPath(), "vpn-child-" + Guid.NewGuid().ToString("N"));
        string powershell = Path.Combine(root, "System32", "WindowsPowerShell", "v1.0");
        System.IO.Directory.CreateDirectory(powershell);
        try
        {
            var parent = new Dictionary<string, string>
            {
                ["SystemRoot"] = root, ["WINDIR"] = root, ["PATH"] = "untrusted-path",
                ["ADLOG_COLLECTION_PRINCIPAL"] = @"EXAMPLE\owner",
                ["ADLOG_COLLECTION_PRINCIPAL_SID"] = "S-1-5-21-100000001-200000002-300000003-1001",
                [VpnSourceAuth.ModeEnvironment] = "dpapi_current_user"
            };
            var child = new Dictionary<string, string>();
            RadiusChildEnvironment.ConfigureWindows(child, key => parent.GetValueOrDefault(key));
            RadiusChildEnvironment.ConfigureMode(child, component, "handler", key => parent.GetValueOrDefault(key));
            Assert.Equal(Path.GetFullPath(powershell), child["PATH"]);
            Assert.Equal(component == "radius-acquisition" ? "dpapi_current_user" : null, child.GetValueOrDefault(VpnSourceAuth.ModeEnvironment));
            Assert.Equal("owner", child["USERNAME"]); Assert.Equal("EXAMPLE", child["USERDOMAIN"]);
            parent.Remove("ADLOG_COLLECTION_PRINCIPAL_SID");
            Assert.Equal("plugin_child_identity_missing", Assert.Throws<InvalidOperationException>(() => RadiusChildEnvironment.ConfigureWindows(child, key => parent.GetValueOrDefault(key))).Message);
        }
        finally { System.IO.Directory.Delete(root, true); }
    }
}
