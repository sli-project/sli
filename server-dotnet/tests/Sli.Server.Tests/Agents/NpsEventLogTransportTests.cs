using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Radius;
using Xunit;

namespace Sli.Server.Tests.Agents;

// Port of tests/sources/test_nps_eventlog_transport.py. No Windows/NPS contact.
public sealed class NpsEventLogTransportTests
{
    private static NpsEventLogRequest Request() => new("radius01.example.test", "radius01.example.test", "2026-09-09T00:00:00Z", "2026-09-09T01:00:00Z") {
        NpsContinuous = true, CredentialMode = "dpapi_current_user",
    };
    private static JsonObject Route() => new() {
        ["source_name"] = "radius01.example.test", ["source_instance_id"] = "radius01.example.test",
        ["owner_confirmed_ip"] = "192.0.2.10", ["event_log_ready"] = true, ["event_log_adapter"] = "windows-eventlog-pywin32",
    };
    private static string Xml(string provider, int id = 6272, string stamp = "2026-09-09T00:30:00Z", long record = 45) =>
        $"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='{provider}'/><EventID>{id}</EventID><TimeCreated SystemTime='{stamp}'/><EventRecordID>{record}</EventRecordID></System></Event>";

    private sealed class Session(params string[] rows) : INpsRemoteSession
    {
        internal List<string> XPaths { get; } = [];
        internal NpsChannelState Before { get; set; } = new(50, 1, "g1");
        internal NpsChannelState After { get; set; } = new(50, 1, "g1");
        internal int Probes { get; private set; }
        internal bool Disposed { get; private set; }
        internal Exception? ReadError { get; init; }
        public NpsChannelState Probe(string channel, Action heartbeat, CancellationToken ct) { Assert.Equal("Security", channel); return Probes++ == 0 ? Before : After; }
        public IEnumerable<string> Read(string channel, string xpath, Action heartbeat, CancellationToken ct)
        {
            Assert.Equal("Security", channel); XPaths.Add(xpath);
            foreach (string xml in rows) { heartbeat(); yield return xml; }
            if (ReadError is not null) throw ReadError;
        }
        public void Dispose() => Disposed = true;
    }

    [Fact]
    public void ResolvesRegisteredRouteBeforeLoadingVpnProfileAndOpeningRpc()
    {
        var calls = new List<string>();
        using var session = NpsEventLogTransport.OpenSession(Request(), () => { calls.Add("route"); return Route(); },
            profile => { calls.Add(profile); return new("vpn@example.test", "synthetic"); },
            (target, login) => {
                calls.Add("rpc"); Assert.Equal("radius01.example.test", target);
                Assert.Equal("vpn@example.test", login!.Username); Assert.Equal("synthetic", login.Password);
                var identity = NpsNativeEventLog.LoginIdentity(login);
                Assert.Equal("vpn@example.test", identity.User); Assert.Null(identity.Domain);
                return new Session();
            });
        Assert.Equal(new[] { "route", "vpn", "rpc" }, calls);
    }

    [Theory]
    [InlineData("source_instance_id", "wrong.example.test")]
    [InlineData("owner_confirmed_ip", "")]
    [InlineData("event_log_adapter", "windows-eventlog-powershell")]
    public void InvalidRegisteredRouteNeverLoadsCredentialsOrContactsSource(string field, string value)
    {
        var route = Route(); route[field] = value;
        Assert.Equal("nps_eventlog_registered_route_required", Assert.Throws<InvalidOperationException>(() => NpsEventLogTransport.OpenSession(Request(), () => route,
            _ => throw new Exception("credentials must not load"), (_, _) => throw new Exception("RPC must not start"))).Message);
    }

    [Fact]
    public void UnregisteredEndpointNeverLoadsCredentials()
    {
        Assert.Equal("nps_eventlog_endpoint_invalid", Assert.Throws<InvalidOperationException>(() => NpsEventLogTransport.OpenSession(Request() with { ComputerName = "other.example.test" }, Route,
            _ => throw new Exception("credentials must not load"), (_, _) => throw new Exception("RPC must not start"))).Message);
    }

    [Fact]
    public void RouteFileUsesExistingRadiusValidationAndExplicitSourceOverrides()
    {
        string file = Path.Combine(Path.GetTempPath(), "nps-route-test-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            File.WriteAllText(file, RadiusCollectionRouteTests.Route);
            var env = new Dictionary<string, string?> {
                ["ADLOG_RADIUS_COLLECTION_ROUTES_PATH"] = file, ["ADLOG_RADIUS_SOURCE_NAME"] = "radius01.example.test",
                ["ADLOG_RADIUS_OWNER_CONFIRMED_IP"] = "192.0.2.10", ["ADLOG_RADIUS_ACCOUNTING_SHARE_UNC"] = "",
            };
            var route = NpsEventLogCommand.LoadRoute("unused", env);
            Assert.Equal("radius01.example.test", NpsEventLogTransport.ResolveEndpoint(Request(), route));
            route["event_log_ready"] = false;
            Assert.Equal("nps_eventlog_registered_route_required", Assert.Throws<InvalidOperationException>(() => NpsEventLogTransport.ResolveEndpoint(Request(), route)).Message);
        }
        finally { File.Delete(file); }
    }

    [Theory]
    [InlineData("Wrong-Provider", true)]
    [InlineData(NpsEventLogTransport.Provider, true)]
    [InlineData("Wrong-Provider", false)]
    [InlineData(NpsEventLogTransport.Provider, false)]
    public void ProviderConstraintIsEnforcedBeforeOutput(string provider, bool continuous)
    {
        var session = new Session(Xml(provider));
        var errors = new List<string>();
        using var output = new StringWriter();
        var request = Request() with { NpsContinuous = continuous };
        var result = NpsEventLogTransport.Collect(request, "Security", output, () => session, errors.Add, ct: TestContext.Current.CancellationToken);
        Assert.Equal(continuous, Assert.Single(session.XPaths).Contains("Provider[@Name='Microsoft-Windows-Security-Auditing']"));
        Assert.True(session.Disposed);
        if (continuous && provider == "Wrong-Provider")
        {
            Assert.Equal("bounded_selection_provider_mismatch", Assert.Throws<InvalidDataException>(() =>
                NpsEventLogTransport.ValidateRow(Sli.Agent.Core.EventXml.Parse(Xml(provider), request.SourceName, request.ComputerName, "Security"), request, request.StartTimeUtc)).Message);
            Assert.Equal("failed", result["status"]!.GetValue<string>());
            Assert.Equal("ad_source_rpc_failed", result["error"]!.GetValue<string>());
            Assert.Equal(new[] { "ad_source_rpc_failed" }, errors);
            Assert.Equal(0, result["count"]!.GetValue<int>()); Assert.Equal("", output.ToString());
        }
        else
        {
            Assert.Empty(errors); Assert.Equal("completed", result["status"]!.GetValue<string>());
            Assert.Equal(1, result["count"]!.GetValue<int>());
            var packet = JsonNode.Parse(output.ToString())!; CollectionPacket.Validate(packet);
            Assert.Equal(provider, packet["records"]![0]!["payload"]!["provider_name"]!.GetValue<string>());
        }
    }

    [Fact]
    public void CursorlessFirstCycleFreezesBoundaryAndPersistsBothGenerations()
    {
        var session = new Session { Before = new(50, 1, "nps-generation-1"), After = new(50, 1, "nps-generation-1") };
        using var output = new StringWriter();
        var result = NpsEventLogTransport.Collect(Request(), "Security", output, () => session, ct: TestContext.Current.CancellationToken);
        Assert.Contains("EventRecordID <= 50", Assert.Single(session.XPaths));
        Assert.Contains("TimeCreated[", session.XPaths[0]); Assert.Equal(2, session.Probes);
        Assert.Equal("nps-generation-1", result["channel_generation_identity"]!.GetValue<string>());
        Assert.Equal("nps-generation-1", result["channel_generation_identity_after_read"]!.GetValue<string>());
        Assert.Equal("not_proven", result["continuity"]!["status"]!.GetValue<string>());
        Assert.Equal("completed", result["status"]!.GetValue<string>()); Assert.Equal("", output.ToString());
    }

    private static string[] Arguments(params string[] extra) => [
        "--nps-continuous", "--computer-name", "radius01.example.test", "--source-name", "radius01.example.test",
        "--ad-source-credential-mode", "dpapi_current_user", "--channels", "Security",
        "--start-time-utc", "2026-08-01T00:00:00Z", "--end-time-utc", "2026-09-09T00:00:00Z",
        "--event-ids-json", "[6272,6273]", "--output-root", "unused", ..extra,
    ];

    [Fact]
    public async Task SecondCursorCycleReachesCollectionAfterCliAdmission()
    {
        bool called = false;
        int code = await NpsEventLogCommand.RunCoreAsync(Arguments("--channel-after-record-ids-json", "{\"Security\":42}", "--channel-cursor-generations-json", "{\"Security\":\"generation-1\"}"),
            (r, _, _) => {
                called = true; Assert.True(r.NpsContinuous); Assert.Equal(42, r.AfterRecordIds["Security"]);
                Assert.Equal("generation-1", r.CursorGenerations["Security"]);
                var session = new Session { Before = new(50, 1, "generation-1"), After = new(50, 1, "generation-1") };
                using var output = new StringWriter();
                var result = NpsEventLogTransport.Collect(r, "Security", output, () => session, ct: TestContext.Current.CancellationToken);
                Assert.Contains("EventRecordID > 42", Assert.Single(session.XPaths));
                Assert.Contains("EventRecordID <= 50", session.XPaths[0]);
                Assert.True(result["cursor_commit_allowed"]!.GetValue<bool>()); return 0;
            }, TextWriter.Null, TextWriter.Null, TestContext.Current.CancellationToken);
        Assert.True(called); Assert.Equal(0, code);
    }

    [Fact]
    public async Task ContinuousModeIsExplicitAndNotAddedToDefaultRequest()
    {
        var args = Arguments().Where(x => x != "--nps-continuous").ToArray();
        bool called = false;
        Assert.Equal(0, await NpsEventLogCommand.RunCoreAsync(args, (r, _, _) => { called = true; Assert.False(r.NpsContinuous); return 0; }, TextWriter.Null, TextWriter.Null, TestContext.Current.CancellationToken));
        Assert.True(called);
    }

    [Theory]
    [InlineData("--max-events-per-channel", "50001", "--channel-limits-json", "{\"Security\":1}")]
    [InlineData("--max-events-per-channel", "10", "--channel-limits-json", "{\"Security\":50000}")]
    [InlineData("--channel-after-record-ids-json", "{\"Security\":0}", "--channel-cursor-generations-json", "{\"Security\":\"g1\"}")]
    [InlineData("--channel-cursor-generations-json", "{\"Security\":\"\"}", "--channel-after-record-ids-json", "{\"Security\":42}")]
    // The Python vectors for 0/empty also omit the paired cursor component.
    [InlineData("--channel-after-record-ids-json", "{\"Security\":0}", "--channels", "Security")]
    [InlineData("--channel-cursor-generations-json", "{\"Security\":\"\"}", "--channels", "Security")]
    [InlineData("--channel-after-record-ids-json", "{\"Security\":true}", "--channel-cursor-generations-json", "{\"Security\":\"g1\"}")]
    [InlineData("--channel-timeout-seconds", "10", "--channel-timeouts-json", "{\"Security\":60}")]
    public async Task InvalidEffectiveCursorOrCeilingIsRejectedBeforeCollection(string a, string b, string c, string d)
    {
        bool called = false;
        using var error = new StringWriter();
        Assert.Equal(12, await NpsEventLogCommand.RunCoreAsync(Arguments(a, b, c, d), (_, _, _) => { called = true; return 0; }, TextWriter.Null, error, TestContext.Current.CancellationToken));
        Assert.False(called); Assert.Equal("continuous_nps_admission_failed" + Environment.NewLine, error.ToString());
    }

    [Theory]
    [InlineData(6274, "2026-09-09T00:30:00Z")]
    [InlineData(6272, "2026-09-08T23:59:59Z")]
    [InlineData(6272, "2026-09-09T01:00:01Z")]
    [InlineData(6272, "2026-09-09T00:30:00+01:00")]
    public void MismatchedSelectionNeverWritesEvidence(int id, string stamp)
    {
        using var output = new StringWriter();
        var result = NpsEventLogTransport.Collect(Request(), "Security", output, () => new Session(Xml(NpsEventLogTransport.Provider, id, stamp)), ct: TestContext.Current.CancellationToken);
        Assert.Equal("failed", result["status"]!.GetValue<string>()); Assert.Equal("", output.ToString());
        Assert.False(result["cursor_commit_allowed"]!.GetValue<bool>());
    }

    [Fact]
    public void CredentialErrorsAndNativeDetailsAreSanitized()
    {
        var errors = new List<string>();
        using var output = new StringWriter();
        var result = NpsEventLogTransport.Collect(Request(), "Security", output,
            () => new Session { ReadError = new InvalidOperationException("synthetic internal credential detail") }, errors.Add, ct: TestContext.Current.CancellationToken);
        Assert.Equal(new[] { "ad_source_rpc_failed" }, errors);
        Assert.DoesNotContain("synthetic", result.ToJsonString());
        Assert.Equal("windows_event_log_access_denied winerror 5", NpsEventLogTransport.PublicError(new Win32Exception(5, "synthetic private detail")));
    }

    [Fact]
    public void FrozenSelectorRunsToExhaustionWithHeartbeatAndNoExecutionCeiling()
    {
        var beats = new List<JsonObject>();
        using var output = new StringWriter();
        var result = NpsEventLogTransport.Collect(Request() with { MaxEvents = 1 }, "Security", output,
            () => new Session(Xml(NpsEventLogTransport.Provider), Xml(NpsEventLogTransport.Provider, record: 46)), heartbeat: beats.Add, ct: TestContext.Current.CancellationToken);
        Assert.Equal(2, result["count"]!.GetValue<int>()); Assert.True(beats.Count >= 5);
        Assert.Equal(46, result["batch_max_record_id"]!.GetValue<long>());
        Assert.Equal("finished", beats[^1]["stage"]!.GetValue<string>());
    }

    [Fact]
    public void ChangedGenerationCannotCommitCursor()
    {
        using var output = new StringWriter();
        var result = NpsEventLogTransport.Collect(Request(), "Security", output,
            () => new Session { After = new(50, 1, "g2") }, ct: TestContext.Current.CancellationToken);
        Assert.False(result["cursor_commit_allowed"]!.GetValue<bool>());
    }

    [Fact]
    public void PreviousGenerationCursorFallsBackToTimeWindowWithoutClaimingContinuity()
    {
        using var output = new StringWriter();
        var session = new Session();
        var request = Request() with { AfterRecordIds = new() { ["Security"] = 42 }, CursorGenerations = new() { ["Security"] = "previous-generation" } };
        var result = NpsEventLogTransport.Collect(request, "Security", output, () => session, ct: TestContext.Current.CancellationToken);
        Assert.Equal("channel_generation_changed", result["cursor_fallback_reason"]!.GetValue<string>());
        Assert.Contains("TimeCreated[", Assert.Single(session.XPaths)); Assert.DoesNotContain("EventRecordID >", session.XPaths[0]);
        Assert.False(result["cursor_commit_allowed"]!.GetValue<bool>());
        Assert.Equal("not_proven", result["continuity"]!["status"]!.GetValue<string>());
    }

    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Length; public IntPtr Data; }
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(ref Blob input, string description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr value);

    [Fact]
    public void CurrentUserVpnStoreLoadsOnlyWithExactProtectedOwnerAndSystemAcl()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal("ad_source_credentials_unavailable", Assert.Throws<InvalidOperationException>(() => NpsSourceCredentials.Load("unused", "vpn")).Message);
            return;
        }
        string data = Path.Combine(Path.GetTempPath(), "nps-dpapi-test-" + Guid.NewGuid().ToString("N"));
        string store = Path.Combine(data, "runtime", "vpn-source-credentials");
        try
        {
            Directory.CreateDirectory(Path.Combine(data, "runtime"));
            using var identity = WindowsIdentity.GetCurrent();
            var owner = identity.User!;
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var directoryAcl = new DirectorySecurity(); directoryAcl.SetOwner(owner); directoryAcl.SetAccessRuleProtection(true, false);
            foreach (var sid in new[] { owner, system }.Distinct()) directoryAcl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(store).Create(directoryAcl);
            byte[] clear = Encoding.UTF8.GetBytes(new JsonObject { ["version"] = 1, ["purpose"] = "sli.vpn-source-credentials", ["owner_sid"] = owner.Value,
                ["username"] = "vpn@example.test", ["password"] = "synthetic" }.ToJsonString());
            var pin = GCHandle.Alloc(clear, GCHandleType.Pinned);
            Blob encrypted = default;
            byte[] cipher;
            try
            {
                var input = new Blob { Length = clear.Length, Data = pin.AddrOfPinnedObject() };
                Assert.True(CryptProtectData(ref input, "sli.vpn-source-credentials", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out encrypted));
                cipher = new byte[encrypted.Length]; Marshal.Copy(encrypted.Data, cipher, 0, cipher.Length);
            }
            finally { pin.Free(); if (encrypted.Data != IntPtr.Zero) LocalFree(encrypted.Data); }
            string blob = Path.Combine(store, "credentials.dpapi"); File.WriteAllBytes(blob, cipher);
            var fileAcl = new FileSecurity(); fileAcl.SetOwner(owner); fileAcl.SetAccessRuleProtection(true, false);
            foreach (var sid in new[] { owner, system }.Distinct()) fileAcl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
            new FileInfo(blob).SetAccessControl(fileAcl);
            var credentials = NpsSourceCredentials.Load(data, "vpn");
            Assert.Equal("vpn@example.test", credentials.Username); Assert.Equal("synthetic", credentials.Password);
            Assert.DoesNotContain("synthetic", credentials.ToString());
            fileAcl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.Read, AccessControlType.Allow));
            new FileInfo(blob).SetAccessControl(fileAcl);
            Assert.Equal("ad_source_credentials_unavailable", Assert.Throws<InvalidOperationException>(() => NpsSourceCredentials.Load(data, "vpn")).Message);
        }
        finally { if (Directory.Exists(data)) Directory.Delete(data, true); }
    }
}
