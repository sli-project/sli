using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Service;
using Sli.Agent.Windows;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class PolicyCycleTests : IDisposable
{
    private readonly string _directory = Helpers.TempDirectory();
    private readonly TestAuthority _ca = new();
    private readonly TestClock _clock = new();
    private readonly List<(string Path, JsonNode? Body)> _requests = [];
    private readonly Source _source = new();
    private readonly AgentOptions _options;
    private JsonObject _assignment = Assignment();
    private bool _receiptLost;
    private bool _moduleDisabled;
    private bool _failNextSession;
    private string? _timeoutPath;
    private HttpStatusCode? _enrollStatus;
    private JsonObject? _renewalResponse;
    private AgentRuntime? _runtime;
    private IDirectorySnapshotReader? _snapshotReader;
    private IFileAuditApi? _fileApi;
    private IFileAuditEventSource? _fileSource;
    private INpsEventSource? _npsSource;
    private IRadiusTailSource? _radiusSource;
    private Func<JsonObject>? _protectionReader;

    public PolicyCycleTests()
    {
        _options = new AgentOptions { ServerUrl = "https://core.example.test/", StateDir = Path.Combine(_directory, "state"), TokenFile = Path.Combine(_directory, "token") };
        File.WriteAllText(_options.TokenFile, new string('t', 43));
        File.SetLastWriteTimeUtc(_options.TokenFile, Helpers.Now.UtcDateTime);
    }
    public void Dispose() { _runtime?.Dispose(); _ca.Dispose(); Directory.Delete(_directory, true); }
    public static JsonObject Assignment(string state = "active") => new()
    {
        ["agent_id"] = Helpers.AgentId, ["policy_revision"] = 1,
        ["assigned_modules"] = new JsonArray(new JsonObject { ["module_id"] = "sli.workstations", ["enabled"] = true, ["config"] = new JsonObject
        { ["policy_revision"] = "1", ["families"] = new JsonObject { ["logons"] = true, ["processes"] = false, ["usb"] = false, ["local_admins"] = false, ["protection"] = false } } }),
        ["collection_policy"] = new JsonObject { ["state"] = state, ["interval_seconds"] = 120, ["batch_size"] = 32, ["rate_limit_per_minute"] = 2 },
    };
    private sealed class Source : IEventLogSource
    {
        public int Reads { get; private set; }
        public SourceBatch Read(string channel, ChannelProgress progress, int limit) { Reads++; return new([]); }
    }
    private sealed class Audit : IWindowsAudit
    {
        public JsonObject Reconcile(AgentPolicy policy, DateTimeOffset now) => new() { ["windows_audit"] = new JsonObject() };
    }
    private sealed class Handler(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request);
    }
    private AgentRuntime Runtime() => _runtime ??= new(Options.Create(_options), _clock, identity =>
    {
        if (identity is not null && _failNextSession) { _failNextSession = false; throw new AgentException("agent_config_invalid"); }
        return new AgentHttpClient(new HttpClient(new Handler(async request =>
        {
            var body = request.Content is null ? null : JsonNode.Parse(await request.Content.ReadAsStringAsync());
            var path = request.RequestUri!.AbsolutePath;
            _requests.Add((path, body?.DeepClone()));
            if (path == _timeoutPath) throw new TaskCanceledException("synthetic private details");
            JsonObject result;
            if (path.EndsWith("/enroll", StringComparison.Ordinal))
            {
                Assert.Null(identity);
                if (_enrollStatus is { } status) return new HttpResponseMessage(status);
                result = _ca.Issue(AgentRuntime.CreateIdentityStore(_options));
            }
            else
            {
                Assert.NotNull(identity);
                if (path.EndsWith("/identity", StringComparison.Ordinal)) result = _assignment;
                else if (path.EndsWith("/renew", StringComparison.Ordinal)) result = _renewalResponse ?? new JsonObject();
                else if (path.EndsWith("/packets", StringComparison.Ordinal))
                {
                    if (body!["envelope"]!["module_id"]!.ToString() is NpsPolicy.Nps or NpsPolicy.Accounting)
                        Assert.Equal(body["payload"]!["header"]!["observed_at_utc"]!.ToString(), body["envelope"]!["observed_at_utc"]!.ToString());
                    if (_receiptLost) throw new HttpRequestException("synthetic lost response");
                    result = Helpers.Receipt(SignedPacket.FromJson(body), "duplicate");
                    if(_moduleDisabled) {
                        result=Helpers.ExpiredReceipt(SignedPacket.FromJson(body)); result["error_code"]="module_disabled";
                    }
                }
                else result = new JsonObject();
            }
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(result.ToJsonString(), Encoding.UTF8, "application/json") };
        })) { BaseAddress = new Uri(_options.ServerUrl) });
    }, _source, new Audit(), _snapshotReader, _fileSource, _fileApi, (_,_) => { }, _ => true, _npsSource, _radiusSource, _protectionReader);

    [Fact]
    public async Task DcAuditResultReachesConsoleBeforeEventDeliveryTimeout()
    {
        await Runtime().RunCycleAsync(CancellationToken.None);
        _assignment["policy_revision"] = 2;
        _assignment["assigned_modules"] = new JsonArray(new JsonObject { ["module_id"] = AdDcModule.ModuleId, ["enabled"] = true,
            ["config"] = new JsonObject { ["source_name"] = "dc.example.test", ["connect_address"] = "localhost" } });
        _assignment["collection_policy"]!["manage_windows_audit"] = true;
        _timeoutPath = "/api/v1/agent/packets";
        _requests.Clear();
        await Runtime().RunCycleAsync(CancellationToken.None);
        var audit = _requests.FindIndex(r => r.Path == "/api/v1/agent/windows-audit-report");
        var delivery = _requests.FindIndex(r => r.Path == _timeoutPath);
        Assert.True(audit >= 0 && delivery > audit);
    }

    [Fact]
    public async Task ReplacementCheckInUsesRetainedHostAndCursorWithOwnCertificateAndSequence()
    {
        var scenario = Vectors.Load("workstations-scenarios.json").AsArray().First(x => x!["steps"]!.AsArray().Count >= 2)!;
        var host = scenario["host_id"]!.GetValue<string>();
        var cursor = scenario["steps"]![0]!["cursor_after"]!.DeepClone();
        _assignment["runtime_handoff"] = new JsonObject { ["source_host_id"] = host,
            ["cursors"] = new JsonObject { [WorkstationsModule.ModuleId] = new JsonObject {
                ["generation"] = host, ["cursor_after"] = cursor.DeepClone() } } };
        _assignment["assigned_modules"]![0]!["config"] = scenario["config"]!.DeepClone();
        var status = await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Null(status.ErrorCode);
        Assert.True(status.Captured > 0);
        _assignment["collection_policy"]!["state"] = "drain";
        await Runtime().RunCycleAsync(CancellationToken.None);
        var packet = SignedPacket.FromJson(_requests.First(r => r.Path.EndsWith("/packets", StringComparison.Ordinal)).Body);
        Assert.Equal(Helpers.AgentId, packet.Envelope.AgentId);
        Assert.Equal(host, packet.Envelope.SourceInstanceId);
        Assert.Equal(host, packet.Envelope.Generation);
        Assert.Equal(1, packet.Envelope.Sequence);
        Assert.Equal(CanonicalJson.Serialize(cursor), CanonicalJson.Serialize(packet.Envelope.CursorBefore.ToJson()));
        Assert.Contains(_requests, r => r.Path.EndsWith("/policy-report", StringComparison.Ordinal)
            && r.Body!["runtime_handoff_supported"]!.GetValue<bool>());
    }

    [Fact]
    public async Task DefenderSnapshotUsesExistingSignedQueueAndStopsWhenPaused()
    {
        var reads = 0;
        _protectionReader = () =>
        {
            reads++;
            return ProtectionSnapshot.FromDefenderOutput(0,
                "{\"antivirus_enabled\":true,\"real_time_protection_enabled\":false,\"behavior_monitor_enabled\":true,"
                + "\"ioav_protection_enabled\":null,\"nis_enabled\":true,\"tamper_protected\":false}");
        };
        var config = _assignment["assigned_modules"]![0]!["config"]!;
        config["families"]!["logons"] = false;
        config["families"]!["protection"] = true;
        _assignment["collection_policy"]!["rate_limit_per_minute"] = 100;
        for (var i = 0; i < 3; i++)
        {
            var status = await Runtime().RunCycleAsync(CancellationToken.None);
            Assert.Null(status.ErrorCode);
            Assert.Equal(1, status.Captured);
            _clock.Now = _clock.Now.AddSeconds(120);
        }
        _assignment["collection_policy"]!["state"] = "drain";
        var drained = await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Equal(0, drained.Captured);
        Assert.Equal(0, drained.Pending);
        var sent = Assert.Single(_requests, r => r.Path.EndsWith("/packets", StringComparison.Ordinal)
            && r.Body?["payload"]?["header"]?["channel"]?.GetValue<string>() == WorkstationPolicy.Channels[2]);
        var packet = SignedPacket.FromJson(sent.Body);
        Assert.Equal(WorkstationsModule.ModuleId, packet.Envelope.ModuleId);
        Assert.Equal(WorkstationPolicy.Channels[2], packet.Payload["header"]!["channel"]!.GetValue<string>());
        var snapshot = packet.Payload["context"]!["workstations"]!["protection_state"]!;
        Assert.Equal("available", snapshot["state"]!.GetValue<string>());
        Assert.False(snapshot["components"]!["real_time_protection_enabled"]!.GetValue<bool>());
        Assert.Null(snapshot["components"]!["ioav_protection_enabled"]);
        Assert.Equal(1, reads);
        _assignment["collection_policy"]!["state"] = "paused";
        var paused = await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.False(paused.CollectionActive);
        Assert.Equal(0, paused.Captured);
        Assert.Equal(1, reads);
    }

    private sealed class AccountingSource(IRadiusTailSource inner) : IRadiusTailSource
    {
        public int Reads { get; private set; }
        public RadiusTailBatch Read(string directory, RadiusCursor cursor, int maximumRecords, bool allowExactBoundaryRecovery)
        { Reads++; return inner.Read(directory, cursor, maximumRecords, allowExactBoundaryRecovery); }
    }

    [Fact]
    public async Task NpsAndAccountingUseExistingDeliveryAndKeepEvidenceThroughLostReceiptRestartPauseDrain()
    {
        var npsStep = NpsTests.Scenario("nps-continuity-restart")["steps"]![0]!.AsObject();
        var radiusStep = NpsTests.Scenario("radius-blank-progress")["steps"]![0]!.AsObject();
        var events = new NpsTests.Events(npsStep) { OnRead = () => _clock.Now = _clock.Now.AddSeconds(1) }; _npsSource = events;
        var accounting = new AccountingSource(new RadiusTailSource(new RadiusMemoryFiles(radiusStep["files"]!.AsArray()))); _radiusSource = accounting;
        _assignment["assigned_modules"] = new JsonArray(new JsonObject { ["module_id"] = NpsPolicy.Nps, ["enabled"] = true, ["config"] = npsStep["config"]!.DeepClone() },
            new JsonObject { ["module_id"] = NpsPolicy.Accounting, ["enabled"] = true, ["config"] = radiusStep["config"]!.DeepClone() });
        _assignment["collection_policy"]!["rate_limit_per_minute"] = 100;
        var first = await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Null(first.ErrorCode); Assert.True(first.CollectionActive); Assert.Equal(4, first.Captured); Assert.Equal(4, first.Pending); Assert.Equal(0, _source.Reads);
        _receiptLost = true; _assignment["collection_policy"]!["state"] = "drain"; _requests.Clear();
        var lost = await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Equal(4, lost.Pending); Assert.Equal(0, lost.Captured); Assert.True(lost.DeliveryFailed);
        var sent = _requests.Where(r => r.Path.EndsWith("/packets", StringComparison.Ordinal)).Select(r => CanonicalJson.Serialize(r.Body)).ToArray();
        Assert.Equal(2, sent.Length); // Failed head of each module blocks its own followers.
        var eventReads = events.Reads; var accountingReads = accounting.Reads;
        _runtime!.Dispose(); _runtime = null; _assignment["collection_policy"]!["state"] = "paused"; _requests.Clear();
        var paused = await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Equal(4, paused.Pending); Assert.False(paused.CollectionActive);
        Assert.DoesNotContain(_requests, r => r.Path.EndsWith("/packets", StringComparison.Ordinal));
        _assignment["collection_policy"]!["state"] = "drain"; _receiptLost = false; _requests.Clear();
        var drained = await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Null(drained.ErrorCode); Assert.Equal(0, drained.Pending); Assert.Equal(0, drained.Captured);
        Assert.Equal(eventReads, events.Reads); Assert.Equal(accountingReads, accounting.Reads);
        var resent = _requests.Where(r => r.Path.EndsWith("/packets", StringComparison.Ordinal)).Select(r => CanonicalJson.Serialize(r.Body)).ToArray();
        Assert.All(sent, packet => Assert.Contains(packet, resent));
        Assert.Contains(_requests, r => r.Path.EndsWith("/policy-report", StringComparison.Ordinal) && r.Body!["collection_state"]!.ToString() == "paused");
    }

    private sealed class FileSource : IFileAuditEventSource
    {
        public int Reads { get; private set; }
        public SourceBatch Read(JsonObject progress,int limit)
        {
            Reads++;
            if (progress["record_id"] is not null) return new([]);
            var rows=Vectors.Load("file-audit-scenarios.json")[0]!["steps"]![0]!["rows"]!.AsArray();
            return new(rows.Select(x => new EventRow(x!["xml"]!.ToString(),x["bookmark"]!.ToString())).Take(limit).ToArray());
        }
    }

    [Fact]
    public async Task FileAuditUsesExistingQueueAndLostAckRestartPauseDrainKeepEvidence()
    {
        var source=new FileSource(); _fileSource=source;
        _assignment["collection_policy"]!["rate_limit_per_minute"]=10;
        _assignment["assigned_modules"]=new JsonArray(new JsonObject { ["module_id"]=FileAuditModule.ModuleId,["enabled"]=true,["config"]=FileAuditManagerTests.Config() });
        var first=await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Null(first.ErrorCode); Assert.Equal(2,first.Captured); Assert.Equal(2,first.Pending); Assert.Equal(0,_source.Reads);
        _runtime!.Dispose(); _runtime=null; _receiptLost=true; _requests.Clear();
        var retry=await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Equal(3,retry.Pending); // A new service cycle also persists its empty tail observation.
        Assert.All(_requests.Where(r => r.Path.EndsWith("/packets",StringComparison.Ordinal)),r => Assert.Equal(FileAuditModule.ModuleId,r.Body!["envelope"]!["module_id"]!.ToString()));
        _assignment["collection_policy"]!["state"]="paused"; var reads=source.Reads; _requests.Clear();
        var paused=await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.False(paused.CollectionActive); Assert.Equal(reads,source.Reads); Assert.Equal(3,paused.Pending);
        Assert.DoesNotContain(_requests,r => r.Path.EndsWith("/packets",StringComparison.Ordinal));
        _clock.Now=_clock.Now.AddMinutes(1); _receiptLost=false; _assignment["collection_policy"]!["state"]="drain";
        var drained=await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Null(drained.ErrorCode); Assert.Equal(0,drained.Pending); Assert.Equal(reads,source.Reads);
    }

    [Fact]
    public async Task FileAuditReportIsRetriedExactlyBeforeNewInventoryAfterLostResponse()
    {
        _assignment["assigned_modules"]=new JsonArray();
        _assignment["file_audit"]=FileAuditManagerTests.Request("check");
        _fileApi=new FileAuditManagerTests.FakeFileApi(Path.Combine(_options.StateDir,"file-audit"));
        _timeoutPath="/api/v1/agent/file-audit-report";
        var failed=await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.NotNull(failed.ErrorCode);
        var report=CanonicalJson.Serialize(_requests.Single(r => r.Path == _timeoutPath).Body);
        _runtime!.Dispose(); _runtime=null; _requests.Clear(); _timeoutPath=null;
        var retried=await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Null(retried.ErrorCode);
        Assert.Equal(report,CanonicalJson.Serialize(_requests.Single(r => r.Path.EndsWith("/file-audit-report",StringComparison.Ordinal)).Body));
        _requests.Clear(); await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.DoesNotContain(_requests,r => r.Path.EndsWith("/file-audit-report",StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("paused")]
    [InlineData("drain")]
    [InlineData("disabled")]
    public async Task SnapshotOnlyPolicyKeepsCheckInResponsiveAndPolicyCancelsTheSource(string action)
    {
        var reader = new SnapshotCaptureTests.BlockingReader(); _snapshotReader = reader;
        _assignment["assigned_modules"] = new JsonArray(new JsonObject { ["module_id"] = SnapshotPolicy.Ad, ["enabled"] = true, ["config"] = SnapshotModuleTests.Policy().Config });
        _assignment["rights_probe_request"] = new JsonObject { ["request_id"] = Guid.NewGuid().ToString() };
        var started = await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Null(started.ErrorCode); Assert.True(started.CollectionActive);
        Assert.Equal("unavailable", _requests.Single(r => r.Path.EndsWith("/policy-report", StringComparison.Ordinal)).Body!["rights_probe"]!["status"]!.GetValue<string>());
        await reader.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        _requests.Clear();
        var reading = await Runtime().RunCycleAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Null(reading.ErrorCode); Assert.Contains(_requests, r => r.Path.EndsWith("/identity", StringComparison.Ordinal));
        if (action == "disabled") _assignment["assigned_modules"]![0]!["enabled"] = false;
        else _assignment["collection_policy"]!["state"] = action;
        var paused = await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.False(paused.CollectionActive); await reader.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, _source.Reads);
    }

    private sealed class FailedSnapshotReader : IDirectorySnapshotReader
    {
        public int Attempts;

        public Task<JsonObject> ReadAsync(SnapshotPolicy policy, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Attempts);
            return Task.FromException<JsonObject>(SnapshotCaptureException.Describe(policy.ModuleId, "ldap_root_dse",
                new System.ComponentModel.Win32Exception(5, "fixture private details")));
        }
    }

    [Fact]
    public async Task SnapshotReasonReachesWarningAndStaysInStatusBetweenIdenticalFailures()
    {
        var reader = new FailedSnapshotReader();
        _snapshotReader = reader;
        _assignment["assigned_modules"] = new JsonArray(new JsonObject
        {
            ["module_id"] = SnapshotPolicy.Ad, ["enabled"] = true, ["config"] = SnapshotModuleTests.Policy().Config
        });
        _assignment["collection_policy"]!["interval_seconds"] = 1;
        var runtime = Runtime();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        const string code = "agent_ad_ldap_root_dse_failed";
        CycleStatus cycle;
        do
        {
            cycle = await runtime.RunCycleAsync(deadline.Token);
            if (cycle.ErrorCode is null) await Task.Delay(10, deadline.Token);
        } while (cycle.ErrorCode is null);
        Assert.Equal(code, cycle.ErrorCode);
        var detail = cycle.ErrorDetail;
        Assert.NotNull(detail);
        var betweenAttempts = await runtime.RunCycleAsync(deadline.Token);
        Assert.Null(betweenAttempts.ErrorCode);

        _clock.Now = _clock.Now.AddMinutes(2);
        var logger = new RecordingLogger();
        using var worker = new AgentWorker(runtime, logger);
        await worker.StartAsync(deadline.Token);
        var warning = await logger.Entry.Task.WaitAsync(deadline.Token);
        var next = await logger.SecondEntry.Task.WaitAsync(deadline.Token);
        await worker.StopAsync(deadline.Token);
        Assert.Equal(2, Volatile.Read(ref reader.Attempts));
        Assert.Equal(LogLevel.Warning, warning.Level);
        Assert.Null(warning.Exception);
        Assert.Contains(detail, warning.Message, StringComparison.Ordinal);
        Assert.Equal(LogLevel.Information, next.Level);
        var status = File.ReadAllText(Path.Combine(_options.StateDir, "status.json"));
        var failure = JsonNode.Parse(status)!["snapshot_errors"]![SnapshotPolicy.Ad]!;
        Assert.Equal(code, failure["error_code"]!.GetValue<string>());
        Assert.Equal(detail, failure["error_detail"]!.GetValue<string>());
        Assert.DoesNotContain("fixture private details", warning.Message);
        Assert.DoesNotContain("fixture private details", status);
    }

    [Fact]
    public async Task DisabledAssignmentStopsCaptureAndTerminalRefusalStopsTheCurrentCycle()
    {
        var first=await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Equal(1,first.Captured); Assert.Equal(1,first.Pending);
        _clock.Now=_clock.Now.AddSeconds(121); _moduleDisabled=true;
        var refused=await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Null(refused.ErrorCode); Assert.Equal(0,refused.Captured); Assert.Equal(0,refused.Pending);
        Assert.False(refused.CollectionActive); Assert.Equal(1,_source.Reads);
        _assignment["policy_revision"]=2;
        _assignment["assigned_modules"]![0]!["enabled"]=false;
        _runtime!.Dispose(); _runtime=null; _requests.Clear();
        var disabled=await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Null(disabled.ErrorCode); Assert.Equal(0,disabled.Captured); Assert.Equal(0,disabled.Pending);
        Assert.Equal(1,_source.Reads);
        Assert.DoesNotContain(_requests,r=>r.Path.EndsWith("/packets",StringComparison.Ordinal));
    }

    [Fact]
    public async Task FirstStartEnrollsThenCheckInAuthorizesCaptureAndRestartKeepsRegistration()
    {
        var first = await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Null(first.ErrorCode);
        Assert.Equal(1, first.Captured);
        Assert.Equal(1, first.Pending);
        Assert.False(File.Exists(_options.TokenFile));
        Assert.Equal(new[] { "/api/v1/agent/enroll", "/api/v1/agent/identity", "/api/v1/agent/policy-report", "/api/v1/agent/windows-audit-report" }, _requests.Select(r => r.Path));
        var diagnostic = JsonNode.Parse(File.ReadAllText(Path.Combine(_options.StateDir, "last-cycle.json")))!;
        Assert.Null(diagnostic["error_code"]);
        Assert.True(diagnostic["collection_active"]!.GetValue<bool>());
        Assert.Equal(1, diagnostic["pending_packets"]!.GetValue<int>());
        var prepared = AgentRuntime.CreateIdentityStore(_options).Prepare();
        _runtime!.Dispose(); _runtime = null; _requests.Clear();
        var next = await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Null(next.ErrorCode);
        Assert.DoesNotContain(_requests, item => item.Path.EndsWith("/enroll", StringComparison.Ordinal));
        Assert.Equal(prepared, AgentRuntime.CreateIdentityStore(_options).Prepare());
        Assert.Contains(_requests, item => item.Path.EndsWith("/packets", StringComparison.Ordinal));
    }

    [Fact]
    public async Task PauseHoldsDeliveryDrainWaitsForTheExactReceiptAndScheduleUsesServerInterval()
    {
        await Runtime().RunCycleAsync(CancellationToken.None);
        _requests.Clear();
        _assignment = Assignment("paused");
        var paused = await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.False(paused.CollectionActive);
        Assert.Equal(1, paused.Pending);
        Assert.Equal(1, _source.Reads);
        Assert.DoesNotContain(_requests, item => item.Path.EndsWith("/packets", StringComparison.Ordinal));
        _assignment = Assignment("drain"); _receiptLost = true; _requests.Clear();
        var held = await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Equal(1, held.Pending);
        Assert.DoesNotContain(_requests, item => item.Path.EndsWith("/policy-report", StringComparison.Ordinal));
        _receiptLost = false; _requests.Clear();
        var drained = await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Equal(0, drained.Pending);
        Assert.Equal("paused", _requests.Single(r => r.Path.EndsWith("/policy-report", StringComparison.Ordinal)).Body!["collection_state"]!.GetValue<string>());
        _assignment = Assignment();
        var early = await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Equal(0, early.Captured);
        _clock.Now = _clock.Now.AddSeconds(121);
        Assert.Equal(1, (await Runtime().RunCycleAsync(CancellationToken.None)).Captured);
    }

    [Fact]
    public async Task InvalidOrWrongAgentPolicyStopsCaptureAndDelivery()
    {
        await Runtime().RunCycleAsync(CancellationToken.None);
        _requests.Clear();
        _assignment["agent_id"] = Helpers.HostId;
        var denied = await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Equal("agent_module_identity_mismatch", denied.ErrorCode);
        Assert.Equal(1, denied.Pending);
        Assert.Single(_requests);
        Assert.Equal(1, _source.Reads);
    }

    [Fact]
    public async Task TransportSetupFailureCanRecoverWithoutEnrollingAgain()
    {
        _failNextSession = true;
        Assert.Equal("agent_config_invalid", (await Runtime().RunCycleAsync(CancellationToken.None)).ErrorCode);
        Assert.False(File.Exists(_options.TokenFile));
        var recovered = await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Null(recovered.ErrorCode);
        Assert.Equal(1, recovered.Captured);
        Assert.Single(_requests, item => item.Path.EndsWith("/enroll", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ReinstallWithAnExpiredBootstrapKeepsThePersistedIdentityAndKey()
    {
        Assert.Null((await Runtime().RunCycleAsync(CancellationToken.None)).ErrorCode);
        var prepared = AgentRuntime.CreateIdentityStore(_options).Prepare();
        using var enrolled = AgentRuntime.CreateIdentityStore(_options).Load()!;
        var thumbprint = enrolled.Certificate.Thumbprint;
        _runtime!.Dispose(); _runtime = null; _requests.Clear();
        // Replacing binaries/configuration must not replace ProgramData identity or depend on bootstrap freshness.
        File.WriteAllText(_options.TokenFile!, new string('t', 43));
        File.SetLastWriteTimeUtc(_options.TokenFile!, Helpers.Now.AddHours(-2).UtcDateTime);
        Assert.Null((await Runtime().RunCycleAsync(CancellationToken.None)).ErrorCode);
        Assert.DoesNotContain(_requests, r => r.Path == "/api/v1/agent/enroll");
        Assert.Equal(prepared, AgentRuntime.CreateIdentityStore(_options).Prepare());
        using var reloaded = AgentRuntime.CreateIdentityStore(_options).Load()!;
        Assert.Equal(thumbprint, reloaded.Certificate.Thumbprint);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Conflict)]
    public async Task AServerConsumedTokenWithoutALocalIdentityRequiresReenrollment(HttpStatusCode status)
    {
        _enrollStatus = status;
        Assert.Equal("agent_identity_missing_reenroll_required", (await Runtime().RunCycleAsync(CancellationToken.None)).ErrorCode);
        Assert.False(File.Exists(Path.Combine(_options.StateDir, "identity.json")));
        Assert.True(File.Exists(_options.TokenFile));
    }

    [Fact]
    public async Task TheFirstSuccessfulCycleIsLoggedAtInformation()
    {
        var logger = new RecordingLogger();
        using var worker = new AgentWorker(Runtime(), logger);
        await worker.StartAsync(CancellationToken.None);
        var logged = await logger.Entry.Task.WaitAsync(TimeSpan.FromSeconds(5));
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await worker.StopAsync(stop.Token);
        Assert.Equal(LogLevel.Information, logged.Level);
        Assert.Contains("ok", logged.Message, StringComparison.Ordinal);
        Assert.Null(logged.Exception);
        Assert.DoesNotContain(new string('t', 43), logged.Message, StringComparison.Ordinal);
    }

    [WindowsFact]
    public async Task ALockedTokenFileDoesNotBlockCheckInAndIsRemovedOnTheNextCycle()
    {
        using (var locked = new FileStream(_options.TokenFile!, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            var first = await Runtime().RunCycleAsync(CancellationToken.None);
            Assert.Equal("agent_bootstrap_cleanup_failed", first.ErrorCode);
            Assert.Contains(_requests, r => r.Path == "/api/v1/agent/identity");
            Assert.True(File.Exists(_options.TokenFile));
        }
        Assert.Null((await Runtime().RunCycleAsync(CancellationToken.None)).ErrorCode);
        Assert.False(File.Exists(_options.TokenFile));
        Assert.Single(_requests, r => r.Path == "/api/v1/agent/enroll");
    }

    [WindowsFact]
    public async Task AFailedDiagnosticWriteIsReportedAndRetriedWithoutLeavingAPartialFile()
    {
        await Runtime().RunCycleAsync(CancellationToken.None);
        var path = Path.Combine(_options.StateDir, "last-cycle.json");
        var original = File.ReadAllText(path);
        using (var locked = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            var status = await Runtime().RunCycleAsync(CancellationToken.None);
            Assert.Equal("agent_cycle_status_write_failed", status.ErrorCode);
            Assert.Equal(original, File.ReadAllText(path));
            Assert.Equal("agent_cycle_status_write_failed", JsonNode.Parse(File.ReadAllText(Path.Combine(_options.StateDir, "status.json")))!["error_code"]!.GetValue<string>());
            Assert.Empty(Directory.GetFiles(_options.StateDir, "*.tmp"));
        }
        _clock.Now = _clock.Now.AddSeconds(1);
        Assert.Null((await Runtime().RunCycleAsync(CancellationToken.None)).ErrorCode);
        Assert.NotEqual(original, File.ReadAllText(path));
    }

    [Theory]
    [InlineData("/api/v1/agent/enroll")]
    [InlineData("/api/v1/agent/renew")]
    [InlineData("/api/v1/agent/identity")]
    [InlineData("/api/v1/agent/policy-report")]
    [InlineData("/api/v1/agent/packets")]
    [InlineData("/api/v1/agent/windows-audit-report")]
    public async Task HttpTimeoutIsReportedInTheCycleAndItsDurableDiagnostic(string path)
    {
        if (path is "/api/v1/agent/packets" or "/api/v1/agent/renew") await Runtime().RunCycleAsync(CancellationToken.None);
        if (path == "/api/v1/agent/renew") _clock.Now = _clock.Now.AddDays(28);
        _timeoutPath = path;
        var status = await Runtime().RunCycleAsync(CancellationToken.None);
        Assert.Equal("agent_http_timeout", status.ErrorCode);
        var diagnostic = JsonNode.Parse(File.ReadAllText(Path.Combine(_options.StateDir, "last-cycle.json")))!;
        Assert.Equal("agent_http_timeout", diagnostic["error_code"]!.GetValue<string>());
        if (path == "/api/v1/agent/enroll") Assert.True(File.Exists(_options.TokenFile));
        else Assert.False(File.Exists(_options.TokenFile));
        if (path == "/api/v1/agent/packets") Assert.Equal(1, status.Pending);
    }

    [Fact]
    public async Task RejectedRenewalKeepsTheIdentityAndReportsTheCertificateCodeInWarningAndLastCycle()
    {
        await Runtime().RunCycleAsync(CancellationToken.None);
        var path = Path.Combine(_options.StateDir, "identity.json");
        var saved = File.ReadAllBytes(path);
        _clock.Now = _clock.Now.AddDays(28);
        _renewalResponse = _ca.Issue(AgentRuntime.CreateIdentityStore(_options), extraSan: true);
        var logger = new RecordingLogger();
        using var worker = new AgentWorker(Runtime(), logger);
        await worker.StartAsync(CancellationToken.None);
        var logged = await logger.Entry.Task.WaitAsync(TimeSpan.FromSeconds(5));
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await worker.StopAsync(stop.Token);
        Assert.Equal(LogLevel.Warning, logged.Level);
        Assert.Contains("agent_certificate_invalid_san", logged.Message, StringComparison.Ordinal);
        Assert.Null(logged.Exception);
        var raw = File.ReadAllText(Path.Combine(_options.StateDir, "last-cycle.json"));
        Assert.Equal("agent_certificate_invalid_san", JsonNode.Parse(raw)!["error_code"]!.GetValue<string>());
        Assert.DoesNotContain("CERTIFICATE", raw, StringComparison.Ordinal);
        Assert.Equal(saved, File.ReadAllBytes(path));
    }

    [Fact]
    public async Task ZipOfferIsRejectedWithTheRunningMsiVersion()
    {
        _assignment["agent_update"] = new JsonObject { ["sha256"] = new string('a', 64), ["version"] = "9.0.0" };
        Assert.Null((await Runtime().RunCycleAsync(CancellationToken.None)).ErrorCode);
        var report = _requests.Single(item => item.Path.EndsWith("/update-result", StringComparison.Ordinal)).Body!;
        Assert.Equal("rejected", report["status"]!.GetValue<string>());
        Assert.Equal("agent_update_msi_required", report["reason"]!.GetValue<string>());
        Assert.Equal(typeof(AgentRuntime).Assembly.GetName().Version!.ToString(3), report["version"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("{\"batch_size\":true}")]
    [InlineData("{\"interval_seconds\":0}")]
    [InlineData("{\"state\":\"unknown\"}")]
    [InlineData("{\"unexpected\":1}")]
    public void CollectionPolicyRejectsInvalidTypesAndUnknownKeys(string json) => Assert.Throws<AgentException>(() => CollectionControl.Parse(JsonNode.Parse(json)));
}
