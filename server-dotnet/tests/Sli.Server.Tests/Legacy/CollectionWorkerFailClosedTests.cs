using System.ComponentModel;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Legacy;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Legacy;

// Behavior vectors from tests/sources/test_collection_worker_fail_closed.py.
public sealed class CollectionWorkerFailClosedTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    [Theory]
    [InlineData("DC2: (1749, 'EvtOpenSession', 'Неправильный контекст безопасности.')")]
    [InlineData("DC1: код возврата 74; Collection blocked before backend fallback/import/cursor update: windows_security_context_invalid")]
    [InlineData("The security context has expired.")]
    public void SecurityContextErrorsDisableAutomaticRetry(string error)
    {
        var decision = LegacyCollectionFailurePolicy.Classify([error]);
        Assert.True(decision.Blocked); Assert.Equal("windows_security_context_invalid", decision.Code);
        Assert.Equal("security_context_invalid", decision.Phase); Assert.Contains("Автоматический повтор отключён", decision.OperatorAction);
    }
    private sealed class NativeHresult : Exception { public NativeHresult() => HResult = unchecked((int)0x800706D5); }
    [Fact] public void NumericErrorsDoNotDependOnLocalizedText()
    {
        Assert.True(LegacyCollectionFailurePolicy.Classify([new Win32Exception(1749, "localized")]).Blocked);
        Assert.True(LegacyCollectionFailurePolicy.Classify([new NativeHresult()]).Blocked);
        Assert.False(LegacyCollectionFailurePolicy.Classify(["bounded channel timeout", null]).Blocked);
    }
    [Theory] [InlineData(1326)] [InlineData(1909)]
    public void AuthenticationFailuresCannotBecomeAutomaticRetries(int code) =>
        Assert.Equal("windows_event_log_authentication_failed", LegacyCollectionFailurePolicy.Classify([new Win32Exception(code, "localized")]).Code);

    private sealed class Session(bool observed = true, bool denied = false) : ILegacyEventSession
    {
        public string? Channel; public bool Closed;
        public bool ReadOne(string channel) { Channel = channel; if (denied) throw new Win32Exception(5, "EvtQuery access denied"); return observed; }
        public void Dispose() => Closed = true;
    }
    [Theory] [InlineData(true)] [InlineData(false)]
    public void PreflightActuallyReadsSecurityAndClosesSessionEvenForEmptyLog(bool observed)
    {
        var session = new Session(observed); string? target = null;
        var result = LegacyWindowsContext.Probe("dc.example.test", server => { target = server; return session; });
        Assert.Equal("dc.example.test", target); Assert.Equal("Security", session.Channel); Assert.True(session.Closed);
        Assert.Equal("ok", result.Text("status")); Assert.Equal("verified", result.Text("query_access")); Assert.Equal(observed, result.Flag("event_observed"));
    }
    [Fact] public void QueryAccessDeniedIsNotSuccessfulSessionOpen()
    {
        var session = new Session(denied: true);
        var result = LegacyWindowsContext.Probe("dc.example.test", _ => session);
        Assert.Equal("failed", result.Text("status")); Assert.Equal("windows_event_log_access_denied", result.Text("failure_code"));
        Assert.Equal(5, result.Number("winerror")); Assert.True(session.Closed);
    }
    [Fact] public void PartialBatchSecurityFailureCannotBeAcceptedForImport()
    {
        // Security succeeded with five events; System failed. The entire batch is rejected.
        int imported = 0; bool cursorAdvanced = false;
        Assert.Throws<InvalidOperationException>(() => {
            LegacyCollectionFailurePolicy.RequireImportAllowed(["(1749, 'EvtOpenSession', 'The security context has expired.')"]);
            imported += 5; cursorAdvanced = true;
        });
        Assert.Equal(0, imported); Assert.False(cursorAdvanced);
    }
    private sealed class Windows : ILegacyWindowsContext
    {
        public string[] Reasons = []; public int Probes;
        public JsonObject Result = new() { ["status"] = "ok", ["query_access"] = "verified" };
        public string[] IdentityReasons() => Reasons;
        public JsonObject Probe(string server) { Probes++; return (JsonObject)Result.DeepClone(); }
    }
    private sealed class State : ILegacyCollectionState
    {
        public JsonObject? Block; public JsonObject? Evidence; public JsonObject? Finished;
        public int Starts, Clears, Activations; public bool FailActivation; public string? Worker, ProbeServer, Actor;
        public Task<JsonObject?> BlockAsync(CancellationToken ct) => Task.FromResult(Block is null ? null : (JsonObject)Block.DeepClone());
        public Task ActivateAsync(string code, string action, string worker, string? server, int? job, JsonObject evidence, CancellationToken ct)
        { Activations++; Worker = worker; Evidence = evidence; if (FailActivation) throw new IOException("test-only-private-detail");
            Block = new() { ["reason_code"] = code, ["operator_action"] = action }; return Task.CompletedTask; }
        public Task ClearAsync(string server, string actor, CancellationToken ct) { Clears++; ProbeServer = server; Actor = actor; Block = null; return Task.CompletedTask; }
        public Task StartAsync(string run, string worker, LegacyJobInput input, CancellationToken ct) { Starts++; return Task.CompletedTask; }
        public Task FinishAsync(string run, JsonObject result, CancellationToken ct) { Finished = (JsonObject)result.DeepClone(); return Task.CompletedTask; }
    }
    [Fact] public async Task ExactIdentityMismatchActivatesBlockBeforeRemoteProbe()
    {
        const string sid = "S-1-5-21-100000001-200000002-300000003-1001";
        var reasons = LegacyWindowsContext.ValidateIdentity("EXAMPLE\\operator", sid, "EXAMPLE\\operator", sid + "0", true);
        Assert.Equal(["sid_mismatch"], reasons);
        var state = new State(); var windows = new Windows { Reasons = reasons };
        var result = await new LegacyCollectionPreflight(windows, state).RunAsync("dc.example.test", "test-worker", Ct);
        Assert.Equal("failed", result.Text("status")); Assert.Equal("windows_security_context_invalid", result.Text("failure_code"));
        Assert.Equal("test-worker", state.Worker); Assert.Equal("sid_mismatch", state.Evidence!["identity_reasons"]![0]!.GetValue<string>());
        Assert.Equal(0, windows.Probes); Assert.Equal(1, state.Activations);
    }
    [Fact] public async Task SuccessfulPreflightClearsMatchingBlockUsingTheSameProbe()
    {
        var state = new State { Block = new() { ["reason_code"] = "windows_security_context_invalid" } }; var windows = new Windows();
        Assert.Equal("ok", (await new LegacyCollectionPreflight(windows, state).RunAsync("dc.example.test", "test-worker", Ct)).Text("status"));
        Assert.Equal(1, windows.Probes); Assert.Equal(1, state.Clears); Assert.Equal("dc.example.test", state.ProbeServer);
        Assert.StartsWith("worker-preflight:", state.Actor);
    }
    [Fact] public async Task SuccessfulProbeNeverClearsUnrelatedBlock()
    {
        var state = new State { Block = new() { ["reason_code"] = "disk_pressure_stop" } };
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => new LegacyCollectionPreflight(new Windows(), state).RunAsync("dc.example.test", "test-worker", Ct));
        Assert.Contains("cannot be cleared", error.Message); Assert.Equal(0, state.Clears);
    }
    [Fact] public async Task CredentialBlockIsNotRetriedByWorkerPreflight()
    {
        var state = new State { Block = new() { ["reason_code"] = "windows_event_log_access_denied" } }; var windows = new Windows();
        Assert.Equal("failed", (await new LegacyCollectionPreflight(windows, state).RunAsync("dc.example.test", "test-worker", Ct)).Text("status"));
        Assert.Equal(0, windows.Probes); Assert.Equal(0, state.Clears);
    }
    private sealed class Jobs(LegacyJobStore store) : ILegacyJobs
    {
        public int Calls; public LegacyJobInput? Input; public JsonObject? Rejection;
        public Task<JsonObject> CreateAsync(bool collect, LegacyJobInput input, CancellationToken ct) => throw new InvalidOperationException("worker must not enqueue background job");
        public Task<JsonObject> CreateExternalAsync(LegacyJobInput input, CancellationToken ct)
        { Calls++; Input = input; return Task.FromResult(Rejection ?? store.Create("collect_all_dc_logs:external_worker", input)); }
    }
    private sealed class Execution(LegacyJobStore store, State state) : ILegacyJobExecution
    {
        public string? Error; public bool Durable; public TaskCompletionSource? Release; public int Calls;
        public async Task RunAsync(LegacyWork work, CancellationToken ct, bool collectionOwnerHeld = false)
        {
            Calls++; store.Update(work.Id, j => { j["status"] = "running"; j["phase"] = "collection"; });
            if (Release is not null) await Release.Task.WaitAsync(ct);
            if (Durable) state.Block = new() { ["reason_code"] = "windows_security_context_invalid", ["operator_action"] = "operator recovery required" };
            store.Update(work.Id, j => { j["status"] = Error is null ? "completed" : "failed"; j["phase"] = "done"; j["duration_ms"] = 100L;
                if (Error is not null) j["errors"]!.AsArray().Add(Error); });
        }
    }
    private sealed class Heartbeat : ILegacyHeartbeat
    {
        public readonly List<JsonObject> Rows = []; public Action? OnRunning;
        public Task WriteAsync(string name, string worker, string status, string phase, int interval, JsonObject details, CancellationToken ct)
        { Rows.Add(new() { ["status"] = status, ["phase"] = phase, ["details"] = details.DeepClone() }); if (status == "running") OnRunning?.Invoke(); return Task.CompletedTask; }
    }
    private sealed class Fixture
    {
        public readonly LegacyJobStore Store = new(); public readonly State State = new(); public readonly Windows Windows = new(); public readonly Heartbeat Heartbeat = new();
        public readonly Jobs Jobs; public readonly Execution Execution; public readonly LegacyCollectionWorker Worker;
        public Fixture() { Jobs = new(Store); Execution = new(Store, State); Worker = new(Jobs, Execution, Store, State, new(Windows, State), Heartbeat); }
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task TerminalJobRechecksDurableBlockAndPersistsBlockedRun(bool durable)
    {
        var f = new Fixture(); f.Execution.Durable = durable;
        f.Execution.Error = durable ? "localized collector failure without stable text" : "(1749, 'EvtOpenSession', 'Неправильный контекст безопасности.')";
        var result = await f.Worker.RunCycleAsync(new(["dc.example.test"], 1, 321), "test-worker", 30, Ct);
        Assert.Equal("blocked", result.Text("status")); Assert.Equal("windows_security_context_invalid", result.Text("reason"));
        Assert.Equal(durable ? "operator_action_required" : "security_context_invalid", result.Text("phase"));
        if (durable) Assert.Equal("operator recovery required", result.Text("operator_action"));
        Assert.Equal(result.ToJsonString(), f.State.Finished!.ToJsonString());
    }
    [Fact] public async Task RunningJobEmitsHeartbeatBeforeItCompletesAndKeepsRequestedCeiling()
    {
        var f = new Fixture(); f.Execution.Release = new();
        f.Heartbeat.OnRunning = () => { Assert.False(f.Execution.Release.Task.IsCompleted); f.Execution.Release.SetResult(); };
        var result = await f.Worker.RunCycleAsync(new(["dc.example.test"], 2, 321), "test-worker", 30, Ct);
        Assert.Equal("completed", result.Text("status")); Assert.Equal(321, f.Jobs.Input!.MaxEvents); Assert.Equal(2, f.Jobs.Input.Hours);
        var heartbeat = Assert.Single(f.Heartbeat.Rows); Assert.Equal("collection", heartbeat.Text("phase")); Assert.Equal(1, heartbeat["details"].Number("job_id"));
    }
    [Theory] [InlineData("")] [InlineData("dc.example.test")]
    public async Task MissingOrFailedPreflightStopsBeforeJobCreation(string server)
    {
        var f = new Fixture(); f.Windows.Reasons = ["sid_mismatch"];
        Assert.Equal(2, await f.Worker.RunAsync(server, "test-worker", new([], 1, 50_000), true, 30, Ct));
        Assert.Equal(0, f.Jobs.Calls); Assert.Equal(0, f.State.Starts); Assert.Equal(0, f.Execution.Calls);
        var last = f.Heartbeat.Rows.Last(); Assert.Equal("blocked", last.Text("status")); Assert.Equal("security_context_preflight", last.Text("phase"));
    }
    [Fact] public async Task ContinuousWorkerExitsImmediatelyAfterBlockedCycle()
    {
        var f = new Fixture(); f.Execution.Error = "windows_security_context_invalid";
        Assert.Equal(2, await f.Worker.RunAsync("dc.example.test", "test-worker", new(["dc.example.test"], 1, 50_000), false, int.MaxValue, Ct));
        Assert.Equal(1, f.Jobs.Calls); Assert.Equal("blocked", f.Heartbeat.Rows.Last().Text("status"));
        Assert.Equal("security_context_invalid", f.Heartbeat.Rows.Last().Text("phase"));
    }
    [Fact] public async Task AdmissionGuardFailureWithoutJobIdIsPersistedWithoutReadingAJob()
    {
        var f = new Fixture(); f.Jobs.Rejection = new() { ["status"] = "blocked", ["phase"] = "admission", ["reason"] = "collection_guard_error" };
        var result = await f.Worker.RunCycleAsync(new([], 1, 321), "test-worker", 30, Ct);
        Assert.Equal("blocked", result.Text("status")); Assert.Equal("admission", f.State.Finished!.Text("phase"));
        Assert.False(result.ContainsKey("job_id")); Assert.Equal(0, f.Execution.Calls);
    }
    private sealed class Environment : ILegacyEnvironment
    {
        public int Targets; public bool Throw, SecurityError; public string? Block; public bool Allowed = true;
        public Task<string[]> TargetsAsync(CancellationToken ct) { Targets++; return Task.FromResult(new[] { "dc.example.test" }); }
        public Task<string?> CollectionBlockAsync(CancellationToken ct) => SecurityError ? throw new Win32Exception(1749, "localized test-only-private-detail") : Task.FromResult(Block);
        public Task<JsonObject> DiskGuardAsync(CancellationToken ct) => Throw ? throw new IOException("test-only-private-detail") :
            Task.FromResult(new JsonObject { ["collection_allowed"] = Allowed, ["reason"] = Allowed ? null : "disk_pressure_threshold" });
    }
    private sealed class Audit : ILegacyAudit { public Task AppendAsync(string action, string status, JsonObject job, CancellationToken ct) => Task.CompletedTask; }
    private static LegacySettings Settings(bool enable = false) => new(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
        ["Sli:Legacy:SLI_LEGACY_COLLECTION_DISABLED"] = "0", ["Sli:Legacy:ADLOG_DISABLE_COLLECTION"] = enable ? "0" : "1",
        ["Sli:Legacy:ADLOG_ACQUISITION_DISABLED"] = "0", ["Sli:Legacy:ADLOG_ENABLE_POSTGRES_COLLECTION"] = "1",
        ["Sli:Legacy:SLI_AD_DC_AGENT_IMPORT_ENABLED"] = "0" }).Build());
    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task AdmissionRejectionDoesNotDiscoverPersistOrEnqueue(bool throws)
    {
        var environment = new Environment { Allowed = false, Throw = throws }; var store = new LegacyJobStore(); var queue = new LegacyWorkQueue();
        var result = await new LegacyJobs(store, queue, Settings(), environment, new Audit()).CreateAsync(true, new([], 1, 321), Ct);
        Assert.Equal(throws ? "blocked" : "skipped", result.Text("status"));
        Assert.Equal(throws ? "collection_guard_error" : "disk_pressure_threshold", result.Text("reason"));
        if (throws) Assert.Equal("IOException", result.Text("error_type"));
        Assert.False(result.ContainsKey("id")); Assert.Empty(store.List()); Assert.Equal(0, environment.Targets);
        Assert.DoesNotContain("private-detail", result.ToJsonString());
        // A queued work item would be readable even after cancellation.
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        await using var reader = queue.ReadAsync(cancel.Token).GetAsyncEnumerator(cancel.Token);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await reader.MoveNextAsync());
    }
    [Fact] public async Task DurableSecurityBlockRemainsVisibleWithEnvironmentCollectionDisabled()
    {
        var environment = new Environment { Block = "windows_security_context_invalid" }; var store = new LegacyJobStore();
        var result = await new LegacyJobs(store, new(), Settings(), environment, new Audit()).CreateAsync(true, new([], 1, 321), Ct);
        Assert.Equal("windows_security_context_invalid", result.Text("reason")); Assert.Equal("blocked", result.Text("status"));
        Assert.Empty(store.List()); Assert.Equal(0, environment.Targets);
    }
    [Fact] public async Task AllowedAdmissionPreservesCallerRequestAndQueuesExactlyOneJobOnSupportedPlatform()
    {
        var store = new LegacyJobStore(); var queue = new LegacyWorkQueue();
        var result = await new LegacyJobs(store, queue, Settings(enable: true), new Environment(), new Audit())
            .CreateAsync(true, new(["dc.example.test"], 2, 321), Ct);
        Assert.Single(store.List()); Assert.Equal(321, result.Number("max_events_per_channel")); Assert.Equal(2, result.Number("hours"));
        if (OperatingSystem.IsWindows()) {
            Assert.Equal("queued", result.Text("status"));
            await using var reader = queue.ReadAsync(Ct).GetAsyncEnumerator(Ct);
            Assert.True(await reader.MoveNextAsync()); Assert.Equal(result.Number("id"), reader.Current.Id);
            Assert.True(reader.Current.Collect); Assert.Equal(321, reader.Current.Input.MaxEvents); Assert.Equal("manual", reader.Current.Reason);
        } else {
            Assert.Equal("skipped", result.Text("status")); Assert.Equal("acquisition_disabled", result.Text("skipped_reason"));
        }
    }
    private sealed class Connections : IPostgresConnectionFactory { public int Calls; public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) { Calls++; throw new InvalidOperationException("unexpected database access"); } }
    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task QueuedJobRechecksAdmissionBeforeDatabaseOrAcquisition(bool throws)
    {
        var environment = new Environment { Allowed = false, Throw = throws }; var store = new LegacyJobStore(); var connections = new Connections();
        var input = new LegacyJobInput(["dc.example.test"], 1, 321); store.Create("collect_all_dc_logs:external_worker", input);
        await new LegacyJobExecution(store, Settings(), environment, null!, null!, null!, connections, NullLogger<LegacyJobExecution>.Instance)
            .RunAsync(new(1, true, input), Ct);
        var result = store.Get(1)!; Assert.Equal(throws ? "blocked" : "skipped", result.Text("status"));
        Assert.Equal(throws ? "collection_guard_error" : "disk_pressure_threshold", result.Text("skipped_reason")); Assert.Equal(0, connections.Calls);
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task ExecutionKeepsTerminalBlockEvenWhenDurablePersistenceFails(bool persistenceFails)
    {
        var state = new State { FailActivation = persistenceFails }; var store = new LegacyJobStore(); var connections = new Connections();
        var input = new LegacyJobInput(["dc.example.test"], 1, 321); store.Create("collect_all_dc_logs:external_worker", input);
        await new LegacyJobExecution(store, Settings(), new Environment { SecurityError = true }, null!, null!, null!, connections,
            NullLogger<LegacyJobExecution>.Instance, state).RunAsync(new(1, true, input), Ct);
        var result = store.Get(1)!; Assert.Equal("blocked", result.Text("status")); Assert.Equal("security_context_invalid", result.Text("phase"));
        Assert.Equal("windows_security_context_invalid", result.Text("reason")); Assert.Equal(1, state.Activations);
        if (!persistenceFails) Assert.Equal("windows_security_context_invalid", state.Block!.Text("reason_code"));
        Assert.Equal(0, connections.Calls); Assert.Equal(0, result.Number("events_collected")); Assert.Null(result["analysis_status"]);
        Assert.DoesNotContain("private-detail", result.ToJsonString());
    }

    private sealed class Database : ISemanticDatabase, ISemanticSession
    {
        public readonly List<(string Sql, object?[] Values)> Statements = []; public int Commits;
        public JsonArray BlockRows = []; public bool FailRead;
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct) => FailRead ? throw new IOException("test-only-private-detail") : Task.FromResult<ISemanticSession>(this);
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        { Statements.Add((sql, values)); return Task.FromResult(sql.StartsWith("select", StringComparison.Ordinal) ? (JsonArray)BlockRows.DeepClone() : new JsonArray()); }
        public Task CommitAsync(CancellationToken ct) { Commits++; return Task.CompletedTask; }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    [Fact] public async Task DurableBlockPersistenceUsesExistingSchemaAndDropsPrivateEvidence()
    {
        var db = new Database(); var state = new LegacyCollectionState(db);
        await state.ActivateAsync("windows_security_context_invalid", "operator action", "test-worker", "dc.example.test", 7,
            new() { ["failure_code"] = "windows_security_context_invalid", ["failure_scope"] = "worker_identity",
                ["identity_reasons"] = new JsonArray("sid_mismatch"), ["private_data"] = "test-only-private-detail" }, Ct);
        var insert = Assert.Single(db.Statements);
        Assert.Contains("on conflict(singleton_id)", insert.Sql); Assert.Contains("observed_count+1", insert.Sql);
        Assert.Contains("'operator_recovery_required'", insert.Sql); Assert.Equal(1, db.Commits);
        Assert.DoesNotContain("private-detail", insert.Sql); var evidence = Assert.IsType<JsonObject>(insert.Values[5]);
        Assert.Equal(2, evidence.Count); Assert.Equal("worker_identity", evidence.Text("failure_scope"));
    }
    [Theory] [InlineData("disk_pressure_stop", true)] [InlineData("windows_security_context_invalid", false)]
    public async Task DurableClearRechecksLockedReasonAndDoesNotOverwriteUnrelatedBlock(string reason, bool rejected)
    {
        var db = new Database { BlockRows = new(new JsonObject { ["active"] = true, ["reason_code"] = reason }) };
        var state = new LegacyCollectionState(db);
        if (rejected) await Assert.ThrowsAsync<InvalidOperationException>(() => state.ClearAsync("dc.example.test", "worker-preflight:operator", Ct));
        else await state.ClearAsync("dc.example.test", "worker-preflight:operator", Ct);
        Assert.Contains("for update", db.Statements[0].Sql);
        Assert.Equal(rejected ? 1 : 2, db.Statements.Count); Assert.Equal(rejected ? 0 : 1, db.Commits);
    }
    [Fact] public async Task AlreadyClearedBlockIsIdempotent()
    {
        var db = new Database { BlockRows = new(new JsonObject { ["active"] = false, ["reason_code"] = "windows_security_context_invalid" }) };
        await new LegacyCollectionState(db).ClearAsync("dc.example.test", "worker-preflight:operator", Ct);
        Assert.Single(db.Statements); Assert.Equal(1, db.Commits);
    }
    [Fact] public async Task GuardErrorIsWrittenToRunHistoryWithoutJobId()
    {
        var db = new Database(); var state = new LegacyCollectionState(db);
        await state.StartAsync("test-run", "test-worker", new([], 1, 321), Ct);
        await state.FinishAsync("test-run", new() { ["status"] = "blocked", ["phase"] = "admission", ["reason"] = "collection_guard_error" }, Ct);
        Assert.Equal(2, db.Commits); var update = db.Statements[1];
        Assert.Equal("blocked", update.Values[1]); Assert.Equal("admission", update.Values[2]); Assert.Null(update.Values[3]);
        Assert.Equal("collection_guard_error", Assert.IsType<JsonArray>(update.Values[5])[0]!.GetValue<string>());
    }
    [Fact] public async Task UnreadableDurableBlockFailsClosedWithoutEchoingDatabaseError()
    {
        var result = await new LegacyCollectionState(new Database { FailRead = true }).BlockAsync(Ct);
        Assert.Equal("runtime_collection_block_contract_unavailable", result!.Text("reason_code"));
        Assert.DoesNotContain("private-detail", result!.ToJsonString());
    }
}
