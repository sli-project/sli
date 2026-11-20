using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Hosting;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Vectors from tests/semantic/test_semantic_continuous_production.py.
public sealed class SemanticContinuousProductionTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static SemanticRuntimeSettings Settings(string mode) => new(true, true, false,
        mode != "facts-v1", mode == "findings-v1", mode == "findings-v1");
    private static JsonObject Guard() => new() {
        ["facts_schema_ready"] = true, ["processor_version_gate_schema_ready"] = true, ["facts_capability_ready"] = true,
        ["investigation_schema_ready"] = true, ["investigation_capability_ready"] = true,
        ["investigation_rule_lock_schema_ready"] = true, ["investigation_rule_lock_capability_ready"] = true,
        ["investigation_context_schema_ready"] = true, ["investigation_context_capability_ready"] = true
    };
    private sealed class Session(JsonObject guard) : ISemanticSession
    {
        internal readonly List<string> Queries = [];
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values) {
            ct.ThrowIfCancellationRequested(); Queries.Add(sql);
            Assert.Equal(SemanticProductionSql.Guard1, sql);
            return Task.FromResult(new JsonArray(guard.DeepClone()));
        }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("guard must not commit rejected admission");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    [Theory]
    [InlineData("facts-v1", "facts_schema_ready", "facts_schema_missing")]
    [InlineData("facts-v1", "processor_version_gate_schema_ready", "facts_schema_missing")]
    [InlineData("investigation-v1", "investigation_rule_lock_schema_ready", "rule_lock_capability_missing")]
    [InlineData("investigation-v1", "investigation_rule_lock_capability_ready", "rule_lock_capability_missing")]
    [InlineData("investigation-v1", "investigation_schema_ready", "investigation_capability_missing")]
    [InlineData("investigation-v1", "investigation_context_schema_ready", "investigation_capability_missing")]
    [InlineData("investigation-v1", "investigation_context_capability_ready", "investigation_capability_missing")]
    [InlineData("investigation-v1", "investigation_capability_ready", "investigation_capability_missing")]
    [InlineData("findings-v1", "investigation_rule_lock_schema_ready", "rule_lock_capability_missing")]
    [InlineData("findings-v1", "investigation_rule_lock_capability_ready", "rule_lock_capability_missing")]
    public async Task Missing_schema_or_least_privilege_capability_never_reaches_policy_or_claim(string mode, string flag, string code)
    {
        var guard = Guard(); guard[flag] = false;
        await using var session = new Session(guard);
        var error = await Assert.ThrowsAsync<WorkerFailure>(() => SemanticProduction.GuardAsync(session, mode, Ct));
        Assert.Equal("production_admission", error.Step); Assert.Contains(code, error.Diagnostic);
        Assert.Single(session.Queries);
    }

    [Theory]
    [InlineData("facts-v1", "assembly")] [InlineData("facts-v1", "correlation")]
    [InlineData("investigation-v1", "normalization")] [InlineData("investigation-v1", "assembly")]
    [InlineData("investigation-v1", "correlation")] [InlineData("investigation-v1", "risk")]
    [InlineData("investigation-v1", "findings")] [InlineData("findings-v1", "normalization")]
    [InlineData("findings-v1", "risk")] [InlineData("findings-v1", "findings")]
    public void Incomplete_or_mixed_feature_chains_fail_before_database_access(string mode, string flag)
    {
        var settings = Settings(mode);
        settings = flag switch {
            "normalization" => settings with { Normalization = false }, "assembly" => settings with { Assembly = false },
            "correlation" => settings with { Correlation = !settings.Correlation },
            "risk" => settings with { Risk = !settings.Risk }, _ => settings with { Findings = !settings.Findings }
        };
        Assert.Throws<InvalidOperationException>(() => settings.Validate(mode, _ => null));
    }

    [Theory] [InlineData("1", "unknown-v1")] [InlineData("0", "facts-v1")]
    public void Unknown_or_unadmitted_modes_fail_before_connection(string admitted, string mode) =>
        Assert.Throws<InvalidOperationException>(() => SemanticRuntimeSettings.Mode(key => key.EndsWith("PRODUCTION_ENABLED", StringComparison.Ordinal) ? admitted : mode));

    [Theory] [InlineData("1")] [InlineData("true")] [InlineData("yes")] [InlineData("on")]
    public void Legacy_admission_defaults_to_findings(string admitted) => Assert.Equal("findings-v1",
        SemanticRuntimeSettings.Mode(key => key.EndsWith("PRODUCTION_ENABLED", StringComparison.Ordinal) ? admitted : null));

    [Theory] [InlineData("facts-v1", "[]", false)] [InlineData("investigation-v1", "[\"shadow\"]", false)]
    [InlineData("findings-v1", "[\"shadow\",\"enabled\"]", true)]
    public void Heartbeat_reports_exact_mode_and_processing_contract(string mode, string allowed, bool findings)
    {
        var details = SemanticProduction.HeartbeatDetails(mode);
        Assert.Equal(mode, details.Text("runtime_mode")); Assert.False(details.Flag("manual_runtime"));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(allowed), details["allowed_modes"]));
        Assert.Equal(findings, details.Flag("finding_creation")); Assert.False(details.ContainsKey("enabled_policy"));
        Assert.Equal(1L, details["processing_contract"].Number("claim_protocol_version"));
        Assert.Equal(SemanticEvent.Version, details["processing_contract"].Text("processor_version"));
    }

    public static IEnumerable<object[]> Activities() {
        foreach (bool production in new[] { false, true })
            foreach (string activity in new[] { "{\"completed\":128,\"failed\":0}", "{\"completed\":0,\"failed\":1}",
                "{\"processing\":{\"claimed\":1}}", "{\"dispatch\":{\"claimed\":1}}", "{\"risk_queued\":1}" }) yield return [production, activity];
    }
    [Theory] [MemberData(nameof(Activities))]
    public async Task Continuous_worker_drains_busy_cycles_before_idle_sleep(bool production, string activity)
    {
        int cycles = 0, sleeps = 0; bool stopped = false; var statuses = new List<string>();
        int result = await SemanticProduction.RunCyclesAsync(new(Limit: 10000), _ => {
            Assert.True(cycles < 3); var result = cycles++ < 2 ? JsonNode.Parse(activity)!.AsObject() : new JsonObject();
            result["status"] = result.Number("failed") > 0 ? "error" : "ok"; return Task.FromResult(result);
        }, (status, result) => {
            if (result is not null) Assert.Equal((production ? "production_" : "") + (cycles < 3 ? "drain" : "sleep"), SemanticProduction.HeartbeatPhase(status, result, development: !production));
            statuses.Add(status); return Task.CompletedTask;
        }, () => stopped, (duration, _) => {
            Assert.Equal(3, cycles); Assert.Equal(TimeSpan.FromSeconds(30), duration); sleeps++; stopped = true; return Task.CompletedTask;
        }, Ct, development: !production);
        Assert.Equal(0, result); Assert.Equal(3, cycles); Assert.Equal(1, sleeps);
        Assert.Equal("idle", statuses[^2]); Assert.Equal("stopped", statuses[^1]);
    }

    [Theory] [InlineData(false, false)] [InlineData(false, true)] [InlineData(true, false)] [InlineData(true, true)]
    public async Task Iteration_error_keeps_backoff_and_once_exit(bool production, bool once)
    {
        bool stopped = false; int cycles = 0, sleeps = 0; var statuses = new List<string>();
        int result = await SemanticProduction.RunCyclesAsync(new(Once: once), _ => {
            cycles++; throw new InvalidOperationException("synthetic guard failure");
        }, (status, _) => { statuses.Add(status); return Task.CompletedTask; }, () => stopped, (duration, _) => {
            Assert.Equal(TimeSpan.FromSeconds(30), duration); sleeps++; stopped = true; return Task.CompletedTask;
        }, Ct, development: !production);
        Assert.Equal(1, result); Assert.Equal(1, cycles); Assert.Equal(once ? 0 : 1, sleeps); Assert.Contains("error", statuses);
    }

    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Stop_request_prevents_next_busy_batch_and_never_sleeps(bool beforeFirst)
    {
        bool stopped = beforeFirst; int cycles = 0; var statuses = new List<string>();
        Assert.Equal(0, await SemanticProduction.RunCyclesAsync(new(), _ => {
            cycles++; stopped = true; return Task.FromResult(new JsonObject { ["status"] = "ok", ["completed"] = 128 });
        }, (status, _) => { statuses.Add(status); return Task.CompletedTask; }, () => stopped,
            (_, _) => throw new InvalidOperationException("busy worker must not sleep"), Ct));
        Assert.Equal(beforeFirst ? 0 : 1, cycles); Assert.Equal("stopped", statuses[^1]);
    }

    [Theory] [InlineData(false, false, 128)] [InlineData(false, true, 37)] [InlineData(true, false, 128)] [InlineData(true, true, 37)]
    public async Task Cli_preserves_once_batch_default_override_and_poll_default(bool production, bool custom, int expected)
    {
        string[] args = custom ? ["--once", "--limit", "37"] : ["--once"];
        Task<int> Run(SemanticProductionOptions options, CancellationToken _) {
            Assert.True(options.Once); Assert.Equal(30, options.PollSeconds); Assert.Equal(expected, options.Limit); return Task.FromResult(0);
        }
        Assert.Equal(0, production ? await SemanticProductionCommand.RunAsync(args, Run)
            : await Sli.Server.Legacy.LegacyWorkerCommand.RunAsync("semantic-worker", args, Run));
    }

    [Theory] [InlineData(1, 1)] [InlineData(7, 7)] [InlineData(40, 16)] [InlineData(10000, 16)]
    public async Task Risk_portion_does_not_reduce_requested_normalization_batch(int limit, int risk)
    {
        Assert.Equal(0, await SemanticProductionCommand.RunAsync(["--once", "--limit", limit.ToString(System.Globalization.CultureInfo.InvariantCulture)], (options, _) => {
            Assert.Equal(limit, options.Limit); Assert.Equal(risk, SemanticProduction.RiskBatchSize(options.Limit)); return Task.FromResult(0);
        }));
    }

    [Theory]
    [InlineData("processing")] [InlineData("dispatch")] [InlineData("detections")] [InlineData("sigma")] [InlineData("risk")]
    public async Task Shutdown_finishes_current_stage_without_starting_the_next(string stoppingStage)
    {
        bool stopped = false; var calls = new List<string>();
        var production = new SemanticProduction(null!, Settings("findings-v1"), "findings-v1", 128, stopping: () => stopped);
        string[] stages = ["processing", "dispatch", "detections", "sigma", "risk"];
        foreach (string stage in stages) {
            var result = await production.Stage(stage, null!, async _ => {
                calls.Add(stage);
                if (stage == stoppingStage) stopped = true;
                await Task.Yield(); // The admitted stage still commits its result after the stop signal.
                return new JsonObject { ["completed"] = 1, ["failed"] = 0 };
            }, Ct);
            Assert.Equal(Array.IndexOf(stages, stage) <= Array.IndexOf(stages, stoppingStage) ? 1L : 0L, result.Number("completed"));
        }
        Assert.Equal(stages.Take(Array.IndexOf(stages, stoppingStage) + 1), calls);
    }

    [Fact]
    public void Exact_source_scope_rejects_invalid_selection_before_claim()
    {
        foreach (long[] ids in new long[][] { [], [0], [-1], [7, 7], Enumerable.Range(1, 17).Select(x => (long)x).ToArray() })
            Assert.Throws<InvalidOperationException>(() => SemanticProduction.ValidateExactSources("facts-v1", ids));
        foreach (string mode in new[] { "investigation-v1", "findings-v1" })
            Assert.Throws<InvalidOperationException>(() => SemanticProduction.ValidateExactSources(mode, [7, 8]));
        Assert.Throws<InvalidOperationException>(() => SemanticProduction.ValidateExactSources("facts-v1", [7, 8], new string('a', 64)));
    }

    [Fact]
    public async Task Facts_exact_sources_persist_actions_leave_other_work_and_never_dispatch_or_evaluate_risk()
    {
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(Ct);
        await using var owner = new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(Ct);
        var (_, events) = await SemanticRuntimePostgresTests.SeedShortAsync(fixture, owner, 0, Ct);
        long[] selected = [events[0].EventId, events[2].EventId];
        long unselected = events[1].EventId;
        // Run the actual ACL preflight under the worker role, with each forbidden grant isolated by rollback.
        foreach (string grant in new[] { "grant update on semantic_correlation_rules to adlog_semantic_worker",
            "grant update(updated_at) on semantic_correlation_rules to adlog_semantic_worker with grant option",
            "grant update(rule_id) on semantic_correlation_rules to adlog_semantic_worker" }) {
            await using var tx = await owner.BeginTransactionAsync(Ct);
            await using (var change = new NpgsqlCommand(grant + "; set local role adlog_semantic_worker", owner, tx)) await change.ExecuteNonQueryAsync(Ct);
            var error = await Assert.ThrowsAsync<WorkerFailure>(() => SemanticProduction.GuardAsync(new SemanticSession(owner, tx), "investigation-v1", Ct));
            Assert.Contains("rule_lock_capability_missing", error.Diagnostic);
            await tx.RollbackAsync(Ct);
        }
        await using var runtime = PasswordProducerRuntime.Create(key => key == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException());
        await using var db = await runtime.OpenAsync(Ct);
        Assert.Equal(3L, (await SemanticProducerBackfill.RunAsync(db, "facts-v1", 10, Ct)).Number("queued"));
        var production = new SemanticProduction(runtime, Settings("facts-v1"), "facts-v1", 2);
        var result = await production.RunOnceAsync(db, Ct, sourceEventIds: selected);
        Assert.Equal("ok", result.Text("status")); Assert.Equal(2L, result.Number("completed"));
        Assert.Equal(2L, result["processing"].Number("normalized")); Assert.True(result["processing"].Number("actions") > 0);
        Assert.Equal(0L, result.Number("failed")); Assert.Equal(0L, result.Number("risk_queued")); Assert.Equal(0L, result.Number("findings_created"));
        Assert.Equal(0L, result["dispatch"].Number("completed"));
        {
        await using var query = new NpgsqlCommand("""
            select array(select source_event_id from normalized_events order by source_event_id),
              (select status from semantic_processing_outbox where source_event_id=@source),
              (select count(*) from semantic_risk_evaluation_jobs), (select count(*) from findings)
            """, owner);
        query.Parameters.AddWithValue("source", unselected);
        await using var rows = await query.ExecuteReaderAsync(Ct); Assert.True(await rows.ReadAsync(Ct));
        Assert.Equal(selected, rows.GetFieldValue<long[]>(0)); Assert.Equal("queued", rows.GetString(1));
        Assert.Equal(0L, rows.GetInt64(2)); Assert.Equal(0L, rows.GetInt64(3));
        }
        await PostCollectionPostgres.Sql(owner, "select pg_advisory_lock(hashtextextended('ad_log_reports_runtime_semantic_production_worker',0))", Ct);
        var info = SemanticRuntimePostgresTests.NativeProcess(fixture, findings: false, bundle: false); info.ArgumentList.Add("--once");
        using var process = Process.Start(info)!;
        var stdout = process.StandardOutput.ReadToEndAsync(Ct); var stderr = process.StandardError.ReadToEndAsync(Ct);
        try { await process.WaitForExitAsync(Ct); }
        finally { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); } }
        Assert.Equal(1, process.ExitCode); Assert.Empty(await stdout); Assert.Contains("semantic_production_worker_already_running", await stderr);
        await using var untouched = new NpgsqlCommand("select status,(select count(*) from runtime_worker_heartbeats) from semantic_processing_outbox where source_event_id=@source", owner);
        untouched.Parameters.AddWithValue("source", unselected);
        await using var untouchedRows = await untouched.ExecuteReaderAsync(Ct); Assert.True(await untouchedRows.ReadAsync(Ct));
        Assert.Equal("queued", untouchedRows.GetString(0)); Assert.Equal(0L, untouchedRows.GetInt64(1));
    }
}
