using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticProductionTests
{
    [Fact] public async Task Connection_exhaustion_waits_without_a_failed_source_and_retries()
    {
        var work = new SemanticWork(independent: true);
        Assert.Null(await work.Run<object>("synthetic", () => throw new Npgsql.PostgresException("private", "FATAL", "FATAL", "53300"), TestContext.Current.CancellationToken));
        Assert.Equal("committed", await work.Run("synthetic", () => Task.FromResult("committed"), TestContext.Current.CancellationToken));
        Assert.Empty(work.Snapshot());
    }

    [Theory] [InlineData(40, 3, 4, 0, 4)] [InlineData(28, 3, 4, 20, 2)]
    [InlineData(26, 3, 4, 20, 1)] [InlineData(40, 3, 4, 32, 2)] [InlineData(40, 5, 4, 32, 1)]
    [InlineData(40, 3, 20, 0, 20)] [InlineData(40, 3, 64, 10, 24)]
    public void Capacity_uses_observed_connections_and_always_admits_a_source(int maximum, int reserved, int cpu, int observed, int expected) =>
        Assert.Equal(expected, SemanticCapacity.Calculate(maximum, reserved, cpu, observed).Sources);

    [Fact] public async Task Zero_concurrency_is_rejected_without_stopping_admission()
    {
        var work = new SemanticWork(independent: true, concurrency: 1);
        Assert.Throws<ArgumentOutOfRangeException>(() => work.SetConcurrency(0));
        Assert.Equal("committed", await work.Run("synthetic", () => Task.FromResult("committed"), TestContext.Current.CancellationToken));
        Assert.Throws<ArgumentOutOfRangeException>(() => new SemanticWork(independent: true, concurrency: 0));
    }

    [Fact] public void Exhausted_capacity_is_explicit_in_heartbeat()
    {
        var exhausted = SemanticCapacity.Calculate(40, 3, 64, 34);
        Assert.Equal(1, exhausted.Sources);
        Assert.Equal("database_connections_exhausted", exhausted.Json().Text("reason"));
        Assert.Null(SemanticCapacity.Calculate(40, 3, 64, 33).Json().Text("reason"));
    }

    [Fact] public async Task Pulse_retries_a_failed_heartbeat_without_worker_polling_and_stops_without_restarting()
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var heartbeat = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int attempts = 0;
        var pulse = SemanticProduction.PulseAsync(_ => {
            int attempt = Interlocked.Increment(ref attempts);
            if (attempt == 2) throw new IOException("synthetic");
            if (attempt == 3) heartbeat.TrySetResult();
            return Task.CompletedTask;
        }, stop.Token);
        try {
            await Task.WhenAny(heartbeat.Task, pulse).WaitAsync(TimeSpan.FromSeconds(20), stop.Token);
            if (pulse.IsCompleted) await pulse;
            Assert.True(heartbeat.Task.IsCompletedSuccessfully);
            Assert.Equal(3, attempts);
        }
        finally {
            stop.Cancel();
            try { await pulse; } catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        }
        Assert.Equal(3, attempts);
    }

    [Fact] public async Task Queued_detectors_precede_a_heavy_source_reentering_and_shutdown_cancels_waiters()
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        stop.CancelAfter(TimeSpan.FromSeconds(10)); var ct = stop.Token;
        var work = new SemanticWork(independent: true, concurrency: 1);
        var first = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var second = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var order = new List<string>();
        await work.Run("heavy", () => { order.Add("heavy"); return first.Task; }, ct);
        await work.Run("password", () => { order.Add("password"); secondStarted.SetResult(); return second.Task; }, ct);
        await work.Run("attack", () => { order.Add("attack"); return Task.FromResult("done"); }, ct);
        Assert.Equal(2, work.Snapshot().Count(x => x.Text("status") == "queued"));
        first.SetResult("done"); await secondStarted.Task.WaitAsync(ct);
        Assert.Equal("done", await work.Run<string>("heavy", () => throw new InvalidOperationException(), ct));
        await work.Run("heavy", () => { order.Add("heavy-again"); return Task.FromResult("done"); }, ct);
        second.SetResult("done"); await work.Drain().WaitAsync(ct);
        Assert.Equal(new[] { "heavy", "password", "attack", "heavy-again" }, order);
        var blocker = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        await work.Run("blocker", () => blocker.Task, ct);
        await work.Run<string>("shutdown", () => throw new InvalidOperationException("must stay queued"), ct);
        stop.Cancel(); blocker.SetResult("done"); await work.Drain(); Assert.Empty(work.Snapshot());
    }

    [Fact] public async Task Pump_task_remains_visible_when_running_completed_or_failed()
    {
        var work = new SemanticWork(independent: true);
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        work.Track("processing_outbox", completion.Task);
        Assert.Equal("running", Assert.Single(work.Snapshot()).Text("status"));
        completion.SetResult(); await completion.Task;
        Assert.Equal("completed", Assert.Single(work.Snapshot()).Text("status"));
        var failure = Task.FromException(new IOException("synthetic"));
        work.Track("processing_outbox", failure);
        Assert.Equal("error", Assert.Single(work.Snapshot()).Text("status"));
        await Assert.ThrowsAsync<IOException>(() => failure);
        work.Forget("processing_outbox"); Assert.Empty(work.Snapshot());
    }

    [Fact] public void Only_server_lock_contention_yields_without_consuming_attempts()
    {
        Assert.True(SemanticProduction.LockWait(new InvalidOperationException("synthetic",new Npgsql.PostgresException("synthetic","ERROR","ERROR","55P03"))));
        Assert.False(SemanticProduction.LockWait(new Npgsql.PostgresException("synthetic","ERROR","ERROR","42501")));
        Assert.False(SemanticProduction.LockWait(new Npgsql.PostgresException("synthetic","ERROR","ERROR","57014")));
        Assert.False(SemanticProduction.LockWait(new IOException("55P03")));
    }

    [Fact] public async Task Independent_sources_keep_advancing_while_one_is_running_and_never_overlap()
    {
        var work=new SemanticWork(independent:true);
        var release=new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        int starts=0;
        Task<int> Slow() { starts++;return release.Task; }
        Assert.Equal(0,await work.Run("slow",Slow,TestContext.Current.CancellationToken));
        Assert.Equal(7,await work.Run("other",()=>Task.FromResult(7),TestContext.Current.CancellationToken));
        Assert.Equal(8,await work.Run("other",()=>Task.FromResult(8),TestContext.Current.CancellationToken));
        Assert.Equal(0,await work.Run("slow",Slow,TestContext.Current.CancellationToken));Assert.Equal(1,starts);
        var active=Assert.Single(work.Snapshot());Assert.Equal("slow",active.Text("operation"));Assert.NotNull(active.Text("started_at"));
        release.SetResult(42);await work.Drain();
        Assert.Equal(42,await work.Run("slow",Slow,TestContext.Current.CancellationToken));Assert.Equal(1,starts);Assert.Empty(work.Snapshot());
    }

    [Fact] public async Task Independent_source_errors_are_observed_and_can_be_retried()
    {
        var work=new SemanticWork(independent:true);
        var release=new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        await work.Run("source",()=>release.Task,TestContext.Current.CancellationToken);
        release.SetException(new IOException("synthetic connection loss"));await work.Drain();
        await Assert.ThrowsAsync<IOException>(()=>work.Run("source",()=>Task.FromResult(0),TestContext.Current.CancellationToken));
        Assert.Equal(9,await work.Run("source",()=>Task.FromResult(9),TestContext.Current.CancellationToken));Assert.Empty(work.Snapshot());
    }

    [Fact]
    public void Catchup_budget_tracks_measured_capacity_with_half_reserved_for_foreground()
    {
        var rate=new SemanticQueueRate(); Assert.Equal(150,rate.HighWatermark);
        rate.Observe(100,TimeSpan.FromSeconds(5)); Assert.Equal(300,rate.HighWatermark);
        rate.Observe(100,TimeSpan.FromSeconds(20)); Assert.Equal(75,rate.HighWatermark);
        rate.Observe(100,TimeSpan.FromSeconds(1)); Assert.Equal(1500,rate.HighWatermark);
    }
    [Fact]
    public void Catchup_capacity_recovers_after_a_slow_completed_segment()
    {
        var rate=new SemanticQueueRate();
        rate.Observe(8,TimeSpan.FromHours(1));
        double slow=rate.JobsPerSecond;
        rate.Observe(4,TimeSpan.FromSeconds(1));
        Assert.Equal(slow,rate.JobsPerSecond);
        rate.Observe(4,TimeSpan.FromSeconds(1));
        Assert.Equal(2,rate.JobsPerSecond);
        rate.Observe(8,TimeSpan.FromSeconds(1));
        Assert.Equal(4,rate.JobsPerSecond);
    }
    [Theory]
    [InlineData(1)]
    [InlineData(3600)]
    [InlineData(86400)]
    public void Catchup_watermark_remains_positive_while_completed_work_advances(double seconds)
    {
        var rate=new SemanticQueueRate();
        for(int segment=0;segment<3;segment++) {
            rate.Observe(8,TimeSpan.FromSeconds(seconds));
            Assert.InRange(rate.HighWatermark,8,SemanticProducer.MaxBatch);
        }
    }
    public static TheoryData<string, string> CycleCases => new()
    {
        { """{"failed":2,"detections":{"sources":2,"failed":2}}""", "error" },
        { """{"failed":2,"detections":{"sources":2,"completed":0,"failed":2,"jobs":3},"findings_created":1}""", "error" },
        { """{"failed":1,"detections":{"sources":2,"failed":1}}""", "partial" },
        { """{"failed":1,"detections":{"sources":1,"failed":1,"file_ransom_status":{"code":"source_policy_waiting","sources":1}}}""", "partial" },
        { """{"failed":2,"detections":{"sources":2,"failed":2,"file_ransom_status":{"code":"source_policy_waiting","sources":1}}}""", "error" },
        { """{"failed":2,"detections":{"sources":3,"completed":1,"failed":2,"file_ransom_status":{"code":"source_policy_waiting","sources":1}}}""", "partial" },
        { """{"failed":1,"detections":{"sources":0,"failed":1}}""", "error" },
        { """{"failed":1,"processing":{"completed":0,"failed":0},"password_producer":{"sources":2,"completed":0,"failed":1,"skipped":2}}""", "error" },
        { """{"failed":1,"password_producer":{"sources":1,"completed":1,"failed":1}}""", "partial" }
    };
    [Theory, MemberData(nameof(CycleCases))]
    public async Task Runtime_readers_require_success_or_only_policy_waits_for_partial(string json, string expected)
    {
        var result = JsonNode.Parse(json)!.AsObject();
        Assert.Equal(expected, SemanticProduction.CycleStatus(result));
        result["status"] = expected;
        var heartbeat = new JsonObject { ["status"] = "partial", ["heartbeat_at"] = DateTimeOffset.UtcNow.ToString("O"), ["expected_interval_seconds"] = 70,
            ["details_json"] = new JsonObject { ["runtime_mode"] = "findings-v1", ["manual_runtime"] = false, ["result"] = result } };
        foreach (string status in new[] { "partial", "running", "idle", expected })
        {
            heartbeat["status"] = status;
            Assert.Equal(expected == "error" ? "inactive" : "active", Sli.Server.Problems.ProblemPresentation.Runtime(heartbeat, DateTimeOffset.UtcNow).Text("findings_state"));
            Assert.Equal(expected == "error" ? "inactive" : "active", Sli.Server.Domains.HomeSummaryReaders.Runtime(heartbeat, DateTimeOffset.UtcNow));
            var execution = await SemanticWorkspace.ExecutionAsync(new SemanticEndpointTests.Database { Heartbeat = heartbeat }, TestContext.Current.CancellationToken);
            Assert.Equal(expected == "error" ? "warning" : "active", execution["worker"].Text("state"));
        }
    }
    [Fact] public void Cycle_failure_keeps_only_safe_step_and_sql_state()
    {
        var pg = new Npgsql.PostgresException("private event XML", "ERROR", "ERROR", "42501", detail: "private AD", constraintName: "private-host");
        var error = new Hosting.WorkerFailure("default_detections", "cycle:postgres_42501", new InvalidOperationException("private password", pg));
        var result = SemanticProduction.CycleFailure(error);
        Assert.Equal("error", result.Text("status")); Assert.Equal(1L, result.Number("failed"));
        Assert.Equal("default_detections", result["error"].Text("step")); Assert.Equal("42501", result["error"].Text("sql_state"));
        Assert.DoesNotContain("private", result.ToJsonString());
        Assert.Equal("unknown", SemanticProduction.CycleFailure(new Npgsql.PostgresException("private", "ERROR", "ERROR", "private state"))["error"].Text("sql_state"));
        Assert.Null(SemanticProduction.CycleFailure(new IOException("private path"))["error"]!["sql_state"]);
        Assert.Equal("cycle", SemanticProduction.CycleFailure(new Hosting.WorkerFailure("private step", "private reason"))["error"].Text("step"));
    }
    private sealed class IdentityReplaySession(SemanticProposal proposal, bool scenarioSchema, bool findingSchema, bool created) : ISemanticSession
    {
        internal static readonly Guid ScenarioId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        internal const long FindingId = 42;
        internal readonly List<(string Sql, object?[] Values)> Commands = [];
        private JsonObject? step, contribution;
        internal JsonObject Scenario => new()
        {
            ["scenario_id"] = ScenarioId.ToString(), ["identity_key"] = proposal.Identity, ["scenario_key"] = new string('b', 64),
            ["scenario_kind"] = proposal.Policy.Kind, ["result_class"] = proposal.Policy.Result, ["partition_key"] = proposal.Partition,
            ["strict_keys_json"] = proposal.Strict.DeepClone(), ["merge_window_seconds"] = proposal.Policy.Window,
            ["title"] = "Synthetic replay", ["explanation"] = "Synthetic replay", ["risk_class"] = "medium", ["confidence_score"] = 100,
            ["first_seen_utc"] = SemanticJson.Stamp(proposal.At), ["last_seen_utc"] = SemanticJson.Stamp(proposal.At), ["evidence_state"] = "ready"
        };
        private static JsonArray Rows(JsonObject row) => new(row.DeepClone());
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            Commands.Add((sql, values));
            JsonArray rows = [];
            if (sql.StartsWith("select observation_id,control_id,partition_key,coverage_status,reason,observed_at_utc from semantic_control_health_observations", StringComparison.Ordinal))
                rows = Rows(new() { ["observation_id"] = proposal.SourceId, ["partition_key"] = proposal.Partition, ["control_id"] = "synthetic", ["coverage_status"] = "complete", ["reason"] = "Synthetic coverage", ["observed_at_utc"] = SemanticJson.Stamp(proposal.At) });
            else if (sql.Contains("to_regclass(")) rows = Rows(new() { ["available"] = sql.Contains("entity_identity_scenario_supersessions_v2") ? scenarioSchema : findingSchema });
            else if (sql.Contains("from semantic_correlation_candidates where candidate_id="))
                rows = Rows(new() { ["candidate_status"] = "matched", ["partition_key"] = proposal.Partition, ["window_start_utc"] = SemanticJson.Stamp(proposal.At), ["window_end_utc"] = SemanticJson.Stamp(proposal.At) });
            else if (sql.Contains("from semantic_correlation_candidate_evidence where candidate_id="))
                rows = new JsonArray(proposal.Evidence.Select(id => (JsonNode)new JsonObject { ["normalized_event_id"] = id.ToString() }).ToArray());
            else if (sql.TrimStart().StartsWith("insert into public.entity_identity_", StringComparison.Ordinal)) { }
            else if (sql == SemanticRiskSql.persist_step0)
                step = new() { ["step_id"] = values[0]!.ToString(), ["scenario_id"] = values[1]!.ToString(), ["source_kind"] = values[3]!.ToString(), ["occurred_at_utc"] = SemanticJson.Stamp((DateTimeOffset)values[7]!), ["title"] = values[8]!.ToString(), ["explanation"] = values[9]!.ToString(), ["confidence_factors_json"] = ((JsonObject)values[12]!).DeepClone() };
            else if (sql == SemanticRiskSql.persist_step1) rows = Rows(step!);
            else if (sql == SemanticRiskSql.persist_contribution0)
                contribution = new()
                {
                    ["contribution_id"] = values[0]!.ToString(), ["scenario_id"] = values[1]!.ToString(), ["source_kind"] = values[3]!.ToString(),
                    ["canonical_action_id"] = values[4]?.ToString(), ["correlation_candidate_id"] = values[5]?.ToString(), ["control_reference"] = values[6]?.ToString(),
                    ["policy_id"] = values[7]!.ToString(), ["policy_version"] = (int)values[8]!, ["policy_sha256"] = Convert.ToHexStringLower((byte[])values[9]!),
                    ["risk_class"] = values[10]!.ToString(), ["raw_score"] = (decimal)values[11]!, ["display_points"] = (int)values[12]!,
                    ["hard_critical"] = (bool)values[13]!, ["rationale"] = values[14]!.ToString(), ["detection_match_id"] = values[15]?.ToString(), ["qw_signal_id"] = values[16]?.ToString()
                };
            else if (sql == SemanticRiskSql.persist_contribution1) { if (contribution is not null) rows = Rows(contribution); }
            else if (sql.StartsWith("select * from semantic_security_scenarios", StringComparison.Ordinal)) rows = Rows(Scenario);
            else if (sql == SemanticRiskSql.refresh_scenario0) rows = Rows(contribution!);
            else if (sql == SemanticRiskSql.refresh_scenario1) rows = Rows(new() { ["confidence_factors_json"] = proposal.Factors.DeepClone() });
            else if (sql == SemanticRiskSql.refresh_scenario3) rows = Rows(new() { ["first_seen_utc"] = SemanticJson.Stamp(proposal.At), ["last_seen_utc"] = SemanticJson.Stamp(proposal.At), ["step_count"] = 1, ["evidence_count"] = 1, ["expected_evidence_count"] = 1, ["contribution_count"] = 1 });
            else if (sql == SemanticRiskSql.publish_enabled_scenario_finding0) rows = Rows(new() { ["evaluation_mode"] = "enabled", ["conclusion_state"] = "observed", ["scenario_id"] = ScenarioId.ToString(), ["policy_admitted"] = true });
            else if (sql == SemanticRiskSql.publish_enabled_scenario_finding4) rows = Rows(new() { ["admitted"] = true, ["lifecycle_status"] = "enabled", ["policy_sha256"] = proposal.Policy.Sha, ["definition_sha256"] = proposal.Policy.Sha });
            else if (sql.StartsWith("select s.source_kind,d.document_json", StringComparison.Ordinal))
            {
                if (proposal.Policy.Source == "detection_match") rows = Rows(new() { ["source_kind"] = "detection_match", ["detection"] = new JsonObject { ["evidence"] = proposal.Native[0]!.DeepClone() } });
            }
            else if (sql.Contains("resolve_finding_evidence_ref(")) rows = Rows(new() { ["verified"] = true });
            else if (sql.Contains("link_finding_evidence_ref(")) rows = Rows(new() { ["added"] = true });
            else if (sql == SemanticRiskSql.publish_enabled_scenario_finding7) { if (created) rows = Rows(new() { ["id"] = FindingId }); }
            else if (sql == SemanticRiskSql.publish_enabled_scenario_finding8) rows = Rows(new() { ["id"] = FindingId, ["rule_code"] = "semantic.synthetic" });
            else if (sql == SemanticRiskSql.publish_enabled_scenario_finding11) rows = Rows(new() { ["count"] = 1, ["max_event_id"] = 7 });
            else if (sql == SemanticRiskSql.publish_enabled_scenario_finding14) rows = Rows(new() { ["finding_id"] = FindingId, ["finding_fingerprint"] = "semantic:" + new string('b', 64) });
            else if (!(sql.Contains("pg_advisory_xact_lock(") || sql.StartsWith("insert into semantic_scenario_evidence", StringComparison.Ordinal) ||
                new[] { SemanticRiskSql.persist_coverage0, SemanticRiskSql.refresh_scenario2, SemanticRiskSql.refresh_scenario4, SemanticRiskSql.publish_enabled_scenario_finding3,
                    SemanticRiskSql.publish_enabled_scenario_finding9, SemanticRiskSql.publish_enabled_scenario_finding10, SemanticRiskSql.publish_enabled_scenario_finding12,
                    SemanticRiskSql.publish_enabled_scenario_finding13, SemanticRiskSql.publish_enabled_scenario_finding15 }.Contains(sql)))
                throw new InvalidOperationException("Unexpected SQL: " + sql);
            return Task.FromResult(rows);
        }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("caller_owns_transaction");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    [Theory]
    [InlineData("canonical_action", true, true, true)]
    [InlineData("correlation_candidate", true, true, true)]
    [InlineData("control_health", true, true, true)]
    [InlineData("detection_match", true, true, true)]
    [InlineData("canonical_action", true, true, false)]
    [InlineData("canonical_action", false, false, true)]
    [InlineData("canonical_action", true, false, true)]
    public async Task Identity_replay_records_scenario_then_published_finding_with_optional_schema(string source, bool scenarioSchema, bool findingSchema, bool created)
    {
        var policy = new SemanticPolicy("synthetic", 1, source, new(), new string('a', 64), "synthetic", "synthetic", "security_incident", ["source_host"], 300, "Synthetic replay", "Synthetic replay", "medium", 25m, 25, false, "Synthetic rationale", 1, [], null);
        var native = new JsonArray();
        if (source == "detection_match") native.Add(new JsonObject
        {
            ["scope"] = new JsonObject { ["installation_id"] = "11111111-1111-1111-1111-111111111111", ["plugin_id"] = "synthetic", ["source_instance_id"] = "synthetic", ["source_generation"] = "1", ["collection_scope_id"] = "synthetic" },
            ["storage_kind"] = "core_event", ["native_id"] = "7", ["sha256"] = new string('c', 64)
        });
        var proposal = new SemanticProposal(policy, source == "detection_match" ? new string('d', 64) : "22222222-2222-2222-2222-222222222222", DateTimeOffset.Parse("2026-01-01T00:00:00Z"), "dc.example.test",
            new() { ["source_host"] = "dc.example.test" }, new() { ["identity_resolution"] = "exact", ["state_confirmed"] = true, ["multi_source_confirmed"] = false, ["sequence_completeness"] = 100, ["time_quality"] = "good", ["parser_quality"] = "good" },
            source is "detection_match" or "control_health" ? [] : [Guid.Parse("33333333-3333-3333-3333-333333333333")], native,
            source == "control_health" ? new JsonArray(new JsonObject { ["control_id"] = "synthetic", ["coverage_status"] = "complete", ["reason"] = "Synthetic coverage", ["observed_at_utc"] = "2026-01-01T00:00:00Z" }) : []);
        var session = new IdentityReplaySession(proposal, scenarioSchema, findingSchema, created);
        var ct = TestContext.Current.CancellationToken;
        var scenario = await SemanticProduction.PersistProposal(session, proposal, ct);
        int persisted = session.Commands.Count;
        Assert.Equal(created, await SemanticProduction.PublishFinding(session, proposal, scenario, Guid.Parse("44444444-4444-4444-4444-444444444444"), ct));
        int scenarioGuard = session.Commands.FindIndex(x => x.Sql.Contains("to_regclass('public.entity_identity_scenario_supersessions_v2')"));
        int findingGuard = session.Commands.FindIndex(x => x.Sql.Contains("to_regclass('public.entity_identity_finding_supersessions_v2')"));
        Assert.InRange(scenarioGuard, 0, persisted - 1);
        Assert.True(scenarioGuard > session.Commands.FindLastIndex(x => x.Sql == SemanticRiskSql.refresh_scenario4));
        Assert.True(findingGuard > session.Commands.FindLastIndex(x => x.Sql == SemanticRiskSql.publish_enabled_scenario_finding14));
        var scenarioWrites = session.Commands.Where(x => x.Sql.TrimStart().StartsWith("insert into public.entity_identity_scenario_supersessions_v2", StringComparison.Ordinal)).ToArray();
        var findingWrites = session.Commands.Where(x => x.Sql.TrimStart().StartsWith("insert into public.entity_identity_finding_supersessions_v2", StringComparison.Ordinal)).ToArray();
        if (scenarioSchema)
        {
            var write = Assert.Single(scenarioWrites);
            Assert.Equal(new object?[] { IdentityReplaySession.ScenarioId }, write.Values);
            Assert.Contains("old_scenario.scenario_kind=new_scenario.scenario_kind", write.Sql);
            Assert.Contains("old_scenario.result_class=new_scenario.result_class", write.Sql);
            Assert.Contains("old_evidence.scenario_id<>$1", write.Sql);
            Assert.Contains("on conflict do nothing", write.Sql);
        }
        else Assert.Empty(scenarioWrites);
        if (findingSchema)
        {
            var write = Assert.Single(findingWrites);
            Assert.Equal(new object?[] { IdentityReplaySession.ScenarioId, IdentityReplaySession.FindingId }, write.Values);
            Assert.Contains("old_publication.scenario_id=supersession.old_scenario_id", write.Sql);
            Assert.Contains("old_publication.finding_id<>$2", write.Sql);
            Assert.Contains("on conflict do nothing", write.Sql);
        }
        else Assert.Empty(findingWrites);
    }
    private sealed class AdmissionSession : ISemanticSession
    {
        internal readonly JsonObject Guard = new()
        {
            ["facts_schema_ready"] = true, ["processor_version_gate_schema_ready"] = true, ["facts_capability_ready"] = true,
            ["investigation_rule_lock_schema_ready"] = true, ["investigation_rule_lock_capability_ready"] = true,
            ["investigation_schema_ready"] = true, ["investigation_context_schema_ready"] = true,
            ["investigation_capability_ready"] = true, ["investigation_context_capability_ready"] = true,
            ["schema_ready"] = true, ["test_policy_exists"] = false, ["admission_configured"] = true, ["unmanaged_enabled_policies"] = new JsonArray()
        };
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values) => Task.FromResult(new JsonArray(Guard.DeepClone()));
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("admission_must_not_write");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    [Theory] [InlineData("facts-v1")] [InlineData("investigation-v1")] [InlineData("findings-v1")]
    public async Task Production_modes_validate_schema_and_least_privilege_before_processing(string mode)
    {
        var session = new AdmissionSession(); await SemanticProduction.GuardAsync(session, mode, TestContext.Current.CancellationToken);
        session.Guard["facts_capability_ready"] = false;
        await Assert.ThrowsAsync<Sli.Server.Hosting.WorkerFailure>(() => SemanticProduction.GuardAsync(session, mode, TestContext.Current.CancellationToken));
    }
    [Theory] [InlineData("schema_ready")] [InlineData("test_policy_exists")] [InlineData("admission_configured")]
    public async Task Findings_admission_rejects_unready_schema_test_policy_and_missing_admission(string field)
    {
        var session = new AdmissionSession(); session.Guard[field] = field == "test_policy_exists";
        await Assert.ThrowsAsync<Sli.Server.Hosting.WorkerFailure>(() => SemanticProduction.GuardAsync(session, "findings-v1", TestContext.Current.CancellationToken));
    }
    [Fact] public async Task Findings_admission_preserves_single_builtin_policy_exception_and_refuses_unmanaged_others()
    {
        var session = new AdmissionSession(); session.Guard["admission_configured"] = false; session.Guard["unmanaged_enabled_policies"] = new JsonArray("l1-audit-policy-changed:2");
        await SemanticProduction.GuardAsync(session, "findings-v1", TestContext.Current.CancellationToken);
        session.Guard["unmanaged_enabled_policies"]!.AsArray().Add("unmanaged:1");
        await Assert.ThrowsAsync<Sli.Server.Hosting.WorkerFailure>(() => SemanticProduction.GuardAsync(session, "findings-v1", TestContext.Current.CancellationToken));
    }
    public static IEnumerable<object[]> DetectionVectors()
    {
        using var stream = typeof(SemanticProductionTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Semantic.detection-reference.json")!;
        return JsonNode.Parse(stream)!.AsArray().Select(x => new object[] { x!.Text("case")!, x.Flag("watch"), x!.ToJsonString() }).ToArray();
    }
    [Theory] [MemberData(nameof(DetectionVectors))]
    public void Account_detections_match_python_event_time_identity_and_severity(string name, bool watch, string json)
    {
        _ = name; var vector = JsonNode.Parse(json)!; var definition = SemanticProduction.Definition(watch ? "qw.account-watch" : "qw.account-decoy", vector["scope"]!.AsObject());
        var (signals, state) = SemanticProduction.EvaluateAccount(definition, vector["row"]!, SigmaProjection.At(vector, "now"), watch);
        Assert.Equal(vector.Text("expected_state"), state);
        Assert.True(JsonNode.DeepEquals(vector["expected"], signals), signals.ToJsonString());
    }
    public static IEnumerable<object[]> NormalizationVectors()
    {
        using var stream = typeof(SemanticProductionTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Semantic.normalization-reference.json")!;
        return JsonNode.Parse(stream)!.AsArray().Select(x => new object[] { (int)x!["source"].Number("event_id"), x.ToJsonString() }).ToArray();
    }
    [Theory] [MemberData(nameof(NormalizationVectors))]
    public void Normalization_and_action_assembly_match_python(int eventId, string json)
    {
        _ = eventId; var vector = JsonNode.Parse(json)!; var expected = vector["expected"]!; var actual = SemanticNormalization.Normalize(vector["source"]!.AsObject());
        Assert.Equal(expected.Text("semantic_type"), actual.Type);
        Assert.True(JsonNode.DeepEquals(expected["roles"], actual.Roles), "roles: " + actual.Roles.ToJsonString());
        Assert.True(JsonNode.DeepEquals(expected["facts"], actual.Facts), "facts: " + actual.Facts.ToJsonString());
        Assert.True(JsonNode.DeepEquals(expected["quality"], actual.Quality), "quality: " + actual.Quality.ToJsonString());
        Assert.Equal(expected.Text("semantic_sha256"), actual.Sha);
        var actions = SemanticAssembly.Assemble([actual]); Assert.Equal(vector["actions"]!.AsArray().Count, actions.Count);
        for (int i = 0; i < actions.Count; i++)
        {
            var action = vector["actions"]![i]!; Assert.Equal(action.Text("action_kind"), actions[i].Kind); Assert.Equal(action.Text("contribution_key"), actions[i].Key);
            Assert.True(JsonNode.DeepEquals(action["attributes"], actions[i].Attributes)); Assert.Equal(action.Text("action_sha256"), actions[i].Sha);
        }
    }
    [Theory] [InlineData("facts-v1", false, false, false)] [InlineData("investigation-v1", true, false, false)] [InlineData("findings-v1", true, true, true)]
    public void Runtime_modes_require_exact_chain(string mode, bool correlation, bool risk, bool findings)
    {
        var values = new Dictionary<string, string?> { ["ADLOG_SEMANTIC_PRODUCTION_ENABLED"] = "1", ["ADLOG_SEMANTIC_RUNTIME_MODE"] = mode,
            ["ADLOG_SEMANTIC_NORMALIZATION_ENABLED"] = "1", ["ADLOG_SEMANTIC_ASSEMBLY_ENABLED"] = "1", ["ADLOG_SEMANTIC_CORRELATION_ENABLED"] = correlation ? "1" : "0", ["ADLOG_SEMANTIC_RISK_ENGINE_ENABLED"] = risk ? "1" : "0", ["ADLOG_SEMANTIC_FINDING_CREATION_ENABLED"] = findings ? "1" : "0" };
        string? Get(string key) => values.GetValueOrDefault(key);
        var settings = SemanticRuntimeSettings.Read(Get); Assert.Equal(mode, SemanticRuntimeSettings.Mode(Get)); settings.Validate(mode, Get);
        values["ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED"] = "1"; Assert.Throws<InvalidOperationException>(() => SemanticRuntimeSettings.Read(Get).Validate(mode, Get));
        values["ADLOG_SEMANTIC_PRODUCTION_ENABLED"] = "0"; Assert.Throws<InvalidOperationException>(() => SemanticRuntimeSettings.Mode(Get));
    }
    [Fact] public void Facts_mode_rejects_raw_flags_hidden_by_upstream_gate()
    {
        string? Get(string name) => name == "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED" ? "1" : null;
        Assert.Throws<InvalidOperationException>(() => new SemanticRuntimeSettings(true, true, false, false, false, false).Validate("facts-v1", Get));
    }
    private static Dictionary<string, string?> FactsEnvironment() => new()
    {
        ["ADLOG_SEMANTIC_PRODUCTION_ENABLED"] = "1",
        ["ADLOG_SEMANTIC_RUNTIME_MODE"] = "facts-v1",
        ["ADLOG_SEMANTIC_NORMALIZATION_ENABLED"] = "1",
        ["ADLOG_SEMANTIC_ASSEMBLY_ENABLED"] = "1"
    };

    // Python: tests/semantic/test_semantic_preconnect_guard.py. The .NET --once
    // path owns the single-cycle connection; continuous mode uses the same guard.
    [Theory]
    [InlineData(true, "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED")]
    [InlineData(true, "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED")]
    [InlineData(true, "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED")]
    [InlineData(true, "missing_assembly")]
    [InlineData(false, "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED")]
    [InlineData(false, "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED")]
    [InlineData(false, "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED")]
    [InlineData(false, "missing_assembly")]
    public async Task Invalid_facts_configuration_fails_before_credentials_or_connect(bool once, string invalidFlag)
    {
        var values = FactsEnvironment();
        if (invalidFlag == "missing_assembly") values["ADLOG_SEMANTIC_ASSEMBLY_ENABLED"] = "0";
        else values[invalidFlag] = "1";
        int runtimeCalls = 0;
        int exit = await SemanticProduction.RunWorker(new(Once: once, PollSeconds: 15, Limit: 1),
            TestContext.Current.CancellationToken, values.GetValueOrDefault, () => {
                runtimeCalls++;
                throw new IOException("Invalid configuration crossed the pre-connect boundary");
            });
        Assert.Equal(1, exit);
        Assert.Equal(0, runtimeCalls);
    }

    [Theory] [InlineData(true)] [InlineData(false)]
    public async Task Valid_facts_configuration_reaches_the_runtime_factory(bool once)
    {
        var values = FactsEnvironment();
        var boundary = new IOException("synthetic_runtime_boundary");
        int runtimeCalls = 0;
        var error = await Assert.ThrowsAsync<IOException>(() => SemanticProduction.RunWorker(new(Once: once),
            TestContext.Current.CancellationToken, values.GetValueOrDefault, () => {
                runtimeCalls++;
                throw boundary;
            }));
        Assert.Same(boundary, error);
        Assert.Equal(1, runtimeCalls);
    }
    private const string Rule = """
        title: Synthetic test
        id: 11111111-1111-1111-1111-111111111111
        author: Synthetic
        logsource:
            product: windows
            service: security
        detection:
            selection:
                EventID: 4625
                TargetUserName|endswith: '$'
            filter:
                IpAddress: '192.0.2.1'
            condition: selection and not filter
        """;
    [Theory] [InlineData(true, "not_matched")] [InlineData(false, "not_evaluable")]
    public void Sigma_negated_unavailable_filter_never_matches(bool present, string state)
    {
        var rule = SigmaRule.Compile(Rule); var fields = new JsonObject { ["EventID"] = 4625, ["TargetUserName"] = "test$" }; if (present) fields["IpAddress"] = "192.0.2.1";
        Assert.Equal(state, rule.Match(fields));
    }
    [Fact] public void Sigma_bound_yaml_and_dsl_refuse_aliases_duplicate_fields_and_empty_selectors()
    {
        var yaml = Rule.ReplaceLineEndings("\n");
        Assert.Throws<InvalidDataException>(() => SigmaRule.Compile(yaml.Replace("selection:\n", "selection: &shared\n")));
        Assert.Throws<InvalidDataException>(() => SigmaRule.Compile(yaml.Replace("EventID: 4625", "EventID: 4625\n        EventID: 4624")));
        Assert.Throws<InvalidDataException>(() => SigmaRule.Compile(yaml.Replace("selection and not filter", "all of missing*")));
    }
    [Fact] public void Sigma_coverage_does_not_count_overlapping_or_partial_windows_twice()
    {
        var rows = new JsonArray();
        var start = DateTimeOffset.Parse("2026-01-01T00:00:00Z"); var end = start.AddDays(1);
        JsonObject Row(int scanned, DateTimeOffset left, DateTimeOffset right, int order) => new() { ["time_from"] = SemanticJson.Stamp(left), ["time_to"] = SemanticJson.Stamp(right), ["created_at"] = SemanticJson.Stamp(end.AddHours(order)), ["coverage_sha256"] = order.ToString(), ["document_json"] = new JsonObject { ["manifest_sha256"] = "m", ["plan_sha256"] = "p", ["compiler_version"] = "c", ["mapping_version"] = "v", ["overlay_sha256"] = "o", ["partition_complete"] = true, ["status"] = "completed", ["counts"] = new JsonObject { ["scanned"] = scanned, ["evaluable"] = scanned, ["matched"] = 0, ["suppressed"] = 0, ["unknown"] = 0, ["skipped"] = 0, ["first_occurred_at"] = SemanticJson.Stamp(left), ["last_occurred_at"] = SemanticJson.Stamp(left), ["reasons"] = new JsonArray(), ["unknown_fields"] = new JsonArray() } } };
        rows.Add(Row(5, start, end, 1)); rows.Add(Row(7, start, end, 2));
        var executions = SigmaProjection.Executions(rows, start, end); Assert.Equal(7, executions[0]!["counts"].Number("scanned")); Assert.Equal("no_matches", executions[0].Text("state"));
        rows.Add(Row(3, start.AddHours(-1), start.AddHours(1), 3)); executions = SigmaProjection.Executions(rows, start, end); Assert.Equal("incomplete", executions[0].Text("state"));
    }
    private sealed class HistoryReader(IEnumerable<SigmaHistoryRecord> records) : ISigmaHistoryReader
    {
        internal int Reads;
        public Task<SigmaHistoryRecord?> ReadOneAsync(SigmaHistoryPartition partition, long after, int maxBytes, TimeSpan timeout, CancellationToken ct)
        { Reads++; Assert.True(maxBytes > 0); Assert.Equal(Timeout.InfiniteTimeSpan,timeout); return Task.FromResult(records.FirstOrDefault(x => x.Position > after)); }
    }
    private static (SigmaHistoryPartition Partition, SigmaHistoryRecord[] Rows) HistoryRecords()
    {
        var start = DateTimeOffset.Parse("2026-01-01T00:00:00Z"); var scope = new JsonObject { ["installation_id"] = "11111111-1111-1111-1111-111111111111", ["source_instance_id"] = "synthetic", ["source_generation"] = "1" };
        var partition = new SigmaHistoryPartition(scope, "core_event", start, start.AddDays(1), "synthetic-snapshot", 3);
        SigmaHistoryRecord Row(long id, bool complete = true) => new(id, new JsonObject { ["storage_kind"] = "core_event", ["native_id"] = id == 2 ? "1" : id.ToString(), ["sha256"] = new string('a', 64) }, scope, start,
            new SigmaEvent(4625, "Security", "dc.example.test", start, complete ? new JsonObject { ["EventID"] = 4625, ["TargetUserName"] = "synthetic$", ["IpAddress"] = "192.0.2.2" } : new JsonObject(), []), [], 100);
        return (partition, [Row(1), Row(2), Row(3, false)]);
    }
    [Fact] public async Task Sigma_history_resumes_snapshot_deduplicates_and_keeps_unknown_separate()
    {
        var (part, rows) = HistoryRecords(); var reader = new HistoryReader(rows); var rule = SigmaRule.Compile(Rule); JsonObject? saved = null;
        Task Save(JsonObject state, CancellationToken ct) { saved = state; return Task.CompletedTask; }
        var first = await SigmaHistory.RunAsync("synthetic", [rule], [part], new string('a', 64), reader, _ => true, Save, limits: new(Rows: 1), ct: TestContext.Current.CancellationToken);
        Assert.Equal("partial", first.Status); Assert.Equal("row_budget", first.Reason); Assert.Equal(1, saved.Number("rows_read"));
        var resumed = await SigmaHistory.RunAsync("synthetic", [rule], [part], new string('a', 64), reader, _ => true, Save, first.Checkpoint, ct: TestContext.Current.CancellationToken);
        Assert.Equal("completed", resumed.Status); Assert.Equal("test", resumed.Mode); Assert.Equal(1, resumed.Checkpoint.Number("deduplicated"));
        var count = resumed.Checkpoint["counts"]![0]!; Assert.Equal(2, count.Number("scanned")); Assert.Equal(1, count.Number("matched")); Assert.Equal(1, count.Number("unknown")); Assert.Equal(1, count.Number("evaluable"));
        Assert.Single(resumed.Checkpoint["samples"]!.AsArray());
        await Assert.ThrowsAsync<InvalidDataException>(() => SigmaHistory.RunAsync("other-job", [rule], [part], new string('a', 64), reader, _ => true, Save, first.Checkpoint, ct: TestContext.Current.CancellationToken));
    }
    [Fact] public async Task Sigma_history_revoked_access_discards_samples_before_checkpoint_and_return()
    {
        var (part, rows) = HistoryRecords(); var reader = new HistoryReader(rows); int saves = 0;
        var result = await SigmaHistory.RunAsync("synthetic", [SigmaRule.Compile(Rule)], [part], new string('a', 64), reader, _ => reader.Reads == 0,
            (_, _) => { saves++; return Task.CompletedTask; }, ct: TestContext.Current.CancellationToken);
        Assert.Equal("failed", result.Status); Assert.Equal("permission_denied", result.Reason); Assert.Equal(0, saves); Assert.Equal(0, result.Checkpoint.Number("rows_read")); Assert.Empty(result.Checkpoint["samples"]!.AsArray());
    }
    [Fact] public async Task Sigma_history_invalid_source_and_cancellation_never_make_complete_zero()
    {
        var (part, rows) = HistoryRecords(); var reader = new HistoryReader([rows[0] with { Position = 4 }]);
        var invalid = await SigmaHistory.RunAsync("synthetic", [SigmaRule.Compile(Rule)], [part], new string('a', 64), reader, _ => true, (_, _) => Task.CompletedTask, ct: TestContext.Current.CancellationToken);
        Assert.Equal("failed", invalid.Status); Assert.Equal("reader_contract_invalid", invalid.Reason); Assert.Empty(invalid.Checkpoint["counts"]!.AsArray());
        using var cts = new CancellationTokenSource(); cts.Cancel();
        var cancelled = await SigmaHistory.RunAsync("synthetic", [SigmaRule.Compile(Rule)], [part], new string('a', 64), reader, _ => true, (_, _) => Task.CompletedTask, ct: cts.Token);
        Assert.Equal("cancelled", cancelled.Status);
    }
    [Fact] public void Correlation_cross_host_exact_sid_and_strict_time_requirements_are_enforced()
    {
        JsonObject definition = new() { ["type"] = "sequence", ["partition_kind"] = "domain_account_sid", ["inputs"] = new JsonArray("reset", "logon"), ["window_seconds"] = 300, ["strict_time_order"] = true, ["continuation_policy"] = "anchor_all_admissible", ["output_relation_kind"] = "reset-logon", ["explanation"] = "Synthetic relation" };
        var rule = SemanticCorrelation.Compile(new JsonObject { ["rule_id"] = "synthetic", ["rule_version"] = 1, ["rule_kind"] = "sequence", ["definition_json"] = definition });
        string sid = "S-1-5-21-100000001-200000002-300000003-1001"; var start = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        SemanticEvent Event(long id, string kind, int seconds, long domain = 1) => new(id, kind, start.AddSeconds(seconds), new JsonObject { ["affected_entity"] = "sid:" + sid, ["source_host"] = id.ToString() }, new JsonObject { ["domain_id"] = domain }, new JsonObject(), new string('a', 64));
        var matched = Assert.Single(rule.Match([Event(1, "reset", 0), Event(2, "logon", 1), Event(3, "logon", 299), Event(4, "logon", 10, 2), Event(5, "logon", 301)]));
        Assert.Equal(new long[] { 1, 2, 3 }, matched.Evidence.Select(x => x.Source)); Assert.Empty(rule.Match([Event(1, "reset", 0), Event(2, "logon", 0)]));
        definition["powershell"] = "untrusted"; Assert.Throws<InvalidDataException>(() => SemanticCorrelation.Compile(new JsonObject { ["rule_kind"] = "sequence", ["definition_json"] = definition.Copy() }));
    }
}
