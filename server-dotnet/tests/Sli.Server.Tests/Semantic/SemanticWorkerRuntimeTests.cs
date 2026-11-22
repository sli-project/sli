using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Vectors from tests/semantic/test_semantic_worker_runtime.py. Only the database
// boundary is replaced: normalization, assembly, correlation and replay are real.
[Collection("Semantic producer environment")]
public sealed class SemanticWorkerRuntimeTests
{
    private static readonly DateTimeOffset At = DateTimeOffset.Parse("2026-07-29T00:00:00Z");
    private const string Sid = "S-1-5-21-100000001-200000002-300000003-1001";
    private static readonly Guid Merge = Guid.Parse("00000000-0000-4000-8000-000000000034");
    private static readonly Guid Prior = Guid.Parse("00000000-0000-0000-0000-000000000001");
    private const string ReplayVersion = "1.4+identity-1.0+r7-12a0dc8b420b";
    private static Guid Id(long id) => new((int)id, 0, 0, new byte[8]);
    private static SemanticProduction Worker(int limit = 2, bool assembly = false, bool correlation = false, bool normalization = true) =>
        new(null!, new(Normalization: normalization, Assembly: assembly, DirectoryState: false, Correlation: correlation, Risk: false, Findings: false), "facts-v1", limit);
    private static SemanticProducerPostgresTests.Admission Bundle()
    {
        var admission = new SemanticProducerPostgresTests.Admission();
        admission.Set("SLI_PLUGIN_LOCK_DIR", Path.Combine(SemanticProduction.SourceBundleRoot(null, AppContext.BaseDirectory), "config/plugin_packages/v3"));
        admission.Set("SLI_PLUGIN_RUNTIME_DIR", null);
        return admission;
    }
    private static void Counts(JsonObject result, int claimed, int completed, int failed, int normalized = 0, int actions = 0, int? relations = null)
    {
        var expected = new JsonObject { ["completed"] = completed, ["failed"] = failed, ["claimed"] = claimed };
        if (relations is null) { expected["normalized"] = normalized; expected["actions"] = actions; }
        else expected["relations"] = relations;
        Assert.True(JsonNode.DeepEquals(expected, result), result.ToJsonString());
    }
    [Theory] [InlineData(4719, "audit.policy.changed", 1)] [InlineData(9999, "event.unknown", 0)]
    public async Task Processing_normalizes_assembles_dispatches_then_completes(int eventId, string type, int actions)
    {
        using var admission = Bundle(); var db = new Database(); db.Add(7, eventId: eventId);
        var result = await Worker(assembly: true, correlation: true).ProcessOutbox(db.Open, TestContext.Current.CancellationToken);
        Counts(result, 1, 1, 0, 1, actions);
        Assert.Equal(new[] { "source:7" }, db.Reads);
        Assert.DoesNotContain(db.Commands, command => command.Sql.Contains("from storage_v2_archive_blocks", StringComparison.Ordinal));
        Assert.Equal(type, Assert.Single(db.Normalized.Values).Text("semantic_type"));
        Assert.Equal(new[] { "normalized:7" }.Concat(Enumerable.Repeat("action:7", actions)).Concat(["dispatch:7", "complete:7"]), db.Writes);
        Assert.Equal(2, db.Claims); // An empty claim ends the slice.
    }
    [Fact]
    public async Task Repair_validates_original_provenance_before_reading_source_and_appends_current_work()
    {
        using var admission = Bundle(); var db = new Database(); var job = db.Add(7, "semantic_repair");
        job["payload_json"] = new JsonObject { ["repair_plan_digest"] = new string('a', 64), ["history_plan_digest"] = new string('b', 64),
            ["original_job_id"] = Prior.ToString(), ["original_source_hash"] = job["source_identity_json"].Text("normalized_hash") };
        db.Original = new JsonObject { ["source_event_id"] = 7, ["job_kind"] = "normalize_event", ["status"] = "completed",
            ["processor_id"] = "semantic-shadow", ["processor_version"] = SemanticEvent.Version, ["source_hash"] = job["source_identity_json"].Text("normalized_hash") };
        var original = db.Original.DeepClone();
        Counts(await Worker(1).ProcessOutbox(db.Open, TestContext.Current.CancellationToken), 1, 1, 0, 1);
        Assert.Equal(new[] { "validate:7", "source:7" }, db.Reads);
        Assert.Equal(new[] { "normalized:7", "complete:7" }, db.Writes);
        Assert.True(JsonNode.DeepEquals(original, db.Original));
        Assert.DoesNotContain(db.Commands, c => c.Sql.Contains("update semantic_processing_outbox") && c.Values.Contains(Prior));
    }
    [Theory] [InlineData("digest")] [InlineData("source_hash")] [InlineData("original_status")]
    public async Task Invalid_repair_fails_closed_before_source_io(string conflict)
    {
        var db = new Database(); var job = db.Add(7, "semantic_repair");
        string hash = job["source_identity_json"].Text("normalized_hash")!;
        job["payload_json"] = new JsonObject { ["repair_plan_digest"] = conflict == "digest" ? "invalid" : new string('a', 64),
            ["history_plan_digest"] = new string('b', 64), ["original_job_id"] = Prior.ToString(), ["original_source_hash"] = conflict == "source_hash" ? new string('c', 64) : hash };
        db.Original = new() { ["source_event_id"] = 7, ["job_kind"] = "normalize_event", ["status"] = conflict == "original_status" ? "queued" : "completed",
            ["processor_id"] = "semantic-shadow", ["processor_version"] = SemanticEvent.Version, ["source_hash"] = hash };
        Counts(await Worker(1).ProcessOutbox(db.Open, TestContext.Current.CancellationToken), 1, 0, 1);
        Assert.DoesNotContain("source:7", db.Reads); Assert.Empty(db.Writes); Assert.Equal(new long[] { 7 }, db.Failed);
    }
    [Theory] [InlineData(101, 0)] [InlineData(100, 1)] [InlineData(0, 1)]
    public async Task Context_publishes_one_page_and_defers_only_when_more_remains(int candidates, int completed)
    {
        var db = new Database { ContextCandidates = candidates }; db.Add(20, "investigation_context");
        Counts(await Worker().ProcessOutbox(db.Open, TestContext.Current.CancellationToken), 1, completed, 0);
        Assert.Equal(Enumerable.Range(100, Math.Min(100, candidates)).Select(i => "context:" + i)
            .Append(completed == 0 ? "defer:20" : "complete:20"), db.Writes);
        Assert.DoesNotContain(db.Commands, c => c.Sql.Contains("insert into normalized_events"));
        foreach (var command in db.Commands.Where(c => c.Sql.Contains("insert into semantic_processing_outbox")))
            Assert.Equal("late_related_context", ((JsonObject)command.Values[3]!).Text("selection_reason"));
        if (completed == 0)
        {
            var deferred = Assert.Single(db.Commands, c => c.Sql.Contains("set status='queued'"));
            Assert.Contains("attempt_count=greatest(attempt_count-1,0)", deferred.Sql);
            Assert.Equal(Id(20), deferred.Values[0]); Assert.Equal(Id(10020), deferred.Values[1]);
        }
    }
    [Fact]
    public async Task Identity_replay_uses_merge_version_and_records_old_to_new_before_dispatch()
    {
        using var admission = Bundle(); var db = new Database(); var job = db.Add(7, "semantic_replay", 4728);
        job["processor_version"] = ReplayVersion; job["payload_json"] = new JsonObject { ["identity_merge_id"] = Merge.ToString() };
        Counts(await Worker(correlation: true).ProcessOutbox(db.Open, TestContext.Current.CancellationToken), 1, 1, 0, 1);
        var ev = Assert.Single(db.Normalized.Values); Assert.Equal(ReplayVersion, ev.Text("normalizer_version"));
        Assert.Equal("sid:" + Sid, ev["roles_json"].Text("affected_entity"));
        var merged = Assert.Single(db.Commands, c => c.Sql.StartsWith("select merge_id::text", StringComparison.Ordinal));
        Assert.Equal(Merge, merged.Values[1]);
        var audit = Assert.Single(db.Commands, c => c.Sql.StartsWith("insert into entity_identity_semantic_replays_v2", StringComparison.Ordinal));
        Assert.Equal(new object?[] { Merge, 7L, Prior, Guid.Parse(ev.Text("normalized_event_id")!), Id(7) }, audit.Values);
        Assert.Equal(new[] { "normalized:7", "replay:7", "dispatch:7", "complete:7" }, db.Writes);
    }
    [Fact]
    public async Task Dispatch_persists_relation_and_uses_scoped_completion_in_same_transaction()
    {
        var db = new Database { Dispatch = true, Match = true }; db.Add(7);
        ISemanticSession? completionSession = null;
        var result = await Worker(correlation: true).ProcessDispatch(db.Open, TestContext.Current.CancellationToken, completeJob: async (session, job, ct) => {
            completionSession = session;
            await SemanticProduction.Complete(session, "semantic_correlation_dispatch_jobs", "dispatch_status", job, ct);
        });
        Counts(result, 1, 1, 0, relations: 1); Assert.NotNull(completionSession);
        var relation = Assert.Single(db.Commands, c => c.Sql.Contains("insert into semantic_correlation_candidates("));
        Assert.Same(completionSession, relation.Session);
        Assert.Equal(new[] { "relation:7", "complete:7" }, db.Writes);
        Assert.Equal(2, db.Commands.Count(c => c.Sql.Contains("insert into semantic_correlation_candidate_evidence(")));
    }
    [Fact]
    public async Task Processing_forwards_exact_source_event_claim_scope()
    {
        var db = new Database(); Counts(await Worker(16).ProcessOutbox(db.Open, TestContext.Current.CancellationToken, sourceEventIds: [9, 7]), 0, 0, 0);
        var claim = Assert.Single(db.Commands); Assert.Contains("source_event_id=any($4)", claim.Sql);
        Assert.Contains("skip locked limit 1", claim.Sql); Assert.Equal(new long[] { 7, 9 }, Assert.IsType<long[]>(claim.Values[3]));
    }
    [Fact]
    public async Task Dispatch_forwards_exact_allowed_job_scope()
    {
        var db = new Database { Dispatch = true }; Counts(await Worker(1, correlation: true).ProcessDispatch(db.Open, TestContext.Current.CancellationToken, allowedJobIds: [Id(1)]), 0, 0, 0, relations: 0);
        var claim = Assert.Single(db.Commands); Assert.Contains("job.job_id=any($1::uuid[])", claim.Sql);
        Assert.Contains("skip locked limit $2", claim.Sql); Assert.Equal(new[] { Id(1) }, Assert.IsType<Guid[]>(claim.Values[0]));
    }
    public static IEnumerable<object[]> Batches() =>
        from dispatch in new[] { false, true }
        from size in new[] { (40, 40, 40), (140, 10000, 128), (20, 7, 7), (3, 128, 3) }
        from stop in new[] { "none", "SIGTERM", "SIGINT" }
        select new object[] { dispatch, size.Item1, size.Item2, size.Item3, stop };
    [Theory] [MemberData(nameof(Batches))]
    public async Task Batches_claim_process_complete_in_order_and_drain_current_job_on_stop(bool dispatch, int queued, int limit, int expected, string stop)
    {
        using var admission = Bundle(); using var stopping = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var db = new Database { Dispatch = dispatch }; for (int i = 1; i <= queued; i++) db.Add(i);
        // Both OS signals map to a stop request, without raising process-wide signals in xUnit.
        if (stop != "none") { db.OnPersist = () => stopping.Cancel(); expected = 1; }
        var worker = Worker(limit, correlation: dispatch);
        var result = dispatch ? await worker.ProcessDispatch(db.Open, stopping.Token) : await worker.ProcessOutbox(db.Open, stopping.Token);
        if (dispatch) Counts(result, expected, expected, 0, relations: 0);
        else Counts(result, expected, expected, 0, expected);
        Assert.Equal(Enumerable.Range(1, expected).SelectMany(i => new[] { "claim:" + i, "persist:" + i, "complete:" + i }), db.Calls);
        Assert.Equal(Enumerable.Range(expected + 1, queued - expected).Select(i => (long)i), db.Pending.Select(j => j.Number("source_event_id")));
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Failed_job_rolls_back_before_failure_record_and_next_claim(bool dispatch)
    {
        using var admission = Bundle(); var db = new Database { Dispatch = dispatch, FailCompletion = 2 };
        for (int i = 1; i <= 3; i++) db.Add(i);
        var worker = Worker(128, correlation: dispatch);
        var result = dispatch ? await worker.ProcessDispatch(db.Open, TestContext.Current.CancellationToken) : await worker.ProcessOutbox(db.Open, TestContext.Current.CancellationToken);
        if (dispatch) Counts(result, 3, 2, 1, relations: 0); else Counts(result, 3, 2, 1, 2);
        Assert.Equal(new long[] { 2 }, db.Failed);
        Assert.Equal(dispatch ? new[] { "complete:1", "complete:3" } : new[] { "normalized:1", "complete:1", "normalized:3", "complete:3" }, db.Writes);
        Assert.Equal(new[] { "claim:1", "persist:1", "complete:1", "claim:2", "persist:2", "rollback:2", "fail:2", "claim:3", "persist:3", "complete:3" }, db.Calls);
        var failed = Assert.Single(db.Commands, c => c.Sql.Contains("last_error_detail=$5"));
        Assert.Equal("failed", failed.Values[0]); Assert.Equal(Id(2), failed.Values[2]); Assert.Equal(Id(10002), failed.Values[3]);
        if (!dispatch) Assert.DoesNotContain(db.Normalized.Values, n => n.Number("source_event_id") == 2);
    }
    [Theory]
    [InlineData("{\"completed\":1}", true)] [InlineData("{\"failed\":1}", true)] [InlineData("{\"risk_queued\":1}", true)]
    [InlineData("{\"processing\":{\"claimed\":1,\"completed\":0,\"failed\":0}}", true)]
    [InlineData("{\"dispatch\":{\"claimed\":1}}", true)]
    [InlineData("{\"password_producer\":{\"jobs\":1}}", true)]
    [InlineData("{\"password_risk\":{\"claimed\":1}}", true)]
    [InlineData("{\"password_producer\":{\"completed\":2,\"jobs\":0},\"password_risk\":{\"claimed\":0}}", false)]
    [InlineData("{\"completed\":0,\"failed\":0,\"processing\":{\"claimed\":0}}", false)]
    public void Cycle_activity_includes_deferred_context_and_failures(string json, bool expected) => Assert.Equal(expected, SemanticProduction.CycleHasWork(JsonNode.Parse(json)));

    private sealed class Database
    {
        internal readonly Queue<JsonObject> Pending = new();
        internal readonly Dictionary<Guid, JsonObject> Normalized = new();
        internal readonly Dictionary<string, JsonObject> Enqueued = new();
        internal readonly Dictionary<long, JsonObject> Native = new();
        internal readonly List<string> Writes = [], Calls = [], Reads = [];
        internal readonly List<long> Failed = [];
        internal readonly List<(string Sql, object?[] Values, ISemanticSession Session)> Commands = [];
        internal bool Dispatch, Match;
        internal int ContextCandidates, Claims;
        internal long FailCompletion;
        internal Action? OnPersist;
        internal JsonObject? Original;
        private JsonObject current = new();
        internal JsonObject Add(long id, string kind = "normalize_event", int eventId = 4719)
        {
            string xml = "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><EventData>" +
                "<Data Name=\"MemberName\">synthetic</Data><Data Name=\"TargetUserName\">synthetic</Data><Data Name=\"TargetDomainName\">example.test</Data></EventData></Event>";
            var row = new JsonObject { ["event_id"] = eventId, ["record_id"] = id, ["time_created"] = SemanticJson.Stamp(At), ["channel"] = "Security", ["machine_name"] = "dc.example.test", ["xml"] = xml };
            string hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(SourceJson.SerializeSorted(row))));
            var identity = new JsonObject { ["id"] = id, ["event_id"] = eventId, ["event_record_id"] = id, ["server_id"] = 1, ["domain_id"] = 1, ["log_source_id"] = 1,
                ["time_created_utc"] = SemanticJson.Stamp(At), ["migrated_at"] = SemanticJson.Stamp(At), ["normalized_hash"] = hash,
                ["channel"] = "Security", ["provider_name"] = "Microsoft-Windows-Security-Auditing", ["computer"] = "dc.example.test" };
            var source=identity.DeepClone().AsObject();
            source["event_data_json"]=new JsonObject { ["MemberName"]="synthetic",["TargetUserName"]="synthetic",["TargetDomainName"]="example.test" };
            Native[id] = source;
            var job = new JsonObject { ["job_id"] = Id(id).ToString(), ["source_event_id"] = id, ["job_kind"] = kind, ["lease_token"] = Id(10000 + id).ToString(), ["attempt_count"] = 1, ["max_attempts"] = 5,
                ["processor_id"] = "semantic-shadow", ["processor_version"] = SemanticEvent.Version, ["source_identity_json"] = identity, ["payload_json"] = new JsonObject(),
                ["rule_id"] = "synthetic", ["rule_version"] = 1, ["normalized_event_id"] = Id(20000 + id).ToString(), ["partition_key"] = "1" };
            Pending.Enqueue(job); return job;
        }
        internal Task<ISemanticSession> Open(CancellationToken ct) => Task.FromResult<ISemanticSession>(new Session(this));
        private JsonObject Event(long id, string type) => new() { ["normalized_event_id"] = Id(20000 + id).ToString(), ["source_event_id"] = id, ["semantic_type"] = type,
            ["occurred_at_utc"] = SemanticJson.Stamp(At.AddSeconds(id)), ["roles_json"] = new JsonObject { ["source_host"] = "1" }, ["facts_json"] = new JsonObject(), ["quality_json"] = new JsonObject(),
            ["semantic_sha256"] = new string('a', 64), ["normalizer_version"] = SemanticEvent.Version, ["normalizer_id"] = SemanticEvent.Normalizer, ["semantic_contract_version"] = 1 };
        private static JsonObject Rule() => new() { ["rule_id"] = "synthetic", ["rule_version"] = 1, ["rule_kind"] = "sequence", ["lifecycle_status"] = "shadow",
            ["definition_json"] = new JsonObject { ["type"] = "sequence", ["inputs"] = new JsonArray("reset", "logon"), ["join_roles"] = new JsonArray("source_host"),
                ["window_seconds"] = 300, ["output_relation_kind"] = "test", ["explanation"] = "synthetic", ["confidence"] = "low" } };
        private sealed class Session(Database db) : ISemanticSession
        {
            private readonly string[] before = db.Writes.ToArray();
            private readonly Dictionary<Guid, JsonObject> normalizedBefore = db.Normalized.ToDictionary(p => p.Key, p => p.Value.DeepClone().AsObject());
            private bool committed;
            private JsonObject? dispatch, candidate;
            private Guid nextReplay, replayJob;
            private static JsonArray Rows(JsonObject row) => new(row.DeepClone());
            public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] v)
            {
                Assert.False(ct.IsCancellationRequested); db.Commands.Add((sql, v, this)); JsonArray rows = [];
                long id = db.current.Number("source_event_id");
                if (sql.Contains("with candidates as"))
                {
                    db.Claims++; if (db.Pending.TryDequeue(out var job)) { db.current = job; rows = Rows(job); db.Calls.Add("claim:" + job.Number("source_event_id")); }
                }
                else if (sql.Contains("set heartbeat_at=now()")) rows = Rows(db.current);
                else if (sql.StartsWith("select lifecycle_status from semantic_correlation_rules", StringComparison.Ordinal)) rows = Rows(new() { ["lifecycle_status"] = "shadow" });
                else if (sql.Contains("last_error_detail=$5")) { db.Failed.Add(id); db.Calls.Add("fail:" + id); rows = Rows(db.current); }
                else if (sql.Contains("set status='queued'")) { db.Writes.Add("defer:" + id); rows = Rows(db.current); }
                else if (sql.Contains("completed_at=now()"))
                {
                    if (id == db.FailCompletion) throw new InvalidOperationException("fixture completion failure");
                    db.Calls.Add("complete:" + id); db.Writes.Add("complete:" + id); rows = Rows(db.current);
                }
                else if (sql.StartsWith("select source_event_id,job_kind,status", StringComparison.Ordinal)) { db.Reads.Add("validate:" + id); rows = Rows(db.Original!); }
                else if (sql.Contains("from public.semantic_event_source355 where id=$1", StringComparison.Ordinal))
                {
                    long sourceId = Assert.IsType<long>(v[0]);
                    db.Reads.Add("source:" + sourceId);
                    if (db.Native.TryGetValue(sourceId, out var source)) rows = Rows(source);
                }
                else if (sql.Contains("from storage_v2_archive_blocks", StringComparison.Ordinal)) { /* No published archive blocks. */ }
                else if (sql.Contains("insert into normalized_events("))
                {
                    db.Normalized[(Guid)v[0]!] = new JsonObject { ["normalized_event_id"] = v[0]!.ToString(), ["source_event_id"] = (long)v[1]!, ["normalizer_version"] = (string)v[2]!,
                        ["semantic_sha256"] = Convert.ToHexStringLower((byte[])v[4]!), ["semantic_type"] = (string)v[5]!, ["occurred_at_utc"] = SemanticJson.Stamp((DateTimeOffset)v[6]!),
                        ["roles_json"] = ((JsonObject)v[8]!).DeepClone(), ["facts_json"] = ((JsonObject)v[9]!).DeepClone(), ["quality_json"] = ((JsonObject)v[10]!).DeepClone() };
                    db.Writes.Add("normalized:" + id); db.Calls.Add("persist:" + id); db.OnPersist?.Invoke();
                }
                else if (sql.StartsWith("select normalized_event_id,semantic_type", StringComparison.Ordinal)) rows = Rows(db.Normalized.Values.Single(n => n.Number("source_event_id") == (long)v[0]!));
                else if (sql.Contains("insert into canonical_actions(")) db.Writes.Add("action:" + id);
                else if (sql.Contains("from semantic_correlation_subscriptions")) rows = Rows(Rule());
                else if (sql.StartsWith("select source_ingested_at", StringComparison.Ordinal)) rows = Rows(new() { ["source_ingested_at"] = SemanticJson.Stamp(At) });
                else if (sql.Contains("insert into semantic_correlation_dispatch_jobs("))
                {
                    dispatch = new() { ["job_id"] = v[0]!.ToString(), ["normalized_event_id"] = v[1]!.ToString(), ["partition_key"] = (string)v[5]!, ["is_late"] = (bool)v[7]! }; db.Writes.Add("dispatch:" + id);
                }
                else if (sql.StartsWith("select job_id,normalized_event_id,partition_key", StringComparison.Ordinal)) rows = Rows(dispatch!);
                else if (sql.Contains("to_regclass('entity_identity_merges_v2')")) rows = Rows(new() { ["available"] = true });
                else if (sql.StartsWith("select merge_id::text", StringComparison.Ordinal))
                    rows = new JsonArray(((string[])v[0]!).Select(key => (JsonNode)new JsonObject { ["merge_id"] = Merge.ToString(), ["source_natural_key"] = key, ["target_natural_key"] = "sid:" + Sid }).ToArray());
                else if (sql.StartsWith("select distinct n.normalized_event_id::text", StringComparison.Ordinal)) rows = Rows(new() { ["normalized_event_id"] = Prior.ToString() });
                else if (sql.StartsWith("insert into entity_identity_semantic_replays_v2", StringComparison.Ordinal)) { nextReplay = (Guid)v[3]!; replayJob = (Guid)v[4]!; db.Writes.Add("replay:" + id); }
                else if (sql.StartsWith("select new_normalized_event_id,replay_job_id", StringComparison.Ordinal)) rows = Rows(new() { ["new_normalized_event_id"] = nextReplay.ToString(), ["replay_job_id"] = replayJob.ToString() });
                else if (sql.StartsWith("select e.domain_id,e.target_user_sid", StringComparison.Ordinal)) rows = Rows(new() { ["domain_id"] = 1, ["target_user_sid"] = Sid, ["time_created_utc"] = SemanticJson.Stamp(At), ["event_id"] = 4724,
                    ["channel"] = "Security", ["provider_name"] = "Microsoft-Windows-Security-Auditing", ["keywords"] = "0x8020000000000000" });
                else if (sql.StartsWith("select e.id from public.semantic_event_source355", StringComparison.Ordinal)) rows = new JsonArray(Enumerable.Range(100, db.ContextCandidates).Select(n => (JsonNode)new JsonObject { ["id"] = n }).ToArray());
                else if (sql.Contains("insert into semantic_processing_outbox("))
                {
                    db.Writes.Add("context:" + v[4]);
                    var identity = db.current["source_identity_json"]!.DeepClone().AsObject(); identity["id"] = (long)v[4]!;
                    db.Enqueued[Convert.ToHexString((byte[])v[2]!)] = new() { ["job_id"] = v[0]!.ToString(), ["payload_json"] = ((JsonObject)v[3]!).DeepClone(), ["source_identity_json"] = identity };
                }
                else if (sql.StartsWith("select job_id,payload_json,source_identity_json", StringComparison.Ordinal)) rows = Rows(db.Enqueued[Convert.ToHexString((byte[])v[0]!)]);
                else if (sql.StartsWith("select rule_id,rule_version,rule_kind", StringComparison.Ordinal)) rows = Rows(Rule());
                else if (sql.StartsWith("select normalized_event_id,source_event_id", StringComparison.Ordinal)) rows = new JsonArray(db.Event(id, "reset"), db.Event(id + 1, "logon"));
                else if (sql.Contains("from normalized_events where normalized_event_id=$1")) rows = Rows(db.Event(id, "reset"));
                else if (sql.Contains("from normalized_events where processing_status='normalized'"))
                {
                    db.Calls.Add("persist:" + id); db.OnPersist?.Invoke();
                    if (db.Match) rows = new JsonArray(db.Event(id, "reset"), db.Event(id + 1, "logon"));
                }
                else if (sql.Contains("insert into semantic_correlation_candidates("))
                {
                    candidate = new() { ["candidate_id"] = v[0]!.ToString(), ["relation_kind"] = (string)v[3]!, ["partition_key"] = (string)v[5]! }; db.Writes.Add("relation:" + id);
                }
                else if (sql.StartsWith("select candidate_id,relation_kind", StringComparison.Ordinal)) rows = Rows(candidate!);
                else if (sql.StartsWith("select count(*) as evidence_count", StringComparison.Ordinal)) rows = Rows(new() { ["evidence_count"] = 2, ["maximum_order"] = 1 });
                else if (!(sql.Contains("pg_advisory_xact_lock") || sql.Contains("canonical_action") || sql.Contains("semantic_correlation_candidate_evidence") || sql.Contains("update semantic_correlation_candidates")))
                    throw new InvalidOperationException("Unexpected test query: " + sql);
                return Task.FromResult(rows);
            }
            public Task CommitAsync(CancellationToken ct) { Assert.False(ct.IsCancellationRequested); committed = true; return Task.CompletedTask; }
            public ValueTask DisposeAsync()
            {
                if (!committed)
                {
                    db.Writes.Clear(); db.Writes.AddRange(before); db.Normalized.Clear();
                    foreach (var pair in normalizedBefore) db.Normalized.Add(pair.Key, pair.Value);
                    db.Calls.Add("rollback:" + db.current.Number("source_event_id"));
                }
                return ValueTask.CompletedTask;
            }
        }
    }
}
