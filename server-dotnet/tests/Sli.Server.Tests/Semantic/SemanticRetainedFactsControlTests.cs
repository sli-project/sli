using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;
using static Sli.Server.Semantic.SemanticRetainedManifest;

namespace Sli.Server.Tests.Semantic;

// Port of tests/semantic/test_semantic_retained_facts_control.py. The fake owns
// transaction boundaries; all selection, publication and controller code is production code.
[Collection("Semantic producer environment")]
public sealed partial class SemanticRetainedFactsControlTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private sealed record Source(long Id, int Event, string Hash, bool Context = false);
    private sealed class Fixture : ISemanticDatabase, IDisposable
    {
        internal readonly string DirectoryPath = Path.Combine(Path.GetTempPath(), "sli-retained-287-" + Guid.NewGuid());
        internal readonly List<Source> Sources = [];
        internal readonly List<(bool Write, string Sql, object?[] Values, int Session)> Calls = [];
        internal readonly List<long[]> Published = [];
        internal readonly HashSet<long> Current = [];
        internal readonly Dictionary<int, JsonObject> Reconciliations = [];
        internal JsonArray Queue = [], Repairs = [];
        internal JsonObject IdentityValue = new() { ["host"] = "192.0.2.1", ["database"] = "synthetic", ["role"] = "test_owner" };
        internal JsonObject Heartbeat = Worker();
        internal bool ThrowPublish, ThrowCommit, Busy, PendingRepair;
        internal int Commits, Opens, SnapshotQueries, PageSize = 5000;
        internal Action<string>? OnLock;
        internal string Mode = "investigation-v1";
        internal string? CallerRole;
        internal readonly List<string> Sequence = [];
        internal SemanticRetainedControl Control(Action<string, JsonObject>? writer = null) => new(this, DirectoryPath, Get, writer);
        private string? Get(string key) => key switch {
            "ADLOG_SEMANTIC_PRODUCTION_ENABLED" or "ADLOG_SEMANTIC_NORMALIZATION_ENABLED" or "ADLOG_SEMANTIC_ASSEMBLY_ENABLED" => "1",
            "ADLOG_SEMANTIC_RUNTIME_MODE" => Mode,
            "ADLOG_SEMANTIC_CORRELATION_ENABLED" => Mode == "investigation-v1" ? "1" : "0", _ => "0" };
        internal void Add(long id, int eventId, bool context = false) => Sources.Add(new(id, eventId, new string('a', 64), context));
        internal JsonObject ExtendedIdentity { get { var value = IdentityValue.DeepClone().AsObject(); value["system_identifier"] = "12345"; value["port"] = "5432"; value["database_oid"] = "16384"; return value; } }
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct) { Opens++; return Task.FromResult<ISemanticSession>(new Session(this, write, Opens)); }
        private sealed class Session(Fixture owner, bool write, int number) : ISemanticSession
        {
            private long[]? pending;
            public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
            {
                owner.Calls.Add((write, sql, values, number));
                JsonArray Rows(IEnumerable<Source> sources) => new(sources.Select(s => (JsonNode)new JsonObject { ["id"] = s.Id, ["normalized_hash"] = s.Hash }).ToArray());
                JsonArray One(JsonNode value) => new(value.DeepClone());
                if (sql.StartsWith("select pg_try_advisory_xact_lock")) { string name = (string)values[0]!; owner.OnLock?.Invoke(name); owner.Sequence.Add("lock-enter:" + name); return Task.FromResult(One(new JsonObject { ["locked"] = !owner.Busy })); }
                if (sql.StartsWith("set local role")) return Task.FromResult(new JsonArray());
                if (sql.StartsWith("select coalesce(inet_server_addr")) { var identity = owner.IdentityValue.DeepClone().AsObject(); if (sql.Contains("current_user as role") && owner.CallerRole is { } role) identity["role"] = role; return Task.FromResult(One(identity)); }
                if (sql.StartsWith("select system_identifier")) return Task.FromResult(One(new JsonObject { ["system_identifier"] = "12345", ["port"] = "5432", ["database_oid"] = "16384" }));
                if (sql.StartsWith("select coalesce(max(id)")) return Task.FromResult(One(new JsonObject { ["high_watermark"] = owner.Sources.Select(s => s.Id).DefaultIfEmpty().Max() }));
                if (sql.Contains("from runtime_worker_heartbeats")) return Task.FromResult(One(owner.Heartbeat));
                if (sql == SemanticRetainedSql.PendingRepair) return Task.FromResult(owner.PendingRepair ? One(new JsonObject { ["original_job_id"] = "synthetic" }) : new JsonArray());
                if (sql == SemanticRetainedSql.ExactQueue) return Task.FromResult(owner.Queue.DeepClone().AsArray());
                if (sql == SemanticRetainedSql.RepairRows) return Task.FromResult(owner.Repairs.DeepClone().AsArray());
                if (sql == SemanticRetainedSql.ContextReconcile) return Task.FromResult(One(owner.Reconciliations.GetValueOrDefault(4624) ?? Counts()));
                if (sql == SemanticRetainedSql.Reconcile) return Task.FromResult(One(owner.Reconciliations.GetValueOrDefault((int)values[7]!) ?? Counts()));
                if (sql == SemanticRetainedSql.Targets) return Task.FromResult(Rows(owner.Sources.Where(s => s.Event == (int)values[1]! && s.Id > (long)values[2]! && s.Id <= (long)values[3]! && !owner.Current.Contains(s.Id)).OrderBy(s => s.Id).Take(Math.Min(owner.PageSize, (int)values[7]!))));
                if (sql.StartsWith("select core.id,encode(core.normalized_hash")) {
                    owner.SnapshotQueries++;
                    return Task.FromResult(Rows(owner.Sources.Where(s => s.Event == (int)values[1]! && s.Id > (long)values[2]! && s.Id <= (long)values[3]!).OrderBy(s => s.Id).Take(256)));
                }
                if (sql.StartsWith("with page as")) return Task.FromResult(new JsonArray(owner.Sources.Where(s => s.Event == 4624 && s.Id > (long)values[0]! && s.Id <= (long)values[1]!).OrderBy(s => s.Id).Take(256).Select(s => (JsonNode)new JsonObject {
                    ["id"] = s.Id, ["normalized_hash"] = s.Hash, ["reset_keywords"] = s.Context ? new JsonArray("Audit Success") : new JsonArray("Audit Failure"), ["current"] = owner.Current.Contains(s.Id) }).ToArray()));
                if (sql.StartsWith("select id from semantic_event_rows")) {
                    var selected = values.Length == 1 ? owner.Sources.Where(s => ((long[])values[0]!).Contains(s.Id)) : owner.Sources.Where(s => s.Id > (long)values[0]! && s.Id <= (long)values[1]!).Take((int)values[2]!);
                    return Task.FromResult(Rows(selected.OrderBy(s => s.Id)));
                }
                if (sql.StartsWith("select e.id,e.event_id::text as event_key")) return Task.FromResult(new JsonArray(owner.Sources.Where(s => ((long[])values[0]!).Contains(s.Id)).OrderBy(s => s.Id).Select(s => (JsonNode)new JsonObject { ["id"] = s.Id, ["event_key"] = s.Event.ToString(), ["stream"] = "Security", ["provider_name"] = Provider(s.Event) }).ToArray()));
                if (sql.Contains("insert into semantic_processing_outbox")) {
                    if (owner.ThrowPublish) throw new InvalidOperationException("producer transaction failed");
                    pending = ((JsonArray)values[0]!).Select(r => r.Number("id")).ToArray(); owner.Published.Add(pending); owner.Sequence.Add("publish"); return Task.FromResult(new JsonArray(pending.Select(id => (JsonNode)new JsonObject { ["job_id"] = id.ToString() }).ToArray()));
                }
                throw new InvalidOperationException("Unexpected test SQL: " + sql);
            }
            public Task CommitAsync(CancellationToken ct) { if (owner.ThrowCommit) throw new InvalidOperationException("commit failed"); owner.Commits++; owner.Sequence.Add("commit"); return Task.CompletedTask; }
            public ValueTask DisposeAsync() { if (owner.Calls.Any(c => c.Session == number && c.Sql.StartsWith("select pg_try_advisory_xact_lock"))) owner.Sequence.Add("lock-exit"); return ValueTask.CompletedTask; }
        }
        public void Dispose() { if (Directory.Exists(DirectoryPath)) Directory.Delete(DirectoryPath, true); }
    }
    private static JsonObject Worker() => new() { ["status"] = "idle", ["phase"] = "production_sleep", ["details_json"] = new JsonObject { ["runtime_mode"] = "investigation-v1", ["manual_runtime"] = false, ["processing_contract"] = ProcessingContract } };
    private static JsonObject Counts(long retained = 0, long normalized = 0, string? state = null, long actions = 0) => new() { ["retained_count"] = retained, ["normalized_count"] = normalized, ["normalization_failed"] = 0, ["normalization_quarantined"] = 0,
        ["outbox_queued"] = state == "queued" ? 1 : 0, ["outbox_leased"] = state == "leased" ? 1 : 0, ["outbox_completed"] = state == "completed" ? 1 : 0, ["outbox_failed"] = state == "failed" ? 1 : 0, ["outbox_quarantined"] = state == "quarantined" ? 1 : 0, ["action_evidence_count"] = actions };
    private static JsonObject QueueRow(long id, string state, bool identity = true, bool normalized = true) => new() { ["source_event_id"] = id, ["status"] = state, ["identity_matches"] = identity, ["normalized"] = normalized };
    private static JsonObject FactsCheckpoint(Fixture f, long high = 10, long after = 5, string? fingerprint = null) => new() { ["checkpoint_type"] = "retained_v2_semantic_facts", ["database_identity"] = f.ExtendedIdentity, ["status"] = "active", ["range_start_event_id"] = 1, ["frozen_high_watermark_event_id"] = high, ["last_committed_event_id"] = after,
        ["rules_fingerprint"] = fingerprint ?? SemanticRetainedControl.RulesFingerprint(), ["batch_limit"] = 5000, ["include_context"] = true };
    private static async Task<JsonObject> SaveHistory(Fixture f, bool v2 = true, int batch = 5000)
    {
        var c = f.Control(); var snapshot = await c.Snapshot(null, true, Ct); var manifest = New(snapshot, PlanDigest(snapshot), v2: v2, batch: batch); Write(c.HistoryPath, manifest); return manifest;
    }
    private static async Task<JsonObject> Check(SemanticRetainedControl c) { var plan = await c.HistoryCheckPlan(Ct); return await c.HistoryCheck(plan.Text("plan_digest")!, plan.Text("confirmation")!, Ct); }

    [Fact]
    public void Fresh_idle_worker_without_current_claim_contract_is_rejected()
    {
        var worker = Worker(); worker["details_json"]!.AsObject().Remove("processing_contract");
        Assert.Contains("fresh compatible managed investigation worker", Assert.Throws<InvalidOperationException>(() => SemanticRetainedControl.RequireCompatibleWorker(worker)).Message);
        SemanticRetainedControl.RequireCompatibleWorker(Worker());
        var extended = Worker(); extended["details_json"]!["processing_contract"]!["extra_metadata"] = "synthetic"; SemanticRetainedControl.RequireCompatibleWorker(extended);
        var encoded = Worker(); encoded["details_json"] = encoded["details_json"]!.ToJsonString(); SemanticRetainedControl.RequireCompatibleWorker(encoded);
        foreach (string name in ProcessingContract.Select(p => p.Key)) { var changed = Worker(); changed["details_json"]!["processing_contract"]![name] = null; Assert.Throws<InvalidOperationException>(() => SemanticRetainedControl.RequireCompatibleWorker(changed)); }
    }
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Facts_publication_or_commit_failure_does_not_advance_durable_cursor(bool commit)
    {
        using var f = new Fixture { Mode = "facts-v1", ThrowPublish = !commit, ThrowCommit = commit }; f.Add(6, 4728); f.Add(7, 4727); var c = f.Control(); Write(c.FactsPath, FactsCheckpoint(f));
        await Assert.ThrowsAsync<InvalidOperationException>(() => c.FactsPoll(Ct)); Assert.Equal(5, Read(c.FactsPath).Number("last_committed_event_id")); Assert.Equal(0, f.Commits);
    }
    [Fact]
    public async Task Facts_resume_uses_only_frozen_range_and_existing_managed_consumer()
    {
        using var f = new Fixture { Mode = "facts-v1" }; f.Add(4, 4727); f.Add(6, 4728); f.Add(8, 4728); f.Add(11, 4727); var c = f.Control(); Write(c.FactsPath, FactsCheckpoint(f));
        var result = await c.FactsPoll(Ct); Assert.Equal(new long[] { 6, 8 }, Assert.Single(f.Published)); Assert.Equal(1, f.Commits); Assert.Equal(8, Read(c.FactsPath).Number("last_committed_event_id")); Assert.Equal("existing_managed_facts_worker", result.Text("consumer"));
        Assert.Contains(f.Calls, q => q.Values.Length == 3 && q.Values.SequenceEqual(new object[] { 5L, 10L, 5000 }));
    }
    [Fact]
    public async Task Changed_rules_fail_before_source_reads_or_publication()
    {
        using var f = new Fixture { Mode = "facts-v1" }; f.Add(2, 4728);
        var c = f.Control();
        Write(c.FactsPath, FactsCheckpoint(f, fingerprint: PreviousRulesFingerprint));
        byte[] previous = File.ReadAllBytes(c.FactsPath);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => c.FactsPoll(Ct));
        Assert.Contains("rules fingerprint mismatch", error.Message);
        Assert.Single(f.Calls);
        Assert.Empty(f.Published);
        Assert.Equal(previous, File.ReadAllBytes(c.FactsPath));

        File.Move(c.FactsPath, c.FactsPath + ".previous");
        var result = await c.FactsPoll(Ct);
        Assert.Equal(0, result.Number("from_event_id_exclusive"));
        Assert.Equal(new long[] { 2 }, Assert.Single(f.Published));
        Assert.Equal(SemanticRetainedControl.RulesFingerprint(), Read(c.FactsPath).Text("rules_fingerprint"));
    }
    [Fact]
    public async Task New_facts_checkpoint_freezes_upper_bound_before_first_publication()
    {
        using var f = new Fixture { Mode = "facts-v1" }; f.Add(1, 4728); f.Add(2, 4728); var c = f.Control((path, value) => { if (value.Number("last_committed_event_id") == 0) { Assert.Empty(f.Published); f.Add(9, 4727); } Write(path, value); });
        await c.FactsPoll(Ct); var checkpoint = Read(c.FactsPath)!; Assert.Equal(1, checkpoint.Number("range_start_event_id")); Assert.Equal(2, checkpoint.Number("frozen_high_watermark_event_id")); Assert.Equal(2, checkpoint.Number("last_committed_event_id")); Assert.Equal(new long[] { 1, 2 }, Assert.Single(f.Published));
    }
    [Fact]
    public async Task Admission_precedes_initial_checkpoint()
    { using var f = new Fixture { Mode = "investigation-v1" }; var c = f.Control(); await Assert.ThrowsAsync<InvalidOperationException>(() => c.FactsPoll(Ct)); Assert.False(File.Exists(c.FactsPath)); Assert.Empty(f.Published); }
    [Fact]
    public async Task Lost_atomic_checkpoint_write_replays_only_the_committed_batch()
    {
        using var f = new Fixture { Mode = "facts-v1" }; f.Add(6, 4728); f.Add(8, 4728); var c = f.Control((_, _) => throw new IOException("checkpoint disk unavailable")); Write(c.FactsPath, FactsCheckpoint(f));
        await Assert.ThrowsAsync<IOException>(() => c.FactsPoll(Ct)); Assert.Equal(1, f.Commits); Assert.Equal(5, Read(c.FactsPath).Number("last_committed_event_id")); await f.Control().FactsPoll(Ct);
        Assert.Equal(2, f.Commits); Assert.Equal(2, f.Published.Count); Assert.All(f.Published, ids => Assert.Equal(new long[] { 6, 8 }, ids)); Assert.Equal(8, Read(c.FactsPath).Number("last_committed_event_id"));
    }
    [Fact]
    public async Task History_plan_is_read_only_and_poll_publishes_one_exact_frozen_cohort()
    {
        using var f = new Fixture(); f.Add(7, 4727); f.Add(9, 4727); var c = f.Control(); var plan = await c.HistoryPlan(Ct);
        Assert.False(plan.Flag("production_changed")); Assert.False(File.Exists(c.HistoryPath)); Assert.All(f.Calls, q => Assert.False(q.Write));
        var result = await c.HistoryPoll(plan.Text("confirmation")!, Ct); Assert.Equal("existing_managed_investigation_worker", result.Text("consumer")); Assert.Equal(new long[] { 7, 9 }, Assert.Single(f.Published));
        var manifest = Read(c.HistoryPath)!; Assert.Equal(V2, manifest.Text("manifest_type")); Assert.Null(manifest["supersedes"]); Assert.Equal(9, manifest["events"]!["4727"].Number("cursor")); Assert.Equal("queued", manifest["events"]!["4727"].Text("state")); Assert.Equal("no_retained_events", manifest["events"]!["1102"].Text("state"));
    }
    [Fact]
    public async Task V2_logon_raw_coverage_is_separate_from_exact_context_and_never_expands_late()
    {
        using var f = new Fixture(); f.Add(7, 4624); f.Add(8, 4624, true); f.Add(9, 4624); var c = f.Control(); var plan = await c.HistoryPlan(Ct);
        var result = await c.HistoryPoll(plan.Text("confirmation")!, Ct); Assert.Equal(4624, result.Number("event_id")); Assert.Equal(new long[] { 8 }, Assert.Single(f.Published));
        var e = Read(c.HistoryPath)!["events"]!["4624"]!; Assert.Equal(3, e.Number("raw_retained_count")); Assert.Equal(1, e.Number("semantic_expected_count"));
        Assert.DoesNotContain(f.Calls, q => q.Sql == SemanticRetainedSql.Targets); var enqueue = Assert.Single(f.Calls, q => q.Sql.Contains("insert into semantic_processing_outbox")); Assert.All(((JsonArray)enqueue.Values[0]!), row => Assert.Equal("normalize_event", row.Text("kind")));
    }
    [Fact]
    public async Task Context_4776_is_an_exact_publication_despite_zero_signal_count()
    { using var f = new Fixture(); f.Add(77, 4776); var c = f.Control(); var plan = await c.HistoryPlan(Ct); var result = await c.HistoryPoll(plan.Text("confirmation")!, Ct); Assert.Equal(1, result["producer"].Number("queued")); Assert.Equal(0, result["producer"].Number("signal_queued")); Assert.Equal("queued", Read(c.HistoryPath)!["events"]!["4776"].Text("state")); }
    [Fact]
    public async Task V1_cannot_poll_until_explicitly_superseded()
    { using var f = new Fixture(); f.Add(9, 4724); var m = await SaveHistory(f, false, 100); var c = f.Control(); string before = File.ReadAllText(c.HistoryPath); var error = await Assert.ThrowsAsync<InvalidOperationException>(() => c.HistoryPoll(SemanticRetainedControl.PollPrefix + m.Text("plan_digest"), Ct)); Assert.Contains("explicit supersede", error.Message); Assert.Equal(before, File.ReadAllText(c.HistoryPath)); Assert.Empty(f.Published); }
    [Fact]
    public async Task Supersede_keeps_legacy_boundaries_archives_once_and_installs_resumable_v2()
    {
        using var f = new Fixture(); f.Add(7, 4624); f.Add(90, 4624, true); f.Add(80, 4724); var legacy = await SaveHistory(f, false, 100); f.Add(100, 4624, true); f.Add(101, 4724); var c = f.Control(); var plan = await c.SupersedePlan(Ct);
        Assert.Equal(5000, plan.Number("batch_limit")); Assert.Equal(90, plan["raw_cohorts"]!["4624"].Number("high_watermark")); Assert.Equal(80, plan["semantic_context_cohort"].Number("reset_high_watermark"));
        var result = await c.Supersede(plan.Text("replacement_plan_digest")!, plan.Text("confirmation")!, Ct); Assert.True(JsonNode.DeepEquals(legacy, Read(result.Text("v1_archive_path")!))); var replacement = Read(c.HistoryPath)!; Assert.Equal(V2, replacement.Text("manifest_type")); Assert.Equal(legacy.Text("plan_digest"), replacement["supersedes"].Text("plan_digest"));
        Assert.Contains("requires a v1 manifest", (await Assert.ThrowsAsync<InvalidOperationException>(() => c.SupersedePlan(Ct))).Message);
    }
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Supersede_refuses_drift_or_unresolved_legacy_repair(bool repair)
    {
        using var f = new Fixture(); f.Add(9, 4624); await SaveHistory(f, false, 100); var c = f.Control(); string before = File.ReadAllText(c.HistoryPath); if (repair) f.PendingRepair = true; else f.Sources[0] = f.Sources[0] with { Hash = new string('b', 64) };
        await Assert.ThrowsAsync<InvalidOperationException>(() => c.SupersedePlan(Ct)); Assert.Equal(before, File.ReadAllText(c.HistoryPath));
    }
    [Fact]
    public async Task Resume_plan_uses_manifest_without_rescanning_frozen_sources()
    { using var f = new Fixture(); f.Add(1, 4727); var manifest = await SaveHistory(f); f.Calls.Clear(); int snapshots = f.SnapshotQueries; var plan = await f.Control().HistoryPlan(Ct); Assert.Equal("security_history_resume_ready", plan.Text("status")); Assert.Equal(manifest.Text("plan_digest"), plan.Text("plan_digest")); Assert.Equal(snapshots, f.SnapshotQueries); Assert.All(f.Calls, q => Assert.Contains("inet_server_addr", q.Sql)); }
    [Fact]
    public async Task Full_chunk_waits_for_managed_worker_and_uses_producer_batch_size()
    { using var f = new Fixture(); foreach (int id in Enumerable.Range(1, 100)) f.Add(id, 4727); var c = f.Control(); var plan = await c.HistoryPlan(Ct); await c.HistoryPoll(plan.Text("confirmation")!, Ct); var entry = Read(c.HistoryPath)!["events"]!["4727"]!; Assert.Equal(100, entry.Number("cursor")); Assert.Equal("queued", entry.Text("state")); Assert.Equal(5000, Assert.Single(f.Calls, q => q.Sql == SemanticRetainedSql.Targets).Values[7]); }
    [Fact]
    public async Task Already_current_empty_selection_recovers_cursor_to_frozen_high_watermark()
    { using var f = new Fixture(); f.Add(9, 4727); f.Current.Add(9); var c = f.Control(); var plan = await c.HistoryPlan(Ct); var result = await c.HistoryPoll(plan.Text("confirmation")!, Ct); Assert.False(result.Flag("production_changed")); Assert.Empty(f.Published); var e = Read(c.HistoryPath)!["events"]!["4727"]!; Assert.Equal(9, e.Number("cursor")); Assert.Equal("queued", e.Text("state")); }
    [Theory]
    [InlineData("queued")] [InlineData("processing")]
    public async Task Any_unfinished_cohort_blocks_every_other_cohort(string state)
    { using var f = new Fixture(); f.Add(1, 4727); f.Add(2, 4730); var m = await SaveHistory(f); m["events"]!["4727"]!["cursor"] = 1; m["events"]!["4727"]!["state"] = state; m["events"]!["4730"]!["state"] = "publishing"; var c = f.Control(); Write(c.HistoryPath, m); f.Calls.Clear(); var result = await c.HistoryPoll(SemanticRetainedControl.PollPrefix + m.Text("plan_digest"), Ct); Assert.Equal("security_history_poll_waiting_for_managed_worker", result.Text("status")); Assert.False(result.Flag("production_changed")); Assert.Empty(f.Published); Assert.DoesNotContain(f.Calls, q => q.Sql == SemanticRetainedSql.Targets); }
    [Fact]
    public async Task Terminal_hash_drift_is_persisted_as_incomplete_original()
    { using var f = new Fixture(); f.Add(1, 4727); await SaveHistory(f, false); f.Reconciliations[4727] = Counts(1, 1, "completed"); f.Sources[0] = f.Sources[0] with { Hash = new string('b', 64) }; var c = f.Control(); int scans = f.SnapshotQueries; await c.HistoryCheckPlan(Ct); Assert.Equal(scans, f.SnapshotQueries); var result = await Check(c); Assert.False(result.Flag("terminal_success")); var e = Read(c.HistoryPath)!["events"]!["4727"]!; Assert.Equal("incomplete_original", e.Text("state")); Assert.Equal("frozen_original_integrity_mismatch", e.Text("terminal_reason")); Assert.Equal(new long[] { 4727 }, result["drift_event_ids"]!.AsArray().Select(x => x!.GetValue<long>())); }
    [Theory]
    [InlineData("queued", "queued")] [InlineData("leased", "processing")]
    public async Task Current_normalization_does_not_complete_nonterminal_outbox(string outbox, string expected)
    { using var f = new Fixture(); f.Add(1, 4727); await SaveHistory(f, false); f.Reconciliations[4727] = Counts(1, 1, outbox, 1); var c = f.Control(); var result = await Check(c); Assert.False(result.Flag("terminal_success")); Assert.Equal(expected, Read(c.HistoryPath)!["events"]!["4727"].Text("state")); }
    [Fact]
    public async Task Reconciliation_keeps_residual_pollable_then_reaches_second_chunk()
    {
        using var f = new Fixture { PageSize = 100 }; foreach (int id in Enumerable.Range(1, 200)) f.Add(id, 4727); var c = f.Control(); var p = await c.HistoryPlan(Ct); await c.HistoryPoll(p.Text("confirmation")!, Ct); int scans = f.SnapshotQueries;
        f.Reconciliations[4727] = Counts(200, 100, "queued"); await Check(c); Assert.Equal("queued", Read(c.HistoryPath)!["events"]!["4727"].Text("state")); Assert.Equal(scans, f.SnapshotQueries);
        f.Reconciliations[4727] = Counts(200, 100, "completed"); await Check(c); Assert.Equal("publishing", Read(c.HistoryPath)!["events"]!["4727"].Text("state")); p = await c.HistoryPlan(Ct); await c.HistoryPoll(p.Text("confirmation")!, Ct);
        Assert.Equal(2, f.Published.Count); Assert.Equal(Enumerable.Range(1, 100).Select(x => (long)x), f.Published[0]); Assert.Equal(Enumerable.Range(101, 100).Select(x => (long)x), f.Published[1]);
        var sessions = f.Calls.Where(q => q.Sql == SemanticRetainedSql.Reconcile).GroupBy(q => q.Session).ToArray(); Assert.Equal(2, sessions.Length); Assert.All(sessions, s => { Assert.Equal(Vocabulary.Length - 1, s.Count()); Assert.All(s, q => Assert.False(q.Write)); });
    }
    [Fact]
    public async Task Stale_readback_confirmation_is_rejected_again_inside_controller_lock()
    { using var f = new Fixture(); f.Add(1, 4727); await SaveHistory(f, false); var c = f.Control(); var plan = await c.HistoryCheckPlan(Ct); f.OnLock = _ => { var m = Read(c.HistoryPath)!; m["events"]!["4727"]!["state"] = "publishing"; Write(c.HistoryPath, m); }; await Assert.ThrowsAsync<InvalidOperationException>(() => c.HistoryCheck(plan.Text("plan_digest")!, plan.Text("confirmation")!, Ct)); Assert.DoesNotContain(f.Calls, q => q.Sql == SemanticRetainedSql.Reconcile); }
}
