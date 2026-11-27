using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Vectors from tests/semantic/test_retained_facts_identity_guards.py.
// All I/O stays in a synthetic database session and a disposable local directory.
public sealed class RetainedFactsIdentityGuardTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "sli-retained-facts-" + Guid.NewGuid());
    private string CheckpointPath => Path.Combine(directory, "checkpoint.json");
    private string ManifestPath => Path.Combine(directory, "exact.json");
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    public void Dispose() { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); }

    private static JsonObject Identity() => new() { ["host"] = "192.0.2.1", ["database"] = "synthetic", ["role"] = "synthetic_owner",
        ["system_identifier"] = "12345", ["port"] = "5432", ["database_oid"] = "16384" };
    private static JsonObject Checkpoint(long committed = 10) => new() {
        ["checkpoint_type"] = "retained_v2_semantic_facts", ["source"] = "semantic_event_rows", ["database_identity"] = Identity(), ["status"] = "active",
        ["range_start_event_id"] = 1, ["frozen_high_watermark_event_id"] = 10, ["last_committed_event_id"] = committed,
        ["rules_fingerprint"] = "rules-v1", ["batch_limit"] = 5000, ["include_context"] = true
    };
    private RetainedFactsControl Control(Database db) => new(db, CheckpointPath, "rules-v1", () => { });
    private async Task Run(Database db, bool poll) { if (poll) await Control(db).PollAsync(Ct); else await Control(db).PlanAsync(Ct); }

    [Theory] [InlineData(null)] [InlineData("events_v2_core")]
    public async Task A_checkpoint_from_another_source_cannot_advance_or_publish(string? source)
    {
        var checkpoint = Checkpoint(); checkpoint["source"] = source;
        RetainedFactsControl.Save(CheckpointPath, checkpoint); byte[] original = File.ReadAllBytes(CheckpointPath);
        var db = new Database();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Control(db).PollAsync(Ct));
        Assert.Contains("source", error.Message);
        Assert.Empty(db.Calls); Assert.Equal(original, File.ReadAllBytes(CheckpointPath));
        Assert.Equal(0, db.Publications); Assert.Equal(0, db.Commits);
    }
    public static TheoryData<string, bool> Targets {
        get {
            var rows = new TheoryData<string, bool>();
            foreach (string name in new[] { "host", "database", "role", "port", "system_identifier", "database_oid" })
                foreach (bool poll in new[] { false, true }) rows.Add(name, poll);
            return rows;
        }
    }

    [Theory] [MemberData(nameof(Targets))]
    public async Task Cross_target_is_rejected_before_selection_or_publication(string field, bool poll)
    {
        var checkpoint = Checkpoint(); checkpoint["database_identity"]![field] = "other";
        RetainedFactsControl.Save(CheckpointPath, checkpoint); byte[] original = File.ReadAllBytes(CheckpointPath);
        var db = new Database();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Run(db, poll));
        Assert.Contains("database identity mismatch", error.Message);
        Assert.Equal(original, File.ReadAllBytes(CheckpointPath));
        Assert.DoesNotContain(db.Calls, call => call.Sql.Contains("where id >", StringComparison.Ordinal));
        Assert.Equal(0, db.Publications); Assert.Equal(0, db.Commits);
    }

    [Theory] [InlineData(0, false)] [InlineData(5, false)] [InlineData(10, false)]
    [InlineData(0, true)] [InlineData(5, true)] [InlineData(10, true)]
    public async Task Legacy_checkpoint_is_never_automatically_adopted(long committed, bool poll)
    {
        var checkpoint = Checkpoint(committed); checkpoint.Remove("database_identity");
        RetainedFactsControl.Save(CheckpointPath, checkpoint); byte[] original = File.ReadAllBytes(CheckpointPath);
        var db = new Database();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Run(db, poll));
        Assert.Contains("operator-reviewed restart", error.Message);
        Assert.Equal(original, File.ReadAllBytes(CheckpointPath)); Assert.Empty(db.Calls); Assert.Equal(0, db.Opens);
    }

    [Fact] public async Task New_checkpoint_target_is_rechecked_in_publication_transaction()
    {
        var snapshot = Identity(); snapshot["system_identifier"] = "other";
        var db = new Database { SnapshotIdentity = snapshot };
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Control(db).PollAsync(Ct));
        Assert.Contains("database identity mismatch", error.Message);
        var saved = RetainedFactsControl.Read(CheckpointPath)!;
        Assert.Equal(0, saved.Number("last_committed_event_id"));
        Assert.True(JsonNode.DeepEquals(snapshot, saved["database_identity"]));
        Assert.DoesNotContain(db.Calls, call => call.Sql.Contains("where id >", StringComparison.Ordinal));
        Assert.Equal(0, db.Publications); Assert.Equal(0, db.Commits);
    }

    [Fact] public async Task New_checkpoint_is_durable_before_publication_and_advances_after_commit()
    {
        var db = new Database { SelectedIds = [1] };
        db.BeforePublish = () => {
            var saved = RetainedFactsControl.Read(CheckpointPath)!;
            Assert.True(JsonNode.DeepEquals(Identity(), saved["database_identity"]));
            Assert.Equal(0, saved.Number("last_committed_event_id")); Assert.Equal(0, db.Commits);
        };
        var result = await Control(db).PollAsync(Ct);
        Assert.Equal(1, db.Publications); Assert.Equal(1, db.Commits);
        Assert.Equal(1, RetainedFactsControl.Read(CheckpointPath).Number("last_committed_event_id"));
        Assert.Equal("existing_managed_facts_worker", result.Text("consumer"));
        var selected = Assert.Single(db.Calls, call => call.Sql.Contains("where id >", StringComparison.Ordinal));
        Assert.Equal(0L, selected.Values[0]); Assert.Equal(10L, selected.Values[1]); Assert.Equal(5000, selected.Values[2]);
        int identity = db.Calls.FindLastIndex(call => call.Sql.Contains("pg_control_system()", StringComparison.Ordinal));
        int role = db.Calls.FindIndex(call => call.Sql == "set local role adlog_storage_worker");
        Assert.True(identity >= 0 && identity < role);
    }

    [Fact] public async Task Failed_publication_commit_does_not_advance_durable_checkpoint()
    {
        RetainedFactsControl.Save(CheckpointPath, Checkpoint(0)); var original = File.ReadAllBytes(CheckpointPath);
        var db = new Database { SelectedIds = [1], FailCommit = true };
        await Assert.ThrowsAsync<IOException>(() => Control(db).PollAsync(Ct));
        Assert.Equal(original, File.ReadAllBytes(CheckpointPath));
    }

    [Fact] public async Task Missing_strong_identity_fails_closed()
    {
        var db = new Database { MissingStrongIdentity = true };
        await using var session = await db.OpenAsync(false, Ct);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => RetainedFactsControl.DatabaseIdentityAsync(session, Ct));
        Assert.Contains("identity is unavailable", error.Message);
        Assert.Equal(0, db.Publications);
    }

    [Fact] public async Task Identity_privilege_failure_is_actionable_and_does_not_leak_detail()
    {
        var db = new Database { DenyIdentity = true };
        await using var session = await db.OpenAsync(false, Ct);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => RetainedFactsControl.DatabaseIdentityAsync(session, Ct));
        Assert.Contains("read-only EXECUTE on pg_control_system", error.Message);
        Assert.DoesNotContain("fixture detail", error.ToString()); Assert.Null(error.InnerException);
    }

    private static JsonObject Job(string status, bool? identity = true, bool normalized = true) => new() {
        ["source_event_id"] = 7, ["status"] = status, ["identity_matches"] = identity, ["normalized"] = normalized
    };
    [Theory] [InlineData("completed", "queued", false)] [InlineData("completed", "queued", true)]
    [InlineData("failed", "completed", false)] [InlineData("failed", "completed", true)]
    public async Task Current_version_wins_regardless_of_old_row_order(string old, string current, bool reverse)
    {
        var db = new Database();
        db.Queue.Add((Job(old), false)); db.Queue.Add((Job(current), true)); if (reverse) db.Queue.Reverse();
        var result = await Control(db).QueueStatusAsync([7], Ct);
        Assert.Equal(1, result.Number(current)); Assert.Equal(0, result.Number(old)); Assert.Equal(0, result.Number("incomplete"));
        Assert.Single(db.Calls); Assert.False(db.Calls[0].Write);
    }

    [Theory] [InlineData(false, true)] [InlineData(true, false)] [InlineData(null, true)]
    public async Task Completed_requires_current_source_and_normalization(bool? identity, bool normalized)
    {
        var db = new Database(); db.Queue.Add((Job("completed", identity, normalized), true));
        var result = await Control(db).QueueStatusAsync([7], Ct);
        Assert.Equal(0, result.Number("completed")); Assert.Equal(1, result.Number("incomplete"));
    }

    [Fact] public async Task Duplicate_current_jobs_fail_closed()
    {
        var db = new Database(); db.Queue.Add((Job("completed"), true)); db.Queue.Add((Job("completed"), true));
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Control(db).QueueStatusAsync([7], Ct));
        Assert.Contains("ambiguous", error.Message);
    }

    [Fact] public async Task Absent_jobs_remain_not_enqueued()
    {
        var result = await Control(new Database()).QueueStatusAsync([7], Ct);
        Assert.Equal(1, result.Number("not_enqueued")); Assert.Equal(0, result.Number("completed"));
    }

    [Theory] [InlineData("intent")] [InlineData("processed")] [InlineData("no_admitted_events")]
    public async Task Incomplete_readback_cannot_attest_terminal_success(string previousState)
    {
        var db = new Database(); db.Queue.Add((Job("completed", false), true));
        var control = Control(db); var plan = await control.CheckPlanAsync([7], ManifestPath, Ct);
        Assert.False(File.Exists(ManifestPath));
        RetainedFactsControl.Save(ManifestPath, new JsonObject {
            ["manifest_type"] = "exact_retained_semantic_facts_check_v1", ["event_ids"] = new JsonArray(7),
            ["rules_fingerprint"] = "rules-v1", ["database_identity"] = plan["database_identity"].Copy(),
            ["plan_digest"] = plan["plan_digest"].Copy(), ["include_context"] = true, ["runtime_mode"] = "facts-v1", ["state"] = previousState
        });
        var publishes = new List<bool>();
        var result = await control.CheckAsync([7], ManifestPath, plan.Text("plan_digest")!, plan.Text("confirmation")!, (ids, publish, _) => {
            Assert.Equal(new long[] { 7 }, ids); publishes.Add(publish);
            return Task.FromResult(new JsonObject { ["runtime"] = new JsonObject { ["processing"] = new JsonObject { ["failed"] = 0, ["completed"] = 0 } } });
        }, Ct);
        Assert.Equal("partial", result.Text("state")); Assert.Equal(new[] { previousState == "intent" }, publishes);
        Assert.Equal("partial", RetainedFactsControl.Read(ManifestPath).Text("state"));
        Assert.Equal(1, result["result"]!["queue"].Number("incomplete"));
    }

    private sealed record Call(string Sql, object?[] Values, bool Write);
    private sealed class Database : ISemanticDatabase
    {
        internal readonly List<Call> Calls = [];
        internal readonly List<(JsonObject Row, bool Current)> Queue = [];
        internal JsonObject? SnapshotIdentity;
        internal long[] SelectedIds = [];
        internal Action? BeforePublish;
        internal bool MissingStrongIdentity, DenyIdentity, FailCommit;
        internal int Publications, Commits, Opens;
        private int identities;
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct) { Opens++; return Task.FromResult<ISemanticSession>(new Session(this, write)); }
        private sealed class Session(Database db, bool write) : ISemanticSession
        {
            public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
            {
                db.Calls.Add(new(sql, values, write));
                JsonArray Rows(params JsonObject[] rows) => new(rows.Cast<JsonNode>().ToArray());
                if (sql.Contains("pg_try_advisory_xact_lock", StringComparison.Ordinal)) return Task.FromResult(Rows(new JsonObject { ["acquired"] = true }));
                if (sql.Contains("inet_server_addr()", StringComparison.Ordinal)) {
                    var identity = Identity();
                    return Task.FromResult(Rows(new JsonObject { ["host"] = identity["host"].Copy(), ["database"] = identity["database"].Copy(), ["role"] = identity["role"].Copy() }));
                }
                if (sql.Contains("pg_control_system()", StringComparison.Ordinal)) {
                    if (db.DenyIdentity) throw new PostgresException("fixture detail must not leak", "ERROR", "ERROR", "42501");
                    var identity = db.identities++ == 0 && db.SnapshotIdentity is not null ? db.SnapshotIdentity : Identity();
                    return Task.FromResult(db.MissingStrongIdentity ? Rows(new JsonObject()) : Rows(new JsonObject {
                        ["system_identifier"] = identity["system_identifier"].Copy(), ["port"] = identity["port"].Copy(), ["database_oid"] = identity["database_oid"].Copy()
                    }));
                }
                if (sql.Contains("as high_watermark", StringComparison.Ordinal)) return Task.FromResult(Rows(new JsonObject { ["high_watermark"] = 10 }));
                if (sql == "set local role adlog_storage_worker") return Task.FromResult(new JsonArray());
                if (sql.Contains("where id >", StringComparison.Ordinal)) return Task.FromResult(Rows(db.SelectedIds.Select(id => new JsonObject { ["id"] = id }).ToArray()));
                if (sql.StartsWith("select id from semantic_event_rows where id=any", StringComparison.Ordinal)) return Task.FromResult(Rows(((long[])values[0]!).Select(id => new JsonObject { ["id"] = id }).ToArray()));
                if (sql.Contains("as event_key", StringComparison.Ordinal)) return Task.FromResult(Rows(((long[])values[0]!).Select(id => new JsonObject {
                    ["id"] = id, ["event_key"] = "4625", ["stream"] = "Security", ["provider_name"] = "Microsoft-Windows-Security-Auditing"
                }).ToArray()));
                if (sql == SemanticProducer.EnqueueSourcesSql) {
                    return Task.FromResult(new JsonArray(((JsonArray)values[0]!)
                        .Where(row => db.SelectedIds.Contains(row.Number("id")))
                        .Select(row => row.Copy()).ToArray()));
                }
                if (sql.Contains("insert into semantic_processing_outbox", StringComparison.Ordinal)) {
                    db.BeforePublish?.Invoke(); db.Publications++;
                    return Task.FromResult(Rows(new JsonObject { ["job_id"] = "synthetic" }));
                }
                if (sql.Contains("from public.semantic_processing_outbox job", StringComparison.Ordinal)) {
                    // As in the Python QueueCursor: only filter historical versions when SQL requests it.
                    bool current = sql.Contains("job.processor_version=$6", StringComparison.Ordinal);
                    Assert.True(current); Assert.Equal(6, values.Length);
                    Assert.Equal(1, values[0]); Assert.Equal(SemanticEvent.Normalizer, values[1]); Assert.Equal(SemanticEvent.Version, values[2]);
                    Assert.Equal(new long[] { 7 }, Assert.IsType<long[]>(values[3])); Assert.Equal("semantic-shadow", values[4]); Assert.Equal(SemanticEvent.Version, values[5]);
                    Assert.Contains("job.source_identity_json->>'id'=core.id::text", sql);
                    Assert.Contains("job.source_identity_json->>'normalized_hash'=encode(core.normalized_hash,'hex')", sql);
                    Assert.Contains("normalized.source_event_sha256=core.normalized_hash", sql); Assert.Contains("normalized.processing_status='normalized'", sql);
                    Assert.Contains("job.job_kind='normalize_event'", sql); Assert.Contains("job.semantic_contract_version=$1", sql);
                    return Task.FromResult(Rows(db.Queue.Where(row => !current || row.Current).Select(row => row.Row.DeepClone().AsObject()).ToArray()));
                }
                throw new InvalidOperationException("unexpected synthetic SQL: " + sql);
            }
            public Task CommitAsync(CancellationToken ct) { if (db.FailCommit) throw new IOException("synthetic commit failure"); db.Commits++; return Task.CompletedTask; }
            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }
    }
}
