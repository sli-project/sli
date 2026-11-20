using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticQuarantineRepairTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static string Hex(char c) => new(c, 64);
    private static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static string? EnvironmentValue(string name) => name switch {
        "ADLOG_SEMANTIC_RUNTIME_MODE" => "investigation-v1",
        "ADLOG_SEMANTIC_PRODUCTION_ENABLED" or "ADLOG_SEMANTIC_NORMALIZATION_ENABLED" or
        "ADLOG_SEMANTIC_ASSEMBLY_ENABLED" or "ADLOG_SEMANTIC_CORRELATION_ENABLED" => "1", _ => null
    };
    private static SemanticQuarantineRepairController Controller(Database db, Func<string,string?>? get = null) =>
        new(db, () => db.Manifest.DeepClone().AsObject(), get ?? EnvironmentValue, () => Hex('f'));

    [Fact] public void Release_fingerprint_is_stable_hex_and_binds_the_deployed_binary()
    {
        string fingerprint = SemanticWorkerContract.ReleaseFingerprint();
        Assert.Equal(fingerprint, SemanticWorkerContract.ReleaseFingerprint());
        Assert.Matches("\\A[0-9a-f]{64}\\z", fingerprint);
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
        try {
            File.Copy(typeof(SemanticProductionOptions).Assembly.Location, path);
            Assert.Equal(fingerprint, SemanticWorkerContract.ReleaseFingerprint(path));
            using (var file = File.Open(path, FileMode.Append)) file.WriteByte(1);
            Assert.NotEqual(fingerprint, SemanticWorkerContract.ReleaseFingerprint(path));
        }
        finally { File.Delete(path); }
    }

    [Fact] public void Managed_heartbeat_advertises_the_release_and_exact_repair_scope()
    {
        var details = SemanticWorkerContract.Details("investigation-v1", false, Hex('a'));
        Assert.Equal(SemanticWorkerContract.ReleaseFingerprint(), details["processing_contract"].Text("release_fingerprint"));
        Assert.Equal("semantic_v2_quarantine_repair", details["repair_scope"].Text("job_kind"));
        Assert.Equal(Hex('a'), details["repair_scope"].Text("repair_plan_digest"));
        Assert.False(details.Flag("manual_runtime"));
        Assert.Null(SemanticWorkerContract.Details("facts-v1", false)["repair_scope"]);
    }

    [Fact] public void Digest_is_stable_and_binds_terminal_evidence_all_raw_cohorts_and_release()
    {
        var manifest = new JsonObject { ["plan_digest"] = Hex('a'), ["database_identity"] = new JsonObject { ["host"] = "192.0.2.1", ["database"] = "sli", ["role"] = "runtime" },
            ["events"] = new JsonObject { ["4624"] = new JsonObject { ["count"] = 260, ["high_watermark"] = 300, ["cohort_digest"] = Hex('0') } } };
        var rows = new JsonArray(new JsonObject { ["original_job_id"] = "12345678-1234-5678-1234-567812345678", ["source_event_id"] = 260,
            ["original_source_hash"] = Hex('b'), ["original_attempt_count"] = 5, ["original_max_attempts"] = 5,
            ["original_error_code"] = "UniqueViolation", ["original_error_detail_sha256"] = Hex('c') });
        var context = new JsonObject { ["count"] = 260, ["cohort_digest"] = Hex('d'), ["reset_high_watermark"] = 99 };
        string first = SemanticQuarantineRepairController.Digest(manifest, rows, context, Hex('f'));
        // Python reference with the same fixed release fingerprint and sanitized database identity.
        Assert.Equal("e547a2c48e6acfd3d125bc60c55b4b7016eaed0383dd150bc2fd1c8a15d6d421", first);
        Assert.Equal(first, SemanticQuarantineRepairController.Digest(manifest, rows, context, Hex('f')));
        rows[0]!["original_error_detail_sha256"] = Hex('e');
        Assert.NotEqual(first, SemanticQuarantineRepairController.Digest(manifest, rows, context, Hex('f')));
        rows[0]!["original_error_detail_sha256"] = Hex('c');
        manifest["events"]!["4624"]!["count"] = 261;
        Assert.NotEqual(first, SemanticQuarantineRepairController.Digest(manifest, rows, context, Hex('f')));
        manifest["events"]!["4624"]!["count"] = 260;
        Assert.NotEqual(first, SemanticQuarantineRepairController.Digest(manifest, rows, context, Hex('0')));
        manifest["database_identity"]!["database"] = "база😀";
        Assert.Equal("4628f022633ad1dffeac1453c82483f2b49dda4508530b187b6c1f88dd3d3bda",
            SemanticQuarantineRepairController.Digest(manifest, rows, context, Hex('f')));
    }

    [Fact] public async Task Plan_is_read_only_and_apply_replay_is_idempotent_with_identity_only_jobs()
    {
        var db = new Database(); var controller = Controller(db);
        var plan = await controller.PlanAsync(Ct);
        Assert.Equal(260, plan.Number("target_events")); Assert.False(plan.Flag("production_changed"));
        Assert.All(db.Opened, write => Assert.False(write)); Assert.Empty(db.Jobs);
        var first = await controller.ApplyAsync(plan.Text("repair_plan_digest")!, plan.Text("confirmation")!, Ct);
        Assert.Equal(260, first.Number("newly_queued")); Assert.True(first.Flag("production_changed"));
        var second = await controller.ApplyAsync(plan.Text("repair_plan_digest")!, plan.Text("confirmation")!, Ct);
        Assert.Equal(0, second.Number("newly_queued")); Assert.False(second.Flag("production_changed"));
        Assert.Equal(260, db.Jobs.Count); Assert.Equal(2, db.Commits);
        Assert.All(db.Jobs.Values, payload => {
            Assert.Equal(9, payload.AsObject().Count); Assert.Equal("UniqueViolation", payload.Text("original_error_code"));
            Assert.Equal(Hash("duplicate key violates unique constraint \"canonical_actions_pkey\""), payload.Text("original_error_detail_sha256"));
        });
        Assert.All(db.Originals, original => Assert.Equal("quarantined", original.Text("status")));
        Assert.Contains(db.Queries, q => q.Contains("session_user as role") && !q.Contains("current_user as role"));
        Assert.Contains(db.Queries, q => q.Contains("for share", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("set local role adlog_storage_worker", db.Queries);
        Assert.Equal(Enumerable.Range(1,260).Select(i => "semantic_source:" + i), db.SourceLocks.Take(260));
    }

    [Theory] [InlineData("duplicate", "missing, extra, or duplicate")] [InlineData("missing", "missing, extra, or duplicate")]
    [InlineData("normalized", "already normalized")] [InlineData("terminal", "terminal contract changed")]
    [InlineData("hash", "terminal contract changed")] [InlineData("raw", "frozen raw cohort changed")]
    [InlineData("context", "frozen v2 context cohort changed")] [InlineData("identity", "immutable contract changed")]
    [InlineData("migration", "migration143")] [InlineData("source", "immutable contract changed")]
    public async Task Selection_fails_closed_for_changed_or_nonexact_evidence(string mutation, string error)
    {
        var db = new Database();
        switch (mutation) {
            case "duplicate": db.Originals[1]!["source_event_id"] = 1; break;
            case "missing": db.Originals.RemoveAt(0); break;
            case "normalized": db.Normalized = true; break;
            case "terminal": db.Originals[0]!["status"] = "failed"; break;
            case "hash": db.Originals[0]!["original_source_hash"] = Hex('e'); break;
            case "raw": db.Manifest["events"]!["4625"]!["raw_cohort_digest"] = Hex('e'); break;
            case "context": db.Manifest["events"]!["4624"]!["semantic_context_digest"] = Hex('e'); break;
            case "identity": db.Identity["role"] = "other_login"; break;
            case "migration": db.Migration = false; break;
            case "source": db.Manifest["source"] = "events_v2_core"; break;
        }
        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => Controller(db).PlanAsync(Ct));
        Assert.Contains(error, failure.Message); Assert.Empty(db.Jobs); Assert.Equal(0, db.Commits);
    }

    [Fact] public async Task Bad_confirmation_precedes_locks_and_busy_lock_precedes_writes()
    {
        var db = new Database(); var controller = Controller(db); var plan = await controller.PlanAsync(Ct);
        Assert.Contains("confirmation", (await Assert.ThrowsAsync<InvalidOperationException>(() => controller.ApplyAsync(plan.Text("repair_plan_digest")!, "wrong", Ct))).Message);
        Assert.DoesNotContain(true, db.Opened); Assert.DoesNotContain(db.Queries, q => q.Contains("pg_try_advisory"));
        db.Busy = true;
        Assert.Contains("lock is busy", (await Assert.ThrowsAsync<InvalidOperationException>(() => controller.ApplyAsync(plan.Text("repair_plan_digest")!, plan.Text("confirmation")!, Ct))).Message);
        Assert.DoesNotContain("set local role adlog_storage_worker", db.Queries); Assert.Empty(db.Jobs); Assert.Equal(0, db.Commits);
    }

    [Theory] [InlineData("fingerprint")] [InlineData("manual")] [InlineData("scope")] [InlineData("contract")] [InlineData("stale")]
    public async Task Apply_requires_a_fresh_managed_compatible_worker_with_exact_scope(string mutation)
    {
        var db = new Database { WorkerMutation = mutation }; var controller = Controller(db); var plan = await controller.PlanAsync(Ct);
        await Assert.ThrowsAsync<InvalidOperationException>(() => controller.ApplyAsync(plan.Text("repair_plan_digest")!, plan.Text("confirmation")!, Ct));
        Assert.Empty(db.Jobs); Assert.Equal(0, db.Commits);
    }

    [Fact] public async Task Conflicting_or_duplicate_replay_fails_before_enqueue_and_transaction_never_commits()
    {
        foreach (bool duplicate in new[] { false, true }) {
            var db = new Database(); var controller = Controller(db); var plan = await controller.PlanAsync(Ct);
            await controller.ApplyAsync(plan.Text("repair_plan_digest")!, plan.Text("confirmation")!, Ct);
            int before = db.Inserts; db.Commits = 0;
            if (duplicate) db.Duplicate = true; else db.Jobs[1] = new JsonObject { ["unexpected"] = "conflict" };
            var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => controller.ApplyAsync(plan.Text("repair_plan_digest")!, plan.Text("confirmation")!, Ct));
            Assert.Contains(duplicate ? "duplicate" : "conflicts", failure.Message); Assert.Equal(before, db.Inserts); Assert.Equal(0, db.Commits);
        }
    }

    [Fact] public async Task Admission_and_source_lock_order_are_shared_and_fail_closed()
    {
        var db = new Database();
        await Assert.ThrowsAsync<InvalidOperationException>(() => Controller(db, _ => null).PlanAsync(Ct)); Assert.Empty(db.Opened);
        await using var session = await db.OpenAsync(true, Ct);
        await SemanticWorkerContract.LockSourcesAsync(session, [3,1,3,2], Ct);
        Assert.Equal(new[] { "semantic_source:1", "semantic_source:2", "semantic_source:3" }, db.SourceLocks);
        Assert.All(db.Queries, q => Assert.Contains("pg_advisory_xact_lock", q));
    }

    [Theory] [InlineData("security-history-v2-quarantine-repair-plan")] [InlineData("security-history-v2-quarantine-repair")]
    public async Task Cli_uses_only_the_explicit_existing_main_manifest_for_v2_without_global_state(string action)
    {
        string root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        string manifest = Path.Combine(root, "artifacts", "stage8", "evidence", "retained-security-history-vocabulary.json");
        Directory.CreateDirectory(Path.GetDirectoryName(manifest)!); File.WriteAllText(manifest, "{}");
        var seen = new List<string>(); var output = new StringWriter();
        try {
            int exit = await SemanticProductionControlCommand.RunCoreAsync([action, "--frozen-security-history-manifest", manifest], root,
                (selected, path, digest, confirmation, ct) => { Assert.Equal(action, selected); seen.Add(path); return Task.FromResult(new JsonObject { ["status"] = "ok" }); }, output, Ct);
            Assert.Equal(0, exit); Assert.Equal(new[] { Path.GetFullPath(manifest) }, seen); Assert.Contains("ok", output.ToString());
        }
        finally { Directory.Delete(root, true); }
    }

    [Theory] [InlineData("security-history-plan", "main", "requires_v2_quarantine_repair")]
    [InlineData("security-history-v2-quarantine-repair-plan", "foreign", "exact_main_file")]
    [InlineData("security-history-v2-quarantine-repair-plan", "relative", "must_be_absolute")]
    [InlineData("security-history-v2-quarantine-repair-plan", "missing", "existing_main_file")]
    public async Task Cli_rejects_invalid_frozen_manifest_before_any_controller_action(string action, string choice, string error)
    {
        string root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        string main = Path.Combine(root, "artifacts", "stage8", "evidence", "retained-security-history-vocabulary.json");
        Directory.CreateDirectory(Path.GetDirectoryName(main)!); File.WriteAllText(main, "{}");
        string foreign = Path.Combine(root, "foreign.json"); File.WriteAllText(foreign, "{}");
        string path = choice switch { "main" => main, "foreign" => foreign, "relative" => "relative.json", _ => Path.Combine(root,"missing.json") };
        var output = new StringWriter();
        try {
            int exit = await SemanticProductionControlCommand.RunCoreAsync([action, "--frozen-security-history-manifest", path], root,
                (_, _, _, _, _) => throw new Xunit.Sdk.XunitException("Controller must not run"), output, Ct);
            Assert.Equal(1, exit); Assert.Contains(error, output.ToString());
        }
        finally { Directory.Delete(root, true); }
    }

    // Only the PostgreSQL boundary is substituted; selection, digest, worker gate and enqueue controller run unchanged.
    private sealed class Database : ISemanticDatabase
    {
        internal JsonObject Manifest = null!;
        internal JsonObject Identity = new() { ["host"] = "192.0.2.1", ["database"] = "sli", ["role"] = "admin_login" };
        internal JsonArray Originals = new();
        internal Dictionary<long,JsonNode> Jobs = new();
        internal List<string> Queries = new(), SourceLocks = new();
        internal List<bool> Opened = new();
        internal bool Normalized, Busy, Duplicate, Migration = true;
        internal string? WorkerMutation;
        internal int Commits, Inserts;
        internal Database()
        {
            var events = new JsonObject();
            int[] vocabulary = [4740,4767,4723,4724,4720,4722,4725,4726,4738,4781,4728,4729,4732,4733,4756,4757,4727,4730,4737,4731,4734,4735,4754,4755,4758,4764,4624,4625,4771,4776,4719,1102];
            string cohort = Hash(string.Concat(Enumerable.Range(1,260).Select(i => $"{i}:{Hex('b')}\n")));
            foreach (int id in vocabulary) events[id.ToString()] = new JsonObject {
                ["predicate"] = new JsonObject { ["channel"] = "Security", ["provider"] = id == 1102 ? "Microsoft-Windows-Eventlog" : "Microsoft-Windows-Security-Auditing", ["event_id"] = id },
                ["count"] = id == 4624 ? 260 : 0, ["raw_retained_count"] = id == 4624 ? 260 : 0,
                ["high_watermark"] = id == 4624 ? 260 : 0, ["min_id"] = id == 4624 ? 1 : null, ["max_id"] = id == 4624 ? 260 : null,
                ["cohort_digest"] = id == 4624 ? cohort : Hash(""), ["raw_cohort_digest"] = id == 4624 ? cohort : Hash(""), ["cursor"] = 0,
                ["state"] = id == 4624 ? "quarantined" : "no_retained_events", ["terminal_reason"] = id == 4624 ? "quarantined_current_version_work" : "no_retained_events",
                ["semantic_scope"] = id == 4624 ? "password_reset_context_only" : "all_retained", ["semantic_expected_count"] = id == 4624 ? 260 : 0,
                ["semantic_context_digest"] = id == 4624 ? cohort : null, ["semantic_context_reset_high_watermark"] = id == 4624 ? 0 : null
            };
            Manifest = new JsonObject { ["manifest_type"] = "retained_security_events_vocabulary_v2", ["plan_digest"] = Hex('a'), ["database_identity"] = Identity.DeepClone(),
                ["runtime_mode"] = "investigation-v1", ["source"] = "semantic_event_rows", ["semantic_contract_version"] = 1,
                ["normalizer"] = new JsonObject { ["id"] = "windows.named-eventdata", ["version"] = "1.4+identity-1.0" },
                ["assembler"] = new JsonObject { ["id"] = "semantic-action-assembler", ["version"] = "1.1" },
                ["vocabulary"] = new JsonArray(vocabulary.Select(i => JsonValue.Create(i)).ToArray()), ["batch_limit"] = 5000,
                ["moves_collection_cursors"] = false, ["contacts_sources"] = false, ["semantic_context_strategy"] = "successful_password_reset_same_domain_sid_within_1h", ["events"] = events,
                ["selection_fingerprint"] = "842718a615f6ada7acf392be70b181853332414b90cee17749569ac5eede499a" };
            for (int i=1; i<=260; i++) Originals.Add(new JsonObject { ["original_job_id"] = $"00000000-0000-0000-0000-{i:000000000000}", ["source_event_id"] = i,
                ["original_source_hash"] = Hex('b'), ["status"] = "quarantined", ["attempt_count"] = 5, ["max_attempts"] = 5, ["last_error_code"] = "UniqueViolation",
                ["last_error_detail"] = "duplicate key violates unique constraint \"canonical_actions_pkey\"" });
        }
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct) { Opened.Add(write); return Task.FromResult<ISemanticSession>(new Session(this, write)); }
        private sealed class Session(Database db, bool write) : ISemanticSession
        {
            public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
            {
                db.Queries.Add(sql); JsonArray rows;
                if (sql.Contains("session_user as role")) rows = new(db.Identity.DeepClone());
                else if (sql.Contains("schema_migrations")) rows = db.Migration ? new(new JsonObject { ["name"] = "semantic_v2_quarantine_repair" }) : new();
                else if (sql.Contains("pg_try_advisory")) rows = new(new JsonObject { ["acquired"] = !db.Busy });
                else if (sql.Contains("pg_advisory_xact_lock")) { db.SourceLocks.Add((string)values[0]!); rows = new(); }
                else if (sql == "set local role adlog_storage_worker") { Assert.True(write); rows = new(); }
                else if (sql.Contains("as original_job_id")) rows = db.Originals.DeepClone().AsArray();
                else if (sql.Contains("from public.normalized_events")) {
                    Assert.DoesNotContain("processing_status", sql);
                    rows = db.Normalized ? new(new JsonObject { ["source_event_id"] = 1, ["normalized_count"] = 1 }) : new();
                }
                else if (sql.Contains("from runtime_worker_heartbeats")) {
                    Assert.Contains("for share", sql.ToLowerInvariant()); Assert.Contains("heartbeat_at >=", sql);
                    var details = SemanticWorkerContract.Details("investigation-v1", false, (string)values[0]!);
                    details["processing_contract"]!["release_fingerprint"] = db.WorkerMutation == "fingerprint" ? Hex('e') : Hex('f');
                    if (db.WorkerMutation == "manual") details["manual_runtime"] = true;
                    if (db.WorkerMutation == "scope") details["repair_scope"]!["repair_plan_digest"] = Hex('e');
                    if (db.WorkerMutation == "contract") details["processing_contract"]!["processor_version"] = "old";
                    rows = db.WorkerMutation == "stale" ? new() : new(new JsonObject { ["details_json"] = details });
                }
                else if (sql.Contains("select payload_json")) {
                    long id = (long)values[0]!; rows = new();
                    if (db.Jobs.TryGetValue(id, out var payload)) { rows.Add(new JsonObject { ["payload_json"] = payload.DeepClone() }); if (db.Duplicate) rows.Add(rows[0]!.DeepClone()); }
                }
                else if (sql.Contains("insert into semantic_processing_outbox")) {
                    Assert.True(write); Assert.Equal("semantic_v2_quarantine_repair", values[5]);
                    db.Inserts++; db.Jobs.TryAdd((long)values[4]!, ((JsonObject)values[3]!).DeepClone()); rows = new();
                }
                else if (sql.Contains("login_target_user_sid")) {
                    rows = new(); foreach (int id in Enumerable.Range(1,260)) rows.Add(new JsonObject { ["source_event_id"] = id, ["normalized_hash"] = Hex('b'),
                        ["login_target_user_sid"] = "S-1-5-21-100000001-200000002-300000003-1", ["reset_target_user_sid"] = "S-1-5-21-100000001-200000002-300000003-1", ["reset_keywords"] = "Audit Success" });
                }
                else if (sql.Contains("from semantic_event_rows core")) {
                    rows = new(); int eventId = (int)values[1]!;
                    long after = (long)values[2]!;
                    if (eventId == 4624) foreach (int id in Enumerable.Range(1,260).Where(i => i>after).Take(256)) rows.Add(new JsonObject { ["id"] = id, ["normalized_hash"] = Hex('b') });
                }
                else throw new InvalidOperationException("Unexpected SQL: " + sql);
                return Task.FromResult(rows);
            }
            public Task CommitAsync(CancellationToken ct) { Assert.True(write); db.Commits++; return Task.CompletedTask; }
            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }
    }

    // Vectors from tests/semantic/test_semantic_v2_quarantine_repair.py.
    private const string Kind = "semantic_v2_quarantine_repair";
    private const string OriginalId = "12345678-1234-5678-1234-567812345678";
    private const string ErrorDetail = "duplicate key value violates unique constraint \"canonical_actions_pkey\"";
    private static readonly string SourceHash = new('a', 64), PlanDigest = new('b', 64);
    private static JsonObject Payload() => new()
    {
        ["repair_plan_digest"] = PlanDigest, ["history_plan_digest"] = new string('c', 64),
        ["original_source_hash"] = SourceHash, ["original_job_id"] = OriginalId,
        ["original_attempt_count"] = 5, ["original_max_attempts"] = 5,
        ["original_error_code"] = "UniqueViolation", ["original_error_detail_sha256"] = SemanticProposal.HashText(ErrorDetail)
    };
    private static JsonObject Job() => new()
    {
        ["job_kind"] = Kind, ["source_event_id"] = 260, ["semantic_contract_version"] = 1,
        ["processor_id"] = "semantic-shadow", ["processor_version"] = SemanticEvent.Version,
        ["source_identity_json"] = new JsonObject
        {
            ["id"] = 260, ["server_id"] = 1, ["domain_id"] = 1, ["log_source_id"] = 1, ["event_id"] = 4624,
            ["time_created_utc"] = "2026-09-20T00:00:00+00:00", ["normalized_hash"] = SourceHash,
            ["migrated_at"] = "2026-09-20T00:00:00+00:00", ["channel"] = "Security"
        },
        ["payload_json"] = Payload()
    };
    private sealed class Session : ISemanticSession
    {
        internal JsonObject? Original = new()
        {
            ["source_event_id"] = 260, ["job_kind"] = "normalize_event", ["status"] = "quarantined",
            ["semantic_contract_version"] = 1, ["processor_id"] = "semantic-shadow", ["processor_version"] = SemanticEvent.Version,
            ["source_hash"] = SourceHash, ["attempt_count"] = 5, ["max_attempts"] = 5,
            ["last_error_code"] = "UniqueViolation", ["last_error_detail"] = ErrorDetail
        };
        internal bool Normalized;
        internal readonly List<(string Sql, object?[] Values)> Calls = [];
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            ct.ThrowIfCancellationRequested(); Calls.Add((sql, values));
            if (sql.Contains("from semantic_processing_outbox where job_id=$1", StringComparison.Ordinal))
                return Task.FromResult(Original is null ? new JsonArray() : new JsonArray(Original.DeepClone()));
            if (sql.StartsWith("select 1 from normalized_events", StringComparison.Ordinal))
                return Task.FromResult(Normalized ? new JsonArray(new JsonObject { ["exists"] = 1 }) : new JsonArray());
            throw new InvalidOperationException("Unexpected source access before repair validation: " + sql);
        }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("Validation must not commit");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    private static Task Validate(Session session, JsonObject job, string? digest = null) =>
        SemanticProduction.ValidateQuarantineRepair(session, job, digest ?? PlanDigest, TestContext.Current.CancellationToken);

    [Fact]
    public async Task Exact_terminal_original_is_checked_before_source_load_without_release_fingerprint()
    {
        var job = Job(); var session = new Session();
        Assert.Null(job["payload_json"]!["worker_release_fingerprint"]);
        await Validate(session, job);
        Assert.Equal(2, session.Calls.Count);
        Assert.Contains("last_error_detail", session.Calls[0].Sql);
        Assert.Equal(new object?[] { Guid.Parse(OriginalId) }, session.Calls[0].Values);
        Assert.Contains("semantic_contract_version=$2 and normalizer_id=$3 and normalizer_version=$4", session.Calls[1].Sql);
        Assert.Equal(new object?[] { 260L, 1L, "windows.named-eventdata", SemanticEvent.Version }, session.Calls[1].Values);
        // Release fingerprints are not part of immutable repair lineage; a later admitted worker can run it.
        job["payload_json"]!["worker_release_fingerprint"] = new string('f', 64);
        await Validate(new Session(), job);
    }

    [Fact]
    public async Task Incompatible_processor_version_cannot_repair_the_original()
    {
        var job = Job(); job["processor_version"] = "incompatible-processor-version";
        var session = new Session();
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => Validate(session, job));
        Assert.Equal("semantic_repair_original_terminal_conflict", error.Message);
        Assert.Single(session.Calls);
    }

    [Theory]
    [InlineData("job_kind", "\"semantic_repair\"")]
    [InlineData("status", "\"completed\"")]
    [InlineData("attempt_count", "4")]
    [InlineData("last_error_code", "\"IntegrityError\"")]
    [InlineData("source_hash", "\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"")]
    [InlineData("source_event_id", "261")]
    [InlineData("semantic_contract_version", "2")]
    [InlineData("processor_id", "\"other-processor\"")]
    [InlineData("processor_version", "\"incompatible-processor-version\"")]
    [InlineData("max_attempts", "6")]
    public async Task Original_contract_mismatches_fail_before_normalization_lookup(string field, string value)
    {
        var session = new Session(); session.Original![field] = JsonNode.Parse(value);
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => Validate(session, Job()));
        Assert.Equal("semantic_repair_original_terminal_conflict", error.Message);
        Assert.Single(session.Calls);
    }

    [Theory]
    [InlineData("repair_plan_digest", "\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\"", "semantic_repair_payload_invalid")]
    [InlineData("original_job_id", "\"ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB\"", "semantic_repair_original_job_id_invalid")]
    [InlineData("original_job_id", "\"12345678123456781234567812345678\"", "semantic_repair_original_job_id_invalid")]
    [InlineData("original_attempt_count", "0", "semantic_repair_terminal_evidence_invalid")]
    [InlineData("original_max_attempts", "4", "semantic_repair_terminal_evidence_invalid")]
    [InlineData("original_attempt_count", "\"5\"", "semantic_repair_attempts_invalid")]
    [InlineData("original_max_attempts", "\"5\"", "semantic_repair_attempts_invalid")]
    [InlineData("original_attempt_count", "true", "semantic_repair_attempts_invalid")]
    [InlineData("original_attempt_count", "5.0", "semantic_repair_attempts_invalid")]
    [InlineData("original_error_code", "\"uniqueviolation\"", "semantic_repair_terminal_evidence_invalid")]
    [InlineData("original_error_detail_sha256", "\"0000000000000000000000000000000000000000000000000000000000000000\"", "semantic_repair_original_terminal_conflict")]
    public async Task Invalid_payload_is_rejected(string field, string value, string code)
    {
        var job = Job(); job["payload_json"]![field] = JsonNode.Parse(value); var session = new Session();
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => Validate(session, job));
        Assert.Equal(code, error.Message);
        Assert.Equal(code == "semantic_repair_original_terminal_conflict" ? 1 : 0, session.Calls.Count);
    }

    [Fact]
    public async Task Current_normalization_prevents_repair()
    {
        var session = new Session { Normalized = true };
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => Validate(session, Job()));
        Assert.Equal("semantic_repair_source_already_normalized", error.Message);
        Assert.Equal(2, session.Calls.Count);
    }

    [Theory]
    [InlineData("canonical_actions_pkey", false)]
    [InlineData("ОШИБКА: повторяющееся значение ключа нарушает ограничение уникальности \"canonical_actions_pkey\"", true)]
    [InlineData("ОШИБКА: повторяющееся значение ключа нарушает ограничение уникальности \"other_pkey\"", false)]
    [InlineData("duplicate key value violates unique constraint 'canonical_actions_pkey'", true)]
    public async Task Constraint_name_requires_exact_quotes_and_accepts_localized_detail(string detail, bool accepted)
    {
        var job = Job(); var session = new Session(); session.Original!["last_error_detail"] = detail;
        job["payload_json"]!["original_error_detail_sha256"] = SemanticProposal.HashText(detail);
        if (accepted) { await Validate(session, job); Assert.Equal(2, session.Calls.Count); }
        else
        {
            var error = await Assert.ThrowsAsync<InvalidDataException>(() => Validate(session, job));
            Assert.Equal("semantic_repair_original_terminal_conflict", error.Message); Assert.Single(session.Calls);
        }
    }

    [Fact]
    public async Task Missing_original_is_rejected_without_loading_source()
    {
        var session = new Session { Original = null };
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => Validate(session, Job()));
        Assert.Equal("semantic_repair_original_terminal_conflict", error.Message); Assert.Single(session.Calls);
    }

    [Fact]
    public async Task Repair_stays_scoped_to_the_selected_plan_and_source_hash()
    {
        var session = new Session(); var job = Job();
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => Validate(session, job, new string('d', 64)));
        Assert.Equal("semantic_repair_terminal_evidence_invalid", error.Message); Assert.Empty(session.Calls);
        job["payload_json"]!["original_source_hash"] = new string('d', 64);
        error = await Assert.ThrowsAsync<InvalidDataException>(() => Validate(session, job));
        Assert.Equal("semantic_repair_terminal_evidence_invalid", error.Message); Assert.Empty(session.Calls);
    }

    [Fact]
    public void V2_repair_identity_is_distinct_and_deterministic()
    {
        JsonNode Row(string kind) => SemanticProducer.JobRows([new(260, "repair", kind)])[0]!;
        var v1 = Row("semantic_repair"); var v2 = Row(Kind); var again = Row(Kind);
        Assert.NotEqual(v1.Text("hash"), v2.Text("hash"));
        Assert.NotEqual(v1["job_id"]!.GetValue<Guid>(), v2["job_id"]!.GetValue<Guid>());
        Assert.Equal(v2.Text("hash"), again.Text("hash"));
        Assert.Equal(v2["job_id"]!.GetValue<Guid>(), again["job_id"]!.GetValue<Guid>());
    }
}
