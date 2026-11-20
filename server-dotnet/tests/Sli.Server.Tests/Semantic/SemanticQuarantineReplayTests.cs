using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticQuarantineReplayTests
{
    private const string Now = "2026-10-09T00:00:00+00:00";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static QuarantineSelection Selection => new(["KeyError", "UniqueViolation"]);
    private static JsonObject Job(string code = "KeyError", string? detail = null, int id = 7) => new() {
        ["job_id"] = $"00000000-0000-0000-0000-{id:000000000000}", ["source_event_id"] = id, ["job_kind"] = "normalize_event", ["status"] = "quarantined",
        ["semantic_contract_version"] = 1, ["processor_id"] = "semantic-shadow", ["processor_version"] = "previous", ["attempt_count"] = 5, ["max_attempts"] = 5,
        ["updated_at"] = Now, ["last_error_code"] = code, ["last_error_detail"] = detail ?? $"'published archive block not found for event {id}'", ["payload_json"] = new JsonObject(),
        ["source_identity_json"] = new JsonObject { ["id"] = id, ["server_id"] = 1, ["domain_id"] = 2, ["log_source_id"] = 3, ["event_id"] = 4625,
            ["time_created_utc"] = Now, ["normalized_hash"] = new string('a', 64), ["migrated_at"] = Now, ["channel"] = "Security", ["computer"] = "fixture-host" }
    };
    private static SemanticQuarantineReplay Replay(Database db, bool fail = false) => new(db, (session, row, dispatch, ct) => {
        db.Effects.Add(row.Number("source_event_id"));
        if (fail) throw new InvalidOperationException("fixture-sensitive-error-detail");
        return Task.FromResult(1);
    });
    private static async Task<string> Digest(SemanticQuarantineReplay replay, QuarantineSelection? selection = null) =>
        (await replay.RunAsync(selection ?? Selection, ct: Ct)).Text("plan_digest")!;
    private static Task<JsonObject> Apply(SemanticQuarantineReplay replay, string digest, QuarantineSelection? selection = null) => replay.RunAsync(selection ?? Selection, true, digest, Ct);

    [Fact] public async Task Deleted_source_closes_once_and_restart_uses_receipt_without_creating_facts()
    {
        var db = new Database(Job());
        var original = db.Rows[0]!.DeepClone();
        var production = new SemanticProduction(null!, new(true, true, false, true, false, false), SemanticRuntimeSettings.FactsMode, 1);
        var replay = new SemanticQuarantineReplay(db, production.ReplayQuarantined);
        var result = await replay.ReplayFixedAsync(10, true, Ct);
        Assert.Equal(1, result.Number("closed")); Assert.Equal(0, result.Number("failed")); Assert.Equal(0, result.Number("replayed"));
        Assert.Equal("closed", db.Rows[0].Text("status"));
        Assert.Equal("source_deleted", Assert.Single(db.Audit).Text("reason"));
        Assert.Equal("closed", db.Audit[0].Text("outcome")); Assert.Equal(0, db.Audit[0].Number("actions"));
        Assert.True(JsonNode.DeepEquals(original["source_identity_json"], db.Rows[0]!["source_identity_json"]));
        Assert.Equal(original.Text("last_error_code"), db.Rows[0].Text("last_error_code"));
        Assert.Empty(db.Effects);
        int reads = db.Sql.Count(q => q.Sql.Contains("from public.semantic_event_source355"));
        result = await new SemanticQuarantineReplay(db, production.ReplayQuarantined).ReplayFixedAsync(10, true, Ct);
        Assert.Equal(1, result.Number("already_resolved")); Assert.Equal(0, result.Number("closed"));
        Assert.Single(db.Audit); Assert.Equal(reads, db.Sql.Count(q => q.Sql.Contains("from public.semantic_event_source355")));
        Assert.DoesNotContain(db.Sql, q => q.Sql.Contains("insert into normalized_events") || q.Sql.Contains("insert into canonical_actions"));
    }

    [Fact]
    public async Task Existing_source_is_not_treated_as_deleted_source()
    {
        var db = new Database(Job()) { RawSourceExists = true };
        var production = new SemanticProduction(null!, new(true, true, false, true, false, false), SemanticRuntimeSettings.FactsMode, 1);
        var result = await new SemanticQuarantineReplay(db, production.ReplayQuarantined).ReplayFixedAsync(10, true, Ct);
        Assert.Equal(1, result.Number("failed")); Assert.Equal(0, result.Number("closed"));
        Assert.Equal("quarantined", db.Rows[0].Text("status"));
        Assert.Equal("source_integrity_failed", Assert.Single(db.Audit).Text("reason")); Assert.Empty(db.Effects);
    }

    [Theory] [InlineData("missing_file", false)] [InlineData("missing_file", true)]
    [InlineData("missing_directory", false)] [InlineData("missing_directory", true)]
    [InlineData("foreign_root", false)] [InlineData("foreign_root", true)]
    [InlineData("absent", true)]
    public async Task Unavailable_source_closes_once_even_with_retained_normalization(string failure, bool retained)
    {
        string root = Path.Combine(Path.GetTempPath(), "sli-quarantine-" + Guid.NewGuid().ToString("N"));
        try {
            if (failure == "missing_file") Directory.CreateDirectory(Path.Combine(root, "published"));
            var db = new Database(Job()) { ConflictingRetained = retained };
            if (failure != "absent") {
                db.ArchiveRoot = failure == "foreign_root" ? (OperatingSystem.IsWindows() ? "/var/lib/sli/archive" : @"D:\synthetic\archive") : root;
                db.ArchiveBlock = Block(Path.Combine(root, "published", "synthetic.gz"));
            }
            await using var runtime = new PasswordProducerRuntime(NpgsqlDataSource.Create("Host=192.0.2.1;Database=synthetic;Username=synthetic;Pooling=false"));
            var production = new SemanticProduction(runtime, new(true, true, false, true, false, false), SemanticRuntimeSettings.FactsMode, 1);
            var result = await new SemanticQuarantineReplay(db, production.ReplayQuarantined).ReplayFixedAsync(10, true, Ct);
            Assert.Equal(1, result.Number("closed")); Assert.Equal(0, result.Number("failed"));
            Assert.Equal(failure == "absent" ? "source_deleted" : "source_unavailable", Assert.Single(db.Audit).Text("reason"));
            Assert.Equal("closed", db.Rows[0].Text("status")); Assert.Equal(0, db.Audit[0].Number("actions"));
            Assert.DoesNotContain(db.Sql, q => q.Sql.Contains("from normalized_events") || q.Sql.Contains("insert into normalized_events") || q.Sql.Contains("insert into canonical_actions") || q.Sql.Contains("insert into semantic_dispatch"));
            int reads = db.Sql.Count(q => q.Sql.Contains("from public.semantic_event_source355"));
            result = await new SemanticQuarantineReplay(db, production.ReplayQuarantined).ReplayFixedAsync(10, true, Ct);
            Assert.Equal(1, result.Number("already_resolved")); Assert.Single(db.Audit);
            Assert.Equal(reads, db.Sql.Count(q => q.Sql.Contains("from public.semantic_event_source355")));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Readable_archive_hash_mismatch_and_invalid_authorization_remain_failures(bool invalidAuthorization)
    {
        string root = Path.Combine(Path.GetTempPath(), "sli-quarantine-" + Guid.NewGuid().ToString("N"));
        try {
            Directory.CreateDirectory(Path.Combine(root, "published"));
            string path = Path.Combine(root, "published", "synthetic.gz");
            await File.WriteAllBytesAsync(path, [1, 2, 3], Ct);
            var db = new Database(Job()) { ArchiveRoot = root, ArchiveBlock = Block(path), InvalidAuthorization = invalidAuthorization };
            await using var runtime = new PasswordProducerRuntime(NpgsqlDataSource.Create("Host=192.0.2.1;Database=synthetic;Username=synthetic;Pooling=false"));
            var production = new SemanticProduction(runtime, new(true, true, false, true, false, false), SemanticRuntimeSettings.FactsMode, 1);
            var result = await new SemanticQuarantineReplay(db, production.ReplayQuarantined).ReplayFixedAsync(10, true, Ct);
            Assert.Equal(1, result.Number("failed")); Assert.Equal(0, result.Number("closed"));
            Assert.Equal("quarantined", db.Rows[0].Text("status"));
            Assert.Equal(invalidAuthorization ? "replay_failed" : "source_integrity_failed", Assert.Single(db.Audit).Text("reason"));
            Assert.DoesNotContain(db.Sql, q => q.Sql.Contains("insert into normalized_events") || q.Sql.Contains("insert into canonical_actions"));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    private static JsonObject Block(string path) => new() {
        ["archive_set_id"] = "00000000-0000-0000-0000-000000000001", ["format_version"] = 1, ["block_index"] = 0,
        ["first_event_id"] = 1, ["last_event_id"] = 10, ["row_count"] = 1, ["raw_bytes"] = 3, ["compressed_bytes"] = 3,
        ["raw_sha256"] = new string('a', 64), ["archive_sha256"] = new string('b', 64), ["object_location"] = path, ["created_at"] = Now
    };

    [Fact] public async Task Automatic_replay_drains_2500_jobs_in_batches_without_changing_terminal_jobs()
    {
        var db = new Database(Enumerable.Range(1, 2500).Select(id => Job("semantic_processing_failed",
            SemanticProcessingFailure.Describe(new FileNotFoundException(), id % 2 == 0 ? SemanticProcessingStep.SourceRead : SemanticProcessingStep.RetainedNormalization), id)).ToArray());
        string original = db.Rows.ToJsonString(); var cursors = new List<long>();
        var result = await Replay(db).ReplayFixedAsync(1000, true, Ct, progress => cursors.Add(progress.Number("cursor")));
        Assert.Equal(2500, result.Number("replayed")); Assert.Equal(0, result.Number("failed"));
        Assert.Equal(2500, db.Effects.Distinct().Count()); Assert.Equal(2500, db.Audit.Count);
        Assert.All(db.Audit, receipt => { Assert.Equal("retry_normalization_source", receipt.Text("reason")); Assert.True(receipt.Flag("dispatch")); });
        Assert.Equal(Enumerable.Range(1, 2500).Select(id => (long)id), cursors); Assert.Equal(original, db.Rows.ToJsonString());
        Assert.All(db.Sql.Where(q => q.Sql.Contains("order by source_event_id")), q => Assert.Equal(1000, q.Values[^1]));
        result = await Replay(db).ReplayFixedAsync(1000, true, Ct);
        Assert.Equal(2500, result.Number("already_resolved")); Assert.Equal(0, result.Number("replayed")); Assert.Equal(2500, db.Effects.Count);
    }

    [Fact] public async Task Automatic_replay_rolls_back_interrupted_job_and_resumes_without_duplicate_effects()
    {
        var db = new Database(Enumerable.Range(1, 15).Select(id => Job(id: id)).ToArray());
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var replay = new SemanticQuarantineReplay(db, (_, row, _, ct) => {
            db.Effects.Add(row.Number("source_event_id"));
            if (row.Number("source_event_id") == 7) { stop.Cancel(); ct.ThrowIfCancellationRequested(); }
            return Task.FromResult(1);
        });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => replay.ReplayFixedAsync(5, false, stop.Token));
        Assert.Equal(Enumerable.Range(1, 6).Select(id => (long)id), db.Effects); Assert.Equal(6, db.Audit.Count);
        var result = await Replay(db).ReplayFixedAsync(5, false, Ct);
        Assert.Equal(9, result.Number("replayed")); Assert.Equal(6, result.Number("already_resolved"));
        Assert.Equal(15, db.Effects.Count); Assert.Equal(15, db.Effects.Distinct().Count()); Assert.Equal(15, db.Audit.Count);
    }

    [Fact] public async Task Automatic_replay_advances_past_blocked_and_failed_rows_and_tied_source_ids()
    {
        var first = Job(id: 1); var second = Job(id: 2); second["source_event_id"] = 1; second["source_identity_json"]!["id"] = 1;
        second["last_error_detail"] = "'published archive block not found for event 1'";
        var db = new Database(first, second, Job("KeyError", "unrelated lookup", 3), Job(id: 4), Job(id: 5), Job("QueryCanceled", "canceling statement due to statement timeout", 6));
        var replay = new SemanticQuarantineReplay(db, (_, row, _, _) => row.Number("source_event_id") == 4
            ? throw new SemanticSourceIntegrityException(new InvalidDataException("fixture-private")) : Task.FromResult(1));
        var result = await replay.ReplayFixedAsync(1, false, Ct);
        Assert.Equal(3, result.Number("replayed")); Assert.Equal(1, result.Number("blocked")); Assert.Equal(1, result.Number("failed"));
        Assert.Equal(1, db.Audit.Count(receipt => receipt.Text("reason") == "source_integrity_failed"));
        Assert.DoesNotContain(db.Audit, receipt => receipt.Number("source_event_id") is 3 or 6);
    }

    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Permanent_failure_is_final_but_legacy_failure_gets_one_corrected_attempt(bool canonical)
    {
        var db = new Database(Job());
        var legacy = Receipt(db.Rows[0]!.AsObject(), "failed", false);
        legacy["reason"] = "source_integrity_failed"; db.Audit.Add(legacy);
        int attempts = 0;
        var replay = new SemanticQuarantineReplay(db, (_, _, _, _) => {
            attempts++;
            if (canonical) throw new InvalidDataException("canonical_action_replay_conflict");
            throw new SemanticSourceIntegrityException(new InvalidDataException("archive_compressed_hash_mismatch"));
        });
        Assert.Equal(1, (await replay.ReplayFixedAsync(10, false, Ct)).Number("failed"));
        Assert.True(db.Audit[1].Flag("final"));
        Assert.Equal(1, (await replay.ReplayFixedAsync(10, true, Ct)).Number("already_resolved"));
        Assert.Equal(1, attempts); Assert.Equal(2, db.Audit.Count); Assert.Equal("quarantined", db.Rows[0].Text("status"));
    }

    [Fact] public async Task Dry_run_counts_without_writes_hydration_or_locks()
    {
        var db = new Database(Job(), Job("UniqueViolation", "duplicate key violates \"canonical_actions_pkey\"", 8), Job("KeyError", "unrelated lookup", 9));
        var replay = new SemanticQuarantineReplay(db, (_, _, _, _) => throw new Exception("dry-run hydrated source"));
        var result = await replay.RunAsync(Selection, ct: Ct);
        Assert.Equal(3, result.Number("selected")); Assert.Equal(2, result.Number("retryable")); Assert.Equal(1, result.Number("blocked"));
        Assert.Equal(1, result["decisions"].Number("fixed_source_lookup")); Assert.Equal(1, result["decisions"].Number("fixed_canonical_identity")); Assert.Equal(1, result["decisions"].Number("unsupported_failure"));
        Assert.Matches("^[0-9a-f]{64}$", result.Text("plan_digest")!); Assert.Empty(db.Audit); Assert.Empty(db.Effects);
        Assert.DoesNotContain("fixture-host", result.ToJsonString()); Assert.DoesNotContain(db.Sql, q => q.Sql.Contains("for update")); Assert.Equal(new[] { false }, db.Opens);
    }

    [Fact] public async Task Apply_records_success_atomically_and_repeated_apply_is_noop()
    {
        var db = new Database(Job()); string original = db.Rows.ToJsonString(); var replay = Replay(db); string digest = await Digest(replay);
        var result = await Apply(replay, digest);
        Assert.Equal(1, result.Number("replayed")); Assert.Equal(1, result.Number("actions")); Assert.Equal(new long[] { 7 }, db.Effects);
        var audit = Assert.Single(db.Audit)!; Assert.Equal("fixed_source_lookup", audit.Text("reason")); Assert.Equal("replayed", audit.Text("outcome"));
        Assert.Equal(original, db.Rows.ToJsonString()); Assert.DoesNotContain("fixture-host", audit.ToJsonString());
        Assert.Equal(1, (await Apply(replay, digest)).Number("already_resolved")); Assert.Single(db.Effects); Assert.Single(db.Audit);
    }

    [Theory] [InlineData("canceling statement due to statement timeout")] [InlineData("cancelling statement due to statement timeout\n")]
    public async Task Timeout_replay_is_explicit_audited_and_idempotent(string detail)
    {
        var db = new Database(Job("QueryCanceled", detail)); var replay = Replay(db); var selection = new QuarantineSelection(["QueryCanceled"]);
        var preview = await replay.RunAsync(selection, ct: Ct); Assert.Equal(1, preview["decisions"].Number("retry_statement_timeout")); Assert.Empty(db.Effects); Assert.Empty(db.Audit);
        Assert.Equal(1, (await Apply(replay, preview.Text("plan_digest")!, selection)).Number("replayed"));
        Assert.Equal("retry_statement_timeout", Assert.Single(db.Audit).Text("reason")); Assert.Equal("quarantined", db.Rows[0].Text("status"));
        Assert.Equal(1, (await Apply(replay, preview.Text("plan_digest")!, selection)).Number("already_resolved")); Assert.Single(db.Effects);
    }

    [Theory] [InlineData("QueryCanceled", "canceling statement due to user request")]
    [InlineData("QueryCanceled", "canceling statement due to statement timeout\nCONTEXT: unverified")]
    [InlineData("RuntimeError", "canceling statement due to statement timeout")]
    public async Task Other_cancellations_remain_blocked(string code, string detail)
    {
        var result = await Replay(new Database(Job(code, detail))).RunAsync(new([code]), ct: Ct);
        Assert.Equal(1, result.Number("blocked")); Assert.Equal(0, result.Number("retryable"));
    }

    [Theory] [InlineData("source_read")] [InlineData("retained_normalization")]
    public async Task Normalization_source_failure_uses_audited_replay_and_keeps_terminal_job(string step)
    {
        var row = Job("semantic_processing_failed", SemanticProcessingFailure.Describe(new FileNotFoundException(),
            step == "source_read" ? SemanticProcessingStep.SourceRead : SemanticProcessingStep.RetainedNormalization));
        var db = new Database(row); var replay = Replay(db); var selection = new QuarantineSelection(["semantic_processing_failed"]);
        string original = db.Rows.ToJsonString();
        var preview = await replay.RunAsync(selection, ct: Ct);
        Assert.Equal(1, preview.Number("retryable")); Assert.Empty(db.Effects);
        Assert.Equal(1, (await Apply(replay, preview.Text("plan_digest")!, selection)).Number("replayed"));
        Assert.Equal("retry_normalization_source", Assert.Single(db.Audit).Text("reason"));
        Assert.Equal(original, db.Rows.ToJsonString());
        Assert.Equal(1, (await Apply(replay, preview.Text("plan_digest")!, selection)).Number("already_resolved"));
        Assert.Single(db.Effects);
    }

    [Theory]
    [InlineData("not-json")]
    [InlineData("{\"code\":\"semantic_processing_failed\",\"step\":\"persist_normalized\",\"sql_state\":null}")]
    [InlineData("{\"code\":\"semantic_processing_failed\",\"step\":\"source_read\",\"sql_state\":\"42501\"}")]
    [InlineData("{\"code\":\"other\",\"step\":\"retained_normalization\",\"sql_state\":null}")]
    public void Unrelated_failures_are_not_admitted_as_normalization_retries(string detail) =>
        Assert.Null(SemanticQuarantineReplay.RetryReason(Job("semantic_processing_failed", detail)));

    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Processing_or_success_audit_failure_rolls_back_effects_then_allows_retry(bool auditFailure)
    {
        var db = new Database(Job()) { FailSuccessAudit = auditFailure }; var replay = Replay(db, fail: !auditFailure); string digest = await Digest(replay);
        var result = await Apply(replay, digest);
        Assert.Equal(1, result.Number("failed")); Assert.Empty(db.Effects); Assert.Equal("failed", Assert.Single(db.Audit).Text("outcome"));
        Assert.DoesNotContain("fixture-sensitive", db.Audit.ToJsonString() + result.ToJsonString());
        db.FailSuccessAudit = false; Assert.Equal(1, (await Apply(Replay(db), digest)).Number("replayed")); Assert.Equal(2, db.Audit.Count);
    }

    [Theory] [InlineData("source_unavailable")] [InlineData("canonical_conflict")] [InlineData("superseded")] [InlineData("unsupported_failure")]
    public async Task Close_requires_explicit_reason_and_keeps_quarantine(string reason)
    {
        var db = new Database(Job("KeyError", "unrelated lookup")); var replay = new SemanticQuarantineReplay(db, (_, _, _, _) => throw new Exception("closed source hydrated"));
        var selection = Selection with { CloseReason = reason };
        Assert.Equal(1, (await Apply(replay, await Digest(replay, selection), selection)).Number("closed"));
        Assert.Equal(reason, Assert.Single(db.Audit).Text("reason")); Assert.Equal("quarantined", db.Rows[0].Text("status"));
        Assert.Equal(1, (await Apply(replay, await Digest(replay, selection), selection)).Number("already_resolved"));
    }

    [Theory] [InlineData("last_error_detail")] [InlineData("processor_version")] [InlineData("updated_at")] [InlineData("payload_json")]
    public async Task Stale_plan_refuses_writes(string field)
    {
        var db = new Database(Job()); var replay = Replay(db); string digest = await Digest(replay);
        db.Rows[0]![field] = field == "payload_json" ? new JsonObject { ["changed"] = true } : JsonValue.Create("changed");
        var error = await Assert.ThrowsAsync<SemanticInputException>(() => Apply(replay, digest)); Assert.Equal("plan_changed", error.Message);
        Assert.Empty(db.Audit); Assert.Empty(db.Effects); Assert.DoesNotContain(true, db.Opens);
    }

    [Theory] [InlineData("range")] [InlineData("zero_source")] [InlineData("same_time")] [InlineData("zero_limit")]
    [InlineData("excess_limit")] [InlineData("close")] [InlineData("reason")] [InlineData("empty_reasons")]
    public async Task Invalid_selection_fails_before_connection(string kind)
    {
        var selection = kind switch {
            "range" => Selection with { SourceIdMin = 9, SourceIdMax = 7 }, "zero_source" => Selection with { SourceIdMin = 0 },
            "same_time" => Selection with { Since = DateTimeOffset.Parse(Now), Until = DateTimeOffset.Parse(Now) },
            "zero_limit" => Selection with { Limit = 0 }, "excess_limit" => Selection with { Limit = 1001 },
            "close" => Selection with { CloseReason = "arbitrary text" }, "empty_reasons" => Selection with { Reasons = [] },
            _ => Selection with { Reasons = ["KeyError' OR true --"] }
        };
        var db = new Database(Job()); await Assert.ThrowsAsync<SemanticInputException>(() => Replay(db).RunAsync(selection, ct: Ct)); Assert.Empty(db.Opens);
    }

    [Fact] public async Task Selection_binds_ranges_and_refuses_truncation()
    {
        var db = new Database(Job(), Job(id: 8)); var selection = Selection with { SourceIdMin = 7, SourceIdMax = 9, Since = DateTimeOffset.Parse(Now), Until = DateTimeOffset.Parse(Now).AddDays(1), Limit = 1 };
        Assert.Equal("selection_limit_exceeded", (await Assert.ThrowsAsync<SemanticInputException>(() => Replay(db).RunAsync(selection, ct: Ct))).Message);
        var query = Assert.Single(db.Sql); Assert.Contains("source_event_id >= $2", query.Sql); Assert.Contains("source_event_id <= $3", query.Sql);
        Assert.Contains("updated_at >= $4", query.Sql); Assert.Contains("updated_at < $5", query.Sql); Assert.Equal(2, query.Values[^1]);
        Assert.Equal(new object?[] { selection.Reasons, 7L, 9L, selection.Since.Value.UtcDateTime, selection.Until.Value.UtcDateTime, 2 }, query.Values);
    }

    [Theory] [InlineData("kind")] [InlineData("contract")] [InlineData("constraint")] [InlineData("identity")]
    [InlineData("hash")] [InlineData("processor")] [InlineData("missing_identity")]
    public async Task Unsupported_candidates_are_not_hydrated_or_audited(string mutation)
    {
        var row = Job();
        switch (mutation) {
            case "kind": row["job_kind"] = "semantic_replay"; break; case "contract": row["semantic_contract_version"] = 999; break;
            case "constraint": row["last_error_code"] = "UniqueViolation"; row["last_error_detail"] = "duplicate key \"other_pkey\""; break;
            case "identity": row["source_identity_json"]!["id"] = 8; break; case "hash": row["source_identity_json"]!["normalized_hash"] = "invalid"; break;
            case "processor": row["processor_id"] = "other"; break; case "missing_identity": row["source_identity_json"]!.AsObject().Remove("channel"); break;
        }
        var db = new Database(row); var replay = new SemanticQuarantineReplay(db, (_, _, _, _) => throw new Exception("blocked source hydrated"));
        Assert.Equal(1, (await Apply(replay, await Digest(replay))).Number("blocked")); Assert.Empty(db.Audit);
    }

    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Source_lock_rechecks_late_job_changes_and_concurrent_resolution(bool resolved)
    {
        var db = new Database(Job()); var replay = Replay(db); string digest = await Digest(replay);
        db.OnLock = () => { if (resolved) db.Audit.Add(Receipt(db.Rows[0]!.AsObject(), "replayed", false)); else db.Rows[0]!["status"] = "completed"; };
        Assert.Equal(1, (await Apply(replay, digest)).Number(resolved ? "already_resolved" : "changed"));
        Assert.Empty(db.Effects); Assert.Equal(resolved ? 1 : 0, db.Audit.Count);
        Assert.True(db.Sql.FindIndex(q => q.Sql.Contains("pg_advisory_xact_lock")) < db.Sql.FindIndex(q => q.Sql.Contains("for update")));
    }

    [Fact] public async Task Dispatch_scope_and_changed_quarantine_do_not_hide_new_work()
    {
        var db = new Database(Job()); var replay = Replay(db);
        foreach (bool dispatch in new[] { false, true, true }) {
            var selection = Selection with { Dispatch = dispatch }; await Apply(replay, await Digest(replay, selection), selection);
        }
        Assert.Equal(2, db.Audit.Count); Assert.True(db.Audit[^1].Flag("dispatch")); Assert.Equal(2, db.Effects.Count);
        db.Rows[0]!["updated_at"] = "2026-10-10T00:00:00Z";
        Assert.Equal(1, (await replay.RunAsync(Selection, ct: Ct)).Number("retryable"));
    }

    [Theory] [InlineData("processor")] [InlineData("assembler")] [InlineData("failed")] [InlineData("closed")]
    public async Task Resolution_receipts_respect_versions_outcome_and_fingerprint(string kind)
    {
        var db = new Database(Job()); var receipt = Receipt(db.Rows[0]!.AsObject(), kind == "closed" ? "closed" : kind == "failed" ? "failed" : "replayed", true);
        if (kind == "processor") receipt["processor_version"] = "old"; if (kind == "assembler") receipt["assembler_version"] = "old";
        db.Audit.Add(receipt); var result = await Replay(db).RunAsync(Selection, ct: Ct);
        Assert.Equal(kind == "closed" ? 1 : 0, result.Number("already_resolved"));
    }

    [Theory] [InlineData("missing", "source_unavailable")] [InlineData("canonical", "canonical_conflict")]
    [InlineData("private", "replay_failed")] [InlineData("integrity", "source_integrity_failed")]
    public async Task Failures_are_classified_without_exception_text_and_keep_quarantine(string kind, string reason)
    {
        Exception error = kind switch {
            "missing" => new KeyNotFoundException("fixture-private-detail"), "canonical" => new InvalidDataException("canonical_action_replay_conflict"),
            "integrity" => new SemanticSourceIntegrityException(new InvalidDataException("fixture-private-integrity-detail")), _ => new InvalidOperationException("fixture-private-detail")
        };
        Assert.Equal(reason, SemanticQuarantineReplay.FailureReason(error));
        var db = new Database(Job()); var replay = new SemanticQuarantineReplay(db, (_, _, _, _) => throw error);
        var result = await Apply(replay, await Digest(replay)); Assert.Equal(1, result["failures"].Number(reason));
        Assert.Equal("quarantined", db.Rows[0].Text("status")); Assert.DoesNotContain("fixture-private", result.ToJsonString() + db.Audit.ToJsonString());
    }

    [Fact] public async Task Missing_digest_is_rejected_before_connection_and_cli_never_discloses_connection_errors()
    {
        var db = new Database(Job()); await Assert.ThrowsAsync<SemanticInputException>(() => Apply(Replay(db), "")); Assert.Empty(db.Opens);
        int calls = 0; using var output = new StringWriter();
        Task<JsonObject> Run(QuarantineSelection _, bool __, string ___, CancellationToken ____) { calls++; throw new Exception("fixture-private-connection-detail"); }
        Assert.Equal(2, await SemanticQuarantineReplayCommand.RunAsync(["--apply", "--reason", "KeyError"], Run, output)); Assert.Equal(0, calls);
        Assert.Equal(1, await SemanticQuarantineReplayCommand.RunAsync(["--dry-run", "--reason", "KeyError"], Run, output)); Assert.Equal(1, calls);
        Assert.DoesNotContain("fixture-private", output.ToString()); Assert.Contains("semantic_quarantine_replay_failed", output.ToString());
    }

    [Fact] public void Timezone_and_explicit_credentials_are_required_and_no_execution_deadline_is_added()
    {
        Assert.Equal("timezone_required", Assert.Throws<SemanticInputException>(() => SemanticQuarantineReplayCommand.Time("2026-10-09T00:00:00")).Message);
        var values = new Dictionary<string, string> { ["ADLOG_SEMANTIC_REPLAY_DSN"] = "host=fixture-db dbname=fixture user=fixture_replay", ["ADLOG_SEMANTIC_REPLAY_PASSWORD"] = "fixture-password" };
        var config = SemanticQuarantineReplayCommand.Configuration(values.GetValueOrDefault, _ => throw new Exception("unexpected file read"));
        Assert.Equal("fixture_replay", config.Username); Assert.Equal("sli_semantic_quarantine_replay", config.ApplicationName);
        Assert.Equal(0, config.Timeout); Assert.Equal(0, config.CommandTimeout); Assert.Equal("-c statement_timeout=0 -c lock_timeout=0", config.Options); Assert.False(config.Pooling);
        Assert.ThrowsAny<Exception>(() => SemanticQuarantineReplayCommand.Configuration(_ => null, _ => []));
    }

    [Fact] public async Task Real_canonical_writer_preserves_stable_id_and_single_prior_interpretation_on_version_bump()
    {
        var action = new SemanticAction("audit.policy.changed", DateTimeOffset.Parse(Now), new string('b', 64), new JsonObject { ["material_identity"] = new JsonObject { ["source_host"] = "fixture-host" } }, []);
        var session = new WriterSession(action);
        await SemanticProduction.PersistAction(session, action, SemanticEvent.Version, Ct);
        await SemanticProduction.PersistAction(session, action, SemanticEvent.Version, Ct);
        Assert.Equal(action.Id.ToString(), session.Stored.Text("canonical_action_id")); Assert.Single(session.Stored["attributes_json"]!["prior_interpretations"]!.AsArray());
        Assert.Contains(session.Sql, sql => sql.Contains("pg_advisory_xact_lock")); Assert.DoesNotContain(session.Sql, sql => sql.Contains("insert into canonical_actions"));
    }

    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Replay_source_uses_real_normalizer_action_writer_and_explicit_dispatch(bool dispatch)
    {
        var job = Job(); job["source_identity_json"]!["event_id"] = 4719;
        var source = job["source_identity_json"]!.DeepClone().AsObject(); source["source_host_id"] = 1;
        source["provider_name"] = "Microsoft-Windows-Security-Auditing"; source["source_ingested_at"] = Now; source["source_event_sha256"] = new string('a', 64);
        source["event_data_json"] = new JsonObject { ["SubjectUserSid"] = "S-1-5-21-100000001-200000002-300000003-1001",
            ["SubcategoryGuid"] = "00000000-0000-0000-0000-000000000001", ["AuditPolicyChanges"] = "synthetic-change" };
        var expected = SemanticNormalization.Normalize(source); var action = Assert.Single(SemanticAssembly.Assemble([expected]));
        var session = new PipelineSession();
        var production = new SemanticProduction(null!, new(true, true, false, dispatch, false, false), SemanticRuntimeSettings.FactsMode, 1);
        Assert.Equal(1, await production.ReplaySource(session, job, source, dispatch, Ct));
        Assert.Equal(1, await production.ReplaySource(session, job, source, dispatch, Ct));
        Assert.Equal(expected.Id().ToString(), session.Normalized.Text("normalized_event_id"));
        Assert.Equal("audit.policy.changed", session.Normalized.Text("semantic_type"));
        Assert.Equal(action.Id.ToString(), session.Action.Text("canonical_action_id")); Assert.Equal(1, session.ActionInserts);
        Assert.Equal(dispatch ? 2 : 0, session.DispatchReads); Assert.Equal("quarantined", job.Text("status"));
    }

    [Fact] public async Task Cli_validates_scope_and_sanitizes_even_unrecognized_input_exceptions()
    {
        using var output = new StringWriter(); int calls = 0;
        Task<JsonObject> Run(QuarantineSelection scope, bool apply, string digest, CancellationToken ct) {
            calls++; Assert.Equal(new[] { "KeyError", "UniqueViolation" }, scope.Reasons); Assert.True(apply); Assert.True(scope.Dispatch);
            Assert.Equal(new string('a', 64), digest); throw new SemanticInputException("fixture-private-detail");
        }
        Assert.Equal(1, await SemanticQuarantineReplayCommand.RunAsync(["--reason", "KeyError", "--since", "2026-10-09T00:00:00"], Run, output)); Assert.Equal(0, calls);
        Assert.Equal(1, await SemanticQuarantineReplayCommand.RunAsync(["--apply", "--plan-digest", new string('a', 64), "--reason", "UniqueViolation", "--reason", "KeyError", "--dispatch"], Run, output));
        Assert.Equal(1, calls); Assert.DoesNotContain("fixture-private", output.ToString());
    }

    private static JsonObject Receipt(JsonObject row, string outcome, bool dispatch) => new() { ["job_id"] = row.Text("job_id"), ["outcome"] = outcome,
        ["original_fingerprint"] = SemanticQuarantineReplay.Fingerprint(row), ["processor_version"] = SemanticEvent.Version, ["assembler_version"] = "1.1", ["dispatch"] = dispatch };

    private sealed class Database(params JsonObject[] rows) : ISemanticDatabase
    {
        internal JsonArray Rows = new(rows); internal JsonArray Audit = []; internal List<long> Effects = [];
        internal List<(string Sql, object?[] Values)> Sql = []; internal List<bool> Opens = [];
        internal Action? OnLock; internal bool FailSuccessAudit, ConflictingRetained, RawSourceExists;
        internal string? ArchiveRoot; internal JsonObject? ArchiveBlock; internal bool InvalidAuthorization;
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct) { Opens.Add(write); return Task.FromResult<ISemanticSession>(new Session(this, write)); }
        private sealed class Session(Database db, bool write) : ISemanticSession
        {
            private readonly int initialAudit = db.Audit.Count, initialEffects = db.Effects.Count;
            private int savedAudit, savedEffects; private bool committed;
            private void Restore(int audit, int effects) {
                while (db.Audit.Count > audit) db.Audit.RemoveAt(db.Audit.Count - 1);
                db.Effects.RemoveRange(effects, db.Effects.Count - effects);
            }
            public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
            {
                ct.ThrowIfCancellationRequested(); db.Sql.Add((sql, values)); JsonArray result = [];
                if (sql.Contains("pg_advisory_xact_lock")) { Assert.True(write); db.OnLock?.Invoke(); }
                else if (sql == "savepoint quarantine_replay") { Assert.True(write); savedAudit = db.Audit.Count; savedEffects = db.Effects.Count; }
                else if (sql == "rollback to savepoint quarantine_replay") Restore(savedAudit, savedEffects);
                else if (sql == "release savepoint quarantine_replay") { }
                else if (sql.Contains("record_semantic_quarantine_resolution368")) {
                    Assert.True(write); var details = (JsonObject)values[1]!;
                    if (details.Text("outcome") == "replayed" && db.FailSuccessAudit) throw new Exception("fixture-sensitive-audit-error");
                    db.Audit.Add(details.DeepClone());
                }
                else if (sql.StartsWith("update semantic_processing_outbox set status='closed'")) {
                    var row = db.Rows.Single(r => r.Text("job_id") == values[0]!.ToString())!;
                    row["status"] = "closed"; row["completed_at"] = Now; row["updated_at"] = "2026-11-17T00:00:00+00:00";
                    result.Add(row.DeepClone());
                }
                else if (sql.Contains("semantic_source_exists374")) result.Add(new JsonObject { ["present"] = db.RawSourceExists });
                else if (sql.Contains("to_regclass('public.storage_v2_runtime_authorizations')")) result.Add(new JsonObject { ["available"] = true });
                else if (sql.Contains("from public.storage_v2_runtime_authorizations")) {
                    var authorization = SemanticArchiveFixture.Authorization(db.ArchiveRoot!);
                    if (db.InvalidAuthorization) authorization["authorization_digest"] = new string('0', 64);
                    result.Add(authorization);
                }
                else if (sql.Contains("from storage_v2_archive_blocks")) { if (db.ArchiveBlock is not null) result.Add(db.ArchiveBlock.DeepClone()); }
                else if (sql.StartsWith("select 1 from normalized_events") && db.ConflictingRetained) result.Add(new JsonObject { ["exists"] = 1 });
                else if (sql.Contains("from public.semantic_event_source355") || sql.Contains("from storage_v2_archive_blocks") || sql.Contains("from normalized_events where source_event_id")) { }
                else if (sql.Contains("from semantic_processing_outbox")) {
                    if (sql.Contains("for update")) { Assert.True(write); result = new JsonArray(db.Rows.Where(r => r.Text("job_id") == values[0]!.ToString()).Select(r => r.Copy()).ToArray()); }
                    else {
                        IEnumerable<JsonNode?> selected = db.Rows.Where(r => ((string[])values[0]!).Contains(r.Text("last_error_code")!));
                        var cursor = System.Text.RegularExpressions.Regex.Match(sql, @"\(source_event_id,job_id\) > \(\$(\d+),\$(\d+)\)");
                        if (cursor.Success) {
                            long source = (long)values[int.Parse(cursor.Groups[1].Value) - 1]!;
                            var job = (Guid)values[int.Parse(cursor.Groups[2].Value) - 1]!;
                            selected = selected.Where(r => r.Number("source_event_id") > source || r.Number("source_event_id") == source && Guid.Parse(r.Text("job_id")!).CompareTo(job) > 0);
                        }
                        result = new JsonArray(selected.OrderBy(r => r.Number("source_event_id")).ThenBy(r => Guid.Parse(r.Text("job_id")!))
                            .Take((int)values[^1]!).Select(r => r.Copy()).ToArray());
                    }
                }
                else if (sql.Contains("from semantic_control_audit")) {
                    Assert.Equal(SemanticQuarantineReplay.AuditAction, values[0]);
                    foreach (var receipt in db.Audit.Where(r => ((string[])values[1]!).Contains(r.Text("job_id")!) && (r.Text("outcome") == "closed" || (r.Text("outcome") == "replayed" || r.Text("outcome") == "failed" && r.Flag("final")) && r.Text("processor_version") == (string)values[2]! && r.Text("assembler_version") == (string)values[3]!)))
                        result.Add(new JsonObject { ["target"] = receipt.Text("job_id"), ["details"] = receipt.Copy() });
                }
                else throw new Exception("Unexpected SQL in quarantine replay test: " + sql);
                return Task.FromResult(result);
            }
            public Task CommitAsync(CancellationToken ct) { committed = true; return Task.CompletedTask; }
            public ValueTask DisposeAsync() { if (!committed) Restore(initialAudit, initialEffects); return ValueTask.CompletedTask; }
        }
    }

    private sealed class WriterSession(SemanticAction action) : ISemanticSession
    {
        internal readonly List<string> Sql = [];
        internal readonly JsonObject Stored = new() { ["canonical_action_id"] = action.Id.ToString(), ["action_kind"] = action.Kind, ["action_status"] = "observed", ["semantic_contract_version"] = 1,
            ["assembler_id"] = "semantic-action-assembler", ["assembler_version"] = "previous", ["dedup"] = action.Key, ["action_sha256"] = new string('a', 64), ["attributes_json"] = action.Attributes.DeepClone() };
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            Sql.Add(sql); Assert.DoesNotContain("insert into canonical_actions", sql);
            if (sql.Contains("set attributes_json=")) { Stored["attributes_json"] = ((JsonObject)values[0]!).DeepClone(); Stored["assembler_version"] = "1.1"; Stored["action_sha256"] = Convert.ToHexStringLower((byte[])values[1]!); }
            else if (sql.Contains("from canonical_actions where")) return Task.FromResult(new JsonArray(Stored.DeepClone()));
            else Assert.True(sql.Contains("pg_advisory_xact_lock") || sql.Contains("from canonical_action_evidence") || sql.Contains("update canonical_actions action"), sql);
            return Task.FromResult(new JsonArray());
        }
        public Task CommitAsync(CancellationToken ct) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    // In-memory SQL boundary only; normalization, assembly, identity and persistence checks execute production code.
    private sealed class PipelineSession : ISemanticSession
    {
        internal JsonObject? Normalized, Action; private Guid? evidence;
        internal int ActionInserts, DispatchReads;
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            JsonArray result = [];
            if (sql.Contains("insert into normalized_events")) {
                Normalized ??= new JsonObject { ["normalized_event_id"] = values[0]!.ToString(), ["source_event_id"] = (long)values[1]!, ["semantic_type"] = (string)values[5]!,
                    ["occurred_at_utc"] = SemanticJson.Stamp((DateTimeOffset)values[6]!), ["semantic_sha256"] = Convert.ToHexStringLower((byte[])values[4]!),
                    ["roles_json"] = ((JsonNode)values[8]!).DeepClone(), ["facts_json"] = ((JsonNode)values[9]!).DeepClone(), ["quality_json"] = ((JsonNode)values[10]!).DeepClone() };
            }
            else if (sql.Contains("from normalized_events where source_event_id")) result.Add(Normalized!.DeepClone());
            else if (sql.Contains("insert into canonical_actions")) {
                Assert.Null(Action); ActionInserts++;
                Action = new JsonObject { ["canonical_action_id"] = values[0]!.ToString(), ["action_kind"] = (string)values[1]!, ["semantic_contract_version"] = 1,
                    ["assembler_id"] = "semantic-action-assembler", ["assembler_version"] = "1.1", ["dedup"] = Convert.ToHexStringLower((byte[])values[3]!),
                    ["action_sha256"] = Convert.ToHexStringLower((byte[])values[4]!), ["attributes_json"] = ((JsonNode)values[5]!).DeepClone() };
            }
            else if (sql.Contains("from canonical_actions where")) { if (Action is not null) result.Add(Action.DeepClone()); }
            else if (sql.Contains("set attributes_json=")) Action!["attributes_json"] = ((JsonNode)values[0]!).DeepClone();
            else if (sql.Contains("select normalized_event_id from canonical_action_evidence")) { if (evidence is not null) result.Add(new JsonObject { ["normalized_event_id"] = evidence.ToString() }); }
            else if (sql.Contains("insert into canonical_action_evidence")) { Assert.Null(evidence); evidence = (Guid)values[1]!; }
            else if (sql.Contains("from semantic_correlation_subscriptions")) DispatchReads++;
            else if (sql.Contains("select to_regclass")) result.Add(new JsonObject { ["available"] = false });
            else Assert.True(sql.Contains("pg_advisory_xact_lock") || sql.Contains("update canonical_actions action"), sql);
            return Task.FromResult(result);
        }
        public Task CommitAsync(CancellationToken ct) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
