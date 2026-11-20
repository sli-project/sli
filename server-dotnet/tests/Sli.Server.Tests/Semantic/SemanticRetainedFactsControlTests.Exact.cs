using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;
using static Sli.Server.Semantic.SemanticRetainedManifest;

namespace Sli.Server.Tests.Semantic;

public sealed partial class SemanticRetainedFactsControlTests
{
    private const string PreviousRulesFingerprint = "e00a5ff93d87fa53770f64ae2e49b19c01160846b84e91806d300d2aaf42d495";

    [Fact]
    public void Exact_digest_binds_current_rules_and_selection_fingerprints_match_reference()
    {
        string fingerprint = SemanticRetainedControl.RulesFingerprint();
        Assert.Equal("4556f8b134a27bd5d1b6aa7d8fdc290a1e537b21d982502e67497c961065fc72", SelectionFingerprint(5000, false));
        Assert.Equal("842718a615f6ada7acf392be70b181853332414b90cee17749569ac5eede499a", SelectionFingerprint(5000, true));
        using var f = new Fixture();
        Assert.Equal("f71b901390a358364e80f0eafeb6157425162626e577477707d12a34bbdb1854", SemanticRetainedControl.ExactDigest([7, 8], fingerprint, f.IdentityValue));
    }

    [Fact]
    public void Installed_catalog_must_match_the_server_rules_before_planning()
    {
        string root = SemanticProduction.SourceBundleRoot(null, AppContext.BaseDirectory);
        string fingerprint = SemanticRetainedControl.RulesFingerprint();
        Assert.Equal(fingerprint, RetainedFactsCommand.RulesFingerprint(root));

        using var f = new Fixture();
        string config = Path.Combine(root, "config");
        string installed = Path.Combine(f.DirectoryPath, "config");
        Directory.CreateDirectory(Path.Combine(installed, "source_packs"));
        foreach (string catalog in Directory.GetFiles(config, "*event_catalog.json"))
            File.Copy(catalog, Path.Combine(installed, Path.GetFileName(catalog)));
        foreach (string manifest in Directory.GetFiles(Path.Combine(config, "source_packs"), "*.json"))
            File.Copy(manifest, Path.Combine(installed, "source_packs", Path.GetFileName(manifest)));

        Assert.Equal(fingerprint, RetainedFactsCommand.RulesFingerprint(f.DirectoryPath));
        string catalogPath = Path.Combine(installed, "event_catalog.json");
        var catalogDocument = JsonNode.Parse(File.ReadAllText(catalogPath))!.AsObject();
        catalogDocument["version"] = "synthetic-catalog-drift";
        File.WriteAllText(catalogPath, catalogDocument.ToJsonString());
        var error = Assert.Throws<InvalidOperationException>(() => RetainedFactsCommand.RulesFingerprint(f.DirectoryPath));
        Assert.Contains("installed rules do not match", error.Message);
    }

    [Fact]
    public async Task Previous_rules_confirmation_cannot_publish_or_write_intent()
    {
        using var f = new Fixture(); f.Add(7, 4728); f.Add(8, 4728);
        var paths = f.Control();
        string manifest = paths.ExactPath;
        var previous = new RetainedFactsControl(f, paths.FactsPath, PreviousRulesFingerprint);
        var oldPlan = await previous.CheckPlanAsync([7, 8], manifest, Ct);
        var control = new RetainedFactsControl(f, paths.FactsPath, SemanticRetainedControl.RulesFingerprint());
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            control.CheckAsync([7, 8], manifest, oldPlan.Text("plan_digest")!, oldPlan.Text("confirmation")!,
                (_, _, _) => throw new InvalidOperationException("must not execute an old plan"), Ct));

        Assert.Contains("plan digest mismatch", error.Message);
        Assert.False(File.Exists(manifest));
        Assert.Empty(f.Published);
        Assert.All(f.Calls, call => Assert.False(call.Write));
    }
    [Fact]
    public async Task Invalid_exact_ids_fail_before_database_or_environment()
    {
        using var f = new Fixture(); var c = new SemanticRetainedControl(f, f.DirectoryPath, _ => throw new InvalidOperationException("must not read environment"));
        foreach (long[] ids in new long[][] { [], [0], [-7], [7, 7], Enumerable.Range(1, 17).Select(x => (long)x).ToArray() }) await Assert.ThrowsAsync<InvalidOperationException>(() => c.ExactPlan(ids, Ct));
        Assert.Equal(0, f.Opens);
    }
    [Fact]
    public async Task Exact_plan_is_read_only_binds_sorted_ids_rules_and_caller_database()
    {
        using var f = new Fixture(); f.Add(7, 4727); f.Add(8, 4727); var c = f.Control(); var p = await c.ExactPlan([8, 7], Ct);
        Assert.Equal(new long[] { 7, 8 }, p["event_ids"]!.AsArray().Select(x => x!.GetValue<long>())); Assert.True(JsonNode.DeepEquals(f.IdentityValue, p["database_identity"])); Assert.Equal(SemanticRetainedControl.RulesFingerprint(), p.Text("rules_fingerprint")); Assert.Equal(SemanticRetainedControl.ExactPrefix + p.Text("plan_digest"), p.Text("confirmation")); Assert.False(File.Exists(c.ExactPath)); Assert.All(f.Calls, q => Assert.False(q.Write));
        f.IdentityValue["database"] = "other_synthetic"; Assert.NotEqual(p.Text("plan_digest"), (await c.ExactPlan([7, 8], Ct)).Text("plan_digest"));
        Assert.NotEqual(p.Text("plan_digest"), (await c.ExactPlan([7], Ct)).Text("plan_digest"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => c.ExactPlan([9], Ct));
        f.CallerRole = "candidate_owner"; Assert.Equal("candidate_owner", (await c.ExactPlan([7], Ct))["database_identity"].Text("role"));
    }
    [Fact]
    public async Task Wrong_exact_confirmation_fails_before_database_and_durable_intent()
    {
        using var f = new Fixture(); var c = f.Control(); await Assert.ThrowsAsync<InvalidOperationException>(() => c.ExactCheck([7], "digest", "wrong", Ct)); Assert.Equal(0, f.Opens); Assert.False(File.Exists(c.ExactPath));
    }
    [Fact]
    public async Task Exact_check_publishes_and_consumes_only_planned_ids_under_production_lock()
    {
        using var f = new Fixture(); f.Add(7, 4728); f.Add(8, 4728); f.Add(9, 4728); f.Queue = new JsonArray(QueueRow(7, "completed"), QueueRow(8, "completed")); var c = f.Control(); var p = await c.ExactPlan([7, 8], Ct); string? before = Environment.GetEnvironmentVariable("ADLOG_SEMANTIC_PRODUCTION_ENABLED");
        var result = await c.ExactCheck([7, 8], p.Text("plan_digest")!, p.Text("confirmation"), Ct, (ids, _) => {
            Assert.Equal(new long[] { 7, 8 }, ids); Assert.Equal("commit", f.Sequence[^1]); f.Sequence.Add("consume"); return Task.FromResult(new JsonObject { ["status"] = "ok", ["runtime_mode"] = "facts-v1", ["processing"] = new JsonObject { ["completed"] = 2, ["failed"] = 0 }, ["findings_created"] = 0 });
        });
        Assert.Equal(new long[] { 7, 8 }, Assert.Single(f.Published)); Assert.Equal(new[] { "lock-enter:" + SemanticRetainedControl.ProductionLock, "publish", "commit", "consume", "lock-exit" }, f.Sequence);
        Assert.Equal("processed", result.Text("state")); Assert.Equal(0, result["result"]!["runtime"].Number("findings_created")); Assert.Equal(before, Environment.GetEnvironmentVariable("ADLOG_SEMANTIC_PRODUCTION_ENABLED"));
        string filter = SemanticProduction.ClaimFilter(null, [7, 8], out var args); Assert.Contains("job_kind='normalize_event' and source_event_id=any($2)", filter); Assert.Equal(new long[] { 7, 8 }, Assert.IsType<long[]>(args[1]));
    }
    [Theory]
    [InlineData(null, "no_admitted_events")] [InlineData("quarantined", "partial")] [InlineData("failed", "partial")] [InlineData("queued", "partial")] [InlineData("leased", "partial")]
    public async Task Exact_check_reports_nonterminal_quarantine_and_no_admission_truthfully(string? queue, string expected)
    {
        using var f = new Fixture(); f.Add(7, 4727); if (queue is not null) f.Queue.Add(QueueRow(7, queue)); var c = f.Control(); var plan = await c.ExactPlan([7], Ct);
        var result = await c.ExactCheck([7], plan.Text("plan_digest")!, plan.Text("confirmation"), Ct, (_, _) => Task.FromResult(new JsonObject { ["status"] = "partial", ["processing"] = new JsonObject { ["completed"] = 0, ["failed"] = queue == "failed" ? 1 : 0 }, ["findings_created"] = 0 }));
        Assert.Equal(expected, result.Text("state")); Assert.Equal(expected, Read(c.ExactPath).Text("state")); Assert.Equal(new long[] { 7 }, Read(c.ExactPath)!["event_ids"]!.AsArray().Select(x => x!.GetValue<long>()));
    }
    [Fact]
    public async Task Exact_partial_retry_keeps_intent_does_not_republish_and_cannot_invoke_global_poll()
    {
        using var f = new Fixture(); f.Add(7, 4727); f.Queue.Add(QueueRow(7, "failed")); var c = f.Control(); var p = await c.ExactPlan([7], Ct);
        await c.ExactCheck([7], p.Text("plan_digest")!, p.Text("confirmation"), Ct, (_, _) => Task.FromResult(new JsonObject { ["processing"] = new JsonObject { ["failed"] = 1 } }));
        var intent = Read(c.ExactPath)!; Assert.Equal("partial", intent.Text("state")); f.Queue = new JsonArray(QueueRow(7, "completed"));
        var second = await c.ExactCheck([7], p.Text("plan_digest")!, p.Text("confirmation"), Ct, (ids, _) => { Assert.Equal(new long[] { 7 }, ids); return Task.FromResult(new JsonObject { ["processing"] = new JsonObject { ["completed"] = 1 } }); });
        Assert.Single(f.Published); Assert.Equal("processed", second.Text("state")); Assert.Equal(intent.Text("created_at_utc"), second.Text("created_at_utc"));
        var third = await c.ExactCheck([7], p.Text("plan_digest")!, p.Text("confirmation"), Ct, (_, _) => throw new InvalidOperationException("terminal check must not consume")); Assert.Equal("exact_retained_facts_check_already_processed", third.Text("status"));
        Assert.DoesNotContain(f.Calls, q => q.Values.Contains(SemanticRetainedControl.FactsLock) || q.Sql.Contains("select coalesce(max(id)"));
    }
    [Fact]
    public void Completed_exact_queue_requires_current_identity_and_normalization_and_unambiguous_coverage()
    {
        foreach (var row in new[] { QueueRow(7, "completed", false), QueueRow(7, "completed", true, false) }) { var result = SemanticRetainedControl.QueueStatus([7], new JsonArray(row)); Assert.Equal(1, result.Number("incomplete")); Assert.Equal(0, result.Number("completed")); }
        Assert.Throws<InvalidOperationException>(() => SemanticRetainedControl.QueueStatus([7], new JsonArray(QueueRow(7, "completed"), QueueRow(7, "completed"))));
        Assert.Throws<InvalidOperationException>(() => SemanticRetainedControl.QueueStatus([7], new JsonArray(QueueRow(8, "completed"))));
    }
    [Fact]
    public async Task Busy_production_lock_persists_intent_without_publication_or_consumption()
    {
        using var f = new Fixture(); f.Add(7, 4727); var c = f.Control(); var p = await c.ExactPlan([7], Ct); f.Busy = true;
        var result = await c.ExactCheck([7], p.Text("plan_digest")!, p.Text("confirmation"), Ct, (_, _) => throw new InvalidOperationException("must not consume")); Assert.Equal("exact_retained_facts_check_blocked", result.Text("status")); Assert.Equal("intent", Read(c.ExactPath).Text("state")); Assert.Empty(f.Published);
    }
    private static JsonObject RepairProof(string digest) => new() {
        ["source_event_id"] = 20, ["source_hash"] = new string('a', 64), ["original_job_count"] = 1, ["original_job_id"] = "00000000-0000-0000-0000-000000000001", ["original_status"] = "quarantined", ["original_attempt_count"] = 3, ["original_max_attempts"] = 3,
        ["original_error_code"] = "UniqueViolation", ["original_error_detail"] = "duplicate key violates \"canonical_actions_pkey\"", ["original_source_hash"] = new string('a', 64), ["repair_job_count"] = 1, ["repair_status"] = "completed", ["repair_semantic_contract_version"] = 1,
        ["repair_source_hash"] = new string('a', 64), ["repair_payload_source_hash"] = new string('a', 64), ["repair_original_job_id"] = "00000000-0000-0000-0000-000000000001", ["repair_history_plan_digest"] = digest, ["repair_plan_digest"] = new string('d', 64),
        ["repair_original_attempt_count"] = "3", ["repair_original_max_attempts"] = "3", ["repair_original_error_code"] = "UniqueViolation", ["repair_original_error_detail_sha256"] = Hash("duplicate key violates \"canonical_actions_pkey\""), ["repair_processor_id"] = "semantic-shadow", ["repair_processor_version"] = SemanticEvent.Version,
        ["normalized_current_count"] = 1, ["normalized_proof_count"] = 1, ["normalized_action_count"] = 1, ["normalized_proof_hash"] = new string('a', 64) };
    [Fact]
    public async Task V2_completed_proof_bound_repair_can_reconcile_immutable_original_quarantine()
    {
        using var f = new Fixture(); f.Add(20, 4624, true); f.Add(10, 4724); var m = await SaveHistory(f); var c = f.Control(); f.Repairs.Add(RepairProof(m.Text("plan_digest")!)); f.Reconciliations[4624] = Counts(1, 1, "quarantined", 1); f.Reconciliations[4724] = Counts(1, 1);
        var result = await Check(c); Assert.True(result.Flag("terminal_success")); var entry = Read(c.HistoryPath)!["events"]!["4624"]!; Assert.Equal("complete", entry.Text("state")); Assert.Equal(1, entry["v2_repair_states"].Number("completed")); Assert.Equal(0, entry["v2_repair_states"].Number("conflict"));
    }
    [Fact]
    public void V2_repair_requires_every_lineage_field_and_current_proof()
    {
        string digest = new string('b', 64), hash = new string('a', 64); var row = RepairProof(digest); Assert.Equal("completed", SemanticRetainedControl.RepairState(row, hash, digest));
        foreach (string field in row.Select(p => p.Key).Where(k => k is not ("source_event_id" or "source_hash"))) {
            var changed = row.DeepClone(); changed[field] = null;
            Assert.NotEqual("completed", SemanticRetainedControl.RepairState(changed, hash, digest));
        }
        foreach (string state in new[] { "queued", "leased", "failed", "quarantined" }) { var changed = row.DeepClone(); changed["repair_status"] = state; changed["normalized_current_count"] = 0; Assert.Equal(state, SemanticRetainedControl.RepairState(changed, hash, digest)); }
    }
    [Fact]
    public async Task Cli_requires_separate_confirmations_and_preserves_exact_ids_digest_and_action()
    {
        var calls = new List<(string Action, long[] Ids, string? Digest, string? Confirm)>();
        Task<JsonObject> Execute(string action, long[] ids, string? digest, string? confirm, CancellationToken _) { calls.Add((action, ids, digest, confirm)); return Task.FromResult(new JsonObject { ["status"] = "ok" }); }
        using var output = new StringWriter(); using var error = new StringWriter();
        Assert.Equal(1, await SemanticRetainedCommand.RunCore(["facts-poll"], Execute, output, error, Ct)); Assert.Empty(calls);
        foreach (string[] args in new string[][] {
            ["security-history-plan"], ["security-history-poll", "--confirm", "POLL-SECURITY-HISTORY:digest"], ["security-history-check-plan"],
            ["security-history-check", "--plan-digest", "digest", "--confirm", "CHECK-SECURITY-HISTORY:digest"],
            ["facts-check", "--event-id", "7", "--event-id", "8", "--plan-digest", "digest", "--confirm", "CHECK-STAGE8-EXACT-FACTS:digest"] }) Assert.Equal(0, await SemanticRetainedCommand.RunCore(args, Execute, output, error, Ct));
        Assert.Equal(new[] { "security-history-plan", "security-history-poll", "security-history-check-plan", "security-history-check", "facts-check" }, calls.Select(c => c.Action));
        Assert.Null(calls[0].Confirm); Assert.Equal("POLL-SECURITY-HISTORY:digest", calls[1].Confirm); Assert.Equal("digest", calls[3].Digest); Assert.Equal("CHECK-SECURITY-HISTORY:digest", calls[3].Confirm); Assert.Equal(new long[] { 7, 8 }, calls[4].Ids); Assert.Equal("CHECK-STAGE8-EXACT-FACTS:digest", calls[4].Confirm);
        Assert.Equal(1, await SemanticRetainedCommand.RunCore(["security-history-check", "--plan-digest", "digest", "--confirm", "POLL-SECURITY-HISTORY:digest"], Execute, output, error, Ct)); Assert.Equal(5, calls.Count);
    }
    [Fact]
    public async Task Cli_loads_the_explicit_existing_supervisor_profile_by_absolute_path()
    {
        using var f = new Fixture(); var loaded = new List<(string, bool)>(); var sequence = new List<string>(); using var output = new StringWriter(); using var error = new StringWriter();
        string path = Path.Combine(f.DirectoryPath, "worker-supervisor.env.dpapi");
        int result = await SemanticRetainedCommand.RunCore(["security-history-plan", "--environment-file", path], (_, _, _, _, _) => { sequence.Add("plan"); return Task.FromResult(new JsonObject { ["status"] = "ok" }); }, output, error, Ct,
            (name, replace) => { sequence.Add("load"); loaded.Add((name, replace)); });
        Assert.Equal(0, result); Assert.Equal((Path.GetFullPath(path), true), Assert.Single(loaded)); Assert.Equal(new[] { "load", "plan" }, sequence);
    }
    [Fact]
    public void Supervisor_profile_validates_owner_and_imports_only_allowlisted_values_without_exposing_them()
    {
        const string sid = "S-1-5-21-100000001-200000002-300000003-1001";
        var profile = new JsonObject { ["version"] = 2, ["owner_sid"] = sid, ["environment"] = new JsonObject { ["ADLOG_PG_DSN"] = "synthetic-dsn", ["ADLOG_SEMANTIC_RUNTIME_MODE"] = "investigation-v1", ["ADLOG_DB_BACKEND"] = "invalid", ["UNTRUSTED_PROFILE_COMMAND"] = "ignored" } };
        var env = new Dictionary<string, string?> { ["ADLOG_SEMANTIC_RUNTIME_MODE"] = "facts-v1", ["ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST"] = new string('a', 64) };
        string? Get(string key) => env.GetValueOrDefault(key); void Set(string key, string? value) => env[key] = value;
        Assert.Throws<InvalidOperationException>(() => SemanticRetainedEnvironment.Apply(profile, sid + "0", Get, Set, true)); Assert.False(env.ContainsKey("ADLOG_PG_DSN"));
        SemanticRetainedEnvironment.Apply(profile, sid, Get, Set, true); Assert.Equal("synthetic-dsn", env["ADLOG_PG_DSN"]); Assert.Equal("investigation-v1", env["ADLOG_SEMANTIC_RUNTIME_MODE"]); Assert.Equal("postgres", env["ADLOG_DB_BACKEND"]); Assert.Null(env["ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST"]); Assert.False(env.ContainsKey("UNTRUSTED_PROFILE_COMMAND"));
    }
    [Fact]
    public void Legacy_control_uses_protected_admin_identity_and_explicit_connection_wins_as_a_whole()
    {
        var env = new Dictionary<string, string?> { ["ADLOG_PG_DSN"] = "Host=192.0.2.1;Database=synthetic;Username=synthetic_service;Password=synthetic-service-secret", ["ADLOG_PG_ADMIN_USER"] = "synthetic_admin", ["ADLOG_PG_ADMIN_PASSWORD"] = "synthetic-admin-secret" };
        var settings = new Npgsql.NpgsqlConnectionStringBuilder(SemanticRetainedCommand.ConnectionString(env.GetValueOrDefault));
        Assert.Equal("synthetic_admin", settings.Username); Assert.Equal("synthetic-admin-secret", settings.Password); Assert.False(settings.Pooling); Assert.False(settings.Multiplexing); Assert.Equal(0, settings.CommandTimeout); Assert.False(settings.IncludeErrorDetail);
        env.Remove("ADLOG_PG_ADMIN_PASSWORD"); Assert.Throws<InvalidOperationException>(() => SemanticRetainedCommand.ConnectionString(env.GetValueOrDefault));
        var explicitSettings = new Npgsql.NpgsqlConnectionStringBuilder(SemanticRetainedCommand.ConnectionString(key => key == "ConnectionStrings__Sli" ? "Host=192.0.2.1;Database=synthetic;Username=synthetic_owner" : key == "Sli__PostgresConnectionString" ? null : throw new InvalidOperationException("must not read legacy credentials")));
        Assert.Equal("synthetic_owner", explicitSettings.Username);
    }
}
