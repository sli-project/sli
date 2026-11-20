using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticDispatchRecoveryTests
{
    private static readonly Guid First = Guid.Parse("10eac730-5285-5740-b605-577d3ef9f4c2");
    private static readonly Guid Second = Guid.Parse("e24572a7-159d-517c-a284-a0eff96ac007");
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact] public void Invalid_confirmation_is_refused_before_environment_or_connection()
    {
        string path = Path.GetTempFileName();
        try {
            var material = new JsonObject { ["plan_version"] = "test" };
            string digest = SemanticJson.Hash(material);
            material["plan_digest"] = digest; material["confirmation"] = "wrong";
            File.WriteAllText(path, material.ToJsonString());
            Assert.Contains("confirmation", Assert.Throws<InvalidOperationException>(() =>
                SemanticDispatchRecovery.LoadApplyPlan(path, digest, "wrong")).Message);
        } finally { File.Delete(path); }
    }

    [Fact] public void Plan_requires_matching_digest_and_exact_confirmation()
    {
        string path = Path.GetTempFileName();
        try {
            var plan = new JsonObject { ["plan_version"] = "test" };
            string digest = SemanticJson.Hash(plan), confirmation = "REPAIR-SEMANTIC-DISPATCH-PARTITION:" + digest;
            plan["plan_digest"] = digest; plan["confirmation"] = confirmation;
            File.WriteAllText(path, plan.ToJsonString());
            Assert.Equal("test", SemanticDispatchRecovery.LoadApplyPlan(path, digest, confirmation).Text("plan_version"));
            Assert.Throws<InvalidOperationException>(() => SemanticDispatchRecovery.LoadApplyPlan(path, "wrong", confirmation));
            plan["plan_version"] = "tampered"; File.WriteAllText(path, plan.ToJsonString());
            Assert.Contains("digest", Assert.Throws<InvalidOperationException>(() => SemanticDispatchRecovery.LoadApplyPlan(path, digest, confirmation)).Message);
        } finally { File.Delete(path); }
    }

    [Fact] public async Task Requeue_only_updates_exact_remaining_uuids_and_preserves_errors_and_attempts()
    {
        var session = new Session(new JsonArray(new JsonObject { ["job_id"] = First.ToString() }, new JsonObject { ["job_id"] = Second.ToString() }));
        await SemanticDispatchRecovery.RequeueAsync(session, [First, Second], Ct);
        var (sql, args) = Assert.Single(session.Calls);
        Assert.Contains("where job_id=any($1::uuid[])", sql);
        foreach (string fragment in new[] { "dispatch_status='quarantined'", "dispatch_status='queued'", "lease_token is null", "lease_until is null", "heartbeat_at is null", "attempt_count=max_attempts", "attempt_count=5", "dispatch_status='leased'", "lease_until<=now()", "returning job_id" }) Assert.Contains(fragment, sql);
        Assert.DoesNotContain("max_attempts=6", sql);
        Assert.DoesNotContain("last_error_code=null", sql); Assert.DoesNotContain("last_error_detail=null", sql);
        Assert.Equal(new[] { First, Second }, Assert.IsType<Guid[]>(args[0]));
        Assert.Contains("\"semantic_correlation_dispatch_terminal\"", args);
    }

    [Fact] public async Task Wrong_requeue_readback_is_refused_without_commit()
    {
        var session = new Session(new JsonArray(new JsonObject { ["job_id"] = Guid.Empty.ToString() }));
        Assert.Contains("requeue set changed", (await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticDispatchRecovery.RequeueAsync(session, [First], Ct))).Message);
        Assert.Equal(0, session.Commits);
    }

    [Fact] public async Task Recovery_claim_is_exact_without_consuming_attempt_or_clearing_error()
    {
        var session = new Session(new JsonArray(new JsonObject { ["job_id"] = First.ToString(), ["lease_token"] = Guid.NewGuid().ToString(), ["attempt_count"] = 5, ["max_attempts"] = 5 }));
        var rows = await SemanticDispatchRecovery.ClaimAsync(session, [First], Ct);
        Assert.Single(rows);
        var (sql, args) = Assert.Single(session.Calls);
        Assert.Contains("job.job_id=any($1::uuid[])", sql);
        Assert.Contains("job.attempt_count=5 and job.max_attempts=5", sql);
        Assert.DoesNotContain("attempt_count=attempt_count+1", sql);
        Assert.DoesNotContain("last_error_code=null", sql); Assert.DoesNotContain("last_error_detail=null", sql);
        Assert.Equal(new[] { First }, Assert.IsType<Guid[]>(args[0]));
        Assert.Contains("\"semantic_correlation_dispatch_terminal\"", args);
        Assert.Contains("investigation.account.unlock.after-lock", args);
        Assert.Contains("5da40e8f5c05bcead8c3bb0175dfabf84fbcad74c5b669f5909dc50250e3a02e", args);
    }

    [Fact] public async Task Unknown_or_empty_claim_scope_never_reaches_database()
    {
        var session = new Session(new JsonArray());
        await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticDispatchRecovery.ClaimAsync(session, [], Ct));
        await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticDispatchRecovery.ClaimAsync(session, [Guid.Empty], Ct));
        Assert.Empty(session.Calls);
    }

    [Theory] [InlineData(true)] [InlineData(false)]
    public async Task Completion_clears_preserved_error_in_same_leased_token_update(bool found)
    {
        Guid lease = Guid.NewGuid();
        var session = new Session(found ? new JsonArray(new JsonObject { ["job_id"] = First.ToString() }) : new JsonArray());
        if (found) await SemanticDispatchRecovery.CompleteAsync(session, First, lease, Ct);
        else Assert.Contains("lease was lost", (await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticDispatchRecovery.CompleteAsync(session, First, lease, Ct))).Message);
        var (sql, args) = Assert.Single(session.Calls);
        foreach (string fragment in new[] { "dispatch_status='completed'", "last_error_code=null", "last_error_detail=null", "dispatch_status='leased'", "lease_token=$2" }) Assert.Contains(fragment, sql);
        Assert.Equal(new object?[] { First, lease }, args);
    }

    [Theory] [InlineData(true, false, "accepted_relations")] [InlineData(false, true, "repairable_relations")] [InlineData(false, false, "blocking_relations")]
    public async Task Snapshot_reads_normalized_source_ids_and_classifies_contract(bool exact, bool repairable, string bucket)
    {
        var session = new Session(new JsonArray(new JsonObject { ["job_id"] = First.ToString(), ["source_event_id"] = 6943209, ["semantic_contract_version"] = 1, ["normalizer_id"] = "windows.named-eventdata", ["normalizer_version"] = "1.4+identity-1.0" }),
            new JsonArray(new JsonObject { ["source_event_ids"] = new JsonArray(6923513, 6943209), ["candidate_key_hex"] = "14febe55ac4f2a650afa1c11a22449743f615a7716b1de2191750abb429d1640", ["contract_exact"] = exact, ["repairable_contract_exact"] = repairable }));
        var rows = await SemanticDispatchRecovery.SnapshotAsync(session, Ct);
        Assert.Single(rows[0]![bucket]!.AsArray());
        foreach (string other in new[] { "accepted_relations", "repairable_relations", "blocking_relations" }.Where(x => x != bucket)) Assert.Empty(rows[0]![other]!.AsArray());
        string sql = session.Calls[^1].Sql;
        Assert.Contains("array_agg(distinct normalized.source_event_id", sql);
        Assert.Contains("filter (where", sql); Assert.Contains("bool_or(normalized.source_event_id=$7)", sql);
        Assert.DoesNotContain("evidence.source_event_id", sql); Assert.Contains("repairable_contract_exact", sql);
    }

    [Fact] public void Audit_is_atomic_redacted_and_read_back()
    {
        string directory = Path.Combine(Path.GetTempPath(), "sli-recovery-" + Guid.NewGuid().ToString("N")), path = Path.Combine(directory, "audit.json");
        try {
            var result = SemanticDispatchRecovery.WriteAtomicAudit(path, new JsonObject { ["status"] = "complete", ["dsn"] = "postgres://synthetic-private@host/db", ["nested"] = new JsonArray(new JsonObject { ["Password"] = "synthetic-private" }) });
            Assert.Equal("complete", result.Text("status")); Assert.DoesNotContain("synthetic-private", File.ReadAllText(path));
            Assert.True(JsonNode.DeepEquals(result, JsonNode.Parse(File.ReadAllText(path))));
            Assert.Single(Directory.GetFiles(directory));
        } finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
    }

    [Theory] [InlineData(null, true)] [InlineData(1, true)] [InlineData(0, false)]
    public async Task Worker_guard_requires_explicit_safe_to_launch(int? code, bool expected) =>
        Assert.Equal(expected, await SemanticDispatchRecovery.WorkerIsLiveAsync(() => Task.FromResult(code)));

    [Fact] public async Task Unavailable_guard_fails_closed() =>
        Assert.True(await SemanticDispatchRecovery.WorkerIsLiveAsync(() => throw new IOException("synthetic-private")));

    [Theory] [InlineData(false, null)] [InlineData(false, "ambient-dsn")] [InlineData(true, null)] [InlineData(true, "ambient-dsn")]
    public async Task Dispatch_owns_ephemeral_login_and_isolates_runtime_even_on_failure(bool raises, string? ambient)
    {
        // The injected getter represents ambient configuration; the recovery path never mutates it.
        var environment = new Dictionary<string, string?> { ["ADLOG_SEMANTIC_WORKER_DSN"] = ambient, ["ADLOG_SEMANTIC_WORKER_DSN_FILE"] = "ambient-dsn-file", ["ADLOG_SEMANTIC_WORKER_PASSWORD"] = "synthetic-ambient", ["ADLOG_SEMANTIC_RUNTIME_MODE"] = "findings-v1", ["ADLOG_SEMANTIC_RISK_ENGINE_ENABLED"] = "1", ["ADLOG_SEMANTIC_FINDING_CREATION_ENABLED"] = "1" };
        var events = new List<string>();
        Task<(string, string)> Create() { events.Add("create"); return Task.FromResult(("adlog_semantic_l1_test", "ephemeral-dsn")); }
        Task Drop(string role) { events.Add("drop:" + role); return Task.CompletedTask; }
        Task<JsonObject> Run(string dsn, SemanticRecoveryScope scope) {
            Assert.Equal("ephemeral-dsn", dsn); Assert.Equal(new[] { First }, scope.JobIds);
            Assert.Equal(DateTimeOffset.Parse("2026-09-20T10:00:00+00:00"), scope.NormalizedBefore);
            Assert.Equal("investigation-v1", scope.Mode); Assert.False(scope.Settings.Risk); Assert.False(scope.Settings.Findings);
            Assert.Equal("ephemeral-dsn", scope.Configuration("ADLOG_SEMANTIC_WORKER_DSN"));
            Assert.Equal("0", scope.Configuration("ADLOG_SEMANTIC_RISK_ENGINE_ENABLED"));
            Assert.Null(scope.Configuration("ADLOG_SEMANTIC_WORKER_DSN_FILE")); Assert.Null(scope.Configuration("ADLOG_SEMANTIC_WORKER_PASSWORD"));
            if (raises) throw new InvalidOperationException("dispatch boom");
            return Task.FromResult(new JsonObject { ["completed"] = 1, ["failed"] = 0, ["relations"] = 0 });
        }
        Task<JsonObject> Dispatch() => SemanticDispatchRecovery.DispatchAsync([First], DateTimeOffset.Parse("2026-09-20T10:00:00+00:00"), Create, Drop, Run, key => environment.GetValueOrDefault(key));
        if (raises) Assert.Equal("dispatch boom", (await Assert.ThrowsAsync<InvalidOperationException>(Dispatch)).Message);
        else Assert.Equal(1, (await Dispatch()).Number("completed"));
        Assert.Equal(ambient, environment["ADLOG_SEMANTIC_WORKER_DSN"]);
        Assert.Equal("findings-v1", environment["ADLOG_SEMANTIC_RUNTIME_MODE"]);
        Assert.Equal("1", environment["ADLOG_SEMANTIC_RISK_ENGINE_ENABLED"]); Assert.Equal("1", environment["ADLOG_SEMANTIC_FINDING_CREATION_ENABLED"]);
        Assert.Equal(new[] { "create", "drop:adlog_semantic_l1_test" }, events);
    }

    [Fact] public async Task Command_does_not_print_exception_message()
    {
        var output = new StringWriter(); var error = new StringWriter();
        Assert.Equal(1, await SemanticDispatchRecovery.ReportAsync(() => throw new InvalidOperationException("should-not-leak-marker"), output, error));
        Assert.DoesNotContain("should-not-leak-marker", error.ToString()); Assert.Contains("InvalidOperationException", error.ToString()); Assert.Empty(output.ToString());
    }

    [Fact] public async Task Command_refuses_bad_confirmation_before_reading_any_configuration()
    {
        string path = Path.GetTempFileName();
        try {
            var plan = new JsonObject { ["plan_version"] = "test" }; string digest = SemanticJson.Hash(plan);
            plan["plan_digest"] = digest; plan["confirmation"] = "wrong"; File.WriteAllText(path, plan.ToJsonString());
            int reads = 0; var error = new StringWriter();
            Assert.Equal(1, await SemanticDispatchRecoveryCommand.ExecuteAsync(true, path, path + ".audit", digest, "wrong", _ => { reads++; throw new InvalidOperationException("configuration touched"); }, new StringWriter(), error, Ct));
            Assert.Equal(0, reads); Assert.False(File.Exists(path + ".audit")); Assert.Contains("failed_closed", error.ToString());
        } finally { File.Delete(path); }
    }

    [Fact] public async Task Postgres_recovery_preserves_attempts_and_errors_until_token_fenced_completion_and_drops_login()
    {
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(Ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(Ct);
        var (_, events) = await SemanticRuntimePostgresTests.SeedShortAsync(fixture, admin, 0, Ct);
        using var packStream = typeof(SemanticCorrelation).Assembly.GetManifestResourceStream("Sli.Server.Semantic.chain_pack.json")!;
        var pack = JsonNode.Parse(packStream)!;
        var definition = pack["rules"]!.AsArray().Single(x => x.Text("rule_id") == "investigation.account.unlock.after-lock" && x.Number("rule_version") == 2)!["definition"]!.DeepClone();
        await using (var rule = new NpgsqlCommand("insert into semantic_correlation_rules(rule_id,rule_version,rule_kind,lifecycle_status,definition_json,definition_sha256) values($1,2,'sequence','shadow',$2,$3)", admin)) {
            SemanticSession.Parameters(rule, ["investigation.account.unlock.after-lock", definition, Convert.FromHexString("5da40e8f5c05bcead8c3bb0175dfabf84fbcad74c5b669f5909dc50250e3a02e")]); await rule.ExecuteNonQueryAsync(Ct);
        }
        const string sid = "S-1-5-21-100000001-200000002-300000003-7291";
        var at = DateTimeOffset.Parse("2026-09-20T09:00:00Z");
        var lockEvent = new SemanticEvent(events[0].EventId, "authentication.account.locked", at, new JsonObject { ["affected_entity"] = "sid:" + sid }, new JsonObject { ["domain_id"] = 1 }, new(), new string('a', 64));
        var unlockEvent = new SemanticEvent(events[1].EventId, "authentication.account.unlocked", at.AddMinutes(1), lockEvent.Roles, lockEvent.Facts, new(), new string('b', 64));
        var newerUnlock = unlockEvent with { Source = events[2].EventId, At = at.AddMinutes(2), Sha = new string('c', 64) };
        foreach (var ev in new[] { lockEvent, unlockEvent, newerUnlock }) {
            await using var normalized = new NpgsqlCommand("""
                insert into normalized_events(normalized_event_id,source_event_id,semantic_contract_version,normalizer_id,normalizer_version,processing_status,normalized_at,source_event_sha256,semantic_sha256,semantic_type,occurred_at_utc,roles_json,facts_json,quality_json,source_ingested_at,source_identity_json)
                select $1,$2,1,'windows.named-eventdata','1.4+identity-1.0','normalized',$8,e.normalized_hash,$3,$4,$5,$6,$7,'{}',e.migrated_at,
                    jsonb_build_object('id',e.id,'server_id',e.server_id,'domain_id',e.domain_id,'log_source_id',e.log_source_id,
                        'event_id',e.event_id,'time_created_utc',e.time_created_utc,'normalized_hash',encode(e.normalized_hash,'hex'),'migrated_at',e.migrated_at,'channel','Security')
                from public.semantic_event_source355 e where e.id=$2
                """, admin);
            SemanticSession.Parameters(normalized, [ev.Id(), ev.Source, Convert.FromHexString(ev.Sha), ev.Type, ev.At, ev.Roles, ev.Facts, DateTimeOffset.Parse(ev.Source == newerUnlock.Source ? "2026-09-20T10:00:01Z" : "2026-09-20T10:00:00Z")]); await normalized.ExecuteNonQueryAsync(Ct);
        }
        await using (var job = new NpgsqlCommand("""
            insert into semantic_correlation_dispatch_jobs(job_id,normalized_event_id,rule_id,rule_version,idempotency_key,partition_key,occurred_at_utc,dispatch_status,attempt_count,max_attempts,last_error_code,last_error_detail)
            values($1,$2,'investigation.account.unlock.after-lock',2,sha256('recovery-test'::bytea),$3,$4,'quarantined',5,5,'UniqueViolation','synthetic "semantic_correlation_candidate__candidate_id_evidence_order_key"')
            """, admin)) {
            SemanticSession.Parameters(job, [First, unlockEvent.Id(), "domain:1|account_sid:" + sid, unlockEvent.At]); await job.ExecuteNonQueryAsync(Ct);
        }
        // Wrong UPDATE readback must roll back the matching subset as well.
        await using (var tx = await admin.BeginTransactionAsync(Ct)) {
            var session = new SemanticSession(admin, tx);
            await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticDispatchRecovery.RequeueAsync(session, [First, Second], Ct));
            await tx.RollbackAsync(Ct);
        }
        await using (var tx = await admin.BeginTransactionAsync(Ct)) {
            var session = new SemanticSession(admin, tx); await session.ExecuteAsync("set local role adlog_storage_worker", Ct);
            await SemanticDispatchRecovery.RequeueAsync(session, [First], Ct); await tx.CommitAsync(Ct);
        }
        var recovery = new SemanticDispatchRecoveryRuntime(fixture.Pg.ConnectionString);
        var login = await recovery.CreateLogin(Ct);
        try {
            await using var runtime = PasswordProducerRuntime.Create(key => key == "ADLOG_SEMANTIC_WORKER_DSN" ? login.Dsn : null, _ => throw new InvalidOperationException());
            await using var worker = await runtime.OpenAsync(Ct);
            Guid lease;
            await using (var tx = await worker.BeginTransactionAsync(Ct)) {
                var rows = await SemanticDispatchRecovery.ClaimAsync(new SemanticSession(worker, tx), [First], Ct);
                var row = Assert.Single(rows)!; lease = Guid.Parse(row.Text("lease_token")!);
                Assert.Equal(5, row.Number("attempt_count")); Assert.Equal(5, row.Number("max_attempts")); Assert.Equal("UniqueViolation", row.Text("last_error_code")); Assert.Contains("semantic_correlation_candidate__candidate_id_evidence_order_key", row.Text("last_error_detail")!);
                await tx.CommitAsync(Ct);
            }
            await using (var tx = await worker.BeginTransactionAsync(Ct)) {
                await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticDispatchRecovery.CompleteAsync(new SemanticSession(worker, tx), First, Guid.NewGuid(), Ct)); await tx.RollbackAsync(Ct);
            }
            // Requeue the expired recovery lease, then execute the actual investigation dispatcher.
            await PostCollectionPostgres.Sql(admin, "update semantic_correlation_dispatch_jobs set lease_until=now()-interval '1 second' where dispatch_status='leased'", Ct);
            await using (var tx = await admin.BeginTransactionAsync(Ct)) {
                await SemanticDispatchRecovery.RequeueAsync(new SemanticSession(admin, tx), [First], Ct); await tx.CommitAsync(Ct);
            }
            var result = await SemanticProduction.RecoverDispatchAsync(runtime, worker, new([First], DateTimeOffset.Parse("2026-09-20T10:00:00Z"), _ => null), Ct);
            await using (var diagnostic = new NpgsqlCommand("select coalesce(last_error_detail,'') from semantic_correlation_dispatch_jobs where job_id=$1", admin)) {
                diagnostic.Parameters.AddWithValue(First);
                string failure = result.Number("failed") == 0 ? "" : string.Join('\n', (await fixture.Pg.DiagnosticsAsync(Ct)).Split('\n').Where(line => line.Contains("ERROR:", StringComparison.Ordinal)));
                Assert.True(result.Number("completed") == 1, result.ToJsonString() + " " + await diagnostic.ExecuteScalarAsync(Ct) + " " + failure);
            }
            Assert.Equal(0, result.Number("failed")); Assert.Equal(1, result.Number("relations"));
            await using (var evidence = new NpgsqlCommand("select count(*) from semantic_correlation_candidate_evidence", admin)) Assert.Equal(2L, await evidence.ExecuteScalarAsync(Ct));
            await using (var tx = await admin.BeginTransactionAsync(Ct)) {
                var session = new SemanticSession(admin, tx);
                var row = (await session.QueryAsync("select dispatch_status,attempt_count,max_attempts,last_error_code,last_error_detail,lease_token from semantic_correlation_dispatch_jobs where job_id=$1", Ct, First)).Single()!;
                Assert.Equal("completed", row.Text("dispatch_status")); Assert.Equal(5, row.Number("attempt_count")); Assert.Equal(5, row.Number("max_attempts")); Assert.Null(row["last_error_code"]); Assert.Null(row["last_error_detail"]); Assert.Null(row["lease_token"]);
            }
        } finally { await recovery.DropLogin(login.Role); }
        await using var roles = new NpgsqlCommand("select count(*) from pg_roles where rolname=$1", admin); roles.Parameters.AddWithValue(login.Role); Assert.Equal(0L, await roles.ExecuteScalarAsync(Ct));
    }

    private sealed class Session(params JsonArray[] responses) : ISemanticSession
    {
        private readonly Queue<JsonArray> rows = new(responses);
        internal List<(string Sql, object?[] Args)> Calls { get; } = [];
        internal int Commits;
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values) { Calls.Add((string.Join(' ', sql.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)), values)); return Task.FromResult(rows.Dequeue()); }
        public Task CommitAsync(CancellationToken ct) { Commits++; return Task.CompletedTask; }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
