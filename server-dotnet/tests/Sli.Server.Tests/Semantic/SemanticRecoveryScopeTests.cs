using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticRecoveryScopeTests
{
    private static readonly string Digest = new('a', 64);
    private static readonly SemanticRuntimeSettings Settings = new(true, true, false, true, false, false);
    private static PasswordProducerRuntime Runtime(SqlPostgresFixture fixture) => PasswordProducerRuntime.Create(
        n => n == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
        _ => throw new InvalidOperationException("test_must_not_read_secrets"));

    // Actual terminal evidence and the real worker role, source reader, normalizer,
    // persistence, leases and SQL claim. Ordinary jobs and another digest coexist.
    private static async Task Seed(SqlPostgresFixture fixture, NpgsqlConnection db, int count, CancellationToken ct)
    {
        for (int i = 0; i <= count; i++) await SemanticRuntimePostgresTests.SeedShortAsync(fixture, db, i, ct);
        await using (var runtime = Runtime(fixture))
        await using (var worker = await runtime.OpenAsync(ct))
            Assert.Equal(3L * (count + 1), (await SemanticProducerBackfill.RunAsync(worker, "facts-v1", 128, ct)).Number("queued"));
        await PostCollectionPostgres.Sql(db, """
            update semantic_processing_outbox set status='quarantined',attempt_count=max_attempts,
                last_error_code='UniqueViolation',last_error_detail='duplicate key violates constraint "canonical_actions_pkey"'
                where source_event_id in(select event_id from event_hot where event_kind=1102);
            insert into semantic_processing_outbox(job_id,source_event_id,job_kind,semantic_contract_version,processor_id,processor_version,
                idempotency_key,source_id,domain_id,partition_key,occurred_at_utc,source_identity_json,payload_json)
                select md5('repair:'||job_id)::uuid,source_event_id,'semantic_v2_quarantine_repair',semantic_contract_version,
                    processor_id,processor_version,sha256(('repair:'||job_id)::bytea),source_id,domain_id,partition_key,
                    occurred_at_utc,source_identity_json,jsonb_build_object('repair_plan_digest',repeat('a',64),
                        'history_plan_digest',repeat('c',64),'original_source_hash',source_identity_json->>'normalized_hash',
                        'original_job_id',job_id,'original_attempt_count',attempt_count,'original_max_attempts',max_attempts,
                        'original_error_code',last_error_code,'original_error_detail_sha256',encode(sha256(last_error_detail::bytea),'hex'))
                from semantic_processing_outbox where status='quarantined';
            update semantic_processing_outbox set payload_json=jsonb_set(payload_json,'{repair_plan_digest}',to_jsonb(repeat('b',64)))
                where job_kind='semantic_v2_quarantine_repair' and source_event_id=(select max(event_id) from event_hot where event_kind=1102);
            """, ct);
    }

    [Theory] [InlineData(1, 1)] [InlineData(128, 17)]
    public async Task Recovery_claims_only_exact_digest_normalizes_completes_and_never_dispatches(int requested, int count)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner = new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        await Seed(fixture, owner, count, ct);
        await using var runtime = Runtime(fixture); await using var db = await runtime.OpenAsync(ct);
        var production = new SemanticProduction(runtime, Settings with { Assembly = false }, "investigation-v1", requested, Digest);
        var result = await production.ProcessOutbox(db, ct);
        await using var failures = new NpgsqlCommand("select coalesce(jsonb_agg(last_error_detail),'[]'::jsonb)::text from semantic_processing_outbox where last_error_detail is not null and job_kind='semantic_v2_quarantine_repair'", owner);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse($$"""{"claimed":{{count}},"completed":{{count}},"failed":0,"normalized":{{count}},"actions":0}"""), result), result.ToJsonString() + " " + await failures.ExecuteScalarAsync(ct));
        await using var state = new NpgsqlCommand("""
            select (select count(*) from normalized_events), (select count(*) from semantic_correlation_dispatch_jobs),
                (select count(*) from semantic_processing_outbox where status='completed'),
                (select count(*) from semantic_processing_outbox where status='queued' and attempt_count=0)
            """, owner);
        await using var rows = await state.ExecuteReaderAsync(ct); Assert.True(await rows.ReadAsync(ct));
        Assert.Equal(count, rows.GetInt64(0)); Assert.Equal(0, rows.GetInt64(1));
        Assert.Equal(count, rows.GetInt64(2)); Assert.Equal(count * 2 + 3, rows.GetInt64(3));
    }

    [Theory] [InlineData("digest")] [InlineData("kind")]
    public async Task Claimed_job_scope_is_rechecked_before_source_access(string mutation)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner = new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        await Seed(fixture, owner, 1, ct);
        // Simulates a bad claim result at the database boundary, without replacing
        // the production claim or source reader. A source read must never occur.
        await PostCollectionPostgres.Sql(owner, """
            create function public.synthetic_bad_claim() returns trigger language plpgsql as $$ begin
                if new.job_kind='semantic_v2_quarantine_repair' and new.status='leased' then
            """ + "\n" + (mutation == "kind" ? "new.job_kind='investigation_context';" : "new.payload_json=jsonb_set(new.payload_json,'{repair_plan_digest}',to_jsonb(repeat('b',64)));") + "\n" + """
                end if; return new; end $$;
            create trigger synthetic_bad_claim before update on semantic_processing_outbox for each row execute function public.synthetic_bad_claim();
            """, ct);
        await using var runtime = Runtime(fixture); await using var db = await runtime.OpenAsync(ct);
        var steps = new List<SemanticProcessingStep>();
        var result = await new SemanticProduction(runtime, Settings, "investigation-v1", 1, Digest).ProcessOutbox(db, ct, (step, _) => steps.Add(step));
        Assert.Equal(1, result.Number("claimed")); Assert.Equal(1, result.Number("failed")); Assert.Equal(0, result.Number("normalized"));
        await using var error = new NpgsqlCommand("select last_error_detail from semantic_processing_outbox where attempt_count=1", owner);
        Assert.Equal("repair_scope", JsonNode.Parse((string)(await error.ExecuteScalarAsync(ct))!).Text("step"));
        Assert.DoesNotContain(SemanticProcessingStep.SourceRead, steps);
    }

    [Theory] [InlineData(1, 1)] [InlineData(128, 17)]
    public async Task Recovery_cycle_reports_scope_and_skips_every_downstream_stage(int requested, int expected)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner = new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        await Seed(fixture, owner, 17, ct);
        var info = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet") {
            UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = PostCollectionPostgres.Repository()
        };
        foreach (string name in info.Environment.Keys.Where(k => k.StartsWith("ADLOG_", StringComparison.OrdinalIgnoreCase)
            || k.StartsWith("SLI", StringComparison.OrdinalIgnoreCase) || k.StartsWith("PG", StringComparison.OrdinalIgnoreCase)
            || k.StartsWith("ConnectionStrings", StringComparison.OrdinalIgnoreCase)).ToArray()) info.Environment.Remove(name);
        foreach (string arg in new[] { typeof(Program).Assembly.Location, "semantic-production-worker", "--once", "--limit", requested.ToString(System.Globalization.CultureInfo.InvariantCulture) }) info.ArgumentList.Add(arg);
        info.Environment["ADLOG_SEMANTIC_WORKER_DSN"] = fixture.Dsn("sli_semantic_login");
        info.Environment["ADLOG_DATA_DIR"] = fixture.Pg.Root;
        info.Environment["ADLOG_SEMANTIC_RUNTIME_MODE"] = "investigation-v1";
        info.Environment["ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST"] = Digest;
        foreach (string stage in new[] { "PRODUCTION", "NORMALIZATION", "ASSEMBLY", "CORRELATION" }) info.Environment["ADLOG_SEMANTIC_" + stage + "_ENABLED"] = "1";
        info.Environment["SLI_PLUGIN_LOCK_DIR"] = Path.Combine(PostCollectionPostgres.Repository(), "config/plugin_packages/v3");
        using var process = Process.Start(info)!;
        JsonObject result;
        try {
            var stdout = process.StandardOutput.ReadToEndAsync(ct); var stderr = process.StandardError.ReadToEndAsync(ct);
            await process.WaitForExitAsync(ct);
            Assert.Equal("", await stderr);
            result = JsonNode.Parse((await stdout).Trim())!.AsObject();
            await using var failures = new NpgsqlCommand("select coalesce(jsonb_agg(last_error_detail),'[]'::jsonb)::text from semantic_processing_outbox where last_error_detail is not null and job_kind='semantic_v2_quarantine_repair'", owner);
            Assert.True(process.ExitCode == 0, result.ToJsonString() + " " + await failures.ExecuteScalarAsync(ct));
        }
        finally { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); } }
        Assert.Equal("ok", result.Text("status")); Assert.Equal(expected, result.Number("completed"));
        Assert.Equal(expected, result["processing"].Number("normalized")); Assert.Equal(0, result.Number("failed"));
        Assert.Equal(Digest, result["repair_scope"].Text("repair_plan_digest"));
        Assert.Equal("semantic_v2_quarantine_repair", result["repair_scope"].Text("job_kind"));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"completed":0,"failed":0,"relations":0}"""), result["dispatch"]));
        Assert.Equal(0, result.Number("risk_queued")); Assert.Equal(0, result.Number("findings_created"));
        foreach (string stage in new[] { "producer_backfill", "import_summary", "risk", "sigma", "detections", "password_producer", "password_risk" }) Assert.Null(result[stage]);
        await using var connections = new NpgsqlCommand("select count(*) from pg_stat_activity where usename='sli_semantic_login'", owner);
        Assert.Equal(0L, await connections.ExecuteScalarAsync(ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Theory] [InlineData("facts-v1")] [InlineData("findings-v1")]
    public async Task Recovery_rejects_wrong_mode_before_database_access(string mode)
    {
        await using var db = new NpgsqlConnection();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new SemanticProduction(null!, Settings, mode, 1, Digest).RunOnceAsync(db, TestContext.Current.CancellationToken));
        Assert.Contains("investigation", error.Message);
    }

    [Fact]
    public async Task Heartbeat_and_controller_require_fresh_managed_release_and_exact_scope_even_before_first_result()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var runtime = Runtime(fixture); await using var db = await runtime.OpenAsync(ct);
        var result = new JsonObject { ["repair_scope"] = new JsonObject { ["job_kind"] = "semantic_v2_quarantine_repair", ["repair_plan_digest"] = Digest } };
        var worker = Guid.NewGuid();
        await SemanticProduction.Heartbeat(db, worker, "investigation-v1", "running", 10, ct, result);
        // The independent pulse has no cycle result yet, but must retain scope.
        await SemanticProduction.Heartbeat(db, worker, "investigation-v1", "running", 5, ct, repairDigest: Digest);
        await using var query = new NpgsqlCommand("select details_json::text from runtime_worker_heartbeats where worker_name='semantic'", db);
        var details = JsonNode.Parse((string)(await query.ExecuteScalarAsync(ct))!)!;
        Assert.Equal(Digest, details["repair_scope"].Text("repair_plan_digest"));
        Assert.Equal("semantic_v2_quarantine_repair", details["repair_scope"].Text("job_kind"));
        Assert.False(details.Flag("manual_runtime"));
        Assert.Equal(new string('a', 64), details["result"]?["repair_scope"].Text("repair_plan_digest"));
        await using (var tx = await db.BeginTransactionAsync(ct)) {
            await using var session = new SemanticSession(db, tx);
            await SemanticProduction.RequireRepairWorkerAsync(session, Digest, ct);
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                SemanticProduction.RequireRepairWorkerAsync(session, new string('b', 64), ct));
            Assert.Contains("scope", error.Message);
        }
        foreach (string fault in new[] { "missing_scope", "extra_scope", "wrong_release", "manual", "wrong_mode", "stale", "error" }) {
            var invalid = details.DeepClone();
            switch (fault) {
                case "missing_scope": invalid.AsObject().Remove("repair_scope"); break;
                case "extra_scope": invalid["repair_scope"]!["extra"] = true; break;
                case "wrong_release": invalid["processing_contract"]!["release_fingerprint"] = new string('f', 64); break;
                case "manual": invalid["manual_runtime"] = true; break;
                case "wrong_mode": invalid["runtime_mode"] = "facts-v1"; break;
            }
            await using (var update = new NpgsqlCommand("update runtime_worker_heartbeats set details_json=@details::jsonb,heartbeat_at=now()-(@age*interval '1 second'),status=@status where worker_name='semantic'", db)) {
                update.Parameters.AddWithValue("details", invalid.ToJsonString());
                update.Parameters.AddWithValue("age", fault == "stale" ? 181 : 0);
                update.Parameters.AddWithValue("status", fault == "error" ? "error" : "running");
                await update.ExecuteNonQueryAsync(ct);
            }
            await using var tx = await db.BeginTransactionAsync(ct);
            await using var session = new SemanticSession(db, tx);
            await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticProduction.RequireRepairWorkerAsync(session, Digest, ct));
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}

