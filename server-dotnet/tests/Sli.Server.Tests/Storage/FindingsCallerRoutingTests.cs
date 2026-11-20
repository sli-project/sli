using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Access;
using Sli.Server.Infrastructure;
using Sli.Server.Legacy;
using Sli.Server.Problems;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Problems;
using Xunit;

namespace Sli.Server.Tests.Storage;

// tests/storage/test_storage_v2_findings_caller_routing.py. The managed runtime
// reads V2 only (CURRENT_BASELINE); its controller capability is persisted, not
// passed as a Python function argument or accepted from an HTTP query.
public sealed class FindingsCallerRoutingTests
{
    [Theory]
    [InlineData("")]
    [InlineData("&route=v1")]
    [InlineData("&route=v2")]
    [InlineData("&route=v1&authorization=unsealed&storage_route_authorization=unsealed")]
    public async Task Findings_request_keeps_server_route_and_reference_defaults(string suffix)
    {
        await using var fixture = await ProblemEndpointTests.Fixture.Start();
        var response = await fixture.Send("GET", "/api/findings?source=semantic-production" + suffix, null);
        Assert.Equal(200, response.Status);
        Assert.Equal(7, response.Json["items"]![0]!["id"]!.GetValue<int>());
        Assert.Equal(1, fixture.Repo.Calls);
        Assert.Equal(new FindingQuery(null, null, null, null, null, null, null, null, 200, false), fixture.Repo.FindingsQuery);
    }

    private static ProblemAccess QueueAccess()
    {
        var facts = ProblemEndpointTests.Facts();
        return new(new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts)));
    }

    private static Task SaveAuthorization(NpgsqlConnection db, DirectRuntimeRecord record, CancellationToken ct)
    {
        return Save();
        async Task Save()
        {
            await using var command = new NpgsqlCommand("""
                delete from storage_v2_runtime_authorizations;
                insert into storage_v2_runtime_authorizations(route,authority,preflight_digest,authorization_digest,
                    archive_root,evidence,authorized_by,authorized_at,expires_at,revoked_at)
                values(@route,@authority,@preflight,@digest,@archive,@evidence,'synthetic',@at,@expires,@revoked)
                """, db);
            command.Parameters.AddWithValue("route", record.Route);
            command.Parameters.AddWithValue("authority", record.Authority);
            command.Parameters.AddWithValue("preflight", record.PreflightDigest);
            command.Parameters.AddWithValue("digest", record.AuthorizationDigest);
            command.Parameters.AddWithValue("archive", record.ArchiveRoot);
            command.Parameters.AddWithValue("evidence", NpgsqlDbType.Jsonb, record.Evidence.ToJsonString());
            command.Parameters.AddWithValue("at", record.AuthorizedAt);
            command.Parameters.AddWithValue("expires", record.ExpiresAt);
            command.Parameters.AddWithValue("revoked", NpgsqlDbType.TimestampTz, (object?)record.RevokedAt ?? DBNull.Value);
            await command.ExecuteNonQueryAsync(ct);
        }
    }

    [Fact]
    public async Task Controller_route_reaches_findings_manual_analysis_and_durable_worker_without_v1_fallback()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString);
        await admin.OpenAsync(ct);
        var events = await ShortEventAdmissionPostgresTests.SeedAsync(admin, ct, eventKinds: [4625]);
        var eventId = Assert.Single(events).EventId;
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, events, ct);
        await using (var seed = new NpgsqlCommand("""
            insert into semantic_security_scenarios(scenario_id,scenario_kind,result_class,identity_key,scenario_key,
                partition_key,strict_keys_json,merge_window_seconds,title,explanation,first_seen_utc,last_seen_utc,risk_class)
            values('00000000-0000-4000-8000-000000000001','synthetic-routing','control_gap',sha256('identity'::bytea),
                sha256('scenario'::bytea),'synthetic','{}',300,'Synthetic routing','Synthetic routing',now(),now(),'high');
            insert into findings(id,fingerprint,rule_code,title,severity,status,source,evidence_count)
            values(7,'semantic:'||repeat('a',64),'synthetic-routing','Synthetic routing','high','new','semantic-production',1);
            insert into finding_evidence(finding_id,event_id,evidence_role) values(7,@event,'primary');
            -- The production trigger stores the finding's copy before hot retention removes its source.
            delete from event_hot where event_id=@event;
            insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
            values('synthetic-routing',1,'control_health','disabled','{}',sha256('{}'::bytea));
            insert into semantic_control_health_observations(observation_id,observation_key,control_id,partition_key,
                coverage_status,reason,observed_at_utc,source_reference)
            values('00000000-0000-4000-8000-000000000001',sha256('observation'::bytea),'synthetic','synthetic',
                'unknown','Synthetic routing',now(),'synthetic');
            insert into semantic_risk_evaluation_jobs(job_id,policy_id,policy_version,source_kind,control_health_id,
                source_reference,evaluation_mode,idempotency_key,evaluation_status,completed_at)
            values('00000000-0000-4000-8000-000000000001','synthetic-routing',1,'control_health',
                '00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000001','enabled',sha256('job'::bytea),'completed',now());
            insert into semantic_risk_evaluation_results(job_id,scenario_id,evaluation_mode,risk_class,raw_score,
                display_score,hard_critical,confidence,confidence_score,coverage_status,evaluation_ms)
            values('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000001',
                'enabled','high',1,1,false,'low',1,'unknown',1);
            insert into semantic_finding_publications(scenario_id,finding_id,first_job_id,finding_fingerprint,published_evidence_count)
            values('00000000-0000-4000-8000-000000000001',7,'00000000-0000-4000-8000-000000000001','semantic:'||repeat('a',64),1);
            """, admin)) {
            seed.Parameters.AddWithValue("event", eventId);
            await seed.ExecuteNonQueryAsync(ct);
        }

        // No legacy event permission: neither evidence nor report generation may
        // silently return to V1. Only this disposable cluster is changed.
        await PostCollectionPostgres.Sql(admin, """
            do $$ begin
                if to_regclass('public.events') is not null then revoke all on public.events from adlog_user; end if;
            end $$;
            """, ct);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user"),
            ["Sli:DataDirectory"] = Path.Combine(fixture.Pg.Root, "reports-data"),
            ["Sli:Legacy:SLI_LEGACY_COLLECTION_DISABLED"] = "0",
            ["Sli:Legacy:ADLOG_ACQUISITION_DISABLED"] = "1",
            ["Sli:Legacy:ADLOG_LEGACY_FINDINGS_ENABLED"] = "1"
        }).Build();
        var connections = new PostgresConnectionFactory(config);
        var repository = new ProblemRepository(connections, TimeProvider.System);
        var query = new FindingQuery(null, null, null, null, null, null, null, null, 200, false);
        var access = QueueAccess();
        DateTime now = DateTime.UtcNow;
        now = now.AddTicks(-(now.Ticks % 10)); // persisted PostgreSQL microseconds
        var record = new DirectRuntimeRecord("v2", "storage-v2-transition-controller/v1", new string('a', 64),
            Path.Combine(fixture.Pg.Root, "archive"), new JsonObject(), "synthetic", now.AddMinutes(-1), now.AddHours(1), null, "");
        record = record with { AuthorizationDigest = DirectRuntimeAuthorization.Digest(record) };
        await SaveAuthorization(admin, record, ct);

        var result = await repository.FindingsAsync(query, access, ct);
        Assert.Equal("ok", result["status"]!.GetValue<string>());
        var finding = Assert.Single(result["items"]!.AsArray())!;
        Assert.Equal(7, finding["id"]!.GetValue<long>());
        Assert.Equal("new", finding["status"]!.GetValue<string>());
        Assert.Equal("high", finding["severity"]!.GetValue<string>());
        var evidence = Assert.Single(finding["evidence"]!.AsArray())!;
        Assert.Equal(eventId, evidence["event_db_id"]!.GetValue<long>());
        Assert.Equal(4625, evidence["event_id"]!.GetValue<int>());
        Assert.Equal("Security", evidence["channel"]!.GetValue<string>());
        var page = await repository.FindingsAsync(query with { PageQueue = true, Compact = true }, access, ct);
        Assert.Equal(7, Assert.Single(page["items"]!.AsArray())!["id"]!.GetValue<long>());

        await using var services = new ServiceCollection().AddLogging().AddSingleton<IConfiguration>(config)
            .AddSingleton<IPostgresConnectionFactory>(connections).AddLegacyJobs(hosted: false).BuildServiceProvider();
        await using var scope = services.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<LegacyJobStore>();
        var input = new LegacyJobInput(["fixture"], 0, 0);
        int jobId = store.Create("analyze_existing_events:manual", input)["id"]!.GetValue<int>();
        await scope.ServiceProvider.GetRequiredService<LegacyJobExecution>().RunAsync(new(jobId, false, input, "manual"), ct);
        Assert.Equal("failed", store.Get(jobId)!["status"]!.GetValue<string>());
        string report = Path.Combine(config["Sli:DataDirectory"]!, "reports", "server-fixture-security-profile.html");
        Assert.False(File.Exists(report));
        var posts = scope.ServiceProvider.GetRequiredService<ILegacyPostStore>();
        var worker = new LegacyPostCollection(posts, scope.ServiceProvider.GetRequiredService<ILegacyAnalysis>(),
            new LegacySettings(config), NullLogger<LegacyPostCollection>.Instance,
            producer: scope.ServiceProvider.GetRequiredService<ILegacyFindings>());
        await posts.QueueAsync("routing-valid", 9910, ["fixture"], ct);
        Assert.Equal(new LegacyPostResult(1, 0, 1), await worker.RunOnceAsync("worker-9913", 1, ct));
        await using (var check = new NpgsqlCommand("select findings_result_json->>'status' from post_collection_jobs where durable_job_id='routing-valid'", admin))
            Assert.Equal("disabled", await check.ExecuteScalarAsync(ct));
        Assert.False(File.Exists(report));

        // A malformed selected transition stops before the canonical read or a
        // durable claim, rather than silently starting pre-transition work.
        await posts.QueueAsync("routing-invalid", 9916, ["fixture"], ct);
        foreach (var invalid in new[] {
            record with { AuthorizationDigest = new string('b', 64) },
            record with { Authority = "unsealed" },
            record with { ExpiresAt = now.AddSeconds(-1) },
            record with { RevokedAt = now },
            record with { Route = "v2_primary_compat" }
        }) {
            await SaveAuthorization(admin, invalid, ct);
            var readError = await Assert.ThrowsAsync<InvalidOperationException>(() => repository.FindingsAsync(query, access, ct));
            Assert.Equal("storage_v2_admission_required", readError.Message);
            await using var http = await ProblemEndpointTests.Fixture.Start(repository: repository);
            var response = await http.Send("GET", "/api/findings?source=semantic-production&route=v1", null);
            Assert.Equal(503, response.Status);
            Assert.Equal("storage_transition_authorization_invalid", response.Json["error"]!.GetValue<string>());
            var workerError = await Assert.ThrowsAsync<InvalidOperationException>(() => worker.RunOnceAsync("worker-9916", 1, ct));
            Assert.Equal("storage_v2_admission_required", workerError.Message);
            var claimError = await Assert.ThrowsAsync<InvalidOperationException>(() => posts.ClaimAsync("worker-9916", 1, ct));
            Assert.Equal("storage_v2_admission_required", claimError.Message);
            await using var check = new NpgsqlCommand("select status,attempt_count from post_collection_jobs where durable_job_id='routing-invalid'", admin);
            await using var rows = await check.ExecuteReaderAsync(ct);
            Assert.True(await rows.ReadAsync(ct));
            Assert.Equal("queued", rows.GetString(0));
            Assert.Equal(0, rows.GetInt32(1));
        }
        // An unset selection is not permission to resurrect V1 in .NET. The
        // canonical reader keeps its existing default; legacy work needs V2
        // admission, just as LegacyAnalysis/LegacyAdmittedDatabase require.
        await PostCollectionPostgres.Sql(admin, "delete from storage_v2_runtime_authorizations", ct);
        var defaultRead = await repository.FindingsAsync(query, access, ct);
        Assert.Equal(7, Assert.Single(defaultRead["items"]!.AsArray())!["id"]!.GetValue<long>());
        var missing = await Assert.ThrowsAsync<InvalidOperationException>(() => worker.RunOnceAsync("worker-9916", 1, ct));
        Assert.Equal("storage_v2_admission_required", missing.Message);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
