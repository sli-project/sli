using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Problems;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Problems;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed partial class StorageV2RuntimeAuthorizationTests
{
    [Fact]
    public async Task Findings_and_dashboard_return_canonical_rows_and_V2_evidence_under_persisted_v2_route()
    {
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(Token);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString);
        await admin.OpenAsync(Token);
        var source = await ShortEventAdmissionPostgresTests.SeedAsync(admin, Token, eventKinds: [4625]);
        long eventId = Assert.Single(source).EventId;
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, source, Token);
        var now = DateTime.UtcNow;
        var record = Record(Path.Combine(fixture.Pg.Root, "absent-archive")) with {
            Route = "v2", AuthorizedAt = now, ExpiresAt = now.AddDays(1)
        };
        await using (var admission = new NpgsqlCommand("""
            insert into storage_v2_runtime_authorizations(route,authority,preflight_digest,authorization_digest,
                archive_root,evidence,authorized_by,authorized_at,expires_at)
            values('v2','storage-v2-transition-controller/v1',repeat('a',64),@digest,
                @root,@evidence::jsonb,'fixture-owner',@issued,@expires)
            """, admin))
        {
            admission.Parameters.AddWithValue("digest", DirectRuntimeAuthorization.Digest(record));
            admission.Parameters.AddWithValue("root", record.ArchiveRoot); admission.Parameters.AddWithValue("evidence", record.Evidence.ToJsonString());
            admission.Parameters.AddWithValue("issued", now); admission.Parameters.AddWithValue("expires", record.ExpiresAt);
            await admission.ExecuteNonQueryAsync(Token);
        }
        await PostCollectionPostgres.Sql(admin, """
            insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
            values('fixture-runtime',1,'control_health','disabled','{}',sha256('{}'::bytea));
            """, Token);
        foreach (var (id, severity, status) in new[] { (7, "high", "new"), (8, "medium", "active") })
        {
            await using var seed = new NpgsqlCommand("""
                insert into semantic_security_scenarios(scenario_id,scenario_kind,result_class,identity_key,scenario_key,partition_key,strict_keys_json,merge_window_seconds,title,explanation,first_seen_utc,last_seen_utc,risk_class)
                values(@uuid,'fixture-runtime','control_gap',sha256(@id::text::bytea),sha256(@id::text::bytea),'fixture','{}',300,'Fixture scenario','Fixture runtime',now(),now(),@severity);
                insert into findings(id,fingerprint,rule_code,title,severity,status,source)
                values(@id,@fingerprint,'fixture-runtime','Fixture runtime '||@severity,@severity,@status,'semantic-production');
                insert into finding_evidence(finding_id,event_id,evidence_role) values(@id,@event,'primary');
                insert into semantic_control_health_observations(observation_id,observation_key,control_id,partition_key,coverage_status,reason,observed_at_utc,source_reference)
                values(@uuid,sha256(@id::text::bytea),'fixture','fixture','unknown','Fixture observation',now(),@uuid::text);
                insert into semantic_risk_evaluation_jobs(job_id,policy_id,policy_version,source_kind,control_health_id,source_reference,evaluation_mode,idempotency_key,evaluation_status,completed_at)
                values(@uuid,'fixture-runtime',1,'control_health',@uuid,@uuid::text,'enabled',sha256(@id::text::bytea),'completed',now());
                insert into semantic_risk_evaluation_results(job_id,scenario_id,evaluation_mode,risk_class,raw_score,display_score,hard_critical,confidence,confidence_score,coverage_status,evaluation_ms)
                values(@uuid,@uuid,'enabled',@severity,1,1,false,'low',1,'unknown',1);
                insert into semantic_finding_publications(scenario_id,finding_id,first_job_id,finding_fingerprint,published_evidence_count)
                values(@uuid,@id,@uuid,@fingerprint,1);
                """, admin);
            seed.Parameters.AddWithValue("id", id); seed.Parameters.AddWithValue("severity", severity); seed.Parameters.AddWithValue("status", status);
            seed.Parameters.AddWithValue("event", eventId);
            seed.Parameters.AddWithValue("uuid", Guid.Parse($"00000000-0000-4000-8000-{id:D12}"));
            seed.Parameters.AddWithValue("fingerprint", "semantic:" + new string(id == 7 ? 'a' : 'b', 64));
            await seed.ExecuteNonQueryAsync(Token);
        }
        // Successful evidence hydration with all V1 relations absent proves the
        // SQL route; use the native runtime reader role, without owner privileges.
        await using (var absent = new NpgsqlCommand("""
            select count(*)=0 from unnest(array['public.events','public.observed_entities','public.event_entity_links','public.events_v2_core']) table_name
            where to_regclass(table_name) is not null
            """, admin))
            Assert.Equal(true, await absent.ExecuteScalarAsync(Token));
        await using (var retained = new NpgsqlCommand("delete from event_hot where event_id=@event", admin)) {
            retained.Parameters.AddWithValue("event", eventId);
            Assert.Equal(1, await retained.ExecuteNonQueryAsync(Token));
        }
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user")
        }).Build();
        var repository = new ProblemRepository(new PostgresConnectionFactory(configuration), TimeProvider.System);
        var data = await repository.LegacyFindingsAsync("high", 5, Token);
        Assert.Equal("ok", data["status"]!.ToString());
        var finding = Assert.Single(data["items"]!.AsArray())!;
        Assert.Equal(7, finding["id"]!.GetValue<int>());
        Assert.Equal(eventId, Assert.Single(finding["evidence"]!.AsArray())!["event_db_id"]!.GetValue<long>());
        var dashboard = await repository.FindingsAsync(new FindingQuery(null, "medium", null, null, null, null, null, null, 5, false),
            ProblemLifecycleTests.Access("security.queue"), Token);
        Assert.Equal("ok", dashboard["status"]!.ToString());
        finding = Assert.Single(dashboard["items"]!.AsArray())!;
        Assert.Equal(8, finding["id"]!.GetValue<int>());
        Assert.Equal(eventId, Assert.Single(finding["evidence"]!.AsArray())!["event_db_id"]!.GetValue<long>());
    }
}
