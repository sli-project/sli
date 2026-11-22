using System.Diagnostics;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Domains;
using GpoJson = Sli.Server.Gpo.GpoJson;
using GpoReadStore = Sli.Server.Gpo.GpoReadStore;
using IGpoReadStore = Sli.Server.Gpo.IGpoReadStore;
using Sli.Server.Infrastructure;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Agents;
using Xunit;
using static Sli.Server.Domains.HomeJson;

namespace Sli.Server.Tests.Domains;

public sealed partial class HomeSummaryEndpointTests
{
    private sealed class LocalHomeDatabase(PostCollectionPostgres pg) : IPostgresConnectionFactory, IAsyncDisposable
    {
        private readonly NpgsqlDataSource source = NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(pg.ConnectionString) { Pooling = true }.ConnectionString);
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => await source.OpenConnectionAsync(ct);
        public ValueTask DisposeAsync() => source.DisposeAsync();
    }

    [Fact]
    public async Task Period_home_reads_scoped_facts_and_thirty_thousand_failed_logons_per_day()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(ct);
        await using var db = await pg.OpenAsync(ct);
        var end = new DateTimeOffset(DateTime.UtcNow.Date, TimeSpan.Zero);
        await PostCollectionPostgres.Sql(db, """
            create role adlog_user;
            create table auth_users(id bigint,username text);
            create table semantic_suppressions(id bigint,finding_id bigint,kind text,state text,expires_at timestamptz,responsible_user_id bigint,semantic_type text);
            create table findings_active(id bigint primary key,domain_id bigint,rule_code text,title text,summary text,severity text,
                actor text,target text,first_seen_utc text,closed_at text,status text,repeat_count int);
            create function is_semantic_finding_published_v1(finding bigint) returns boolean language sql stable as 'select finding <> 9';
            create function semantic_finding_in_domains_v265(finding bigint, ids bigint[]) returns boolean language sql stable
                as 'select ids is null or exists(select 1 from findings_active f where f.id=finding and f.domain_id=any(ids))';
            create function semantic_finding_suppressed_v160(finding bigint,rule text) returns boolean language sql stable as 'select false';
            create table finding_entities(finding_id bigint,entity_id bigint);
            create table finding_event_copies337(finding_id bigint,event_id bigint,event_kind int,domain_id bigint,time_created_utc timestamptz,computer text);
            create table storage_v2_entity_type(id bigint,value text);
            create table entities_v2_active(id bigint,entity_type_id bigint,domain_id bigint,display_name text);
            create table ad_context_entity_versions(entity_id bigint,source_section text,valid_from_utc timestamptz,
                valid_to_utc timestamptz,attributes_json jsonb,source_run_id uuid);
            create table ad_context_runs(run_id uuid,domain_id bigint,status text);
            create table ad_context_evidence(source_run_id uuid,observed_at_utc timestamptz,evidence_type text,locator_json jsonb);
            create table ad_context_sections(run_id uuid,section_name text,status text);
            create table ad_snapshot_manifest_sources(manifest_id uuid,family text,source_id text);
            create table sli_agent_snapshot_cycles(manifest_id uuid,publication_state text,agent_id uuid,cycle_id uuid,gpo_source_run_id uuid);
            create table sli_agents(id uuid,last_seen timestamptz);
            create table platform_settings(key text,value text);
            create table gpo_report_v2_source_snapshots(domain_id bigint,source_run_id uuid,import_status text,payload_json jsonb);
            create table servers(id bigint primary key,domain_id bigint);
            create table event_hot(event_id bigint,time_created_utc timestamptz,event_kind int,domain_id bigint,
                actor text,target text,source text,computer text,method jsonb,outcome jsonb,fields jsonb,
                primary key(time_created_utc,event_id)) partition by range(time_created_utc);
            create table event_hot_fixture partition of event_hot default;
            create index on event_hot(domain_id,event_kind,time_created_utc);
            """, ct);
        await using (var seed = new NpgsqlCommand("""
            insert into servers values (17,7),(18,8);
            insert into event_hot
            select n,@end-interval '8 days'+(n-1)*interval '2.88 seconds',4625,7,
                'test-actor','test-target',null,'DC01.example.test',
                '{"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing","$server_id":17}',
                '{}','{}' from generate_series(1,240000) n;
            insert into event_hot values
                (250001,@end-interval '90 minutes',4624,7,'test-actor','test-target',null,'DC01',
                 '{"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing","$server_id":17}','{}','{}'),
                (250002,@end-interval '90 minutes',4625,8,'other-actor','other-target',null,'DC09',
                 '{"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing","$server_id":18}','{}','{}'),
                (250003,@end-interval '45 minutes',4720,7,'test-admin','test-account',null,'DC01',
                 '{"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing","$server_id":17}','{}','{}'),
                (250004,@end-interval '35 minutes',4728,7,'test-admin','test-group',null,'DC01',
                 '{"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing","$server_id":17}','{}','{"MemberName":"test-account"}'),
                (250005,@end-interval '20 minutes',4625,7,null,null,null,'DC01',
                 '{"$channel":"Application","$provider":"synthetic","$server_id":17}','{}','{}');
            insert into findings_active values
                (1,7,'test-high','New high problem','A new high problem','high','test-actor','test-group',(@end-interval '35 minutes')::text,null,'active',0),
                (2,7,'test-medium','Closed problem','A closed problem','medium',null,'test-account',(@end-interval '2 hours')::text,(@end-interval '1 hour')::text,'closed',0),
                (3,7,'test-hygiene','Hygiene problem',null,'low',null,'test-account',(@end-interval '3 hours')::text,null,'new',0),
                (4,7,'test-medium','Old problem',null,'medium',null,'test-account',(@end-interval '2 days')::text,null,'review',0),
                (5,8,'test-critical','Other domain problem',null,'critical',null,'other-account',(@end-interval '2 hours')::text,null,'new',0),
                (9,7,'test-critical','Unpublished problem',null,'critical',null,'test-account',(@end-interval '2 hours')::text,null,'new',0);
            insert into finding_event_copies337 values (1,250004,4728,7,@end-interval '35 minutes','DC01.example.test');
            insert into storage_v2_entity_type values(1,'ad_computer'),(2,'password_policy');
            insert into entities_v2_active values(10,1,7,'DC01.example.test'),(11,1,7,'DC02.example.test'),(20,2,7,'Default domain password policy');
            insert into finding_entities values (1,10);
            insert into ad_context_runs values('10000000-0000-4000-8000-000000000001',7,'completed');
            insert into ad_context_evidence values
                ('10000000-0000-4000-8000-000000000001',@end-interval '20 minutes','data_quality','{"section":"domain_health","record_key":"dc1"}'),
                ('10000000-0000-4000-8000-000000000001',@end-interval '20 minutes','data_quality','{"section":"domain_health","record_key":"dc2"}');
            insert into ad_context_entity_versions values
                (10,'domain_health',@end-interval '20 minutes',null,'{"record_key":"dc1","attributes":{"infrastructure_role":"domain_controller","dns_state":"failed","sysvol_state":"passed"}}','10000000-0000-4000-8000-000000000001'),
                (11,'domain_health',@end-interval '20 minutes',null,'{"record_key":"dc2","attributes":{"infrastructure_role":"domain_controller","dns_state":"passed","sysvol_state":"passed"}}','10000000-0000-4000-8000-000000000001'),
                (20,'domain_posture',@end-interval '2 days',@end-interval '30 minutes','{"attributes":{"password_min_length":14}}','10000000-0000-4000-8000-000000000021'),
                (20,'domain_posture',@end-interval '30 minutes',null,'{"attributes":{"password_min_length":16}}','10000000-0000-4000-8000-000000000022');
            insert into ad_context_sections values
                ('10000000-0000-4000-8000-000000000021','domain_posture','complete'),
                ('10000000-0000-4000-8000-000000000022','domain_posture','complete');
            insert into ad_snapshot_manifest_sources values
                ('10000000-0000-4000-8000-000000000004','ad_domain_health','10000000-0000-4000-8000-000000000001');
            insert into sli_agent_snapshot_cycles(manifest_id,publication_state,agent_id) values
                ('10000000-0000-4000-8000-000000000004','published','10000000-0000-4000-8000-000000000003');
            insert into sli_agents values('10000000-0000-4000-8000-000000000003',@end-interval '21 minutes');
            analyze;
            """, db))
        {
            seed.Parameters.AddWithValue("end", end);
            await seed.ExecuteNonQueryAsync(ct);
        }
        await SeedGpo(db, end.AddMinutes(-25), ct);
        await using var database = new LocalHomeDatabase(pg);
        var config = new ConfigurationBuilder().Build();
        var owner = Report("events.journal").Capabilities! with { IsOwner = true };
        using var services = new ServiceCollection().AddLogging().AddSingleton(new TransportGate(config))
            .AddSingleton<IPrincipalAuthenticator>(new Authentication()).AddSingleton<IDomainAccessService>(new Access(true))
            .AddSingleton<IHomeSummaryAccess>(new Reports(Report("security.problems", ["security","identity_basic","technical","raw_evidence"]) with { Capabilities = owner },
                 Report("ad.infrastructure") with { Capabilities = owner },
                 Report("ad.gpo.v2") with { Capabilities = owner },
                 Report("events.journal", ["security","identity_basic","technical","raw_evidence"]) with { Capabilities = owner }))
            .AddSingleton<IDomainRepository>(new Domains(true))
            .AddSingleton<IConfiguration>(config).AddSingleton<IGpoReadStore, GpoReadStore>()
            .AddSingleton<IPostgresConnectionFactory>(database).AddSingleton<IHomeSummaryRepository, HomeSummaryRepository>()
            .AddScoped<HomeSummaryReaders>().AddScoped<HomeSummaryService>().BuildServiceProvider();
        async Task<JsonObject> Read()
        {
            using var scope = services.CreateScope();
            var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider, RequestAborted = ct };
            context.Request.Path = "/api/v1/home/summary";
            context.Request.QueryString = QueryString.Create(new Dictionary<string,string?> {
                ["contract"]="v4",["domain_id"]="7",["period"]="custom",["from"]=end.AddDays(-1).ToString("O"),["to"]=end.ToString("O")
            });
            using var body = new MemoryStream();
            context.Response.Body = body;
            await HomeSummaryEndpoints.HandleAsync(context);
            Assert.True(context.Response.StatusCode == 200, System.Text.Encoding.UTF8.GetString(body.ToArray()));
            return JsonNode.Parse(body.ToArray())!.AsObject();
        }

        await Read(); // Warm the local pool before measuring the request.
        var timer = Stopwatch.StartNew();
        var payload = await Read();
        timer.Stop();
        TestContext.Current.TestOutputHelper?.WriteLine($"Home took {timer.Elapsed.TotalMilliseconds:N0} ms with 240,000 logons over eight days.");
        Assert.True(timer.Elapsed < TimeSpan.FromSeconds(1), $"Home took {timer.Elapsed.TotalMilliseconds:N0} ms.");
        var problems = payload["problems"]!;
        Assert.Equal(3, problems.Number("new_count"));
        Assert.Equal(1, problems.Number("closed_count"));
        Assert.Equal(3, problems.Number("open_count"));
        var rows = problems["items"]!.AsArray();
        Assert.Equal(new long[] { 1, 2 }, rows.Select(row => row.Number("id")));
        Assert.Contains("id=1", rows[0].Text("href"));
        Assert.Equal("/app/entities/10", rows[0].Text("object_href"));
        Assert.Equal(4728, Assert.Single(rows[0]!["observations"]!.AsArray()).Number("event_id"));

        var controllers = payload["controllers"]!["items"]!.AsArray();
        Assert.Equal("dns", Assert.Single(controllers[0]!["failures"]!.AsArray()).Text("key"));
        Assert.Equal(end.AddMinutes(-21), controllers[0].Stamp("at"));
        Assert.Equal(2, controllers[1].Number("passed"));
        var changes = payload["changes"]!["items"]!.AsArray();
        Assert.Equal(3, changes.Count);
        Assert.Equal("Browser settings", changes[0].Text("name"));
        Assert.Equal("Download mode", changes[0].Text("label"));
        Assert.Equal("Disabled", changes[0].Text("after"));
        Assert.Equal("14", changes[1].Text("before"));
        Assert.Equal("16", changes[1].Text("after"));
        Assert.Equal(4720, changes[2].Number("event_id"));
        var activity = payload["activity"]!;
        var hours = activity["hours"]!.AsArray();
        Assert.Equal(24, hours.Count);
        Assert.Equal(30_000, hours.Sum(hour => hour.Number("failed")));
        Assert.Equal(1, hours.Sum(hour => hour.Number("succeeded")));
        Assert.All(hours, hour => Assert.Equal(1250, hour.Number("typical")));
        Assert.Equal(2, activity["markers"]!.AsArray().Count);
    }

    private static async Task SeedGpo(NpgsqlConnection db, DateTimeOffset at, CancellationToken ct)
    {
        await PostCollectionPostgres.InstallSnapshotChangeStorageAsync(db, ct);
        var manifest = Guid.Parse("10000000-0000-4000-8000-000000000051");
        var batch = new string('a', 64);
        var change = Object(new {
            object_type = "gpo_setting", object_id = "setting-one", related_object_id = "policy-one",
            kind = "attribute_changed", field = "value_display",
            before_sha256 = GpoJson.Hash(JsonValue.Create("Enabled")), after_sha256 = GpoJson.Hash(JsonValue.Create("Disabled"))
        });
        var id = GpoJson.Hash(new JsonArray(batch, change.DeepClone()));
        var payload = LifecycleJson.Canonical(change);
        await using var transaction = await db.BeginTransactionAsync(ct);
        await SnapshotChangeStore.WriteAsync(db, transaction, manifest, batch, 7, "gpo_v2", at.UtcDateTime,
            [Object(new { record_id = id, payload_json = payload })], [("Enabled", "Disabled")], [], null, null, ct);
        await using var prepare = new NpgsqlCommand("""
            insert into ad_snapshot_history_confirmations(manifest_id,family,domain_id,previous_manifest_id,source_sha256,
                previous_sha256,batch_id,records_sha256,record_count,observed_at,coverage_state)
            values(@manifest,'gpo_v2',7,'10000000-0000-4000-8000-000000000050',repeat('b',64),repeat('c',64),@batch,@digest,1,@at,'complete');
            insert into ad_snapshot_manifest_sources values(@manifest,'gpo_v2','10000000-0000-4000-8000-000000000052');
            insert into gpo_report_v2_source_snapshots values (7,'10000000-0000-4000-8000-000000000052','completed',
                '{"gpos":[{"id":"policy-one","display_name":"Browser settings"}],"settings":[{"id":"setting-one","setting_name":"Download mode"}]}');
            """, db, transaction);
        prepare.Parameters.AddWithValue("manifest", manifest);
        prepare.Parameters.AddWithValue("batch", batch);
        prepare.Parameters.AddWithValue("digest", GpoJson.Hash(new JsonArray(new JsonArray(id, payload))));
        prepare.Parameters.AddWithValue("at", at);
        await prepare.ExecuteNonQueryAsync(ct);
        await transaction.CommitAsync(ct);
    }
}
