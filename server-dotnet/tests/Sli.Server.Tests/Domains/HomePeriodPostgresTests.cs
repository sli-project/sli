using System.Diagnostics;
using System.Globalization;
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
using Sli.Server.Problems;
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
    public async Task Period_home_reads_scoped_subjects_and_three_thousand_failed_logons_per_hour()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(ct);
        await using var db = await pg.OpenAsync(ct);
        var end = new DateTimeOffset(DateTime.UtcNow.Date, TimeSpan.Zero);
        await PostCollectionPostgres.Sql(db, """
            create role adlog_user;
            create table auth_users(id bigint,username text,role text,is_active bool,is_service bool,previous_login_at timestamptz);
            create table auth_api_keys(report_subject_id bigint);
            create table semantic_suppressions(id bigint,finding_id bigint,kind text,state text,expires_at timestamptz,responsible_user_id bigint,semantic_type text);
            create table findings_active(id bigint primary key,domain_id bigint,rule_code text,title text,summary text,severity text,
                actor text,target text,first_seen_utc text,closed_at text,status text,repeat_count int);
            create function is_semantic_finding_published_v1(finding bigint) returns boolean language sql stable as 'select finding <> 9';
            create function semantic_finding_in_domains_v265(finding bigint, ids bigint[]) returns boolean language sql stable
                as 'select ids is null or exists(select 1 from findings_active f where f.id=finding and f.domain_id=any(ids))';
            create function semantic_finding_suppressed_v160(finding bigint,rule text) returns boolean language sql stable as 'select false';
            create table semantic_security_scenarios(scenario_key bytea,scenario_kind text,partition_key text,strict_keys_json jsonb);
            create table finding_event_details337(finding_id bigint,event_db_id bigint,event_id int);
            create function password_problem_facts395(finding bigint,rule text) returns jsonb language sql stable as 'select null::jsonb';
            create table finding_entities(finding_id bigint,entity_id bigint,display_name text,entity_role text);
            create table finding_event_copies337(finding_id bigint,event_id bigint,event_kind int,domain_id bigint,time_created_utc timestamptz,
                computer text,method jsonb,fields jsonb);
            create index on finding_event_copies337(finding_id,event_kind,event_id);
            create table storage_v2_entity_type(id bigint,value text);
            create table entities_v2_active(id bigint,entity_type_id bigint,domain_id bigint,display_name text);
            create table ad_context_entity_versions(entity_id bigint,source_section text,valid_from_utc timestamptz,
                valid_to_utc timestamptz,attributes_json jsonb,source_run_id uuid);
            create table ad_context_runs(run_id uuid,domain_id bigint,status text);
            create table ad_context_evidence(source_run_id uuid,observed_at_utc timestamptz,evidence_type text,locator_json jsonb);
            create table ad_context_sections(run_id uuid,section_name text,status text);
            create table ad_snapshot_manifest_sources(manifest_id uuid,family text,source_id text);
            create table sli_agent_snapshot_cycles(manifest_id uuid,publication_state text,agent_id uuid,cycle_id uuid,gpo_source_run_id uuid);
            create table platform_settings(key text,value text);
            create table gpo_report_v2_source_snapshots(domain_id bigint,source_run_id uuid,import_status text,payload_json jsonb,
                schema_version text,source_completed_at_utc timestamptz,source_observed_at_utc timestamptz,payload_sha256 bytea);
            create table servers(id bigint primary key,domain_id bigint);
            create table event_hot(event_id bigint,time_created_utc timestamptz,event_kind int,domain_id bigint,
                actor text,target text,source text,computer text,method jsonb,outcome jsonb,fields jsonb,
                source_sha256 bytea,primary key(time_created_utc,event_id)) partition by range(time_created_utc);
            create table event_hot_fixture partition of event_hot default;
            create index on event_hot(domain_id,event_kind,time_created_utc) where source_sha256 is not null;
            """, ct);
        await using (var seed = new NpgsqlCommand("""
            do $partitions$ declare day date;
            begin
                for day in select generate_series(current_date-12,current_date,interval '1 day')::date loop
                    execute format('create table event_hot_%s partition of event_hot for values from (%L) to (%L)',
                        to_char(day,'YYYYMMDD'),day,day+1);
                end loop;
            end $partitions$;
            insert into servers values (17,7),(18,8);
            insert into event_hot
            select day*72000+n,@end-day*interval '1 day'+(n-1)*interval '1.2 seconds',4625,7,
                'test-actor','test-target',null,'DC01.example.test',
                '{"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing","$server_id":17}',
                '{}','{}',decode(repeat('aa',32),'hex') from generate_series(1,12) day
                cross join lateral generate_series(1,72000) n where day<=6 or n%5<>0;
            insert into event_hot(event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields) values
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
            insert into event_hot(event_id,time_created_utc,event_kind,domain_id,actor,target,computer,method,outcome,fields)
            select 960000+kind,@end-interval '2 days',kind,7,null,'DC01','DC01',
                jsonb_build_object('$channel',case when kind=4726 then 'security' else 'Security' end,
                    '$provider','microsoft-windows-security-auditing','$server_id',17,
                    '$principals','{"SubjectUserName":"test-admin","TargetUserName":"test-subject"}'::jsonb), '{}',
                '{"MemberName":"test-member","UserPrincipalName":"test-subject@example.test"}'
            from unnest(array[4720,4725,4726,4728,4729,4732,4733,4738,4756,4757]) kind;
            insert into event_hot(event_id,time_created_utc,event_kind,domain_id,actor,target,computer,method,outcome,fields) values
                (950006,@end-interval '2 days',4726,8,'other-actor','other-target','DC09',
                 '{"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing","$server_id":18}','{}','{}'),
                (950007,@end-interval '2 days',4726,7,null,null,'DC01',
                 '{"$channel":"Security","$provider":"synthetic","$server_id":17}','{}','{}'),
                (950008,@end,4726,7,'test-admin','outside-window','DC01',
                 '{"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing","$server_id":17}','{}','{}');
            insert into findings_active values
                (1,7,'semantic.security.privileged_group_member_added','Stored English title',null,'high','test-actor','test-group',(@end-interval '35 minutes')::text,null,'active',0),
                (2,7,'semantic.security.audit_controls_changed','Stored English title',null,'medium',null,null,(@end-interval '2 hours')::text,(@end-interval '1 hour')::text,'closed',0),
                (3,7,'test-hygiene','Hygiene problem',null,'low',null,'test-account',(@end-interval '3 hours')::text,null,'new',0),
                (4,7,'test-medium','Old problem',null,'medium',null,'test-account',(@end-interval '2 days')::text,null,'review',0),
                (5,8,'test-critical','Other domain problem',null,'critical',null,'other-account',(@end-interval '2 hours')::text,null,'new',0),
                (6,7,'semantic.qw.password-brute-force','Stored English title',null,'high','','',(@end-interval '39 minutes')::text,null,'active',0),
                (7,7,'semantic.qw.password-spray','Stored English title',null,'high','','',(@end-interval '40 minutes')::text,null,'active',0),
                (9,7,'test-critical','Unpublished problem',null,'critical',null,'test-account',(@end-interval '2 hours')::text,null,'new',0),
                (10,7,'qw.ad-hardening.machine-account-quota','MachineAccountQuota',null,'medium',null,'example.test',(@end-interval '3 hours')::text,null,'new',0),
                (11,7,'qw.ad-hardening.lockout-threshold','Lockout threshold',null,'medium',null,'example.test',(@end-interval '3 hours')::text,null,'new',0),
                (12,7,'qw.ad-hardening.privileged-nonexpiring','Password never expires',null,'high',null,'test-account',(@end-interval '3 hours')::text,null,'new',0),
                (13,7,'semantic.security.privileged_group_member_added','Earlier occurrence',null,'high',null,'test-group',(@end-interval '8 days')::text,null,'new',0);
            alter table findings_active add column last_seen_utc text, add column fingerprint text, add column source text, add column evidence_count int, add column assigned_to text,
                add column created_at timestamptz, alter column closed_at type timestamptz using closed_at::timestamptz;
            update findings_active set last_seen_utc=first_seen_utc,created_at=first_seen_utc::timestamptz;
            insert into auth_users values
                (1,'admin-example','admin',true,false,@end-interval '1 day'),
                (2,'operator-example','operator',true,false,null),
                (3,'viewer-example','viewer',true,false,null),
                (4,'inactive-example','operator',false,false,null),
                (5,'service-example','operator',true,true,null),
                (6,'key-example','operator',true,false,null);
            insert into auth_api_keys values(6);
            insert into finding_event_copies337 values
                (1,250004,4728,7,@end-interval '35 minutes','DC01.example.test',
                 '{"$principals":{"TargetUserName":"test-group"}}','{"MemberName":"test-account"}'),
                (2,970000,4719,7,@end-interval '2 hours','DC01.example.test','{}','{}'),
                (6,970099,4625,8,@end-interval '24 minutes','DC09.example.test',
                 '{"$principals":{"TargetUserName":"other-account","IpAddress":"198.51.100.2"}}','{}'),
                (6,970100,4625,7,@end-interval '8 days','DC01.example.test',
                 '{"$principals":{"TargetUserName":"outside-period","IpAddress":"192.0.2.2"}}','{}');
            insert into finding_event_copies337
            select 6,970000+n,4625,7,@end-interval '39 minutes'+(n-1)*interval '40 seconds','DC01.example.test',
                '{"$principals":{"TargetUserName":"test-account","IpAddress":"203.0.113.11"}}','{}'
            from generate_series(1,18) n;
            insert into finding_event_copies337
            select 7,980000+n,4625,7,@end-interval '40 minutes'+n*interval '1 second','DC02.example.test',
                jsonb_build_object('$principals',jsonb_build_object('TargetUserName','test-account-'||(n%12),'IpAddress','203.0.113.'||n)), '{}'
            from generate_series(1,38) n;
            insert into storage_v2_entity_type values(1,'ad_computer'),(2,'password_policy');
            insert into entities_v2_active values(10,1,7,'DC01.example.test'),(11,1,7,'DC02.example.test'),(20,2,7,'Default domain password policy');
            insert into finding_entities values
                (1,10,'DC01.example.test','source'),
                (2,10,'DC01.example.test','target_entity'),
                (4,null,'test-computer','target_entity');
            insert into ad_context_runs values
                ('10000000-0000-4000-8000-000000000001',7,'completed'),
                ('10000000-0000-4000-8000-000000000002',7,'completed');
            insert into ad_context_evidence values
                ('10000000-0000-4000-8000-000000000001',@end-interval '20 minutes','entity_observation','{"section":"domain_health","record_key":"dc1"}'),
                ('10000000-0000-4000-8000-000000000001',@end-interval '20 minutes','entity_observation','{"section":"domain_health","record_key":"dc2"}'),
                ('10000000-0000-4000-8000-000000000002',@end-interval '10 minutes','entity_observation','{"section":"domain_health","record_key":"dc1"}');
            insert into ad_context_entity_versions values
                (10,'domain_health',@end-interval '20 minutes',null,'{"record_key":"dc1","attributes":{"infrastructure_role":"domain_controller","dns_state":"failed","sysvol_state":"passed"}}','10000000-0000-4000-8000-000000000001'),
                (11,'domain_health',@end-interval '20 minutes',null,'{"record_key":"dc2","attributes":{"infrastructure_role":"domain_controller","dns_state":"passed","sysvol_state":"passed","services_state":"running","connectivity_state":"passed","advertising_state":"passed","time_service_state":"running","operating_system":"Windows Server 2022"}}','10000000-0000-4000-8000-000000000001'),
                (20,'domain_posture',@end-interval '2 days',@end-interval '30 minutes','{"attributes":{"password_min_length":14}}','10000000-0000-4000-8000-000000000021'),
                (20,'domain_posture',@end-interval '30 minutes',null,'{"attributes":{"password_min_length":16}}','10000000-0000-4000-8000-000000000022');
            insert into ad_context_sections values
                ('10000000-0000-4000-8000-000000000021','domain_posture','complete'),
                ('10000000-0000-4000-8000-000000000022','domain_posture','complete');
            insert into ad_snapshot_manifest_sources values
                ('10000000-0000-4000-8000-000000000004','ad_domain_health','10000000-0000-4000-8000-000000000001'),
                ('10000000-0000-4000-8000-000000000005','ad_domain_health','10000000-0000-4000-8000-000000000002');
            insert into sli_agent_snapshot_cycles(manifest_id,publication_state,agent_id) values
                ('10000000-0000-4000-8000-000000000004','published','10000000-0000-4000-8000-000000000003'),
                ('10000000-0000-4000-8000-000000000005','publishing','10000000-0000-4000-8000-000000000003');
            analyze;
            """, db))
        {
            seed.CommandTimeout = 120;
            seed.Parameters.AddWithValue("end", end);
            await seed.ExecuteNonQueryAsync(ct);
        }
        await SeedGpo(db, end.AddMinutes(-25), ct);
        var queries = new System.Collections.Concurrent.ConcurrentQueue<(string Sql, IReadOnlyDictionary<string, object?> Parameters, bool Activity)>();
        await using var database = new LocalHomeDatabase(pg);
        var repository = new ProfiledHomeRepository(new HomeSummaryRepository(database), queries);
        var config = new ConfigurationBuilder().Build();
        var owner = Report("events.journal").Capabilities! with { IsOwner = true };
        using var services = new ServiceCollection().AddLogging().AddSingleton(new TransportGate(config))
            .AddSingleton<IPrincipalAuthenticator>(new Authentication()).AddSingleton<IDomainAccessService>(new Access(true))
            .AddSingleton<IHomeSummaryAccess>(new Reports(Report("security.problems", ["security","identity_basic","technical","raw_evidence"]) with { Capabilities = owner },
                 Report("ad.infrastructure") with { Capabilities = owner },
                 Report("ad.gpo.v2") with { Capabilities = owner },
                 Report("security.events.chains") with { Capabilities = owner },
                 Report("events.journal", ["security","identity_basic","technical","raw_evidence"]) with { Capabilities = owner }))
            .AddSingleton<IDomainRepository>(new Domains(true))
            .AddSingleton<IConfiguration>(config).AddSingleton<IGpoReadStore, GpoReadStore>()
            .AddSingleton<IPostgresConnectionFactory>(database).AddSingleton<IHomeSummaryRepository>(repository)
            .AddScoped<HomeSummaryReaders>().AddScoped<HomeSummaryService>().BuildServiceProvider();
        async Task<JsonObject> Read(int days, string language = "en", DateTimeOffset? until = null, bool openQueue = false,
            int page = 1, int limit = 25, string filter = "all")
        {
            using var scope = services.CreateScope();
            var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider, RequestAborted = ct };
            context.Request.Path = "/api/v1/home/summary";
            context.Request.Headers.AcceptLanguage = language;
            var to = until ?? end;
            var args = new Dictionary<string,string?> {
                ["contract"] = openQueue ? "v5" : "v4", ["domain_id"] = "7", ["period"] = "custom",
                ["from"] = to.AddDays(-days).ToString("O"), ["to"] = to.ToString("O")
            };
            if (openQueue)
            {
                args["page"] = page.ToString(CultureInfo.InvariantCulture);
                args["limit"] = limit.ToString(CultureInfo.InvariantCulture);
                args["queue"] = filter;
            }
            context.Request.QueryString = QueryString.Create(args);
            using var body = new MemoryStream();
            context.Response.Body = body;
            await HomeSummaryEndpoints.HandleAsync(context);
            Assert.True(context.Response.StatusCode == 200, System.Text.Encoding.UTF8.GetString(body.ToArray()));
            return JsonNode.Parse(body.ToArray())!.AsObject();
        }

        var output = TestContext.Current.TestOutputHelper;
        async Task<JsonObject> Measure(int days)
        {
            await Read(days); // Warm the pool and shared pages before measuring the request.
            queries.Clear();
            var timer = Stopwatch.StartNew();
            var data = await Read(days);
            timer.Stop();
            await PostCollectionPostgres.Sql(db, "set jit=off", ct);
            foreach (var (sql, parameters, activity) in queries) {
                await PostCollectionPostgres.Sql(db, activity ? "set enable_sort=off" : "set enable_sort=on", ct);
                await using var explain = new NpgsqlCommand(
                    "explain (analyze, buffers) select to_jsonb(home_row) from (" + sql + ") home_row", db);
                foreach (var (key, value) in parameters) explain.Parameters.AddWithValue(key, value!);
                await using var plan = await explain.ExecuteReaderAsync(ct);
                while (await plan.ReadAsync(ct)) {
                    var line = plan.GetString(0);
                    if (line.StartsWith("Execution Time:", StringComparison.Ordinal))
                        output?.WriteLine($"{days * 24}h {sql.Split('\n')[0]}: {line}");
                }
            }
            output?.WriteLine($"{days * 24}h Home took {timer.Elapsed.TotalMilliseconds.ToString("F0", CultureInfo.InvariantCulture)} ms.");
            Assert.True(timer.Elapsed < TimeSpan.FromSeconds(1), $"{days * 24}h Home took {timer.Elapsed.TotalMilliseconds:N0} ms.");
            return data;
        }

        var payload = await Measure(1);
        var week = await Measure(7);
        var russian = await Read(1, "ru");
        var noHistory = await Read(1, until: end.AddDays(-11));
        var partial = await Read(1, until: end.AddMinutes(-15));
        var partialHours = partial["activity"]!["hours"]!.AsArray();
        Assert.Equal(end.AddDays(-1).AddMinutes(-15), partialHours[0].Stamp("at"));
        Assert.Equal(750, partialHours[0].Number("failed"));
        Assert.Equal(2250, partialHours[^1].Number("failed"));
        Assert.Equal(3000, partialHours[^1].Number("typical"));
        var problems = payload["problems"]!;
        Assert.Equal(8, problems.Number("new_count"));
        Assert.Equal(1, problems.Number("closed_count"));
        var (_, queueSql, queueArguments) = ProblemRepository.FindingsQueries(new FindingQuery(null, null, null, null, null, null, null, [7], 25, false) {
            Population = "open", PageQueue = true, GroupQueue = true, QueueList = true, Timezone = "UTC"
        });
        queueArguments.Remove("limit");
        var queue = await new HomeSummaryRepository(database).ReadAsync(queueSql, queueArguments, ct);
        Assert.Equal(8, queue.Sum(row => row.Number("count")));
        Assert.Equal(queue.Sum(row => row.Number("count")), problems.Number("open_count"));
        var rows = problems["items"]!.AsArray();
        Assert.Equal(new long[] { 1, 6, 7, 2 }, rows.Select(row => row.Number("id")));
        Assert.Contains("id=1", rows[0].Text("href"));
        Assert.Null(rows[0].Text("object_href"));
        Assert.Equal(4728, Assert.Single(rows[0]!["observations"]!.AsArray()).Number("event_id"));
        Assert.Equal("test-group · test-account", rows[0].Text("name"));
        Assert.Equal("test-account", rows[1].Text("name"));
        var passwordRule = new JsonObject { ["rule_code"] = "semantic.qw.password-brute-force" };
        var englishTitle = ProblemPresentation.RuleMessage(passwordRule, "title", "en").Text("text");
        var russianTitle = ProblemPresentation.RuleMessage(passwordRule, "title", "ru").Text("text");
        Assert.NotEqual(englishTitle, russianTitle);
        Assert.Equal(englishTitle + " · Failed attempts: 18 · 203.0.113.11 · 23:21–23:32", rows[1].Text("fact"));
        Assert.Equal("Accounts: 12", rows[2].Text("name"));
        Assert.Contains("Source addresses: 38", rows[2].Text("fact"));
        Assert.Equal(20, rows[2]!["observations"]!.AsArray().Count);
        Assert.Equal("DC01.example.test", rows[3].Text("name"));
        Assert.Equal("/app/entities/10", rows[3].Text("object_href"));
        Assert.Equal("Windows audit policy changed", rows[3].Text("fact"));
        var russianRows = russian["problems"]!["items"]!.AsArray();
        Assert.Equal(russianTitle + " · Неудачные попытки: 18 · 203.0.113.11 · 23:21–23:32", russianRows[1].Text("fact"));
        Assert.Equal("Изменена политика аудита Windows", russianRows[3].Text("fact"));
        var oldProblem = week["problems"]!["items"]!.AsArray().Single(row => row.Number("id") == 4);
        Assert.Equal("test-computer", oldProblem.Text("name"));
        Assert.Null(oldProblem!["fact"]);

        var controllers = payload["controllers"]!["items"]!.AsArray();
        Assert.Equal(2, controllers.Count);
        Assert.Equal("dns", Assert.Single(controllers[0]!["failures"]!.AsArray()).Text("key"));
        Assert.Equal(1, controllers[0].Number("passed"));
        Assert.Equal(end.AddMinutes(-20), controllers[0].Stamp("at"));
        Assert.Equal(7, controllers[1].Number("passed"));
        var changes = payload["changes"]!["items"]!.AsArray();
        Assert.Equal(3, changes.Count);
        Assert.Equal("Browser settings", changes[0].Text("name"));
        Assert.Equal("Download mode", changes[0].Text("label"));
        Assert.Equal("Disabled", changes[0].Text("after"));
        Assert.Equal("14", changes[1].Text("before"));
        Assert.Equal("16", changes[1].Text("after"));
        Assert.Equal(4720, changes[2].Number("event_id"));
        var weekChanges = week["changes"]!["items"]!.AsArray().Where(row => row.Stamp("at") == end.AddDays(-2)).ToArray();
        Assert.Equal(new long[] { 4720, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4756, 4757 },
            weekChanges.Select(row => row.Number("event_id")).Order());
        Assert.All(weekChanges, row => {
            Assert.Equal("test-subject", row.Text("name"));
            Assert.Equal("test-admin", row.Text("initiator"));
        });
        Assert.DoesNotContain(week["changes"]!["items"]!.AsArray(), row => row.Stamp("at") == end);

        var activity = payload["activity"]!;
        var hours = activity["hours"]!.AsArray();
        Assert.Equal(24, hours.Count);
        Assert.Equal(72_000, hours.Sum(hour => hour.Number("failed")));
        Assert.Equal(1, hours.Sum(hour => hour.Number("succeeded")));
        Assert.All(hours, hour => Assert.Equal(3000, hour.Number("typical")));
        Assert.Equal(4, activity["markers"]!.AsArray().Count);
        var weekHours = week["activity"]!["hours"]!.AsArray();
        Assert.Equal(168, weekHours.Count);
        Assert.Equal(2400, weekHours[0].Number("typical"));
        Assert.Equal(3000, weekHours[^1].Number("typical"));
        Assert.All(noHistory["activity"]!["hours"]!.AsArray(), hour => Assert.Null(hour!["typical"]));

        await PostCollectionPostgres.Sql(db, """
            create function public.password_queue_presentation399(bigint,text) returns table(facts jsonb,aliases jsonb)
                language sql as 'select public.password_problem_facts395($1,$2),null::jsonb';
            update findings_active set assigned_to='analyst-example' where id=1;
            update findings_active set repeat_count=2 where id=4;
            insert into findings_active(id,domain_id,rule_code,severity,target,first_seen_utc,last_seen_utc,status)
            select n,7,'test-paged','low','account-'||n,(now()-interval '2 days')::text,(now()-interval '1 day')::text,'new'
            from generate_series(100,222) n;
            insert into findings_active(id,domain_id,rule_code,severity,target,first_seen_utc,last_seen_utc,status,assigned_to)
            select 223,domain_id,rule_code,severity,target,first_seen_utc,last_seen_utc,'new','another-analyst'
            from findings_active where id=4;
            """, ct);
        await Read(7, openQueue: true);
        queries.Clear();
        var openTimer = Stopwatch.StartNew();
        var open = await Read(7, openQueue: true);
        openTimer.Stop();
        output?.WriteLine($"7-day Home queue with {open["problems"].Number("open_count")} groups took {openTimer.ElapsedMilliseconds} ms.");
        Assert.True(openTimer.Elapsed < TimeSpan.FromSeconds(3));
        Assert.DoesNotContain(queries, item => item.Activity);
        Assert.Null(open["activity"]);
        Assert.Equal(2, open.Number("active_operator_count"));
        var delta = open["since_previous_login"]!;
        Assert.Equal(8, delta.Number("new_count"));
        Assert.Equal(1, delta.Number("closed_count"));
        Assert.Equal(end.AddDays(-1), delta.Stamp("from"));
        Assert.Contains("created_from=", delta.Text("new_href"));
        Assert.Contains("created_to=", delta.Text("new_href"));
        var firstPage = open["problems"]!["items"]!.AsArray();
        Assert.Equal(25, firstPage.Count);
        Assert.DoesNotContain(firstPage, row => row.Number("id") is 2 or 5 or 9);
        var inProgress = await Read(1, openQueue: true, filter: "in_work");
        var olderProblem = inProgress["problems"]!["items"]!.AsArray().Single(row => row.Number("id") is 4 or 223);
        Assert.Equal(4, olderProblem.Number("occurrence_count"));
        Assert.Equal("mixed", olderProblem.Text("assignee_state"));
        Assert.Null(olderProblem.Text("assignee"));
        var second = await Read(1, openQueue: true, page: 2);
        var unassigned = await Read(1, openQueue: true, filter: "unassigned", limit: 100);
        Assert.Equal(100, unassigned["problems"]!["items"]!.AsArray().Count);
        Assert.DoesNotContain(unassigned["problems"]!["items"]!.AsArray(), row => row.Number("id") is 1 or 4 or 223);
        foreach (var subsequent in new[] { second, inProgress, unassigned })
            foreach (var count in new[] { "open_count", "unassigned_count", "in_work_count" })
                Assert.Equal(open["problems"].Number(count), subsequent["problems"].Number(count));
        var secondPage = second["problems"]!["items"]!.AsArray();
        Assert.Empty(firstPage.Select(row => row.Number("id")).Intersect(secondPage.Select(row => row.Number("id"))));
        var topChanges = Assert.IsType<JsonObject>(open["changes"])["items"]!.AsArray();
        Assert.Equal(10, topChanges.Count);
        Assert.Contains(topChanges, row => row.Text("name") == "test-account" && row.Number("event_id") == 4720);
        Assert.DoesNotContain(topChanges, row => row.Text("name") == "test-group" && row.Number("event_id") == 4728);
        Assert.Contains("security.events.chains", open["changes"].Text("href"));
        Assert.Contains("period=custom", open["changes"].Text("href"));

        await PostCollectionPostgres.Sql(db, "update auth_users set is_active=false where id=2", ct);
        var oneOperator = await Read(1, openQueue: true, page: 2, filter: "unassigned");
        Assert.Equal(1, oneOperator.Number("active_operator_count"));
        Assert.Null(oneOperator["problems"]!["unassigned_count"]);
        Assert.Equal(1, oneOperator["problems"].Number("page"));
        var visible = oneOperator["problems"]!["items"]!.AsArray();
        Assert.Equal(firstPage.Select(row => row.Number("id")), visible.Select(row => row.Number("id")));
        Assert.All(visible, row => Assert.Null(row!["assignee"]));
    }

    private sealed class ProfiledHomeRepository(HomeSummaryRepository repository,
        System.Collections.Concurrent.ConcurrentQueue<(string Sql, IReadOnlyDictionary<string, object?> Parameters, bool Activity)> queries)
        : IHomeSummaryRepository
    {
        public Task<IReadOnlyList<JsonObject>> ReadAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct)
        {
            queries.Enqueue((sql, parameters, false));
            return repository.ReadAsync(sql, parameters, ct);
        }

        public Task<IReadOnlyList<JsonObject>> ReadActivityAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct)
        {
            queries.Enqueue((sql, parameters, true));
            return repository.ReadActivityAsync(sql, parameters, ct);
        }
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
