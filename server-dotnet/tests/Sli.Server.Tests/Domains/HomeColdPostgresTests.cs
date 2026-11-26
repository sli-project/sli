using System.Diagnostics;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Ad;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Auth;
using Sli.Server.Domains;
using Sli.Server.Gpo;
using Sli.Server.Infrastructure;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Domains;

public sealed partial class HomeSummaryEndpointTests
{
    [Fact]
    public async Task Cold_home_reads_stand_size_event_and_evidence_tables_within_budget()
    {
        var test = TestContext.Current;
        var ct = test.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 423);
        var day = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-1), TimeSpan.Zero);
        await using (var db = await fixture.Pg.OpenAsync(ct))
        {
            await SeedHomeSnapshots(db, day.AddHours(12), ct);
            await using var seed = new NpgsqlCommand(ColdHomeSeed, db) { CommandTimeout = 0 };
            seed.Parameters.AddWithValue("day", day);
            await seed.ExecuteNonQueryAsync(ct);
            await PostCollectionPostgres.Sql(db, "alter system set shared_preload_libraries='pg_stat_statements'", ct);
            await PostCollectionPostgres.Sql(db, "alter system set pg_stat_statements.save=off", ct);
        }
        var migration = MigrationDirectory.Read(424).Single(item => item.Version == 424).Path;
        await fixture.Pg.ApplyFileAsync(migration, null, ct);

        // Restart only this fixture after the bulk load and ANALYZE. PostgreSQL
        // shared buffers are cold. The host filesystem cache may retain pages.
        await fixture.Pg.RestartExistingAsync(ct);
        await using var stats = await fixture.Pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(stats, "create extension pg_stat_statements", ct);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Sli"] = new NpgsqlConnectionStringBuilder(fixture.Dsn("adlog_user")) { Pooling = true }.ConnectionString
        }).Build();
        var database = new PostgresConnectionFactory(config);
        var queue = Report("security.problems", ["security", "identity_basic", "technical", "privilege"], [1]);
        var journal = Report("events.journal", ids: [1]) with
        {
            Capabilities = new(false, new HashSet<string> { "events.view" }, new HashSet<string>(), [], new Dictionary<string, System.Text.Json.JsonElement>())
        };
        var access = new Reports(queue, journal, Report("ad.infrastructure", ids: [1]),
            Report("ad.users.v2", ids: [1]), Report("ad.computers.v6", ids: [1]), Report("ad.gpo.v2", ids: [1]));
        var queries = new System.Collections.Concurrent.ConcurrentQueue<(string Sql, IReadOnlyDictionary<string, object?> Parameters, bool Activity)>();
        var repository = new ProfiledHomeRepository(new HomeSummaryRepository(database), queries);
        var home = new HomeSummaryService(access, new DomainRepository(database),
            new HomeSummaryReaders(repository), new GpoReadStore(database, config),
            config, ad: new AdV2Store(database, config));
        using var services = new ServiceCollection().AddLogging().AddSingleton(new TransportGate(config))
            .AddSingleton<IPrincipalAuthenticator>(new Authentication()).AddSingleton<IDomainAccessService>(new Access(true))
            .AddSingleton(home).BuildServiceProvider();
        using var body = new MemoryStream();
        var context = new DefaultHttpContext { RequestServices = services, RequestAborted = ct };
        context.Request.Path = "/api/v1/home/summary";
        context.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["contract"] = "v5", ["domain_id"] = "1", ["tz"] = "UTC", ["period"] = "custom",
            ["from"] = HomeWindow.Iso(day), ["to"] = HomeWindow.Iso(day.AddDays(1))
        });
        context.Response.Body = body;
        var timer = Stopwatch.StartNew();
        await HomeSummaryEndpoints.HandleAsync(context);
        timer.Stop();
        body.Position = 0;
        var payload = (await JsonNode.ParseAsync(body, cancellationToken: ct))!.AsObject();

        test.TestOutputHelper!.WriteLine($"Home wall time: {timer.Elapsed.TotalMilliseconds:F1} ms");
        await using var summary = new NpgsqlCommand("""
            select query,shared_blks_read,shared_blks_hit,total_exec_time,calls
            from pg_stat_statements where userid='adlog_user'::regrole
            order by total_exec_time desc
            """, stats);
        await using var rows = await summary.ExecuteReaderAsync(ct);
        var overBudget = new List<string>();
        while (await rows.ReadAsync(ct))
        {
            string sql = rows.GetString(0);
            long blocks = rows.GetInt64(1);
            string label = HomeStatement(sql);
            test.TestOutputHelper.WriteLine($"{blocks} read / {rows.GetInt64(2)} hit, {rows.GetDouble(3):F1} ms ({rows.GetInt64(4)} calls) | {label}");
            if (blocks > 2_000) overBudget.Add($"{blocks} blocks: {label}");
        }
        await rows.DisposeAsync();
        foreach (var (sql, parameters, _) in queries.Where(query => overBudget.Any(reason => reason.EndsWith(HomeStatement(query.Sql), StringComparison.Ordinal))))
        {
            await using var explainDb = await database.OpenAsync(ct);
            await PostCollectionPostgres.Sql(explainDb, "set jit=off", ct);
            await using var explain = new NpgsqlCommand("explain(analyze,buffers) select to_jsonb(home_row) from (" + sql + ") home_row", explainDb)
                { CommandTimeout = 0 };
            foreach (var (key, value) in parameters) explain.Parameters.AddWithValue(key, value!);
            await using var plan = await explain.ExecuteReaderAsync(ct);
            while (await plan.ReadAsync(ct)) test.TestOutputHelper.WriteLine(plan.GetString(0));
        }
        Assert.Equal(200, context.Response.StatusCode);
        Assert.Equal(25, payload["problems"]!["items"]!.AsArray().Count);
        Assert.Equal(10, payload["changes"]!["items"]!.AsArray().Count);
        Assert.Contains(payload["changes"]!["items"]!.AsArray(), row => HomeJson.Text(row, "kind") == "gpo");
        Assert.Empty(payload["weak_spots"]!["failed"]!.AsArray());
        Assert.Contains(payload["weak_spots"]!["items"]!.AsArray(), row => HomeJson.Text(row, "report") == "ad.gpo.v2");
        Assert.Equal(1, HomeJson.Number(payload["since_previous_login"], "closed_count"));
        Assert.Empty(overBudget);
        Assert.True(timer.Elapsed < TimeSpan.FromSeconds(2), $"Cold Home took {timer.Elapsed.TotalMilliseconds:F1} ms.");

        // The fixture gives every admitted finding a different cohort and the
        // same severity and timestamp, so the original ordering is by ID.
        await using var legacy = new NpgsqlCommand($"""
            select array_agg(findings.id order by findings.id desc)
            {HomeSummarySql.Population}
            where ({HomeSummarySql.EffectiveStatus}) in ('new','confirmed','repeated','active','review')
              and is_semantic_finding_published_v1(findings.id)
              and (findings.rule_code<>'semantic.qw.file-acl-broad-write' or semantic_finding_in_domains_v265(findings.id,null))
              and not ({Sli.Server.Problems.ProblemRepository.Accepted})
              and not ({Sli.Server.Problems.ProblemRepository.Suppressed})
              and semantic_finding_in_domains_v265(findings.id,array[1::bigint])
            """, stats);
        var legacyIds = Assert.IsType<long[]>(await legacy.ExecuteScalarAsync(ct));
        Assert.Equal(legacyIds.Length, HomeJson.Number(payload["problems"], "open_count"));
        Assert.Equal(legacyIds.Take(25), payload["problems"]!["items"]!.AsArray().Select(row => HomeJson.Number(row, "id")));

        // A partition created after the upgrade must inherit the ordered index.
        await PostCollectionPostgres.Sql(stats, "select create_event_storage_partitions(current_date+32,current_date+32)", ct);
        await using var attached = new NpgsqlCommand("""
            select exists(select 1 from pg_inherits i join pg_index idx on idx.indexrelid=i.inhrelid
                where i.inhparent='event_hot_home_changes424'::regclass
                  and idx.indrelid=to_regclass('event_hot_d'||to_char(current_date+32,'YYYYMMDD')))
            """, stats);
        Assert.Equal(true, await attached.ExecuteScalarAsync(ct));
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
    }

    private static string HomeStatement(string sql)
    {
        if (sql.Contains("with admitted as (", StringComparison.Ordinal)) return "OpenQueue";
        if (sql.Contains("open_findings as materialized", StringComparison.Ordinal)) return "OpenQueueChanges";
        if (sql.Contains("active_operator_count", StringComparison.Ordinal)) return "OperatorContext";
        if (sql.Contains("as closed_count", StringComparison.Ordinal)) return "SincePreviousLogin";
        if (sql.Contains("prior.valid_from_utc as before_at", StringComparison.Ordinal)) return "PasswordPolicyChanges";
        if (sql.Contains("with short_rows as (", StringComparison.Ordinal)) return "AD review events";
        if (sql.Contains("from gpo_report_v2_source_snapshots", StringComparison.Ordinal)) return "GPO weak spots snapshot pair";
        if (sql.Contains("from domains d left join lateral", StringComparison.Ordinal))
            return sql.Contains("users_report_v2_snapshots", StringComparison.Ordinal) ? "AD users snapshot" : "AD computers snapshot";
        return sql.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)[0];
    }

    private static async Task SeedHomeSnapshots(NpgsqlConnection db, DateTimeOffset day, CancellationToken ct)
    {
        var manifest = Guid.NewGuid();
        var computerRun = Guid.NewGuid();
        var users = JsonNode.Parse("""
            {"users":[{"sid":"S-1-5-21-100000001-200000002-300000003-1001","samAccountName":"synthetic-user",
                      "enabled":true,"doesNotRequirePreAuth":true}],"metadata":{"user_count":1}}
            """)!.AsObject();
        var computers = JsonNode.Parse("""
            {"schema_version":"2.0","objects":[{"objectGuid":"10000000-0000-4000-8000-000000000001",
                    "name":"dc01","userAccountControl":524288}],
             "metadata":{"collection_status":"complete","object_count":1}}
            """)!.AsObject();
        computers["metadata"]!["snapshot_id"] = computerRun.ToString();
        await using var command = new NpgsqlCommand("""
            insert into users_report_v2_snapshots(snapshot_id,domain_id,contract_id,scope_json,scope_sha256,bucket_start_utc,
                captured_at_utc,source_observed_at_utc,source_state,user_count,payload_json,payload_sha256)
            values(1,1,'sli.users-report.v2','{}',sha256('{}'::bytea),@day,@day,@day,'complete',1,@users::jsonb,@users_hash);
            insert into computers_v6_source_snapshots(domain_id,snapshot_uuid,source_started_at_utc,source_completed_at_utc,
                captured_at_utc,query_dc,collector_version,collector_sha256,collection_status,base_inventory_status,object_count,
                source_options_json,payload_json,payload_sha256,collector_exit_code)
            values(1,@computer_run,@day,@day,@day,'dc01.example.test','sli-agent/ad-snapshot/1',
                sha256('sli-agent/ad-snapshot/1'::bytea),'complete','observed',1,
                '{"server":"dc01.example.test","search_base":null,"skip_dns":true,"collect_ad_site":false,"collect_exact_last_logon":false}',
                @computers::jsonb,@computers_hash,0);
            insert into ad_snapshot_manifests(manifest_id,domain_id,domain_sid,domain_dns,slot_start_utc,assembled_at_utc,
                contract_version,coverage_state,manifest_sha256)
            values(@manifest,1,'S-1-5-21-100000001-200000002-300000003','example.test',@day,@day,
                'sli.ad-snapshot-manifest/1.0','complete',sha256('synthetic-home'::bytea));
            insert into ad_snapshot_manifest_sources(manifest_id,family,contract_id,source_id,observed_at_utc,source_state,payload_sha256)
            values(@manifest,'users_v2','sli.users-report.v2','1',@day,'complete',@users_hash),
                  (@manifest,'computers_v6','sli.computers-report.v6',@computer_run::text,@day,'complete',@computers_hash);
            """, db);
        command.Parameters.AddWithValue("day", day);
        command.Parameters.AddWithValue("manifest", manifest);
        command.Parameters.AddWithValue("computer_run", computerRun);
        command.Parameters.AddWithValue("users", users.ToJsonString());
        command.Parameters.AddWithValue("users_hash", Convert.FromHexString(AdJobPlugin.Digest(users)));
        command.Parameters.AddWithValue("computers", computers.ToJsonString());
        command.Parameters.AddWithValue("computers_hash", Convert.FromHexString(AdJobPlugin.Digest(computers)));
        await command.ExecuteNonQueryAsync(ct);

        var policy = JsonNode.Parse("""
            {"schema_version":"sli.ad-gpo.snapshot/1.0","collector_version":"synthetic-gpo","demo":false,
             "collection_status":"complete","domain":{},"scope":{},"source_states":{
               "gpo_list":{"status":"observed"},"gpo_reports":{"status":"observed"},"gpc_directory":{"status":"observed"},
               "sysvol_gpt":{"status":"observed"},"links":{"status":"observed"},"permissions":{"status":"observed"},
               "wmi_filters":{"status":"observed"}},
             "gpos":[{"id":"synthetic-policy","guid":"10000000-0000-4000-8000-000000000002","display_name":"Synthetic policy",
                      "computer":{"directory_version":12,"sysvol_version":11},
                      "source_states":{"report":{"status":"observed"},"sysvol_gpt":{"status":"observed"}}}],
             "settings":[],"scopes":[],"links":[],"permissions":[],"wmi_filters":[],"unresolved_links":[],"collection_errors":[]}
            """)!.AsObject();
        string stamp = HomeWindow.Iso(day);
        policy["started_at"] = stamp;
        policy["completed_at"] = stamp;
        policy["observed_at"] = stamp;
        var currentRun = Guid.NewGuid();
        var previousRun = Guid.NewGuid();
        var previousManifest = Guid.NewGuid();
        var previous = (JsonObject)policy.DeepClone();
        string before = "Prior synthetic policy";
        string after = "Synthetic policy";
        string priorStamp = HomeWindow.Iso(day.AddDays(-1));
        previous["started_at"] = priorStamp;
        previous["completed_at"] = priorStamp;
        previous["observed_at"] = priorStamp;
        previous["gpos"]![0]!["display_name"] = before;
        await using var tx = await db.BeginTransactionAsync(ct);
        await GpoSnapshotStore.StoreAndVerifyAsync(db, tx, 1, previousRun, previous, true, ct);
        await GpoSnapshotStore.StoreAndVerifyAsync(db, tx, 1, currentRun, policy, true, ct);
        string batch = new('a', 64);
        var change = HomeJson.Object(new
        {
            object_type = "gpo", object_id = "synthetic-policy",
            kind = "attribute_changed", field = "display_name",
            before_sha256 = GpoJson.Hash(JsonValue.Create(before)), after_sha256 = GpoJson.Hash(JsonValue.Create(after))
        });
        string record = GpoJson.Hash(new JsonArray(batch, change.DeepClone()));
        string serialized = LifecycleJson.Canonical(change);
        await SnapshotChangeStore.WriteAsync(db, tx, manifest, batch, 1, "gpo_v2", day.UtcDateTime,
            [HomeJson.Object(new { record_id = record, payload_json = serialized })], [(before, after)], [], null, null, ct);
        await using var history = new NpgsqlCommand("""
            insert into ad_snapshot_manifests(manifest_id,domain_id,domain_sid,domain_dns,slot_start_utc,assembled_at_utc,
                contract_version,coverage_state,manifest_sha256)
            select @previous_manifest,domain_id,domain_sid,domain_dns,slot_start_utc-interval '1 day',assembled_at_utc-interval '1 day',
                contract_version,coverage_state,sha256('synthetic-home-prior'::bytea)
            from ad_snapshot_manifests where manifest_id=@manifest;
            insert into ad_snapshot_manifest_sources(manifest_id,family,contract_id,source_id,observed_at_utc,source_state,payload_sha256)
            select case when source_run_id=@current_run then @manifest else @previous_manifest end,
                'gpo_v2',schema_version,source_run_id::text,source_observed_at_utc,'complete',payload_sha256
            from gpo_report_v2_source_snapshots where source_run_id in (@current_run,@previous_run);
            insert into ad_snapshot_history_confirmations(manifest_id,family,domain_id,previous_manifest_id,source_sha256,
                previous_sha256,batch_id,records_sha256,record_count,observed_at,coverage_state)
            select @manifest,'gpo_v2',1,@previous_manifest,encode(cur.payload_sha256,'hex'),encode(prev.payload_sha256,'hex'),
                @batch,@digest,1,@day,'complete'
            from gpo_report_v2_source_snapshots cur cross join gpo_report_v2_source_snapshots prev
            where cur.source_run_id=@current_run and prev.source_run_id=@previous_run;
            """, db, tx);
        history.Parameters.AddWithValue("manifest", manifest);
        history.Parameters.AddWithValue("previous_manifest", previousManifest);
        history.Parameters.AddWithValue("current_run", currentRun);
        history.Parameters.AddWithValue("previous_run", previousRun);
        history.Parameters.AddWithValue("batch", batch);
        history.Parameters.AddWithValue("digest", GpoJson.Hash(new JsonArray(new JsonArray(record, serialized))));
        history.Parameters.AddWithValue("day", day);
        await history.ExecuteNonQueryAsync(ct);
        await tx.CommitAsync(ct);
    }

    private const string ColdHomeSeed = """
        insert into servers(id,domain_id,hostname,fqdn,role)
        values(900001,1,'dc01','dc01.example.test','domain_controller');
        select create_event_storage_partitions(@day::date,@day::date);
        insert into event_hot(event_id,time_created_utc,event_kind,domain_id,actor,target,computer,method,outcome,fields)
        select n,@day+n*interval '0.17 seconds',
            case when n<=20 then 4720 when n%1000=0 then 4624 else 4625 end,1,
            'S-1-5-21-100000001-200000002-300000003-1001','synthetic-target','dc01.example.test',
            '{"$server_id":900001,"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing"}',
            '{}',jsonb_build_object('synthetic_padding',repeat(md5(n::text),12))
        from generate_series(1,500000) n;
        insert into findings(id,fingerprint,rule_code,title,status,severity,source,actor,target,evidence_count,first_seen_utc,last_seen_utc,created_at,closed_at)
        select n,'semantic:'||encode(sha256(('load-finding-'||n)::bytea),'hex'),
            'semantic.qw.privileged-group-addition','Synthetic finding',case when n=30 then 'closed' else 'new' end,'high',
            'synthetic','synthetic-actor','object-'||n,1,@day::text,@day::text,@day,
            case when n=30 then (@day+interval '1 hour')::text end
        from generate_series(1,212) n;
        update auth_users set previous_login_at=@day-interval '1 hour' where id=1;
        insert into finding_event_copies337(finding_id,event_id,time_created_utc,event_kind,domain_id,actor,computer,method,outcome,fields,source_sha256,evidence_role)
        select case when n=20 then 1 else n%212+1 end,n,@day+n*interval '0.17 seconds',
            case when n=20 then 4720 else 4625 end,1,'synthetic-actor','dc01.example.test',
            '{"$server_id":900001,"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing"}',
            '{}',jsonb_build_object('synthetic_padding',repeat(md5(n::text),12)),sha256(n::text::bytea),'primary'
        from generate_series(20,200019) n;
        insert into semantic_security_scenarios(scenario_id,scenario_kind,result_class,identity_key,scenario_key,partition_key,strict_keys_json,merge_window_seconds,title,explanation,first_seen_utc,last_seen_utc,risk_class)
        select md5('load-scenario-'||n)::uuid,'synthetic','control_gap',sha256(('load-identity-'||n)::bytea),
            sha256(('load-scenario-'||n)::bytea),'synthetic','{}',300,'Synthetic scenario','Synthetic load',@day,@day,'low'
        from generate_series(1,30) n;
        insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
        values('synthetic-load',1,'control_health','disabled','{}',sha256('{}'::bytea));
        insert into semantic_control_health_observations(observation_id,observation_key,control_id,partition_key,coverage_status,reason,observed_at_utc,source_reference)
        select md5('load-observation-'||n)::uuid,sha256(('load-observation-'||n)::bytea),'synthetic','synthetic','unknown','Synthetic load',@day,'synthetic-'||n
        from generate_series(1,30) n;
        insert into semantic_risk_evaluation_jobs(job_id,policy_id,policy_version,source_kind,control_health_id,source_reference,evaluation_mode,idempotency_key,evaluation_status,completed_at)
        select md5('load-evaluation-'||n)::uuid,'synthetic-load',1,'control_health',md5('load-observation-'||n)::uuid,
            md5('load-observation-'||n)::uuid::text,'enabled',sha256(('load-evaluation-'||n)::bytea),'completed',@day
        from generate_series(1,30) n;
        insert into semantic_risk_evaluation_results(job_id,scenario_id,evaluation_mode,risk_class,raw_score,display_score,hard_critical,confidence,confidence_score,coverage_status,evaluation_ms)
        select md5('load-evaluation-'||n)::uuid,md5('load-scenario-'||n)::uuid,'enabled','low',1,1,false,'low',1,'unknown',1
        from generate_series(1,30) n;
        insert into semantic_finding_publications(scenario_id,finding_id,first_job_id,finding_fingerprint,published_evidence_count)
        select md5('load-scenario-'||n)::uuid,n,md5('load-evaluation-'||n)::uuid,'semantic:'||encode(sha256(('load-finding-'||n)::bytea),'hex'),1
        from generate_series(1,30) n;
        insert into storage_v2_entity_type(value) values('ad_user'),('password_policy') on conflict(value) do nothing;
        insert into entities_v2(entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
        select t.id,'synthetic-'||n,'synthetic-'||n,1,sha256(n::text::bytea)
        from storage_v2_entity_type t cross join generate_series(1,90000) n where t.value='ad_user';
        insert into storage_v2_entity_type(value) values('ad_computer') on conflict(value) do nothing;
        insert into entities_v2(entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
        select id,'home-'||value,'Synthetic '||value,1,sha256(value::bytea)
        from storage_v2_entity_type where value in ('ad_computer','password_policy');
        insert into ad_context_runs(run_id,source_pack_id,source_pack_version,domain_id,mode,observed_at_utc,bundle_sha256,status)
        values('10000000-0000-4000-8000-000000000010','sli.ad','1',1,'full',@day-interval '1 day',sha256('prior'::bytea),'completed'),
              ('10000000-0000-4000-8000-000000000011','sli.ad','1',1,'full',@day+interval '1 hour',sha256('current'::bytea),'completed');
        insert into ad_context_sections(run_id,section_name,status,record_count)
        select run_id,'domain_posture','complete',1 from ad_context_runs
        where run_id in ('10000000-0000-4000-8000-000000000010','10000000-0000-4000-8000-000000000011');
        insert into ad_context_sections(run_id,section_name,status,record_count)
        values('10000000-0000-4000-8000-000000000011','domain_health','complete',1);
        insert into ad_context_entity_versions(entity_id,source_section,valid_from_utc,valid_to_utc,last_observed_at_utc,
            content_sha256,attributes_json,source_run_id)
        select entity.id,'domain_posture',run.observed_at_utc,
            case when run.observed_at_utc<@day then @day+interval '1 hour' end,run.observed_at_utc,
            run.bundle_sha256,jsonb_build_object('attributes',
                jsonb_build_object('password_min_length',case when run.observed_at_utc<@day then 14 else 16 end)),run.run_id
        from entities_v2 entity cross join ad_context_runs run where entity.natural_key='home-password_policy'
          and run.run_id in ('10000000-0000-4000-8000-000000000010','10000000-0000-4000-8000-000000000011');
        insert into ad_context_entity_versions(entity_id,source_section,valid_from_utc,last_observed_at_utc,
            content_sha256,attributes_json,source_run_id)
        select id,'domain_health',@day,@day,source_core_sha256,
            '{"attributes":{"infrastructure_role":"domain_controller","dns_state":"failed"}}',
            '10000000-0000-4000-8000-000000000011'
        from entities_v2 where natural_key='home-ad_computer';
        insert into ad_context_entity_versions(entity_id,source_section,valid_from_utc,last_observed_at_utc,
            content_sha256,attributes_json,source_run_id)
        select id,'directory_accounts',@day,@day,source_core_sha256,
            '{"attributes":{"enabled":true}}','10000000-0000-4000-8000-000000000011'
        from entities_v2 where natural_key like 'synthetic-%' order by id limit 660;
        analyze;
        """;
}
