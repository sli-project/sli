using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests;

public sealed partial class SemanticLargeDatabaseTests
{
    [Fact]
    public async Task Schema310_accepts311_without_receipt_wide_probes_and_preserves_discovery()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 311);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        string directory = Path.Combine(SqlPostgresFixture.Repository(), "config/postgres_migrations");
        string forward = Path.Combine(directory, "311_semantic_inbox_admission.sql");
        string rollback = Path.Combine(directory, "311_semantic_inbox_admission.rollback.sql");
        await fixture.Pg.ApplyFileAsync(rollback, null, ct);
        async Task<string> Scalar(string sql) {
            await using var command = new NpgsqlCommand(sql, db) { CommandTimeout = 120 };
            return (string)(await command.ExecuteScalarAsync(ct))!;
        }
        const string authoritySql = """
            select jsonb_agg(jsonb_build_object('oid',oid,'owner',proowner,'acl',proacl::text,
                'definer',prosecdef,'config',proconfig) order by oid)::text from pg_proc
            where oid in ('public.t109_detection_sources()'::regprocedure,'public.default_detection_sources()'::regprocedure,
                'public.default_detection_sources_before_v301()'::regprocedure,'sli_plugin_workstations.inventory_inputs_v1(bigint)'::regprocedure)
            """;
        string authority = await Scalar(authoritySql);
        string oldDefinition = await Scalar("select pg_get_functiondef('public.t109_detection_sources()'::regprocedure)");
        string oldInventory = await Scalar("select pg_get_functiondef('sli_plugin_workstations.inventory_inputs_v1(bigint)'::regprocedure)");
        string seedSql = """
            insert into servers(id,domain_id,hostname,role,is_active)
                select 900001,id,'dc.example.test','domain_controller',true from domains limit 1;
            insert into log_sources(name) values('Security'),('System'),('Microsoft-Windows-PowerShell/Operational') on conflict do nothing;
            insert into storage_v2_channel(value) values('Security') on conflict do nothing;
            insert into sli_agents(id,host_id,key_fingerprint,assigned_modules)
            select md5('agent:'||n)::uuid,md5('host:'||n)::uuid,md5(n::text)||md5(n::text),
                jsonb_build_array(jsonb_build_object('module_id','sli.windows.ad-dc','enabled',n<>3,
                    'config',jsonb_build_object('channels',jsonb_build_object('Microsoft-Windows-PowerShell/Operational',false))))
            from generate_series(1,3) n;
            update sli_agents set status='disabled' where id=md5('agent:2')::uuid;
            insert into sli_agent_module_bindings(agent_id,module_id,source_instance_id,source_name,channel,module_version,policy_revision)
                select id,'sli.windows.ad-dc','synthetic-dc','dc.example.test','ad-dc','1.0.0','1' from sli_agents;
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            select md5('agent:'||case when n%109=0 then 2 when n%113=0 then 3 else 1 end)::uuid,
                case when n%107=0 then 'sli.vpn-nps' else 'sli.windows.ad-dc' end,n,md5('packet:'||n)::uuid,repeat('a',64),
                jsonb_build_object('source_instance_id','synthetic-dc','generation',
                    case when n<=150000 then 'old-generation' else 'current-generation' end),'  {"status":"committed"}'::jsonb
            from generate_series(1,300000) n;
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
            select packet_id,case when sequence%101=0 then envelope||'{"mismatch":true}'::jsonb else envelope end,
                jsonb_build_object('contract','sli.collection-packet.v1','header',jsonb_build_object('channel',
                    case when sequence%25=0 then 'System' when sequence%25=1 then 'Microsoft-Windows-PowerShell/Operational' else 'Security' end)),
                '[]'::jsonb,case when sequence%103=0 then null else now() end from sli_agent_receipts
                where sequence>@lower and sequence<=@upper;
            insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
            select sequence,900001,(select id from log_sources where name='Security'),
                'agent-packet:'||packet_id,'jsonl',md5(packet_id::text) from sli_agent_receipts
            where (sequence%25<2 and sequence%4<2) or sequence>299872;
            insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,channel_id,
                time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
            select raw.id,raw.id,900001,1,(select id from log_sources where name=i.collection_channel),4624,
                (select id from storage_v2_channel where value='Security'),now(),now(),sha256(raw.id::text::bytea),sha256(raw.id::text::bytea),
                (select version from event_catalog_revisions order by id limit 1)
            from raw_log_files raw join sli_agent_packet_inbox i on raw.file_path='agent-packet:'||i.packet_id;
            insert into finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
                source_instance_id,source_generation,collection_scope_id,storage_kind,log_source_id,agent_id)
            select 'sli_semantic_login'::regrole,'sli_semantic_login',installation_id,'sli.windows.ad-dc','synthetic-dc',
                generation,'','core_event',(select id from log_sources where name='Security'),md5('agent:1')::uuid
                from semantic_default_installation cross join (values('old-generation'),('current-generation')) g(generation);
            analyze sli_agents; analyze sli_agent_receipts; analyze sli_agent_packet_inbox;
            analyze raw_log_files; analyze events_v2_core; analyze finding_evidence_source_bindings;
            """;
        int inboxStart = seedSql.IndexOf("insert into sli_agent_packet_inbox", StringComparison.Ordinal);
        int rawStart = seedSql.IndexOf("insert into raw_log_files", StringComparison.Ordinal);
        async Task Seed(string sql) {
            await using var seed = new NpgsqlCommand(sql, db) { CommandTimeout = 120 };
            await seed.ExecuteNonQueryAsync(ct);
        }
        await Seed(seedSql[..inboxStart]);
        // Commit batches so the real stream-health trigger can prune its hot
        // summary rows; one giant INSERT builds a quadratic MVCC update chain.
        for (int lower = 0; lower < 300000; lower += 1000) {
            await using var batch = new NpgsqlCommand(seedSql[inboxStart..rawStart], db) { CommandTimeout = 120 };
            batch.Parameters.AddWithValue("lower", lower); batch.Parameters.AddWithValue("upper", lower + 1000);
            await batch.ExecuteNonQueryAsync(ct);
        }
        await Seed(seedSql[rawStart..]);
        // Each rejected case has its own binding/generation and retained core:
        // valid packets from another generation cannot mask an admission bug.
        await Seed("""
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            select md5('agent:'||case n when 3 then 2 when 4 then 3 else 1 end)::uuid,
                case when n=5 then 'sli.vpn-nps' else 'sli.windows.ad-dc' end,400000+n,md5('rejected:'||n)::uuid,repeat('b',64),
                jsonb_build_object('source_instance_id',case when n=10 then 'wrong-instance' else 'synthetic-dc' end,
                    'generation','rejected:'||n),'{"status":"committed"}'::jsonb from generate_series(1,10) n;
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
            select packet_id,case when sequence=400002 then envelope||'{"mismatch":true}'::jsonb else envelope end,
                jsonb_build_object('contract','sli.collection-packet.v1','header',jsonb_build_object('channel',
                    case sequence when 400006 then 'Microsoft-Windows-PowerShell/Operational' when 400009 then 'Security' else 'System' end)),
                '[]'::jsonb,case when sequence=400001 then null else now() end from sli_agent_receipts where sequence>400000;
            insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
            select sequence,900001,(select id from log_sources where name=case when sequence=400009 then 'Security' else 'System' end),
                'agent-packet:'||packet_id,'jsonl',md5(packet_id::text)
                from sli_agent_receipts where sequence>400000;
            insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,channel_id,
                time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
            select id,id,900001,1,log_source_id,4624,(select id from storage_v2_channel where value='Security'),
                now(),now(),sha256(id::text::bytea),sha256(id::text::bytea),(select version from event_catalog_revisions order by id limit 1)
                from raw_log_files where id>400000;
            insert into finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
                source_instance_id,source_generation,collection_scope_id,storage_kind,log_source_id,agent_id)
            select 'sli_semantic_login'::regrole,case when r.sequence=400007 then 'foreign-principal' else 'sli_semantic_login' end,
                installation_id,case when r.sequence=400008 then 'sli.file-audit' else 'sli.windows.ad-dc' end,
                'synthetic-dc',r.envelope->>'generation',case when r.sequence=400008 then 'foreign-scope' else '' end,
                case when r.sequence=400008 then 'file_audit_observation' else 'core_event' end,
                case when r.sequence<>400008 then (select id from log_sources where name='Security') end,r.agent_id
                from semantic_default_installation cross join sli_agent_receipts r where r.sequence>400000;
            analyze sli_agent_receipts; analyze sli_agent_packet_inbox; analyze finding_evidence_source_bindings;
            """);

        async Task<(string Default, string T109, string Channels)> Discover() {
            await using var tx = await db.BeginTransactionAsync(ct);
            await PostCollectionPostgres.Sql(db, "set session authorization sli_semantic_login; set role adlog_semantic_worker; set local statement_timeout='15s'", ct);
            var watch = Stopwatch.StartNew();
            string defaults = await Scalar("select coalesce(jsonb_agg(source order by source::text),'[]')::text from public.default_detection_sources()");
            double defaultMs = watch.Elapsed.TotalMilliseconds; watch.Restart();
            string t109 = await Scalar("select coalesce(jsonb_agg(source order by source::text),'[]')::text from public.t109_detection_sources()");
            output.WriteLine($"discovery default: {defaultMs:F0} ms; t109: {watch.Elapsed.TotalMilliseconds:F0} ms");
            await PostCollectionPostgres.Sql(db, "reset role; reset session authorization", ct);
            string channels = await Scalar("select coalesce(jsonb_agg(to_jsonb(c) order by source_generation,native_channel,log_source_id),'[]')::text from semantic_t109_channels c");
            await tx.RollbackAsync(ct);
            return (defaults, t109, channels);
        }
        var expected = await Discover();
        Assert.NotEmpty(JsonNode.Parse(expected.Default)!.AsArray());
        var admitted = JsonNode.Parse(expected.Channels)!.AsArray();
        Assert.Equal(2, admitted.Count);
        Assert.All(admitted, c => Assert.Equal("System", c!["native_channel"]!.ToString()));
        Assert.Contains(admitted, c => c!["source_generation"]!.ToString() == "old-generation");

        await fixture.Pg.ApplyFileAsync(forward, null, ct);
        Assert.Equal(authority, await Scalar(authoritySql));
        // Repeated calls also exercise PL/pgSQL cached plans on the same backend.
        for (int repeat = 0; repeat < 3; repeat++) Assert.Equal(expected, await Discover());
        Assert.Equal("true", await Scalar("select (to_regclass('public.semantic_receipt_stream_v310') is null and to_regclass('public.semantic_native_inbox_v310') is not null)::text"));

        // Explain the actual INSERT extracted from the function, under its real principal.
        // Reintroducing a receipt-first join fails on work performed, not wall-clock noise.
        string definition = await Scalar("select pg_get_functiondef('public.t109_detection_sources()'::regprocedure)");
        int start = definition.IndexOf("    with ", StringComparison.Ordinal);
        int end = definition.IndexOf("    -- WS XML", start, StringComparison.Ordinal);
        string sql = definition[start..end].Replace("b.principal_oid=login", "b.principal_oid='sli_semantic_login'::regrole")
            .Replace("select distinct login,", "select distinct 'sli_semantic_login'::regrole,").Replace("session_user", "'sli_semantic_login'");
        await using (var tx = await db.BeginTransactionAsync(ct)) {
            await PostCollectionPostgres.Sql(db, "set role adlog_storage_owner", ct);
            string plan = await Scalar("explain(analyze,buffers,format json) " + sql);
            var nodes = PlanNodes(JsonNode.Parse(plan)![0]!["Plan"]!);
            var receipts = nodes.Where(n => n["Relation Name"]?.ToString() == "sli_agent_receipts").ToArray();
            Assert.NotEmpty(receipts);
            Assert.All(receipts, n => Assert.True(n["Actual Rows"]!.GetValue<double>() * n["Actual Loops"]!.GetValue<double>() <= 24000, n.ToJsonString()));
            Assert.All(receipts, n => Assert.True(n["Actual Loops"]!.GetValue<double>() <= 24000, n.ToJsonString()));
            Assert.All(receipts, n => Assert.Contains("packet_id", n["Index Cond"]?.ToString() ?? ""));
            Assert.Contains(nodes, n => n["Index Name"]?.ToString() == "semantic_native_inbox_v310");
            foreach (var n in receipts) output.WriteLine($"receipt plan: {n["Node Type"]}, rows={n["Actual Rows"]}, loops={n["Actual Loops"]}");
            output.WriteLine($"admission EXPLAIN: {JsonNode.Parse(plan)![0]!["Execution Time"]} ms");
            await tx.RollbackAsync(ct);
        }

        // Active status is checked anew after cached plans. Channel settings
        // are covered by the separate rejected PowerShell generation above.
        await Seed("update sli_agents set status='disabled' where id=md5('agent:1')::uuid");
        Assert.Empty(JsonNode.Parse((await Discover()).Channels)!.AsArray());
        await Seed("update sli_agents set status='active' where id=md5('agent:1')::uuid");
        Assert.Equal(expected, await Discover());

        await fixture.Pg.ApplyFileAsync(rollback, null, ct);
        Assert.Equal(oldDefinition, await Scalar("select pg_get_functiondef('public.t109_detection_sources()'::regprocedure)"));
        Assert.Equal(oldInventory, await Scalar("select pg_get_functiondef('sli_plugin_workstations.inventory_inputs_v1(bigint)'::regprocedure)"));
        Assert.Equal(authority, await Scalar(authoritySql));
        Assert.Equal(expected, await Discover());
        await fixture.Pg.ApplyFileAsync(forward, null, ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Schema311_directory_filters_entity_type_before_ordered_limit()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 311);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        string directory = Path.Combine(SqlPostgresFixture.Repository(), "config/postgres_migrations");
        await fixture.Pg.ApplyFileAsync(Path.Combine(directory, "311_semantic_inbox_admission.rollback.sql"), null, ct);
        await PostCollectionPostgres.Sql(db, """
            insert into storage_v2_entity_type(value) values('ad_computer'),('synthetic-other') on conflict do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
            select n,(select id from storage_v2_entity_type where value=case when n>200000 then 'ad_computer' else 'synthetic-other' end),
                'synthetic:'||n,'synthetic',1,sha256(n::text::bytea) from generate_series(1,200010) n;
            analyze entities_v2; analyze storage_v2_entity_type;
            """, ct);
        async Task<string> Scalar(string sql) {
            await using var c = new NpgsqlCommand(sql, db); return (string)(await c.ExecuteScalarAsync(ct))!;
        }
        string expected = await Scalar("select sli_plugin_workstations.inventory_inputs_v1(1)::text");
        Assert.Equal(10, JsonNode.Parse(expected)!["directory"]!.AsArray().Count);
        string unowned = await Scalar("select sli_plugin_workstations.inventory_inputs_v1(0)::text");
        string foreign = await Scalar("select sli_plugin_workstations.inventory_inputs_v1(2)::text");
        await fixture.Pg.ApplyFileAsync(Path.Combine(directory, "311_semantic_inbox_admission.sql"), null, ct);
        var watch = Stopwatch.StartNew();
        for (int repeat = 0; repeat < 7; repeat++) {
            Assert.Equal(expected, await Scalar("select sli_plugin_workstations.inventory_inputs_v1(1)::text"));
            Assert.Equal(unowned, await Scalar("select sli_plugin_workstations.inventory_inputs_v1(0)::text"));
            Assert.Equal(foreign, await Scalar("select sli_plugin_workstations.inventory_inputs_v1(2)::text"));
        }
        output.WriteLine($"inventory 21 calls: {watch.Elapsed.TotalMilliseconds:F0} ms");
        string definition = await Scalar("select pg_get_functiondef('sli_plugin_workstations.inventory_inputs_v1(bigint)'::regprocedure)");
        string sql = definition.Split("$directory_query$")[1].Replace("$1", "@type").Replace("$2", "@domain");
        await using var explain = new NpgsqlCommand("explain(analyze,buffers,format json) " + sql, db);
        explain.Parameters.AddWithValue("type", int.Parse(await Scalar("select id::text from storage_v2_entity_type where value='ad_computer'"), System.Globalization.CultureInfo.InvariantCulture));
        explain.Parameters.AddWithValue("domain", 1L);
        string plan = (string)(await explain.ExecuteScalarAsync(ct))!;
        Assert.True(plan.Contains("inventory_directory_type_v311", StringComparison.Ordinal), plan);
        var entities = PlanNodes(JsonNode.Parse(plan)![0]!["Plan"]!).Where(n => n["Relation Name"]?.ToString() == "entities_v2").ToArray();
        Assert.NotEmpty(entities);
        Assert.All(entities, n => Assert.True((n["Actual Rows"]!.GetValue<double>() + (n["Rows Removed by Filter"]?.GetValue<double>() ?? 0)) * n["Actual Loops"]!.GetValue<double>() <= 10, n.ToJsonString()));
        output.WriteLine($"directory EXPLAIN: {JsonNode.Parse(plan)![0]!["Execution Time"]} ms; entities read: 10");
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    private static IEnumerable<JsonNode> PlanNodes(JsonNode node)
    {
        yield return node;
        foreach (var child in node["Plans"]?.AsArray() ?? [])
            foreach (var descendant in PlanNodes(child!)) yield return descendant;
    }
}


