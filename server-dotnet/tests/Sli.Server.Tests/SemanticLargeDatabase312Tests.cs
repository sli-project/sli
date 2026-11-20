using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Consumer;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests;

public sealed partial class SemanticLargeDatabaseTests
{
    [Fact]
    public async Task Schema312_preserves_generation_values_errors_and_retained_principal_bindings()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 311);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, """
            insert into sli_agents(id,host_id,key_fingerprint,assigned_modules)
                values(md5('edge-agent')::uuid,md5('edge-host')::uuid,repeat('c',64),
                '[{"module_id":"sli.workstations","enabled":true,"config":{}}]');
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                values(md5('edge-agent')::uuid,'sli.workstations',1,md5('edge-packet')::uuid,repeat('c',64),
                jsonb_build_object('source_instance_id',md5('edge-host')::uuid::text,'generation','receipt-only'),'{"status":"committed"}');
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
                select packet_id,envelope,'{"contract":"sli.collection-packet.v1"}','[]',now() from sli_agent_receipts;
            -- The only valid witness is older than 128 newer receipts.
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                select md5('edge-agent')::uuid,'sli.workstations',n,md5('edge-packet:'||n)::uuid,repeat('c',64),
                    '{"source_instance_id":"wrong-source","generation":"newer"}','{"status":"committed"}'
                    from generate_series(2,301) n;
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
                select packet_id,envelope,'{"contract":"sli.collection-packet.v1"}','[]',now() from sli_agent_receipts where sequence>1;
            insert into sli_plugin_workstations.observations(id,agent_key,entity_id,family,event_id,observed_at,observation,observation_sha256,source_xml)
                select encode(sha256(('edge:'||n)::bytea),'hex'),md5('edge-agent')::uuid::text,1,'logons',4624,
                    now()-interval '10 years',jsonb_build_object('generation',g),repeat('c',64),'<Event/>'
                from (values(1,'"A"'::jsonb),(2,'"a"'),(3,'"old"'),(4,'"old"'),(5,'42'),(6,'true'),(7,'{"v":1}')) v(n,g);
            insert into finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
                source_instance_id,source_generation,collection_scope_id,storage_kind,agent_key)
                select case when n=3 then 'adlog_storage_owner'::regrole else 'sli_semantic_login'::regrole end,
                    case when n=2 then 'foreign-name' else 'sli_semantic_login' end,installation_id,'sli.workstations',
                    md5('edge-host')::uuid::text,'retained:'||n,'','workstation_observation',md5('edge-agent')::uuid::text
                    from semantic_default_installation cross join generate_series(1,3) n;
            """, ct);
        async Task<string> DiscoverEdges() {
            await using var tx = await db.BeginTransactionAsync(ct);
            await PostCollectionPostgres.Sql(db, "set session authorization sli_semantic_login; set role adlog_semantic_worker; set local statement_timeout='30s'", ct);
            await using var query = new NpgsqlCommand("select jsonb_agg(source order by source::text)::text from public.t109_detection_sources()", db);
            string result = (string)(await query.ExecuteScalarAsync(ct))!;
            await PostCollectionPostgres.Sql(db, "reset role; reset session authorization", ct);
            await tx.RollbackAsync(ct);
            return result;
        }
        async Task InvalidGenerations() {
            // Catch inside PostgreSQL: expected data errors never enter the SQL error log.
            foreach (string invalid in new[] { "{}", "{\"generation\":null}", "{\"generation\":\"\"}",
                new JsonObject { ["generation"] = new string('x', 513) }.ToJsonString() }) {
                await using (var change = new NpgsqlCommand("update sli_plugin_workstations.observations set observation=@value::jsonb where id=repeat('d',64)", db)) {
                    change.Parameters.AddWithValue("value", invalid); await change.ExecuteNonQueryAsync(ct);
                }
                await PostCollectionPostgres.Sql(db, """
                    set session authorization sli_semantic_login; set role adlog_semantic_worker;
                    do $$ begin
                        begin perform * from public.t109_detection_sources();
                            raise exception 'invalid_generation_was_accepted';
                        exception when not_null_violation or check_violation then null; end;
                    end $$;
                    reset role; reset session authorization;
                    """, ct);
            }
        }
        string expected = await DiscoverEdges();
        Assert.Equal(7, JsonNode.Parse(expected)!.AsArray().Count);
        Assert.DoesNotContain("retained:2", expected); Assert.DoesNotContain("retained:3", expected);
        await PostCollectionPostgres.Sql(db, """
            insert into sli_plugin_workstations.observations(id,agent_key,entity_id,family,event_id,observed_at,observation,observation_sha256,source_xml)
                values(repeat('d',64),md5('edge-agent')::uuid::text,1,'usb',4624,now(),'{}',repeat('d',64),'<Event/>')
            """, ct);
        await InvalidGenerations();
        await fixture.Pg.ApplyFileAsync(Path.Combine(SqlPostgresFixture.Repository(), "config/postgres_migrations/312_semantic_workstation_discovery.sql"), null, ct);
        await InvalidGenerations();
        await PostCollectionPostgres.Sql(db, "delete from sli_plugin_workstations.observations where id=repeat('d',64)", ct);
        Assert.Equal(expected, await DiscoverEdges());
        // A retained binding is still returned when current receipt witnesses disappear.
        await PostCollectionPostgres.Sql(db, "update sli_agent_packet_inbox set imported_at=null", ct);
        Assert.Single(JsonNode.Parse(await DiscoverEdges())!.AsArray());
        await PostCollectionPostgres.Sql(db, "update sli_agents set assigned_modules='[]'", ct);
        await using (var worker = new NpgsqlConnection(fixture.Dsn("sli_semantic_login"))) {
            await worker.OpenAsync(ct);
            await PostCollectionPostgres.Sql(worker, "set role adlog_semantic_worker", ct);
            await using var count = new NpgsqlCommand("select count(*) from public.t109_detection_sources()", worker);
            Assert.Equal(0L, await count.ExecuteScalarAsync(ct));
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Schema311_accepts312_with_exact_workstation_generations_and_bounded_probes()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 311);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        string directory = Path.Combine(SqlPostgresFixture.Repository(), "config/postgres_migrations");
        string forward = Path.Combine(directory, "312_semantic_workstation_discovery.sql");
        string rollback = Path.Combine(directory, "312_semantic_workstation_discovery.rollback.sql");
        async Task<string> Scalar(string sql) {
            await using var command = new NpgsqlCommand(sql, db) { CommandTimeout = 300 };
            return (string)(await command.ExecuteScalarAsync(ct))!;
        }
        async Task Seed(string sql) {
            await using var command = new NpgsqlCommand(sql, db) { CommandTimeout = 600 };
            await command.ExecuteNonQueryAsync(ct);
        }
        const string authoritySql = "select jsonb_build_object('oid',oid,'owner',proowner,'acl',proacl::text,'definer',prosecdef,'config',proconfig)::text from pg_proc where oid='public.t109_detection_sources()'::regprocedure";
        string authority = await Scalar(authoritySql);
        string oldDefinition = await Scalar("select pg_get_functiondef('public.t109_detection_sources()'::regprocedure)");
        await Seed("""
            insert into sli_agents(id,host_id,key_fingerprint,assigned_modules)
            select md5('ws-agent:'||n)::uuid,md5('ws-host:'||n)::uuid,md5(n::text)||md5(n::text),
                jsonb_build_array(jsonb_build_object('module_id','sli.workstations','enabled',n<>4,'config','{}'::jsonb))
                from generate_series(1,11) n;
            update sli_agents set status='disabled' where id=md5('ws-agent:3')::uuid;
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            select md5('ws-agent:'||case when n<=499980 or n>499991 then 1 else n-499980 end)::uuid,
                case when n=499990 then 'sli.vpn-nps' else 'sli.workstations' end,n,md5('ws-packet:'||n)::uuid,repeat('a',64),
                jsonb_build_object('source_instance_id',case when n=499989 then 'wrong-host' else
                    md5('ws-host:'||case when n<=499980 or n>499991 then 1 else n-499980 end)::uuid::text end,
                    'generation',case when n=499981 then 'receipt-only' else 'current' end),
                case when n=499986 then '{}'::jsonb else '{"status":"committed"}'::jsonb end
                from generate_series(1,500000) n;
            """);
        // Commit inbox batches with the actual stream-health trigger enabled.
        for (int lower = 0; lower < 500000; lower += 1000) {
            await using var batch = new NpgsqlCommand("""
                insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
                select packet_id,case when sequence=499987 then envelope||'{"mismatch":true}'::jsonb else envelope end,
                    '{"contract":"sli.collection-packet.v1","header":{"channel":"Security"}}'::jsonb,
                    '[]'::jsonb,case when sequence=499988 then null else now() end
                    from sli_agent_receipts where sequence>@lower and sequence<=@upper and sequence<>499985
                """, db) { CommandTimeout = 120 };
            batch.Parameters.AddWithValue("lower", lower); batch.Parameters.AddWithValue("upper", lower + 1000);
            await batch.ExecuteNonQueryAsync(ct);
        }
        output.WriteLine("seeded 500000 receipts, 499999 inboxes");
        // Real observation constraints and projection triggers remain enabled.
        // An old observation-only generation proves receipts cannot supply DISTINCT.
        for (int lower = 0; lower < 2000000; lower += 10000) {
            await using var batch = new NpgsqlCommand("""
                insert into sli_plugin_workstations.observations(id,agent_key,entity_id,family,event_id,
                    observed_at,observation,observation_sha256,source_xml)
                select encode(sha256(('ws-observation:'||n)::bytea),'hex'),
                    md5('ws-agent:'||case when n%2=0 then 1 else 2 end)::uuid::text,1,
                    case n%4 when 0 then 'processes' when 1 then 'logons' when 2 then 'protection' else 'usb' end,
                    4624,now()-interval '4 years',jsonb_build_object('generation',
                        case when n<=2 then 'observation-only-old' else 'current' end,'facts','{}'::jsonb),
                    repeat('a',64),'<Event>'||repeat('synthetic',256)||'</Event>'
                    from generate_series(@lower+1,@upper) n
                """, db) { CommandTimeout = 600 };
            batch.Parameters.AddWithValue("lower", lower); batch.Parameters.AddWithValue("upper", lower + 10000);
            await batch.ExecuteNonQueryAsync(ct);
        }
        await Seed("""
            insert into sli_plugin_workstations.observations(id,agent_key,entity_id,family,event_id,
                observed_at,observation,observation_sha256,source_xml)
            select encode(sha256(('rejected-observation:'||n)::bytea),'hex'),md5('ws-agent:'||n)::uuid::text,1,
                'logons',4624,now(),'{"generation":"rejected"}'::jsonb,repeat('b',64),'<Event/>'
                from generate_series(3,10) n;
            """);
        output.WriteLine("seeded 2000008 observations");
        // Bulk seed makes autovacuum eligible. Blocking ANALYZE/DDL can cancel
        // that worker and put ERROR in the strict SQL log. Finish maintenance
        // without queuing a conflicting lock; keep autovacuum and log checks on.
        foreach (string table in new[] { "sli_agents", "sli_agent_receipts", "sli_agent_packet_inbox", "sli_plugin_workstations.observations" }) {
            bool completed = false;
            var maintenanceWatch = Stopwatch.StartNew();
            while (maintenanceWatch.Elapsed < TimeSpan.FromMinutes(5)) {
                bool skipped = false;
                void Notice(object? sender, NpgsqlNoticeEventArgs args) => skipped = true;
                db.Notice += Notice;
                try {
                    await using var vacuum = new NpgsqlCommand("vacuum (analyze, skip_locked) " + table, db) { CommandTimeout = 300 };
                    await vacuum.ExecuteNonQueryAsync(ct);
                } finally { db.Notice -= Notice; }
                if (!skipped) { completed = true; break; }
                await Task.Delay(100, ct);
            }
            Assert.True(completed, "seed maintenance did not finish: " + table);
        }
        async Task<(string Sources, string Bindings, string Channels)> Discover(bool bounded) {
            await using var tx = await db.BeginTransactionAsync(ct);
            await PostCollectionPostgres.Sql(db, "set session authorization sli_semantic_login; set role adlog_semantic_worker; set local statement_timeout='" + (bounded ? "30s" : "300s") + "'", ct);
            var watch = Stopwatch.StartNew();
            string sources = await Scalar("select coalesce(jsonb_agg(source order by source::text),'[]')::text from public.t109_detection_sources()");
            output.WriteLine($"t109 ({(bounded ? "312" : "311")}): {watch.Elapsed.TotalMilliseconds:F0} ms");
            if (bounded) Assert.True(watch.Elapsed < TimeSpan.FromSeconds(30));
            await PostCollectionPostgres.Sql(db, "reset role; reset session authorization", ct);
            string bindings = await Scalar("select coalesce(jsonb_agg(to_jsonb(b) order by source_instance_id,source_generation),'[]')::text from finding_evidence_source_bindings b");
            string channels = await Scalar("select coalesce(jsonb_agg(to_jsonb(c) order by source_instance_id,source_generation),'[]')::text from semantic_t109_channels c");
            await tx.RollbackAsync(ct);
            return (sources, bindings, channels);
        }
        var expected = await Discover(false);
        var sources = JsonNode.Parse(expected.Sources)!.AsArray();
        Assert.Equal(4, sources.Count);
        Assert.Equal(2, sources.Count(s => s!["scope"]!["source_generation"]!.ToString() == "observation-only-old"));
        Assert.DoesNotContain(sources, s => s!["scope"]!["source_generation"]!.ToString() == "receipt-only");
        output.WriteLine("observation table bytes: " + await Scalar("select pg_table_size('sli_plugin_workstations.observations')::text"));

        // Compare the actual importer on the same large database and packet set.
        // Each run rolls back receipts, observations, projections and inbox marks.
        // The current inbox selector also reads the nullable terminal marker
        // introduced in 363. Add that column on both sides of this 312 comparison.
        await PostCollectionPostgres.Sql(db,
            "alter table public.sli_agent_packet_inbox add column module_disabled_at timestamptz", ct);
        Guid importAgent = Guid.NewGuid(), importHost = Guid.NewGuid();
        Guid[] importPackets = Enumerable.Range(0, 128).Select(_ => Guid.NewGuid()).ToArray();
        async Task<string> ImportBatch(string version) {
            await using var tx = await db.BeginTransactionAsync(ct);
            await PostCollectionPostgres.Sql(db, "set local role adlog_user; set local statement_timeout='30s'", ct);
            await using (var agent = new NpgsqlCommand("insert into sli_agents(id,host_id,key_fingerprint,assigned_modules) values(@agent,@host,repeat('e',64),'[{\"module_id\":\"sli.workstations\",\"enabled\":true}]')", db, tx)) {
                agent.Parameters.AddWithValue("agent", importAgent); agent.Parameters.AddWithValue("host", importHost);
                await agent.ExecuteNonQueryAsync(ct);
            }
            var sample = JsonNode.Parse(File.ReadAllText(Path.Combine(SqlPostgresFixture.Repository(), "server-dotnet/tests/Sli.Server.Tests/Agents/M4/workstation-process.json")))![0]!["packet"]!;
            var stamp = new DateTime(2100, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            for (int n = 0; n < importPackets.Length; n++) {
                var packet = sample.DeepClone().AsObject();
                packet["header"]!["source"] = importHost.ToString("D");
                packet["header"]!["generation"] = importPackets[n].ToString("D");
                foreach (var record in packet["records"]!.AsArray()) record!["payload"]!["computer_name"] = importHost.ToString("D");
                var rows = new JsonArray(packet["records"]!.AsArray().Select(r => r!["payload"]!.DeepClone()).ToArray());
                var envelope = new JsonObject { ["agent_id"] = importAgent.ToString("D"), ["packet_id"] = importPackets[n].ToString("D"),
                    ["module_id"] = "sli.workstations", ["source_instance_id"] = importHost.ToString("D"), ["payload_sha256"] = Packets.Digest(packet) };
                await using var insert = new NpgsqlCommand("""
                    insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                    values(@agent,'sli.workstations',@sequence,@packet,@hash,@envelope,'{"status":"committed"}');
                    insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at)
                    values(@packet,@envelope,@payload,@rows,@stamp)
                    """, db, tx);
                insert.Parameters.AddWithValue("agent", importAgent); insert.Parameters.AddWithValue("sequence", (long)n + 1);
                insert.Parameters.AddWithValue("packet", importPackets[n]); insert.Parameters.AddWithValue("hash", Packets.Digest(envelope));
                insert.Parameters.AddWithValue("envelope", NpgsqlDbType.Jsonb, CanonicalJson.Serialize(envelope));
                insert.Parameters.AddWithValue("payload", NpgsqlDbType.Jsonb, CanonicalJson.Serialize(packet));
                insert.Parameters.AddWithValue("rows", NpgsqlDbType.Jsonb, CanonicalJson.Serialize(rows));
                insert.Parameters.AddWithValue("stamp", stamp.AddSeconds(n));
                await insert.ExecuteNonQueryAsync(ct);
            }
            (DateTime, Guid)? cursor = (stamp.AddDays(-1), Guid.Empty);
            var watch = Stopwatch.StartNew();
            foreach (Guid packet in importPackets) {
                var step = await AgentWorkstationInboxConsumer.ProcessNextAsync(db, tx, cursor, ct);
                Assert.True(step.Scanned); Assert.Equal(packet, step.PacketId); Assert.True(step.Imported, step.PendingReason);
                cursor = (step.Received, step.PacketId);
            }
            output.WriteLine($"import {version}: {importPackets.Length} packets, {watch.Elapsed.TotalMilliseconds:F0} ms");
            await using var verify = new NpgsqlCommand("""
                -- Allocation sequences advance even on rollback; compare the payload
                -- while checking each allocated entity against its observation.
                select count(*)::text||':'||bool_and((observation->>'entity_id')::bigint=entity_id)::text
                    ||':'||md5(jsonb_agg(observation-'entity_id' order by id)::text)
                from sli_plugin_workstations.observations where agent_key=@agent
                """, db, tx);
            verify.Parameters.AddWithValue("agent", importAgent.ToString("D"));
            string result = (string)(await verify.ExecuteScalarAsync(ct))!;
            Assert.False(result.StartsWith("0:", StringComparison.Ordinal));
            Assert.Contains(":true:", result);
            await using var marks = new NpgsqlCommand("select count(*) from sli_agent_packet_inbox where packet_id=any(@packets) and imported_at is not null", db, tx);
            marks.Parameters.AddWithValue("packets", importPackets);
            Assert.Equal((long)importPackets.Length, await marks.ExecuteScalarAsync(ct));
            await tx.RollbackAsync(ct);
            return result;
        }
        string importedBefore = await ImportBatch("311");

        // Observe the migration's actual SHARE lock and a waiting RowExclusiveLock.
        // This DML inserts no rows; normal readers must remain able to read.
        await using var writer = new NpgsqlConnection(fixture.Pg.ConnectionString); await writer.OpenAsync(ct);
        var migrationWatch = Stopwatch.StartNew();
        Task applying = fixture.Pg.ApplyFileAsync(forward, null, ct);
        Task<int>? waitingWrite = null;
        bool shareLock = false, blockedWrite = false;
        await using var write = new NpgsqlCommand("insert into sli_plugin_workstations.observations select * from sli_plugin_workstations.observations where false", writer) { CommandTimeout = 120 };
        while (!applying.IsCompleted) {
            if (await Scalar("select exists(select 1 from pg_locks where relation='sli_plugin_workstations.observations'::regclass and mode='ShareLock' and granted)::text") == "true") {
                shareLock = true;
                Assert.Equal("true", await Scalar("select exists(select 1 from sli_plugin_workstations.observations limit 1)::text"));
                waitingWrite ??= write.ExecuteNonQueryAsync(ct);
                blockedWrite |= await Scalar("select exists(select 1 from pg_locks where relation='sli_plugin_workstations.observations'::regclass and mode='RowExclusiveLock' and not granted)::text") == "true";
            }
            await Task.Delay(20, ct);
        }
        await applying;
        if (waitingWrite is not null) await waitingWrite;
        output.WriteLine($"312 build/apply: {migrationWatch.Elapsed.TotalMilliseconds:F0} ms; SHARE={shareLock}; blocked writer={blockedWrite}; index bytes=" + await Scalar("select pg_relation_size('sli_plugin_workstations.workstation_discovery_generation_v312')::text"));
        Assert.True(shareLock); Assert.True(blockedWrite);
        Assert.Equal(authority, await Scalar(authoritySql));
        Assert.Equal(importedBefore, await ImportBatch("312"));
        // Same backend, repeated calls exercise cached PL/pgSQL plans as well.
        for (int repeat = 0; repeat < 7; repeat++) Assert.Equal(expected, await Discover(true));
        string definition = await Scalar("select pg_get_functiondef('public.t109_detection_sources()'::regprocedure)");
        int start = definition.IndexOf("    -- WS XML", StringComparison.Ordinal);
        int end = definition.IndexOf("    return query", start, StringComparison.Ordinal);
        string sql = definition[start..end].Replace("login", "'sli_semantic_login'::regrole")
            .Replace("session_user", "'sli_semantic_login'").Replace("installation,", "(select installation_id from semantic_default_installation),");
        await using (var tx = await db.BeginTransactionAsync(ct)) {
            await PostCollectionPostgres.Sql(db, "set local role adlog_storage_owner", ct);
            string plan = await Scalar("explain(analyze,buffers,format json) " + sql);
            var nodes = PlanNodes(JsonNode.Parse(plan)![0]!["Plan"]!).ToArray();
            var observations = nodes.Where(n => n["Relation Name"]?.ToString() == "observations").ToArray();
            Assert.NotEmpty(observations);
            Assert.All(observations, n => Assert.True(n["Actual Rows"]!.GetValue<double>() * n["Actual Loops"]!.GetValue<double>() < 100, n.ToJsonString()));
            var receipts = nodes.Where(n => n["Relation Name"]?.ToString() == "sli_agent_receipts").ToArray();
            Assert.NotEmpty(receipts);
            Assert.All(receipts, n => {
                Assert.Contains("agent_id", n["Index Cond"]?.ToString() ?? "");
                Assert.True(n["Actual Loops"]!.GetValue<double>() <= 9, n.ToJsonString());
                Assert.True((n["Actual Rows"]!.GetValue<double>() + (n["Rows Removed by Filter"]?.GetValue<double>() ?? 0)) * n["Actual Loops"]!.GetValue<double>() < 100, n.ToJsonString());
            });
            Assert.DoesNotContain(nodes, n => n["Node Type"]?.ToString() is "Sort" or "Merge Join" or "Hash Join");
            Assert.Contains(nodes, n => n["Index Name"]?.ToString() == "workstation_discovery_generation_v312");
            foreach (var n in observations.Concat(receipts)) output.WriteLine($"312 plan: {n["Relation Name"]}, {n["Node Type"]}, rows={n["Actual Rows"]}, loops={n["Actual Loops"]}, condition={n["Index Cond"]}");
            output.WriteLine($"workstation INSERT EXPLAIN: {JsonNode.Parse(plan)![0]!["Execution Time"]} ms");
            await tx.RollbackAsync(ct);
        }
        await fixture.Pg.ApplyFileAsync(rollback, null, ct);
        Assert.Equal(oldDefinition, await Scalar("select pg_get_functiondef('public.t109_detection_sources()'::regprocedure)"));
        Assert.Equal(authority, await Scalar(authoritySql));
        Assert.Equal(expected, await Discover(false));
        await fixture.Pg.ApplyFileAsync(forward, null, ct);
        Assert.Equal(expected, await Discover(true));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
