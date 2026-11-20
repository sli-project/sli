using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests;

public sealed partial class SemanticLargeDatabaseTests
{
    [Fact]
    public async Task Schema324_accepts325_with_identical_workstation_rows_and_bounded_resolver_calls()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 324);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        async Task<string> Scalar(string sql) {
            await using var q = new NpgsqlCommand(sql, db) { CommandTimeout = 0 };
            return (string)(await q.ExecuteScalarAsync(ct))!;
        }
        const string definitionSql = "select pg_get_functiondef('public.read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure)";
        const string catalogSql = "select (to_jsonb(p)-'prosrc')::text from pg_proc p where oid='public.read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure";
        string original = await Scalar(definitionSql), catalog = await Scalar(catalogSql);
        await PostCollectionPostgres.Sql(db, """
            insert into finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
                source_instance_id,source_generation,collection_scope_id,storage_kind,agent_key)
            select 'sli_semantic_login'::regrole,'sli_semantic_login',installation_id,'sli.workstations',
                'synthetic-host','current','','workstation_observation','synthetic-agent' from semantic_default_installation;
            insert into sli_plugin_workstations.observations(id,agent_key,entity_id,family,event_id,observed_at,
                observation,observation_sha256,source_xml)
            select encode(sha256(('325:'||n)::bytea),'hex'),'synthetic-agent',1,'processes',
                case when n%100=0 then (array[4104,1102,4719,7036,7040,7045])[1+(n/100)%6] else 4688 end,
                '2026-11-01'::timestamptz+(n/5)*interval '1 second',
                jsonb_build_object('generation','current','agent_key','synthetic-agent',
                    'source_sha256',case when n>11880 then repeat('0',64) else encode(sha256('<Event/>'::bytea),'hex') end),
                repeat('a',64),'<Event/>' from generate_series(1,12000) n;
            insert into sli_plugin_workstations.observations(id,agent_key,entity_id,family,event_id,observed_at,
                observation,observation_sha256,source_xml)
            select encode(sha256(('325-excluded:'||n)::bytea),'hex'),case when n=1 then 'foreign' else 'synthetic-agent' end,
                1,'processes',case when n=2 then 4624 else 4688 end,
                case when n=3 then '2100-01-01'::timestamptz else '2026-11-01 00:40:00'::timestamptz end,
                jsonb_build_object('generation',case when n=4 then 'old' else 'current' end,'agent_key','synthetic-agent',
                    'source_sha256',encode(sha256('<Event/>'::bytea),'hex')),repeat('a',64),'<Event/>'
                from generate_series(1,4) n;
            analyze sli_plugin_workstations.observations;
            set track_functions='all';
            """, ct);
        string scope = await Scalar("select jsonb_build_object('installation_id',installation_id::text,'plugin_id',plugin_id,'source_instance_id',source_instance_id,'source_generation',source_generation,'collection_scope_id',collection_scope_id)::text from finding_evidence_source_bindings where agent_key='synthetic-agent'");
        async Task<(string Rows, long Calls)> Read(string window = "", string? requestedScope = null) {
            await using var tx = await db.BeginTransactionAsync(ct);
            const string callsSql = "select coalesce(sum(calls),0)::text from pg_stat_xact_user_functions where funcid='public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text)'::regprocedure";
            long priorCalls = long.Parse(await Scalar(callsSql));
            await PostCollectionPostgres.Sql(db, "set session authorization sli_semantic_login;set role adlog_semantic_worker", ct);
            await using var q = new NpgsqlCommand("select coalesce(jsonb_agg(to_jsonb(r)),'[]')::text from public.read_t109_native(@scope::jsonb" + window + ") r", db, tx) { CommandTimeout = 0 };
            q.Parameters.AddWithValue("scope", requestedScope ?? scope);
            string rows = (string)(await q.ExecuteScalarAsync(ct))!;
            await PostCollectionPostgres.Sql(db, "reset role;reset session authorization", ct);
            long calls = long.Parse(await Scalar(callsSql)) - priorCalls;
            await tx.RollbackAsync(ct);
            return (rows, calls);
        }
        async Task Seen(bool foreign = false) {
            await using var q = new NpgsqlCommand("""
                insert into semantic_t109_seen(source_key,native_id,scope_json,storage_kind)
                select repeat(@key,64),encode(sha256(('325:'||n)::bytea),'hex'),@scope::jsonb,'workstation_observation'
                from generate_series(11000,11200) n
                """, db);
            q.Parameters.AddWithValue("key", foreign ? "b" : "a");
            q.Parameters.AddWithValue("scope", foreign ? scope.Replace("current", "other", StringComparison.Ordinal) : scope);
            await q.ExecuteNonQueryAsync(ct);
        }
        await Seen(foreign: true); await Seen();
        await SemanticRuntimePostgresTests.SeedNative(db, ct);
        await Scalar("""
            insert into sli_agents(id,host_id,key_fingerprint,assigned_modules)
            values(md5('325-file-agent')::uuid,md5('325-file-host')::uuid,repeat('e',64),
                '[{"module_id":"sli.file-audit","enabled":true,"config":{"policy_revision":"1","roots":[{"collection_scope_id":"synthetic-root"}]}}]');
            insert into sli_plugin_file_audit.policy_revisions(agent_id,source_instance_id,revision,authored_at,actor_kind,actor_id,policy,policy_sha256)
            values(md5('325-file-agent')::uuid,'synthetic-files',1,now(),'session',1,'{"source_kind":"server"}',repeat('e',64));
            insert into sli_plugin_file_audit.observations(evidence_key,agent_id,source_instance_id,collection_scope_id,channel,provider,
                generation,record_id,event_id,event_version,observed_at,policy_revision,core_evidence_ref,payload_sha256,normalized)
            select encode(sha256(('325-file:'||n)::bytea),'hex'),md5('325-file-agent')::uuid,'synthetic-files','synthetic-root',
                'Security','Microsoft-Windows-Security-Auditing','current',1000000+n,4663,1,'2026-11-01'::timestamptz+n*interval '1 second',
                1,'synthetic',repeat('e',64),jsonb_build_object('evidence_key',encode(sha256(('325-file:'||n)::bytea),'hex'),
                    'payload_sha256',case when n>10900 then repeat('0',64) else repeat('e',64) end)
                from generate_series(1,11020) n;
            insert into sli_plugin_file_audit.actions(action_id,contract_version,agent_id,source_instance_id,collection_scope_id,observed_at,
                object_type,operation,outcome,correlation_state,projection_version)
            select evidence_key,1,agent_id,source_instance_id,collection_scope_id,observed_at,'file','write','success','complete',1
                from sli_plugin_file_audit.observations;
            insert into sli_plugin_file_audit.action_evidence(action_id,core_evidence_ref,evidence_key,role)
                select evidence_key,'synthetic',evidence_key,'primary' from sli_plugin_file_audit.observations;
            insert into finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,source_instance_id,
                source_generation,collection_scope_id,storage_kind,agent_id)
            select 'sli_semantic_login'::regrole,'sli_semantic_login',installation_id,'sli.file-audit','synthetic-files',
                'current','synthetic-root','file_audit_observation',md5('325-file-agent')::uuid from semantic_default_installation;
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            values(md5('325-file-agent')::uuid,'sli.file-audit',1,md5('325-file-packet')::uuid,repeat('e',64),
                jsonb_build_object('agent_id',md5('325-file-agent')::uuid,'source_instance_id','synthetic-files','generation','current'),'{"status":"committed"}');
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
            select packet_id,envelope,'{"contract":"sli.collection-packet.v1","header":{"channel":"Security"}}','[]',now()
                from sli_agent_receipts where packet_id=md5('325-file-packet')::uuid;
            insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
            select 8000001,900001,id,'agent-packet:'||md5('325-file-packet')::uuid,'jsonl',repeat('e',64) from log_sources where name='Security';
            insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,event_record_id,channel_id,provider_id,
                time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
            select 8000000+n,8000001,900001,domain_id,log_source_id,4663,1000000+n,channel_id,provider_id,
                time_created_utc,normalized_at,decode(repeat('e',64),'hex'),decode(repeat('e',64),'hex'),noise_catalog_version
                from events_v2_core cross join generate_series(1,11020) n where id=900002;
            analyze sli_plugin_file_audit.actions;analyze sli_plugin_file_audit.observations;analyze events_v2_core;
            select 'file seeded';
            """);
        string fileScope = await Scalar("select jsonb_build_object('installation_id',installation_id::text,'plugin_id',plugin_id,'source_instance_id',source_instance_id,'source_generation',source_generation,'collection_scope_id',collection_scope_id)::text from finding_evidence_source_bindings where plugin_id='sli.file-audit'");
        const string window = ",'2026-11-01'::timestamptz,'2026-11-02'::timestamptz";
        var before = await Read(); var beforeWindow = await Read(window);
        var fileBefore = await Read(requestedScope: fileScope); var fileWindowBefore = await Read(window, fileScope);
        Assert.Equal(1000, JsonNode.Parse(before.Rows)!.AsArray().Count);
        Assert.Equal(1000, JsonNode.Parse(fileBefore.Rows)!.AsArray().Count);
        Assert.Equal(10001, JsonNode.Parse(fileWindowBefore.Rows)!.AsArray().Count);
        string directory = Path.Combine(SqlPostgresFixture.Repository(), "config/postgres_migrations");
        string forward = Path.Combine(directory, "325_t109_workstation_path.sql");
        await fixture.Pg.ApplyFileAsync(forward, null, ct);
        Assert.Equal(catalog, await Scalar(catalogSql));
        string updated = await Scalar(definitionSql);
        // The core-event path must remain byte-for-byte unchanged.
        Assert.Equal(original.Split("    elsif b.storage_kind='workstation_observation' then")[0].Split("begin\n")[1],
            updated.Split("    elsif b.storage_kind='workstation_observation' then")[0].Split("begin\n")[1]);
        string candidateSql = updated.Split("$candidates$")[1]
            .Replace("$1", "'synthetic-agent'", StringComparison.Ordinal).Replace("$2", "'current'", StringComparison.Ordinal)
            .Replace("$3", "'" + scope + "'::jsonb", StringComparison.Ordinal)
            .Replace("$4", "null::timestamptz", StringComparison.Ordinal).Replace("$5", "null::timestamptz", StringComparison.Ordinal)
            .Replace("$6", "null::timestamptz", StringComparison.Ordinal).Replace("$7", "null::text", StringComparison.Ordinal);
        var plan = JsonNode.Parse(await Scalar("explain(analyze,buffers,format json) " + candidateSql))!;
        var nodes = PlanNodes(plan[0]!["Plan"]!).ToArray();
        var observationScans = nodes.Where(n => n["Relation Name"]?.ToString() == "observations").ToArray();
        Assert.NotEmpty(observationScans);
        Assert.All(observationScans, n => Assert.Equal("t109_workstation_candidates325", n["Index Name"]?.ToString()));
        Assert.Contains(nodes, n => n["Relation Name"]?.ToString() == "semantic_t109_seen" && n["Index Cond"] is not null);
        Assert.DoesNotContain("md5", candidateSql);
        output.WriteLine("325 candidate plan: " + plan.ToJsonString());
        var after = await Read(); var afterWindow = await Read(window);
        Assert.Equal(before.Rows, after.Rows); Assert.Equal(beforeWindow.Rows, afterWindow.Rows);
        Assert.InRange(after.Calls, 1000, 1256); Assert.InRange(afterWindow.Calls, 1000, 1256);
        Assert.True(before.Calls > after.Calls, $"before={before.Calls}, after={after.Calls}");
        output.WriteLine($"325 workstation: rows=1000; resolve before={before.Calls}, after={after.Calls}, window={afterWindow.Calls}");
        var fileAfter = await Read(requestedScope: fileScope); var fileWindowAfter = await Read(window, fileScope);
        Assert.Equal(fileBefore.Rows, fileAfter.Rows); Assert.Equal(fileWindowBefore.Rows, fileWindowAfter.Rows);
        Assert.InRange(fileAfter.Calls, 1000, 1256); Assert.InRange(fileWindowAfter.Calls, 10001, 10257);
        output.WriteLine($"325 file: resolve before={fileBefore.Calls}, after={fileAfter.Calls}; window rows=10001, calls={fileWindowAfter.Calls}");
        await Scalar("update sli_agent_packet_inbox set envelope=envelope||'{\"tampered\":true}'::jsonb where packet_id=md5('325-file-packet')::uuid;select 'tampered'");
        Assert.Empty(JsonNode.Parse((await Read(requestedScope: fileScope)).Rows)!.AsArray());
        // More than a full rejected portion must not starve older valid evidence.
        await Scalar("update sli_plugin_workstations.observations set observation=jsonb_set(observation,'{source_sha256}',to_jsonb(repeat('0',64))) where observed_at>'2026-11-01 00:38:00';select 'changed'");
        Assert.Equal(1000, JsonNode.Parse((await Read()).Rows)!.AsArray().Count);
        // Exhausted and partial portions; exact inclusive window and seen bypass.
        Assert.Empty(JsonNode.Parse((await Read(",'2026-10-01'::timestamptz,'2026-10-02'::timestamptz")).Rows)!.AsArray());
        Assert.Equal(10, JsonNode.Parse((await Read(",'2026-11-01 00:00:01'::timestamptz,'2026-11-01 00:00:02'::timestamptz")).Rows)!.AsArray().Count);
        await fixture.Pg.ApplyFileAsync(Path.Combine(directory, "325_t109_workstation_path.rollback.sql"), null, ct);
        Assert.Equal(original, await Scalar(definitionSql)); Assert.Equal(catalog, await Scalar(catalogSql));
        await fixture.Pg.ApplyFileAsync(forward, null, ct);
        Assert.Equal("325", await Scalar("select max(version)::text from schema_migrations"));
        string index = await Scalar("select pg_get_indexdef('sli_plugin_workstations.t109_workstation_candidates325'::regclass)");
        Assert.Contains("agent_key, event_id, observed_at DESC, id DESC", index);
        Assert.Equal("true", await Scalar("select (indisvalid and indisready)::text from pg_index where indexrelid='sli_plugin_workstations.t109_workstation_candidates325'::regclass"));
        output.WriteLine("325 workstation index bytes / 12004 rows: " + await Scalar("select pg_relation_size('sli_plugin_workstations.t109_workstation_candidates325')::text"));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
