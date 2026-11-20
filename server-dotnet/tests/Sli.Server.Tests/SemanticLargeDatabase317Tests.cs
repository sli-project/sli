using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests;

public sealed partial class SemanticLargeDatabaseTests
{
    // Reuses 316's cluster: CI adds no extra baseline installation. The full
    // retained-data distribution is opt-in for local profiling, not every CI run.
    private async Task Check317(SqlPostgresFixture fixture, NpgsqlConnection db, CancellationToken ct)
    {
        async Task<string> Scalar(string sql) { await using var q = new NpgsqlCommand(sql, db) { CommandTimeout = 25 }; return (string)(await q.ExecuteScalarAsync(ct))!; }
        string directory = Path.Combine(SqlPostgresFixture.Repository(), "config/postgres_migrations");
        string forward = Path.Combine(directory, "317_semantic_event_candidates.sql"), rollback = Path.Combine(directory, "317_semantic_event_candidates.rollback.sql");
        // Restore 316's tamper/seen test before comparing all reader outputs.
        await PostCollectionPostgres.Sql(db, "delete from semantic_t109_seen", ct);
        await PostCollectionPostgres.Sql(db, """
            insert into normalized_events(normalized_event_id,source_event_id,semantic_contract_version,normalizer_id,normalizer_version,
                processing_status,normalized_at,source_event_sha256,semantic_sha256,semantic_type,occurred_at_utc,roles_json,source_ingested_at,source_identity_json)
            select md5('317-normalized:'||id)::uuid,id,1,'windows.named-eventdata','1','normalized',time_created_utc,
                normalized_hash,sha256(id::text::bytea),'authentication.session.created',time_created_utc,'{}',migrated_at,jsonb_build_object('id',id,'server_id',server_id,'domain_id',domain_id,'log_source_id',log_source_id,'event_id',event_id,'time_created_utc',time_created_utc,'normalized_hash',encode(normalized_hash,'hex'),'migrated_at',migrated_at,'channel','Security')
            from events_v2_core e where id in(900002,900003);
            insert into decoy_label_versions(id,revision,kind,identity,owner,reason,active,active_from,actor_type,actor_id,readiness,plugin_id,entity_id,collection_scope_id)
            values(md5('317-decoy')::uuid,1,'account','{"domain_id":1,"entity_id":1,"sid":"S-1-5-21-100000001-200000002-300000003-1001","guid":"00000000-0000-4000-8000-000000000001"}',
                'synthetic','synthetic',true,'2026-01-01','session',1,'{"state":"ready"}','sli.ad',1,'ad-domain:1');
            insert into watch_entry_versions(id,revision,identity,entity_id,collection_scope_id,owner,reason,active,active_from,expires_at,valid_from,actor_type,actor_id)
            values(md5('317-watch')::uuid,1,'{"domain_id":1,"entity_id":1,"sid":"S-1-5-21-100000001-200000002-300000003-1001","guid":"00000000-0000-4000-8000-000000000001"}',1,'ad-domain:1',
                'synthetic','synthetic',true,'2026-01-01','2100-01-01','2026-01-01','session',1);
            insert into sli_agents(id,host_id,key_fingerprint,assigned_modules)
            values(md5('317-file-agent')::uuid,md5('317-file-host')::uuid,repeat('e',64),
                '[{"module_id":"sli.file-audit","enabled":true,"config":{"policy_revision":"1","roots":[{"collection_scope_id":"synthetic-root"}]}}]');
            insert into sli_plugin_file_audit.policy_revisions(agent_id,source_instance_id,revision,authored_at,actor_kind,actor_id,policy,policy_sha256)
            values(md5('317-file-agent')::uuid,'synthetic-files',1,now(),'session',1,'{"source_kind":"server"}',repeat('e',64));
            insert into sli_plugin_file_audit.observations(evidence_key,agent_id,source_instance_id,collection_scope_id,channel,provider,
                generation,record_id,event_id,event_version,observed_at,policy_revision,core_evidence_ref,payload_sha256,normalized)
            values(repeat('e',64),md5('317-file-agent')::uuid,'synthetic-files','synthetic-root','Security','Microsoft-Windows-Security-Auditing',
                'synthetic-generation',101,4663,1,'2026-11-01',1,'synthetic',repeat('e',64),jsonb_build_object('evidence_key',repeat('e',64),'payload_sha256',repeat('e',64)));
            insert into sli_plugin_file_audit.actions(action_id,contract_version,agent_id,source_instance_id,collection_scope_id,observed_at,
                object_type,operation,outcome,correlation_state,projection_version)
            values(repeat('e',64),1,md5('317-file-agent')::uuid,'synthetic-files','synthetic-root','2026-11-01','file','write','success','complete',1);
            insert into sli_plugin_file_audit.action_evidence(action_id,core_evidence_ref,evidence_key,role)
            values(repeat('e',64),'synthetic',repeat('e',64),'primary');
            insert into finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,source_instance_id,
                source_generation,collection_scope_id,storage_kind,agent_id)
            select 'sli_semantic_login'::regrole,'sli_semantic_login',installation_id,'sli.file-audit','synthetic-files',
                'synthetic-generation','synthetic-root','file_audit_observation',md5('317-file-agent')::uuid from semantic_default_installation;
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            values(md5('317-file-agent')::uuid,'sli.file-audit',1,md5('317-file-packet')::uuid,repeat('e',64),
                jsonb_build_object('agent_id',md5('317-file-agent')::uuid,'source_instance_id','synthetic-files','generation','synthetic-generation'),'{"status":"committed"}');
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
            select packet_id,envelope,'{"contract":"sli.collection-packet.v1","header":{"channel":"Security"}}','[]',now()
            from sli_agent_receipts where packet_id=md5('317-file-packet')::uuid;
            insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
            select 8000001,900001,id,'agent-packet:'||md5('317-file-packet')::uuid,'jsonl',repeat('e',64) from log_sources where name='Security';
            insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,event_record_id,channel_id,provider_id,
                time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
            select 8000001,8000001,900001,domain_id,log_source_id,4663,101,channel_id,provider_id,
                time_created_utc,normalized_at,decode(repeat('e',64),'hex'),decode(repeat('e',64),'hex'),noise_catalog_version
            from events_v2_core where id=900002;
            """, ct);
        const string signatures = "'public.read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure,'public.read_identity_attack_events_v301(jsonb,bigint[])'::regprocedure,'public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure,'public.read_account_watch_events(uuid,text,text,text,text,uuid)'::regprocedure,'public.read_default_password_events(jsonb)'::regprocedure,'public.read_default_password_window_v2(jsonb)'::regprocedure";
        string catalogSql = $"select jsonb_agg(to_jsonb(p)-'prosrc' order by oid)::text from pg_proc p where oid in ({signatures})";
        string definitionsSql = $"select jsonb_agg(pg_get_functiondef(oid) order by oid)::text from pg_proc where oid in ({signatures})";
        string authority = await Scalar(catalogSql), definitions = await Scalar(definitionsSql);
        string scope;
        // Discovery must run as the actual NOINHERIT login, not a superuser
        // merely SET ROLE-ing into the worker.
        await PostCollectionPostgres.Sql(db, "set session authorization sli_semantic_login;set role adlog_semantic_worker;set statement_timeout='20s'", ct);
        await Scalar("select count(*)::text from default_detection_sources()");
        scope = await Scalar("select (source->'scope')::text from t109_detection_sources() where source#>>'{scope,source_instance_id}'=md5('semantic-host')::uuid::text");
        string installation = JsonNode.Parse(scope)!["installation_id"]!.GetValue<string>();
        string fileScope = new JsonObject { ["installation_id"] = installation, ["plugin_id"] = "sli.file-audit", ["source_instance_id"] = "synthetic-files",
            ["source_generation"] = "synthetic-generation", ["collection_scope_id"] = "synthetic-root" }.ToJsonString();
        var queries = new Dictionary<string, string> {
            ["t109"] = "select * from read_t109_native(@scope::jsonb)",
            ["t109_window"] = "select * from read_t109_native(@scope::jsonb,'2026-11-01','2026-11-02')",
            ["t109_file"] = "select * from read_t109_native(@scope::jsonb)",
            ["t109_file_window"] = "select * from read_t109_native(@scope::jsonb,'2026-11-01','2026-11-02')",
            ["identity"] = "select * from read_identity_attack_events_v301(@scope::jsonb)",
            ["identity_ref"] = "select * from read_identity_attack_events_v301(@scope::jsonb,array[900002]::bigint[])",
            ["password"] = "select * from read_default_password_events(@scope::jsonb)",
            ["password_v2"] = "select record_kind,source_event_id,event_id,occurred_at_utc,sha256,source_xml from read_default_password_window_v2(@scope::jsonb)",
            ["decoy"] = $"select * from read_account_decoy_events('{installation}','sli.windows.ad-dc',md5('semantic-host')::uuid::text,md5('semantic-host')::uuid::text,repeat('a',64),null)",
            ["watch"] = $"select * from read_account_watch_events('{installation}','sli.windows.ad-dc',md5('semantic-host')::uuid::text,md5('semantic-host')::uuid::text,repeat('a',64),null)"
        };
        async Task<Dictionary<string, JsonNode>> Read(string label) {
            var results = new Dictionary<string, JsonNode>();
            foreach (var (name, sql) in queries) {
                var timer = Stopwatch.StartNew();
                await using var q = new NpgsqlCommand("select coalesce(jsonb_agg(to_jsonb(r) order by to_jsonb(r)::text),'[]')::text from (" + sql + ") r", db) { CommandTimeout = 25 };
                q.Parameters.AddWithValue("scope", name.StartsWith("t109_file", StringComparison.Ordinal) ? fileScope : scope);
                results[name] = JsonNode.Parse((string)(await q.ExecuteScalarAsync(ct))!)!;
                output.WriteLine($"317 {label} {name}: {timer.Elapsed.TotalMilliseconds:F1} ms");
                Assert.True(timer.Elapsed < TimeSpan.FromSeconds(20), name);
            }
            return results;
        }
        var expected = await Read("schema316");
        Assert.Equal(2, expected["decoy"].AsArray().Count);
        Assert.Single(expected["t109_file"].AsArray());
        await PostCollectionPostgres.Sql(db, "reset role;reset session authorization", ct);
        await fixture.Pg.ApplyFileAsync(forward, null, ct);
        Assert.Equal(authority, await Scalar(catalogSql));
        await PostCollectionPostgres.Sql(db, "set session authorization sli_semantic_login;set role adlog_semantic_worker", ct);
        var actual = await Read("schema317");
        foreach (string key in queries.Keys) Assert.True(JsonNode.DeepEquals(expected[key], actual[key]), key);
        await PostCollectionPostgres.Sql(db, "reset role;reset session authorization", ct);
        await fixture.Pg.ApplyFileAsync(rollback, null, ct);
        Assert.Equal(definitions, await Scalar(definitionsSql)); Assert.Equal(authority, await Scalar(catalogSql));

        bool full = Environment.GetEnvironmentVariable("SLI_SEMANTIC_FULL_SCALE") == "1";
        int inboxCount = full ? 1500000 : 1200, sameAgent = full ? 400000 : 400, coreCount = full ? 16000000 : 16000;
        var load = Stopwatch.StartNew();
        await PostCollectionPostgres.Sql(db, "set statement_timeout=0", ct); // fixture loading only; readers retain 20s
        // Both real inbox triggers remain enabled. Batch commits avoid repeatedly
        // rewriting the stream-health tuple in one enormous transaction.
        for (int lower = 1; lower <= inboxCount; lower += 1000) {
            await using var seed = new NpgsqlCommand("""
                insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                select case when n<=@same then md5('semantic-agent')::uuid else md5('semantic-agent1')::uuid end,
                    'sli.windows.ad-dc',n+10000,md5('317-history:'||n)::uuid,repeat('c',64),
                    jsonb_build_object('agent_id',case when n<=@same then md5('semantic-agent')::uuid else md5('semantic-agent1')::uuid end,
                        'source_instance_id',md5('semantic-host')::uuid::text,'generation',md5('semantic-host')::uuid::text),'{"status":"committed"}'
                from generate_series(@lower,@upper) n;
                insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
                select packet_id,envelope,'{"contract":"sli.collection-packet.v1","header":{"channel":"Security"}}','[]','2026-10-01'
                from sli_agent_receipts where sequence between @lower+10000 and @upper+10000;
                """, db) { CommandTimeout = 120 };
            seed.Parameters.AddWithValue("same", sameAgent); seed.Parameters.AddWithValue("lower", lower); seed.Parameters.AddWithValue("upper", Math.Min(lower + 999, inboxCount));
            await seed.ExecuteNonQueryAsync(ct);
        }
        await using (var seed = new NpgsqlCommand("""
            insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
            select 10000000+n,900001,(select id from log_sources where name='Security'),'agent-packet:'||md5('317-history:'||n)::uuid,'jsonl',encode(sha256(('317-raw:'||n)::bytea),'hex')
            from generate_series(1,@inbox) n;
            """, db) { CommandTimeout = 300 }) {
            seed.Parameters.AddWithValue("inbox", inboxCount); await seed.ExecuteNonQueryAsync(ct);
        }
        for (int lower = 1; lower <= coreCount; lower += 100000) {
            await using var seed = new NpgsqlCommand("""
                insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,event_record_id,channel_id,provider_id,
                    time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
                select 10000000+n,10000000+1+(n-1)%@inbox,900001,(select domain_id from servers where id=900001),
                    (select id from log_sources where name='Security'),4624,n+10000000,
                    (select id from storage_v2_channel where value='Security'),(select id from storage_v2_provider where value='Microsoft-Windows-Security-Auditing'),
                    '2026-10-01','2026-10-01',sha256(n::text::bytea),sha256(n::text::bytea),
                    (select version from event_catalog_revisions order by id limit 1) from generate_series(@lower,@upper) n;
                """, db) { CommandTimeout = 300 };
            seed.Parameters.AddWithValue("inbox", inboxCount); seed.Parameters.AddWithValue("lower", lower); seed.Parameters.AddWithValue("upper", Math.Min(lower + 99999, coreCount));
            await seed.ExecuteNonQueryAsync(ct);
        }
        await PostCollectionPostgres.Sql(db, "analyze events_v2_core;analyze sli_agent_receipts;analyze raw_log_files;analyze sli_agent_packet_inbox;analyze normalized_events", ct);
        output.WriteLine($"317 fixture: inbox={inboxCount}, core={coreCount}, one agent receipts={sameAgent}; load={load.Elapsed}");
        var migration = Stopwatch.StartNew(); await fixture.Pg.ApplyFileAsync(forward, null, ct);
        output.WriteLine($"317 populated migration: {migration.Elapsed}");
        await PostCollectionPostgres.Sql(db, "load 'auto_explain';set auto_explain.log_min_duration=0;set auto_explain.log_nested_statements=on;set auto_explain.log_analyze=on;set auto_explain.log_buffers=on;set auto_explain.log_format=json;set session authorization sli_semantic_login;set role adlog_semantic_worker;set statement_timeout='20s'", ct);
        actual = await Read("retained-history");
        foreach (string key in queries.Keys) Assert.True(JsonNode.DeepEquals(expected[key], actual[key]), key);
        await PostCollectionPostgres.Sql(db, "reset role;reset session authorization;set auto_explain.log_min_duration=-1", ct);
        string plans = await fixture.Pg.DiagnosticsAsync(ct);
        Assert.Contains("semantic_t109_event_time_v317", plans);
        Assert.DoesNotContain("semantic_account_inbox_v315", plans);
        await Check318(fixture,db,scope,ct);
    }
}
