using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests;

public sealed partial class SemanticLargeDatabaseTests
{
    [Fact]
    public async Task Schema315_limits_native_proofs_to_the_batch_and_advances_checkpoint()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 314);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await SemanticRuntimePostgresTests.SeedNative(db, ct);
        // A complementary distribution: ALL core rows belong to the admitted
        // source. Directory/receipt history is small so this isolates native proof cost.
        string seedSql = Seed315.Replace("150000", "2000").Replace("200000", "6000")
            .Replace("case when n<=160 then 900001 else 900004 end", "900001");
        await using (var seed = new NpgsqlCommand(seedSql, db) { CommandTimeout = 120 }) await seed.ExecuteNonQueryAsync(ct);
        async Task<string> Scalar(string sql) { await using var q = new NpgsqlCommand(sql, db) { CommandTimeout = 30 }; return (string)(await q.ExecuteScalarAsync(ct))!; }
        string installation = await Scalar("select installation_id::text from semantic_default_installation");
        var expected = new Dictionary<string,JsonArray>();
        var nextExpected = new Dictionary<string,JsonArray>();
        await PostCollectionPostgres.Sql(db, "set session authorization sli_semantic_login; set role adlog_semantic_worker; set statement_timeout='30s'", ct);
        async Task<JsonArray> Addressed(string name, int lower, int upper) {
            // The original 314 reader still performs every admission/proof and
            // returns every JSON field. One SQL request avoids per-ID round trips.
            await using var q = new NpgsqlCommand($"select coalesce(jsonb_agg(to_jsonb(r) order by normalized_event_id),'[]')::text from generate_series(@lower,@upper) g(n) cross join lateral read_account_{name}_events('{installation}','sli.windows.ad-dc',md5('semantic-host')::uuid::text,md5('semantic-host')::uuid::text,repeat('a',64),md5('normalized:'||g.n)::uuid) r", db) { CommandTimeout = 30 };
            q.Parameters.AddWithValue("lower", lower); q.Parameters.AddWithValue("upper", upper);
            return JsonNode.Parse((string)(await q.ExecuteScalarAsync(ct))!)!.AsArray();
        }
        foreach (string name in new[] { "decoy", "watch" }) {
            expected[name] = await Addressed(name, 1, 128);
            Assert.Equal(128, expected[name].Count);
        }
        await PostCollectionPostgres.Sql(db, "reset role; reset session authorization", ct);
        await fixture.Pg.ApplyFileAsync(Path.Combine(SqlPostgresFixture.Repository(), "config/postgres_migrations/315_semantic_bounded_readers.sql"), null, ct);
        await PostCollectionPostgres.Sql(db, "set track_functions='all'", ct);
        async Task CheckBatches(int proofCount, string stage) {
            foreach (string name in new[] { "decoy", "watch" }) {
                await PostCollectionPostgres.Sql(db, "select pg_stat_force_next_flush()", ct);
                await PostCollectionPostgres.Sql(db, "select pg_stat_reset(); set session authorization sli_semantic_login; set role adlog_semantic_worker", ct);
                var timer = Stopwatch.StartNew();
                string rows = await Scalar($"select jsonb_agg(to_jsonb(r) order by normalized_event_id)::text from read_account_{name}_events('{installation}','sli.windows.ad-dc',md5('semantic-host')::uuid::text,md5('semantic-host')::uuid::text,repeat('a',64),null) r");
                output.WriteLine($"315 single-source 6000 {stage} {name}: {timer.Elapsed.TotalMilliseconds:F1} ms");
                Assert.True(JsonNode.DeepEquals(expected[name], JsonNode.Parse(rows)), name);
                await PostCollectionPostgres.Sql(db, "reset role; reset session authorization; select pg_stat_force_next_flush(); select pg_stat_clear_snapshot()", ct);
                string calls = await Scalar("select calls::text from pg_stat_user_functions where funcid='public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text)'::regprocedure");
                output.WriteLine($"315 single-source {name} native proofs: {calls}");
                Assert.Equal(proofCount.ToString(System.Globalization.CultureInfo.InvariantCulture), calls);
            }
        }
        await CheckBatches(128, "all-valid");
        await fixture.RollbackAfterAsync(314, ct);
        await PostCollectionPostgres.Sql(db, """
            -- These candidates pass the source prefilter, but their packet has
            -- no matching receipt envelope. Proof must reject them before LIMIT.
            update events_v2_core set raw_log_file_id=900004 where id<=3;
            update sli_agent_packet_inbox set envelope=envelope||jsonb_build_object(
                'source_instance_id',md5('semantic-host')::uuid::text,'generation',md5('semantic-host')::uuid::text)
                where packet_id=md5('history:1')::uuid;
            set session authorization sli_semantic_login; set role adlog_semantic_worker;
            """, ct);
        foreach (string name in new[] { "decoy", "watch" }) {
            Assert.Empty(await Addressed(name, 1, 3));
            expected[name] = await Addressed(name, 4, 131);
            nextExpected[name] = await Addressed(name, 132, 259);
            Assert.Equal(128, expected[name].Count);
            Assert.Equal(128, nextExpected[name].Count);
        }
        await PostCollectionPostgres.Sql(db, "reset role; reset session authorization", ct);
        await fixture.Pg.ApplyFileAsync(Path.Combine(SqlPostgresFixture.Repository(), "config/postgres_migrations/315_semantic_bounded_readers.sql"), null, ct);
        await CheckBatches(131, "unavailable-prefix");
        // Match runtime: read a batch, persist checks as the scoped worker, read
        // the next batch using the SAME checkpoint. Compare both complete JSONs
        // with 314 addressed reads, including the unavailable three-row prefix.
        string scope = $"jsonb_build_object('installation_id','{installation}','plugin_id','sli.windows.ad-dc','source_instance_id',md5('semantic-host')::uuid::text,'source_generation',md5('semantic-host')::uuid::text,'collection_scope_id','')";
        await PostCollectionPostgres.Sql(db, "set session authorization sli_semantic_login; set role adlog_semantic_worker", ct);
        foreach (string name in new[] { "decoy", "watch" }) {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonArray baseline in new[] { expected[name], nextExpected[name] }) {
                var batch = JsonNode.Parse(await Scalar($"select jsonb_agg(to_jsonb(r) order by normalized_event_id)::text from read_account_{name}_events('{installation}','sli.windows.ad-dc',md5('semantic-host')::uuid::text,md5('semantic-host')::uuid::text,repeat('a',64),null) r"))!.AsArray();
                Assert.Equal(128, batch.Count);
                Assert.True(JsonNode.DeepEquals(baseline, batch), name + " checkpoint batch");
                var ids = batch.Select(row => Guid.Parse(row!["normalized_event_id"]!.ToString())).ToArray();
                foreach (Guid id in ids) Assert.True(seen.Add(id.ToString()), name + " repeated normalization");
                await using var check = new NpgsqlCommand($"insert into semantic_account_{name}_checks(checkpoint_key,normalized_event_id,scope_json,result_code) select repeat('a',64),id,{scope},'observed' from unnest(@ids::uuid[]) id", db);
                check.Parameters.AddWithValue("ids", ids);
                Assert.Equal(128, await check.ExecuteNonQueryAsync(ct));
            }
            Assert.Equal(256, seen.Count);
            Assert.Equal("256", await Scalar($"select count(*)::text from semantic_account_{name}_checks where checkpoint_key=repeat('a',64)"));
        }
        await PostCollectionPostgres.Sql(db, "reset role; reset session authorization", ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Schema314_accepts315_with_equal_bounded_account_health_and_snapshot_reads()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 314);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await SemanticRuntimePostgresTests.SeedNative(db, ct);
        // 6k receipts/inbox, 12k core/normalizations, 6k directory versions.
        string seedSql = Seed315.Replace("150000", "6000").Replace("200000", "12000");
        // History belongs to the SAME agent and revision: a latest packet LIMIT
        // must not scan the full receipt history or sort it per module.
        int inboxStart = seedSql.IndexOf("insert into sli_agent_packet_inbox", StringComparison.Ordinal);
        int inboxEnd = seedSql.IndexOf("-- Newest", StringComparison.Ordinal);
        await using (var seed = new NpgsqlCommand(seedSql[..inboxStart], db) { CommandTimeout = 120 }) await seed.ExecuteNonQueryAsync(ct);
        // Commit batches with both real inbox triggers enabled. A single huge
        // transaction repeatedly updates the same import-health tuple.
        for (int lower = 1; lower <= 6000; lower += 1000) {
            string sql = seedSql[inboxStart..inboxEnd].Replace("where sequence>1", "where sequence>@lower and sequence<=@upper");
            await using var batch = new NpgsqlCommand(sql, db) { CommandTimeout = 120 };
            batch.Parameters.AddWithValue("lower", lower); batch.Parameters.AddWithValue("upper", lower + 1000);
            await batch.ExecuteNonQueryAsync(ct);
        }
        await using (var seed = new NpgsqlCommand(seedSql[inboxEnd..], db) { CommandTimeout = 120 }) await seed.ExecuteNonQueryAsync(ct);
        string directory = Path.Combine(SqlPostgresFixture.Repository(), "config/postgres_migrations");
        string forward = Path.Combine(directory, "315_semantic_bounded_readers.sql");
        string rollback = Path.Combine(directory, "315_semantic_bounded_readers.rollback.sql");
        async Task<string> Scalar(string sql) { await using var q = new NpgsqlCommand(sql, db); return (string)(await q.ExecuteScalarAsync(ct))!; }
        const string functions = """
            'public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure,
            'public.read_account_watch_events(uuid,text,text,text,text,uuid)'::regprocedure,
            'public.read_t109_agent_health(jsonb)'::regprocedure,
            'public.identity_snapshot_rows_v301(jsonb,bigint[])'::regprocedure
            """;
        string authoritySql = $"select jsonb_agg(to_jsonb(p)-'prosrc' order by oid)::text from pg_proc p where oid in ({functions})";
        string definitionsSql = $"select jsonb_agg(pg_get_functiondef(oid) order by oid)::text from pg_proc where oid in ({functions})";
        string authority = await Scalar(authoritySql), definitions = await Scalar(definitionsSql);
        string installation = await Scalar("select installation_id::text from semantic_default_installation");
        string scope = $"jsonb_build_object('installation_id','{installation}','plugin_id','sli.windows.ad-dc','source_instance_id',md5('semantic-host')::uuid::text,'source_generation',md5('semantic-host')::uuid::text,'collection_scope_id','')";
        string snapshotScope = $"jsonb_build_object('installation_id','{installation}','plugin_id','sli.ad-snapshot','source_instance_id','domain:1','source_generation','directory-v1','collection_scope_id','')";
        var queries = new Dictionary<string, string> {
            ["decoy"] = $"select coalesce(jsonb_agg(to_jsonb(r) order by normalized_event_id),'[]')::text from read_account_decoy_events('{installation}','sli.windows.ad-dc',md5('semantic-host')::uuid::text,md5('semantic-host')::uuid::text,repeat('a',64),null) r",
            ["watch"] = $"select coalesce(jsonb_agg(to_jsonb(r) order by normalized_event_id),'[]')::text from read_account_watch_events('{installation}','sli.windows.ad-dc',md5('semantic-host')::uuid::text,md5('semantic-host')::uuid::text,repeat('a',64),null) r",
            ["health"] = $"select read_t109_agent_health({scope})::text",
            ["snapshot"] = $"select coalesce(jsonb_agg(to_jsonb(r) order by source_event_id,attributes_json::text),'[]')::text from read_identity_attack_snapshot_v301({snapshotScope},null) r",
            ["snapshot_refs"] = $"select coalesce(jsonb_agg(to_jsonb(r) order by source_event_id,attributes_json::text),'[]')::text from read_identity_attack_snapshot_v301({snapshotScope},array[1,2,3,999999]::bigint[]) r",
            ["native"] = "select read_agent_semantic_source_v190(900002)::text"
        };
        // Explicit IDs intentionally bypass latest-normalization/checkpoint filtering.
        foreach (string name in new[] { "decoy", "watch" })
            queries[name + "_explicit"] = queries[name].Replace("repeat('a',64),null)", "repeat('a',64),md5('normalized:1')::uuid)");
        async Task<Dictionary<string,string>> Read(string stage) {
            var results = new Dictionary<string,string>();
            await using var worker = new NpgsqlConnection(fixture.Dsn("sli_semantic_login")); await worker.OpenAsync(ct);
            await PostCollectionPostgres.Sql(worker, "set role adlog_semantic_worker; set statement_timeout='30s'", ct);
            if (stage != "after") await PostCollectionPostgres.Sql(worker, """
                create temp table measure_anchor_v315(value boolean);
                create function pg_temp.measure_v315(query_text text) returns jsonb language plpgsql as $$
                declare result text; begin
                    execute query_text into result;
                    return jsonb_build_object('result',result);
                exception when query_canceled then return jsonb_build_object('timeout',true);
                end $$;
                """, ct);
            async Task<string> AddressedBatch(string name) {
                // Same 128 original-reader calls, evaluated server-side, with
                // complete JSON aggregation and the original normalized-ID order.
                string addressed = queries[name]
                    .Replace(" from read_account_", " from generate_series(1,128) g(n) cross join lateral read_account_")
                    .Replace("repeat('a',64),null)", "repeat('a',64),md5('normalized:'||g.n)::uuid)");
                await using var q = new NpgsqlCommand(addressed, worker) { CommandTimeout = 30 };
                return (string)(await q.ExecuteScalarAsync(ct))!;
            }
            foreach (var (name, sql) in queries) {
                if (stage == "rollback" && name is "decoy" or "watch") { results[name] = await AddressedBatch(name); continue; }
                // Only the two historical account probes may time out; all exact
                // addressed reference reads retain the normal 30-second budget.
                string timeout = stage == "before" && name is "decoy" or "watch" ? "1s" : "30s";
                await PostCollectionPostgres.Sql(worker, $"set statement_timeout='{timeout}'", ct);
                var timer = Stopwatch.StartNew();
                await using var q = new NpgsqlCommand(stage == "after" ? sql : "select pg_temp.measure_v315(@sql)::text", worker) { CommandTimeout = 30 };
                if (stage != "after") q.Parameters.AddWithValue("sql", sql);
                string value = (string)(await q.ExecuteScalarAsync(ct))!;
                output.WriteLine($"315 {stage} {name}: {timer.Elapsed.TotalMilliseconds:F1} ms");
                if (stage == "after") results[name] = value;
                else {
                    var measured = JsonNode.Parse(value)!;
                    if (measured["timeout"] is not null) {
                        Assert.Contains(name, new[] { "decoy", "watch" });
                        output.WriteLine($"315 {stage} {name}: statement_timeout={timeout} reproduced; exact values read by addressed calls");
                        await PostCollectionPostgres.Sql(worker, "set statement_timeout='30s'", ct);
                        results[name] = await AddressedBatch(name);
                    } else results[name] = measured["result"]!.GetValue<string>();
                }
            }
            // Expected denials are caught on the server, preserving the SQL error log gate.
            await PostCollectionPostgres.Sql(worker, $"""
                do $$ begin
                    begin perform * from read_account_decoy_events('{installation}','sli.windows.ad-dc','foreign','generation',repeat('a',64),null);
                        raise exception 'foreign_decoy_accepted'; exception when insufficient_privilege then null; end;
                    begin perform * from read_account_watch_events('{installation}','sli.windows.ad-dc','foreign','generation',repeat('a',64),null);
                        raise exception 'foreign_watch_accepted'; exception when insufficient_privilege then null; end;
                    begin perform * from read_identity_attack_snapshot_v301({snapshotScope}||jsonb_build_object('source_instance_id','domain:999'),null);
                        raise exception 'foreign_snapshot_accepted'; exception when insufficient_privilege then null; end;
                end $$;
                """, ct);
            return results;
        }
        var expected = await Read("before");
        Assert.Equal(128, JsonNode.Parse(expected["decoy"])!.AsArray().Count);
        Assert.Equal(128, JsonNode.Parse(expected["watch"])!.AsArray().Count);
        Assert.Single(JsonNode.Parse(expected["decoy_explicit"])!.AsArray());
        Assert.Equal(3, JsonNode.Parse(expected["snapshot"])!.AsArray().Count);
        Assert.NotEqual("null", expected["native"]);
        Assert.True(File.Exists(forward), "Migration315 must replace the history-wide plans measured above");
        var build = Stopwatch.StartNew(); await fixture.Pg.ApplyFileAsync(forward, null, ct);
        output.WriteLine($"315 populated migration: {build.Elapsed.TotalMilliseconds:F1} ms");
        output.WriteLine(await Scalar("select jsonb_object_agg(indexrelname,pg_relation_size(indexrelid))::text from pg_stat_user_indexes where indexrelname like '%v315'"));
        Assert.Equal(authority, await Scalar(authoritySql));
        var actual = await Read("after"); foreach (string name in queries.Keys)
            Assert.True(JsonNode.DeepEquals(JsonNode.Parse(expected[name]), JsonNode.Parse(actual[name])), name);
        // EXPLAIN the actual nested statements, not surrogate schemas/queries.
        await PostCollectionPostgres.Sql(db, "load 'auto_explain'; set auto_explain.log_min_duration=0; set auto_explain.log_nested_statements=on; set auto_explain.log_analyze=on; set auto_explain.log_buffers=on; set auto_explain.log_format=json; set session authorization sli_semantic_login; set role adlog_semantic_worker", ct);
        foreach (string sql in queries.Values) await Scalar(sql);
        await PostCollectionPostgres.Sql(db, "reset role; reset session authorization; set auto_explain.log_min_duration=-1", ct);
        string plans = await fixture.Pg.DiagnosticsAsync(ct);
        Assert.Contains("semantic_account_inbox_v315", plans);
        Assert.Contains("identity_version_record_v315", plans);
        Assert.Contains("identity_version_keys_v315", plans);
        Assert.Contains("sli_agent_stream_receipts_lookup", plans);
        await fixture.Pg.ApplyFileAsync(rollback, null, ct);
        Assert.Equal(definitions, await Scalar(definitionsSql)); Assert.Equal(authority, await Scalar(authoritySql));
        var restored = await Read("rollback"); foreach (string name in queries.Keys)
            Assert.True(JsonNode.DeepEquals(JsonNode.Parse(expected[name]), JsonNode.Parse(restored[name])), name);
        await fixture.Pg.ApplyFileAsync(forward, null, ct);
        Assert.Equal(authority, await Scalar(authoritySql));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    private const string Seed315 = """
        update sli_agent_receipts set envelope=envelope||'{"policy_revision":"1"}';
        update sli_agent_packet_inbox set envelope=envelope||'{"policy_revision":"1"}';
        insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt,received_at)
        select md5('semantic-agent')::uuid,'sli.windows.ad-dc',n+1,md5('history:'||n)::uuid,repeat('c',64),
            jsonb_build_object('agent_id',md5('semantic-agent')::uuid,'source_instance_id','history-source','generation','history','policy_revision','1'),
            '{"status":"committed"}','2026-10-01'::timestamptz+n*interval '1 millisecond' from generate_series(1,150000) n;
        insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
        select packet_id,envelope,jsonb_build_object('contract','sli.collection-packet.v1','header',jsonb_build_object('channel',
            case when sequence%3=0 then null when sequence%3=1 then '' else 'Security' end)),
            '[]',case when sequence in(10,20) then null else '2026-10-01'::timestamptz end from sli_agent_receipts where sequence>1;
        -- Newest mismatched receipt must be skipped, and empty/null channels stay distinct.
        update sli_agent_packet_inbox set envelope=envelope||'{"mismatch":true}' where packet_id=md5('history:150000')::uuid;
        insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
            select 900004,900001,id,'agent-packet:'||md5('history:1')::uuid,'jsonl',repeat('d',64) from log_sources where name='Security';
        insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,event_record_id,channel_id,provider_id,
            time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
        select n,case when n<=160 then 900001 else 900004 end,900001,1,(select id from log_sources where name='Security'),
            case when n%3=0 then 4625 else 4624 end,n+1000000,
            (select id from storage_v2_channel where value='Security'),(select id from storage_v2_provider where value='Microsoft-Windows-Security-Auditing'),
            '2026-11-01'::timestamptz,'2026-11-01'::timestamptz,sha256(n::text::bytea),sha256(n::text::bytea),
            (select version from event_catalog_revisions order by id limit 1) from generate_series(1,200000) n;
        insert into normalized_events(normalized_event_id,source_event_id,semantic_contract_version,normalizer_id,normalizer_version,
            processing_status,normalized_at,source_event_sha256,semantic_sha256,semantic_type,occurred_at_utc,roles_json,source_ingested_at,source_identity_json)
        select md5('normalized:'||id)::uuid,id,1,'windows.named-eventdata','1','normalized',
            '2026-11-01'::timestamptz+id*interval '1 microsecond',normalized_hash,sha256(id::text::bytea),'auth.logon',time_created_utc,
            jsonb_build_object('actor',case when id%3=0 then 'sam:example.test:synthetic-user'
                when id%3=1 then 'sid:S-1-5-21-100000001-200000002-300000003-1001'
                else 'guid:00000000-0000-4000-8000-000000000001' end),migrated_at,
            jsonb_build_object('id',id,'server_id',server_id,'domain_id',domain_id,'log_source_id',log_source_id,
                'event_id',event_id,'time_created_utc',time_created_utc,'normalized_hash',encode(normalized_hash,'hex'),
                'migrated_at',migrated_at,'channel','Security') from events_v2_core where id<900000;
        insert into finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,source_instance_id,source_generation,
            collection_scope_id,storage_kind,log_source_id,agent_id)
        select 'sli_semantic_login'::regrole,'sli_semantic_login',installation_id,'sli.windows.ad-dc',md5('semantic-host')::uuid::text,
            md5('semantic-host')::uuid::text,'','core_event',(select id from log_sources where name='Security'),md5('semantic-agent')::uuid from semantic_default_installation;
        insert into decoy_label_versions(id,revision,kind,identity,owner,reason,active,active_from,actor_type,actor_id,readiness,plugin_id,entity_id,collection_scope_id)
        values(md5('decoy')::uuid,1,'account','{"domain_id":1,"entity_id":1,"sid":"S-1-5-21-100000001-200000002-300000003-1001","guid":"00000000-0000-4000-8000-000000000001"}',
            'synthetic','synthetic',true,'2026-01-01','session',1,'{"state":"ready"}','sli.ad',1,'ad-domain:1');
        insert into watch_entry_versions(id,revision,identity,entity_id,collection_scope_id,owner,reason,active,active_from,expires_at,valid_from,actor_type,actor_id)
        values(md5('watch')::uuid,1,'{"domain_id":1,"entity_id":1,"sid":"S-1-5-21-100000001-200000002-300000003-1001","guid":"00000000-0000-4000-8000-000000000001"}',1,'ad-domain:1',
            'synthetic','synthetic',true,'2026-01-01','2100-01-01','2026-01-01','session',1);
        insert into storage_v2_entity_type(value) values('ad_user') on conflict do nothing;
        insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
            select n,(select id from storage_v2_entity_type where value='ad_user'),'snapshot:'||n,'Synthetic',1,sha256(n::text::bytea) from generate_series(1,150000) n;
        insert into ad_context_runs(run_id,source_pack_id,source_pack_version,domain_id,mode,observed_at_utc,bundle_sha256,status)
            select md5('snapshot:'||n)::uuid,'sli.windows.ad-context','1',1,'full','2026-10-01'::timestamptz+n*interval '1 day',sha256(n::text::bytea),'completed' from generate_series(1,2) n;
        insert into ad_context_sections(run_id,section_name,status,record_count) select run_id,'directory_accounts','complete',150000 from ad_context_runs;
        insert into ad_context_entity_versions(entity_id,source_section,valid_from_utc,last_observed_at_utc,content_sha256,attributes_json,source_run_id)
            select n,'directory_accounts','2026-01-01','2026-10-01',sha256(n::text::bytea),
                jsonb_build_object('record_key','key:'||n,'identity',jsonb_build_object('kind','ad_user','object_sid','S-1-5-21-100000001-200000002-300000003-'||n,
                    'object_guid',case when n=1001 then '00000000-0000-4000-8000-000000000001' end),
                    'attributes',jsonb_build_object('sam_account_name',case when n=1001 then 'synthetic-user' end)),
                md5('snapshot:1')::uuid from generate_series(1,150000) n;
        -- Deliberately retained version source_run_id differs from evidence's run.
        -- Joining on source_run_id would change the result and lose these rows.
        insert into ad_context_evidence(id,evidence_key,evidence_type,source_pack_id,source_run_id,observed_at_utc,locator_json,integrity_sha256)
            select n,'evidence:'||n,'entity_observation','sli.windows.ad-context',md5('snapshot:'||case when n=1 then 1 else 2 end)::uuid,
                '2026-10-03',jsonb_build_object('section','directory_accounts','record_key','key:'||n),sha256(n::text::bytea) from generate_series(1,4) n;
        insert into finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id,storage_kind)
            select 'sli_semantic_login'::regrole,'sli_semantic_login',installation_id,'sli.ad-snapshot','domain:1','directory-v1','','ad_directory_observation' from semantic_default_installation;
        analyze sli_agent_receipts; analyze sli_agent_packet_inbox; analyze sli_agent_stream_receipts;
        analyze raw_log_files; analyze events_v2_core; analyze normalized_events;
        analyze entities_v2; analyze ad_context_entity_versions; analyze ad_context_evidence; analyze ad_context_runs;
        """;
}
