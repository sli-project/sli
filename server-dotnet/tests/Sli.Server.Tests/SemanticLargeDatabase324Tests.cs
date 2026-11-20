using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests;

public sealed partial class SemanticLargeDatabaseTests
{
    [Fact]
    public async Task Detector324_directory_plans_keep_active_rows_and_use_type_seeks()
    {
        var ct=TestContext.Current.CancellationToken;
        // Compare 324 with its saved predecessor. Migration 327 deliberately
        // moves directory reads behind a SECURITY DEFINER function, whose inner
        // entity scans are covered separately by the 327 nested-plan tests.
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:324);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString);await db.OpenAsync(ct);
        async Task<string> Scalar(string sql) {
            await using var q=new NpgsqlCommand(sql,db){CommandTimeout=0};return (string)(await q.ExecuteScalarAsync(ct))!;
        }
        await Scalar("""
            -- Keep the flat-graph guard enabled. A thousand merges suffices to
            -- expose the unrelated aggregation over a 200k-entity directory.
            insert into storage_v2_entity_type(value) values('ad_computer'),('synthetic-other') on conflict do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
            select n,(select id from storage_v2_entity_type where value=case when n>200000 then 'ad_computer' else 'synthetic-other' end),
                'synthetic:'||n,'synthetic',1,sha256(n::text::bytea) from generate_series(1,200010) n;
            insert into entity_identity_merges_v2(merge_id,source_entity_id,target_entity_id,source_natural_key,target_natural_key,
                plan_sha256,source_core_sha256_before,target_core_sha256_before,source_links_before,target_links_before,target_links_after,
                source_links_sha256,target_links_before_sha256,target_links_after_sha256,affected_events,affected_events_sha256,semantic_replay_events,evidence_json)
            select md5('324-merge:'||n)::uuid,n,n+100000,'synthetic:'||n,'synthetic:'||(n+100000),h,h,h,0,0,0,h,h,h,0,h,0,'{}'::jsonb
                from generate_series(1,1000) n cross join (select sha256('synthetic'::bytea) h) s;
            analyze entities_v2;analyze entity_identity_merges_v2;analyze storage_v2_entity_type;select 'seeded';
            """);
        string type=await Scalar("select id::text from storage_v2_entity_type where value='ad_computer'");
        var plans=new JsonObject();
        foreach(string stage in new[]{"before","after"}) {
            foreach(var (name,signature) in new[]{("directory","sli_plugin_workstations.inventory_inputs_v1(bigint)"),("domains","read_workstation_inventory_job_sources_v1()")}) {
                string definition=await Scalar(stage=="before"
                    ? $"select definition from detector_definitions324 where signature='{signature}'"
                    : $"select pg_get_functiondef('{signature}'::regprocedure)");
                string query;
                if(name=="directory")query=definition.Split("$directory_query$")[1].Replace("$1",type,StringComparison.Ordinal).Replace("$2","2",StringComparison.Ordinal);
                else if(stage=="after")query=definition.Split("$domains$")[1].Replace("$1",type,StringComparison.Ordinal);
                else {
                    int start=definition.IndexOf("    select array_agg(domain_id",StringComparison.Ordinal),end=definition.IndexOf("    if cardinality(domains)",StringComparison.Ordinal);
                    Assert.True(start>0&&end>start);query=definition[start..end].Replace(" into domains","",StringComparison.Ordinal);
                }
                var plan=JsonNode.Parse(await Scalar("explain(analyze,buffers,format json) "+query))!;plans[stage+"_"+name]=plan;
                output.WriteLine($"324 {stage} {name}: ms={plan[0]!["Execution Time"]}");
                if(name=="directory") {
                    var metadata=PlanNodes(plan[0]!["Plan"]!).Where(n=>n["Relation Name"]?.ToString()=="ad_context_entity_versions").ToArray();
                    if(stage=="before")Assert.Contains(metadata,n=>n["Actual Loops"]!.GetValue<double>()>0);
                    else Assert.All(metadata,n=>Assert.Equal(0,n["Actual Loops"]!.GetValue<double>()));
                }
                if(stage=="after") {
                    var entityScans=PlanNodes(plan[0]!["Plan"]!).Where(n=>n["Relation Name"]?.ToString()=="entities_v2").ToArray();Assert.NotEmpty(entityScans);
                    Assert.All(entityScans,n=>Assert.True((n["Actual Rows"]!.GetValue<double>()+(n["Rows Removed by Filter"]?.GetValue<double>()??0))*n["Actual Loops"]!.GetValue<double>()<=10,n.ToJsonString()));
                    Assert.Equal(0,plan[0]!["Plan"]!["Temp Written Blocks"]!.GetValue<int>());
                }
            }
        }
        string outputDir=Path.Combine(SqlPostgresFixture.Repository(),".net-local/wk33");Directory.CreateDirectory(outputDir);
        await File.WriteAllTextAsync(Path.Combine(outputDir,"directory324.json"),plans.ToJsonString(new(){WriteIndented=true}),ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Detector324_watch_pending_rotates_without_losing_later_labels()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:324);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString);await db.OpenAsync(ct);
        await SemanticRuntimePostgresTests.SeedNative(db,ct,canonicalAssignment:true);
        await using var worker=new NpgsqlConnection(fixture.Dsn("sli_semantic_login"));await worker.OpenAsync(ct);
        await PostCollectionPostgres.Sql(worker,"set role adlog_semantic_worker",ct);
        async Task<string> Scalar(string sql,NpgsqlConnection? connection=null) {
            await using var q=new NpgsqlCommand(sql,connection??db){CommandTimeout=0};return (string)(await q.ExecuteScalarAsync(ct))!;
        }
        string scope=await Scalar("select source->'scope' from t109_detection_sources() limit 1",worker);
        await Scalar("""
            insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,event_record_id,channel_id,provider_id,computer_id,
                time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
            select 10000000+n,e.raw_log_file_id,e.server_id,e.domain_id,e.log_source_id,4624,10000000+n,e.channel_id,e.provider_id,e.computer_id,
                e.time_created_utc,e.normalized_at,sha256(n::text::bytea),sha256(n::text::bytea),e.noise_catalog_version
                from events_v2_core e cross join generate_series(1,6000) n where e.id=900002;
            insert into normalized_events(normalized_event_id,source_event_id,semantic_contract_version,normalizer_id,normalizer_version,
                processing_status,normalized_at,source_event_sha256,semantic_sha256,semantic_type,occurred_at_utc,roles_json,source_ingested_at,source_identity_json)
            select md5('324-pending:'||id)::uuid,id,1,'windows.named-eventdata','1','normalized',now(),normalized_hash,sha256(id::text::bytea),
                'auth.logon',time_created_utc,'{}',migrated_at,
                jsonb_build_object('id',id,'server_id',server_id,'domain_id',domain_id,'log_source_id',log_source_id,'event_id',event_id,
                    'time_created_utc',time_created_utc,'normalized_hash',encode(normalized_hash,'hex'),'migrated_at',migrated_at,'channel','Security')
            from events_v2_core where event_id in(4624,4625);
            select semantic_import_refresh320();select 'seeded';
            """);
        string query=$"select coalesce(jsonb_agg(to_jsonb(r)),'[]')::text from read_account_watch_events('{JsonNode.Parse(scope)!["installation_id"]!.GetValue<string>()}','sli.windows.ad-dc',md5('semantic-host')::uuid::text,md5('semantic-host')::uuid::text,repeat('a',64),null) r";
        Assert.Equal("[]",await Scalar(query,worker));Assert.Equal("[]",await Scalar(query,worker));
        Assert.Equal("6002",await Scalar("select count(*)::text from semantic_source_pending320 where kind='watch'"));
        await Scalar("""
            insert into watch_entry_versions(id,revision,identity,entity_id,collection_scope_id,owner,reason,active,active_from,expires_at,valid_from,actor_type,actor_id)
            values(md5('324-pending-watch')::uuid,1,'{"domain_id":1,"entity_id":1,"sid":"S-1-5-21-100000001-200000002-300000003-1001","guid":"00000000-0000-4000-8000-000000000001"}',1,'ad-domain:1',
                'synthetic','synthetic',true,'2026-01-01','2100-01-01','2026-01-01','session',1);select 'enabled';
            """);
        var seen=new HashSet<Guid>();
        for(int pass=0;pass<100&&seen.Count<6002;pass++) {
            var rows=JsonNode.Parse(await Scalar(query,worker))!.AsArray();Assert.InRange(rows.Count,0,128);
            var ids=rows.Select(r=>Guid.Parse(r!["normalized_event_id"]!.GetValue<string>())).ToArray();
            foreach(var id in ids)Assert.True(seen.Add(id),"An acknowledged normalization must not repeat");
            await using var check=new NpgsqlCommand("insert into semantic_account_watch_checks(checkpoint_key,normalized_event_id,scope_json,result_code) select repeat('a',64),id,@scope::jsonb,'no_match' from unnest(@ids::uuid[]) id",worker){CommandTimeout=0};
            check.Parameters.AddWithValue("ids",ids);check.Parameters.AddWithValue("scope",scope);await check.ExecuteNonQueryAsync(ct);
        }
        Assert.Equal(6002,seen.Count);await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Detector324_file_context_and_directory_keep_exact_results()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:323);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString);await db.OpenAsync(ct);
        await SemanticRuntimePostgresTests.SeedNative(db,ct,canonicalAssignment:true);
        async Task<string> Scalar(string sql) {
            await using var q=new NpgsqlCommand(sql,db){CommandTimeout=0};return (string)(await q.ExecuteScalarAsync(ct))!;
        }
        int rows=Environment.GetEnvironmentVariable("SLI_DETECTOR_324_SCALE")=="10"?550000:55000;
        await Scalar($$"""
            insert into sli_plugin_file_audit.observations(evidence_key,agent_id,source_instance_id,collection_scope_id,channel,provider,generation,
                record_id,event_id,event_version,observed_at,policy_revision,core_evidence_ref,payload_sha256,normalized)
            select md5('324-file:'||n)||md5('324-file:'||n),md5('semantic-agent')::uuid,md5('semantic-host')::uuid::text,'synthetic-root','Security',
                case when n=3 then 'Microsoft-Windows-Eventlog' else 'Microsoft-Windows-Security-Auditing' end,'file-generation',n,case when n={{rows+1}} then 4660 when n=3 then 1102 else 4663 end,
                0,'2026-11-01'::timestamptz,1,'synthetic:'||n,repeat('a',64),
                jsonb_build_object('record_id',n,'event_id',case when n={{rows+1}} then 4660 when n=3 then 1102 else 4663 end,
                    'policy_revision','1','facts',jsonb_build_object('subject_user_sid','S-1-5-21-100000001-200000002-300000003-1001',
                        'logon_id_numeric',1,'server_process_id',1,'handle_id',case when n=1 then '1.0'::jsonb when n=2 or n={{rows+1}} then '1'::jsonb else to_jsonb(n) end))
            from generate_series(1,{{rows+1}}) n;
            insert into storage_v2_entity_type(value) values('ad_computer'),('synthetic-other') on conflict do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
            select n,(select id from storage_v2_entity_type where value=case when n>200000 then 'ad_computer' else 'synthetic-other' end),
                'synthetic:'||n,'synthetic',1,sha256(n::text::bytea) from generate_series(1,200010) n;
            insert into entity_identity_merges_v2(merge_id,source_entity_id,target_entity_id,source_natural_key,target_natural_key,
                plan_sha256,source_core_sha256_before,target_core_sha256_before,source_links_before,target_links_before,target_links_after,
                source_links_sha256,target_links_before_sha256,target_links_after_sha256,affected_events,affected_events_sha256,semantic_replay_events,evidence_json)
            select md5('324-merge')::uuid,200009,200010,'synthetic:200009','synthetic:200010',h,h,h,0,0,0,h,h,h,0,h,0,'{}'::jsonb
                from (select sha256('synthetic'::bytea) h) s;
            insert into ad_context_runs(run_id,source_pack_id,source_pack_version,domain_id,mode,observed_at_utc,bundle_sha256,status)
            values(md5('324-directory-metadata')::uuid,'sli.windows.ad-context','1',1,'full','2026-11-01',sha256('synthetic'::bytea),'completed');
            insert into ad_context_entity_versions(entity_id,source_section,valid_from_utc,last_observed_at_utc,content_sha256,attributes_json,source_run_id)
            values(200001,'directory_accounts','2026-01-01','2026-11-01',sha256('synthetic'::bytea),
                jsonb_build_object('attributes',jsonb_build_object('organizational_unit','synthetic-ou','operating_system','synthetic-os')),md5('324-directory-metadata')::uuid);
            analyze sli_plugin_file_audit.observations;analyze entities_v2;analyze storage_v2_entity_type;
            select 'seeded';
            """);
        string context=$"select file_decoy_contexts(md5('semantic-agent')::uuid,md5('semantic-host')::uuid::text,'file-generation',md5('324-file:{rows+1}')||md5('324-file:{rows+1}'))::text";
        var filePlans=new JsonObject { ["observation_rows"]=rows+1 };
        async Task MeasureContext(string stage) {
            string body=await Scalar("select prosrc from pg_proc where oid='file_decoy_contexts(uuid,text,text,text)'::regprocedure");
            body=body.Replace("p_agent","md5('semantic-agent')::uuid",StringComparison.Ordinal)
                .Replace("p_source","md5('semantic-host')::uuid::text",StringComparison.Ordinal)
                .Replace("p_generation","'file-generation'",StringComparison.Ordinal)
                .Replace("p_native",$"(md5('324-file:{rows+1}')||md5('324-file:{rows+1}'))",StringComparison.Ordinal);
            var plan=JsonNode.Parse(await Scalar("explain(analyze,buffers,format json) "+body))!;filePlans[stage]=plan;
            output.WriteLine($"324 file_context {stage} rows={rows+1}: ms={plan[0]!["Execution Time"]}");
        }
        await MeasureContext("before");
        string expected=await Scalar(context);Assert.Equal(3,JsonNode.Parse(expected)!.AsArray().Count);
        var inventory=new Dictionary<int,string>();foreach(int domain in new[]{0,1,2})inventory[domain]=await Scalar($"select sli_plugin_workstations.inventory_inputs_v1({domain})::text");
        Assert.Equal(9,JsonNode.Parse(inventory[1])!["directory"]!.AsArray().Count);
        Assert.Contains("synthetic-ou",inventory[1],StringComparison.Ordinal);
        await Scalar("set session authorization sli_job_dispatcher_light;select 'set'");
        const string sources="select jsonb_agg(s order by s::text)::text from read_workstation_inventory_job_sources_v1() s";
        string expectedSources=await Scalar(sources);await Scalar("reset session authorization;select 'reset'");
        await fixture.Pg.ApplyFileAsync(Path.Combine(SqlPostgresFixture.Repository(),"config/postgres_migrations/324_detector_query_paths.sql"),null,ct);
        Assert.Equal(expected,await Scalar(context));
        await MeasureContext("after");
        string outputDir=Path.Combine(SqlPostgresFixture.Repository(),".net-local/wk33");Directory.CreateDirectory(outputDir);
        await File.WriteAllTextAsync(Path.Combine(outputDir,"file-context324.json"),filePlans.ToJsonString(new(){WriteIndented=true}),ct);
        foreach(var (domain,value) in inventory)Assert.Equal(value,await Scalar($"select sli_plugin_workstations.inventory_inputs_v1({domain})::text"));
        await Scalar("set session authorization sli_job_dispatcher_light;select 'set'");Assert.Equal(expectedSources,await Scalar(sources));
        await Scalar("reset session authorization;select 'reset'");
        // Compare the current collection function to the captured 323 original
        // across complete, gap and pending-packet states, with the same input.
        await Scalar("""
            do $$ declare definition text;begin
                select d.definition into definition from detector_definitions324 d where signature like 'sli_plugin_file_audit.collection_context_for_packet(%';
                execute replace(definition,'sli_plugin_file_audit.collection_context_for_packet(', 'sli_plugin_file_audit.collection_original324(');
            end $$;
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            select md5('semantic-agent')::uuid,'sli.file-audit',n,md5('324-context:'||n)::uuid,repeat('c',64),
                jsonb_build_object('agent_id',md5('semantic-agent')::uuid,'module_id','sli.file-audit','source_instance_id',md5('semantic-host')::uuid::text,
                    'generation','file-generation','sequence',n::text,'continuity_state',case when n=1 then 'gap' else 'continuous' end,
                    'cursor_after',jsonb_build_object('token','{"record_id":0}')),'{"status":"committed"}' from unnest(array[1,1000]) n;
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
            select packet_id,envelope,'{"contract":"sli.collection-packet.v1"}','[]',case when sequence=1 then now() else null end
            from sli_agent_receipts where module_id='sli.file-audit';select 'seeded';
            """);
        string collection="select sli_plugin_file_audit.collection_context_for_packet(md5('semantic-agent')::uuid,md5('324-context:1000')::uuid,'2026-11-01','2026-11-01','[{\"policy_revision\":\"1\",\"facts\":{\"subject_user_sid\":\"S-1-5-21-100000001-200000002-300000003-1001\",\"logon_id_numeric\":1,\"server_process_id\":1,\"handle_id\":1}}]'::jsonb)::text";
        foreach(string state in new[]{"complete","gap","pending"}) {
            if(state=="gap")await Scalar("""update sli_agent_receipts set envelope=jsonb_set(envelope,'{cursor_after,token}',to_jsonb('{"record_id":9999999}'::text)) where module_id='sli.file-audit' and sequence=1;select 'gap'""");
            if(state=="pending")await Scalar("update sli_agent_packet_inbox set imported_at=null where packet_id=md5('324-context:1')::uuid;select 'pending'");
            string actual=await Scalar(collection);Assert.Equal(await Scalar(collection.Replace("collection_context_for_packet","collection_original324",StringComparison.Ordinal)),actual);
            Assert.Equal(state=="complete",JsonNode.Parse(actual)!["complete"]!.GetValue<bool>());
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Detector324_explain_before_after_on_retained_history()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:323);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString);await db.OpenAsync(ct);
        await SemanticRuntimePostgresTests.SeedNative(db,ct,canonicalAssignment:true);
        await using var worker=new NpgsqlConnection(fixture.Dsn("sli_semantic_login"));await worker.OpenAsync(ct);
        await PostCollectionPostgres.Sql(worker,"set role adlog_semantic_worker;set statement_timeout=0;set work_mem='4MB';set plan_cache_mode=force_generic_plan",ct);
        async Task<string> Scalar(string sql,NpgsqlConnection? connection=null) {
            await using var q=new NpgsqlCommand(sql,connection??db){CommandTimeout=0};return (string)(await q.ExecuteScalarAsync(ct))!;
        }
        string scope=await Scalar("select source->'scope' from t109_detection_sources() limit 1",worker);
        // Default CI fixture is 1% of the stand; the requested local run uses
        // 10%. Keep packet/core skew and the 4MB spill threshold unchanged.
        int scale=Environment.GetEnvironmentVariable("SLI_DETECTOR_324_SCALE")=="10"?10:1;
        int packets=15000*scale,normalized=23000*scale,totalCore=167000*scale;
        for(int lower=1;lower<=packets;lower+=1000) {
            await using var q=new NpgsqlCommand("""
                insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                select md5('semantic-agent')::uuid,case when n%2=0 then 'sli.file-audit' else 'sli.windows.ad-dc' end,
                    n+1,md5('324-history:'||n)::uuid,repeat('c',64),
                    jsonb_build_object('agent_id',md5('semantic-agent')::uuid,'source_instance_id',case when n%2=0 then 'history-source' else md5('semantic-host')::uuid::text end,
                        'generation',case when n%2=0 then 'history' else md5('semantic-host')::uuid::text end,'sequence',(n+1)::text,'continuity_state',case when n=2 then 'gap' else 'continuous' end,
                        'cursor_after',jsonb_build_object('token','{"record_id":1}')),'{"status":"committed"}'
                from generate_series(@lower,@upper) n;
                insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
                select packet_id,envelope,'{"contract":"sli.collection-packet.v1","header":{"channel":"Security"}}','[]',now()
                from sli_agent_receipts where sequence between @lower+1 and @upper+1;
                """,db){CommandTimeout=0};
            q.Parameters.AddWithValue("lower",lower);q.Parameters.AddWithValue("upper",Math.Min(packets,lower+999));await q.ExecuteNonQueryAsync(ct);
        }
        await Scalar($$"""
            insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
                select 10000000+n,900001,(select id from log_sources where name='Security'),
                    'agent-packet:'||md5('324-history:'||n)::uuid,'jsonl',encode(sha256(n::text::bytea),'hex') from generate_series(1,{{packets}}) n;
            insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,event_record_id,channel_id,provider_id,computer_id,
                time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
            select 10000000+n,10000000+case when n<={{normalized}} then 2*((n-1)%{{packets/2}}+1)
                else 2*((n-{{normalized}}-1)%{{packets/2}}+1)-1 end,e.server_id,e.domain_id,e.log_source_id,
                case when n<={{normalized}} then 4624 else 9999 end,10000000+n,e.channel_id,e.provider_id,e.computer_id,
                e.time_created_utc,e.normalized_at,sha256(n::text::bytea),sha256(n::text::bytea),e.noise_catalog_version
            from events_v2_core e cross join generate_series(1,{{totalCore}}) n where e.id=900002;
            insert into normalized_events(normalized_event_id,source_event_id,semantic_contract_version,normalizer_id,normalizer_version,
                processing_status,normalized_at,source_event_sha256,semantic_sha256,semantic_type,occurred_at_utc,roles_json,source_ingested_at,source_identity_json)
            select md5('324-normalized:'||id)::uuid,id,1,'windows.named-eventdata','1','normalized',now(),normalized_hash,sha256(id::text::bytea),
                'auth.logon',time_created_utc,'{}',migrated_at,
                jsonb_build_object('id',id,'server_id',server_id,'domain_id',domain_id,'log_source_id',log_source_id,
                    'event_id',event_id,'time_created_utc',time_created_utc,'normalized_hash',encode(normalized_hash,'hex'),'migrated_at',migrated_at,'channel','Security')
            from events_v2_core where id in(900002,900003) or id between 10000001 and {{10000000+normalized}};
            insert into watch_entry_versions(id,revision,identity,entity_id,collection_scope_id,owner,reason,active,active_from,expires_at,valid_from,actor_type,actor_id)
            values(md5('324-watch')::uuid,1,'{"domain_id":1,"entity_id":1,"sid":"S-1-5-21-100000001-200000002-300000003-1001","guid":"00000000-0000-4000-8000-000000000001"}',1,'ad-domain:1',
                'synthetic','synthetic',true,'2026-01-01','2100-01-01','2026-01-01','session',1);
            analyze sli_agent_receipts;analyze sli_agent_packet_inbox;analyze raw_log_files;analyze events_v2_core;analyze normalized_events;
            -- These rows model history already on disk before 320/324, not a
            -- multi-million notification queue produced by fixture INSERTs.
            truncate semantic_import_dirty320,semantic_default_dirty320;
            select 'seeded';
            """);
        string installation=JsonNode.Parse(scope)!["installation_id"]!.GetValue<string>();
        var queries=new Dictionary<string,string> {
            ["native"]=$"select * from read_t109_native('{scope}'::jsonb)",
            ["watch"]=$"select * from read_account_watch_events('{installation}','sli.windows.ad-dc',md5('semantic-host')::uuid::text,md5('semantic-host')::uuid::text,repeat('a',64),null)",
            ["receipt_gap"]=$"""
                select not exists(select 1 from public.sli_agent_receipts r
                    where r.agent_id=md5('semantic-agent')::uuid and r.module_id='sli.file-audit'
                      and r.envelope->>'generation'='history' and (r.envelope->>'sequence')::bigint<{packets+2}
                      and r.envelope->>'continuity_state'='gap'
                      and (nullif(r.envelope->'cursor_after'->>'token','')::jsonb->>'record_id')::bigint>=1000)
                """
        };
        var results=new Dictionary<string,string>();
        var plans=new JsonObject { ["scale_percent"]=scale,["core_rows"]=totalCore+3,["normalized_rows"]=normalized+2,["inbox_rows"]=packets+1,["receipt_rows"]=packets+1 };
        // Nested auto_explain captures the actual stored query trees as well as
        // top-level EXPLAIN counters, including all function tuplestores.
        await worker.CloseAsync();
        await Scalar("""
            load 'auto_explain';set auto_explain.log_min_duration=-1;
            alter role sli_semantic_login set session_preload_libraries='auto_explain';
            alter role sli_semantic_login set auto_explain.log_min_duration=0;
            alter role sli_semantic_login set auto_explain.log_nested_statements=on;
            alter role sli_semantic_login set auto_explain.log_analyze=on;
            alter role sli_semantic_login set auto_explain.log_buffers=on;
            alter role sli_semantic_login set auto_explain.log_format=json;select 'loaded';
            """);
        await worker.OpenAsync(ct);
        await PostCollectionPostgres.Sql(worker,"set role adlog_semantic_worker;set statement_timeout=0;set work_mem='4MB';set plan_cache_mode=force_generic_plan",ct);
        string outputDir=Path.Combine(SqlPostgresFixture.Repository(),".net-local/wk33");Directory.CreateDirectory(outputDir);
        foreach(string stage in new[]{"before","after"}) {
            if(stage=="after") {
                string migration=Path.Combine(SqlPostgresFixture.Repository(),"config/postgres_migrations/324_detector_query_paths.sql");
                await fixture.Pg.ApplyFileAsync(migration,null,ct);
                // Bootstrap is measured separately and commits every 512 keys;
                // it is never hidden in the detector timings.
                var timer=System.Diagnostics.Stopwatch.StartNew();int portions=0;
                while(await Scalar("select (not bootstrap_done or exists(select 1 from semantic_import_dirty320))::text from semantic_import_state320")=="true") {
                    await Scalar("select semantic_import_refresh320();select 'refreshed'");Assert.True(++portions<10000);
                    if(portions%32==0)output.WriteLine($"324 bootstrap portions committed: {portions}");
                }
                plans["bootstrap_ms"]=timer.Elapsed.TotalMilliseconds;plans["bootstrap_portions"]=portions;
                await Scalar("analyze semantic_event_facts320;analyze semantic_stream_facts320;select 'analyzed'");
            }
            foreach(var (name,originalQuery) in queries) {
                string query=originalQuery;
                if(stage=="after"&&name=="receipt_gap")query=query.Replace("and r.envelope->>'generation'='history'","and md5(r.envelope->>'generation')=md5('history') and r.envelope->>'generation'='history'",StringComparison.Ordinal);
                NpgsqlConnection connection=name=="receipt_gap"?db:worker;
                string result=await Scalar("select coalesce(jsonb_agg(to_jsonb(r) order by to_jsonb(r)::text),'[]')::text from ("+query+") r",connection);
                if(stage=="before")results[name]=result;else Assert.Equal(results[name],result);
                var plan=JsonNode.Parse(await Scalar("explain(analyze,buffers,format json) "+query,connection))!;
                plans[stage+"_"+name]=plan;
                output.WriteLine($"324 {stage} {name}: ms={plan[0]!["Execution Time"]},temp_read={plan[0]!["Plan"]!["Temp Read Blocks"]},temp_written={plan[0]!["Plan"]!["Temp Written Blocks"]}");
                if(stage=="after")Assert.Equal(0,plan[0]!["Plan"]!["Temp Written Blocks"]!.GetValue<int>());
                await File.WriteAllTextAsync(Path.Combine(outputDir,"plans324.json"),plans.ToJsonString(new(){WriteIndented=true}),ct);
            }
        }
        Assert.Single(JsonNode.Parse(results["native"])!.AsArray());Assert.Equal(2,JsonNode.Parse(results["watch"])!.AsArray().Count);
        await File.WriteAllTextAsync(Path.Combine(outputDir,"nested324.log"),await fixture.Pg.DiagnosticsAsync(ct),ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Schema323_accepts324_and_rollback_preserves_authority_and_results()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:323);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString);await db.OpenAsync(ct);
        await SemanticRuntimePostgresTests.SeedNative(db,ct,canonicalAssignment:true);
        await using var worker=new NpgsqlConnection(fixture.Dsn("sli_semantic_login"));await worker.OpenAsync(ct);
        await PostCollectionPostgres.Sql(worker,"set role adlog_semantic_worker",ct);
        async Task<string> Scalar(string sql,NpgsqlConnection? connection=null) {
            await using var q=new NpgsqlCommand(sql,connection??db){CommandTimeout=0};return (string)(await q.ExecuteScalarAsync(ct))!;
        }
        const string discover="select coalesce(jsonb_agg(source order by source::text),'[]')::text from t109_detection_sources()";
        // The migration owns this historical import contract. The current runtime
        // no longer refreshes it after the move to the short-event store.
        async Task RefreshHistoricalSummary() {
            await PostCollectionPostgres.Sql(worker,"select public.semantic_import_refresh320();select public.semantic_default_refresh320()",ct);
            Assert.Equal("false",await Scalar("select public.semantic_import_progress320()->>'pending'",worker));
        }
        await RefreshHistoricalSummary();
        string before=await Scalar(discover,worker);
        string scope=JsonNode.Parse(before)![0]!["scope"]!.ToJsonString();
        string native=$"select coalesce(jsonb_agg(to_jsonb(r) order by native_id),'[]')::text from read_t109_native('{scope}'::jsonb) r";
        string expected=await Scalar(native,worker);Assert.Single(JsonNode.Parse(expected)!.AsArray());
        string directory=Path.Combine(SqlPostgresFixture.Repository(),"config/postgres_migrations");
        string forward=Path.Combine(directory,"324_detector_query_paths.sql"),rollback=Path.Combine(directory,"324_detector_query_paths.rollback.sql");
        const string catalog="select jsonb_agg(to_jsonb(p) order by oid)::text from pg_proc p where oid in ('semantic_source_candidates320(uuid,jsonb,text,text,timestamptz,timestamptz,uuid)'::regprocedure,'read_account_watch_events(uuid,text,text,text,text,uuid)'::regprocedure,'sli_plugin_workstations.inventory_inputs_v1(bigint)'::regprocedure,'file_decoy_contexts(uuid,text,text,text)'::regprocedure)";
        string original=await Scalar(catalog);
        for(int pass=0;pass<2;pass++) {
            await fixture.Pg.ApplyFileAsync(forward,null,ct);
            Assert.Equal("324",await Scalar("select max(version)::text from schema_migrations"));
            await RefreshHistoricalSummary();
            Assert.Equal(before,await Scalar(discover,worker));Assert.Equal(expected,await Scalar(native,worker));
            Assert.Equal("7",await Scalar("select count(*)::text from pg_index i join pg_class c on c.oid=i.indexrelid where c.relname like 'detector_%324' and i.indisvalid and i.indisready"));
            Assert.Equal("true",await Scalar("select (not has_table_privilege('adlog_semantic_worker','detector_definitions324','SELECT'))::text"));
            if(pass==0) {
                await fixture.Pg.ApplyFileAsync(rollback,null,ct);
                Assert.Equal("323",await Scalar("select max(version)::text from schema_migrations"));
                Assert.Equal(original,await Scalar(catalog));
                await RefreshHistoricalSummary();
                Assert.Equal(before,await Scalar(discover,worker));Assert.Equal(expected,await Scalar(native,worker));
            }
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
