using System.Text.Json.Nodes;
using Npgsql;
using Xunit;

namespace Sli.Server.Tests;

public sealed partial class SemanticLargeDatabaseTests
{
    [Fact]
    public async Task Remaining327_matches326_and_bounds_reads()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:326);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString);await db.OpenAsync(ct);
        async Task<string> Scalar(string sql) {
            await using var q=new NpgsqlCommand(sql,db){CommandTimeout=0};return (string)(await q.ExecuteScalarAsync(ct))!;
        }
        await SemanticRuntimePostgresTests.SeedNative(db,ct,canonicalAssignment:true);
        // Reuse canonical history, native evidence, labels, AD validity and live
        // constraints/triggers. No stand connection, substitute tables or grants.
        string seed=Seed315.Replace("150000","30000",StringComparison.Ordinal).Replace("200000","100000",StringComparison.Ordinal)
            .Replace("case when sequence%3=0 then null when sequence%3=1 then '' else 'Security' end","'System'",StringComparison.Ordinal);
        // Typical bounded agent packets, rather than 99840 events in one raw
        // file: otherwise PostgreSQL's average raw-file cardinality estimate
        // deliberately chooses a core scan even for packets with no raw file.
        int rawStart=seed.IndexOf("insert into raw_log_files",StringComparison.Ordinal);
        int coreStart=seed.IndexOf("insert into events_v2_core",rawStart,StringComparison.Ordinal);
        seed=seed[..rawStart]+"""
            insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
            select 900002+r.sequence,900001,(select id from log_sources where name='Security'),
                'agent-packet:'||r.packet_id,'jsonl',encode(sha256(r.packet_id::text::bytea),'hex')
                from sli_agent_receipts r where sequence>1;
            """+seed[coreStart..];
        seed=seed.Replace("case when n<=160 then 900001 else 900004 end","case when n<=160 then 900001 else 900004+(n%30000) end",StringComparison.Ordinal);
        int inboxStart=seed.IndexOf("insert into sli_agent_packet_inbox",StringComparison.Ordinal),inboxEnd=seed.IndexOf("-- Newest",StringComparison.Ordinal);
        await Scalar(seed[..inboxStart]+"select 'seeded'");
        for(int lower=1;lower<=30000;lower+=1000)
            await Scalar(seed[inboxStart..inboxEnd].Replace("where sequence>1",$"where sequence>{lower} and sequence<={lower+1000}",StringComparison.Ordinal)+"select 'seeded'");
        await Scalar(seed[inboxEnd..]+"select 'seeded'");
        await Scalar("""
            insert into storage_v2_entity_type(value) values('ad_computer'),('device') on conflict do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
            select 200000+n,(select id from storage_v2_entity_type where value='ad_computer'),
                'synthetic-computer:'||n,'synthetic',1,sha256(n::text::bytea) from generate_series(1,100000) n;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
            select 400001,(select id from storage_v2_entity_type where value='device'),
                'core:'||encode(sha256(convert_to('["device","sli.agent.key","agent-registry","'||md5('semantic-agent')::uuid::text||'"]','UTF8')),'hex'),
                'synthetic device',1,sha256('device'::bytea);
            update sli_agents set assigned_modules=assigned_modules||'[{"module_id":"sli.workstations","enabled":true}]'::jsonb;
            insert into core_entity_observations(observation_sha256,plugin_id,source_instance_id,entity_kind,entity_id,
                observed_at_utc,identifiers_json,evidence_refs,resolution)
            select sha256(n::text::bytea),'sli.workstations',md5('semantic-host')::uuid::text,'device',400001,
                '2026-11-01'::timestamptz+n*interval '1 microsecond','[{}]',array['synthetic:'||n],'resolved'
                from generate_series(1,100000) n;
            insert into core_entity_associations(source_entity_id,target_entity_id,relation,actor_id,evidence_refs)
            select 400001,200001,'directory_computer',id,array['synthetic'] from auth_users limit 1;
            insert into finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,source_instance_id,source_generation,
                collection_scope_id,storage_kind,log_source_id,agent_id)
            select 'sli_semantic_login'::regrole,'sli_semantic_login',installation_id,'sli.windows.ad-dc','history-source','history',
                '','core_event',(select id from log_sources where name='Security'),md5('semantic-agent')::uuid from semantic_default_installation;
            analyze entities_v2;analyze core_entity_observations;analyze core_entity_associations;
            select 'seeded';
            """);
        // The steady-state decoy measurement excludes bootstrap work, which
        // remains a separately measured complete-history T109 boundary below.
        while(await Scalar("select bootstrap_done::text from semantic_import_state320 where singleton")!="true")
            await Scalar("select public.semantic_import_refresh320()::text");
        await Scalar("""
            set role adlog_storage_owner;
            create function public.test_plan327(q text) returns text language plpgsql security definer as $$
            declare result text;begin execute 'explain(analyze,buffers,format json) '||q into result;return result;end $$;
            grant execute on function public.test_plan327(text) to adlog_semantic_worker;
            reset role;
            create function public.test_result327(q text) returns text language plpgsql as $$
            declare result text;begin execute q into result;return result;
            exception when others then return sqlstate;end $$;
            select 'created';
            """);
        string installation=await Scalar("select installation_id::text from semantic_default_installation");
        string logSource=await Scalar("select id::text from log_sources where name='Security'");
        const string decoySignature="public.read_account_decoy_events(uuid,text,text,text,text,uuid)";
        const string directorySignature="sli_plugin_workstations.inventory_inputs_v1(bigint)";
        const string functions="'public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure,'sli_plugin_workstations.inventory_inputs_v1(bigint)'::regprocedure";
        string catalogSql=$"select jsonb_agg(to_jsonb(p)-'prosrc' order by oid)::text from pg_proc p where oid in ({functions})";
        string definitionsSql=$"select jsonb_agg(pg_get_functiondef(oid) order by oid)::text from pg_proc where oid in ({functions})";
        string catalog=await Scalar(catalogSql),definitions=await Scalar(definitionsSql);
        string Decoy(string reference="null",string checkpoint="repeat('a',64)") =>
            $"select coalesce(jsonb_agg(to_jsonb(r) order by normalized_event_id),'[]')::text from read_account_decoy_events('{installation}','sli.windows.ad-dc',md5('semantic-host')::uuid::text,md5('semantic-host')::uuid::text,{checkpoint},{reference}) r";
        const string login="set session authorization sli_semantic_login;set role adlog_semantic_worker;";
        const string reset="reset role;reset session authorization;";
        var cases=new (string Name,string Mutation,string Query)[] {
            ("batch","",Decoy()),
            ("explicit","",Decoy("md5('normalized:1')::uuid")),
            ("missing explicit","",Decoy("md5('missing')::uuid")),
            ("invalid checkpoint","",Decoy(checkpoint:"'invalid'")),
            ("acknowledged","insert into semantic_account_decoy_checks(checkpoint_key,normalized_event_id,scope_json,result_code) values(repeat('a',64),md5('normalized:1')::uuid,'{}','no_match')",Decoy("md5('normalized:1')::uuid")),
            ("principal name","update finding_evidence_source_bindings set principal_name='foreign'",Decoy()),
            ("principal OID","update finding_evidence_source_bindings set principal_oid='adlog_user'::regrole",Decoy()),
            ("disabled","update sli_agents set status='disabled'",Decoy()),
            ("expired label","update decoy_label_versions set active_to='2026-10-31'",Decoy()),
            ("source proof","update sli_agent_packet_inbox set envelope=envelope||'{\"foreign\":true}' where packet_id=md5('semantic-packet')::uuid",Decoy()),
        };
        async Task<string[]> Snapshot() {
            var results=new List<string>();
            foreach(string mode in new[]{"force_custom_plan","force_generic_plan"})
            foreach(var c in cases) {
                await using var tx=await db.BeginTransactionAsync(ct);
                try {
                    if(c.Mutation.Length>0)await Scalar(c.Mutation+";select 'mutated'");
                    await Scalar(login+$"set plan_cache_mode={mode};select 'login'");
                    string result=await Scalar("select public.test_result327($q$"+c.Query+"$q$)");
                    if(c.Name=="batch")Assert.Equal(128,JsonNode.Parse(result)!.AsArray().Count);
                    if(c.Name=="explicit")Assert.Single(JsonNode.Parse(result)!.AsArray());
                    if(c.Name.StartsWith("principal",StringComparison.Ordinal)||c.Name=="invalid checkpoint")Assert.Equal("42501",result);
                    results.Add(result);
                } finally {await tx.RollbackAsync(ct);await Scalar(reset+"select 'reset'");}
            }
            return results.ToArray();
        }
        const string smallDirectory="""
            update storage_v2_entity_type set value='synthetic-large-computers' where value='ad_computer';
            insert into storage_v2_entity_type(value) values('ad_computer');
            update entities_v2 set entity_type_id=(select id from storage_v2_entity_type where value='ad_computer') where id in(200001,200002);
            """;
        async Task<string[]> DirectorySnapshot() {
            var values=new List<string>();
            foreach(bool small in new[]{false,true}) {
                await using var tx=await db.BeginTransactionAsync(ct);
                try {
                    if(small)await Scalar(smallDirectory+"select 'small'");
                    string result=await Scalar("select public.test_result327('select sli_plugin_workstations.inventory_inputs_v1(1)::text')");
                    if(!small)Assert.Equal("P0001",result);
                    else {
                        var value=JsonNode.Parse(result)!;
                        Assert.Equal(2,value["directory"]!.AsArray().Count);Assert.Single(value["devices"]!.AsArray());
                        Assert.Single(value["agents"]!.AsArray());Assert.Single(value["associations"]!.AsArray());
                    }
                    values.Add(result);
                } finally {await tx.RollbackAsync(ct);}
            }
            return values.ToArray();
        }
        async Task<JsonNode> Plan(string name,string sql,bool worker=false) {
            await using var tx=await db.BeginTransactionAsync(ct);
            try {
                if(worker)await Scalar(login+"select 'login'");
                var plan=JsonNode.Parse(await Scalar(worker?"select public.test_plan327($q$"+sql+"$q$)":"explain(analyze,buffers,format json) "+sql))!;
                output.WriteLine($"327 {name}: ms={plan[0]!["Execution Time"]}; hit={plan[0]!["Plan"]!["Shared Hit Blocks"]}; read={plan[0]!["Plan"]!["Shared Read Blocks"]}");
                return plan;
            } finally {await tx.RollbackAsync(ct);await Scalar(reset+"select 'reset'");}
        }
        async Task<string> DecoySql() {
            string definition=await Scalar($"select pg_get_functiondef('{decoySignature}'::regprocedure)");
            int first=definition.IndexOf("    with source_candidates",StringComparison.Ordinal),last=definition.LastIndexOf(";\nend",StringComparison.Ordinal);
            return definition[first..last]
                .Replace("source_binding.agent_id","md5('semantic-agent')::uuid",StringComparison.Ordinal)
                .Replace("source_binding.log_source_id",logSource,StringComparison.Ordinal)
                .Replace("p_installation",$"'{installation}'::uuid",StringComparison.Ordinal).Replace("p_plugin","'sli.windows.ad-dc'",StringComparison.Ordinal)
                .Replace("p_source","md5('semantic-host')::uuid::text",StringComparison.Ordinal).Replace("p_generation","md5('semantic-host')::uuid::text",StringComparison.Ordinal)
                .Replace("p_checkpoint","repeat('a',64)",StringComparison.Ordinal).Replace("p_normalized","null::uuid",StringComparison.Ordinal);
        }
        async Task<string> DirectorySql() {
            string definition=await Scalar($"select pg_get_functiondef('{directorySignature}'::regprocedure)");
            return definition.Split("$directory_query$")[1].Replace("$1","(select id from storage_v2_entity_type where value='ad_computer')",StringComparison.Ordinal).Replace("$2","0",StringComparison.Ordinal);
        }
        // Full-history fallback cannot be replaced by an incomplete 320 summary.
        // Measure its exact admission query independently of the default reader.
        string fullDefinition=await Scalar("select pg_get_functiondef('public.semantic_t109_full320()'::regprocedure)");
        int fullFirst=fullDefinition.IndexOf("    with assignments as materialized",StringComparison.Ordinal);
        int fullLast=fullDefinition.IndexOf("    on conflict do nothing;",fullFirst,StringComparison.Ordinal);
        string fullSql=fullDefinition[fullFirst..fullLast]
            .Replace("    insert into public.semantic_t109_channels\n","",StringComparison.Ordinal)
            .Replace("login","'sli_semantic_login'::regrole::oid",StringComparison.Ordinal);
        var fullPlan=await Plan("before full T109 admission",fullSql,true);
        Assert.Contains(PlanNodes(fullPlan[0]!["Plan"]!),n=>n["Relation Name"]?.ToString()=="events_v2_core"&&n["Actual Rows"]!.GetValue<double>()*n["Actual Loops"]!.GetValue<double>()>=99000);
        // Compare complete JSON, every output field, role failures, proof and
        // explicit-reference semantics on identical rolled-back input states.
        string[] before=await Snapshot(),directoryResults=await DirectorySnapshot();
        var oldDecoy=await Plan("before decoy",await DecoySql(),true);
        var oldDirectory=await Plan("before directory",await DirectorySql());
        Assert.Contains(PlanNodes(oldDecoy[0]!["Plan"]!),n=>n["Relation Name"]?.ToString()=="ad_context_entity_versions"&&n["Actual Rows"]!.GetValue<double>()*n["Actual Loops"]!.GetValue<double>()>=30000*128);
        string directoryBefore=await Scalar("select ("+await DirectorySql()+")::text");
        string path=Path.Combine(SqlPostgresFixture.Repository(),"config/postgres_migrations/327_detector_remaining_paths.sql");
        await fixture.Pg.ApplyFileAsync(path,null,ct);
        Assert.Equal(catalog,await Scalar(catalogSql));
        Assert.Equal(before,await Snapshot());
        Assert.Equal(directoryResults,await DirectorySnapshot());
        Assert.Equal(directoryBefore,await Scalar("select ("+await DirectorySql()+")::text"));
        var newDecoy=await Plan("after decoy",await DecoySql(),true);
        var identityScans=PlanNodes(newDecoy[0]!["Plan"]!).Where(n=>n["Relation Name"]?.ToString()=="ad_context_entity_versions").ToArray();
        Assert.NotEmpty(identityScans);
        Assert.All(identityScans,n=>Assert.True(n["Actual Rows"]!.GetValue<double>()*n["Actual Loops"]!.GetValue<double>()<=256,n.ToJsonString()));
        Assert.Contains(PlanNodes(newDecoy[0]!["Plan"]!),n=>n["Index Name"]?.ToString()=="identity_version_keys_v315");
        await Plan("after directory",await DirectorySql());
        string pageDefinition=await Scalar("select pg_get_functiondef('public.detector_directory_page327(integer)'::regprocedure)");
        var page=await Plan("directory page",pageDefinition.Split("$page$")[1].Replace("$1","(select id from storage_v2_entity_type where value='ad_computer')",StringComparison.Ordinal));
        var entityScans=PlanNodes(page[0]!["Plan"]!).Where(n=>n["Relation Name"]?.ToString()=="entities_v2").ToArray();
        Assert.NotEmpty(entityScans);
        Assert.All(entityScans,n=>Assert.True(n["Actual Rows"]!.GetValue<double>()*n["Actual Loops"]!.GetValue<double>()<=10001,n.ToJsonString()));
        Assert.Equal(fullDefinition,await Scalar("select pg_get_functiondef('public.semantic_t109_full320()'::regprocedure)"));
        await Plan("after full T109 admission (unchanged)",fullSql,true);
        // Real SECURITY DEFINER calls: internal helper plans alone must not
        // conceal history-wide scans. One identity and one provenance suffice.
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            const string counts="select jsonb_build_object('seq',seq_tup_read,'idx',idx_tup_fetch)::text from pg_stat_xact_user_tables where relid='core_entity_observations'::regclass";
            await Scalar(smallDirectory+"select 'small'");
            var prior=JsonNode.Parse(await Scalar(counts))!;
            await Scalar("select sli_plugin_workstations.inventory_inputs_v1(1)::text");
            var current=JsonNode.Parse(await Scalar(counts))!;
            Assert.Equal(0,current["seq"]!.GetValue<long>()-prior["seq"]!.GetValue<long>());
            Assert.InRange(current["idx"]!.GetValue<long>()-prior["idx"]!.GetValue<long>(),0,2);
            output.WriteLine("327 real directory: observation sequential tuples=0; indexed fetches="+(current["idx"]!.GetValue<long>()-prior["idx"]!.GetValue<long>()));
            await tx.RollbackAsync(ct);
        }
        // Both private helpers preserve existing view-only authority boundaries.
        Assert.Equal("false",await Scalar("select (has_function_privilege('adlog_semantic_worker','public.detector_directory_page327(integer)','EXECUTE') or has_function_privilege('adlog_user','public.detector_workstation_devices327(text,text)','EXECUTE') or has_table_privilege('adlog_semantic_worker','detector_definitions327','SELECT'))::text"));
        output.WriteLine("327 new index: "+await Scalar("select jsonb_build_object('rows',100000,'bytes',pg_relation_size('detector_device_provenance327'),'projected_3470000',ceil(pg_relation_size('detector_device_provenance327')/100000.0*3470000),'valid',(select indisvalid and indisready from pg_index where indexrelid='detector_device_provenance327'::regclass))::text"));
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(path,".rollback.sql"),null,ct);
        Assert.Equal(definitions,await Scalar(definitionsSql));Assert.Equal(catalog,await Scalar(catalogSql));
        Assert.Equal("true",await Scalar("select (to_regprocedure('public.detector_directory_page327(integer)') is null and to_regclass('public.detector_device_provenance327') is null)::text"));
        await fixture.Pg.ApplyFileAsync(path,null,ct);
        output.WriteLine($"327: {before.Length} old/new decoy cases, complete directory JSON, catalogs, exact rollback and reapply passed");
    }
}
