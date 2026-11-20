using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Storage.Direct;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Detections;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests;

public sealed partial class SemanticLargeDatabaseTests
{
    private async Task Check318(SqlPostgresFixture fixture,NpgsqlConnection db,string scope,CancellationToken ct)
    {
        var added=Stopwatch.StartNew();
        string directory=Path.Combine(SqlPostgresFixture.Repository(),"config/postgres_migrations");
        string forward=Path.Combine(directory,"318_semantic_pending_candidates.sql"),rollback=Path.Combine(directory,"318_semantic_pending_candidates.rollback.sql");
        const string signatures="'public.read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure,'public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure";
        async Task<string> Scalar(string sql) {await using var q=new NpgsqlCommand(sql,db){CommandTimeout=25};return (string)(await q.ExecuteScalarAsync(ct))!;}
        string catalog=$"select jsonb_agg(to_jsonb(p)-'prosrc' order by oid)::text from pg_proc p where oid in ({signatures})";
        string definitions=$"select jsonb_agg(pg_get_functiondef(oid) order by oid)::text from pg_proc where oid in ({signatures})";
        string authority=await Scalar(catalog),original=await Scalar(definitions);
        string installation=JsonNode.Parse(scope)!["installation_id"]!.GetValue<string>();
        string decoy=$"select * from read_account_decoy_events('{installation}','sli.windows.ad-dc',md5('semantic-host')::uuid::text,md5('semantic-host')::uuid::text,repeat('a',64),@ref::uuid)";
        async Task<JsonArray> Read(bool t109,bool window=false,string? reference=null) {
            await using var login=new NpgsqlConnection(fixture.Dsn("sli_semantic_login"));await login.OpenAsync(ct);
            // The persistent producer can switch to a generic cached plan after
            // repeated scopes. Exercise that plan even with fresh real logins.
            await PostCollectionPostgres.Sql(login,"set role adlog_semantic_worker;set statement_timeout='20s';set plan_cache_mode=force_generic_plan",ct);
            string query=t109?"select * from read_t109_native(@scope::jsonb"+(window?",'2026-11-01','2026-11-02'":"")+")":decoy;
            var timer=Stopwatch.StartNew();
            await using var q=new NpgsqlCommand("select coalesce(jsonb_agg(to_jsonb(r) order by to_jsonb(r)::text),'[]')::text from ("+query+") r",login){CommandTimeout=25};
            q.Parameters.AddWithValue("scope",scope);q.Parameters.AddWithValue("ref",NpgsqlTypes.NpgsqlDbType.Uuid,reference is null?DBNull.Value:Guid.Parse(reference));
            var rows=JsonNode.Parse((string)(await q.ExecuteScalarAsync(ct))!)!.AsArray();
            if(t109)DetectionNative.ParseEvents(PasswordScope.Read(JsonNode.Parse(scope)),rows.Select(n=>n!.AsObject()).ToArray());
            output.WriteLine($"318 schema/read t109={t109},window={window},ref={reference is not null}: rows={rows.Count},ms={timer.Elapsed.TotalMilliseconds:F1}");
            Assert.True(timer.Elapsed<TimeSpan.FromSeconds(20));return rows;
        }
        bool full=Environment.GetEnvironmentVariable("SLI_SEMANTIC_PENDING_FULL_SCALE")=="1";
        int count=full?2000000:4000;
        var beforeNative=await Read(true);var beforeDecoy=await Read(false);
        Assert.Single(beforeNative);Assert.Equal(2,beforeDecoy.Count);
        await PostCollectionPostgres.Sql(db,"set statement_timeout=0",ct); // fixture loading only
        var load=Stopwatch.StartNew();
        // The stand shape: uncheckable imported history in the SAME log_source,
        // empty decoy checks, only 961 seen rows. None belongs to an agent packet.
        await PostCollectionPostgres.Sql(db,"""
            insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
            select 60000000,900001,id,'synthetic:legacy-domain.evtx','jsonl',repeat('d',64) from log_sources where name='Security';
            -- Many foreign hosts, retaining consistent receipt/inbox envelopes.
            update sli_agent_receipts set envelope=jsonb_set(envelope,'{source_instance_id}',to_jsonb(md5('foreign:'||packet_id)::uuid::text))
              where agent_id=md5('semantic-agent1')::uuid and sequence>10000;
            update sli_agent_packet_inbox i set envelope=r.envelope from sli_agent_receipts r
              where r.packet_id=i.packet_id and r.agent_id=md5('semantic-agent1')::uuid and r.sequence>10000;
            """,ct);
        for(int lower=1;lower<=count;lower+=100000)
        await using(var seed=new NpgsqlCommand("""
            insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,event_record_id,
                channel_id,provider_id,time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
            select 30000000+n,60000000,900001,(select domain_id from servers where id=900001),
                (select id from log_sources where name='Security'),case when n%2=0 then 1102 else 4624 end,30000000+n,
                (select id from storage_v2_channel where value='Security'),(select id from storage_v2_provider where value='Microsoft-Windows-Security-Auditing'),
                '2026-11-01','2026-11-01',sha256(n::text::bytea),sha256(n::text::bytea),
                (select version from event_catalog_revisions order by id limit 1)
            from generate_series(@lower,@upper) n;
            insert into normalized_events(normalized_event_id,source_event_id,semantic_contract_version,normalizer_id,normalizer_version,
                processing_status,normalized_at,source_event_sha256,semantic_sha256,semantic_type,occurred_at_utc,roles_json,source_ingested_at,source_identity_json)
            select md5('318-normalized:'||id)::uuid,id,1,'windows.named-eventdata','1','normalized',time_created_utc,
                normalized_hash,sha256(id::text::bytea),'authentication.session.created',time_created_utc,'{}',migrated_at,
                jsonb_build_object('id',id,'server_id',server_id,'domain_id',domain_id,'log_source_id',log_source_id,'event_id',event_id,
                    'time_created_utc',time_created_utc,'normalized_hash',encode(normalized_hash,'hex'),'migrated_at',migrated_at,'channel','Security')
            from events_v2_core where id between 30000000+@lower and 30000000+@upper and event_id=4624;
            """,db){CommandTimeout=300}) {
            seed.Parameters.AddWithValue("lower",lower);seed.Parameters.AddWithValue("upper",Math.Min(lower+99999,count));await seed.ExecuteNonQueryAsync(ct);
        }
        await using(var seed=new NpgsqlCommand("""
            insert into semantic_t109_seen(source_key,native_id,scope_json,storage_kind)
            select repeat('b',64),(30000000+n)::text,@scope::jsonb,'core_event' from generate_series(1,961) n;
            analyze events_v2_core;analyze normalized_events;analyze raw_log_files;analyze semantic_t109_seen;
            analyze sli_agent_packet_inbox;analyze sli_agent_receipts;
            """,db){CommandTimeout=300}) {seed.Parameters.AddWithValue("scope",scope);await seed.ExecuteNonQueryAsync(ct);}
        Assert.Equal("0",await Scalar("select count(*)::text from semantic_account_decoy_checks"));
        Assert.Equal("961",await Scalar("select count(*)::text from semantic_t109_seen"));
        output.WriteLine($"318 legacy fixture: core={count},normalized={count/2},seen=961,checks=0;load={load.Elapsed}");
        await fixture.Pg.ApplyFileAsync(forward,null,ct);Assert.Equal(authority,await Scalar(catalog));
        string selected=await Scalar("select pg_get_functiondef('public.read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure)");
        if(full) {
            string candidate=System.Text.RegularExpressions.Regex.Match(selected,@"for candidate in(.*?)\n\s*loop",System.Text.RegularExpressions.RegexOptions.Singleline).Groups[1].Value
                .Replace("p_start","@start",StringComparison.Ordinal).Replace("p_end","@end",StringComparison.Ordinal).Replace("seen.scope_json=s","seen.scope_json=@scope::jsonb",StringComparison.Ordinal);
            await using var explain=new NpgsqlCommand("explain(format json) select q.* from finding_evidence_source_bindings b cross join lateral ("+candidate+") q where b.principal_name='sli_semantic_login' and b.storage_kind='core_event' and b.source_instance_id=md5('semantic-host')::uuid::text",db);
            explain.Parameters.AddWithValue("scope",scope);explain.Parameters.AddWithValue("start",NpgsqlTypes.NpgsqlDbType.TimestampTz,DBNull.Value);explain.Parameters.AddWithValue("end",NpgsqlTypes.NpgsqlDbType.TimestampTz,DBNull.Value);
            string plan=(string)(await explain.ExecuteScalarAsync(ct))!;
            Assert.Contains("events_v2_core_raw_packet_lookup",plan);
            output.WriteLine("318 fenced core candidate plan: "+plan);
        }
        Assert.True(JsonNode.DeepEquals(beforeNative,await Read(true)));Assert.True(JsonNode.DeepEquals(beforeDecoy,await Read(false)));
        Assert.True(JsonNode.DeepEquals(beforeNative,await Read(true,true)));
        // Compare both window directions on the same distribution and real role.
        // The alternative rejects non-agent raw files before inbox probes.
        var relation=System.Text.RegularExpressions.Regex.Match(File.ReadAllText(forward).Replace("\r\n","\n"),@"new_sql text:=\$new\$(.*?)\$new\$",System.Text.RegularExpressions.RegexOptions.Singleline).Groups[1].Value;
        const string coreFirst="""
            from (
                select core.id,core.event_id,core.time_created_utc,core.normalized_hash,core.log_source_id,raw.file_path
                from public.events_v2_core core join public.raw_log_files raw on raw.id=core.raw_log_file_id
                where raw.file_path ~ '^agent-packet:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                  and (core.log_source_id=b.log_source_id or exists(select 1 from public.semantic_t109_channels c
                    where c.principal_oid=b.principal_oid and c.principal_name=b.principal_name
                      and c.installation_id=b.installation_id and c.source_instance_id=b.source_instance_id
                      and c.source_generation=b.source_generation and c.log_source_id=core.log_source_id))
                  and core.event_id in (4688,4104,1102,4719,7036,7040,7045)
                  and core.time_created_utc<=statement_timestamp()
                  and core.time_created_utc between p_start and p_end
                offset 0
            ) e cross join lateral (
                select i.packet_id from public.sli_agent_packet_inbox i
                where i.packet_id=substr(e.file_path,14)::uuid
                  and i.envelope->>'agent_id'=b.agent_id::text
                  and i.envelope->>'source_instance_id'=b.source_instance_id
                  and i.envelope->>'generation'=b.source_generation offset 0
            ) inbox
            """;
        Assert.Contains(relation,selected);
        try {
            await PostCollectionPostgres.Sql(db,selected.Replace(relation,coreFirst,StringComparison.Ordinal),ct);
            output.WriteLine("318 WINDOW CORE-FIRST (fast raw rejection)");
            Assert.True(JsonNode.DeepEquals(beforeNative,await Read(true,true)));
        } finally {await PostCollectionPostgres.Sql(db,selected,ct);}
        Assert.Equal(authority,await Scalar(catalog));
        Assert.Equal("0",await Scalar("select count(*)::text from pg_indexes where indexname='semantic_t109_seen_scope_v318'"));
        await fixture.Pg.ApplyFileAsync(rollback,null,ct);Assert.Equal(original,await Scalar(definitions));Assert.Equal(authority,await Scalar(catalog));
        await fixture.Pg.ApplyFileAsync(forward,null,ct); // actual previous maximum317 ->318
        await using(var mark=new NpgsqlCommand("""
            insert into semantic_t109_seen(source_key,native_id,scope_json,storage_kind) values(repeat('b',64),'900001',@scope::jsonb,'core_event');
            insert into semantic_account_decoy_checks(checkpoint_key,normalized_event_id,scope_json,result_code)
            select repeat('a',64),normalized_event_id,@scope::jsonb,'no_match' from normalized_events where source_event_id in(900002,900003);
            """,db)) {mark.Parameters.AddWithValue("scope",scope);await mark.ExecuteNonQueryAsync(ct);}
        Assert.Empty(await Read(true));Assert.Empty(await Read(false));
        // Explicit context and publication rereads bypass seen/checks, unchanged.
        Assert.Single(await Read(true,true));
        Assert.Single(await Read(false,reference:beforeDecoy[0]!["normalized_event_id"]!.GetValue<string>()));
        // Insert real late native events older than the already-checked tail.
        var nativeRows=JsonNode.Parse(await Scalar("select event_rows::text from sli_agent_packet_inbox where packet_id=md5('semantic-packet')::uuid"))!.AsArray();
        foreach((int code,int record,long id) in new[]{(1102,10,50000010L),(4624,11,50000011L),(1102,12,50000012L),(1102,13,50000013L),(4624,14,50000014L)}) {
            var native=nativeRows.First(n=>n!["event_id"]!.GetValue<int>()==code)!.DeepClone().AsObject();
            string stamp=record==10?"2026-10-01T00:00:00,123456+0000":record>=13?"2026-10-01T00:00:00.1234565Z":"2026-10-01T00:00:00.1234567Z";
            int oldRecord=native["record_id"]!.GetValue<int>();native["record_id"]=record;
            native["time_created"]=record==10?"2026-10-01T00:00:00.123456Z":stamp;
            native["xml"]=native["xml"]!.GetValue<string>().Replace($"<EventRecordID>{oldRecord}</EventRecordID>",$"<EventRecordID>{record}</EventRecordID>").Replace("2026-11-01T00:00:00Z",stamp);
            if(code==1102)native["xml"]=native["xml"]!.GetValue<string>().Replace("</Event>","<EventData><Binary>00</Binary></EventData></Event>");
            nativeRows.Add(native);
            string hash=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(SourceJson.SerializeSorted(native))));
            await using var late=new NpgsqlCommand("""
                update sli_agent_packet_inbox set event_rows=@rows::jsonb where packet_id=md5('semantic-packet')::uuid;
                insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,event_record_id,channel_id,provider_id,
                    time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
                select @id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,@record,channel_id,provider_id,
                    @at::timestamptz,now(),decode(@hash,'hex'),decode(@hash,'hex'),noise_catalog_version from events_v2_core where id=@original;
                """,db);
            late.Parameters.AddWithValue("rows",nativeRows.ToJsonString());late.Parameters.AddWithValue("id",id);late.Parameters.AddWithValue("record",record);late.Parameters.AddWithValue("hash",hash);late.Parameters.AddWithValue("original",code==1102?900001:900002);
            late.Parameters.AddWithValue("at",DirectEventTime.IsoUtc(native["time_created"]!.GetValue<string>()));await late.ExecuteNonQueryAsync(ct);
        }
        await PostCollectionPostgres.Sql(db,"""
            insert into normalized_events(normalized_event_id,source_event_id,semantic_contract_version,normalizer_id,normalizer_version,
                processing_status,normalized_at,source_event_sha256,semantic_sha256,semantic_type,occurred_at_utc,roles_json,source_ingested_at,source_identity_json)
            select md5('late-normalized:'||id)::uuid,id,1,'windows.named-eventdata','1','normalized',now(),normalized_hash,sha256(id::text::bytea),
                'authentication.session.created',time_created_utc,'{}',migrated_at,jsonb_build_object('id',id,'server_id',server_id,'domain_id',domain_id,
                    'log_source_id',log_source_id,'event_id',event_id,'time_created_utc',time_created_utc,'normalized_hash',encode(normalized_hash,'hex'),
                    'migrated_at',migrated_at,'channel','Security') from events_v2_core where id in(50000011,50000014);
            """,ct);
        var lateNative=await Read(true);Assert.Equal(new[]{"50000010","50000012","50000013"},lateNative.Select(n=>D.Text(n!["native_id"])).Order().ToArray());
        var lateDecoy=await Read(false);Assert.Equal(new[]{50000011L,50000014L},lateDecoy.Select(n=>n!["source_event_id"]!.GetValue<long>()).Order().ToArray());
        await using(var login=new NpgsqlConnection(fixture.Dsn("sli_semantic_login"))) {
            await login.OpenAsync(ct);await PostCollectionPostgres.Sql(login,"set role adlog_semantic_worker",ct);
            await using var tx=await login.BeginTransactionAsync(ct);
            var parsed=await DetectionProducer.ReadIdentity(new DetectionSql(login,tx),PasswordScope.Read(JsonNode.Parse(scope)),ct,[50000011,50000014]);
            Assert.Equal(2,parsed.Count);Assert.Contains(parsed,r=>r.At.Microsecond==457);Assert.Contains(parsed,r=>r.At.Microsecond==456);
        }
        await CheckAclProof318(fixture,db,ct);
        output.WriteLine($"318 additional checks: {added.Elapsed}; legacy events={count}");
    }

    private static async Task CheckAclProof318(SqlPostgresFixture fixture,NpgsqlConnection db,CancellationToken ct)
    {
        using var stream=typeof(SemanticLargeDatabaseTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Semantic.Fixtures.native-reference.json")!;
        var vector=JsonNode.Parse(stream)!["acl"]!;var snapshot=vector["snapshot"]!;var result=vector["result"]!;
        string agent=D.Text(result["agent_id"]),source=D.Text(result["source_instance_id"]);
        await using(var seed=new NpgsqlCommand("""
            insert into sli_agents(id,host_id,key_fingerprint,assigned_modules) values(@agent::uuid,@source::uuid,repeat('f',64),
                jsonb_build_array(jsonb_build_object('module_id','sli.file-audit','enabled',true,'config',@config::jsonb)));
            insert into sli_plugin_file_audit.policy_revisions(agent_id,source_instance_id,revision,authored_at,actor_kind,actor_id,policy,policy_sha256)
            values(@agent::uuid,@source,1,now(),'session',1,@config::jsonb,encode(sha256(convert_to((@config::jsonb)::text,'UTF8')),'hex'));
            insert into sli_plugin_file_audit.audit_commands(command_id,agent_id,source_instance_id,policy_revision,action,collection_scope_ids,requested_at,actor_kind,actor_id,command_sha256)
            values('synthetic-command',@agent::uuid,@source,1,'check',array['synthetic-root'],now(),'session',1,
                encode(sha256(convert_to(jsonb_build_object('contract_id','sli.file-audit.audit-command.v1','command_id','synthetic-command',
                    'action','check','policy_revision','1','collection_scope_ids',jsonb_build_array('synthetic-root'))::text,'UTF8')),'hex'));
            insert into sli_plugin_file_audit.audit_receipts(receipt_id,command_id,agent_id,source_instance_id,policy_revision,action,collection_scope_id,state,observed_at,result_sha256)
            values(md5('318-acl-receipt')::uuid,'synthetic-command',@agent::uuid,@source,1,'check','synthetic-root','verified','2026-01-01',@snapshot::jsonb->>'snapshot_sha256');
            insert into sli_plugin_file_audit.access_snapshots(snapshot_id,agent_id,source_instance_id,collection_scope_id,observed_at,contract_version,completeness,snapshot_sha256,snapshot,unread_objects)
            values((@snapshot::jsonb->>'snapshot_id')::uuid,@agent::uuid,@source,'synthetic-root','2026-01-01',1,'complete',@snapshot::jsonb->>'snapshot_sha256',@snapshot::jsonb,0);
            insert into findings(id,fingerprint,rule_code,title,severity) values(318001,'318-synthetic-acl','file-audit.broad-write','synthetic','medium');
            insert into sli_plugin_file_audit.rule_results(result_id,finding_id,agent_id,source_instance_id,collection_scope_id,rule_code,rule_version,conclusion_state,observed_at,result,result_sha256)
            values(@result::jsonb->>'result_id',318001,@agent::uuid,@source,'synthetic-root','file-audit.broad-write',1,'observed','2026-01-01',@result::jsonb,
                encode(sha256(convert_to((@result::jsonb)::text,'UTF8')),'hex'));
            insert into sli_plugin_file_audit.rule_snapshots(result_id,snapshot_id) values(@result::jsonb->>'result_id',(@snapshot::jsonb->>'snapshot_id')::uuid);
            """,db)) {
            seed.Parameters.AddWithValue("agent",agent);seed.Parameters.AddWithValue("source",source);seed.Parameters.AddWithValue("config",vector["config"]!.ToJsonString());
            seed.Parameters.AddWithValue("snapshot",snapshot.ToJsonString());seed.Parameters.AddWithValue("result",result.ToJsonString());await seed.ExecuteNonQueryAsync(ct);
        }
        await using var worker=new NpgsqlConnection(fixture.Dsn("sli_semantic_login"));await worker.OpenAsync(ct);
        await PostCollectionPostgres.Sql(worker,"set role adlog_semantic_worker;set statement_timeout='20s'",ct);
        var resource=new JsonObject{["agent_id"]=agent,["plugin_id"]="sli.file-audit",["source_instance_id"]=source,["collection_scope_id"]="synthetic-root"};
        await using(var installation=new NpgsqlCommand("select installation_id::text from semantic_default_installation",db))resource["installation_id"]=(string)(await installation.ExecuteScalarAsync(ct))!;
        async Task<JsonObject> Page() {
            await using var query=new NpgsqlCommand("select read_file_acl_results(@resource::jsonb)::text",worker);query.Parameters.AddWithValue("resource",resource.ToJsonString());
            return JsonNode.Parse((string)(await query.ExecuteScalarAsync(ct))!)!.AsObject();
        }
        var good=await Page();Assert.Single(good["items"]!.AsArray());Assert.Equal(D.Text(vector["severity"]),D.Text(good["items"]![0]!["severity"]));
        // A retained result without a valid command/readback is real missing
        // proof, not a .NET conversion error. Python calls this exact SQL gate.
        foreach(string mutation in new[]{
            "delete from sli_plugin_file_audit.rule_snapshots where result_id='"+D.Text(result["result_id"])+"'",
            "delete from sli_plugin_file_audit.audit_receipts where command_id='synthetic-command'",
            "update sli_plugin_file_audit.access_snapshots set snapshot_sha256=repeat('0',64) where agent_id='"+agent+"'"}) {
            await using var tx=await db.BeginTransactionAsync(ct);
            await PostCollectionPostgres.Sql(db,mutation,ct);
            // Separate worker cannot see uncommitted fixture tampering; query as
            // the actual login in this transaction, then roll back the fixture.
            await PostCollectionPostgres.Sql(db,"set local session authorization sli_semantic_login;set local role adlog_semantic_worker",ct);
            await using var query=new NpgsqlCommand("select read_file_acl_results(@resource::jsonb)::text",db,tx);query.Parameters.AddWithValue("resource",resource.ToJsonString());
            var blocked=JsonNode.Parse((string)(await query.ExecuteScalarAsync(ct))!)!.AsObject();Assert.Empty(blocked["items"]!.AsArray());Assert.Equal(1,blocked["diagnostics"]!["snapshot_proof_mismatch"]!.GetValue<int>());
            var diagnostics=new DetectionDiagnostics();diagnostics.FileAcl(blocked["diagnostics"]!.AsObject());Assert.Equal(1,diagnostics.Counts["file_acl_source_diagnostics"]!.GetValue<int>());
            await tx.RollbackAsync(ct);
        }
        Assert.Single((await Page())["items"]!.AsArray());
        // A bad old snapshot sorts before the valid result in the same page.
        // Python and .NET share this SQL reader: record the refusal, keep the
        // valid neighbor, then suppress only the failed proof for five minutes.
        await PostCollectionPostgres.Sql(db,"""
            insert into sli_plugin_file_audit.rule_results(result_id,finding_id,agent_id,source_instance_id,collection_scope_id,
                rule_code,rule_version,conclusion_state,observed_at,result,result_sha256)
            select repeat('0',64),finding_id,agent_id,source_instance_id,collection_scope_id,rule_code,rule_version,conclusion_state,
                observed_at-interval '1 second',bad,encode(sha256(convert_to(bad::text,'UTF8')),'hex')
            from sli_plugin_file_audit.rule_results r cross join lateral (
                select jsonb_set(jsonb_set(r.result,'{result_id}',to_jsonb(repeat('0',64))),'{snapshot_ids}','[]') as bad
            ) b;
            """,ct);
        var mixed=await Page();Assert.Single(mixed["items"]!.AsArray());Assert.Equal(1,mixed["diagnostics"]!["snapshot_proof_mismatch"]!.GetValue<int>());
        Assert.Equal(D.Text(result["result_id"]),D.Text(mixed["items"]![0]!["result"]!["result_id"]));
        var next=await Page();Assert.Single(next["items"]!.AsArray());Assert.Empty(next["diagnostics"]!.AsObject());
    }
}
