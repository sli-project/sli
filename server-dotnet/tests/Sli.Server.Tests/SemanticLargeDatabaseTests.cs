using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests;

public sealed partial class SemanticLargeDatabaseTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Schema309_accepts310_with_identical_discovery_and_admission_on_large_core()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct, throughVersion: 311);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString);await db.OpenAsync(ct);
        string directory=Path.Combine(SqlPostgresFixture.Repository(),"config/postgres_migrations");
        string forward=Path.Combine(directory,"310_semantic_discovery_streams.sql"),rollback=Path.Combine(directory,"310_semantic_discovery_streams.rollback.sql");
        await fixture.Pg.ApplyFileAsync(Path.Combine(directory,"311_semantic_inbox_admission.rollback.sql"),null,ct);
        await fixture.Pg.ApplyFileAsync(rollback,null,ct);
        async Task<string> Scalar(string sql) {await using var c=new NpgsqlCommand(sql,db);return (string)(await c.ExecuteScalarAsync(ct))!;}
        const string authoritySql="select jsonb_build_object('oid',oid,'owner',proowner,'acl',proacl::text,'definer',prosecdef,'config',proconfig)::text from pg_proc where oid='public.t109_detection_sources()'::regprocedure";
        string authority=await Scalar(authoritySql),definition=await Scalar("select pg_get_functiondef('public.t109_detection_sources()'::regprocedure)");
        await PostCollectionPostgres.Sql(db,"""
            insert into servers(id,domain_id,hostname,role,is_active) select 900001,id,'dc.example.test','domain_controller',true from domains limit 1;
            insert into log_sources(id,name) values(900001,'Security'),(900002,'System'),(900003,'Microsoft-Windows-PowerShell/Operational') on conflict(name) do nothing;
            insert into storage_v2_channel(id,value) values(900001,'Security') on conflict(value) do nothing;
            insert into sli_agents(id,host_id,key_fingerprint,assigned_modules)
                values('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002',repeat('a',64),
                '[{"module_id":"sli.windows.ad-dc","enabled":true,"config":{"channels":{"Microsoft-Windows-PowerShell/Operational":false}}}]');
            insert into sli_agent_module_bindings(agent_id,module_id,source_instance_id,source_name,channel,module_version,policy_revision)
                values('00000000-0000-4000-8000-000000000001','sli.windows.ad-dc','synthetic-dc','dc.example.test','ad-dc','1.0.0','1');
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            select '00000000-0000-4000-8000-000000000001','sli.windows.ad-dc',n,md5('packet:'||n)::uuid,repeat('a',64),
                jsonb_build_object('source_instance_id','synthetic-dc','generation',case when n=1 then 'old-generation' else 'current-generation' end),'{"status":"committed"}'::jsonb
            from generate_series(1,6) n;
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
            select packet_id,case when sequence=4 then envelope||'{"mismatch":true}'::jsonb else envelope end,
                jsonb_build_object('contract','sli.collection-packet.v1','header',jsonb_build_object('channel',case when sequence=6 then 'Security' when sequence=5 then 'Microsoft-Windows-PowerShell/Operational' else 'System' end)),
                '[]'::jsonb,case when sequence=3 then null else now() end from sli_agent_receipts;
            insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
                select n,900001,(select id from log_sources where name='Security'),'unrelated:'||n,'jsonl',md5(n::text) from generate_series(1,50000) n;
            insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
                select 50000+sequence,900001,(select id from log_sources where name='Security'),'agent-packet:'||packet_id,'jsonl',md5(packet_id::text) from sli_agent_receipts;
            insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,channel_id,time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
            select n,n,900001,1,(select id from log_sources where name=case when n in(50001,50002,50003,50004) then 'System' when n=50005 then 'Microsoft-Windows-PowerShell/Operational' else 'Security' end),
                4624,(select id from storage_v2_channel where value='Security'),now(),now(),sha256(n::text::bytea),sha256(n::text::bytea),
                (select version from event_catalog_revisions order by id limit 1) from generate_series(1,50006) n;
            -- Historical bindings remain eligible for additional channels too.
            insert into finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id,storage_kind,log_source_id,agent_id)
            select 'sli_semantic_login'::regrole,'sli_semantic_login',installation_id,'sli.windows.ad-dc','synthetic-dc','old-generation','','core_event',
                (select id from log_sources where name='Security'),'00000000-0000-4000-8000-000000000001' from semantic_default_installation;
            analyze events_v2_core;analyze raw_log_files;analyze sli_agent_receipts;analyze sli_agent_packet_inbox;
            """,ct);
        async Task<(string Sources,string Channels)> Discover() {
            await using var tx=await db.BeginTransactionAsync(ct);
            await using(var run=new NpgsqlCommand("set session authorization sli_semantic_login;set role adlog_semantic_worker;set local statement_timeout='5s'",db,tx))await run.ExecuteNonQueryAsync(ct);
            string sources;
            await using(var run=new NpgsqlCommand("select coalesce(jsonb_agg(source order by source::text),'[]')::text from public.t109_detection_sources()",db,tx))sources=(string)(await run.ExecuteScalarAsync(ct))!;
            await using(var reset=new NpgsqlCommand("reset role;reset session authorization",db,tx))await reset.ExecuteNonQueryAsync(ct);
            string channels;
            await using(var run=new NpgsqlCommand("select coalesce(jsonb_agg(jsonb_build_array(source_generation,native_channel,log_source_id) order by source_generation,native_channel,log_source_id),'[]')::text from semantic_t109_channels",db,tx))channels=(string)(await run.ExecuteScalarAsync(ct))!;
            await tx.RollbackAsync(ct);return(sources,channels);
        }
        var expected=await Discover();Assert.Single(JsonNode.Parse(expected.Sources)!.AsArray());
        var channels=JsonNode.Parse(expected.Channels)!.AsArray();Assert.Equal(2,channels.Count);
        Assert.All(channels,c=>Assert.Equal("System",(string?)c![1]));
        await fixture.Pg.ApplyFileAsync(forward,null,ct);
        Assert.Equal(authority,await Scalar(authoritySql));Assert.Equal(expected,await Discover());
        string plan=await Scalar("explain(analyze,buffers,format json) select distinct core.log_source_id from events_v2_core core where core.raw_log_file_id=50002 offset 0");
        Assert.Contains("events_v2_core_raw_packet_lookup",plan);output.WriteLine(plan);
        await fixture.Pg.ApplyFileAsync(rollback,null,ct);
        Assert.Equal(definition,await Scalar("select pg_get_functiondef('public.t109_detection_sources()'::regprocedure)"));
        Assert.Equal(authority,await Scalar(authoritySql));
        await fixture.Pg.ApplyFileAsync(forward,null,ct);Assert.Equal(expected,await Discover());
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Schema308_accepts309_and_rollback_preserves_function_authority()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 311);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString);
        await db.OpenAsync(ct);
        string directory = Path.Combine(SqlPostgresFixture.Repository(), "config/postgres_migrations");
        string forward = Path.Combine(directory, "309_semantic_source_lookup.sql");
        string rollback = Path.Combine(directory, "309_semantic_source_lookup.rollback.sql");
        await fixture.Pg.ApplyFileAsync(Path.Combine(directory,"311_semantic_inbox_admission.rollback.sql"),null,ct);
        await fixture.Pg.ApplyFileAsync(Path.Combine(directory,"310_semantic_discovery_streams.rollback.sql"),null,ct);
        await fixture.Pg.ApplyFileAsync(rollback, null, ct);
        const string state = """
            select jsonb_agg(jsonb_build_object('oid',oid,'owner',proowner,'acl',proacl::text,
                'definer',prosecdef,'config',proconfig) order by oid)::text from pg_proc
            where oid in ('public.default_detection_sources()'::regprocedure,
                'public.default_detection_sources_before_v301()'::regprocedure,
                'public.read_file_decoy_observations(jsonb,uuid,text,text)'::regprocedure)
            """;
        async Task<string> Scalar(string sql) { await using var c = new NpgsqlCommand(sql,db); return (string)(await c.ExecuteScalarAsync(ct))!; }
        string authority = await Scalar(state);
        string oldDefinition = await Scalar("select pg_get_functiondef('public.default_detection_sources_before_v301()'::regprocedure)");
        await fixture.Pg.ApplyFileAsync(forward, null, ct);
        Assert.Equal(authority, await Scalar(state));
        string definition = await Scalar("select pg_get_functiondef('public.default_detection_sources_before_v301()'::regprocedure)");
        Assert.Contains("where e.raw_log_file_id=(select raw.id", definition);
        // Nonempty core plus an empty imported packet is the adversarial LIMIT
        // plan. Check the actual lookup used by discovery, with default planner settings.
        await PostCollectionPostgres.Sql(db, """
            insert into servers(id,domain_id,hostname) select 900001,id,'dc.example.test' from domains limit 1;
            insert into log_sources(id,name) values(900001,'synthetic');
            insert into storage_v2_channel(id,value) values(900001,'synthetic');
            insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
                select n,900001,900001,'synthetic:'||n,'jsonl',md5(n::text) from generate_series(1,50000) n;
            insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,
                channel_id,time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
                select n,n,900001,1,900001,4624,900001,now(),now(),sha256(n::text::bytea),sha256(n::text::bytea),
                    (select version from event_catalog_revisions order by id limit 1)
                from generate_series(1,50000) n;
            analyze raw_log_files; analyze events_v2_core;
            """, ct);
        string plan = await Scalar("""
            explain(analyze,buffers,format json) select e.log_source_id from public.events_v2_core e
            where e.raw_log_file_id=(select raw.id from public.raw_log_files raw where raw.file_path='synthetic:50000')
              and e.log_source_id is not null order by e.id limit 1
            """);
        Assert.Contains("events_v2_core_raw_packet_lookup", plan);
        Assert.DoesNotContain("Rows Removed by Filter\": 49999", plan);
        output.WriteLine(plan);
        await using (var worker = new NpgsqlConnection(fixture.Dsn("sli_semantic_login"))) {
            await worker.OpenAsync(ct);
            await PostCollectionPostgres.Sql(worker, "set role adlog_semantic_worker; set statement_timeout=30000; select source from public.default_detection_sources()", ct);
        }
        await PostCollectionPostgres.Sql(db, """
            insert into public.sli_agents(id,host_id,key_fingerprint)
                values('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002',repeat('a',64));
            insert into sli_plugin_file_audit.policy_revisions(agent_id,source_instance_id,revision,authored_at,actor_kind,actor_id,policy,policy_sha256)
                values('00000000-0000-4000-8000-000000000001','synthetic-files',1,now(),'session',1,'{"source_kind":"server"}',repeat('a',64));
            insert into sli_plugin_file_audit.observations(evidence_key,agent_id,source_instance_id,collection_scope_id,channel,provider,
                generation,record_id,event_id,event_version,observed_at,policy_revision,core_evidence_ref,payload_sha256,normalized)
            select encode(sha256(n::text::bytea),'hex'),'00000000-0000-4000-8000-000000000001','synthetic-files','synthetic-root','Security',
                'Microsoft-Windows-Security-Auditing','synthetic-generation',n,case when n=2000 then 4660 else 4663 end,1,
                '2026-10-01'::timestamptz+n*interval '1 second',1,'synthetic',repeat('a',64),
                jsonb_build_object('evidence_key',encode(sha256(n::text::bytea),'hex'),'payload_sha256',repeat('a',64),
                    'event_id',case when n=2000 then 4660 else 4663 end,'record_id',n,
                    'scopes',jsonb_build_array(jsonb_build_object('collection_scope_id','synthetic-root')))
            from generate_series(1,2000) n;
            -- Historical generations share the source/time index. The new
            -- stream prefix must avoid walking that history before the batch.
            insert into sli_plugin_file_audit.observations(evidence_key,agent_id,source_instance_id,collection_scope_id,channel,provider,
                generation,record_id,event_id,event_version,observed_at,policy_revision,core_evidence_ref,payload_sha256,normalized)
            select encode(sha256((o.record_id::text||':'||g)::bytea),'hex'),o.agent_id,o.source_instance_id,o.collection_scope_id,o.channel,o.provider,
                'historical-'||g,o.record_id,o.event_id,o.event_version,o.observed_at-interval '1 day',o.policy_revision,o.core_evidence_ref,o.payload_sha256,
                jsonb_set(o.normalized,'{evidence_key}',to_jsonb(encode(sha256((o.record_id::text||':'||g)::bytea),'hex')))
            from sli_plugin_file_audit.observations o cross join generate_series(1,10) g where o.generation='synthetic-generation';
            insert into public.finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
                source_instance_id,source_generation,collection_scope_id,storage_kind,agent_id)
            select 'sli_semantic_login'::regrole,'sli_semantic_login',installation_id,'sli.file-audit',
                'synthetic-files','synthetic-generation','synthetic-root','file_audit_observation','00000000-0000-4000-8000-000000000001'
            from public.semantic_default_installation;
            analyze sli_plugin_file_audit.observations;
            """, ct);
        const string readFiles = """
            select coalesce(jsonb_agg(to_jsonb(result)),'[]')::text
            from public.semantic_default_installation installation cross join lateral
                public.read_file_decoy_observations(jsonb_build_object('installation_id',installation.installation_id,
                    'plugin_id','sli.file-audit','source_instance_id','synthetic-files',
                    'source_generation','synthetic-generation','collection_scope_id','synthetic-root'),
                    '00000000-0000-4000-8000-000000000001',repeat('c',64),null) result
            """;
        // Installation metadata is owner-only: build the worker scope on the
        // owner connection, then invoke only the admitted reader as the login.
        string installation = await Scalar("select installation_id::text from public.semantic_default_installation");
        string workerReadFiles = readFiles.Replace("public.semantic_default_installation installation", $"(select '{installation}'::uuid as installation_id) installation");
        async Task<string> FileRows() {
            await using var worker = new NpgsqlConnection(fixture.Dsn("sli_semantic_login"));
            await worker.OpenAsync(ct);
            await PostCollectionPostgres.Sql(worker,"set role adlog_semantic_worker; set statement_timeout=30000",ct);
            await using var query=new NpgsqlCommand(workerReadFiles,worker);
            return (string)(await query.ExecuteScalarAsync(ct))!;
        }
        string files=await FileRows();
        Assert.Equal(128,JsonNode.Parse(files)!.AsArray().Count);
        string filePlan=await Scalar("""
            explain(analyze,buffers,format json) select evidence_key from sli_plugin_file_audit.observations
            where agent_id='00000000-0000-4000-8000-000000000001' and source_instance_id='synthetic-files'
              and generation='synthetic-generation' and observed_at<=statement_timestamp()
              and event_id in (4656,5145,4663,4660,4670) order by observed_at,evidence_key limit 128
            """);
        output.WriteLine(filePlan);
        Assert.Contains("file_audit_decoy_stream_v309",filePlan);
        await fixture.Pg.ApplyFileAsync(rollback, null, ct);
        Assert.Equal(files,await FileRows());
        Assert.Equal(oldDefinition, await Scalar("select pg_get_functiondef('public.default_detection_sources_before_v301()'::regprocedure)"));
        Assert.Equal(authority, await Scalar(state));
        await fixture.Pg.ApplyFileAsync(forward, null, ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
