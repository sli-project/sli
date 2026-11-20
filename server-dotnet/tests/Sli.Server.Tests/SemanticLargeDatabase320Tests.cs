using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Semantic.Detections;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests;

public sealed partial class SemanticLargeDatabaseTests
{
    // 372 retired the live import summary. Exercise the original migration's
    // bounded PostgreSQL functions as the semantic worker on a 320 database.
    private static async Task<JsonObject> RefreshSummary320Async(NpgsqlConnection worker, CancellationToken ct)
    {
        var budget = Stopwatch.StartNew();
        var previous = new JsonObject();
        JsonObject progress;
        do
        {
            await PostCollectionPostgres.Sql(worker, "select public.semantic_import_refresh320()", ct);
            await using var refreshTail = new NpgsqlCommand("select public.semantic_default_refresh320()", worker);
            bool tailAdvanced = (bool)(await refreshTail.ExecuteScalarAsync(ct))!;
            await using var read = new NpgsqlCommand("select public.semantic_import_progress320()::text", worker);
            progress = JsonNode.Parse((string)(await read.ExecuteScalarAsync(ct))!)!.AsObject();
            if (!progress["pending"]!.GetValue<bool>() || (!tailAdvanced && JsonNode.DeepEquals(previous, progress)))
                break;
            previous = progress;
        } while (budget.Elapsed < TimeSpan.FromSeconds(5));
        return progress;
    }

    [Fact]
    public async Task Summary320_size_bootstrap_and_retention_100000_rows()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct, throughVersion: 320);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString);await db.OpenAsync(ct);
        await SemanticRuntimePostgresTests.SeedNative(db,ct,canonicalAssignment:true);
        async Task<string> Scalar(string sql,int lower=0,int upper=0) {
            await using var q=new NpgsqlCommand(sql,db){CommandTimeout=300};
            q.Parameters.AddWithValue("lower",lower);q.Parameters.AddWithValue("upper",upper);
            return (string)(await q.ExecuteScalarAsync(ct))!;
        }
        // Synthetic packet-backed history only; no stand connection or data.
        for(int lower=1;lower<=100000;lower+=1000)
        await Scalar("""
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                select r.agent_id,r.module_id,n+10,md5('measure320:'||n)::uuid,r.envelope_sha256,r.envelope,r.receipt
                from sli_agent_receipts r cross join generate_series(@lower,@upper) n where r.sequence=1;
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
                select r.packet_id,r.envelope,'{"contract":"sli.collection-packet.v1","header":{"channel":"Security"}}','[]',now()
                from sli_agent_receipts r where sequence between @lower+10 and @upper+10;
            insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
                select r.sequence+10000000,900001,(select log_source_id from raw_log_files where id=900001),
                    'agent-packet:'||r.packet_id,'jsonl',encode(sha256(r.packet_id::text::bytea),'hex') from sli_agent_receipts r where sequence between @lower+10 and @upper+10;
            insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,event_record_id,channel_id,provider_id,computer_id,time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
                select raw.id,raw.id,e.server_id,e.domain_id,e.log_source_id,1102,raw.id,e.channel_id,e.provider_id,e.computer_id,
                    e.time_created_utc,e.normalized_at,sha256(raw.id::text::bytea),sha256(raw.id::text::bytea),e.noise_catalog_version
                from raw_log_files raw cross join events_v2_core e where raw.id between @lower+10000010 and @upper+10000010 and e.id=900001;
            select 'seeded';
            """,lower,Math.Min(lower+999,100000));
        await Scalar("""
            analyze sli_agent_receipts;analyze sli_agent_packet_inbox;analyze events_v2_core;analyze raw_log_files;
            -- Model history already present when 320 is installed, rather than
            -- charging bootstrap for 400000 synthetic post-install notifications.
            truncate semantic_import_dirty320,semantic_default_dirty320;
            select 'seeded';
            """);
        await using var worker=new NpgsqlConnection(fixture.Dsn("sli_semantic_login"));await worker.OpenAsync(ct);
        await PostCollectionPostgres.Sql(worker,"set role adlog_semantic_worker",ct);
        long packets=0;int cycles=0;var bootstrap=Stopwatch.StartNew();
        while(true) {
            var timer=Stopwatch.StartNew();
            var progress=await RefreshSummary320Async(worker,ct);
            long next=progress["bootstrap_packets"]!.GetValue<long>();
            output.WriteLine($"320 budget cycle {++cycles}: packets={next-packets},ms={timer.Elapsed.TotalMilliseconds:F1}");packets=next;
            if(!progress["pending"]!.GetValue<bool>())break;
            Assert.True(cycles<100);
        }
        output.WriteLine($"320 bootstrap 100001 packets: cycles={cycles},ms={bootstrap.Elapsed.TotalMilliseconds:F1}");
        Assert.Equal("100003",await Scalar("select count(*)::text from semantic_event_facts320"));
        string sizes=await Scalar("""
            select jsonb_build_object('heap',pg_table_size('semantic_event_facts320'),
                'indexes',pg_indexes_size('semantic_event_facts320'),'total',pg_total_relation_size('semantic_event_facts320'),
                'bytes_per_row',pg_total_relation_size('semantic_event_facts320')/100003.0,
                'projected_11012600',ceil(pg_total_relation_size('semantic_event_facts320')/100003.0*11012600),
                'parts',(select jsonb_object_agg(indexrelname,pg_relation_size(indexrelid)) from pg_stat_user_indexes where relname='semantic_event_facts320'))::text;
            """);
        output.WriteLine("320 facts size: "+sizes);
        Assert.True(JsonNode.Parse(sizes)!["projected_11012600"]!.GetValue<long>()<5000000000L);
        // Malformed and noncanonical UUID paths remain excluded, without an
        // invalid UUID cast on either the INSERT or DELETE transition table.
        await Scalar("""
            insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
                select 990000+n,900001,(select log_source_id from raw_log_files where id=900001),
                    'agent-packet:'||case when n=1 then repeat('g',36) else upper(md5('noncanonical320')::uuid::text) end,
                    'jsonl',encode(sha256(n::text::bytea),'hex') from generate_series(1,2) n;
            delete from raw_log_files where id in (990001,990002);
            select 'excluded';
            """);
        Assert.Equal("0",await Scalar("select count(*)::text from semantic_import_dirty320"));
        // Same rows, constraints and transaction boundaries; only 320's DELETE
        // transition triggers differ. Rollback preserves the identical input.
        foreach(bool enabled in new[]{false,true}) {
            await using var tx=await db.BeginTransactionAsync(ct);
            string setting=enabled?"enable":"disable";
            await Scalar($"alter table events_v2_core {setting} trigger semantic_import_delete320;alter table raw_log_files {setting} trigger semantic_import_delete320;select 'configured'");
            foreach(string table in new[]{"events_v2_core","raw_log_files"}) {
                string plan=await Scalar($"explain(analyze,buffers,format json) delete from {table} where id>10000000");
                var document=JsonNode.Parse(plan)![0]!;
                output.WriteLine($"320 DELETE {table} 100000,enabled={enabled}: ms={document["Execution Time"]},triggers={document["Triggers"]?.ToJsonString()}");
            }
            if(enabled) {
                Assert.Equal("200000",await Scalar("select count(*)::text from semantic_import_dirty320"));
                Assert.Equal("2",await Scalar("select count(*)::text from semantic_default_dirty320"));
            }
            await tx.RollbackAsync(ct);
        }
    }

    [Fact]
    public async Task Summary320_tail_failure_does_not_rollback_bootstrap()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct, throughVersion: 320);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString);await db.OpenAsync(ct);
        await SemanticRuntimePostgresTests.SeedNative(db,ct,canonicalAssignment:true);
        await using var worker=new NpgsqlConnection(fixture.Dsn("sli_semantic_login"));await worker.OpenAsync(ct);
        await PostCollectionPostgres.Sql(worker,"set role adlog_semantic_worker",ct);
        await PostCollectionPostgres.Sql(db,"""
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                select agent_id,module_id,n+10,md5('tail320:'||n)::uuid,envelope_sha256,envelope,receipt
                from sli_agent_receipts cross join generate_series(1,1024) n;
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
                select packet_id,envelope,'{"contract":"sli.collection-packet.v1"}','[]',now() from sli_agent_receipts where sequence>10;
            create function fail_tail320() returns trigger language plpgsql as $$ begin
                raise exception 'synthetic_tail_timeout' using errcode='57014';
            end $$;
            create trigger fail_tail320 before update on semantic_default_state320
                for each row when (not new.dirty) execute function fail_tail320();
            """,ct);
        await PostCollectionPostgres.Sql(worker,"select public.semantic_import_refresh320()",ct);
        var failure=await Assert.ThrowsAsync<PostgresException>(()=>
            PostCollectionPostgres.Sql(worker,"select public.semantic_default_refresh320()",ct));
        Assert.Equal("57014",failure.SqlState);
        Assert.Equal("synthetic_tail_timeout",failure.MessageText);
        await using var check=new NpgsqlCommand("select bootstrap_packets from semantic_import_state320",db);
        Assert.Equal(512L,(long)(await check.ExecuteScalarAsync(ct))!);
        await PostCollectionPostgres.Sql(worker,"select public.semantic_import_refresh320()",ct);
        await PostCollectionPostgres.Sql(worker,"select public.semantic_import_refresh320()",ct);
        Assert.Equal(1025L,(long)(await check.ExecuteScalarAsync(ct))!);
    }

    [Theory]
    [InlineData("commit")]
    [InlineData("channel")]
    [InlineData("channel-disabled")]
    [InlineData("cursor")]
    public async Task Summary320_review_regressions(string scenario)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct, throughVersion: 320);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString);await db.OpenAsync(ct);
        await SemanticRuntimePostgresTests.SeedNative(db,ct,canonicalAssignment:true);
        await using var worker=new NpgsqlConnection(fixture.Dsn("sli_semantic_login"));await worker.OpenAsync(ct);
        await PostCollectionPostgres.Sql(worker,"set role adlog_semantic_worker",ct);
        async Task<string> Scalar(string sql,NpgsqlConnection? connection=null,string? scope=null) {
            await using var q=new NpgsqlCommand(sql,connection??db);
            if(scope is not null)q.Parameters.AddWithValue("scope",scope);
            return (string)(await q.ExecuteScalarAsync(ct))!;
        }
        if(scenario=="commit") {
            await PostCollectionPostgres.Sql(db,"""
                create or replace function public.default_detection_sources() returns table(source jsonb)
                language plpgsql as $$ begin
                    raise exception 'synthetic_detector_failure' using errcode='57014';
                end $$;
                """,ct);
            var progress=await RefreshSummary320Async(worker,ct);
            long committed=progress["bootstrap_packets"]!.GetValue<long>();
            Assert.True(committed>0);
            var batch=await new DetectionProducer(new(),new()).RunOnceAsync(worker,ct,refreshImport:false);
            Assert.Equal(1,batch.Failed);
            Assert.Equal(committed,long.Parse(await Scalar("select bootstrap_packets::text from semantic_import_state320")));
            return;
        }
        await RefreshSummary320Async(worker,ct);
        string scope=await Scalar("select source->'scope' from t109_detection_sources() limit 1",worker);
        const string native="select coalesce(jsonb_agg(native_id order by native_id),'[]')::text from read_t109_native(@scope::jsonb)";
        await Scalar(native,worker,scope);
        if(scenario=="cursor") {
            string decoy="select count(*)::text from read_account_decoy_events((@scope::jsonb->>'installation_id')::uuid,'sli.windows.ad-dc',@scope::jsonb->>'source_instance_id',@scope::jsonb->>'source_generation',repeat('a',64),null)";
            for(int n=0;n<300;n++)
            {
                await Scalar(decoy.Replace("repeat('a',64)","md5('revision:"+n+"')||md5('revision:"+n+"')"),worker,scope);
                if(n==0)await PostCollectionPostgres.Sql(db,"insert into semantic_source_pending320 select principal_oid,principal_name,scope_key,kind,checkpoint,900002 from semantic_source_cursor320 where kind='decoy'",ct);
            }
            Assert.Equal("1",await Scalar("select count(*)::text from semantic_source_cursor320 where kind='decoy'"));
            Assert.Equal("1",await Scalar("select count(*)::text from semantic_source_cursor320 where kind='native'"));
            Assert.Equal("0",await Scalar("select count(*)::text from semantic_source_pending320 p where not exists(select 1 from semantic_source_cursor320 c where (c.principal_oid,c.principal_name,c.scope_key,c.kind,c.checkpoint)=(p.principal_oid,p.principal_name,p.scope_key,p.kind,p.checkpoint))"));
            return;
        }
        async Task SetSystem(bool enabled) {
            await using var change=new NpgsqlCommand("""
                insert into sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy)
                select id,policy_revision+1,jsonb_set(jsonb_set(assigned_modules,'{0,config,channels,System}',@enabled::jsonb),
                    '{0,config,policy_revision}',to_jsonb((policy_revision+1)::text)),collection_policy from sli_agents;
                update sli_agents a set policy_revision=a.policy_revision+1,assigned_modules=h.assigned_modules
                from sli_agent_policy_history h where h.agent_id=a.id and h.revision=a.policy_revision+1;
                """,db);
            change.Parameters.AddWithValue("enabled",enabled?"true":"false");await change.ExecuteNonQueryAsync(ct);
        }
        if(scenario=="channel-disabled")await SetSystem(false);
        // Discovery has run, but the first packet of System arrives afterwards.
        var row=JsonNode.Parse(await Scalar("select event_rows::text from sli_agent_packet_inbox limit 1"))![0]!.DeepClone().AsObject();
        row["channel"]="System";row["event_id"]=7045;
        row["xml"]=row["xml"]!.GetValue<string>().Replace("<Channel>Security</Channel>","<Channel>System</Channel>").Replace("<EventID>1102</EventID>","<EventID>7045</EventID>");
        string hash=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(SourceJson.SerializeSorted(row))));
        await using(var q=new NpgsqlCommand("""
            insert into log_sources(name) values('System') on conflict do nothing;
            insert into storage_v2_channel(value) values('System') on conflict do nothing;
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                select agent_id,module_id,2,md5('review-channel')::uuid,envelope_sha256,envelope,receipt from sli_agent_receipts limit 1;
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
                select md5('review-channel')::uuid,envelope,jsonb_set(packet,'{header,channel}','"System"'),@rows::jsonb,now() from sli_agent_packet_inbox limit 1;
            insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
                select 990001,server_id,(select id from log_sources where name='System'),'agent-packet:'||md5('review-channel')::uuid,file_format,@hash from raw_log_files limit 1;
            insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,event_record_id,channel_id,provider_id,computer_id,time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
                select 990001,990001,server_id,domain_id,(select id from log_sources where name='System'),7045,1,(select id from storage_v2_channel where value='System'),provider_id,computer_id,time_created_utc,normalized_at,decode(@hash,'hex'),decode(@hash,'hex'),noise_catalog_version from events_v2_core where id=900001;
            select semantic_import_refresh320();
            """,db)) {q.Parameters.AddWithValue("rows",new JsonArray(row).ToJsonString());q.Parameters.AddWithValue("hash",hash);await q.ExecuteNonQueryAsync(ct);}
        if(scenario=="channel-disabled") {
            // More than one cursor portion of a genuinely unrelated log_source
            // in the same packet stream must not accumulate in pending either.
            await PostCollectionPostgres.Sql(db,"""
                insert into log_sources(name) values('unrelated320');
                insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,event_record_id,channel_id,provider_id,computer_id,time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
                select 1000000+n,raw_log_file_id,server_id,domain_id,(select id from log_sources where name='unrelated320'),1102,1000000+n,channel_id,provider_id,computer_id,time_created_utc,normalized_at,sha256(n::text::bytea),sha256(n::text::bytea),noise_catalog_version
                from events_v2_core cross join generate_series(1,5000) n where id=900001;
                select semantic_import_refresh320();
                """,ct);
            for(int pass=0;pass<3;pass++) {
                Assert.DoesNotContain("990001",await Scalar(native,worker,scope));
                Assert.Equal("0",await Scalar("select count(*)::text from semantic_source_pending320 where core_id=990001"));
                Assert.Equal("0",await Scalar("select count(*)::text from semantic_source_pending320 where core_id>1000000"));
            }
            Assert.Equal("true",await Scalar("select ((q.revision,q.core_id)>=(f.revision,f.core_id))::text from semantic_source_cursor320 q cross join semantic_event_facts320 f where q.kind='native' and f.core_id=990001"));
            await SetSystem(true);
        }
        Assert.Contains("990001",await Scalar(native,worker,scope));
        await Scalar("select count(*)::text from t109_detection_sources()",worker);
        Assert.Contains("990001",await Scalar(native,worker,scope));
        if(scenario=="channel-disabled") {
            // Disabling also removes an already pending event, but enabling
            // must recover it again without a new import revision or discovery.
            await SetSystem(false);
            Assert.DoesNotContain("990001",await Scalar(native,worker,scope));
            Assert.Equal("0",await Scalar("select count(*)::text from semantic_source_pending320 where core_id=990001"));
            await SetSystem(true);
            Assert.Contains("990001",await Scalar(native,worker,scope));
        }
    }

    [Fact]
    public async Task Summary320_dirty_discovery_uses_summary_and_delivers_next_cycle()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct, throughVersion: 320);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString);await db.OpenAsync(ct);
        await SemanticRuntimePostgresTests.SeedNative(db,ct,canonicalAssignment:true);
        await using var worker=new NpgsqlConnection(fixture.Dsn("sli_semantic_login"));await worker.OpenAsync(ct);
        await PostCollectionPostgres.Sql(worker,"set role adlog_semantic_worker",ct);
        async Task<string> Scalar(string sql,NpgsqlConnection? connection=null) {
            await using var q=new NpgsqlCommand(sql,connection??db);return (string)(await q.ExecuteScalarAsync(ct))!;
        }
        const string discovery="select coalesce(jsonb_agg(source order by source::text),'[]')::text from default_detection_sources()";
        await RefreshSummary320Async(worker,ct);
        string before=await Scalar(discovery,worker);Assert.Single(JsonNode.Parse(before)!.AsArray());
        // The test-only trap makes any full-history fallback fail immediately.
        // It is installed only after bootstrap, never on a runtime database.
        string full=await Scalar("select pg_get_functiondef('semantic_default_full320()'::regprocedure)");
        await PostCollectionPostgres.Sql(db,"""
            create or replace function public.semantic_default_full320() returns table(source jsonb)
            language plpgsql security definer set search_path=pg_catalog,pg_temp as $$ begin
                raise exception 'unexpected_full_discovery320';
            end $$;
            update sli_agent_receipts set receipt=receipt;
            select semantic_import_refresh320();
            """,ct);
        Assert.Equal("true",await Scalar("select dirty::text from semantic_default_state320"));
        Assert.Equal(before,await Scalar(discovery,worker));
        await SemanticRuntimePostgresTests.SeedNative(db,ct,1,canonicalAssignment:true);
        Assert.NotEqual("0",await Scalar("select count(*)::text from semantic_default_dirty320"));
        Assert.Equal(before,await Scalar(discovery,worker));
        Assert.Equal("0",await Scalar("select count(*)::text from semantic_event_facts320 where core_id=900011"));
        // The following cycle handles dirty facts and receipt tails. Discovery
        // still cannot enter the trapped full branch while either is dirty.
        await PostCollectionPostgres.Sql(worker,"select semantic_import_refresh320()",ct);
        Assert.Equal(before,await Scalar(discovery,worker));
        await PostCollectionPostgres.Sql(worker,"select semantic_default_refresh320();select semantic_default_refresh320()",ct);
        string after=await Scalar(discovery,worker);Assert.Equal(2,JsonNode.Parse(after)!.AsArray().Count);
        await PostCollectionPostgres.Sql(db,full,ct);
        await PostCollectionPostgres.Sql(db,"grant execute on function semantic_default_full320() to adlog_semantic_worker",ct);
        Assert.Equal(after,await Scalar(discovery.Replace("default_detection_sources()","semantic_default_full320()"),worker));
        string native=await Scalar("""
            select coalesce(jsonb_agg(r.native_id),'[]')::text from t109_detection_sources() d
            cross join lateral read_t109_native(d.source->'scope') r
            where d.source#>>'{scope,source_instance_id}'=md5('semantic-host1')::uuid::text
            """,worker);
        Assert.Equal("[\"900011\"]",native);
    }

    [Fact]
    public async Task Schema319_accepts320_summary_resumes_and_readers_keep_late_events()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct, throughVersion: 319);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString);await db.OpenAsync(ct);
        async Task<string> Scalar(string sql) {await using var q=new NpgsqlCommand(sql,db){CommandTimeout=300};return (string)(await q.ExecuteScalarAsync(ct))!;}
        // This transition tests exactly 319 -> 320, regardless of later migrations.
        await using var worker=new NpgsqlConnection(fixture.Dsn("sli_semantic_login"));await worker.OpenAsync(ct);
        await PostCollectionPostgres.Sql(worker,"set role adlog_semantic_worker;set statement_timeout='20s';set plan_cache_mode=force_generic_plan",ct);
        bool maintain=false;
        async Task<string> Query(string sql,string? scope=null) {
            if(maintain) {
                await PostCollectionPostgres.Sql(worker,"select public.semantic_import_refresh320()",ct);
                await PostCollectionPostgres.Sql(worker,"select public.semantic_default_refresh320()",ct);
            }
            await using var q=new NpgsqlCommand(sql,worker){CommandTimeout=25};
            if(scope is not null)q.Parameters.AddWithValue("scope",scope);
            return (string)(await q.ExecuteScalarAsync(ct))!;
        }
        string directory=Path.Combine(SqlPostgresFixture.Repository(),"config/postgres_migrations");
        string forward=Path.Combine(directory,"320_semantic_import_summary.sql"),rollback=Path.Combine(directory,"320_semantic_import_summary.rollback.sql");
        // Compare the entire public discovery result to the previous full recomputation.
        Assert.Equal("319",await Scalar("select max(version)::text from schema_migrations"));
        Assert.Equal("storage_lifecycle_roles",await Scalar("select name from schema_migrations where version=319"));
        Assert.Equal("3",await Scalar("select count(*)::text from pg_roles where rolname in ('adlog_storage_lifecycle_worker','adlog_storage_lifecycle_delete','adlog_storage_lifecycle_guard')"));
        await SemanticRuntimePostgresTests.SeedNative(db,ct,canonicalAssignment:true);
        const string discovery="select coalesce(jsonb_agg(source order by source::text),'[]')::text from t109_detection_sources()";
        const string native="select coalesce(jsonb_agg(to_jsonb(r) order by native_id),'[]')::text from read_t109_native(@scope::jsonb) r";
        string expected=await Query(discovery);
        string scope=JsonNode.Parse(expected)![0]!["scope"]!.ToJsonString();
        string expectedNative=await Query(native,scope);
        Assert.Single(JsonNode.Parse(expectedNative)!.AsArray());
        // This second agent has only historical packets. Its source must remain
        // discoverable even when none of its UUIDs has reached the summary yet.
        await SemanticRuntimePostgresTests.SeedNative(db,ct,1,canonicalAssignment:true);
        expected=await Query(discovery);
        Assert.Equal(2,JsonNode.Parse(expected)!.AsArray().Count);
        bool full=Environment.GetEnvironmentVariable("SLI_SEMANTIC_SUMMARY_FULL_SCALE")=="1";
        int receipts=full?400000:1536,channels=full?150000:576,witnesses=full?6973:32;
        await using(var setup=new NpgsqlCommand("update sli_agent_receipts set sequence=@receipts+100 where packet_id=md5('semantic-packet')::uuid;insert into log_sources(name) values('System'),('Microsoft-Windows-PowerShell/Operational') on conflict do nothing",db)) {
            setup.Parameters.AddWithValue("receipts",receipts);await setup.ExecuteNonQueryAsync(ct);
        }
        for(int lower=1;lower<=receipts;lower+=4096) {
        await using var packets=new NpgsqlCommand("""
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            select md5('semantic-agent')::uuid,'sli.windows.ad-dc',n+1,md5('320-packet:'||n)::uuid,repeat('c',64),
                jsonb_build_object('agent_id',md5('semantic-agent')::uuid,'source_instance_id',md5('semantic-host')::uuid::text,
                    'generation',md5('semantic-host')::uuid::text),'{"status":"committed"}' from generate_series(@lower,@upper) n;
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
            select packet_id,envelope,jsonb_build_object('contract','sli.collection-packet.v1','header',jsonb_build_object('channel',
                case when sequence<=@channels+1 then case when sequence%2=0 then 'System' else 'Microsoft-Windows-PowerShell/Operational' end else 'Security' end)),
                '[]',now() from sli_agent_receipts where sequence between @lower+1 and @upper+1;
            """,db){CommandTimeout=300};
            packets.Parameters.AddWithValue("lower",lower);packets.Parameters.AddWithValue("upper",Math.Min(receipts,lower+4095));packets.Parameters.AddWithValue("channels",channels);
            await packets.ExecuteNonQueryAsync(ct);
            if(full && lower%65536==1)output.WriteLine($"320 fixture packets committed: {Math.Min(receipts,lower+4095)}");
        }
        await using(var seed=new NpgsqlCommand("""
            insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
            select 70000000+sequence,900001,(select id from log_sources where name='Security'),'agent-packet:'||packet_id,'jsonl',encode(sha256(packet_id::text::bytea),'hex')
                from sli_agent_receipts where sequence between 2 and @witnesses+1;
            insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,event_record_id,channel_id,provider_id,
                time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
            select raw.id,raw.id,900001,(select domain_id from servers where id=900001),
                (select id from log_sources where name=i.collection_channel),9999,raw.id,
                (select id from storage_v2_channel where value='Security'),(select id from storage_v2_provider limit 1),
                '2026-10-01',now(),sha256(raw.id::text::bytea),sha256(raw.id::text::bytea),
                (select version from event_catalog_revisions order by id limit 1)
            from raw_log_files raw join sli_agent_packet_inbox i on raw.file_path='agent-packet:'||i.packet_id
                where raw.id>=70000000;
            analyze sli_agent_receipts;analyze sli_agent_packet_inbox;analyze raw_log_files;analyze events_v2_core;
            """,db){CommandTimeout=300}) {
            seed.Parameters.AddWithValue("witnesses",witnesses);
            await seed.ExecuteNonQueryAsync(ct);
        }
        const string channelRows="select coalesce(jsonb_agg(to_jsonb(c) order by log_source_id),'[]')::text from semantic_t109_channels c";
        // Independent FULL recomputation, not the maintained facts. The added
        // packets keep the same generation and contain no native detector IDs,
        // so source JSON and accepted native rows remain the baseline above.
        string expectedChannels=await Scalar("""
            select coalesce(jsonb_agg(to_jsonb(c) order by log_source_id),'[]')::text from (
                select distinct b.principal_oid,b.principal_name,b.installation_id,b.source_instance_id,b.source_generation,
                    e.log_source_id,i.collection_channel native_channel
                from finding_evidence_source_bindings b join sli_agents a on a.id=b.agent_id
                cross join lateral jsonb_array_elements(a.assigned_modules) m
                join sli_agent_receipts r on r.agent_id=a.id and r.module_id='sli.windows.ad-dc'
                    and r.envelope->>'source_instance_id'=b.source_instance_id and r.envelope->>'generation'=b.source_generation
                join sli_agent_packet_inbox i using(packet_id)
                join raw_log_files raw on raw.file_path='agent-packet:'||r.packet_id::text
                join events_v2_core e on e.raw_log_file_id=raw.id
                where b.principal_name='sli_semantic_login' and b.plugin_id='sli.windows.ad-dc'
                    and b.storage_kind='core_event' and b.collection_scope_id='' and a.status='active'
                    and m->>'module_id'='sli.windows.ad-dc' and m->'enabled'='true'::jsonb
                    and i.collection_channel in ('System','Microsoft-Windows-PowerShell/Operational')
                    and coalesce(m#>array['config','channels',i.collection_channel],'true'::jsonb)='true'::jsonb
                    and r.receipt->>'status'='committed' and i.imported_at is not null and i.envelope=r.envelope
            ) c
            """);
        Assert.Equal(2,JsonNode.Parse(expectedChannels)!.AsArray().Count);
        const string signatures="'public.t109_detection_sources()'::regprocedure,'public.default_detection_sources_before_v301()'::regprocedure,'public.read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure,'public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure";
        string definitions="select jsonb_agg(pg_get_functiondef(oid) order by oid)::text from pg_proc where oid in ("+signatures+")";
        string catalog="select jsonb_agg(to_jsonb(p)-'prosrc'-'provolatile' order by oid)::text from pg_proc p where oid in ("+signatures+")";
        string beforeDefinitions=await Scalar(definitions),authority=await Scalar(catalog);
        await fixture.Pg.ApplyFileAsync(forward,null,ct);
        Assert.Equal("320",await Scalar("select max(version)::text from schema_migrations"));
        maintain=true;
        Assert.Equal(authority,await Scalar(catalog));
        // Hold the refresh writer open: force every public read to take the
        // full branch while the acceleration tables are completely empty.
        await using(var bootstrapFence=await db.BeginTransactionAsync(ct)) {
            await PostCollectionPostgres.Sql(db,"select 1 from semantic_import_state320 for update",ct);
            Assert.Equal(expected,await Query(discovery));
            Assert.Equal(expectedChannels,await Scalar(channelRows));
            Assert.Equal(expectedNative,await Query(native,scope));
            Assert.Equal("0",await Scalar("select count(*)::text from semantic_packet_facts320"));
            await bootstrapFence.CommitAsync(ct);
        }
        await Query(discovery);
        const string progress="select to_jsonb(s)::text from semantic_import_state320 s";
        string saved=await Scalar(progress);
        Assert.True(JsonNode.Parse(saved)!["bootstrap_packets"]!.GetValue<long>()>0);
        // Cancel the next actual discovery statement; its in-flight portion is
        // atomic, while the previously committed bootstrap key survives.
        await PostCollectionPostgres.Sql(worker,"set statement_timeout='1ms'",ct);
        maintain=false;
        var cancelled=await Assert.ThrowsAsync<PostgresException>(()=>Query("select pg_sleep(0.1);"+discovery));
        Assert.Equal("57014",cancelled.SqlState);
        await PostCollectionPostgres.Sql(worker,"set statement_timeout='20s'",ct);
        Assert.Equal(saved,await Scalar(progress));
        maintain=true;
        var bootstrap=Stopwatch.StartNew();int portions=1;
        while(await Scalar("select (not bootstrap_done or exists(select 1 from semantic_import_dirty320))::text from semantic_import_state320") == "true") {
            await Query(discovery);Assert.True(++portions<2000);
            if(full && portions%128==0)output.WriteLine($"320 bootstrap portions committed: {portions}");
        }
        output.WriteLine($"320 bootstrap: receipts={receipts},native_channels={channels},witnesses={witnesses},portions={portions},ms={bootstrap.Elapsed.TotalMilliseconds:F1}");
        Assert.Equal(expected,await Query(discovery));Assert.Equal(expectedChannels,await Scalar(channelRows));
        Assert.Equal(expectedNative,await Query(native,scope));
        // The fixture and worker both read the inbox before this baseline.
        // Publish both backends' pending counts before sampling the steady-state reads.
        await PostCollectionPostgres.Sql(db,"select pg_stat_force_next_flush()",ct);
        await PostCollectionPostgres.Sql(worker,"select pg_stat_force_next_flush()",ct);
        await PostCollectionPostgres.Sql(db,"select pg_stat_clear_snapshot()",ct);
        const string counters="select jsonb_build_object('sequential',seq_tup_read,'fetched',idx_tup_fetch,'read',heap_blks_read+idx_blks_read,'hit',heap_blks_hit+idx_blks_hit)::text from pg_stat_user_tables join pg_statio_user_tables using(relid,schemaname,relname) where relname='sli_agent_packet_inbox'";
        var startCounters=JsonNode.Parse(await Scalar(counters))!;
        // PG18's bundled extension evicts shared buffers in this disposable
        // cluster only. OS cache is not flushed and is not claimed as cold.
        if(full)await PostCollectionPostgres.Sql(db,"create extension pg_buffercache",ct);
        for(int pass=0;pass<3;pass++) {
            if(full)await Scalar("select to_jsonb(e)::text from pg_buffercache_evict_all() e");
            var timer=Stopwatch.StartNew();Assert.Equal(expected,await Query(discovery));
            output.WriteLine($"320 discovery pass {pass+2}: {timer.Elapsed.TotalMilliseconds:F1} ms");Assert.True(timer.Elapsed<TimeSpan.FromSeconds(1));
            if(full)await Scalar("select to_jsonb(e)::text from pg_buffercache_evict_all() e");
            timer.Restart();Assert.Equal(expectedNative,await Query(native,scope));
            output.WriteLine($"320 native pass {pass+2}: {timer.Elapsed.TotalMilliseconds:F1} ms");Assert.True(timer.Elapsed<TimeSpan.FromSeconds(1));
        }
        await PostCollectionPostgres.Sql(worker,"select pg_stat_force_next_flush()",ct);
        await PostCollectionPostgres.Sql(db,"select pg_stat_clear_snapshot()",ct);
        var endCounters=JsonNode.Parse(await Scalar(counters))!;
        long Delta(string key)=>endCounters[key]!.GetValue<long>()-startCounters[key]!.GetValue<long>();
        output.WriteLine($"320 repeated inbox access: sequential rows={Delta("sequential")},fetched={Delta("fetched")},disk blocks={Delta("read")},cache blocks={Delta("hit")}");
        Assert.Equal(0,Delta("sequential"));Assert.InRange(Delta("fetched"),0,32);Assert.InRange(Delta("read")+Delta("hit"),0,10000);
        // Current channel configuration and status govern every projection.
        await SetSystem(false);
        await Query(discovery);Assert.Equal("1",await Scalar("select count(*)::text from semantic_t109_channels"));
        await PostCollectionPostgres.Sql(db,"update sli_agents set status='disabled'",ct);
        Assert.Equal("[]",await Query(discovery));Assert.Equal("[]",await Query(native,scope));
        Assert.Equal("0",await Scalar("select count(*)::text from semantic_t109_channels"));
        await PostCollectionPostgres.Sql(db,"update sli_agents set status='active'",ct);
        await SetSystem(true);
        // Policy revision changed through the audited issuer, so compare scopes
        // and channels and use its new config in subsequent equality checks.
        expected=await Query(discovery);Assert.Equal(2,JsonNode.Parse(expected)!.AsArray().Count);Assert.Equal(expectedChannels,await Scalar(channelRows));
        await SetSystem(true,false);
        Assert.Equal("[]",await Query(discovery));Assert.Equal("[]",await Query(native,scope));
        Assert.Equal("0",await Scalar("select count(*)::text from semantic_t109_channels"));
        await SetSystem(true,true);
        expected=await Query(discovery);Assert.Equal(2,JsonNode.Parse(expected)!.AsArray().Count);Assert.Equal(expectedChannels,await Scalar(channelRows));
        // Acknowledgement is separate from the candidate cursor. Publication
        // rereads bypass it; cancellation before acknowledgement can retry.
        Assert.Equal(expectedNative,await Query(native,scope));
        await using(var seen=new NpgsqlCommand("insert into semantic_t109_seen(source_key,native_id,scope_json,storage_kind) values(repeat('b',64),'900001',@scope::jsonb,'core_event')",db)) {
            seen.Parameters.AddWithValue("scope",scope);await seen.ExecuteNonQueryAsync(ct);
        }
        Assert.Equal("[]",await Query(native,scope));
        Assert.Equal(expectedNative,await Query(native.Replace("@scope::jsonb)","@scope::jsonb,'2026-11-01','2026-11-02')",StringComparison.Ordinal),scope));
        await CheckReview320(db,worker,fixture,scope,ct);
        await CheckLate320(db,worker,scope,ct,full);
        // Workstation generations come from observations, not receipts. The
        // original discovery accepts imported source-matched older envelopes
        // without a generation field; the summary must preserve that contract.
        await PostCollectionPostgres.Sql(db,"""
            insert into sli_agents(id,host_id,key_fingerprint,assigned_modules)
            values(md5('320-ws-agent')::uuid,md5('320-ws-host')::uuid,repeat('f',64),'[{"module_id":"sli.workstations","enabled":true,"config":{}}]');
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            values(md5('320-ws-agent')::uuid,'sli.workstations',1,md5('320-ws-packet')::uuid,repeat('f',64),
                jsonb_build_object('source_instance_id',md5('320-ws-host')::uuid::text),'{"status":"committed"}');
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
            select packet_id,envelope,'{"contract":"sli.collection-packet.v1"}','[]',now() from sli_agent_receipts where packet_id=md5('320-ws-packet')::uuid;
            insert into sli_plugin_workstations.observations(id,agent_key,entity_id,family,event_id,observed_at,observation,observation_sha256,source_xml)
            values(repeat('f',64),md5('320-ws-agent')::uuid::text,1,'usb',4624,now()-interval '4 years',
                '{"generation":"observation-only"}',repeat('f',64),'<Event/>');
            """,ct);
        var workstation=Assert.Single(JsonNode.Parse(await Query(discovery))!.AsArray(),n=>n!["scope"]!["plugin_id"]!.GetValue<string>()=="sli.workstations");
        Assert.Equal("observation-only",workstation!["scope"]!["source_generation"]!.GetValue<string>());
        Assert.Equal("0",await Scalar("select count(*)::text from semantic_default_state320 where module_id='sli.workstations'"));
        // Progress reaches the actual worker result (including the empty
        // default-policy case); it contains no event or principal data.
        var batch=await new DetectionProducer(new(),new()).RunOnceAsync(worker,ct,refreshImport:false);
        Assert.True(batch.ImportSummary["bootstrap_done"]!.GetValue<bool>());
        // Exact rollback/reapply from the previous maximum, including volatility.
        await fixture.Pg.ApplyFileAsync(rollback,null,ct);
        Assert.Equal(beforeDefinitions,await Scalar(definitions));Assert.Equal(authority,await Scalar(catalog));
        await fixture.Pg.ApplyFileAsync(forward,null,ct);
        Assert.Equal(authority,await Scalar(catalog));

        async Task SetSystem(bool enabled,bool? moduleEnabled=null) {
            await using var tx=await db.BeginTransactionAsync(ct);
            await using var change=new NpgsqlCommand("""
                insert into sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy)
                select id,policy_revision+1,jsonb_set(jsonb_set(jsonb_set(assigned_modules,'{0,config,channels,System}',@enabled::jsonb),
                    '{0,config,policy_revision}',to_jsonb((policy_revision+1)::text)),
                    '{0,enabled}',coalesce(@module::jsonb,assigned_modules#>'{0,enabled}')),collection_policy from sli_agents;
                update sli_agents a set policy_revision=a.policy_revision+1,assigned_modules=h.assigned_modules
                from sli_agent_policy_history h where h.agent_id=a.id and h.revision=a.policy_revision+1;
                """,db,tx);
            change.Parameters.AddWithValue("enabled",enabled?"true":"false");change.Parameters.AddWithValue("module",NpgsqlTypes.NpgsqlDbType.Text,moduleEnabled is null?DBNull.Value:moduleEnabled.Value?"true":"false");
            await change.ExecuteNonQueryAsync(ct);await tx.CommitAsync(ct);
        }
    }

    private async Task CheckReview320(NpgsqlConnection db,NpgsqlConnection worker,SqlPostgresFixture fixture,string scope,CancellationToken ct)
    {
        async Task<string> Scalar(string sql,NpgsqlConnection? connection=null) {
            if(connection==worker && sql.Contains("read_t109_native",StringComparison.Ordinal))
                await RefreshSummary320Async(worker,ct);
            await using var q=new NpgsqlCommand(sql,connection??db);q.Parameters.AddWithValue("scope",scope);
            return (string)(await q.ExecuteScalarAsync(ct))!;
        }
        async Task Read(NpgsqlConnection connection,string sql) {
            await using var q=new NpgsqlCommand(sql,connection);q.Parameters.AddWithValue("scope",scope);await q.ExecuteNonQueryAsync(ct);
        }
        string installation=JsonNode.Parse(scope)!["installation_id"]!.GetValue<string>();
        string decoy=$"select * from read_account_decoy_events('{installation}','sli.windows.ad-dc',md5('semantic-host')::uuid::text,md5('semantic-host')::uuid::text,repeat('c',64),null)";
        const string native="select * from read_t109_native(@scope::jsonb)";
        // Read-only callers get PostgreSQL's write refusal for BOTH public
        // VOLATILE readers, rather than silently reading without a checkpoint.
        foreach(string query in new[]{native,decoy}) {
            await using var tx=await worker.BeginTransactionAsync(ct);
            await Read(worker,"set transaction read only");
            var error=await Assert.ThrowsAsync<PostgresException>(()=>Read(worker,query));
            Assert.Equal("25006",error.SqlState);await tx.RollbackAsync(ct);
        }
        foreach(string checkpoint in new[]{"null","repeat('a',65)","repeat('a',63)","repeat('A',64)","repeat('a',64)||chr(10)","repeat('a',10000)"}) {
            var error=await Assert.ThrowsAsync<PostgresException>(()=>Read(worker,decoy.Replace("repeat('c',64)",checkpoint)));
            Assert.Equal("42501",error.SqlState);
        }
        // Exact instance/generation, two installations with different log_source
        // bindings. Rejected log sources must never enter either pending set.
        await Read(db,"""
            insert into finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
                source_instance_id,source_generation,collection_scope_id,storage_kind,agent_id,agent_key,log_source_id)
            select principal_oid,principal_name,md5('320-other-installation')::uuid,plugin_id,source_instance_id,
                source_generation,collection_scope_id,storage_kind,agent_id,agent_key,
                (select id from log_sources where name='System')
            from finding_evidence_source_bindings where installation_id=(@scope::jsonb->>'installation_id')::uuid
                and source_instance_id=@scope::jsonb->>'source_instance_id' and storage_kind='core_event';
            """);
        // Use named columns below as the binding catalog also carries timestamps.
        string foreignScope=JsonNode.Parse(scope)!.ToJsonString();
        var foreign=JsonNode.Parse(foreignScope)!.AsObject();
        foreign["installation_id"]=await Scalar("select md5('320-other-installation')::uuid::text");
        await using(var q=new NpgsqlCommand(native,worker)) {q.Parameters.AddWithValue("scope",foreign.ToJsonString());await q.ExecuteNonQueryAsync(ct);}
        Assert.Equal("0",await Scalar("select count(*)::text from semantic_source_pending320 p join semantic_source_cursor320 q using(principal_oid,principal_name,scope_key,kind,checkpoint) where q.scope_json->>'installation_id'=md5('320-other-installation')::uuid::text"));
        await Read(worker,native);
        Assert.Equal("0",await Scalar("select count(*)::text from semantic_source_pending320 p join semantic_source_cursor320 q using(principal_oid,principal_name,scope_key,kind,checkpoint) join semantic_event_facts320 f on f.core_id=p.core_id where q.kind='native' and f.event_id<>1102"));
        // Fill the new finite principal quota cheaply; repeated known cursors
        // still work, but an unbounded stream of checkpoint hashes is refused.
        await Read(db,"""
            insert into semantic_source_cursor320(principal_oid,principal_name,scope_key,kind,checkpoint,scope_json)
            select 'sli_semantic_login'::regrole,'sli_semantic_login','quota:'||n,'decoy',md5(n::text)||md5(n::text),@scope::jsonb
            from generate_series(1,256-(select count(*)::int from semantic_source_cursor320 where principal_name='sli_semantic_login')) n;
            """);
        var quota=await Assert.ThrowsAsync<PostgresException>(()=>Read(worker,decoy));Assert.Equal("54000",quota.SqlState);
        await Read(worker,native);
        Assert.Equal("256",await Scalar("select count(*)::text from semantic_source_cursor320 where principal_name='sli_semantic_login'"));
        await Read(db,"delete from semantic_source_cursor320 where scope_key like 'quota:%'");
        // Detector owns both the refresh watermark and refreshed cache rows.
        // Receipt insertion (even for the SAME dirty packet) must commit now.
        await using(var detector=await worker.BeginTransactionAsync(ct)) {
            await Read(db,"update sli_agent_receipts set receipt=receipt where packet_id=md5('semantic-packet')::uuid");
            await Read(worker,native);
            await Read(db,"set statement_timeout='1s';insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt) select agent_id,module_id,100000001,md5('320-receipt-nonblocking')::uuid,envelope_sha256,envelope,receipt from sli_agent_receipts where packet_id=md5('semantic-packet')::uuid;update sli_agent_receipts set receipt=receipt where packet_id=md5('semantic-packet')::uuid;reset statement_timeout");
            await detector.CommitAsync(ct);
        }
        // Revision allocation belongs to the serialized refresh, NOT ingestion.
        // Two ingest transactions allocate queue identities in reverse commit
        // order; the read between commits cannot advance past the late packet.
        await using var late=new NpgsqlConnection(fixture.Pg.ConnectionString);await late.OpenAsync(ct);
        await using var early=new NpgsqlConnection(fixture.Pg.ConnectionString);await early.OpenAsync(ct);
        async Task Packet(NpgsqlConnection connection,string tag,int number) {
            var rows=JsonNode.Parse(await Scalar("select event_rows::text from sli_agent_packet_inbox where packet_id=md5('semantic-packet')::uuid"))!.AsArray();
            var row=rows[0]!.DeepClone().AsObject();row["record_id"]=number;
            row["xml"]=row["xml"]!.GetValue<string>().Replace("<EventRecordID>1</EventRecordID>","<EventRecordID>"+number+"</EventRecordID>");
            string hash=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(SourceJson.SerializeSorted(row))));
            await using var q=new NpgsqlCommand("""
                insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                select agent_id,module_id,@number,md5(@tag)::uuid,envelope_sha256,envelope,receipt from sli_agent_receipts where packet_id=md5('semantic-packet')::uuid;
                insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
                select md5(@tag)::uuid,envelope,packet,@rows::jsonb,now() from sli_agent_packet_inbox where packet_id=md5('semantic-packet')::uuid;
                insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
                select @number,server_id,log_source_id,'agent-packet:'||md5(@tag)::uuid,file_format,@hash from raw_log_files where id=900001;
                """,connection);
            q.Parameters.AddWithValue("rows",new JsonArray(row).ToJsonString());q.Parameters.AddWithValue("hash",hash);
            q.Parameters.AddWithValue("number",number);q.Parameters.AddWithValue("tag",tag);await q.ExecuteNonQueryAsync(ct);
        }
        await Packet(late,"320-late-commit",81000001);
        await Packet(early,"320-early-commit",81000002);
        async Task Core(NpgsqlConnection connection,int number) {
            await using var q=new NpgsqlCommand("""
                insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,event_record_id,channel_id,provider_id,computer_id,
                    time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
                select @number,@number,server_id,domain_id,log_source_id,event_id,@number,channel_id,provider_id,computer_id,
                    time_created_utc,normalized_at,decode((select sha256 from raw_log_files where id=@number),'hex'),decode((select sha256 from raw_log_files where id=@number),'hex'),noise_catalog_version from events_v2_core where id=900001;
                """,connection);
            q.Parameters.AddWithValue("number",number);await q.ExecuteNonQueryAsync(ct);
        }
        await using(var low=await late.BeginTransactionAsync(ct)) {
            await Core(late,81000001);
            await using(var high=await early.BeginTransactionAsync(ct)) {await Core(early,81000002);await high.CommitAsync(ct);}
            // A detector revision is allocated but still uncommitted. Another
            // reader must neither see it nor advance past it; SKIP LOCKED
            // also prevents a second writer allocating a later revision.
            await using(var refresh=await early.BeginTransactionAsync(ct)) {
                await Read(early,"select semantic_import_refresh320()");
                Assert.Equal("[]",await Scalar("select coalesce(jsonb_agg(native_id),'[]')::text from read_t109_native(@scope::jsonb)",worker));
                await refresh.CommitAsync(ct);
            }
            Assert.Equal("[\"81000002\"]",await Scalar("select coalesce(jsonb_agg(native_id order by native_id),'[]')::text from read_t109_native(@scope::jsonb)",worker));
            await low.CommitAsync(ct);
        }
        Assert.Equal("[\"81000001\", \"81000002\"]",await Scalar("select coalesce(jsonb_agg(native_id order by native_id),'[]')::text from read_t109_native(@scope::jsonb)",worker));
        Assert.Equal("true",await Scalar("select (a.revision>b.revision)::text from semantic_event_facts320 a,semantic_event_facts320 b where a.core_id=81000001 and b.core_id=81000002"));
        // Independent pre-320 reader, not the acceleration helper itself.
        await Read(db,"""
            set role adlog_storage_owner;
            do $$ declare definition text; begin
                select d.definition into strict definition from semantic_summary_definitions320 d
                where signature like 'read_t109_native(%';
                execute replace(definition,'public.read_t109_native(', 'public.semantic_native_full_test320(');
            end $$;
            revoke all on function semantic_native_full_test320(jsonb,timestamptz,timestamptz) from public;
            grant execute on function semantic_native_full_test320(jsonb,timestamptz,timestamptz) to adlog_semantic_worker;
            reset role;
            """);
        const string aggregate="select coalesce(jsonb_agg(to_jsonb(r) order by native_id),'[]')::text from read_t109_native(@scope::jsonb) r";
        string accelerated=await Scalar(aggregate,worker);
        Assert.Equal(accelerated,await Scalar(aggregate.Replace("read_t109_native", "semantic_native_full_test320"),worker));
        var second=JsonNode.Parse(scope)!.AsObject();
        second["source_instance_id"]=await Scalar("select md5('semantic-host1')::uuid::text");
        second["source_generation"]=second["source_instance_id"]!.DeepClone();
        foreach(string reader in new[]{"read_t109_native","semantic_native_full_test320"}) {
            await using var q=new NpgsqlCommand(aggregate.Replace("read_t109_native",reader),worker);q.Parameters.AddWithValue("scope",second.ToJsonString());
            string result=(string)(await q.ExecuteScalarAsync(ct))!;
            if(reader=="read_t109_native")foreignScope=result;else Assert.Equal(foreignScope,result);
        }
        await Read(db,"drop function semantic_native_full_test320(jsonb,timestamptz,timestamptz)");
        await Read(db,"update semantic_import_state320 set bootstrap_done=false");
        await using(var fence=await db.BeginTransactionAsync(ct)) {
            await Read(db,"select 1 from semantic_import_state320 for update");
            Assert.Equal(accelerated,await Scalar(aggregate,worker));
            await fence.RollbackAsync(ct);
        }
        await Read(db,"update semantic_import_state320 set bootstrap_done=true");
        await Read(db,"delete from events_v2_core where id in (81000001,81000002);delete from finding_evidence_source_bindings where installation_id=md5('320-other-installation')::uuid");
    }

    private async Task CheckLate320(NpgsqlConnection db,NpgsqlConnection worker,string scope,CancellationToken ct,bool full)
    {
        async Task<JsonArray> Rows(string sql) {
            await RefreshSummary320Async(worker,ct);
            await using var q=new NpgsqlCommand("select coalesce(jsonb_agg(to_jsonb(r) order by to_jsonb(r)::text),'[]')::text from ("+sql+") r",worker);
            q.Parameters.AddWithValue("scope",scope);return JsonNode.Parse((string)(await q.ExecuteScalarAsync(ct))!)!.AsArray();
        }
        string installation=JsonNode.Parse(scope)!["installation_id"]!.GetValue<string>();
        string decoy=$"select * from read_account_decoy_events('{installation}','sli.windows.ad-dc',md5('semantic-host')::uuid::text,md5('semantic-host')::uuid::text,repeat('a',64),null)";
        // No normalized rows yet: the source cursor must not drop delayed work.
        Assert.Empty(await Rows(decoy));
        await PostCollectionPostgres.Sql(db,"""
            insert into decoy_label_versions(id,revision,kind,identity,owner,reason,active,active_from,actor_type,actor_id,readiness,plugin_id,entity_id,collection_scope_id)
            values(md5('320-label')::uuid,1,'account','{"domain_id":1,"entity_id":1,"sid":"S-1-5-21-100000001-200000002-300000003-1001","guid":"00000000-0000-4000-8000-000000000001"}',
                'synthetic','synthetic',true,'2026-01-01','session',1,'{"state":"ready"}','sli.ad',1,'ad-domain:1');
            insert into normalized_events(normalized_event_id,source_event_id,semantic_contract_version,normalizer_id,normalizer_version,
                processing_status,normalized_at,source_event_sha256,semantic_sha256,semantic_type,occurred_at_utc,roles_json,source_ingested_at,source_identity_json)
            select md5('320-normalized:'||id)::uuid,id,1,'windows.named-eventdata','1','normalized',now(),normalized_hash,sha256(id::text::bytea),
                'authentication.session.created',time_created_utc,'{}',migrated_at,
                jsonb_build_object('id',id,'server_id',server_id,'domain_id',domain_id,'log_source_id',log_source_id,'event_id',event_id,
                    'time_created_utc',time_created_utc,'normalized_hash',encode(normalized_hash,'hex'),'migrated_at',migrated_at,'channel','Security')
                from events_v2_core e where id in(900002,900003);
            """,ct);
        async Task Evict() {if(full)await PostCollectionPostgres.Sql(db,"select pg_buffercache_evict_all()",ct);}
        await Evict();var timer=Stopwatch.StartNew();Assert.Equal(2,(await Rows(decoy)).Count);
        output.WriteLine($"320 delayed normalization: {timer.Elapsed.TotalMilliseconds:F1} ms");Assert.True(timer.Elapsed<TimeSpan.FromSeconds(1));
        await using(var mark=new NpgsqlCommand("""
            insert into semantic_account_decoy_checks(checkpoint_key,normalized_event_id,scope_json,result_code)
            select repeat('a',64),normalized_event_id,@scope::jsonb,'no_match' from normalized_events;
            """,db)) {mark.Parameters.AddWithValue("scope",scope);await mark.ExecuteNonQueryAsync(ct);}
        for(int pass=0;pass<3;pass++) {
            await Evict();timer.Restart();Assert.Empty(await Rows(decoy));output.WriteLine($"320 decoy pass {pass+2}: {timer.Elapsed.TotalMilliseconds:F1} ms");Assert.True(timer.Elapsed<TimeSpan.FromSeconds(1));
        }
        await PostCollectionPostgres.Sql(db,"""
            insert into normalized_events(normalized_event_id,source_event_id,semantic_contract_version,normalizer_id,normalizer_version,
                processing_status,normalized_at,source_event_sha256,semantic_sha256,semantic_type,occurred_at_utc,roles_json,source_ingested_at,source_identity_json)
            select md5('320-superseded')::uuid,source_event_id,semantic_contract_version+1,normalizer_id,normalizer_version,
                processing_status,normalized_at-interval '1 day',source_event_sha256,semantic_sha256,semantic_type,occurred_at_utc,
                roles_json,source_ingested_at,source_identity_json from normalized_events where source_event_id=900002 limit 1;
            """,ct);
        Assert.Empty(await Rows(decoy));
        await using(var pending=new NpgsqlCommand("select count(*) from semantic_source_pending320 where kind='decoy'",db))
            Assert.Equal(0L,(long)(await pending.ExecuteScalarAsync(ct))!);
        // Old occurred_at, new core in an ALREADY traversed packet. No arbitrary
        // event-time lookback or id watermark is allowed to lose this event.
        await using(var q=new NpgsqlCommand("select event_rows::text from sli_agent_packet_inbox where packet_id=md5('semantic-packet')::uuid",db)) {
            var packet=JsonNode.Parse((string)(await q.ExecuteScalarAsync(ct))!)!.AsArray();
            var late=packet[0]!.DeepClone().AsObject();late["record_id"]=11;late["time_created"]="2026-10-01T00:00:00Z";
            late["xml"]=late["xml"]!.GetValue<string>().Replace("<EventRecordID>1</EventRecordID>","<EventRecordID>11</EventRecordID>").Replace("2026-11-01T00:00:00Z","2026-10-01T00:00:00Z");packet.Add(late);
            string hash=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(SourceJson.SerializeSorted(late))));
            await using var insert=new NpgsqlCommand("""
                update sli_agent_packet_inbox set event_rows=@rows::jsonb where packet_id=md5('semantic-packet')::uuid;
                insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,event_record_id,channel_id,provider_id,computer_id,
                    time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
                select 80000011,raw_log_file_id,server_id,domain_id,log_source_id,event_id,11,channel_id,provider_id,computer_id,
                    '2026-10-01',now(),decode(@hash,'hex'),decode(@hash,'hex'),noise_catalog_version from events_v2_core where id=900001;
                """,db);insert.Parameters.AddWithValue("rows",packet.ToJsonString());insert.Parameters.AddWithValue("hash",hash);await insert.ExecuteNonQueryAsync(ct);
        }
        var result=Assert.Single(await Rows("select * from read_t109_native(@scope::jsonb)"));Assert.Equal("80000011",result!["native_id"]!.GetValue<string>());
        // Previously valid cached candidates cannot bypass current proof.
        await PostCollectionPostgres.Sql(db,"update sli_agent_packet_inbox set envelope=envelope||'{\"tampered\":true}' where packet_id=md5('semantic-packet')::uuid",ct);
        Assert.Empty(await Rows("select * from read_t109_native(@scope::jsonb)"));
        await PostCollectionPostgres.Sql(db,"update sli_agent_packet_inbox set envelope=envelope-'tampered' where packet_id=md5('semantic-packet')::uuid",ct);
        Assert.Single(await Rows("select * from read_t109_native(@scope::jsonb)"));
        foreach(bool foreign in new[]{true,false}) {
            await using var alter=new NpgsqlCommand("""
                update sli_agent_receipts set envelope=jsonb_set(envelope,'{agent_id}',to_jsonb(@agent::text)) where packet_id=md5('semantic-packet')::uuid;
                update sli_agent_packet_inbox i set envelope=r.envelope from sli_agent_receipts r
                    where i.packet_id=r.packet_id and i.packet_id=md5('semantic-packet')::uuid;
                """,db);
            alter.Parameters.AddWithValue("agent",foreign?"00000000-0000-4000-8000-000000000099":new Guid(MD5.HashData(Encoding.UTF8.GetBytes("semantic-agent")),bigEndian:true).ToString());
            await alter.ExecuteNonQueryAsync(ct);
            if(foreign)Assert.Empty(await Rows("select * from read_t109_native(@scope::jsonb)"));
            else Assert.Single(await Rows("select * from read_t109_native(@scope::jsonb)"));
        }
        // A newly imported UUID behind the bootstrap key is delivered by the
        // transactional dirty queue, including the smallest possible UUID.
        await using(var original=new NpgsqlCommand("select event_rows::text from sli_agent_packet_inbox where packet_id=md5('semantic-packet')::uuid",db)) {
            var late=JsonNode.Parse((string)(await original.ExecuteScalarAsync(ct))!)!.AsArray().Last()!.DeepClone().AsObject();
            late["record_id"]=12;late["xml"]=late["xml"]!.GetValue<string>().Replace("<EventRecordID>11</EventRecordID>","<EventRecordID>12</EventRecordID>");
            string hash=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(SourceJson.SerializeSorted(late))));
            await using var insert=new NpgsqlCommand("""
                insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                select agent_id,module_id,100000000,'00000000-0000-0000-0000-000000000000',envelope_sha256,envelope,receipt
                from sli_agent_receipts where packet_id=md5('semantic-packet')::uuid;
                insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows)
                select '00000000-0000-0000-0000-000000000000',envelope,packet,@rows::jsonb from sli_agent_packet_inbox where packet_id=md5('semantic-packet')::uuid;
                insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
                select 80000012,server_id,log_source_id,'agent-packet:00000000-0000-0000-0000-000000000000',file_format,@hash
                    from raw_log_files where id=900001;
                insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,event_id,event_record_id,channel_id,provider_id,computer_id,
                    time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
                select 80000012,80000012,server_id,domain_id,log_source_id,event_id,12,channel_id,provider_id,computer_id,
                    '2026-10-01',now(),decode(@hash,'hex'),decode(@hash,'hex'),noise_catalog_version from events_v2_core where id=900001;
                """,db);
            insert.Parameters.AddWithValue("rows",new JsonArray(late).ToJsonString());insert.Parameters.AddWithValue("hash",hash);await insert.ExecuteNonQueryAsync(ct);
        }
        Assert.Single(await Rows("select * from read_t109_native(@scope::jsonb)"));
        await PostCollectionPostgres.Sql(db,"update sli_agent_packet_inbox set imported_at=now() where packet_id='00000000-0000-0000-0000-000000000000'",ct);
        var imported=await Rows("select * from read_t109_native(@scope::jsonb)");
        Assert.Equal(new[]{"80000011","80000012"},imported.Select(n=>n!["native_id"]!.GetValue<string>()).Order().ToArray());
        await using var denied=new NpgsqlCommand("select has_table_privilege(current_user,'semantic_import_state320','SELECT')",worker);
        Assert.False((bool)(await denied.ExecuteScalarAsync(ct))!);
    }
}
