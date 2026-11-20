using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.Ingress;
using Sli.Server.Infrastructure;
using Sli.Server.Storage.Direct;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentInboxDeferralTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData(true,false)]
    [InlineData(true,true)]
    [InlineData(false,false)]
    [InlineData(false,true)]
    public async Task Legacy_short_event_replay_imports_or_quarantines_once_with_a_durable_reason(bool committed,bool conflict)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        Guid agent=Guid.NewGuid(),host=Guid.NewGuid();
        await SeedAsync(admin,fixture.Pg.Root,Guid.NewGuid(),agent,host,ct);
        var sample=Sample(agent,host,"dc.example.test",1);
        await using(var tx=await admin.BeginTransactionAsync(ct)) {
            await InsertAsync(admin,tx,sample,1,ct); await tx.CommitAsync(ct);
        }
        var settings=new Dictionary<string,string?> { ["ADLOG_STORAGE_V2_WORKER_DSN"]=fixture.Dsn("sli_storage_login") };
        await using var runtime=DirectAdDcRuntime.TryCreate(settings.GetValueOrDefault,_=>throw new InvalidOperationException(),Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json"));
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user")); await app.OpenAsync(ct);
        var consumer=new AgentWorkstationInboxConsumer(new BorrowedOnly(),runtime);
        Assert.Equal(1,(await consumer.RunOnceAsync(app,1,ct)).Imported);
        await PostCollectionPostgres.Sql(admin,"""
            update event_hot set source_sha256=null,event_record_id=null,method=method-'$origin';
            update sli_agent_packet_inbox set imported_at=null;
            """,ct);
        if(conflict) await PostCollectionPostgres.Sql(admin,"update event_hot set actor='different-stored-actor'",ct);
        consumer=new AgentWorkstationInboxConsumer(new BorrowedOnly(),runtime);
        if(committed) {
            var replay=await consumer.RunOnceAsync(app,1,ct);
            Assert.Equal(conflict?0:1,replay.Imported); Assert.Equal(conflict?1:0,replay.Quarantined); Assert.Empty(replay.PendingReasons);
        } else {
            await using var tx=await app.BeginTransactionAsync(ct);
            var replay=await AgentWorkstationInboxConsumer.ProcessNextAsync(app,tx,null,ct,runtime);
            Assert.Equal(!conflict,replay.Imported); Assert.Equal(conflict,replay.Quarantined);
            Assert.Equal(conflict?"short_event_attestation_failed":null,replay.PendingReason);
            await tx.CommitAsync(ct);
        }
        Assert.Equal(0,(await consumer.RunOnceAsync(app,1,ct)).Scanned);
        await using(var stored=new NpgsqlCommand("""
            select i.imported_at is not null,q.reason_code,h.source_sha256 is not null,
                (select sum(event_count)::bigint from event_cold_daily)
            from sli_agent_packet_inbox i left join sli_agent_packet_quarantine q using(packet_id) cross join event_hot h
            """,admin)) {
            await using var r=await stored.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct));
            Assert.Equal(!conflict,r.GetBoolean(0)); Assert.Equal(conflict?"short_event_attestation_failed":null,r.IsDBNull(1)?null:r.GetString(1));
            Assert.Equal(!conflict,r.GetBoolean(2)); Assert.Equal(1L,r.GetInt64(3));
        }
        // The same durable refusal feeds system status, even on the next empty poll.
        if(conflict && committed) {
            var history=Sample(agent,host,"dc.example.test",2);
            history.Envelope["module_id"]=AgentAdDcValidator.History; history.Envelope["policy_revision"]="old";
            await using var tx=await admin.BeginTransactionAsync(ct);
            await InsertAsync(admin,tx,history,2,ct);
            await using var quarantine=new NpgsqlCommand("insert into sli_agent_packet_quarantine(packet_id,reason_code,event_ordinal) values(@packet,'short_event_summary_conflict',0)",admin,tx);
            quarantine.Parameters.AddWithValue("packet",Guid.Parse((string)history.Envelope["packet_id"]!));
            await quarantine.ExecuteNonQueryAsync(ct); await tx.CommitAsync(ct);
        }
        foreach(string sql in new[] { Sli.Server.Operations.OperationsSql.Streams,
            File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(),"server-dotnet/src/Sli.Server/Installation/setup-streams.sql")).Replace("@p0","@requested") }) {
            await using var status=new NpgsqlCommand(sql,app);
            status.Parameters.AddWithValue("requested",new JsonArray(new JsonObject {
                ["agent_id"]=agent.ToString(),["module_id"]="sli.windows.ad-dc",["revision"]="1",["channel"]="Security",["snapshot"]=false
            }).ToJsonString());
            await using var r=await status.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct));
            int reason=r.GetOrdinal("import_failure_reason");
            Assert.Equal(conflict ? committed ? "short_event_summary_conflict" : "short_event_attestation_failed" : null,r.IsDBNull(reason)?null:r.GetString(reason));
            Assert.True(r.IsDBNull(r.GetOrdinal("pending_since")));
            Assert.Equal(!conflict,r.IsDBNull(r.GetOrdinal("import_failure_at")));
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Same_dc_aliases_and_compatible_versions_import_once_per_log_record()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        Guid first=Guid.NewGuid(),second=Guid.NewGuid(),host=Guid.NewGuid();
        await SeedAsync(admin,fixture.Pg.Root,first,second,host,ct);
        await using(var fix=new NpgsqlCommand("update sli_agent_module_bindings set source_name='dc.example.test' where agent_id=@id",admin)) {
            fix.Parameters.AddWithValue("id",first); await fix.ExecuteNonQueryAsync(ct);
        }
        var tail=Sample(first,host,"DC",1,"dc.example.test");
        await using(var tx=await admin.BeginTransactionAsync(ct)) {
            var current=Sample(second,host,"dc.example.test",1); current.Envelope["module_version"]="1.2.0";
            await InsertAsync(admin,tx,tail,1,ct); await InsertAsync(admin,tx,current,2,ct); await tx.CommitAsync(ct);
        }
        var settings=new Dictionary<string,string?> { ["ADLOG_STORAGE_V2_WORKER_DSN"]=fixture.Dsn("sli_storage_login") };
        await using var runtime=DirectAdDcRuntime.TryCreate(settings.GetValueOrDefault,_=>throw new InvalidOperationException(),Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json"));
        Assert.NotNull(runtime);
        // A completed short-store import retains the original source proof.
        await using(var legacy=await admin.BeginTransactionAsync(ct)) {
            var source=await DirectAdDcPacket.SourceAsync(admin,legacy,"DC",ct);
            // Use the exact retained JSONB representation, as the inbox reader does.
            await using var retained=new NpgsqlCommand("select event_rows::text from sli_agent_packet_inbox where packet_id=@id",admin,legacy);
            retained.Parameters.AddWithValue("id",Guid.Parse((string)tail.Envelope["packet_id"]!));
            var rows=JsonNode.Parse((string)(await retained.ExecuteScalarAsync(ct))!)!.AsArray();
            await DirectAdDcPacket.PublishAsync(admin,legacy,runtime.Worker,Envelope.Parse(tail.Envelope),tail.Payload,rows,runtime.CatalogPath,"DC",source.Server,source.Domain,source.Site,ct);
            await legacy.CommitAsync(ct);
        }
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user")); await app.OpenAsync(ct);
        var result=await new AgentWorkstationInboxConsumer(new BorrowedOnly(),runtime).RunOnceAsync(app,16,ct);
        // PublishAsync already completed the first packet; only its alias is pending.
        Assert.Equal(1,result.Imported); Assert.Empty(result.PendingReasons); await AssertCountsAsync(admin,0,2,ct);
        await using var count=new NpgsqlCommand("select count(*) from event_hot",admin);
        Assert.Equal(1L,await count.ExecuteScalarAsync(ct));
        await using(var proof=new NpgsqlCommand("select bool_and(source_sha256 is not null and event_record_id=1) from event_hot",admin))
            Assert.Equal(true,await proof.ExecuteScalarAsync(ct));
        await using(var identities=new NpgsqlCommand("select count(*) from storage_v2_event_identity_allocations",admin))
            Assert.Equal(1L,await identities.ExecuteScalarAsync(ct));
        // Old queues retain their attested transport alias, but replacement must
        // exclude them even if an earlier reconciliation admitted the tail.
        await using(var tx=await admin.BeginTransactionAsync(ct)) {
            await InsertAsync(admin,tx,Sample(first,host,"DC",2,"dc.example.test"),3,ct);
            await using var retire=new NpgsqlCommand("""
                update sli_agents set status='replaced' where id=@id;
                insert into sli_agent_audit(action,actor,target,details) values('disable','synthetic',@target,
                    '{"reason":"registration_replaced","tail_import":true}'::jsonb)
                """,admin,tx);
            retire.Parameters.AddWithValue("id",first); retire.Parameters.AddWithValue("target",first.ToString()); await retire.ExecuteNonQueryAsync(ct);
            await tx.CommitAsync(ct);
        }
        var tailResult=await new AgentWorkstationInboxConsumer(new BorrowedOnly(),runtime).RunOnceAsync(app,16,ct);
        Assert.Equal(0,tailResult.Scanned); Assert.Equal(0,tailResult.Imported); Assert.Empty(tailResult.PendingReasons); Assert.Equal(1L,await count.ExecuteScalarAsync(ct));
        await AssertCountsAsync(admin,1,2,ct);
    }

    [Fact]
    public async Task Replaced_agent_queue_is_retained_without_claiming_or_blocking_active_import()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        Guid old=Guid.NewGuid(),current=Guid.NewGuid(),host=Guid.NewGuid();
        await SeedAsync(admin,fixture.Pg.Root,old,current,host,ct);
        await using(var tx=await admin.BeginTransactionAsync(ct)) {
            await InsertAsync(admin,tx,Sample(old,host,"missing.example.test",1),1,ct);
            await InsertAsync(admin,tx,Sample(current,host,"dc.example.test",2),2,ct);
            await using var retire=new NpgsqlCommand("update sli_agents set status='replaced' where id=@id",admin,tx);
            retire.Parameters.AddWithValue("id",old); await retire.ExecuteNonQueryAsync(ct); await tx.CommitAsync(ct);
        }
        var settings=new Dictionary<string,string?> { ["ADLOG_STORAGE_V2_WORKER_DSN"]=fixture.Dsn("sli_storage_login") };
        await using var runtime=DirectAdDcRuntime.TryCreate(settings.GetValueOrDefault,_=>throw new InvalidOperationException(),Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json"));
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user")); await app.OpenAsync(ct);
        var consumer=new AgentWorkstationInboxConsumer(new BorrowedOnly(),runtime);
        var result=await consumer.RunOnceAsync(app,16,ct);
        Assert.Equal(1,result.Scanned); Assert.Equal(1,result.Imported); Assert.Empty(result.PendingReasons);
        Assert.Equal(0,(await consumer.RunOnceAsync(app,16,ct)).Scanned);
        await AssertCountsAsync(admin,1,1,ct);
    }

    [Fact]
    public async Task Streams_drain_oldest_first_while_another_stream_keeps_receiving_and_inactive_agent_keeps_its_packets()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        Guid a=Guid.NewGuid(),b=Guid.NewGuid(),host=Guid.NewGuid();
        await SeedAsync(admin,fixture.Pg.Root,a,b,host,ct);
        await using(var fix=new NpgsqlCommand("update sli_agent_module_bindings set source_name='dc.example.test' where agent_id=@id",admin)) {
            fix.Parameters.AddWithValue("id",a); await fix.ExecuteNonQueryAsync(ct);
        }
        // Stream A: four old packets. Stream B: two packets, then two more arrive before every following poll.
        await using(var tx=await admin.BeginTransactionAsync(ct)) {
            for(int i=1;i<=4;i++) await InsertAsync(admin,tx,Sample(a,host,"dc.example.test",i),i,ct);
            for(int i=1;i<=2;i++) await InsertAsync(admin,tx,Sample(b,host,"dc.example.test",1000+i),10+i,ct);
            await tx.CommitAsync(ct);
        }
        var settings=new Dictionary<string,string?> { ["ADLOG_STORAGE_V2_WORKER_DSN"]=fixture.Dsn("sli_storage_login") };
        await using var runtime=DirectAdDcRuntime.TryCreate(settings.GetValueOrDefault,_=>throw new InvalidOperationException(),Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json"));
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user")); await app.OpenAsync(ct);
        var consumer=new AgentWorkstationInboxConsumer(new BorrowedOnly(),runtime);
        int next=1003;
        for(int cycle=0;cycle<4;cycle++) {
            var result=await consumer.RunOnceAsync(app,2,ct);
            Assert.Equal(2,result.Imported);
            await using var arrive=await admin.BeginTransactionAsync(ct);
            for(int i=0;i<2;i++,next++) await InsertAsync(admin,arrive,Sample(b,host,"dc.example.test",next),100+next,ct);
            await arrive.CommitAsync(ct);
        }
        await using var order=new NpgsqlCommand("""
            select count(*) filter(where imported_at is null),
                   (select array_agg(envelope->>'sequence' order by imported_at) from sli_agent_packet_inbox where envelope->>'agent_id'=@a and imported_at is not null)
            from sli_agent_packet_inbox where envelope->>'agent_id'=@a
            """,admin);
        order.Parameters.AddWithValue("a",a.ToString());
        await using(var rows=await order.ExecuteReaderAsync(ct)) {
            Assert.True(await rows.ReadAsync(ct)); Assert.Equal(0,rows.GetInt64(0));
            Assert.Equal(new[]{"1","2","3","4"},rows.GetFieldValue<string[]>(1));
        }
        await using var bImported=new NpgsqlCommand("select count(*) from sli_agent_packet_inbox where envelope->>'agent_id'=@b and imported_at is not null",admin);
        bImported.Parameters.AddWithValue("b",b.ToString());
        Assert.Equal(4L,await bImported.ExecuteScalarAsync(ct));
        // A disabled agent's packets are neither claimed nor changed.
        await using(var tx=await admin.BeginTransactionAsync(ct)) {
            await InsertAsync(admin,tx,Sample(a,host,"dc.example.test",5),900,ct);
            await using var off=new NpgsqlCommand("update sli_agents set status='disabled' where id=@id",admin,tx);
            off.Parameters.AddWithValue("id",a); await off.ExecuteNonQueryAsync(ct); await tx.CommitAsync(ct);
        }
        var last=await consumer.RunOnceAsync(app,16,ct); Assert.Equal(6,last.Scanned); Assert.Equal(6,last.Imported);
        await using var kept=new NpgsqlCommand("select count(*) from sli_agent_packet_inbox where envelope->>'agent_id'=@a and imported_at is null",admin);
        kept.Parameters.AddWithValue("a",a.ToString()); Assert.Equal(1L,await kept.ExecuteScalarAsync(ct));
    }

    private sealed class BorrowedOnly : IPostgresConnectionFactory
    { public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => throw new InvalidOperationException("Use the caller's session"); }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task Transient_failure_retries_at_its_stream_tail_while_another_stream_keeps_receiving(int limit)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        Guid a=Guid.NewGuid(),b=Guid.NewGuid(),host=Guid.NewGuid();
        await SeedAsync(admin,fixture.Pg.Root,a,b,host,ct);
        await PostCollectionPostgres.Sql(admin,"update sli_agent_module_bindings set source_name='dc.example.test'",ct);
        var retry=Sample(a,host,"dc.example.test",1);
        await using(var tx=await admin.BeginTransactionAsync(ct)) {
            await InsertAsync(admin,tx,retry,1,ct); await tx.CommitAsync(ct);
        }
        // A sequence survives rollback: the marker update fails twice, as with a transient database conflict.
        await using(var inject=new NpgsqlCommand("""
            create sequence public.test_import_attempts;
            create function public.test_transient_import() returns trigger language plpgsql security definer as $$
            begin
                if new.packet_id=TG_ARGV[0]::uuid and nextval('public.test_import_attempts')<=2 then
                    raise exception 'Synthetic serialization failure' using errcode='40001';
                end if;
                return new;
            end $$;
            """,admin)) await inject.ExecuteNonQueryAsync(ct);
        // The UUID is generated by this test, not supplied by a host.
        await PostCollectionPostgres.Sql(admin,$"""
            create trigger test_transient_import before update of imported_at on sli_agent_packet_inbox
            for each row execute function public.test_transient_import('{retry.Envelope["packet_id"]!.GetValue<string>()}');
            """,ct);
        var settings=new Dictionary<string,string?> { ["ADLOG_STORAGE_V2_WORKER_DSN"]=fixture.Dsn("sli_storage_login") };
        await using var runtime=DirectAdDcRuntime.TryCreate(settings.GetValueOrDefault,_=>throw new InvalidOperationException(),Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json"));
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user")); await app.OpenAsync(ct);
        var consumer=new AgentWorkstationInboxConsumer(new BorrowedOnly(),runtime);
        for(int poll=0;poll<(limit==1?9:5);poll++) {
            await using(var tx=await admin.BeginTransactionAsync(ct)) {
                for(int n=0;n<2;n++) {
                    int record=100+poll*2+n;
                    await InsertAsync(admin,tx,Sample(b,host,"dc.example.test",record),record,ct);
                }
                await tx.CommitAsync(ct);
            }
            var result=await consumer.RunOnceAsync(app,limit,ct);
            Assert.Equal(limit,result.Scanned);
            Assert.InRange(result.PendingReasons.GetValueOrDefault("agent_ad_dc_projection_failed"),0,1);
            Assert.InRange(result.Imported,0,limit);
            await using var backlog=new NpgsqlCommand("select count(*) from sli_agent_packet_inbox where imported_at is null and envelope->>'agent_id'=@b",admin);
            backlog.Parameters.AddWithValue("b",b.ToString());
            Assert.True((long)(await backlog.ExecuteScalarAsync(ct))!>0);
        }
        await using var check=new NpgsqlCommand("select imported_at is not null from sli_agent_packet_inbox where packet_id=@packet",admin);
        check.Parameters.AddWithValue("packet",Guid.Parse(retry.Envelope["packet_id"]!.GetValue<string>()));
        Assert.Equal(true,await check.ExecuteScalarAsync(ct));
        await using var attempts=new NpgsqlCommand("select last_value from public.test_import_attempts",admin);
        Assert.Equal(3L,await attempts.ExecuteScalarAsync(ct));
    }

    [Theory]
    [InlineData("replaced")]
    [InlineData("disabled")]
    public async Task Inactive_registrations_retain_all_packets_without_import_even_with_legacy_tail_permission(string status)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        Guid old=Guid.NewGuid(),current=Guid.NewGuid(),host=Guid.NewGuid();
        await SeedAsync(admin,fixture.Pg.Root,old,current,host,ct);
        await using(var tx=await admin.BeginTransactionAsync(ct)) {
            await InsertAsync(admin,tx,Sample(old,host,"missing.example.test",1),1,ct);
            var history=Sample(old,host,"missing.example.test",2); history.Envelope["module_id"]=AgentAdDcValidator.History;
            await InsertAsync(admin,tx,history,2,ct);
            var other=Sample(old,host,"missing.example.test",3); other.Envelope["module_id"]="sli.windows.workstations";
            await InsertAsync(admin,tx,other,3,ct);
            await InsertAsync(admin,tx,Sample(old,host,"missing.example.test",4),100,ct);
            await using var retire=new NpgsqlCommand("""
                update sli_agents set status=@status where id=@id;
                insert into sli_agent_audit(action,actor,target,occurred_at,details)
                values('disable','synthetic',@target,'2026-10-07T00:00:10Z','{"reason":"registration_replaced","tail_import":true}'::jsonb);
                """,admin,tx);
            retire.Parameters.AddWithValue("id",old); retire.Parameters.AddWithValue("target",old.ToString());
            retire.Parameters.AddWithValue("status",status); await retire.ExecuteNonQueryAsync(ct);
            await tx.CommitAsync(ct);
        }
        var settings=new Dictionary<string,string?> { ["ADLOG_STORAGE_V2_WORKER_DSN"]=fixture.Dsn("sli_storage_login") };
        await using var runtime=DirectAdDcRuntime.TryCreate(settings.GetValueOrDefault,_=>throw new InvalidOperationException(),Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json"));
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user")); await app.OpenAsync(ct);
        var (result,logs)=await PollAsync(new AgentWorkstationInboxConsumer(new BorrowedOnly(),runtime),app,1,ct);
        Assert.Equal(0,result.Scanned); Assert.Equal(0,result.Imported);
        var excluded=Assert.Single(logs,x=>(string?)x["code"]=="agent_not_active");
        Assert.Equal(old.ToString(),(string?)excluded["agent_id"]); Assert.Equal(4,(long)excluded["skipped"]!);
        Assert.DoesNotContain(logs,x=>(string?)x["code"]=="agent_ad_dc_tail_pending");
        await AssertCountsAsync(admin,4,0,ct);
    }

    [Fact]
    public async Task Stale_source_instance_does_not_defer_valid_packet_of_same_agent_and_module()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        Guid broken=Guid.NewGuid(), agent=Guid.NewGuid(), host=Guid.NewGuid();
        await SeedAsync(admin,fixture.Pg.Root,broken,agent,host,ct);
        var stale=Sample(agent,Guid.NewGuid(),"dc.example.test",1);
        var ready=Sample(agent,host,"dc.example.test",2);
        await using(var tx=await admin.BeginTransactionAsync(ct)) {
            await InsertAsync(admin,tx,stale,1,ct); await InsertAsync(admin,tx,ready,2,ct);
            await tx.CommitAsync(ct);
        }
        var settings=new Dictionary<string,string?> { ["ADLOG_STORAGE_V2_WORKER_DSN"]=fixture.Dsn("sli_storage_login") };
        await using var runtime=DirectAdDcRuntime.TryCreate(settings.GetValueOrDefault,_=>throw new InvalidOperationException(),
            Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json"));
        Assert.NotNull(runtime);
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user")); await app.OpenAsync(ct);
        var consumer=new AgentWorkstationInboxConsumer(new BorrowedOnly(),runtime);
        var (result,_)=await PollAsync(consumer,app,16,ct);
        Assert.Equal(2,result.Scanned); Assert.Equal(1,result.Imported); Assert.Equal(0,result.Skipped);
        Assert.Equal(1,result.PendingReasons["agent_ad_dc_source_not_bound"]);
        await AssertCountsAsync(admin,1,1,ct);
        await using var query=new NpgsqlCommand("select imported_at is not null from sli_agent_packet_inbox where packet_id=@packet",admin);
        query.Parameters.AddWithValue("packet",Guid.Parse((string)ready.Envelope["packet_id"]!));
        Assert.Equal(true,await query.ExecuteScalarAsync(ct));
    }

    [Fact]
    public async Task Unbound_source_packets_are_skipped_without_blocking_other_agents_and_import_after_binding_is_fixed()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        Guid stale=Guid.NewGuid(), live=Guid.NewGuid(), host=Guid.NewGuid();
        await SeedAsync(admin,fixture.Pg.Root,stale,live,host,ct);
        // The stale agent is bound to another source name than its packets carry: they can never import.
        var olderA=Sample(stale,host,"renamed.example.test",1); var olderB=Sample(stale,host,"renamed.example.test",2);
        var ready=Sample(live,host,"dc.example.test",3);
        await using(var tx=await admin.BeginTransactionAsync(ct)) {
            await InsertAsync(admin,tx,olderA,1,ct); await InsertAsync(admin,tx,olderB,2,ct); await InsertAsync(admin,tx,ready,3,ct);
            await tx.CommitAsync(ct);
        }
        var settings=new Dictionary<string,string?> { ["ADLOG_STORAGE_V2_WORKER_DSN"]=fixture.Dsn("sli_storage_login") };
        await using var runtime=DirectAdDcRuntime.TryCreate(settings.GetValueOrDefault,_=>throw new InvalidOperationException(),
            Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json"));
        Assert.NotNull(runtime);
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user")); await app.OpenAsync(ct);
        var consumer=new AgentWorkstationInboxConsumer(new BorrowedOnly(),runtime);
        var (first,_)=await PollAsync(consumer,app,16,ct);
        // One attempt for the identical unbindable signature, then the live agent imports.
        Assert.Equal(2,first.Scanned); Assert.Equal(1,first.Imported); Assert.Equal(0,first.Quarantined);
        Assert.Equal(1,first.PendingReasons["agent_ad_dc_source_not_bound"]);
        await AssertCountsAsync(admin,2,1,ct);
        // Later polls ignore the unbindable packets; they are neither deleted nor quarantined.
        var (again,_)=await PollAsync(consumer,app,16,ct);
        Assert.Equal(0,again.Scanned);
        await AssertCountsAsync(admin,2,1,ct);
        // Fixing the binding makes the same packets importable again without any manual release.
        await PostCollectionPostgres.Sql(admin,"""
            insert into servers(domain_id,hostname,fqdn,role) select id,'renamed.example.test','renamed.example.test','domain_controller' from domains where fqdn='example.test';
            """,ct);
        await using(var fix=new NpgsqlCommand("update sli_agent_module_bindings set source_name='renamed.example.test' where agent_id=@agent",admin)) {
            fix.Parameters.AddWithValue("agent",stale); await fix.ExecuteNonQueryAsync(ct);
        }
        var (fixedRun,_)=await PollAsync(consumer,app,16,ct);
        Assert.Equal(2,fixedRun.Imported); Assert.Empty(fixedRun.PendingReasons);
        await AssertCountsAsync(admin,0,3,ct);
    }

    [Theory]
    [InlineData("count")]
    [InlineData("log")]
    [InlineData("unrequested_cancellation")]
    [InlineData("cancellation")]
    public async Task Optional_diagnostics_preserve_committed_results_except_requested_cancellation(string failure)
    {
        var ct=TestContext.Current.CancellationToken;
        using var cancel=CancellationTokenSource.CreateLinkedTokenSource(ct);
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        Guid broken=Guid.NewGuid(), good=Guid.NewGuid(), host=Guid.NewGuid();
        await SeedAsync(admin,fixture.Pg.Root,broken,good,host,ct);
        await using(var tx=await admin.BeginTransactionAsync(ct)) {
            await InsertAsync(admin,tx,Sample(broken,host,"missing.example.test",1),1,ct);
            await InsertAsync(admin,tx,Sample(good,host,"dc.example.test",2),2,ct);
            await tx.CommitAsync(ct);
        }
        if(failure=="count") {
            // Fail only the optional count after the ready packet has committed.
            await PostCollectionPostgres.Sql(admin,"""
                create function public.test_revoke_count() returns trigger language plpgsql security definer as $$
                begin revoke select on public.sli_agent_packet_inbox from adlog_user; return new; end $$;
                create trigger test_revoke_count after update of imported_at on public.sli_agent_packet_inbox
                for each row execute function public.test_revoke_count();
                """,ct);
        }
        var settings=new Dictionary<string,string?> { ["ADLOG_STORAGE_V2_WORKER_DSN"]=fixture.Dsn("sli_storage_login") };
        await using var runtime=DirectAdDcRuntime.TryCreate(settings.GetValueOrDefault,_=>throw new InvalidOperationException(),
            Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json"));
        Assert.NotNull(runtime);
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user")); await app.OpenAsync(ct);
        var consumer=new AgentWorkstationInboxConsumer(new BorrowedOnly(),runtime);
        var original=Console.Error;
        using var writer=new FailingDiagnosticWriter(failure,cancel);
        try {
            if(failure!="count") Console.SetError(writer);
            if(failure=="cancellation") {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>consumer.RunOnceAsync(app,2,cancel.Token));
                Assert.True(cancel.IsCancellationRequested);
            } else {
                var result=await consumer.RunOnceAsync(app,2,cancel.Token);
                Assert.Equal(2,result.Scanned); Assert.Equal(1,result.Imported);
                Assert.Equal(1,result.PendingReasons["agent_ad_dc_source_not_configured"]);
                Assert.Equal(0,result.Quarantined);
            }
        } finally { Console.SetError(original); }
        await AssertCountsAsync(admin,1,1,ct);
    }

    private sealed class FailingDiagnosticWriter(string failure,CancellationTokenSource cancel) : StringWriter
    {
        public override void WriteLine(string? value)
        {
            if(failure=="cancellation") { cancel.Cancel(); throw new OperationCanceledException(cancel.Token); }
            if(failure=="unrequested_cancellation") throw new OperationCanceledException();
            throw new IOException("Synthetic diagnostic failure");
        }
    }

    [Fact]
    public async Task Deferred_agent_and_full_batch_of_attestation_failures_do_not_starve_ready_packets()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        Guid incomplete=Guid.NewGuid(), good=Guid.NewGuid(), host=Guid.NewGuid();
        await SeedAsync(admin,fixture.Pg.Root,incomplete,good,host,ct);
        const int limit=4;
        await using(var tx=await admin.BeginTransactionAsync(ct)) {
            await InsertAsync(admin,tx,Sample(incomplete,host,"missing.example.test",1),1,ct);
            // A full batch of repeatable non-configuration failures precedes every ready packet.
            for(int i=2;i<=limit+6;i++) {
                var packet=Sample(good,host,"dc.example.test",i);
                if(i<=limit+1) packet.Envelope["payload_sha256"]=new string('f',64);
                await InsertAsync(admin,tx,packet,i,ct);
            }
            await tx.CommitAsync(ct);
        }
        var settings=new Dictionary<string,string?> { ["ADLOG_STORAGE_V2_WORKER_DSN"]=fixture.Dsn("sli_storage_login") };
        await using var runtime=DirectAdDcRuntime.TryCreate(settings.GetValueOrDefault,_=>throw new InvalidOperationException(),
            Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json"));
        Assert.NotNull(runtime);
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user")); await app.OpenAsync(ct);
        var consumer=new AgentWorkstationInboxConsumer(new BorrowedOnly(),runtime);
        int imported=0,attestationFailures=0,configurationAttempts=0,calls=0;
        const int maxCalls=6;
        for(;calls<maxCalls && imported<5;calls++) {
            var (result,_)=await PollAsync(consumer,app,limit,ct);
            Assert.InRange(result.Scanned,1,limit);
            Assert.InRange(result.PendingReasons.GetValueOrDefault("agent_ad_dc_source_not_configured"),0,1);
            Assert.Equal(0,result.Quarantined);
            imported+=result.Imported;
            attestationFailures+=result.PendingReasons.GetValueOrDefault("agent_packet_attestation_invalid");
            configurationAttempts+=result.PendingReasons.GetValueOrDefault("agent_ad_dc_source_not_configured");
        }
        Assert.Equal(5,imported);
        Assert.Equal(limit,attestationFailures);
        // Independent stream wrap may revisit the configuration failure in a later poll;
        // the per-poll assertion above still permits only one attempt before deferral.
        Assert.InRange(configurationAttempts,1,calls);
        await AssertCountsAsync(admin,limit+1,5,ct);
        output.WriteLine($"Ready packets imported={imported}, calls={calls}/{maxCalls}, attestation failures={attestationFailures}");
    }

    [Fact]
    public async Task Unconfigured_backlog_defers_once_and_resumes_in_order_after_configuration()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        Guid broken=Guid.NewGuid(), good=Guid.NewGuid(), host=Guid.NewGuid();
        await SeedAsync(admin,fixture.Pg.Root,broken,good,host,ct);
        var pending=new List<Guid>();
        await using(var tx=await admin.BeginTransactionAsync(ct)) {
            for(int i=1;i<=505;i++) {
                bool incomplete=i<=500;
                var packet=Sample(incomplete?broken:good,host,incomplete?"missing.example.test":"dc.example.test",i);
                if(incomplete) pending.Add(Guid.Parse((string)packet.Envelope["packet_id"]!));
                await InsertAsync(admin,tx,packet,i,ct);
            }
            await tx.CommitAsync(ct);
        }
        var settings=new Dictionary<string,string?> { ["ADLOG_STORAGE_V2_WORKER_DSN"]=fixture.Dsn("sli_storage_login") };
        await using var runtime=DirectAdDcRuntime.TryCreate(settings.GetValueOrDefault,_=>throw new InvalidOperationException(),
            Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json"));
        Assert.NotNull(runtime);
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user")); await app.OpenAsync(ct);
        var consumer=new AgentWorkstationInboxConsumer(new BorrowedOnly(),runtime);
        await ExplainClaimAsync(app,broken,ct);
        var timer=Stopwatch.StartNew();
        var (first,logs)=await PollAsync(consumer,app,16,ct);
        output.WriteLine($"500 unconfigured + 5 ready: scanned={first.Scanned}, imported={first.Imported}, elapsed={timer.Elapsed.TotalMilliseconds:F1} ms");
        Assert.Equal(5,first.Imported);
        Assert.Equal(6,first.Scanned);
        Assert.Equal(1,first.PendingReasons["agent_ad_dc_source_not_configured"]);
        Assert.Equal(0,first.Quarantined);
        Assert.Equal(499,first.Skipped);
        var diagnostic=Assert.Single(logs);
        Assert.Equal("source_configuration",(string?)diagnostic["step"]);
        Assert.Equal("agent_ad_dc_source_not_configured",(string?)diagnostic["reason"]);
        Assert.Equal(499,(long)diagnostic["skipped"]!);
        Assert.Equal(broken.ToString(),(string?)diagnostic["agent_id"]);
        await AssertCountsAsync(admin,500,5,ct);
        // Deferral is local to one call, while a full batch retains its scan position.
        var retry=await consumer.RunOnceAsync(app,1,ct);
        Assert.Equal(1,retry.Scanned); Assert.Equal(0,retry.Imported);
        Assert.Equal(1,retry.PendingReasons["agent_ad_dc_source_not_configured"]);
        Assert.Equal(499,retry.Skipped);
        var next=await consumer.RunOnceAsync(app,1,ct);
        Assert.Equal(1,next.Scanned); Assert.Equal(0,next.Imported);
        Assert.Equal(1,next.PendingReasons["agent_ad_dc_source_not_configured"]);
        Assert.Equal(498,next.Skipped);
        // Only reaching the end wraps the cursor back to the deferred head.
        var wrap=await consumer.RunOnceAsync(app,16,ct);
        Assert.Equal(1,wrap.Scanned); Assert.Equal(0,wrap.Imported);
        Assert.Equal(1,wrap.PendingReasons["agent_ad_dc_source_not_configured"]);
        Assert.Equal(497,wrap.Skipped);
        await AssertCountsAsync(admin,500,5,ct);
        await PostCollectionPostgres.Sql(admin,"insert into servers(domain_id,hostname,fqdn,role) select id,'missing.example.test','missing.example.test','domain_controller' from domains where fqdn='example.test'",ct);
        var head=await consumer.RunOnceAsync(app,2,ct);
        Assert.Equal(2,head.Imported); Assert.Empty(head.PendingReasons);
        await using(var check=new NpgsqlCommand("select packet_id from sli_agent_packet_inbox where imported_at is not null and envelope->>'agent_id'=@agent order by received_at,packet_id",admin)) {
            check.Parameters.AddWithValue("agent",broken.ToString());
            await using var rows=await check.ExecuteReaderAsync(ct);
            foreach(var id in pending.Take(2)) { Assert.True(await rows.ReadAsync(ct)); Assert.Equal(id,rows.GetGuid(0)); }
            Assert.False(await rows.ReadAsync(ct));
        }
        timer.Restart(); int recovered=head.Imported;
        for(int batch=0;batch<4;batch++) {
            var result=await consumer.RunOnceAsync(app,128,ct);
            Assert.Empty(result.PendingReasons); Assert.Equal(0,result.Quarantined); recovered+=result.Imported;
        }
        Assert.Equal(500,recovered);
        await AssertCountsAsync(admin,0,505,ct);
        output.WriteLine($"After configuration: imported={recovered}, remaining 498 elapsed={timer.Elapsed.TotalMilliseconds:F1} ms");
        await AssertModuleIsolationAndAttestationAsync(admin,app,consumer,broken,good,host,ct);
    }

    private async Task ExplainClaimAsync(NpgsqlConnection db,Guid broken,CancellationToken ct)
    {
        await using var tx=await db.BeginTransactionAsync(ct);
        await using var query=new NpgsqlCommand("explain (analyze,buffers,format json) "+AgentWorkstationInboxConsumer.ClaimSql,db,tx);
        query.Parameters.AddWithValue("after_time",NpgsqlDbType.TimestampTz,new DateTime(2026,10,7,0,0,1,DateTimeKind.Utc));
        query.Parameters.AddWithValue("after_packet",NpgsqlDbType.Uuid,Guid.Empty);
        query.Parameters.AddWithValue("skipped",NpgsqlDbType.Array|NpgsqlDbType.Text,Array.Empty<string>());
        query.Parameters.AddWithValue("deferred_agents",new[]{broken.ToString()});
        query.Parameters.AddWithValue("deferred_modules",new[]{AgentAdDcValidator.Live});
        query.Parameters.AddWithValue("served",NpgsqlDbType.Array|NpgsqlDbType.Text,Array.Empty<string>());
        query.Parameters.AddWithValue("cur_keys",NpgsqlDbType.Array|NpgsqlDbType.Text,Array.Empty<string>());
        query.Parameters.AddWithValue("cur_times",NpgsqlDbType.Array|NpgsqlDbType.TimestampTz,Array.Empty<DateTime>());
        query.Parameters.AddWithValue("cur_ids",NpgsqlDbType.Array|NpgsqlDbType.Uuid,Array.Empty<Guid>());
        var document=JsonNode.Parse((string)(await query.ExecuteScalarAsync(ct))!)![0]!;
        Assert.Equal(1.0,(double)document["Plan"]!["Actual Rows"]!);
        output.WriteLine("Claim excluding the 500-packet backlog: "+document.ToJsonString());
        await tx.RollbackAsync(ct);
    }

    private static async Task<(AgentInboxBatchResult Result,JsonNode[] Logs)> PollAsync(AgentWorkstationInboxConsumer consumer,NpgsqlConnection db,int limit,CancellationToken ct)
    {
        var original=Console.Error; using var captured=new StringWriter();
        try {
            Console.SetError(captured);
            var result=await consumer.RunOnceAsync(db,limit,ct);
            return (result,captured.ToString().Split('\n',StringSplitOptions.RemoveEmptyEntries).Select(x=>JsonNode.Parse(x)!).ToArray());
        } finally { Console.SetError(original); }
    }

    private static async Task AssertModuleIsolationAndAttestationAsync(NpgsqlConnection admin,NpgsqlConnection app,AgentWorkstationInboxConsumer consumer,Guid broken,Guid good,Guid host,CancellationToken ct)
    {
        await using(var tx=await admin.BeginTransactionAsync(ct)) {
            await using(var remove=new NpgsqlCommand("delete from sli_agent_module_bindings where agent_id=@agent",admin,tx)) {
                remove.Parameters.AddWithValue("agent",broken); await remove.ExecuteNonQueryAsync(ct);
            }
            for(int i=506;i<=509;i++) {
                var packet=Sample(i==509?good:broken,host,i==509?"dc.example.test":"missing.example.test",i);
                if(i==508) packet.Envelope["module_id"]=AgentAdDcValidator.History;
                await InsertAsync(admin,tx,packet,i,ct);
            }
            await tx.CommitAsync(ct);
        }
        var (unbound,logs)=await PollAsync(consumer,app,16,ct);
        Assert.Equal(3,unbound.Scanned); Assert.Equal(1,unbound.Imported); Assert.Equal(0,unbound.Skipped);
        Assert.Equal(1,unbound.PendingReasons["agent_ad_dc_source_not_bound"]);
        Assert.Equal(1,unbound.PendingReasons["agent_module_not_assigned"]);
        Assert.Equal(2,logs.Length);
        Assert.Equal(1,logs.Count(x=>(string?)x["reason"]=="agent_ad_dc_source_not_bound"));
        var diagnostic=Assert.Single(logs,x=>(string?)x["reason"]=="agent_module_not_assigned");
        Assert.Equal(AgentAdDcValidator.History,(string?)diagnostic["module_id"]);
        Assert.Equal(0,(long)diagnostic["skipped"]!);
        await using(var tx=await admin.BeginTransactionAsync(ct)) {
            await using(var restore=new NpgsqlCommand("""
                insert into sli_agent_module_bindings(agent_id,module_id,source_instance_id,source_name,channel,module_version,policy_revision)
                values(@agent,'sli.windows.ad-dc',@host,'missing.example.test','ad-dc','1.0.0','1')
                """,admin,tx)) {
                restore.Parameters.AddWithValue("agent",broken); restore.Parameters.AddWithValue("host",host.ToString()); await restore.ExecuteNonQueryAsync(ct);
            }
            for(int i=510;i<=511;i++) {
                var packet=Sample(broken,host,"missing.example.test",i);
                if(i==510) packet.Envelope["payload_sha256"]=new string('f',64);
                await InsertAsync(admin,tx,packet,i,ct);
            }
            await tx.CommitAsync(ct);
        }
        var final=await consumer.RunOnceAsync(app,16,ct);
        Assert.Equal(5,final.Scanned); Assert.Equal(3,final.Imported); Assert.Equal(0,final.Skipped);
        Assert.Equal(1,final.PendingReasons["agent_module_not_assigned"]);
        Assert.Equal(1,final.PendingReasons["agent_packet_attestation_invalid"]);
        await AssertCountsAsync(admin,2,509,ct);
    }

    private static async Task AssertCountsAsync(NpgsqlConnection db,long pending,long imported,CancellationToken ct)
    {
        await using var query=new NpgsqlCommand("select count(*) filter(where imported_at is null),count(*) filter(where imported_at is not null),(select count(*) from sli_agent_packet_quarantine) from sli_agent_packet_inbox",db);
        await using var rows=await query.ExecuteReaderAsync(ct); Assert.True(await rows.ReadAsync(ct));
        Assert.Equal(pending,rows.GetInt64(0)); Assert.Equal(imported,rows.GetInt64(1)); Assert.Equal(0,rows.GetInt64(2));
    }

    internal sealed record Packet(JsonObject Envelope,JsonObject Payload,JsonArray Rows);
    internal static Packet Sample(Guid agent,Guid host,string source,int record,string? computer=null)
    {
        var scenario=JsonNode.Parse(File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(),"agent-dotnet/tests/vectors/ad-dc-scenarios.json")))!
            .AsArray().Single(x=>(string?)x!["name"]=="security-initial-window-all")!;
        var step=scenario["steps"]![0]!; var expected=step["expected"]!;
        string old=(string)scenario["host_id"]!;
        var payload=JsonNode.Parse(((string)expected["payload_canonical"]!).Replace(old,host.ToString()).Replace("fixture-dc",source))!.AsObject();
        payload["records"]!.AsArray().Clear();
        string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>{record}</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00Z'/><Channel>Security</Channel><Computer>{computer ?? source}</Computer></System><EventData><Data Name='LogonType'>3</Data></EventData></Event>";
        payload["records"]!.AsArray().Add(new JsonObject { ["format"]="event_xml",["record_id"]=record,["payload"]=EventXml.Parse(xml,source,"fixture-endpoint","Security") });
        payload["header"]!["cursor"]!["last_record_id"]=record;
        payload["header"]!["record_id_range"]!["first"]=record; payload["header"]!["record_id_range"]!["last"]=record;
        var before=JsonNode.Parse(expected["cursor_before"]!.ToJsonString().Replace(old,host.ToString()));
        var after=JsonNode.Parse(expected["cursor_after"]!.ToJsonString().Replace(old,host.ToString()));
        var state=JsonNode.Parse((string)after!["token"]!)!;
        state["channels"]!["Security"]!["record_id"]=record;
        state["channels"]!["Security"]!["bookmark"]=((string)state["channels"]!["Security"]!["bookmark"]!).Replace("RecordId='1'",$"RecordId='{record}'");
        after["token"]=CanonicalJson.Serialize(state);
        var envelope=new Envelope(Guid.NewGuid().ToString(),agent.ToString(),host.ToString(),AgentAdDcValidator.Live,
            "1.0.0","1","ad-dc",host.ToString(),record,Cursor.FromJson(before),Cursor.FromJson(after),CollectionPacket.Contract,
            Packets.Digest(payload),1,CanonicalJson.Length(payload),(string)step["now"]!,"not_proven",0,0);
        return new(envelope.ToJson(),payload,AgentAdDcValidator.Validate(envelope,payload,null,source));
    }

    private static async Task InsertAsync(NpgsqlConnection db,NpgsqlTransaction tx,Packet sample,int index,CancellationToken ct)
    {
        await using var query=new NpgsqlCommand("""
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            values(@agent,@module,@sequence,@packet,@hash,@envelope,'{"status":"committed"}');
            insert into sli_agent_packet_inbox(packet_id,received_at,envelope,packet,event_rows)
            values(@packet,@received,@envelope,@body,@rows);
            """,db,tx);
        query.Parameters.AddWithValue("agent",Guid.Parse((string)sample.Envelope["agent_id"]!));
        query.Parameters.AddWithValue("module",(string)sample.Envelope["module_id"]!);
        query.Parameters.AddWithValue("sequence",(long)sample.Envelope["sequence"]!);
        query.Parameters.AddWithValue("packet",Guid.Parse((string)sample.Envelope["packet_id"]!));
        query.Parameters.AddWithValue("hash",Packets.Digest(sample.Envelope));
        query.Parameters.AddWithValue("received",new DateTime(2026,10,7,0,0,0,DateTimeKind.Utc).AddSeconds(index));
        query.Parameters.AddWithValue("envelope",NpgsqlDbType.Jsonb,sample.Envelope.ToJsonString());
        query.Parameters.AddWithValue("body",NpgsqlDbType.Jsonb,sample.Payload.ToJsonString());
        query.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,sample.Rows.ToJsonString());
        await query.ExecuteNonQueryAsync(ct);
    }

    private static async Task SeedAsync(NpgsqlConnection db,string archive,Guid broken,Guid good,Guid host,CancellationToken ct)
    {
        await PostCollectionPostgres.Sql(db,"""
            insert into servers(domain_id,hostname,fqdn,role) select id,'dc.example.test','dc.example.test','domain_controller' from domains where fqdn='example.test';
            insert into log_sources(name) values('Security') on conflict do nothing;
            update plugin_installations_v1 set desired_activation='enabled_manual' where plugin_id='sli.ad';
            """,ct);
        foreach(var (agent,source) in new[]{(broken,"missing.example.test"),(good,"dc.example.test")}) {
            await using var query=new NpgsqlCommand("""
                insert into sli_agents(id,host_id,key_fingerprint,assigned_modules,policy_revision) values(@agent,@host,@fp,@modules,1);
                insert into sli_agent_module_bindings(agent_id,module_id,source_instance_id,source_name,channel,module_version,policy_revision)
                values(@agent,'sli.windows.ad-dc',@instance,@source,'ad-dc','1.0.0','1');
                """,db);
            query.Parameters.AddWithValue("agent",agent); query.Parameters.AddWithValue("host",agent==good?Guid.NewGuid():host);
            query.Parameters.AddWithValue("instance",host.ToString()); query.Parameters.AddWithValue("source",source);
            query.Parameters.AddWithValue("fp",new string(agent==good?'b':'a',64));
            query.Parameters.AddWithValue("modules",NpgsqlDbType.Jsonb,new JsonArray(new JsonObject {
                ["module_id"]=AgentAdDcValidator.Live,["enabled"]=true,
                ["config"]=AgentAdDcValidator.NormalizePolicy(new JsonObject { ["source_name"]=source,["connect_address"]=source },false)
            }).ToJsonString());
            await query.ExecuteNonQueryAsync(ct);
        }
        var record=new DirectRuntimeRecord("v2","storage-v2-fresh-bootstrap/v1",new string('a',64),archive,
            new JsonObject { ["kind"]="fresh-event-store",["version"]=1 },"synthetic",DateTime.UtcNow.AddMinutes(-1),DateTime.UtcNow.AddHours(1),null,"");
        await using var authorization=new NpgsqlCommand("""
            insert into storage_v2_runtime_authorizations(route,authority,preflight_digest,authorization_digest,archive_root,evidence,authorized_by,authorized_at,expires_at)
            values('v2',@authority,@preflight,@digest,@archive,@evidence,'synthetic',@at,@expires)
            """,db);
        authorization.Parameters.AddWithValue("authority",record.Authority); authorization.Parameters.AddWithValue("preflight",record.PreflightDigest);
        authorization.Parameters.AddWithValue("digest",DirectRuntimeAuthorization.Digest(record)); authorization.Parameters.AddWithValue("archive",archive);
        authorization.Parameters.AddWithValue("evidence",NpgsqlDbType.Jsonb,record.Evidence.ToJsonString());
        authorization.Parameters.AddWithValue("at",record.AuthorizedAt); authorization.Parameters.AddWithValue("expires",record.ExpiresAt);
        await authorization.ExecuteNonQueryAsync(ct);
    }
}
