using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Ingress;
using Sli.Server.Infrastructure;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class DirectWorkerImportDatabaseTests
{
    private sealed class Factory : IPostgresConnectionFactory
    { public Task<NpgsqlConnection> OpenAsync(CancellationToken ct)=>throw new InvalidOperationException("caller owns session"); }
    private static string Catalog=>Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json");
    private static DirectAdDcRuntime Runtime(SqlPostgresFixture fixture)=>DirectAdDcRuntime.TryCreate(
        k=>k=="ADLOG_STORAGE_V2_WORKER_DSN"?fixture.Dsn("sli_storage_login"):null,_=>[],Catalog)!;
    private static async Task Seed(NpgsqlConnection db,SqlPostgresFixture fixture,CancellationToken ct)
    {
        string archive=Path.Combine(fixture.Pg.Root,"unavailable-archive");await File.WriteAllTextAsync(archive,"synthetic",ct);
        await DirectWorkerMixedDatabaseTests.SeedAsync(db,archive,ct);
    }
    private static async Task<(JsonObject Envelope,JsonObject Packet,JsonArray Rows)> Insert(NpgsqlConnection db,int sequence,int count,CancellationToken ct)
    {
        var sample=DirectWorkerMixedDatabaseTests.Sample();
        var payload=sample.Packet;payload["records"]!.AsArray().Clear();
        int first=(sequence-1)*count+1,last=sequence*count;
        for(int id=first;id<=last;id++) {
            string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>{id}</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00Z'/><Channel>Security</Channel><Computer>{DirectWorkerMixedDatabaseTests.Name}</Computer></System><EventData><Data Name='LogonType'>3</Data></EventData></Event>";
            payload["records"]!.AsArray().Add(new JsonObject { ["format"]="event_xml",["record_id"]=id,
                ["payload"]=EventXml.Parse(xml,DirectWorkerMixedDatabaseTests.Name,"fixture-endpoint","Security") });
        }
        payload["header"]!["cursor"]!["last_record_id"]=last;payload["header"]!["record_id_range"]!["first"]=first;payload["header"]!["record_id_range"]!["last"]=last;
        var envelope=sample.Envelope;envelope["packet_id"]=Guid.NewGuid().ToString("D");envelope["sequence"]=sequence;
        envelope["record_count"]=count;envelope["payload_sha256"]=Packets.Digest(payload);envelope["payload_bytes"]=CanonicalJson.Length(payload);
        var state=JsonNode.Parse(envelope["cursor_after"]!["token"]!.GetValue<string>())!.AsObject();
        state["channels"]!["Security"]!["record_id"]=last;
        state["channels"]!["Security"]!["bookmark"]=state["channels"]!["Security"]!["bookmark"]!.GetValue<string>().Replace("RecordId='1'",$"RecordId='{last}'",StringComparison.Ordinal);
        envelope["cursor_after"]!["token"]=CanonicalJson.Serialize(state);
        var env=Envelope.Parse(envelope);var rows=AgentAdDcValidator.Validate(env,payload,null,DirectWorkerMixedDatabaseTests.Name);
        await using var insert=new NpgsqlCommand("""
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            values(@agent,@module,@sequence,@packet,@hash,@envelope,'{"status":"committed"}'::jsonb);
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows) values(@packet,@envelope,@payload,@rows)
            """,db);
        insert.Parameters.AddWithValue("agent",Guid.Parse(env.AgentId));insert.Parameters.AddWithValue("module",env.ModuleId);insert.Parameters.AddWithValue("sequence",(long)sequence);
        insert.Parameters.AddWithValue("packet",Guid.Parse(env.PacketId));insert.Parameters.AddWithValue("hash",Packets.Digest(envelope));
        insert.Parameters.AddWithValue("envelope",NpgsqlDbType.Jsonb,envelope.ToJsonString());insert.Parameters.AddWithValue("payload",NpgsqlDbType.Jsonb,payload.ToJsonString());insert.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,rows.ToJsonString());
        await insert.ExecuteNonQueryAsync(ct);return(envelope,payload,rows);
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Import_commits_events_without_an_available_archive(bool committed)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString);await admin.OpenAsync(ct);await Seed(admin,fixture,ct);
        await using var runtime=Runtime(fixture);Assert.NotNull(runtime);
        await using var db=new NpgsqlConnection(fixture.Dsn("adlog_user"));await db.OpenAsync(ct);
        var consumer=new AgentWorkstationInboxConsumer(new Factory(),runtime);double total=0;
        for(int i=1;i<=4;i++) {
            var sample=await Insert(admin,i,128,ct);var watch=Stopwatch.StartNew();
            if(committed) {
                var result=await consumer.RunOnceAsync(db,1,ct);Assert.Equal(1,result.Imported);Assert.Empty(result.PendingReasons);
            } else {
                var timings=new List<string>();var previous=AdDcProjectionStep.Authorization;double last=0;
                await using var tx=await db.BeginTransactionAsync(ct);
                await DirectAdDcPacket.ImportAsync(db,tx,runtime.Worker,Guid.Parse(sample.Envelope["packet_id"]!.GetValue<string>()),sample.Envelope,sample.Packet,sample.Rows,Catalog,ct,step=> {
                    double now=watch.Elapsed.TotalMilliseconds;timings.Add($"{previous}={now-last:F2}");previous=step;last=now;
                });
                await using var mark=new NpgsqlCommand("update sli_agent_packet_inbox set imported_at=clock_timestamp() where packet_id=@id",db,tx);
                mark.Parameters.AddWithValue("id",Guid.Parse(sample.Envelope["packet_id"]!.GetValue<string>()));await mark.ExecuteNonQueryAsync(ct);await tx.CommitAsync(ct);
                timings.Add($"{previous}={watch.Elapsed.TotalMilliseconds-last:F2}");Console.WriteLine("before_steps_ms: "+string.Join("; ",timings));
            }
            watch.Stop();total+=watch.Elapsed.TotalMilliseconds;
            Console.WriteLine($"synthetic committed={committed} packet={i} rows=128 packet_ms={watch.Elapsed.TotalMilliseconds:F2}");
        }
        Console.WriteLine($"synthetic committed={committed} mean_packet_ms={total/4:F2} backlog_5392_hours={total/4*5392/3600000:F4}");
        await using var check=new NpgsqlCommand("select (select count(*) from event_hot),(select count(*) from sli_agent_packet_inbox where imported_at is not null)",admin);
        await using(var reader=await check.ExecuteReaderAsync(ct)) {Assert.True(await reader.ReadAsync(ct));Assert.Equal(512,reader.GetInt64(0));Assert.Equal(4,reader.GetInt64(1));}
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
    private static async Task WaitForBlock(NpgsqlConnection monitor,int blocked,int blocker,CancellationToken ct)
    {
        while(true) {
            await using var query=new NpgsqlCommand("select @blocker=any(pg_blocking_pids(@blocked))",monitor);
            query.Parameters.AddWithValue("blocked",blocked);query.Parameters.AddWithValue("blocker",blocker);
            if(await query.ExecuteScalarAsync(ct) is true)return;
            await Task.Delay(10,ct);
        }
    }
    private static async Task Revoke(NpgsqlConnection db,NpgsqlTransaction tx,Guid agent,CancellationToken ct)
    { await new AgentManagementService(new AgentControlAudit()).RevokeAsync(db,tx,JsonSerializer.SerializeToElement(new {agent_id=agent}),"synthetic",true,ct); }

    [Fact]
    public async Task Cancelled_hot_write_releases_locks_and_retries_without_accepting_tampered_rows()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var monitor=new NpgsqlConnection(fixture.Pg.ConnectionString);await monitor.OpenAsync(ct);await Seed(monitor,fixture,ct);
        await Insert(monitor,1,1,ct);
        await using var runtime=Runtime(fixture);
        await using var db=new NpgsqlConnection(fixture.Dsn("adlog_user"));await db.OpenAsync(ct);
        await using var blocker=new NpgsqlConnection(fixture.Pg.ConnectionString);await blocker.OpenAsync(ct);
        await using var hold=await blocker.BeginTransactionAsync(ct);
        await using(var gate=new NpgsqlCommand("select pg_advisory_xact_lock(hashtext('entity_identity_merge_r7'))",blocker,hold))await gate.ExecuteNonQueryAsync(ct);
        using var stop=CancellationTokenSource.CreateLinkedTokenSource(ct);
        var consumer=new AgentWorkstationInboxConsumer(new Factory(),runtime);var import=consumer.RunOnceAsync(db,1,stop.Token);
        while(true) {
            await using var query=new NpgsqlCommand("select exists(select 1 from pg_stat_activity where usename='sli_storage_login' and @pid=any(pg_blocking_pids(pid)))",monitor);
            query.Parameters.AddWithValue("pid",blocker.ProcessID);
            if(await query.ExecuteScalarAsync(ct) is true)break;
            Assert.False(import.IsCompleted);await Task.Delay(10,ct);
        }
        stop.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>import);await hold.CommitAsync(ct);
        await using(var check=new NpgsqlCommand("select not exists(select 1 from pg_locks where pid=@pid and locktype='advisory' and granted),not exists(select 1 from event_hot),not exists(select 1 from sli_agent_packet_inbox where imported_at is not null)",monitor)) {
            check.Parameters.AddWithValue("pid",db.ProcessID);
            await using var reader=await check.ExecuteReaderAsync(ct);Assert.True(await reader.ReadAsync(ct));
            Assert.True(reader.GetBoolean(0));Assert.True(reader.GetBoolean(1));Assert.True(reader.GetBoolean(2));
        }
        var retry=await consumer.RunOnceAsync(db,1,ct);Assert.Equal(1,retry.Imported);
        await Insert(monitor,2,1,ct);
        await PostCollectionPostgres.Sql(monitor,"update sli_agent_packet_inbox set event_rows='[]'::jsonb where imported_at is null",ct);
        var refused=await consumer.RunOnceAsync(db,1,ct);Assert.Equal(0,refused.Imported);Assert.Equal(1,refused.PendingReasons["agent_ad_dc_projection_failed"]);
        await using(var check=new NpgsqlCommand("select (select count(*) from event_hot),(select count(*) from sli_agent_packet_inbox where imported_at is not null)",monitor))
        await using(var reader=await check.ExecuteReaderAsync(ct)) {Assert.True(await reader.ReadAsync(ct));Assert.Equal(1,reader.GetInt64(0));Assert.Equal(1,reader.GetInt64(1));}
    }

    [Fact]
    public async Task Hot_write_has_no_open_inbox_transaction_and_serializes_revocation()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var monitor=new NpgsqlConnection(fixture.Pg.ConnectionString);await monitor.OpenAsync(ct);await Seed(monitor,fixture,ct);
        var sample=await Insert(monitor,1,1,ct);Guid agent=Guid.Parse(sample.Envelope["agent_id"]!.GetValue<string>());
        await using var runtime=Runtime(fixture);
        await using var db=new NpgsqlConnection(fixture.Dsn("adlog_user"));await db.OpenAsync(ct);
        await using var blocker=new NpgsqlConnection(fixture.Pg.ConnectionString);await blocker.OpenAsync(ct);
        await using var hold=await blocker.BeginTransactionAsync(ct);
        await using(var gate=new NpgsqlCommand("select pg_advisory_xact_lock(hashtext('entity_identity_merge_r7'))",blocker,hold))await gate.ExecuteNonQueryAsync(ct);
        var import=new AgentWorkstationInboxConsumer(new Factory(),runtime).RunOnceAsync(db,1,ct);
        while(true) {
            await using var query=new NpgsqlCommand("select exists(select 1 from pg_stat_activity where usename='sli_storage_login' and @pid=any(pg_blocking_pids(pid)))",monitor);
            query.Parameters.AddWithValue("pid",blocker.ProcessID);
            if(await query.ExecuteScalarAsync(ct) is true)break;
            Assert.False(import.IsCompleted,"Import finished before reaching the controlled hot-write wait");await Task.Delay(10,ct);
        }
        await using(var state=new NpgsqlCommand("select state='idle' and xact_start is null from pg_stat_activity where pid=@pid",monitor)) {
            state.Parameters.AddWithValue("pid",db.ProcessID);Assert.Equal(true,await state.ExecuteScalarAsync(ct));
        }
        await using var revoker=new NpgsqlConnection(fixture.Dsn("adlog_user"));await revoker.OpenAsync(ct);
        await using var revokeTx=await revoker.BeginTransactionAsync(ct);var revoke=Revoke(revoker,revokeTx,agent,ct);
        await WaitForBlock(monitor,revoker.ProcessID,db.ProcessID,ct);Assert.False(import.IsCompleted);Assert.False(revoke.IsCompleted);
        await hold.CommitAsync(ct);var result=await import;Assert.Equal(1,result.Imported);
        await revoke;await revokeTx.CommitAsync(ct);
        var pending=await Insert(monitor,2,1,ct);
        var refused=await new AgentWorkstationInboxConsumer(new Factory(),runtime).RunOnceAsync(db,1,ct);
        Assert.Equal(0,refused.Scanned);Assert.Equal(0,refused.Imported);Assert.Empty(refused.PendingReasons);
        await using(var check=new NpgsqlCommand("""
            select (select count(*) from event_hot),
                   (select count(*) from sli_agent_packet_inbox where imported_at is not null),
                   exists(select 1 from sli_agent_packet_inbox where packet_id=@packet and imported_at is null)
            """,monitor)) {
            check.Parameters.AddWithValue("packet",Guid.Parse(pending.Envelope["packet_id"]!.GetValue<string>()));
            await using var reader=await check.ExecuteReaderAsync(ct);Assert.True(await reader.ReadAsync(ct));
            Assert.Equal(1,reader.GetInt64(0));Assert.Equal(1,reader.GetInt64(1));Assert.True(reader.GetBoolean(2));
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
    [Fact]
    public async Task Revocation_winning_during_import_prevents_hot_writes_and_receipt_marker()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var monitor=new NpgsqlConnection(fixture.Pg.ConnectionString);await monitor.OpenAsync(ct);await Seed(monitor,fixture,ct);
        var sample=await Insert(monitor,1,1,ct);Guid agent=Guid.Parse(sample.Envelope["agent_id"]!.GetValue<string>());
        await using var runtime=Runtime(fixture);
        await using var db=new NpgsqlConnection(fixture.Dsn("adlog_user"));await db.OpenAsync(ct);
        await using var revoker=new NpgsqlConnection(fixture.Dsn("adlog_user"));await revoker.OpenAsync(ct);
        await using var tx=await revoker.BeginTransactionAsync(ct);await Revoke(revoker,tx,agent,ct);
        var import=new AgentWorkstationInboxConsumer(new Factory(),runtime).RunOnceAsync(db,1,ct);
        await WaitForBlock(monitor,db.ProcessID,revoker.ProcessID,ct);await tx.CommitAsync(ct);
        var result=await import;Assert.Equal(0,result.Imported);Assert.Equal(1,result.PendingReasons["agent_disabled"]);
        await using var check=new NpgsqlCommand("select not exists(select 1 from event_hot),not exists(select 1 from sli_agent_packet_inbox where imported_at is not null)",monitor);
        await using(var reader=await check.ExecuteReaderAsync(ct)) {Assert.True(await reader.ReadAsync(ct));Assert.True(reader.GetBoolean(0));Assert.True(reader.GetBoolean(1));}
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
