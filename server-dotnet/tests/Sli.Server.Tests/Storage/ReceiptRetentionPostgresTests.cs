using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Server.Agents;
using Sli.Server.Agents.Ingress;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class ReceiptRetentionPostgresTests
{
    // Proposed schema capability, only installed in this disposable cluster.
    internal const string Schema = """
        set role adlog_storage_owner;
        alter table public.sli_agents add column receipt_summary jsonb not null default '{}'::jsonb
          check(jsonb_typeof(receipt_summary)='object');
        grant select(id,receipt_summary),update(receipt_summary) on public.sli_agents to adlog_storage_lifecycle_delete;
        grant delete on public.sli_agent_receipts to adlog_storage_lifecycle_delete;
        grant select(packet_id) on public.sli_agent_snapshot_chunks to adlog_storage_lifecycle_delete;
        reset role;
        """;
    static readonly Guid Agent = Guid.Parse("00000000-0000-4000-8000-000000000017");
    static readonly DateTime Cutoff = new(2026,11,1,0,0,0,DateTimeKind.Utc);
    static NpgsqlDataSource Deletion(SqlPostgresFixture fixture) => NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(fixture.Dsn("sli_storage_lifecycle_delete_login")) {
        Options="-c role=adlog_storage_lifecycle_delete",CommandTimeout=0 }.ConnectionString);
    static async Task<object?> Scalar(NpgsqlConnection db, string sql, CancellationToken ct) {
        await using var command=new NpgsqlCommand(sql,db) { CommandTimeout=0 }; return await command.ExecuteScalarAsync(ct);
    }
    static Task SeedAgent(NpgsqlConnection db,CancellationToken ct) => PostCollectionPostgres.Sql(db,$"insert into sli_agents(id,host_id,key_fingerprint) values('{Agent}','{Agent}',repeat('a',64))",ct);
    static async Task<Guid> Receipt(NpgsqlConnection db,long sequence,string module,CancellationToken ct,bool gap=false) {
        Guid packet=Guid.NewGuid();
        var envelope=new JsonObject { ["agent_id"]=Agent.ToString(),["module_id"]=module,["sequence"]=sequence,["packet_id"]=packet.ToString(),
            ["source_instance_id"]=Agent.ToString(),["channel"]="Security",["generation"]="synthetic",["continuity_state"]=gap ? "gap" : "not_proven",["lost_count"]=gap ? 2 : 0 };
        await using var command=new NpgsqlCommand("""
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt,received_at)
            values(@agent,@module,@sequence,@packet,@hash,@envelope,'{"status":"committed"}',@received)
            """,db);
        command.Parameters.AddWithValue("agent",Agent); command.Parameters.AddWithValue("module",module); command.Parameters.AddWithValue("sequence",sequence);
        command.Parameters.AddWithValue("packet",packet); command.Parameters.AddWithValue("hash",Packets.Digest(envelope));
        command.Parameters.AddWithValue("envelope",NpgsqlDbType.Jsonb,envelope.ToJsonString()); command.Parameters.AddWithValue("received",Cutoff.AddDays(-1));
        await command.ExecuteNonQueryAsync(ct); return packet;
    }
    static async Task<JsonObject> Summary(NpgsqlConnection db,string module,CancellationToken ct) {
        await using var cmd=new NpgsqlCommand("select (receipt_summary->@module)::text from sli_agents where id=@agent",db);
        cmd.Parameters.AddWithValue("module",module); cmd.Parameters.AddWithValue("agent",Agent);
        return JsonNode.Parse((string)(await cmd.ExecuteScalarAsync(ct))!)!.AsObject();
    }

    [Fact]
    public async Task Compaction_merges_ranges_and_gap_flags_and_keeps_live_inbox_receipts()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await SeedAgent(db,ct);
        foreach(long sequence in new long[] {1,2,5}) await Receipt(db,sequence,"sli.windows.ad-dc",ct,sequence==5);
        Guid own=await Receipt(db,6,"sli.windows.ad-dc",ct);
        Guid young=await Receipt(db,7,"sli.windows.ad-dc",ct);
        Guid invalid=await Receipt(db,8,"sli.windows.ad-dc",ct);
        await Receipt(db,1,"sli.heartbeat",ct);
        await PostCollectionPostgres.Sql(db,$$$"""
            update sli_agent_receipts set received_at='2026-11-01T00:00:00Z' where packet_id='{{{young}}}';
            update sli_agent_receipts set envelope_sha256=repeat('b',64) where packet_id='{{{invalid}}}';
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
              select packet_id,envelope,'{"contract":"sli.collection-packet.v1","header":{"source":"fixture","channel":"Security","generation":"synthetic"}}',
              '[{"record_id":101,"event_id":4624,"time_created":"2026-10-01T00:00:00Z","computer_name":"fixture","channel":"Security"}]',now()
              from sli_agent_receipts where packet_id='{{{own}}}';
            """,ct);
        using var state=new StorageLifecycleTests.State(); await using var deletion=Deletion(fixture);
        var retention=new ReceiptRetention(deletion,state.Files);
        Assert.Equal("receipt_retention_schema_not_ready",(await retention.RunAsync(Cutoff,Guid.Empty,1000,ct))["reason"]?.ToString());
        object? indexes=await Scalar(db,"select count(*) from pg_index",ct);
        await PostCollectionPostgres.Sql(db,Schema,ct);
        Assert.Equal(indexes,await Scalar(db,"select count(*) from pg_index",ct));
        Guid after=Guid.Empty; long deleted=0,scanned=0; var held=new Dictionary<string,long>();
        while(true) {
            var batch=await retention.RunAsync(Cutoff,after,2,ct);
            deleted+=LifecycleJson.Number(batch,"deleted_count"); scanned+=LifecycleJson.Number(batch,"selected_count");
            foreach(var pair in batch["held_reasons"]!.AsObject()) held[pair.Key]=held.GetValueOrDefault(pair.Key)+long.Parse(pair.Value!.ToString());
            after=Guid.Parse(batch["last_scanned_packet_id"]!.ToString());
            if(batch["status"]?.ToString()=="complete") break;
            Assert.Equal("partial",batch["status"]?.ToString());
        }
        Assert.Equal(7,scanned); Assert.Equal(4,deleted);
        Assert.Equal(1,held["inbox_present"]); Assert.Equal(1,held["within_seven_days"]); Assert.Equal(1,held["receipt_unconfirmed"]);
        var summary=await Summary(db,"sli.windows.ad-dc",ct);
        Assert.Equal("[[1,2],[5,5]]",summary["ranges"]!.ToJsonString());
        Assert.Equal("[[5,5]]",summary["gap_ranges"]!.ToJsonString());
        Assert.Equal("[[3,4]]",summary["missing_ranges"]!.ToJsonString());
        Assert.Equal(3,summary["receipt_count"]!.GetValue<long>());
        Assert.True(summary["has_sequence_gaps"]!.GetValue<bool>()); Assert.True(summary["has_declared_gaps"]!.GetValue<bool>());
        Assert.Equal(1,(await Summary(db,"sli.heartbeat",ct))["receipt_count"]!.GetValue<long>());
        Assert.Equal(true,await Scalar(db,$"select exists(select 1 from sli_agent_receipts where packet_id='{own}')",ct));
        Assert.Equal(0,LifecycleJson.Number(await retention.RunAsync(Cutoff,Guid.Empty,1000,ct),"deleted_count"));
        await PostCollectionPostgres.Sql(db,$"delete from sli_agent_packet_inbox where packet_id='{own}'",ct);
        Assert.Equal(1,LifecycleJson.Number(await retention.RunAsync(Cutoff,Guid.Empty,1000,ct),"deleted_count"));
        Assert.Equal("[[1,2],[5,6]]",(await Summary(db,"sli.windows.ad-dc",ct))["ranges"]!.ToJsonString());
        Assert.Equal(false,await Scalar(db,$"select exists(select 1 from sli_agent_receipts where packet_id='{own}')",ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Compaction_rechecks_inbox_after_wait_and_rolls_back_summary_if_delete_is_not_confirmed()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await SeedAgent(db,ct); Guid packet=await Receipt(db,1,"sli.heartbeat",ct);
        await PostCollectionPostgres.Sql(db,Schema,ct);
        using var state=new StorageLifecycleTests.State(); await using var deletion=Deletion(fixture);
        bool waiting=false; var retention=new ReceiptRetention(deletion,state.Files,value => waiting=value);
        await using var writer=new NpgsqlConnection(fixture.Pg.ConnectionString); await writer.OpenAsync(ct);
        await using(var writing=await writer.BeginTransactionAsync(ct)) {
            await PostCollectionPostgres.Sql(writer,$"""
                insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows)
                select packet_id,envelope,jsonb_build_object('contract','sli.collection-packet.v1'),'[]'::jsonb
                from sli_agent_receipts where packet_id='{packet}'
                """,ct);
            var compaction=retention.RunAsync(Cutoff,Guid.Empty,1000,ct);
            while(!(bool)(await Scalar(db,"select exists(select 1 from pg_locks where relation='sli_agent_packet_inbox'::regclass and mode='ShareLock' and not granted)",ct))!) {
                if(compaction.IsCompleted) { await compaction; Assert.Fail("Compaction escaped provenance writer lock"); }
                ct.ThrowIfCancellationRequested(); await Task.Yield();
            }
            Assert.True(waiting); await writing.CommitAsync(ct);
            var held=await compaction; Assert.False(waiting);
            Assert.Equal(1,LifecycleJson.Number(held["held_reasons"]!.AsObject(),"inbox_present"));
            Assert.Equal(0,LifecycleJson.Number(held,"deleted_count"));
        }
        await PostCollectionPostgres.Sql(db,$"""
            delete from sli_agent_packet_inbox where packet_id='{packet}';
            create function public.synthetic_receipt_veto() returns trigger language plpgsql as 'begin return null; end';
            create trigger synthetic_receipt_veto before delete on public.sli_agent_receipts
              for each row execute function public.synthetic_receipt_veto();
            """,ct);
        var error=await Assert.ThrowsAsync<LifecycleBlocked>(() => retention.RunAsync(Cutoff,Guid.Empty,1000,ct));
        Assert.Equal("receipt_retention_delete_mismatch",error.Message);
        Assert.Equal("{}",await Scalar(db,"select receipt_summary::text from sli_agents",ct));
        Assert.Equal(1L,await Scalar(db,"select count(*) from sli_agent_receipts",ct));
        await PostCollectionPostgres.Sql(db,"drop trigger synthetic_receipt_veto on sli_agent_receipts; drop function public.synthetic_receipt_veto()",ct);
        Assert.Equal(1,LifecycleJson.Number(await retention.RunAsync(Cutoff,Guid.Empty,1000,ct),"deleted_count"));
        Assert.Equal(1,(await Summary(db,"sli.heartbeat",ct))["receipt_count"]!.GetValue<long>());
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Summary_tip_preserves_ingress_cursor_replay_gap_and_recovery_authorization()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct); await SeedAgent(db,ct);
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert=new CertificateRequest("CN=synthetic",key,HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(1));
        var now=DateTimeOffset.UtcNow;
        var identity=new AgentIdentity(Agent,Agent,new string('a',64),"active");
        using var state=new StorageLifecycleTests.State();
        var diagnostics=new AgentIngressDiagnostics(state.Path,NullLogger<AgentIngressDiagnostics>.Instance,TimeProvider.System);
        var service=new AgentPacketService(TimeProvider.System,new AgentInboxLimits(10000,100000000,10000,100000000,10000,100000000,1000000000),diagnostics);
        JsonObject Packet(long sequence,string before) => Packets.Make(new EcdsaPacketSigner(key),Agent.ToString(),sequence,
            new Sample("sli.heartbeat",Agent.ToString(),"heartbeat",Agent.ToString(),new Cursor("record_id",before),new Cursor("record_id",sequence.ToString()),
                new JsonObject { ["contract"]="sli.heartbeat.v1",["status"]="alive" }),now).ToJson();
        async Task<JsonObject> Send(JsonObject packet) {
            await using var tx=await db.BeginTransactionAsync(ct);
            await using(var locked=new NpgsqlCommand("select id from sli_agents where id=@agent for no key update",db,tx)) { locked.Parameters.AddWithValue("agent",Agent); await locked.ExecuteScalarAsync(ct); }
            var result=await service.ReceiveAsync(db,tx,identity,cert,packet,ct); await tx.CommitAsync(ct); return result;
        }
        var first=Packet(1,""); Assert.Equal("committed",(await Send(first))["status"]?.ToString());
        await PostCollectionPostgres.Sql(db,Schema+"update sli_agent_receipts set received_at=now()-interval '8 days'",ct);
        await using var deletion=Deletion(fixture); var retention=new ReceiptRetention(deletion,state.Files);
        Assert.Equal(1,LifecycleJson.Number(await retention.RunAsync(DateTime.UtcNow.AddDays(-7),Guid.Empty,1000,ct),"deleted_count"));
        Assert.Equal("agent_sequence_replayed",(await Send(first))["error_code"]?.ToString());
        Assert.Equal("agent_cursor_mismatch",(await Send(Packet(2,"wrong")))["error_code"]?.ToString());
        var gap=Packet(3,"1");
        Assert.Equal("agent_sequence_gap",(await Send(gap))["error_code"]?.ToString());
        var recovery=new Sli.Server.Agents.Control.AgentRecoveryService(new Sli.Server.Agents.Control.AgentControlAudit());
        // Preview and authorization must hash the same original envelope after compaction.
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            var list=JsonNode.Parse((await recovery.ListAsync(db,tx,Agent.ToString(),ct)).GetRawText())!;
            var preview=list["recovery_preview"]!;
            Assert.Single(preview["observation_ids"]!.AsArray());
            var body=preview.DeepClone().AsObject(); body.Remove("streams"); body["confirm_loss"]=true;
            using var document=System.Text.Json.JsonDocument.Parse(body.ToJsonString());
            Assert.Equal("authorized",(await recovery.AuthorizeAsync(db,tx,document.RootElement,"synthetic",ct)).GetProperty("status").GetString());
            await tx.CommitAsync(ct);
        }
        Assert.Equal("committed",(await Send(gap))["status"]?.ToString());
        Assert.Equal("committed",(await Send(Packet(4,"3")))["status"]?.ToString());
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
