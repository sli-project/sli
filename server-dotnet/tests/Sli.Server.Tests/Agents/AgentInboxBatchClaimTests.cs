using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Agents.Consumer;
using Xunit;

namespace Sli.Server.Tests.Agents;

[Collection("Semantic producer environment")]
public sealed class AgentInboxBatchClaimTests
{
    [Fact]
    public async Task Claim_locks_a_fair_ordered_page_together_and_rollback_releases_every_packet()
    {
        var ct=TestContext.Current.CancellationToken;
        using var environment=new Semantic.SemanticProducerPostgresTests.Admission(mode:null);
        environment.Set("SLI_CORE_JOB_WORKSTATIONS_PROJECTION",null);
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString);await db.OpenAsync(ct);
        Guid a=Guid.NewGuid(),b=Guid.NewGuid();var ids=Enumerable.Range(0,5).Select(_=>Guid.NewGuid()).ToArray();
        await using(var agents=new NpgsqlCommand("insert into sli_agents(id,host_id,key_fingerprint) values(@a,@a,repeat('a',64)),(@b,@b,repeat('b',64))",db)) {
            agents.Parameters.AddWithValue("a",a);agents.Parameters.AddWithValue("b",b);await agents.ExecuteNonQueryAsync(ct);
        }
        for(int n=0;n<ids.Length;n++) {
            await using var insert=new NpgsqlCommand("""
                insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                values(@agent,'sli.windows.ad-dc',@sequence,@packet,@hash,@envelope,'{"status":"committed"}');
                insert into sli_agent_packet_inbox(packet_id,received_at,envelope,packet,event_rows)
                values(@packet,'2026-01-01'::timestamptz+@n*interval '1 second',@envelope,'{}','[]')
                """,db);
            insert.Parameters.AddWithValue("packet",ids[n]);insert.Parameters.AddWithValue("n",n);
            var envelope=new JsonObject {
                ["agent_id"]=(n<3?a:b).ToString(),["module_id"]="sli.windows.ad-dc"
            };
            insert.Parameters.AddWithValue("agent",n<3?a:b);insert.Parameters.AddWithValue("sequence",(long)n+1);
            insert.Parameters.AddWithValue("hash",Sli.Agent.Protocol.Packets.Digest(envelope));
            insert.Parameters.AddWithValue("envelope",NpgsqlDbType.Jsonb,envelope.ToJsonString());await insert.ExecuteNonQueryAsync(ct);
        }
        await using var other=new NpgsqlConnection(fixture.Pg.ConnectionString);await other.OpenAsync(ct);
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            var page=await AgentWorkstationInboxConsumer.ClaimBatchAsync(db,tx,4,[],[],new(),ct);
            Assert.Equal(new[]{ids[0],ids[3],ids[1],ids[4]},page.Select(p=>p.PacketId));
            // A parallel consumer cannot acquire any member of the claimed page.
            await using var otherTx=await other.BeginTransactionAsync(ct);
            await using var available=new NpgsqlCommand("select packet_id from sli_agent_packet_inbox order by received_at for update skip locked",other,otherTx);
            await using(var rows=await available.ExecuteReaderAsync(ct)) {
                Assert.True(await rows.ReadAsync(ct));Assert.Equal(ids[2],rows.GetGuid(0));Assert.False(await rows.ReadAsync(ct));
            }
            await otherTx.RollbackAsync(ct);await tx.RollbackAsync(ct);
        }
        await using(var tx=await other.BeginTransactionAsync(ct)) {
            var page=await AgentWorkstationInboxConsumer.ClaimBatchAsync(other,tx,5,[],[],new(),ct);
            Assert.Equal(new[]{ids[0],ids[3],ids[1],ids[4],ids[2]},page.Select(p=>p.PacketId));
            await tx.RollbackAsync(ct);
        }
    }
}
