using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class SnapshotIngressQuotaTests
{
    [Theory]
    [InlineData("sli_agent_snapshot_chunks")]
    [InlineData("sli_agent_snapshot_cycles")]
    [InlineData("sli_agent_snapshot_policies")]
    [InlineData("sli_agent_snapshot_bindings")]
    [InlineData("sli_agent_receipts")]
    public async Task Retained_file_space_allows_snapshot_but_live_data_over_quota_rejects(string relation)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(ct);
        await using var db = await pg.OpenAsync(ct);
        // Only the columns read by the quota are needed. Padding models retained snapshot data.
        await PostCollectionPostgres.Sql(db, """
            create table sli_agent_snapshot_chunks(packet_id uuid,cycle_id uuid,payload jsonb,padding text);
            create table sli_agent_snapshot_cycles(cycle_id uuid,transport_state text,padding text);
            create table sli_agent_snapshot_policies(padding text);
            create table sli_agent_snapshot_bindings(padding text);
            create table sli_agent_receipts(packet_id uuid,agent_id uuid,module_id text,padding text);
            """, ct);
        // Relation comes solely from the fixed theory cases above.
        await PostCollectionPostgres.Sql(db, $"""
            insert into {relation}(padding) select repeat('x',1000) from generate_series(1,10000);
            delete from {relation} where ctid not in (select ctid from {relation} limit 10);
            analyze {relation};
            """, ct);
        const long storageLimit = 1024 * 1024;
        await using (var size = new NpgsqlCommand("select pg_total_relation_size(to_regclass(@relation))", db))
        {
            size.Parameters.AddWithValue("relation", relation);
            Assert.True(Convert.ToInt64(await size.ExecuteScalarAsync(ct)) > storageLimit);
        }
        var policy = SnapshotIngressPolicy.Parse(SnapshotPolicy.Ad, new JsonObject
        {
            ["source_instance_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            ["domain_sid"] = "S-1-5-21-100000001-200000002-300000003",
            ["domain_dns"] = "example.test", ["scope"] = "domain"
        });
        var envelope = new Envelope("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            policy.SourceId, SnapshotPolicy.Ad, "1.0.0", policy.Revision, "snapshot", policy.SourceId, 1,
            Cursor.Start("snapshot"), Cursor.Start("snapshot"), SnapshotPolicy.Ad + ".chunk.v1", new string('a', 64),
            1, 0, "2026-11-15T00:00:00+00:00", "complete", 0, 0);
        var plan = new SnapshotPrepared(envelope, new JsonObject(), policy);
        var receipt = AgentReceipt.Make(envelope, "committed", null, DateTimeOffset.UtcNow);
        var limits = new AgentInboxLimits(1000, long.MaxValue / 4, 1000, long.MaxValue / 4,
            1000, long.MaxValue / 4, storageLimit) { FreeDiskBytes = () => long.MaxValue };
        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            Assert.Null(await SnapshotIngress.CheckQuotaAsync(db, tx, plan, receipt, limits, ct));
            await tx.RollbackAsync(ct);
        }
        await PostCollectionPostgres.Sql(db, $"""
            insert into {relation}(padding) select repeat('x',1000) from generate_series(1,10000);
            analyze {relation};
            """, ct);
        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            Assert.Equal("agent_snapshot_storage_bytes_limit",
                await SnapshotIngress.CheckQuotaAsync(db, tx, plan, receipt, limits, ct));
            await tx.RollbackAsync(ct);
        }
    }
}
