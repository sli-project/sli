using System.Text.Json.Nodes;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Sli.Server.Operations;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentInboxCapacityTests
{
    private const long Gib = 1024L * 1024 * 1024;
    private const long PacketBytes = 90 * 1024;

    [Fact]
    public async Task PostgreSQL_backlog_above_old_limit_accepts_next_packet_and_refuses_when_disk_is_full()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(ct);
        await using var db = await pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, """
            create table sli_agents(id uuid,status text);
            create table sli_agent_receipts(packet_id uuid,agent_id uuid,module_id text,envelope jsonb,receipt jsonb);
            create table sli_agent_packet_inbox(packet_id uuid,imported_at timestamptz,envelope jsonb,packet jsonb,event_rows jsonb,quota_payload_bytes bigint,module_disabled_at timestamptz);
            """, ct);
        var agent = Guid.NewGuid();
        await using (var seed = new NpgsqlCommand("""
            insert into sli_agents values(@agent,'active');
            insert into sli_agent_receipts select md5(n::text)::uuid,@agent,'sli.windows-eventlog','{}','{}' from generate_series(1,3000) n;
            insert into sli_agent_packet_inbox select packet_id,null,'{}',jsonb_build_object('text',repeat('x',45*1024)),
                jsonb_build_array(jsonb_build_object('text',repeat('x',45*1024))),90*1024,null from sli_agent_receipts;
            analyze sli_agent_packet_inbox; analyze sli_agent_receipts;
            """, db))
        { seed.Parameters.AddWithValue("agent", agent); await seed.ExecuteNonQueryAsync(ct); }
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var packet = Packets.Make(new EcdsaPacketSigner(key), agent.ToString("D"), 3001,
            new Sample("sli.windows-eventlog", Guid.NewGuid().ToString("D"), "Security", "g",
                new Cursor("record_id", "3000"), new Cursor("record_id", "3001"), new JsonObject {
                    ["contract"] = "sli.collection-packet.v1", ["text"] = new string('x', 45 * 1024) }), DateTimeOffset.UtcNow);
        long free = 20 * Gib;
        var limits = AgentInboxLimits.FromEnvironment(_ => null) with { FreeDiskBytes = () => free };
        var diagnostics = new AgentIngressDiagnostics(pg.Root, NullLogger<AgentIngressDiagnostics>.Instance, TimeProvider.System);
        await using var tx = await db.BeginTransactionAsync(ct);
        var receipt = AgentReceipt.Make(packet.Envelope, "committed", null, DateTimeOffset.UtcNow);
        var rows = new JsonArray(packet.Payload.DeepClone());
        Assert.Null(await AgentInboxQuota.CheckAsync(db, tx, packet.Envelope, packet.Payload, rows, receipt, limits, diagnostics, ct));
        var explicitLimit = AgentInboxLimits.FromEnvironment(name => name == "SLI_AGENT_INBOX_AGENT_BYTES" ? "268435456" : null)
            with { FreeDiskBytes = () => free };
        Assert.Equal("agent_inbox_agent_bytes_limit", await AgentInboxQuota.CheckAsync(db, tx, packet.Envelope, packet.Payload, rows, receipt, explicitLimit, diagnostics, ct));
        free = 100 * 1024;
        Assert.Equal("agent_inbox_disk_bytes_limit", await AgentInboxQuota.CheckAsync(db, tx, packet.Envelope, packet.Payload, rows, receipt, limits, diagnostics, ct));
        Assert.Equal("full", limits.CapacityStatus());
        await using var remaining = new NpgsqlCommand("select count(*) from sli_agent_packet_inbox", db, tx);
        Assert.Equal(3000L, await remaining.ExecuteScalarAsync(ct));
        await tx.RollbackAsync(ct);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(10)]
    public void Backlog_of_3000_measured_packets_fits_when_disk_has_space(int agents)
    {
        long pending = 0;
        long free = 20 * Gib;
        for (int i = 0; i < 3000; i++)
        {
            Assert.Null(AgentInboxQuota.CheckCapacity(pending, pending, PacketBytes, agents, free));
            pending += PacketBytes;
            free -= AgentInboxLimits.DiskBytes(PacketBytes);
        }
        Assert.True(pending > 256L * 1024 * 1024);
    }

    [Fact]
    public void Fair_share_keeps_room_for_other_agents()
    {
        Assert.Equal("agent_inbox_agent_bytes_limit", AgentInboxQuota.CheckCapacity(2 * Gib, 2 * Gib, PacketBytes, 10, Gib));
        Assert.Null(AgentInboxQuota.CheckCapacity(0, 2 * Gib, PacketBytes, 10, Gib));
    }

    [Fact]
    public async Task Disk_refusal_is_visible_in_storage_status_and_recovers_after_expansion()
    {
        long free = 100 * 1024;
        var limits = new AgentInboxLimits(4096, long.MaxValue, 32768, 2 * Gib, 65536, 4 * Gib, 16 * Gib)
        { FreeDiskBytes = () => free };
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["Sli:ProjectRoot"] = Path.GetTempPath(), ["Sli:DataDirectory"] = Path.GetTempPath()
        }).Build();
        var service = new OperationsService(new NoQueries(), new Files(configuration), new OperationsCatalog(),
            new OperationsJobs(), TimeProvider.System, inboxLimits: limits);
        Assert.Equal("agent_inbox_disk_bytes_limit", AgentInboxQuota.CheckCapacity(0, 0, PacketBytes, 1, free));
        var status = await service.ReadAsync("/api/v1/operations/overview", new() { ["view"] = ["storage"] }, TestContext.Current.CancellationToken);
        Assert.Equal("full", (string?)status["storage"]?["agent_inbox_capacity"]);
        free = 20 * Gib;
        Assert.Null(AgentInboxQuota.CheckCapacity(0, 0, PacketBytes, 1, free));
        status = await service.ReadAsync("/api/v1/operations/overview", new() { ["view"] = ["storage"] }, TestContext.Current.CancellationToken);
        Assert.Equal("ok", (string?)status["storage"]?["agent_inbox_capacity"]);
    }

    [Fact]
    public void Large_packet_refusal_remains_visible_until_it_fits()
    {
        long free = 1024 * 1024;
        var limits = new AgentInboxLimits(4096, long.MaxValue, 32768, 2 * Gib, 65536, 4 * Gib, 16 * Gib)
        { FreeDiskBytes = () => free };
        Assert.Equal("agent_inbox_disk_bytes_limit", AgentInboxQuota.CheckCapacity(0, 0, 1024 * 1024, 1, free));
        limits.RecordDiskRejection(1024 * 1024);
        Assert.Equal("full", limits.CapacityStatus());
        free = Gib;
        Assert.Equal("ok", limits.CapacityStatus());
    }

    [Fact]
    public void Failed_measurement_fails_closed_with_a_status()
    {
        var limits = new AgentInboxLimits(4096, long.MaxValue, 32768, 2 * Gib, 65536, 4 * Gib, 16 * Gib)
        { FreeDiskBytes = () => throw new IOException("synthetic") };
        Assert.Equal("agent_inbox_disk_unavailable", AgentInboxQuota.CheckCapacity(0, 0, PacketBytes, 1, limits.ReadFreeBytes()));
        Assert.Equal("unavailable", limits.CapacityStatus());
    }

    private sealed class NoQueries : IOperationsQueries
    {
        public Task<JsonArray> ReadAsync(string sql, CancellationToken ct, params (string Name,object? Value)[] parameters)
            => throw new InvalidOperationException("Storage view must not query the database");
    }
    private sealed class Files(IConfiguration config) : OperationsFiles(config)
    {
        public override JsonObject Footprint(DateTimeOffset now) => new();
        public override JsonObject DiskPressure() => new();
    }
}
