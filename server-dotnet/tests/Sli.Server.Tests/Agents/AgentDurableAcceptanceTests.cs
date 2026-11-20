using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.Ingress;
using Sli.Server.Entities;
using Sli.Server.Infrastructure;
using Sli.Server.Storage.Direct;
using Sli.Server.Storage.EventReports;
using Sli.Server.Tests.Semantic;
using Xunit;

namespace Sli.Server.Tests.Agents;

// GAP-003: committed/duplicate proves durable acceptance, never import or report success.
[Collection("Semantic producer environment")]
public sealed class AgentDurableAcceptanceTests
{
    private sealed class Clock(DateTimeOffset now) : TimeProvider
    { public override DateTimeOffset GetUtcNow() => now; }
    private sealed class Connections(string dsn) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        { var db = new NpgsqlConnection(dsn); await db.OpenAsync(ct); return db; }
    }

    [Fact]
    public async Task Receipt_spool_import_and_report_have_independent_crash_and_replay_boundaries()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        using var environment = new SemanticProducerPostgresTests.Admission(mode: null);
        environment.Set("ADLOG_POSTGRES_IMPORT_QUEUE_LOCK", Path.Combine(fixture.Pg.Root, "post-collection.lock"));
        environment.Set("SLI_PLUGIN_RUNTIME_DIR", null);
        environment.Set("SLI_PLUGIN_LOCK_DIR", null);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString);
        await admin.OpenAsync(ct);
        var connections = new Connections(fixture.Dsn("adlog_user"));
        await using var db = await connections.OpenAsync(ct);
        var agent = AdDcImportPerformanceTests.Agent;
        var host = AdDcImportPerformanceTests.Host;
        var now = Iso8601.Truncate(DateTimeOffset.UtcNow);
        var sample = AgentPacketReportPostgresTests.CaptureSample(now, AdDcImportPerformanceTests.Source, host);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var peer = new CertificateRequest("CN=synthetic.example.test", key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
        string fingerprint = Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
        await AdDcImportPerformanceTests.SeedAsync(admin, fixture.Pg.Root, peer, ct, fingerprint);
        string catalog = Path.Combine(PostCollectionPostgres.Repository(), "config", "event_catalog.json");
        await using var runtime = new DirectAdDcRuntime(NpgsqlDataSource.Create(fixture.Dsn("sli_storage_login")), catalog);
        var consumer = new AgentWorkstationInboxConsumer(connections, runtime);
        var service = new AgentPacketService(new Clock(now),
            new AgentInboxLimits(4096,268435456,32768,2147483648,65536,4294967296,17179869184),
            new AgentIngressDiagnostics(fixture.Pg.Root, NullLogger<AgentIngressDiagnostics>.Instance, new Clock(now)));
        var spool = Path.Combine(fixture.Pg.Root, "spool");
        FilePacketQueue Queue() => new(spool, new PhysicalDurableFiles(), 10_000_000, 7 * 86400);
        SignedPacket packet;
        using (var queue = Queue()) packet = queue.Capture(new EcdsaPacketSigner(key), agent.ToString("D"), sample, now);

        async Task<JsonObject> Receive(bool commit)
        {
            await using var tx = await db.BeginTransactionAsync(ct);
            await using var held = new NpgsqlCommand("select id from sli_agents where id=@agent for no key update", db, tx);
            held.Parameters.AddWithValue("agent", agent); Assert.Equal(agent, await held.ExecuteScalarAsync(ct));
            var receipt = await service.ReceiveAsync(db, tx, new(agent, host, fingerprint, "active"), peer, packet.ToJson(), ct);
            if (commit) await tx.CommitAsync(ct); else await tx.RollbackAsync(ct);
            return receipt;
        }
        async Task AssertStored(long accepted, bool imported, long events)
        {
            await using var read = new NpgsqlCommand("""
                select (select count(*) from sli_agent_receipts where packet_id=@packet),
                       (select count(*) from sli_agent_packet_inbox where packet_id=@packet),
                       (select count(*) from sli_agent_packet_inbox where packet_id=@packet and imported_at is not null),
                       (select count(*) from event_hot where method#>>'{$origin,agent_id}'=@agent)
                """, admin);
            read.Parameters.AddWithValue("packet", Guid.Parse(packet.Envelope.PacketId));
            read.Parameters.AddWithValue("agent", agent.ToString("D"));
            await using var rows = await read.ExecuteReaderAsync(ct); Assert.True(await rows.ReadAsync(ct));
            Assert.Equal(accepted, rows.GetInt64(0)); Assert.Equal(accepted, rows.GetInt64(1));
            Assert.Equal(imported ? 1L : 0L, rows.GetInt64(2)); Assert.Equal(events, rows.GetInt64(3));
        }

        // A receipt built inside a transaction is not yet authority for an HTTP ACK.
        Assert.Equal("committed", (string?)(await Receive(false))["status"]);
        await AssertStored(0, false, 0);
        using (var queue = Queue()) Assert.Equal(packet.ToCanonical(), Assert.Single(queue.Pending()).ToCanonical());
        var accepted = await Receive(true);
        Assert.Equal("committed", (string?)accepted["status"]);
        Assert.Equal("sli.agent-receipt.v1", (string?)accepted["contract_id"]);
        Assert.Equal(packet.Envelope.PacketId, (string?)accepted["packet_id"]);
        Assert.Equal(packet.Envelope.PayloadSha256, (string?)accepted["payload_sha256"]);
        Assert.True(JsonNode.DeepEquals(packet.Envelope.CursorAfter.ToJson(), accepted["committed_cursor"]));
        Assert.Equal("agent-packet:" + packet.Envelope.PacketId, (string?)accepted["evidence_ref"]);
        Assert.NotNull(accepted["committed_at_utc"]); Assert.Null(accepted["error_code"]);
        Assert.Equal(8, accepted.Count); // Wire receipt has no import-success/readiness fields.
        await AssertStored(1, false, 0);

        async Task<List<(long Id, int EventKind, string Channel, byte[] SourceDigest)>> ReportSource()
        {
            await using var read = new NpgsqlCommand("with short_events as (" + EntityShortSql.Source("@boundary", daily: false) + ") " +
                "select e.id,e.event_id,e.channel,h.source_sha256 " + EventReadService.ShortJoins +
                " join event_hot h on h.event_id=e.id and h.time_created_utc=e.time_created_utc where s.id is not null", db);
            read.Parameters.AddWithValue("boundary", now.AddDays(-1));
            var items = new List<(long, int, string, byte[])>();
            await using var rows = await read.ExecuteReaderAsync(ct);
            while (await rows.ReadAsync(ct)) items.Add((rows.GetInt64(0), rows.GetInt32(1), rows.GetString(2), rows.GetFieldValue<byte[]>(3)));
            return items;
        }
        Assert.Empty(await ReportSource());

        // Response lost after commit: the same on-disk packet recovers the original proof.
        var duplicate = await Receive(true);
        var expectedDuplicate = accepted.DeepClone(); expectedDuplicate["status"] = "duplicate";
        Assert.True(JsonNode.DeepEquals(expectedDuplicate, duplicate));
        using (var queue = Queue())
        {
            Assert.Equal(packet.ToCanonical(), Assert.Single(queue.Pending()).ToCanonical());
            var wrong = duplicate.DeepClone(); wrong["payload_sha256"] = new string('0',64);
            Assert.False(queue.Acknowledge(packet, wrong)); Assert.Single(queue.Pending());
            Assert.True(queue.Acknowledge(packet, duplicate)); Assert.Empty(queue.Pending());
        }
        using (var queue = Queue())
        {
            Assert.Empty(queue.Pending());
            Assert.Equal(packet.Envelope.Generation, queue.Captured(sample.ModuleId)!.Generation);
            Assert.Equal(packet.Envelope.CursorAfter, queue.Captured(sample.ModuleId)!.CursorAfter);
        }
        await AssertStored(1, false, 0); Assert.Empty(await ReportSource());

        // A sink failure after its INSERT must roll back both projection and marker, not the receipt.
        await PostCollectionPostgres.Sql(admin, """
            create function public.test_projection_failure() returns trigger language plpgsql as $$
            begin raise exception 'synthetic private diagnostic'; end $$;
            create trigger test_projection_failure after insert on public.event_hot
                for each row execute function public.test_projection_failure();
            """, ct);
        var failed = await consumer.RunOnceAsync(db, 1, ct);
        Assert.Equal(1, failed.Scanned); Assert.Equal(0, failed.Imported);
        Assert.Equal(1, failed.PendingReasons["agent_ad_dc_projection_failed"]);
        await AssertStored(1, false, 0); Assert.Empty(await ReportSource());
        Assert.True(JsonNode.DeepEquals(expectedDuplicate, await Receive(true)));
        await PostCollectionPostgres.Sql(admin, "drop trigger test_projection_failure on public.event_hot; drop function public.test_projection_failure()", ct);

        // Simulated consumer crash before commit: neither the report row nor imported_at is visible.
        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            var projected = await AgentWorkstationInboxConsumer.ProcessNextAsync(db, tx, null, ct, runtime);
            Assert.True(projected.Imported, projected.PendingReason);
            Assert.Equal(Guid.Parse(packet.Envelope.PacketId), projected.PacketId);
            await tx.RollbackAsync(ct);
        }
        await AssertStored(1, false, 0); Assert.Empty(await ReportSource());
        consumer = new AgentWorkstationInboxConsumer(connections, runtime);
        var imported = await consumer.RunOnceAsync(db, 1, ct);
        Assert.Equal(1, imported.Imported); Assert.Empty(imported.PendingReasons);
        await AssertStored(1, true, 1);
        var item = Assert.Single(await ReportSource());
        Assert.Equal(AgentPacketReportPostgresTests.EventKind, item.EventKind);
        Assert.Equal("Security", item.Channel);
        Assert.Equal(32, item.SourceDigest.Length);

        // Explicit sink replay retains identity and one result; normal restart skips imported packets.
        consumer = new AgentWorkstationInboxConsumer(connections, runtime);
        Assert.Equal(0, (await consumer.RunOnceAsync(db, 1, ct)).Scanned);
        await using (var reset = new NpgsqlCommand("update sli_agent_packet_inbox set imported_at=null where packet_id=@packet", admin))
        { reset.Parameters.AddWithValue("packet", Guid.Parse(packet.Envelope.PacketId)); Assert.Equal(1, await reset.ExecuteNonQueryAsync(ct)); }
        Assert.Equal(1, (await consumer.RunOnceAsync(db, 1, ct)).Imported);
        await AssertStored(1, true, 1);
        var replayed = Assert.Single(await ReportSource());
        Assert.Equal(item.Id, replayed.Id);
        Assert.Equal(item.SourceDigest, replayed.SourceDigest);
        Assert.Equal(0, (await consumer.RunOnceAsync(db, 1, ct)).Scanned);
        Assert.True(JsonNode.DeepEquals(expectedDuplicate, await Receive(true)));
    }
}
