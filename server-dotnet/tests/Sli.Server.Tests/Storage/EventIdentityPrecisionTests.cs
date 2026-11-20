using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents;
using Sli.Server.Agents.Ingress;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Semantic;
using Xunit;

namespace Sli.Server.Tests.Storage;

[Collection("Semantic producer environment")]
public sealed class EventIdentityPrecisionTests
{
    [Fact]
    public async Task Signed_native_precision_matches_short_publication_and_refuses_other_microseconds()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        using var environment = new SemanticProducerPostgresTests.Admission(mode: null);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var now = Iso8601.Truncate(DateTimeOffset.UtcNow);
        using var certificate = new CertificateRequest("CN=synthetic.example.test", key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
        string fingerprint = Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
        var agent = AdDcImportPerformanceTests.Agent;
        var host = AdDcImportPerformanceTests.Host;
        string source = AdDcImportPerformanceTests.Source;
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await AdDcImportPerformanceTests.SeedAsync(owner, fixture.Pg.Root, certificate, ct, fingerprint);

        var second = DateTimeOffset.FromUnixTimeSeconds(now.ToUnixTimeSeconds()).UtcDateTime.AddMinutes(-2);
        string[] fractions = ["000125500", "000126500", "000248500", "999999500"];
        long[] ticks = [1260, 1260, 2480, 10000000];
        var nativeLog = new PrecisionLog(fractions.Select((fraction, index) =>
        {
            long record = index + 1;
            string timestamp = second.ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture) + "." + fraction + "Z";
            string xml = $"""
                <Event xmlns="{EventXml.Namespace}"><System>
                <Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID>
                <EventRecordID>{record}</EventRecordID><TimeCreated SystemTime="{timestamp}"/>
                <Channel>Security</Channel><Computer>{source}</Computer></System><EventData>
                <Data Name="TargetUserName">synthetic-user</Data><Data Name="TargetDomainName">EXAMPLE</Data>
                <Data Name="Status">0xc000006a</Data></EventData></Event>
                """;
            return new EventRow(xml, $"<Bookmark Channel='Security' RecordId='{record}' IsCurrent='true'/>");
        }).ToArray());
        var catalog = EventCatalog.Load();
        var policy = AgentAdDcValidator.NormalizePolicy(new JsonObject
        {
            ["source_name"] = source,
            ["connect_address"] = source,
            ["channels"] = new JsonObject { ["Security"] = true, ["System"] = true, ["Directory Service"] = true },
        }, false);
        var module = new AdDcModule(host.ToString("D"), AdDcConfig.Parse(policy, catalog), nativeLog, catalog);
        var sample = Assert.IsType<Sample>(module.Collect(null, now, "Security").Sample);
        var packet = Packets.Make(new EcdsaPacketSigner(key), agent.ToString("D"), 1, sample, now);
        var rows = AgentAdDcValidator.Validate(packet.Envelope, packet.Payload, null, source);
        await using var app = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await app.OpenAsync(ct);
        var diagnostics = new AgentIngressDiagnostics(fixture.Pg.Root, NullLogger<AgentIngressDiagnostics>.Instance, TimeProvider.System);
        var ingress = new AgentPacketService(TimeProvider.System,
            new AgentInboxLimits(4096, 268435456, 32768, 2147483648, 65536, 4294967296, 17179869184), diagnostics);
        await using (var tx = await app.BeginTransactionAsync(ct))
        {
            var receipt = await ingress.ReceiveAsync(app, tx, new Sli.Server.Agents.AgentIdentity(agent, host, fingerprint, "active"),
                certificate, packet.ToJson(), ct);
            Assert.Equal("committed", receipt["status"]?.GetValue<string>());
            Assert.Equal(packet.Envelope.PacketId, receipt["packet_id"]?.GetValue<string>());
            await tx.CommitAsync(ct);
        }

        await using var worker = NpgsqlDataSource.Create(fixture.Dsn("sli_storage_login"));
        var packetId = Guid.Parse(packet.Envelope.PacketId);
        string catalogPath = Path.Combine(PostCollectionPostgres.Repository(), "config/event_catalog.json");
        var authorization = Authorization(fixture.Pg.Root);
        var records = new List<(long Id, long Record, long Server, int Channel, DateTime Time, byte[] Hash)>();
        await ImportAsync();
        await using (var query = new NpgsqlCommand("""
            select h.event_id,h.event_record_id,a.server_id,a.channel_id,h.time_created_utc,h.source_sha256,
                a.time_created_utc,a.normalized_hash,h.method#>>'{$origin,agent_id}'
            from event_hot h join storage_v2_event_identity_allocations a on a.id=h.event_id
            order by h.event_record_id
            """, owner))
        await using (var data = await query.ExecuteReaderAsync(ct))
        {
            while (await data.ReadAsync(ct))
            {
                var time = data.GetDateTime(4);
                var hash = data.GetFieldValue<byte[]>(5);
                Assert.Equal(second.AddTicks(ticks[records.Count]), time);
                Assert.Equal(time, data.GetDateTime(6));
                Assert.Equal(hash, data.GetFieldValue<byte[]>(7));
                Assert.Equal(agent.ToString("D"), data.GetString(8));
                records.Add((data.GetInt64(0), data.GetInt64(1), data.GetInt64(2), data.GetInt32(3), time, hash));
            }
        }
        Assert.Equal(fractions.Length, records.Count);
        await ImportAsync();
        await using (var count = new NpgsqlCommand("select count(*) from event_hot", owner))
            Assert.Equal((long)records.Count, (long)(await count.ExecuteScalarAsync(ct))!);

        for (int i = 0; i < records.Count; i++)
        {
            var stored = records[i];
            var native = rows[i]!.AsObject();
            string hash = DirectEventIdentity.Hash(native);
            Assert.Equal(stored.Hash, Convert.FromHexString(hash));
            var replay = await Reserve(stored, native, hash);
            Assert.Equal(stored.Id, replay.Id);
            Assert.True(replay.Published);
        }

        var first = records[0];
        var firstNative = rows[0]!.AsObject();
        var shortRow = ShortEventRow.Create(first.Id, 1, firstNative, Direct4624Projection.Create(firstNative), first.Server)! with
        {
            Time = first.Time.AddTicks(10),
            PacketId = packetId,
            PacketOrdinal = 0,
        };
        var refusal = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            ShortEventAdmissionPostgresTests.WriteAsync(fixture, [shortRow], ct));
        Assert.Equal("short_event_attestation_failed", refusal.Message);
        await using (var count = new NpgsqlCommand("select count(*) from event_hot", owner))
            Assert.Equal((long)records.Count, (long)(await count.ExecuteScalarAsync(ct))!);

        var digest = DirectEventIdentity.Hash(firstNative);
        string differentHash = new string('c', 64);
        var incomingConflict = await Assert.ThrowsAsync<DirectSourceConflict>(() => Reserve(first, firstNative, differentHash));
        Assert.Equal(0, incomingConflict.Ordinal);
        Assert.True(incomingConflict.Published);
        // A discrepancy in a disposable allocation must never overwrite the published proof.
        await using (var update = new NpgsqlCommand("update storage_v2_event_identity_allocations set normalized_hash=@hash where id=@id", owner))
        {
            update.Parameters.AddWithValue("hash", Convert.FromHexString(differentHash));
            update.Parameters.AddWithValue("id", first.Id);
            await update.ExecuteNonQueryAsync(ct);
        }
        var allocationConflict = await Assert.ThrowsAsync<DirectSourceConflict>(() => Reserve(first, firstNative, digest));
        Assert.Equal(0, allocationConflict.Ordinal);
        Assert.True(allocationConflict.Published);
        await fixture.AssertNoSqlErrorsAsync(ct);

        async Task ImportAsync()
        {
            await using var tx = await app.BeginTransactionAsync(ct);
            await DirectAdDcPacket.ImportAsync(app, tx, worker, packetId, packet.Envelope.ToJson(), packet.Payload, rows, catalogPath, ct);
            await tx.CommitAsync(ct);
        }

        Task<DirectEventReservation> Reserve((long Id, long Record, long Server, int Channel, DateTime Time, byte[] Hash) stored,
            JsonObject native, string hash) =>
            DirectEventIdentityStore.ReserveAsync(authorization, worker, stored.Server, stored.Channel, stored.Record, stored.Time, native, hash, ct);
    }

    private static DirectRuntimeAuthorization Authorization(string archive)
    {
        var now = DateTime.UtcNow;
        var record = new DirectRuntimeRecord("v2", "storage-v2-fresh-bootstrap/v1", new string('a', 64), archive,
            new JsonObject { ["kind"] = "fresh-event-store", ["version"] = 1 }, "synthetic",
            now, now.AddHours(1), null, "");
        return DirectRuntimeAuthorization.Validate(record with { AuthorizationDigest = DirectRuntimeAuthorization.Digest(record) }, now);
    }

    private sealed class PrecisionLog(EventRow[] rows) : IEventLogSource
    {
        public SourceBatch Read(string channel, ChannelProgress progress, int limit)
        {
            Assert.Equal("Security", channel);
            Assert.True(rows.Length <= limit);
            return new(rows);
        }
    }
}
