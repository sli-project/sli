using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Consumer;
using Sli.Server.Storage.Direct;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed partial class AdDcImportPerformanceTests
{
    [Fact]
    public async Task Packet_capacity_preserves_events_and_amortizes_import_cost()
    {
        var ct = TestContext.Current.CancellationToken;
        using var environment = new Semantic.SemanticProducerPostgresTests.Admission(mode: null);
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert = new CertificateRequest("CN=synthetic", key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        await SeedAsync(admin, fixture.Pg.Root, cert, ct);
        await using var app = new NpgsqlConnection(fixture.Dsn("adlog_user")); await app.OpenAsync(ct);
        string catalog = Path.Combine(PostCollectionPostgres.Repository(), "config/event_catalog.json");
        int record = 1, total = 0;
        foreach (bool pooled in new[] { false, true }) {
            var settings = new NpgsqlConnectionStringBuilder(fixture.Dsn("sli_storage_login")) { Pooling = pooled };
            var source = new NpgsqlDataSourceBuilder(settings.ConnectionString);
            source.UsePhysicalConnectionInitializer(_ => throw new NotSupportedException(), DirectAdDcRuntime.InitializeWorkerAsync);
            await using var baseline = source.Build();
            await using var runtime = DirectAdDcRuntime.TryCreate(name => name == "ADLOG_STORAGE_V2_WORKER_DSN" ? settings.ConnectionString : null,
                _ => throw new InvalidOperationException(), catalog);
            Assert.NotNull(runtime);
            var worker = pooled ? runtime.Worker : baseline;
            if (pooled) {
                int pid;
                await using (var session = await worker.OpenConnectionAsync(ct)) {
                    pid = session.ProcessID;
                    await PostCollectionPostgres.Sql(session, "set application_name='synthetic-dirty'; create temporary table synthetic_pool_state(id int)", ct);
                }
                await using (var session = await worker.OpenConnectionAsync(ct)) {
                    Assert.Equal(pid, session.ProcessID);
                    await using var tx = await session.BeginTransactionAsync(ct);
                    await using (var role = new NpgsqlCommand("set local role adlog_storage_worker", session, tx)) await role.ExecuteNonQueryAsync(ct);
                    await using var checkRole = new NpgsqlCommand("select current_user, to_regclass('pg_temp.synthetic_pool_state') is null, current_setting('application_name')<>'synthetic-dirty'", session, tx);
                    await using var result = await checkRole.ExecuteReaderAsync(ct); Assert.True(await result.ReadAsync(ct));
                    Assert.Equal("adlog_storage_worker", result.GetString(0)); Assert.True(result.GetBoolean(1)); Assert.True(result.GetBoolean(2));
                }
            }
            // Warm both paths before measuring; use fresh event identities on every import.
            var warm = Sample(record++); await ReceiptAsync(admin, warm, ct); total++;
            await using (var tx = await app.BeginTransactionAsync(ct)) {
                await ImportAsync(app, tx, worker, warm, catalog, ct); await tx.CommitAsync(ct);
            }
            var costs = new Dictionary<int, double>();
            foreach (int count in new[] { 8, 24, 32 }) {
                const int packets = 6;
                var elapsed = new List<double>();
                var stages = new Dictionary<AdDcProjectionStep, double>();
                double verifyMs = 0;
                for (int packet = 0; packet < packets; packet++) {
                    var sample = Sample(record, count); record += count; total += count;
                    var envelope = Envelope.Parse(sample.Envelope);
                    var signed = new SignedPacket(envelope, sample.Payload, Convert.ToBase64String(
                        key.SignData(Packets.SignedMessage(envelope), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)));
                    var verify = Stopwatch.StartNew();
                    PacketVerifier.Verify(signed.ToJson(), key); verify.Stop(); verifyMs += verify.Elapsed.TotalMilliseconds;
                    await ReceiptAsync(admin, sample, ct);
                    var clock = Stopwatch.StartNew(); double last = 0;
                    var step = AdDcProjectionStep.ImportQueueWait;
                    void Report(AdDcProjectionStep next) {
                        double now = clock.Elapsed.TotalMilliseconds;
                        stages[step] = stages.GetValueOrDefault(step) + now - last; step = next; last = now;
                    }
                    await using (var tx = await app.BeginTransactionAsync(ct)) {
                        await DirectAdDcPacket.ImportAsync(app, tx, worker, Guid.Parse(envelope.PacketId),
                            sample.Envelope, sample.Payload, sample.Rows, catalog, ct, Report);
                        await tx.CommitAsync(ct);
                    }
                    Report(AdDcProjectionStep.RawFinalization); clock.Stop(); elapsed.Add(clock.Elapsed.TotalMilliseconds);
                }
                costs[count] = elapsed.Order().ElementAt(packets / 2) / count;
                output.WriteLine($"CAPACITY pooled={pooled}, N={packets}, M={count}: mean={elapsed.Average():F2} ms/packet, median={costs[count]:F3} ms/event, events/min={60000 * count / elapsed.Average():F0}, packets/min={60000 / elapsed.Average():F0}, verification={verifyMs / packets:F2} ms/packet");
                foreach (var stage in stages.OrderByDescending(x => x.Value).Take(8))
                    output.WriteLine($"  {stage.Key}: {stage.Value / packets:F2} ms/packet");
            }
            // Compare fourfold batch growth, using medians to exclude a one-off fsync or scheduling stall.
            Assert.True(costs[32] <= costs[8], $"pooled={pooled}: {costs[32]:F3} vs {costs[8]:F3} ms/event");
        }
        await using var check = new NpgsqlCommand("select (select count(*) from event_hot), (select count(*) from sli_agent_packet_inbox where imported_at is null), (select count(*) from event_hot where source_sha256 is null or event_record_id is null)", admin);
        await using var rows = await check.ExecuteReaderAsync(ct); Assert.True(await rows.ReadAsync(ct));
        Assert.Equal(total, rows.GetInt64(0)); Assert.Equal(0, rows.GetInt64(1)); Assert.Equal(0, rows.GetInt64(2));
    }
}
