using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Server.Agents;
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.Ingress;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class InboxRetentionConcurrencyPostgresTests
{
    [Fact]
    public async Task Reception_and_AD_import_commit_before_retention_releases_its_packet_locks()
    {
        var ct = TestContext.Current.CancellationToken;
        var sample = DirectWorkerMixedDatabaseTests.Sample();
        var envelope = Envelope.Parse(sample.Envelope);
        var policy = AgentAdDcValidator.NormalizePolicy(new JsonObject {
            ["source_name"] = DirectWorkerMixedDatabaseTests.Name, ["connect_address"] = DirectWorkerMixedDatabaseTests.Name
        }, false);
        sample.Packet["records"]![0]!["payload"]!["connect_address"] = DirectWorkerMixedDatabaseTests.Name;
        sample.Packet["context"]!["ad_dc"]!["channels"] = policy["channels"]!.DeepClone();
        Assert.Single(AgentAdDcValidator.Validate(envelope, sample.Packet, policy, DirectWorkerMixedDatabaseTests.Name));
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var monitor = new NpgsqlConnection(fixture.Pg.ConnectionString); await monitor.OpenAsync(ct);
        await DirectWorkerMixedDatabaseTests.SeedAsync(monitor, fixture.Pg.Root, ct);
        Guid agent = Guid.Parse(envelope.AgentId), host = Guid.Parse(envelope.SourceInstanceId);
        await using (var seed = new NpgsqlCommand("""
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt,received_at)
            values(@agent,'sli.heartbeat',1,'00000000-0000-4000-8000-000000000195',repeat('a',64),
              jsonb_build_object('agent_id',@agent::text,'module_id','sli.heartbeat'),'{"status":"committed"}',now()-interval '10 days');
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at,imported_at)
            select packet_id,envelope,'{}','[]',received_at,received_at from sli_agent_receipts;
            """, monitor)) {
            seed.Parameters.AddWithValue("agent", agent); await seed.ExecuteNonQueryAsync(ct);
        }
        using var state = new StorageLifecycleTests.State();
        await using var deletion = NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(fixture.Dsn("sli_storage_lifecycle_delete_login")) {
            Options = "-c role=adlog_storage_lifecycle_delete", CommandTimeout = 0 }.ConnectionString);
        var locked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var retention = new InboxRetention(deletion, state.Files, waiting => {
            if (waiting) return;
            locked.TrySetResult(); release.Task.GetAwaiter().GetResult();
        });
        var cleanup = Task.Run(() => retention.RunAsync(DateTime.UtcNow.AddDays(-7), Guid.Empty, 1000, ct), ct);
        try {
            if (await Task.WhenAny(locked.Task, cleanup) == cleanup) await cleanup;
            await locked.Task.WaitAsync(ct);
            await using (var locks = new NpgsqlCommand("""
                select exists(select 1 from pg_locks l join pg_stat_activity a using(pid)
                  where a.usename='sli_storage_lifecycle_delete_login' and l.granted
                    and l.relation='sli_agent_packet_inbox'::regclass and l.mode='RowShareLock'),
                  exists(select 1 from pg_locks l join pg_stat_activity a using(pid)
                  where a.usename='sli_storage_lifecycle_delete_login' and l.granted
                    and l.relation='sli_agents'::regclass and l.mode='RowShareLock')
                """, monitor))
            await using (var rows = await locks.ExecuteReaderAsync(ct)) {
                Assert.True(await rows.ReadAsync(ct)); Assert.True(rows.GetBoolean(0)); Assert.False(rows.GetBoolean(1));
            }
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var cert = new CertificateRequest("CN=synthetic", key, HashAlgorithmName.SHA256)
                .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            var signed = Packets.Make(new EcdsaPacketSigner(key), envelope.AgentId, 1,
                new Sample(envelope.ModuleId, envelope.SourceInstanceId, envelope.Channel, envelope.Generation,
                    envelope.CursorBefore, envelope.CursorAfter, sample.Packet, LostCount: 0), DateTimeOffset.UtcNow);
            var diagnostics = new AgentIngressDiagnostics(state.Path, NullLogger<AgentIngressDiagnostics>.Instance, TimeProvider.System);
            var service = new AgentPacketService(TimeProvider.System,
                new AgentInboxLimits(10000, 100000000, 10000, 100000000, 10000, 100000000, 1000000000), diagnostics);
            await using var ingress = new NpgsqlConnection(fixture.Dsn("adlog_user")); await ingress.OpenAsync(ct);
            await using (var tx = await ingress.BeginTransactionAsync(ct)) {
                await using var command = new NpgsqlCommand("select id from sli_agents where id=@agent for no key update", ingress, tx);
                command.Parameters.AddWithValue("agent", agent); Assert.Equal(agent, await command.ExecuteScalarAsync(ct));
                var receipt = await service.ReceiveAsync(ingress, tx, new AgentIdentity(agent, host, new string('a', 64), "active"), cert, signed.ToJson(), ct);
                Assert.True(receipt["status"]?.ToString() == "committed", receipt["error_code"]?.ToString()); await tx.CommitAsync(ct);
            }
            await using var runtime = DirectAdDcRuntime.TryCreate(k => k == "ADLOG_STORAGE_V2_WORKER_DSN" ? fixture.Dsn("sli_storage_login") : null,
                _ => [], Path.Combine(PostCollectionPostgres.Repository(), "config/event_catalog.json"));
            Assert.NotNull(runtime);
            await using var import = new NpgsqlConnection(fixture.Dsn("adlog_user")); await import.OpenAsync(ct);
            await using (var tx = await import.BeginTransactionAsync(ct)) {
                var step = await AgentWorkstationInboxConsumer.ProcessNextAsync(import, tx, null, ct, runtime);
                Assert.True(step.Imported, step.PendingReason); Assert.Equal(Guid.Parse(signed.Envelope.PacketId), step.PacketId);
                await tx.CommitAsync(ct);
            }
            Assert.False(cleanup.IsCompleted);
            await using var check = new NpgsqlCommand("select imported_at is not null from sli_agent_packet_inbox where packet_id=@packet", monitor);
            check.Parameters.AddWithValue("packet", Guid.Parse(signed.Envelope.PacketId)); Assert.Equal(true, await check.ExecuteScalarAsync(ct));
        } finally { release.TrySetResult(); await cleanup; }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
