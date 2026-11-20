using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Consumer;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Agents.M4;

public sealed class AgentImportWorkerDatabaseTests
{
    private sealed class OwnedFactory(SyntheticDatabase database) : IPostgresConnectionFactory
    { public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => database.OpenConnectionAsync(ct); }

    [Fact]
    public async Task HostLockAndOnceCommitOnlyTheSupportedPacket()
    {
        var ct = TestContext.Current.CancellationToken;
        var binding = OwnedDatabaseBinding.FromEnvironment();
        Assert.Equal("6a13bcc8-3cba-4ee1-85ce-5808480a9e21", binding.RunId.ToString("D"));
        var evidence = Environment.GetEnvironmentVariable("SLI_WORKER_EVIDENCE_DIR") ?? throw new InvalidOperationException();
        await using var database = await SyntheticDatabase.BorrowAsync(binding, ct);
        var baseline = await database.ReadBaselineAsync(ct); Assert.Equal(300, baseline.SchemaVersion);
        await using var db = await database.OpenConnectionAsync(ct);
        await using (var c = new NpgsqlCommand("select current_user,(select count(*) from sli_agent_packet_inbox where imported_at is null)", db))
        await using (var r = await c.ExecuteReaderAsync(ct))
        { Assert.True(await r.ReadAsync(ct)); Assert.Equal("adlog_user", r.GetString(0)); Assert.Equal(0L, r.GetInt64(1)); }

        async Task<int> HostOnce()
        {
            var builder = Host.CreateApplicationBuilder([]);
            builder.Services.AddSingleton<IPostgresConnectionFactory>(new OwnedFactory(database));
            builder.Services.AddSingleton<AgentWorkstationInboxConsumer>();
            builder.Services.AddSingleton(new AgentImportOptions(true, 10));
            builder.Services.AddSingleton<AgentImportWorker>();
            builder.Services.AddHostedService(sp => sp.GetRequiredService<AgentImportWorker>());
            using var host = builder.Build(); var worker = host.Services.GetRequiredService<AgentImportWorker>(); await host.RunAsync(ct);
            return worker.ExitCode;
        }

        await using (var held = new NpgsqlCommand("select pg_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))", db))
            await held.ExecuteScalarAsync(ct);
        Assert.Equal(9, await HostOnce());
        await using (var unlock = new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_post_collection_process'))", db))
            Assert.Equal(true, await unlock.ExecuteScalarAsync(ct));

        Guid agent = Guid.NewGuid(), hostId = Guid.NewGuid(), packetId = Guid.NewGuid(), pendingId = Guid.NewGuid();
        await File.WriteAllTextAsync(Path.Combine(evidence, "own-ids.json"), JsonSerializer.Serialize(new { agent, hostId, packetId, pendingId }), ct);
        var f = JsonNode.Parse(await File.ReadAllTextAsync(Path.Combine(Path.GetDirectoryName(SourcePath())!, "workstation-1102.json"), ct))!.AsObject();
        var packet = f["packet"]!.DeepClone().AsObject(); packet["header"]!["source"] = hostId.ToString("D");
        packet["records"]![0]!["payload"]!["computer_name"] = hostId.ToString("D");
        var rows = new JsonArray(packet["records"]!.AsArray().Select(x => x!["payload"]!.DeepClone()).ToArray());
        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            await using (var seed = new NpgsqlCommand("insert into sli_agents(id,host_id,key_fingerprint,assigned_modules) values(@id,@host,repeat('a',64),'[{\"module_id\":\"sli.workstations\",\"enabled\":true}]'::jsonb)", db, tx))
            { seed.Parameters.AddWithValue("id", agent); seed.Parameters.AddWithValue("host", hostId); await seed.ExecuteNonQueryAsync(ct); }
            for (int i = 0; i < 2; i++)
            {
                Guid id = i == 0 ? packetId : pendingId; string module = i == 0 ? "sli.workstations" : "sli.windows-eventlog";
                var env = new JsonObject { ["agent_id"] = agent.ToString("D"), ["packet_id"] = id.ToString("D"), ["module_id"] = module,
                    ["source_instance_id"] = hostId.ToString("D"), ["payload_sha256"] = Packets.Digest(packet) };
                await using var insert = new NpgsqlCommand("""
                    insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                    values(@agent,@module,@sequence,@packet,@hash,@envelope,'{"status":"committed"}'::jsonb);
                    insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at)
                    values(@packet,@envelope,@payload,@rows,clock_timestamp()+(@sequence * interval '1 second'))
                    """, db, tx);
                insert.Parameters.AddWithValue("agent",agent); insert.Parameters.AddWithValue("module",module); insert.Parameters.AddWithValue("sequence",(long)i+1);
                insert.Parameters.AddWithValue("packet",id); insert.Parameters.AddWithValue("hash",Packets.Digest(env));
                insert.Parameters.AddWithValue("envelope",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(env));
                insert.Parameters.AddWithValue("payload",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(packet)); insert.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(rows));
                await insert.ExecuteNonQueryAsync(ct);
            }
            await tx.CommitAsync(ct);
        }
        Assert.Equal(0, await HostOnce());
        await using (var verify = new NpgsqlCommand("""
            select (select count(*) from sli_agent_packet_inbox where packet_id=@packet and imported_at is not null),
                   (select count(*) from sli_agent_packet_inbox where packet_id=@pending and imported_at is null),
                   (select count(*) from sli_plugin_workstations.observations where agent_key=@agent)
            """, db))
        {
            verify.Parameters.AddWithValue("packet",packetId); verify.Parameters.AddWithValue("pending",pendingId); verify.Parameters.AddWithValue("agent",agent.ToString("D"));
            await using var r = await verify.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct)); Assert.Equal(1L,r.GetInt64(0)); Assert.Equal(1L,r.GetInt64(1)); Assert.Equal(1L,r.GetInt64(2));
        }
        await using (var reacquire = new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))", db))
            Assert.Equal(true,await reacquire.ExecuteScalarAsync(ct));
        await using (var release = new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_post_collection_process'))", db))
            Assert.Equal(true,await release.ExecuteScalarAsync(ct));
    }
    private static string SourcePath([CallerFilePath] string path = "") => path;
}
