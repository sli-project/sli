using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Updates;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class ShippedAgentUpdateTests
{
    [Fact]
    public async Task AcceptedReleaseRegistersOnePackageAndOffersOnlyToOlderAgentsWithoutManualPolicy()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var db = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await db.OpenAsync(ct);
        var old = Identity();
        var current = Identity();
        var overridden = Identity();
        await using (var seed = new NpgsqlCommand("""
            insert into sli_agents(id,host_id,key_fingerprint,rights_probe) values
                (@old,gen_random_uuid(),repeat('a',64),'{"agent_version":"26.0.136"}'),
                (@current,gen_random_uuid(),repeat('b',64),'{"agent_version":"26.0.185"}'),
                (@overridden,gen_random_uuid(),repeat('c',64),'{"agent_version":"26.0.136"}');
            insert into sli_agent_update_policy(agent_id,package_sha256) values(@overridden,null)
            """, db))
        {
            seed.Parameters.AddWithValue("old", old.Id);
            seed.Parameters.AddWithValue("current", current.Id);
            seed.Parameters.AddWithValue("overridden", overridden.Id);
            await seed.ExecuteNonQueryAsync(ct);
        }
        string directory = Path.Combine(fixture.Pg.Root, "shipped-agent");
        Directory.CreateDirectory(directory);
        string msi = Path.Combine(directory, "SliAgent.msi");
        byte[] data = "synthetic MSI contents"u8.ToArray();
        string hash = Convert.ToHexStringLower(SHA256.HashData(data));
        await File.WriteAllBytesAsync(msi, data, ct);
        await File.WriteAllTextAsync(msi + ".json", JsonSerializer.Serialize(new { product_version = "26.0.185", sha256 = hash }), ct);
        var audit = new AgentControlAudit();
        await ShippedAgentUpdate.RegisterAsync(db, directory, audit, ct);
        await ShippedAgentUpdate.RegisterAsync(db, directory, audit, ct);
        await using (var packages = new NpgsqlCommand("select version,sha256,archive from sli_agent_update_packages", db))
        await using (var reader = await packages.ExecuteReaderAsync(ct))
        {
            Assert.True(await reader.ReadAsync(ct));
            Assert.Equal("26.0.185", reader.GetString(0));
            Assert.Equal(hash, reader.GetString(1));
            Assert.Equal(data, reader.GetFieldValue<byte[]>(2));
            Assert.False(await reader.ReadAsync(ct));
        }
        await using var tx = await db.BeginTransactionAsync(ct);
        await AgentClientControlService.LockUpdateWavesAsync(db, tx, ct);
        var client = new AgentClientControlService(audit, TimeProvider.System);
        var offer = (await client.CheckInAsync(db, tx, old, ct))["agent_update"]!;
        Assert.Equal(hash, offer["sha256"]!.GetValue<string>());
        Assert.Equal("26.0.185", offer["version"]!.GetValue<string>());
        Assert.Equal("msi", offer["format"]!.GetValue<string>());
        Assert.Equal(("updating", "26.0.136"), await UpdateState());
        Assert.Null((await client.CheckInAsync(db, tx, current, ct))["agent_update"]);
        Assert.Null((await client.CheckInAsync(db, tx, overridden, ct))["agent_update"]);
        var updates = new AgentUpdateService(audit);
        var package = await updates.DownloadPackageAsync(db, tx, old, hash, ct);
        Assert.Equal("application/octet-stream", package.ContentType);
        await using (var payload = package.Content)
        {
            using var downloaded = new MemoryStream();
            await payload.CopyToAsync(downloaded, ct);
            Assert.Equal(data, downloaded.ToArray());
        }
        await Assert.ThrowsAsync<AgentControlException>(() => updates.DownloadAsync(db, tx, current, hash, ct));
        await updates.ReportAsync(db, tx, old, new JsonObject
        {
            ["sha256"] = hash, ["status"] = "rolled_back", ["reason"] = "agent_update_start_failed", ["version"] = "26.0.136"
        }, ct);
        Assert.Equal(("failed", "26.0.136"), await UpdateState());
        Assert.NotNull((await client.CheckInAsync(db, tx, old, ct))["agent_update"]);
        await using (var retry = await updates.DownloadAsync(db, tx, old, hash, ct))
            Assert.Equal(data.Length, retry.Length);
        Assert.Equal(("updating", "26.0.136"), await UpdateState());
        await updates.ReportAsync(db, tx, old, new JsonObject
        {
            ["sha256"] = hash, ["status"] = "updated", ["reason"] = null, ["version"] = "26.0.185"
        }, ct);
        Assert.Null((await client.CheckInAsync(db, tx, old, ct))["agent_update"]);
        Assert.Equal(("updated", "26.0.185"), await UpdateState());
        await tx.CommitAsync(ct);

        async Task<(string? State, string? RunningVersion)> UpdateState()
        {
            var inventory = await new AgentManagementService(audit).ListAgentsAsync(db, tx, old.Id.ToString("D"), "session:1", ct);
            var agent = inventory.GetProperty("items")[0];
            return (agent.GetProperty("update").GetProperty("status").GetString(), agent.GetProperty("agent_version").GetString());
        }

        await using (var policy = new NpgsqlCommand("update platform_settings set value='disabled',updated_by='session:1' where key='agents.automatic_update'", db))
            Assert.Equal(1, await policy.ExecuteNonQueryAsync(ct));
        await ShippedAgentUpdate.RegisterAsync(db, directory, audit, ct);
        await using (var policy = new NpgsqlCommand("select value from platform_settings where key='agents.automatic_update'", db))
            Assert.Equal("disabled", await policy.ExecuteScalarAsync(ct));

        await File.WriteAllBytesAsync(msi, "mismatched synthetic contents"u8.ToArray(), ct);
        await Assert.ThrowsAsync<AgentControlException>(() => ShippedAgentUpdate.RegisterAsync(db, directory, audit, ct));

        static AgentIdentity Identity() => new(Guid.NewGuid(), Guid.NewGuid(), new string('a', 64), "active");
    }
}
