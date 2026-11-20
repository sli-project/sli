using System.Text.Json;
using Npgsql;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class GpoWorkerHostDatabaseTests
{
    [Fact]
    public async Task ScopedWorkerRoleUsesTheSourceLockAndDoesNotPublishAnEmptyScan()
    {
        var ct = TestContext.Current.CancellationToken;
        var binding = OwnedDatabaseBinding.FromEnvironment();
        Assert.Equal("6a13bcc8-3cba-4ee1-85ce-5808480a9e21",binding.RunId.ToString("D"));
        string path = Environment.GetEnvironmentVariable("SLI_GPO_HOST_SECRET") ?? throw new InvalidOperationException();
        using var secret = JsonDocument.Parse(await File.ReadAllBytesAsync(path,ct));
        string username = secret.RootElement.GetProperty("username").GetString()!;
        string password = secret.RootElement.GetProperty("password").GetString()!;
        Assert.Equal("sli_gpo_7395d21260b2447493643097d1712aba",username);
        await using var fixture = await SyntheticDatabase.BorrowAsync(binding,ct);
        await using var admin = await fixture.OpenConnectionAsync(ct); // source adlog_user, not owner
        await using (var pre = new NpgsqlCommand("select current_user,(select count(*) from sli_agent_snapshot_cycles where module_id='sli.gpo-snapshot' and (transport_state='pending' or publication_state='pending'))",admin))
        await using (var r = await pre.ExecuteReaderAsync(ct))
        { Assert.True(await r.ReadAsync(ct)); Assert.Equal("adlog_user",r.GetString(0)); Assert.Equal(0L,r.GetInt64(1)); }
        var connection = new NpgsqlConnectionStringBuilder { Host="127.0.0.1",Port=60872,Database="sli_oracle",Username=username,Password=password,SslMode=SslMode.Disable,Pooling=false };
        await using (var worker = new NpgsqlConnection(connection.ConnectionString))
        {
            await worker.OpenAsync(ct);
            await using (var role = new NpgsqlCommand("set role adlog_context_worker",worker)) await role.ExecuteNonQueryAsync(ct);
            await using var check = new NpgsqlCommand("select session_user,current_user",worker);
            await using var reader = await check.ExecuteReaderAsync(ct);
            Assert.True(await reader.ReadAsync(ct)); Assert.Equal(username,reader.GetString(0)); Assert.Equal("adlog_context_worker",reader.GetString(1));
        }
        string? oldDsn=Environment.GetEnvironmentVariable("ADLOG_AD_CONTEXT_WORKER_DSN"), oldPass=Environment.GetEnvironmentVariable("ADLOG_AD_CONTEXT_WORKER_PASSWORD");
        try
        {
            Environment.SetEnvironmentVariable("ADLOG_AD_CONTEXT_WORKER_DSN",$"host=127.0.0.1 port=60872 dbname=sli_oracle user={username} sslmode=disable");
            Environment.SetEnvironmentVariable("ADLOG_AD_CONTEXT_WORKER_PASSWORD",password);
            await using (var held = new NpgsqlCommand("select pg_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))",admin)) await held.ExecuteScalarAsync(ct);
            try { Assert.Equal(9,await GpoWorkerCommand.RunAsync(["--once"])); }
            finally { await using var unlock = new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_post_collection_process'))",admin); await unlock.ExecuteScalarAsync(ct); }
            Assert.Equal(0,await GpoWorkerCommand.RunAsync(["--once"]));
            await using var checkLock = new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))",admin);
            Assert.Equal(true,await checkLock.ExecuteScalarAsync(ct));
            await using var release = new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_post_collection_process'))",admin);
            Assert.Equal(true,await release.ExecuteScalarAsync(ct));
        }
        finally
        {
            Environment.SetEnvironmentVariable("ADLOG_AD_CONTEXT_WORKER_DSN",oldDsn);
            Environment.SetEnvironmentVariable("ADLOG_AD_CONTEXT_WORKER_PASSWORD",oldPass);
        }
    }
}

public sealed class GpoRetainedReadOnlyTests
{
    [Fact]
    public async Task PreviouslyRetainedWorkerEvidenceIsUnchanged()
    {
        var ct = TestContext.Current.CancellationToken;
        string path = Environment.GetEnvironmentVariable("SLI_C3_OWN_IDS") ?? throw new InvalidOperationException();
        using var ids = JsonDocument.Parse(await File.ReadAllBytesAsync(path,ct));
        Guid agent = ids.RootElement.GetProperty("agent").GetGuid(), packet = ids.RootElement.GetProperty("packetId").GetGuid(), pending = ids.RootElement.GetProperty("pendingId").GetGuid();
        await using var fixture = await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        await using var db = await fixture.OpenConnectionAsync(ct);
        await using var query = new NpgsqlCommand("""
            select (select count(*) from sli_agent_packet_inbox where packet_id=@packet and imported_at is not null),
                   (select count(*) from sli_agent_packet_inbox where packet_id=@pending and imported_at is null),
                   (select count(*) from sli_plugin_workstations.observations where agent_key=@agent)
            """,db);
        query.Parameters.AddWithValue("packet",packet); query.Parameters.AddWithValue("pending",pending); query.Parameters.AddWithValue("agent",agent.ToString("D"));
        await using var reader = await query.ExecuteReaderAsync(ct);
        Assert.True(await reader.ReadAsync(ct)); Assert.Equal(1L,reader.GetInt64(0)); Assert.Equal(1L,reader.GetInt64(1)); Assert.Equal(1L,reader.GetInt64(2));
    }
}
