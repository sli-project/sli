using System.Text.Json;
using Npgsql;
using Sli.Server.Agents.Consumer;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Agents.M4;

public sealed class AgentImportBorrowedSessionDatabaseTests
{
    private sealed class NoExtraConnection : IPostgresConnectionFactory
    { public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => throw new InvalidOperationException("Borrowed session must be used"); }

    [Fact]
    public async Task BorrowedLockSessionOwnsPollAndDisconnectRollsBackItsTransaction()
    {
        var ct = TestContext.Current.CancellationToken;
        var binding = OwnedDatabaseBinding.FromEnvironment();
        Assert.Equal("6a13bcc8-3cba-4ee1-85ce-5808480a9e21", binding.RunId.ToString("D"));
        string evidence = Environment.GetEnvironmentVariable("SLI_WORKER_EVIDENCE_DIR") ?? throw new InvalidOperationException();
        using var ids = JsonDocument.Parse(await File.ReadAllBytesAsync(Path.Combine(evidence, "own-ids.json"), ct));
        Guid pending = ids.RootElement.GetProperty("pendingId").GetGuid();
        await using var fixture = await SyntheticDatabase.BorrowAsync(binding, ct);
        await using var observer = await fixture.OpenConnectionAsync(ct);
        var session = await fixture.OpenConnectionAsync(ct);
        await using (var acquire = new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))", session))
            Assert.Equal(true, await acquire.ExecuteScalarAsync(ct));
        var consumer = new AgentWorkstationInboxConsumer(new NoExtraConnection());
        var result = await consumer.RunOnceAsync(session, 16, ct);
        Assert.True(result.PendingReasons.ContainsKey("agent_storage_unavailable"));
        Assert.Equal(System.Data.ConnectionState.Open, session.State);
        await using (var blocked = new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))", observer))
            Assert.Equal(false, await blocked.ExecuteScalarAsync(ct));

        // A lost physical session must discard in-flight progress and release its advisory lock.
        await using var tx = await session.BeginTransactionAsync(ct);
        await using (var mark = new NpgsqlCommand("update sli_agent_packet_inbox set imported_at=clock_timestamp() where packet_id=@id and imported_at is null", session, tx))
        { mark.Parameters.AddWithValue("id", pending); Assert.Equal(1, await mark.ExecuteNonQueryAsync(ct)); }
        await session.DisposeAsync();
        await using (var verify = new NpgsqlCommand("select imported_at is null from sli_agent_packet_inbox where packet_id=@id", observer))
        { verify.Parameters.AddWithValue("id",pending); Assert.Equal(true,await verify.ExecuteScalarAsync(ct)); }
        await using (var released = new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))", observer))
            Assert.Equal(true, await released.ExecuteScalarAsync(ct));
        await using (var unlock = new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_post_collection_process'))", observer))
            Assert.Equal(true, await unlock.ExecuteScalarAsync(ct));
    }
}
