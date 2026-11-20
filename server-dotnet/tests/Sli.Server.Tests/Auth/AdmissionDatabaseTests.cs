using Npgsql;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Auth;

public sealed class AdmissionDatabaseTests
{
    private sealed class Connections(SyntheticDatabase database) : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => database.OpenConnectionAsync(ct);
    }

    [Fact]
    public async Task ActualTransactionsPreserveBudgetLockBackoffResetRollbackAndAudit()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var database = await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(), ct);
        var throttle = new AccountThrottle();
        string marker = "netadmission_" + Guid.NewGuid().ToString("N");
        string key = AccountThrottle.AccountKey(marker), otherKey = AccountThrottle.AccountKey(marker + "_other");
        string auditAction = "user_created:1:" + marker;
        try
        {
            for (int n = 1; n <= 9; n++)
            {
                await using var connection = await database.OpenConnectionAsync(ct);
                if (n > 5) await Execute(connection, "update auth_login_throttle set blocked_until=clock_timestamp()-interval '1 second' where account_key=$1", key, ct);
                await using (var tx = await connection.BeginTransactionAsync(ct))
                {
                    await using var attempt = await throttle.BeginAsync(tx, " " + marker.ToUpperInvariant() + " ", ct);
                    await attempt.FailAsync(ct);
                    await tx.CommitAsync(ct);
                }
                await using var read = new NpgsqlCommand("select failures,extract(epoch from(blocked_until-clock_timestamp())) from auth_login_throttle where account_key=$1", connection);
                read.Parameters.AddWithValue(key);
                await using (var reader = await read.ExecuteReaderAsync(ct))
                {
                    Assert.True(await reader.ReadAsync(ct));
                    Assert.Equal(n, reader.GetInt32(0));
                    if (n < 5) Assert.True(reader.IsDBNull(1));
                    else Assert.InRange(reader.GetDecimal(1), Math.Min(300, 30 * (1 << (n - 5))) - 5, Math.Min(300, 30 * (1 << (n - 5))));
                }
                if (n >= 5)
                {
                    await using var tx = await connection.BeginTransactionAsync(ct);
                    var denied = await Assert.ThrowsAsync<LoginThrottledException>(() => throttle.BeginAsync(tx, marker, ct));
                    Assert.InRange(denied.RetryAfterSeconds, Math.Min(300, 30 * (1 << (n - 5))) - 5, Math.Min(300, 30 * (1 << (n - 5))));
                }
            }
            await using (var connection = await database.OpenConnectionAsync(ct))
            {
                await Execute(connection, "update auth_login_throttle set blocked_until=clock_timestamp()-interval '1 second' where account_key=$1", key, ct);
                await using var tx = await connection.BeginTransactionAsync(ct);
                await using var attempt = await throttle.BeginAsync(tx, marker, ct);
                await attempt.SucceedAsync(ct);
                await tx.CommitAsync(ct);
                Assert.Equal(0L, await Count(connection, key, ct));
            }
            // The advisory transaction lock rejects another connection immediately; another account proceeds.
            await using (var first = await database.OpenConnectionAsync(ct))
            await using (var second = await database.OpenConnectionAsync(ct))
            await using (var tx1 = await first.BeginTransactionAsync(ct))
            await using (var tx2 = await second.BeginTransactionAsync(ct))
            {
                await using var held = await throttle.BeginAsync(tx1, marker, ct);
                var denied = await Assert.ThrowsAsync<LoginThrottledException>(() => throttle.BeginAsync(tx2, marker.ToUpperInvariant(), ct));
                Assert.Equal(1, denied.RetryAfterSeconds);
                await using var independent = await throttle.BeginAsync(tx2, marker + "_other", ct);
                await independent.FailAsync(ct);
                await tx2.CommitAsync(ct);
                await held.FailAsync(ct);
                await tx1.RollbackAsync(ct);
            }
            await using (var connection = await database.OpenConnectionAsync(ct))
            {
                Assert.Equal(0L, await Count(connection, key, ct));
                Assert.Equal(1L, await Count(connection, otherKey, ct));
                // Expired windows reset to one failure using the DB clock, without waiting 900 seconds.
                await Execute(connection, "update auth_login_throttle set failures=9,window_started_at=clock_timestamp()-interval '901 seconds',blocked_until=null where account_key=$1", otherKey, ct);
                await using var tx = await connection.BeginTransactionAsync(ct);
                await using var attempt = await throttle.BeginAsync(tx, marker + "_other", ct);
                await attempt.FailAsync(ct);
                await tx.CommitAsync(ct);
                await using var read = new NpgsqlCommand("select failures from auth_login_throttle where account_key=$1", connection);
                read.Parameters.AddWithValue(otherKey);
                Assert.Equal(1, await read.ExecuteScalarAsync(ct));
            }
            // Exercise the real 64-row cleanup limit in a transaction that is always rolled back.
            // Make only owned synthetic rows older than every existing row so the check is deterministic.
            await using (var connection = await database.OpenConnectionAsync(ct))
            await using (var tx = await connection.BeginTransactionAsync(ct))
            {
                string[] cleanupKeys = Enumerable.Range(0, 70).Select(i => AccountThrottle.AccountKey(marker + "_cleanup_" + i)).ToArray();
                await using (var insert = new NpgsqlCommand("""
                    insert into auth_login_throttle(account_key,failures,window_started_at)
                    select k,1,(select least(coalesce(min(window_started_at),clock_timestamp()),clock_timestamp())-interval '901 seconds' from auth_login_throttle)
                    from unnest($1::text[]) as k
                    """, connection, tx))
                {
                    insert.Parameters.AddWithValue(cleanupKeys);
                    await insert.ExecuteNonQueryAsync(ct);
                }
                await using var attempt = await throttle.BeginAsync(tx, marker, ct);
                await attempt.FailAsync(ct);
                await using (var count = new NpgsqlCommand("select count(*) from auth_login_throttle where account_key=any($1)", connection, tx))
                {
                    count.Parameters.AddWithValue(cleanupKeys);
                    Assert.Equal(6L, await count.ExecuteScalarAsync(ct));
                }
                await tx.RollbackAsync(ct);
            }
            var audit = new AuthAudit(new Connections(database));
            var evt = new AuthAuditEvent("anonymous", null, auditAction, RemoteAddress: "192.0.2.1");
            await audit.WriteAsync(evt, ct);
            await using (var connection = await database.OpenConnectionAsync(ct))
            {
                await using (var tx = await connection.BeginTransactionAsync(ct))
                {
                    await audit.AppendAsync(tx, evt, ct);
                    await tx.RollbackAsync(ct);
                }
                await using var count = new NpgsqlCommand("select count(*) from auth_audit where action=$1 and actor_type='anonymous' and actor_id is null and outcome='ok' and remote_address='192.0.2.1'", connection);
                count.Parameters.AddWithValue(auditAction);
                Assert.Equal(1L, await count.ExecuteScalarAsync(ct));
            }
            // A rejected mirror action rolls back the auth row as well; errors never become successful audit.
            await Assert.ThrowsAsync<InvalidOperationException>(() => audit.WriteAsync(evt with { Action = "unsupported:" + marker }, ct));
        }
        finally
        {
            await using var connection = await database.OpenConnectionAsync(ct);
            await Execute(connection, "delete from auth_login_throttle where account_key=$1", key, ct);
            await Execute(connection, "delete from auth_login_throttle where account_key=$1", otherKey, ct);
            await Execute(connection, "delete from auth_audit where action=$1", auditAction, ct);
            await Execute(connection, "delete from auth_audit where action=$1", "unsupported:" + marker, ct);
        }
    }

    private static async Task Execute(NpgsqlConnection connection, string sql, string key, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        command.Parameters.AddWithValue(key);
        await command.ExecuteNonQueryAsync(ct);
    }

    private static async Task<long> Count(NpgsqlConnection connection, string key, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("select count(*) from auth_login_throttle where account_key=$1", connection);
        command.Parameters.AddWithValue(key);
        return (long)(await command.ExecuteScalarAsync(ct))!;
    }
}
