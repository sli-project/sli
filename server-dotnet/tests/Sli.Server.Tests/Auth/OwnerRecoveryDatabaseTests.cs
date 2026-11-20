using Npgsql;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Auth.Recovery;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Auth;

[Collection("Owned owner recovery")]
public sealed class OwnerRecoveryDatabaseTests
{
    private const string Password = "Owned-Recovery-Synthetic-Password-🔐";

    private sealed class Connections(SyntheticDatabase database) : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => database.OpenConnectionAsync(ct);
    }

    private sealed class ObservedPasswords : IPasswordCodec
    {
        private readonly PasswordCodec real = new();
        public int Calls;
        public Action? AfterVerify;
        public PasswordVerification Verify(string encoded, string password)
        {
            Interlocked.Increment(ref Calls);
            var result = real.Verify(encoded, password);
            AfterVerify?.Invoke();
            return result;
        }
        public string Hash(string password) => real.Hash(password);
        public bool NeedsRehash(string encoded) => real.NeedsRehash(encoded);
    }

    private sealed class FailingSessions : ISessionLifecycle
    {
        public Task<string?> IssueForPasswordAsync(Sli.Server.Auth.Principal principal, string hash, bool remember, CancellationToken ct) =>
            throw new InvalidOperationException("synthetic_session_failure");
        public Task RevokeAsync(string? token, CancellationToken ct) => throw new NotSupportedException();
    }

    private sealed class FailingAudit(IAuthAudit real, bool duringCredentialTransaction) : IAuthAudit
    {
        public Task WriteAsync(AuthAuditEvent entry, CancellationToken ct) => duringCredentialTransaction
            ? real.WriteAsync(entry, ct) : throw new InvalidOperationException("synthetic_route_audit_failure");
        public Task AppendAsync(NpgsqlTransaction transaction, AuthAuditEvent entry, CancellationToken ct) => duringCredentialTransaction
            ? throw new InvalidOperationException("synthetic_credential_audit_failure") : real.AppendAsync(transaction, entry, ct);
    }

    [Fact]
    public async Task ReviewedRecoveryAuditMappingsAcceptOnlyDeclaredActionForms()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var database = await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(), ct);
        var audit = new AuthAudit(new Connections(database));
        await using var connection = await database.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        foreach (var entry in new[]
        {
            new AuthAuditEvent("anonymous", null, "owner_recovery_login", "failed"),
            new AuthAuditEvent("anonymous", null, "owner_recovery_login", "throttled"),
            new AuthAuditEvent("local_operator", null, "owner_recovery_issued", "failed"),
            new AuthAuditEvent("local_operator", null, "owner_recovery_issued:12345")
        }) await audit.AppendAsync(transaction, entry, ct);
        foreach (string action in new[] { "unknown_recovery_action", "owner_recovery_login:12345", "owner_recovery_issued:0", "owner_recovery_issued:-1", "owner_recovery_issued:1:extra" })
        {
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() => audit.AppendAsync(transaction,
                new("local_operator", null, action), ct));
            Assert.StartsWith("administrative_activity_auth_", error.Message);
        }
        await transaction.RollbackAsync(ct);
    }

    [Fact]
    public async Task RealPostgresRecoveryPreservesAccountBlockSingleUseExpiryAndConcurrentWinner()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var database = await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(), ct);
        // A privileged fixture controller creates ONLY this invocation's owner. Runtime remains adlog_user.
        string username = Environment.GetEnvironmentVariable("SLI_RECOVERY_FIXTURE_USERNAME")
            ?? throw new InvalidOperationException("Explicit owned recovery fixture required");
        long id = long.Parse(Environment.GetEnvironmentVariable("SLI_RECOVERY_FIXTURE_USER_ID")
            ?? throw new InvalidOperationException("Explicit owned recovery fixture required"));
        Assert.StartsWith("netrecovery_", username);
        var connections = new Connections(database);
        var tokens = new CredentialTokens();
        var passwords = new ObservedPasswords();
        var audit = new AuthAudit(connections);
        var sessions = new SessionLifecycle(connections, tokens, TimeProvider.System);
        var service = new OwnerRecoveryService(connections, passwords, tokens, audit, sessions,
            new OwnerRecoveryAdmission(TimeProvider.System), new OwnerRecoveryTerminal());
        string accountKey = AccountThrottle.AccountKey(username);
        long nonOwnerId = 0;
        await using (var connection = await database.OpenConnectionAsync(ct))
        {
            await using var check = new NpgsqlCommand("""
                select u.password_hash from auth_users u join access_platform_owners o on o.user_id=u.id
                where u.id=@id and u.username=@name and o.owner_key=@name and u.is_active=true
                """, connection);
            check.Parameters.AddWithValue("id", id); check.Parameters.AddWithValue("name", username);
            string? hash = await check.ExecuteScalarAsync(ct) as string;
            Assert.True(hash is not null && new PasswordCodec().Verify(hash, Password).Valid, "Owned fixture password mismatch");
        }
        int address = 20;
        Task<LoginResult> Login(string code, string? password = null) => service.LoginAsync(new(username, password ?? Password, false),
            code, new("192.0.2." + Interlocked.Increment(ref address)), ct);
        async Task<string> SeedCode(double expirySeconds = 600)
        {
            string code = tokens.NewSessionToken();
            await using var connection = await database.OpenConnectionAsync(ct);
            await using var seed = new NpgsqlCommand("""
                insert into auth_owner_recovery(user_id,code_hash,expires_at)
                values(@id,@hash,clock_timestamp()+@seconds*interval '1 second')
                on conflict(user_id) do update set code_hash=excluded.code_hash,expires_at=excluded.expires_at
                """, connection);
            seed.Parameters.AddWithValue("id", id); seed.Parameters.AddWithValue("hash", tokens.Digest(code));
            seed.Parameters.AddWithValue("seconds", expirySeconds);
            await seed.ExecuteNonQueryAsync(ct);
            return code;
        }
        async Task<bool> HasCode(string code)
        {
            await using var connection = await database.OpenConnectionAsync(ct);
            await using var query = new NpgsqlCommand("select exists(select 1 from auth_owner_recovery where user_id=@id and code_hash=@hash)", connection);
            query.Parameters.AddWithValue("id", id); query.Parameters.AddWithValue("hash", tokens.Digest(code));
            return (bool)(await query.ExecuteScalarAsync(ct))!;
        }
        try
        {
            string first = await SeedCode();
            Assert.False((await Login("guess")).Succeeded);
            Assert.False((await Login("")).Succeeded);
            Assert.False((await Login(new string('x', 129))).Succeeded);
            Assert.Equal(0, passwords.Calls);
            Assert.True(await HasCode(first));
            await using (var connection = await database.OpenConnectionAsync(ct))
            {
                await using var disabled = new NpgsqlCommand("update auth_users set is_active=false where id=@id and username=@name", connection);
                disabled.Parameters.AddWithValue("id", id); disabled.Parameters.AddWithValue("name", username);
                Assert.Equal(1, await disabled.ExecuteNonQueryAsync(ct));
            }
            try
            {
                Assert.False((await Login(first)).Succeeded);
                Assert.Equal(0, passwords.Calls);
                Assert.True(await HasCode(first));
            }
            finally
            {
                await using var connection = await database.OpenConnectionAsync(ct);
                await using var activate = new NpgsqlCommand("update auth_users set is_active=true where id=@id and username=@name", connection);
                activate.Parameters.AddWithValue("id", id); activate.Parameters.AddWithValue("name", username);
                Assert.Equal(1, await activate.ExecuteNonQueryAsync(ct));
            }
            await using (var connection = await database.OpenConnectionAsync(ct))
            {
                await using var nonOwner = new NpgsqlCommand("""
                    insert into auth_users(username,password_hash,role,is_active)
                    select @name,password_hash,'admin',true from auth_users where id=@id returning id
                    """, connection);
                nonOwner.Parameters.AddWithValue("name", username + "_other"); nonOwner.Parameters.AddWithValue("id", id);
                nonOwnerId = Convert.ToInt64(await nonOwner.ExecuteScalarAsync(ct));
            }
            Assert.False((await service.LoginAsync(new(username + "_other", Password, false), first, new("192.0.2.19"), ct)).Succeeded);
            Assert.Equal(0, passwords.Calls);
            Assert.True(await HasCode(first));
            Assert.False((await Login(first, "incorrect-private-synthetic")).Succeeded);
            Assert.Equal(1, passwords.Calls);
            Assert.True(await HasCode(first));
            string expired = await SeedCode(-1);
            Assert.False((await Login(expired)).Succeeded);
            Assert.Equal(1, passwords.Calls);
            Assert.True(await HasCode(expired));

            // Seed a durable account block through the actual production throttle.
            var throttle = new AccountThrottle();
            for (int i = 0; i < 5; i++)
            {
                await using var connection = await database.OpenConnectionAsync(ct);
                await using var transaction = await connection.BeginTransactionAsync(ct);
                await using var attempt = await throttle.BeginAsync(transaction, username, ct);
                await attempt.FailAsync(ct);
                await transaction.CommitAsync(ct);
            }
            async Task AssertStillBlocked()
            {
                await using var connection = await database.OpenConnectionAsync(ct);
                await using var transaction = await connection.BeginTransactionAsync(ct);
                await Assert.ThrowsAsync<LoginThrottledException>(() => throttle.BeginAsync(transaction, username, ct));
                await using var query = new NpgsqlCommand("select failures from auth_login_throttle where account_key=@key", connection, transaction);
                query.Parameters.AddWithValue("key", accountKey);
                Assert.Equal(5, await query.ExecuteScalarAsync(ct));
            }
            await AssertStillBlocked();
            string valid = await SeedCode();
            var result = await Login(valid);
            Assert.True(result.Succeeded);
            Assert.Equal(id, result.Principal!.Id);
            Assert.False(await HasCode(valid));
            await AssertStillBlocked();
            Assert.False((await Login(valid)).Succeeded);

            // Synchronize expiry only after the cheap lookup and real hash verification have run.
            // The new expiry is after this transaction's start, so NOW() would incorrectly consume.
            string nearExpiry = await SeedCode();
            int beforeExpiryCheck = passwords.Calls;
            passwords.AfterVerify = () =>
            {
                using var connection = database.OpenConnectionAsync(ct).GetAwaiter().GetResult();
                using var expire = new NpgsqlCommand("""
                    update auth_owner_recovery set expires_at=clock_timestamp()
                    where user_id=@id and code_hash=@hash returning user_id
                    """, connection);
                expire.Parameters.AddWithValue("id", id); expire.Parameters.AddWithValue("hash", tokens.Digest(nearExpiry));
                Assert.Equal(id, expire.ExecuteScalar());
            };
            Assert.False((await Login(nearExpiry)).Succeeded);
            passwords.AfterVerify = null;
            Assert.Equal(beforeExpiryCheck + 1, passwords.Calls);
            Assert.True(await HasCode(nearExpiry));

            string raceCode = await SeedCode();
            int beforeRace = passwords.Calls;
            using var barrier = new Barrier(2);
            passwords.AfterVerify = () => Assert.True(barrier.SignalAndWait(TimeSpan.FromSeconds(10)), "Concurrent credential checks failed to overlap");
            var race = await Task.WhenAll(Task.Run(() => Login(raceCode), ct), Task.Run(() => Login(raceCode), ct));
            passwords.AfterVerify = null;
            Assert.Equal(beforeRace + 2, passwords.Calls);
            Assert.Single(race, r => r.Succeeded);
            Assert.False(await HasCode(raceCode));
            await AssertStillBlocked();

            // Reissue replaces the digest atomically; predecessor stays unusable.
            string predecessor = await SeedCode(), replacement = await SeedCode();
            Assert.False((await Login(predecessor)).Succeeded);
            Assert.True(await HasCode(replacement));

            OwnerRecoveryService With(IAuthAudit useAudit, ISessionLifecycle useSessions) => new(connections, passwords, tokens,
                useAudit, useSessions, new OwnerRecoveryAdmission(TimeProvider.System), new OwnerRecoveryTerminal());
            var failedCredentialAudit = With(new FailingAudit(audit, true), sessions);
            await Assert.ThrowsAsync<InvalidOperationException>(() => failedCredentialAudit.LoginAsync(new(username, Password, false),
                replacement, new("192.0.2.80"), ct));
            Assert.True(await HasCode(replacement)); // Credential audit failure rolls back conditional DELETE.

            var failedRouteAudit = With(new FailingAudit(audit, false), sessions);
            await Assert.ThrowsAsync<InvalidOperationException>(() => failedRouteAudit.LoginAsync(new(username, Password, false),
                replacement, new("192.0.2.81"), ct));
            Assert.False(await HasCode(replacement)); // Recovery commit survives later route audit failure.

            string sessionFailureCode = await SeedCode();
            var failedSession = With(audit, new FailingSessions());
            await Assert.ThrowsAsync<InvalidOperationException>(() => failedSession.LoginAsync(new(username, Password, false),
                sessionFailureCode, new("192.0.2.82"), ct));
            Assert.False(await HasCode(sessionFailureCode)); // Both audits commit before session issuance.
            await using (var connection = await database.OpenConnectionAsync(ct))
            {
                await using var check = new NpgsqlCommand("""
                    select count(*) from auth_audit where actor_type='session' and actor_id=@id
                      and outcome='ok' and remote_address='192.0.2.82' and action in ('owner_recovery_login','login')
                    """, connection);
                check.Parameters.AddWithValue("id", id);
                Assert.Equal(2L, await check.ExecuteScalarAsync(ct));
            }
            await AssertStillBlocked();
        }
        finally
        {
            // Controller retains ownership of owner/user rows and removes them after the test exits.
            await using var connection = await database.OpenConnectionAsync(ct);
            await using var cleanup = new NpgsqlCommand("""
                delete from auth_sessions where user_id=@id;
                delete from auth_owner_recovery where user_id=@id;
                delete from auth_login_throttle where account_key=@key;
                delete from auth_audit where actor_type='session' and actor_id=@id;
                delete from auth_users where id=@other and username=@othername
                """, connection);
            cleanup.Parameters.AddWithValue("id", id); cleanup.Parameters.AddWithValue("key", accountKey);
            cleanup.Parameters.AddWithValue("other", nonOwnerId); cleanup.Parameters.AddWithValue("othername", username + "_other");
            await cleanup.ExecuteNonQueryAsync(ct);
        }
    }
}
