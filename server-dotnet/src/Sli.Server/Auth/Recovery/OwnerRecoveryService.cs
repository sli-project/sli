using Npgsql;
using System.Text;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Infrastructure;

namespace Sli.Server.Auth.Recovery;

public sealed class OwnerRecoveryService(IPostgresConnectionFactory connections, IPasswordCodec passwords,
    ICredentialTokens tokens, IAuthAudit audit, ISessionLifecycle sessions, OwnerRecoveryAdmission admission,
    OwnerRecoveryTerminal terminal) : IOwnerRecoveryService
{
    private sealed record VerifiedCredential(Principal Principal, string Hash);

    public async Task<LoginResult> LoginAsync(LoginCommand command, string recoveryCode, RequestIdentity identity, CancellationToken ct)
    {
        VerifiedCredential? credential;
        try
        {
            credential = await admission.VerifyAsync(identity.RemoteAddress,
                () => AuthenticateAsync(command, recoveryCode, identity.RemoteAddress, ct));
        }
        catch (LoginThrottledException error)
        {
            await audit.WriteAsync(new("anonymous", null, "owner_recovery_login", "throttled", identity.RemoteAddress), ct);
            return new(null, null, error.RetryAfterSeconds);
        }
        if (credential is null)
        {
            await audit.WriteAsync(new("anonymous", null, "login", "failed", identity.RemoteAddress), ct);
            return new(null, null);
        }
        // Credential consumption commits before the route audit, which commits before session issuance.
        var (principal, hash) = credential;
        await audit.WriteAsync(new("session", principal.Id, "login", RemoteAddress: identity.RemoteAddress), ct);
        string? token = await sessions.IssueForPasswordAsync(principal, hash, command.Remember, ct);
        return new(principal, token);
    }

    private async Task<VerifiedCredential?> AuthenticateAsync(LoginCommand command, string code, string address, CancellationToken ct)
    {
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var select = new NpgsqlCommand("""
            select u.id,u.username,u.password_hash,u.role from auth_users u
            where lower(u.username)=lower(@username) and u.is_active=true
              and exists(select 1 from access_platform_owners o where o.user_id=u.id) for update of u
            """, connection, transaction);
        select.Parameters.AddWithValue("username", Strip(command.Username));
        long id = 0;
        string username = "", hash = "", role = "";
        await using (var reader = await select.ExecuteReaderAsync(ct))
            if (await reader.ReadAsync(ct))
            {
                id = reader.GetInt64(0); username = reader.GetString(1);
                hash = reader.GetString(2); role = reader.GetString(3);
            }
        Principal? principal = null;
        if (id != 0 && code.Length is > 0 && code.EnumerateRunes().Take(129).Count() <= 128)
        {
            string digest = tokens.Digest(code);
            await using var check = new NpgsqlCommand("""
                select user_id from auth_owner_recovery
                where user_id=@id and code_hash=@hash and expires_at>clock_timestamp()
                """, connection, transaction);
            check.Parameters.AddWithValue("id", id);
            check.Parameters.AddWithValue("hash", digest);
            if (await check.ExecuteScalarAsync(ct) is not null && passwords.Verify(hash, command.Password).Valid)
            {
                // DB wall clock must be sampled again after potentially slow Argon2, never transaction NOW().
                await using var consume = new NpgsqlCommand("""
                    delete from auth_owner_recovery
                    where user_id=@id and code_hash=@hash and expires_at>clock_timestamp() returning user_id
                    """, connection, transaction);
                consume.Parameters.AddWithValue("id", id);
                consume.Parameters.AddWithValue("hash", digest);
                if (await consume.ExecuteScalarAsync(ct) is not null)
                {
                    await using var update = new NpgsqlCommand("""
                        update auth_users set previous_login_at=last_login_at,last_login_at=now() where id=@id
                        """, connection, transaction);
                    update.Parameters.AddWithValue("id", id);
                    await update.ExecuteNonQueryAsync(ct);
                    principal = new("session", id, role, Username: username);
                }
            }
        }
        await audit.AppendAsync(transaction, new(principal is null ? "anonymous" : "session", principal?.Id,
            "owner_recovery_login", principal is null ? "failed" : "ok", address), ct);
        await transaction.CommitAsync(ct);
        return principal is null ? null : new(principal, hash);
    }

    // No HTTP endpoint calls issuance; root and terminal are verified here as well as by the CLI adapter.
    internal async Task<string> IssueAsync(string username, CancellationToken ct)
    {
        terminal.RequireRootInteractiveTerminal();
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var select = new NpgsqlCommand("""
            select u.id from auth_users u where lower(u.username)=lower(@username) and u.is_active=true
              and exists(select 1 from access_platform_owners o where o.user_id=u.id)
            """, connection, transaction);
        select.Parameters.AddWithValue("username", Strip(username));
        object? result = await select.ExecuteScalarAsync(ct);
        long? id = result is null ? null : Convert.ToInt64(result);
        string? code = null;
        if (id is not null)
        {
            code = tokens.NewSessionToken();
            await using var insert = new NpgsqlCommand("""
                insert into auth_owner_recovery(user_id,code_hash,expires_at)
                values(@id,@hash,clock_timestamp()+interval '10 minutes')
                on conflict(user_id) do update set code_hash=excluded.code_hash,expires_at=excluded.expires_at
                """, connection, transaction);
            insert.Parameters.AddWithValue("id", id.Value);
            insert.Parameters.AddWithValue("hash", tokens.Digest(code));
            await insert.ExecuteNonQueryAsync(ct);
        }
        await audit.AppendAsync(transaction, new("local_operator", null,
            id is null ? "owner_recovery_issued" : $"owner_recovery_issued:{id}", id is null ? "failed" : "ok"), ct);
        await transaction.CommitAsync(ct);
        return code ?? throw new InvalidOperationException("active_platform_owner_required");
    }

    private static string Strip(string value)
    {
        int start = 0, end = value.Length;
        static bool Space(char c) => char.IsWhiteSpace(c) || c is >= '\u001c' and <= '\u001f';
        while (start < end && Space(value[start])) start++;
        while (end > start && Space(value[end - 1])) end--;
        return value[start..end];
    }
}
