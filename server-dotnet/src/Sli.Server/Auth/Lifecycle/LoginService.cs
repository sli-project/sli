using Npgsql;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Infrastructure;

namespace Sli.Server.Auth.Lifecycle;

public sealed class LoginService(IPostgresConnectionFactory connections, IPasswordCodec passwords,
    IAccountThrottle throttle, IAuthAudit audit, ISessionLifecycle sessions, AuthRequestPolicy policy) : ILoginService
{
    public async Task<LoginResult> LoginAsync(LoginCommand command, RequestIdentity identity, CancellationToken ct)
    {
        Principal? principal;
        try { principal = await AuthenticatePasswordAsync(command, ct); }
        catch (LoginThrottledException error)
        {
            await audit.WriteAsync(new("anonymous", null, "login", "throttled", identity.RemoteAddress), ct);
            return new(null, null, error.RetryAfterSeconds);
        }
        if (principal is null)
        {
            await audit.WriteAsync(new("anonymous", null, "login", "failed", identity.RemoteAddress), ct);
            return new(null, null);
        }
        // Deliberately separate commits: the Python route commits credential/throttle
        // updates, then the audit, then session issuance. A later failure cannot
        // roll back a previously committed successful authentication or audit.
        await audit.WriteAsync(new("session", principal.Id, "login", RemoteAddress: identity.RemoteAddress), ct);
        string token = await sessions.IssueAsync(principal, command.Remember, ct);
        return new(principal, token);
    }

    private async Task<Principal?> AuthenticatePasswordAsync(LoginCommand command, CancellationToken ct)
    {
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var attempt = await throttle.BeginAsync(transaction, command.Username, ct);
        await using var select = new NpgsqlCommand("""
            select id, username, password_hash, role, is_active, last_login_at
            from auth_users where lower(username)=lower(@username)
            """, connection, transaction);
        select.Parameters.AddWithValue("username", Strip(command.Username));
        long id = 0;
        string username = "", hash = "", role = "";
        bool active = false, neverLoggedIn = true;
        await using (var reader = await select.ExecuteReaderAsync(ct))
            if (await reader.ReadAsync(ct))
            {
                id = reader.GetInt64(0); username = reader.GetString(1); hash = reader.GetString(2);
                role = reader.GetString(3); active = reader.GetBoolean(4); neverLoggedIn = reader.IsDBNull(5);
            }
        if (!active || policy.OwnerSetup && username == "platform-owner" && neverLoggedIn
            || !passwords.Verify(hash, command.Password).Valid)
        {
            await attempt.FailAsync(ct);
            await transaction.CommitAsync(ct);
            return null;
        }
        if (passwords.NeedsRehash(hash))
        {
            await using var rehash = new NpgsqlCommand("update auth_users set password_hash=@hash, updated_at=now() where id=@id", connection, transaction);
            rehash.Parameters.AddWithValue("hash", passwords.Hash(command.Password));
            rehash.Parameters.AddWithValue("id", id);
            await rehash.ExecuteNonQueryAsync(ct);
        }
        await using var login = new NpgsqlCommand("update auth_users set previous_login_at=last_login_at, last_login_at=now() where id=@id", connection, transaction);
        login.Parameters.AddWithValue("id", id);
        await login.ExecuteNonQueryAsync(ct);
        await attempt.SucceedAsync(ct);
        await transaction.CommitAsync(ct);
        return new("session", id, role, Username: username);
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
