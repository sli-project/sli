using System.Text;
using Npgsql;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Infrastructure;

namespace Sli.Server.Auth.InitialOwner;

public sealed class InitialAdminPassword(IPostgresConnectionFactory connections, IPasswordCodec passwords,
    ICredentialTokens tokens, IAuthAudit audit, ISessionLifecycle sessions)
{
    internal const string HashPrefix = "initial-password:";
    private const string TokenPrefix = "initial.";
    internal const string ChangeApi = "/api/auth/change-initial-password";
    public const string ChangePage = "/login/change-password";

    internal static bool IsPending(string hash) => hash.StartsWith(HashPrefix, StringComparison.Ordinal);
    internal static bool IsRestricted(string? token) => token?.StartsWith(TokenPrefix, StringComparison.Ordinal) == true;
    internal static string RestrictedToken(string token) => TokenPrefix + token;
    // A NUL cannot appear in an HTTP session cookie.
    internal static string SessionDigest(ICredentialTokens tokens, string token) =>
        tokens.Digest(IsRestricted(token) ? "\0" + token : token);

    // Use the same cookie name to replace any earlier full session in this browser.
    internal static string? RequestToken(HttpContext context) =>
        context.Request.Cookies.TryGetValue("adlog_session", out string? token) && IsRestricted(token) ? token : null;

    internal async Task<bool> CanChangeAsync(string token, CancellationToken ct)
    {
        await using var connection = await connections.OpenAsync(ct);
        await using var command = SelectPending(connection, null, token);
        return await command.ExecuteScalarAsync(ct) is not null;
    }

    internal async Task<LoginResult> ChangeAsync(string token, string? password, string? repeat, string address, CancellationToken ct)
    {
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        // Serialize with root reset before reading the session. A reset can
        // replace a pending password with another pending password.
        await using var ownerLock = new NpgsqlCommand("""
            select u.id from auth_users u join access_platform_owners o on o.user_id=u.id
            where o.owner_key='primary' for update of u
            """, connection, transaction);
        if (await ownerLock.ExecuteScalarAsync(ct) is null) return new(null, null);
        await using var select = SelectPending(connection, transaction, token);
        Principal principal;
        string oldHash;
        await using (var reader = await select.ExecuteReaderAsync(ct))
        {
            if (!await reader.ReadAsync(ct)) return new(null, null);
            principal = new("session", reader.GetInt64(0), "admin", Username: reader.GetString(1));
            oldHash = reader.GetString(2)[HashPrefix.Length..];
        }
        if (password is null || password != repeat || password.Contains('\0')
            || password.EnumerateRunes().Take(4097).Count() is < 12 or > 4096)
            throw new AuthInputException("new_password_invalid", 400);
        if (passwords.Verify(oldHash, password).Valid)
            throw new AuthInputException("initial_password_reused", 400);

        string hash = passwords.Hash(password);
        await using var update = new NpgsqlCommand("""
            update auth_users set password_hash=@hash, updated_at=now(),
                previous_login_at=last_login_at, last_login_at=now() where id=@id;
            update auth_sessions set revoked_at=now() where user_id=@id and revoked_at is null;
            """, connection, transaction);
        update.Parameters.AddWithValue("hash", hash);
        update.Parameters.AddWithValue("id", principal.Id);
        await update.ExecuteNonQueryAsync(ct);
        await audit.AppendAsync(transaction, new("session", principal.Id, "initial_admin_password_changed", RemoteAddress: address), ct);
        await transaction.CommitAsync(CancellationToken.None);

        string? session = await sessions.IssueForPasswordAsync(principal, hash, false, ct);
        return new(principal, session);
    }

    private NpgsqlCommand SelectPending(NpgsqlConnection connection, NpgsqlTransaction? transaction, string token)
    {
        var command = new NpgsqlCommand("""
            select u.id,u.username,u.password_hash from auth_users u
            join access_platform_owners o on o.user_id=u.id and o.owner_key='primary'
            join auth_sessions s on s.user_id=u.id
            where u.is_active and u.role='admin' and starts_with(u.password_hash,@prefix)
              and s.token_hash=@digest and s.revoked_at is null and s.expires_at>now()
            """, connection, transaction);
        command.Parameters.AddWithValue("prefix", HashPrefix);
        command.Parameters.AddWithValue("digest", SessionDigest(tokens, token));
        return command;
    }
}
