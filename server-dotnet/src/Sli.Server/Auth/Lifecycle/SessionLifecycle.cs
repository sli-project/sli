using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth.InitialOwner;
using Sli.Server.Infrastructure;

namespace Sli.Server.Auth.Lifecycle;

public interface ISessionLifecycle
{
    Task<string?> IssueForPasswordAsync(Principal principal, string hash, bool remember, CancellationToken ct);
    Task RevokeAsync(string? token, CancellationToken ct);
}

public sealed class SessionLifecycle(IPostgresConnectionFactory connections, ICredentialTokens tokens,
    TimeProvider time, SessionAccessFactsCache? accessCache = null) : ISessionLifecycle
{
    public async Task<string> IssueAsync(Principal principal, bool remember, CancellationToken ct) =>
        await IssueCoreAsync(principal, null, remember, ct) ?? throw new InvalidOperationException("session_user_unavailable");

    public Task<string?> IssueForPasswordAsync(Principal principal, string hash, bool remember, CancellationToken ct) =>
        IssueCoreAsync(principal, hash, remember, ct);

    private async Task<string?> IssueCoreAsync(Principal principal, string? hash, bool remember, CancellationToken ct)
    {
        string token = tokens.NewSessionToken();
        bool pending = hash is not null && InitialAdminPassword.IsPending(hash);
        if (pending) token = InitialAdminPassword.RestrictedToken(token);
        await using var connection = await connections.OpenAsync(ct);
        await using var command = new NpgsqlCommand("""
            insert into auth_sessions(user_id, token_hash, expires_at)
            select id, @hash, @expires from auth_users
            where id=@id and is_active and (@expected is null or password_hash=@expected) for share
            """, connection);
        command.Parameters.AddWithValue("id", principal.Id);
        command.Parameters.AddWithValue("hash", InitialAdminPassword.SessionDigest(tokens, token));
        command.Parameters.AddWithValue("expected", NpgsqlTypes.NpgsqlDbType.Text, (object?)hash ?? DBNull.Value);
        command.Parameters.AddWithValue("expires", time.GetUtcNow().AddHours(remember && !pending ? 24 * 14 : 12));
        return await command.ExecuteNonQueryAsync(ct) == 1 ? token : null;
    }

    public async Task RevokeAsync(string? token, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(token)) return;
        await using var connection = await connections.OpenAsync(ct);
        await using var command = new NpgsqlCommand("""
            update auth_sessions set revoked_at=now() where token_hash=@hash and revoked_at is null
            """, connection);
        command.Parameters.AddWithValue("hash", InitialAdminPassword.SessionDigest(tokens, token));
        await command.ExecuteNonQueryAsync(ct);
        accessCache?.Invalidate(token);
    }

    public async Task<int> RevokeAllAsync(CancellationToken ct)
    {
        await using var connection = await connections.OpenAsync(ct);
        await using var command = new NpgsqlCommand("update auth_sessions set revoked_at=now() where revoked_at is null", connection) { CommandTimeout = 0 };
        int revoked = await command.ExecuteNonQueryAsync(ct);
        accessCache?.Invalidate();
        return revoked;
    }
}
