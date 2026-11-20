using Npgsql;
using Sli.Server.Access;
using Sli.Server.Infrastructure;

namespace Sli.Server.Auth.Lifecycle;

public interface ISessionLifecycle
{
    Task<string> IssueAsync(Principal principal, bool remember, CancellationToken ct);
    Task RevokeAsync(string? token, CancellationToken ct);
}

public sealed class SessionLifecycle(IPostgresConnectionFactory connections, ICredentialTokens tokens,
    TimeProvider time, SessionAccessFactsCache? accessCache = null) : ISessionLifecycle
{
    public async Task<string> IssueAsync(Principal principal, bool remember, CancellationToken ct)
    {
        string token = tokens.NewSessionToken();
        await using var connection = await connections.OpenAsync(ct);
        await using var command = new NpgsqlCommand("""
            insert into auth_sessions(user_id, token_hash, expires_at) values (@id, @hash, @expires)
            """, connection);
        command.Parameters.AddWithValue("id", principal.Id);
        command.Parameters.AddWithValue("hash", tokens.Digest(token));
        command.Parameters.AddWithValue("expires", time.GetUtcNow().AddHours(remember ? 24 * 14 : 12));
        await command.ExecuteNonQueryAsync(ct);
        return token;
    }

    public async Task RevokeAsync(string? token, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(token)) return;
        await using var connection = await connections.OpenAsync(ct);
        await using var command = new NpgsqlCommand("""
            update auth_sessions set revoked_at=now() where token_hash=@hash and revoked_at is null
            """, connection);
        command.Parameters.AddWithValue("hash", tokens.Digest(token));
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
