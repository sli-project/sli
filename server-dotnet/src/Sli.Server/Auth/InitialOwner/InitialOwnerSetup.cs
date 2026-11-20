using System.Text;
using Npgsql;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Infrastructure;

namespace Sli.Server.Auth.InitialOwner;

public sealed class InitialOwnerSetup(IPostgresConnectionFactory connections, IPasswordCodec passwords,
    IAuthAudit audit, ISessionLifecycle sessions, AuthRequestPolicy policy) : IInitialOwnerSetup
{
    public async Task<bool> IsPendingAsync(CancellationToken ct)
    {
        if (!policy.OwnerSetup) return false;
        await using var connection = await connections.OpenAsync(ct);
        await using var command = new NpgsqlCommand("""
            select u.id,u.username,u.role,u.is_active,u.last_login_at
            from auth_users u join access_platform_owners o on o.user_id=u.id
            where u.username='platform-owner' and o.owner_key='primary'
            """, connection);
        await using var reader = await command.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) && reader.GetInt64(0) != 0 && reader.GetString(1) == "platform-owner"
            && reader.GetString(2) == "admin" && reader.GetBoolean(3) && reader.IsDBNull(4);
    }

    public async Task<LoginResult> ClaimAsync(SetupCommand command, RequestIdentity identity, CancellationToken ct)
    {
        if (!policy.OwnerSetup) return new(null, null);
        if (!ValidNewPassword(command.Password, command.Code)) throw new InitialOwnerPasswordException();
        Principal? principal = await ClaimCredentialAsync(command.Code, command.Password!, identity.RemoteAddress, ct);
        if (principal is null)
        {
            await audit.WriteAsync(new("anonymous", null, "initial_owner_claimed", "failed", identity.RemoteAddress), ct);
            return new(null, null);
        }
        // The owner/password claim is permanent even if the later session insertion fails.
        string token = await sessions.IssueAsync(principal, false, ct);
        return new(principal, token);
    }

    public static bool ValidNewPassword(string? password, string? code) => password is not null
        && !password.Contains('\0') && password != code && CodePointLengthWithin(password, 12, 4096);

    public static bool CodeCurrent(DateTime issued, DateTime checkedAt) => checkedAt.AddHours(-24) < issued && issued <= checkedAt;

    internal static bool CodePointLengthWithin(string value, int min, int max)
    {
        int count = value.EnumerateRunes().Take(max + 1).Count();
        return count >= min && count <= max;
    }

    private async Task<Principal?> ClaimCredentialAsync(string? code, string password, string address, CancellationToken ct)
    {
        if (code is null || !CodePointLengthWithin(code, 12, 4096)) return null;
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var select = new NpgsqlCommand("""
            select u.id,u.username,u.password_hash,u.role,u.is_active,u.last_login_at,
                u.updated_at,clock_timestamp() as checked_at
            from auth_users u join access_platform_owners o on o.user_id=u.id
            where u.username='platform-owner' and o.owner_key='primary' for update of u
            """, connection, transaction);
        long id = 0;
        string hash = "";
        bool eligible = false;
        await using (var reader = await select.ExecuteReaderAsync(ct))
            if (await reader.ReadAsync(ct))
            {
                id = reader.GetInt64(0); hash = reader.GetString(2);
                eligible = id != 0 && reader.GetString(1) == "platform-owner" && reader.GetString(3) == "admin"
                    && reader.GetBoolean(4) && reader.IsDBNull(5) && !reader.IsDBNull(6)
                    && CodeCurrent(reader.GetDateTime(6), reader.GetDateTime(7));
            }
        if (!eligible || !passwords.Verify(hash, code).Valid) return null;
        await using var update = new NpgsqlCommand("""
            update auth_users set password_hash=@hash,updated_at=now(),last_login_at=now() where id=@id
            """, connection, transaction);
        update.Parameters.AddWithValue("hash", passwords.Hash(password));
        update.Parameters.AddWithValue("id", id);
        await update.ExecuteNonQueryAsync(ct);
        await audit.AppendAsync(transaction, new("session", id, "initial_owner_claimed", RemoteAddress: address), ct);
        await transaction.CommitAsync(ct);
        return new("session", id, "admin", Username: "platform-owner");
    }
}
