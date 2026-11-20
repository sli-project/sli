using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Infrastructure;

namespace Sli.Server.Auth.Administration;

public sealed class UserAdministrationService(IPostgresConnectionFactory connections, IPasswordCodec passwords,
    IAuthAudit audit, SessionAccessFactsCache? accessCache = null) : IUserAdministration
{
    public async Task<IReadOnlyList<JsonElement>> ListAsync(CancellationToken ct)
    {
        await using var connection = await connections.OpenAsync(ct);
        await using var command = new NpgsqlCommand("""
            select to_jsonb(u) from (
                select u.id,u.username,u.role,u.is_active,u.created_at,u.updated_at,u.last_login_at,
                  (u.is_service or exists(select 1 from auth_api_keys k where k.report_subject_id=u.id)) as is_service
                from auth_users u order by lower(u.username),u.id
            ) u
            """, connection);
        var rows = new List<JsonElement>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) rows.Add(Row(reader.GetString(0)));
        return rows;
    }

    public async Task<JsonElement> CreateAsync(CreateUserCommand command, UserAdministrationActor actor, CancellationToken ct)
    {
        string username = Strip(command.Username);
        if (!Regex.IsMatch(username, @"\A[A-Za-z0-9][A-Za-z0-9_.-]{2,63}\z", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking))
            throw new UserAdministrationException("username_must_be_3_to_64_characters");
        string role = Role(command.Role);
        ValidatePassword(command.Password);
        string hash = passwords.Hash(command.Password);
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var insert = new NpgsqlCommand("""
            with inserted as (
                insert into auth_users(username,password_hash,role,is_service) values(@username,@hash,@role,@service)
                returning id,username,role,is_active,created_at
            ) select to_jsonb(inserted) from inserted
            """, connection, transaction);
        insert.Parameters.AddWithValue("username", username);
        insert.Parameters.AddWithValue("hash", hash);
        insert.Parameters.AddWithValue("role", role);
        insert.Parameters.AddWithValue("service", command.IsService);
        var result = Row((string)(await insert.ExecuteScalarAsync(ct))!);
        await AppendAuditAsync(transaction, actor, "user_created", result, ct);
        await transaction.CommitAsync(ct);
        return result;
    }

    public async Task<JsonElement> UpdateAsync(UpdateUserCommand command, UserAdministrationActor actor, CancellationToken ct)
    {
        if (command.Role is null && command.IsActive is null) throw new UserAdministrationException("user_update_required");
        string? role = command.Role is null ? null : Role(command.Role);
        if (command.UserId < long.MinValue || command.UserId > long.MaxValue) throw new UserAdministrationException("user_not_found");
        long userId = (long)command.UserId;
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var select = new NpgsqlCommand("select id,username,role,is_active from auth_users where id=@id", connection, transaction);
        select.Parameters.AddWithValue("id", userId);
        string currentRole;
        bool currentActive;
        await using (var reader = await select.ExecuteReaderAsync(ct))
        {
            if (!await reader.ReadAsync(ct)) throw new UserAdministrationException("user_not_found");
            currentRole = reader.GetString(2); currentActive = reader.GetBoolean(3);
        }
        string nextRole = role ?? currentRole;
        bool nextActive = command.IsActive ?? currentActive;
        if (actor.Type == "session" && actor.Id == userId && !nextActive)
            throw new UserAdministrationException("cannot_disable_current_user");
        if (currentRole == "admin" && currentActive && (nextRole != "admin" || !nextActive))
        {
            // Lock in the same deterministic order as the source. Do not lock the target
            // first: two different target locks would deadlock before this shared check.
            await using var admins = new NpgsqlCommand("select id from auth_users where role='admin' and is_active=true order by id for update", connection, transaction);
            bool remaining = false;
            await using var reader = await admins.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct)) remaining |= reader.GetInt64(0) != userId;
            if (!remaining) throw new UserAdministrationException("last_active_admin_required");
        }
        await using var update = new NpgsqlCommand("""
            with updated as (
                update auth_users set role=@role,is_active=@active,updated_at=now() where id=@id
                returning id,username,role,is_active,created_at,updated_at,last_login_at
            ) select to_jsonb(updated) from updated
            """, connection, transaction);
        update.Parameters.AddWithValue("id", userId);
        update.Parameters.AddWithValue("role", nextRole);
        update.Parameters.AddWithValue("active", nextActive);
        var result = Row((string)(await update.ExecuteScalarAsync(ct))!);
        if (!nextActive) await RevokeSessionsAsync(connection, transaction, userId, ct);
        await AppendAuditAsync(transaction, actor, "user_updated", result, ct);
        await transaction.CommitAsync(ct);
        accessCache?.Invalidate(userId: userId);
        return result;
    }

    public async Task<JsonElement> ResetPasswordAsync(BigInteger targetId, string password, UserAdministrationActor actor, CancellationToken ct)
    {
        ValidatePassword(password);
        if (targetId < long.MinValue || targetId > long.MaxValue) throw new UserAdministrationException("user_not_found");
        long userId = (long)targetId;
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var select = new NpgsqlCommand("select id,username,is_active from auth_users where id=@id for update", connection, transaction);
        select.Parameters.AddWithValue("id", userId);
        string username;
        await using (var reader = await select.ExecuteReaderAsync(ct))
        {
            if (!await reader.ReadAsync(ct)) throw new UserAdministrationException("user_not_found");
            if (!reader.GetBoolean(2)) throw new UserAdministrationException("cannot_reset_password_for_disabled_user");
            username = reader.GetString(1);
        }
        await using var update = new NpgsqlCommand("update auth_users set password_hash=@hash,updated_at=now() where id=@id", connection, transaction);
        update.Parameters.AddWithValue("id", userId);
        update.Parameters.AddWithValue("hash", passwords.Hash(password));
        await update.ExecuteNonQueryAsync(ct);
        await RevokeSessionsAsync(connection, transaction, userId, ct);
        var result = JsonSerializer.SerializeToElement(new { id = userId, username, sessions_revoked = true });
        await AppendAuditAsync(transaction, actor, "user_password_reset", result, ct);
        await transaction.CommitAsync(ct);
        accessCache?.Invalidate(userId: userId);
        return result;
    }

    private Task AppendAuditAsync(NpgsqlTransaction transaction, UserAdministrationActor actor, string action, JsonElement user, CancellationToken ct) =>
        audit.AppendAsync(transaction, new(actor.Type, actor.Id,
            action + ":" + user.GetProperty("id").GetInt64().ToString(CultureInfo.InvariantCulture) + ":" + user.GetProperty("username").GetString(),
            RemoteAddress: actor.RemoteAddress), ct);

    private static async Task RevokeSessionsAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, long id, CancellationToken ct)
    {
        await using var revoke = new NpgsqlCommand("update auth_sessions set revoked_at=now() where user_id=@id and revoked_at is null", connection, transaction);
        revoke.Parameters.AddWithValue("id", id);
        await revoke.ExecuteNonQueryAsync(ct);
    }

    private static void ValidatePassword(string password)
    {
        // These routes have only the source's minimum; bootstrap's maximum/NUL
        // policy belongs to bootstrap and must not silently constrain user admin.
        if (password.EnumerateRunes().Take(12).Count() < 12)
            throw new UserAdministrationException("password_must_be_at_least_12_characters");
    }

    private static string Role(string role)
    {
        string clean = Strip(role).ToLowerInvariant();
        return clean is "viewer" or "operator" or "admin" ? clean : throw new UserAdministrationException("invalid_role");
    }

    internal static string Strip(string value)
    {
        int start = 0, end = value.Length;
        static bool Space(char c) => char.IsWhiteSpace(c) || c is >= '\u001c' and <= '\u001f';
        while (start < end && Space(value[start])) start++;
        while (end > start && Space(value[end - 1])) end--;
        return value[start..end];
    }

    private static JsonElement Row(string json)
    {
        var row = JsonNode.Parse(json)!.AsObject();
        foreach (string field in new[] { "created_at", "updated_at", "last_login_at" })
        {
            if (row[field] is not JsonValue node || !node.TryGetValue<string>(out var value)) continue;
            var time = DateTimeOffset.Parse(value, CultureInfo.InvariantCulture);
            string stamp = time.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
            if (time.Ticks % TimeSpan.TicksPerSecond != 0) stamp += "." + time.ToString("ffffff", CultureInfo.InvariantCulture);
            row[field] = stamp + time.ToString("zzz", CultureInfo.InvariantCulture);
        }
        return JsonSerializer.SerializeToElement(row);
    }
}
