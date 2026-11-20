using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sli.Server.Access.Administration;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;

namespace Sli.Server.Auth.Lifecycle.Security;

public sealed class AuthAudit(IPostgresConnectionFactory connections) : IAuthAudit
{
    private static readonly IReadOnlyDictionary<string, (string Category, string Action, string? Target)> Actions =
        new Dictionary<string, (string, string, string?)>(StringComparer.Ordinal)
        {
            ["login"] = ("authentication", "auth.login", null),
            // Reviewed correction of the frozen source bridge's missing recovery mappings.
            ["owner_recovery_login"] = ("authentication", "auth.owner_recovery.login", null),
            ["owner_recovery_issued"] = ("access_management", "auth.owner_recovery.issued", null),
            ["logout"] = ("authentication", "auth.logout", null),
            ["initial_owner_claimed"] = ("access_management", "auth.initial_owner.claimed", "platform_owner"),
            ["user_created"] = ("access_management", "auth.user.created", "user"),
            ["user_updated"] = ("access_management", "auth.user.updated", "user"),
            ["user_password_reset"] = ("access_management", "auth.user.password_reset", "user"),
            ["api_key_issued"] = ("access_management", "auth.api_key.issued", "api_key"),
            ["api_key_revoked"] = ("access_management", "auth.api_key.revoked", "api_key")
        };

    public async Task WriteAsync(AuthAuditEvent auditEvent, CancellationToken ct)
    {
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await AppendAsync(transaction, auditEvent, ct);
        await transaction.CommitAsync(ct);
    }

    public Task AppendAsync(NpgsqlTransaction transaction, AuthAuditEvent auditEvent, CancellationToken ct) =>
        AppendAsync(transaction, auditEvent, ct, null);

    internal async Task AppendAsync(NpgsqlTransaction transaction, AuthAuditEvent auditEvent, CancellationToken ct, bool? writeEnabled)
    {
        var connection = transaction.Connection ?? throw new InvalidOperationException("auth_audit_transaction_required");
        // Python slices characters rather than UTF-16 units.
        string action = Slice(auditEvent.Action, 200), outcome = Slice(auditEvent.Outcome, 40);
        long id;
        DateTime created;
        await using (var command = new NpgsqlCommand("""
            insert into auth_audit(actor_type,actor_id,action,outcome,remote_address)
            values($1,$2,$3,$4,$5) returning id,created_at
            """, connection, transaction))
        {
            command.Parameters.AddWithValue(auditEvent.ActorType);
            command.Parameters.AddWithValue(NpgsqlDbType.Bigint, (object?)auditEvent.ActorId ?? DBNull.Value);
            command.Parameters.AddWithValue(action);
            command.Parameters.AddWithValue(outcome);
            command.Parameters.AddWithValue(NpgsqlDbType.Text, (object?)auditEvent.RemoteAddress ?? DBNull.Value);
            await using var reader = await command.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct)) throw new InvalidOperationException("auth_audit_write_result_invalid");
            id = reader.GetInt64(0);
            created = reader.GetDateTime(1);
        }
        await MirrorAsync(transaction, id, created, auditEvent with { Action = action, Outcome = outcome }, ct, writeEnabled);
    }

    internal static Task<System.Text.Json.Nodes.JsonObject> MirrorAsync(NpgsqlTransaction transaction, long id,
        DateTime created, AuthAuditEvent auditEvent, CancellationToken ct, bool? writeEnabled = null)
    {
        // Validation precedes the contract flag, including while writes are disabled.
        var activity = Project(id, auditEvent.Action, auditEvent.Outcome, auditEvent);
        var projected = new AdministrativeActivity(Uuid5("sli:auth_audit:" + id.ToString(CultureInfo.InvariantCulture)),
            created, activity.ActorKind, activity.ActorKind + ":" + (auditEvent.ActorId?.ToString(CultureInfo.InvariantCulture) ?? "anonymous"),
            activity.Category, activity.Action, activity.TargetKind, activity.TargetKey, activity.Outcome,
            auditEvent.Outcome == "throttled" ? "authentication_throttled" : null,
            new() { ["legacy_auth_audit_id"] = id }, auditEvent.RemoteAddress);
        return AdministrativeActivityProducer.MirrorAsync(transaction, projected, "auth_audit", id,
            writeEnabled ?? RuntimeWriteEnabled(), ct);
    }

    private sealed record Activity(string ActorKind, string Category, string Action, string? TargetKind, string? TargetKey, string Outcome);

    private static Activity Project(long id, string action, string outcome, AuthAuditEvent audit)
    {
        if (id < 1) throw new InvalidOperationException("administrative_activity_auth_audit_id_invalid");
        string[] parts = action.Split(':');
        if (!Actions.TryGetValue(parts[0], out var mapping))
            throw new InvalidOperationException("administrative_activity_auth_action_not_allowlisted");
        string actor = audit.ActorType.Trim().ToLowerInvariant() switch
        {
            "session" => "session", "api_key" => "api_key", "windows" => "windows",
            "system" or "anonymous" => "system", "local" or "local_operator" => "local_operator", "plugin" => "plugin",
            _ => throw new InvalidOperationException("administrative_activity_auth_actor_not_allowlisted")
        };
        string mappedOutcome = outcome.Trim().ToLowerInvariant() switch
        {
            "ok" => "succeeded", "failed" => "failed", "throttled" or "denied" => "denied",
            _ => throw new InvalidOperationException("administrative_activity_auth_outcome_not_allowlisted")
        };
        string? target = null;
        string? targetKind = mapping.Target;
        if (parts[0] == "owner_recovery_login" && parts.Length != 1)
            throw new InvalidOperationException("administrative_activity_auth_target_invalid");
        if (parts[0] == "owner_recovery_issued")
        {
            // Unknown-owner failed issuance has no target. Successful issuance supplies a verified ID.
            if (parts.Length == 2 && long.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out long ownerId) && ownerId > 0)
            {
                targetKind = "user";
                target = "user:" + ownerId.ToString(CultureInfo.InvariantCulture);
            }
            else if (parts.Length != 1)
                throw new InvalidOperationException("administrative_activity_auth_target_invalid");
        }
        else if (mapping.Target == "platform_owner")
        {
            if (parts.Length != 1) throw new InvalidOperationException("administrative_activity_auth_target_invalid");
            target = "platform_owner:primary";
        }
        else if (mapping.Target is not null)
        {
            if (parts.Length < 2 || !System.Numerics.BigInteger.TryParse(parts[1], NumberStyles.None,
                CultureInfo.InvariantCulture, out var targetId))
                throw new InvalidOperationException("administrative_activity_auth_target_invalid");
            target = mapping.Target + ":" + targetId.ToString(CultureInfo.InvariantCulture);
            if (target.Length > 240) throw new InvalidOperationException("administrative_activity_target_key_invalid");
        }
        return new(actor, mapping.Category, mapping.Action, targetKind, target, mappedOutcome);
    }

    private static bool RuntimeWriteEnabled()
    {
        using var stream = typeof(AuthAudit).Assembly.GetManifestResourceStream("Sli.Server.Auth.Lifecycle.Security.administrative-activity-v1.json")
            ?? throw new InvalidOperationException("administrative_activity_contract_unreadable");
        using var contract = JsonDocument.Parse(stream);
        var root = contract.RootElement;
        // The frozen Python contract explicitly rejects activation without a reviewed code/contract change.
        if (root.GetProperty("schema_version").GetInt32() != 1
            || root.GetProperty("contract_id").GetString() != "sli.administrative-activity.v1"
            || root.GetProperty("required_migration").GetInt32() != 66
            || root.GetProperty("runtime_write_enabled").GetBoolean()
            || root.GetProperty("runtime_read_enabled").GetBoolean()
            || root.GetProperty("source_contact_allowed").GetBoolean()
            || root.GetProperty("maximum_detail_bytes").GetInt32() != 8192
            || root.GetProperty("details_shape").GetString() != "flat_scalar_object_only"
            || root.TryGetProperty("status", out _) || root.TryGetProperty("production_migration_applied", out _))
            throw new InvalidOperationException("administrative_activity_contract_invalid");
        return root.GetProperty("runtime_write_enabled").GetBoolean();
    }

    private static string Slice(string value, int count) => string.Concat(value.EnumerateRunes().Take(count).Select(x => x.ToString()));

    internal static Guid Uuid5(string name)
    {
        Span<byte> ns = stackalloc byte[16];
        new Guid("6ba7b811-9dad-11d1-80b4-00c04fd430c8").TryWriteBytes(ns, bigEndian: true, out _);
        byte[] bytes = SHA1.HashData(ns.ToArray().Concat(Encoding.UTF8.GetBytes(name)).ToArray());
        bytes[6] = (byte)((bytes[6] & 0x0f) | 0x50);
        bytes[8] = (byte)((bytes[8] & 0x3f) | 0x80);
        return new Guid(bytes.AsSpan(0, 16), bigEndian: true);
    }
}
