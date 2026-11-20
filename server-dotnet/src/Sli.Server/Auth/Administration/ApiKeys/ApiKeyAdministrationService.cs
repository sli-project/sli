using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Infrastructure;
using Sli.Server.Access.Administration;
using Sli.Server.Auth.ReportKeys;

namespace Sli.Server.Auth.Administration.ApiKeys;

public sealed class ApiKeyAdministrationService(IPostgresConnectionFactory connections, ICredentialTokens tokens,
    IAuthAudit audit) : IApiKeyAdministration
{
    public async Task<IReadOnlyList<JsonElement>> ListAsync(CancellationToken ct)
    {
        await using var connection = await connections.OpenAsync(ct);
        await using var query = new NpgsqlCommand("""
            select row_to_json(k)::text from (
                select id,key_prefix,label,role,is_active,expires_at,created_at,last_used_at,revoked_at
                from auth_api_keys order by id desc) k
            """, connection);
        List<JsonElement> items = [];
        await using var reader = await query.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) items.Add(Row(reader.GetString(0)));
        return items;
    }

    public async Task<ApiKeyIssueResult> IssueAsync(IssueApiKeyCommand command, UserAdministrationActor actor, CancellationToken ct)
    {
        string role = UserAdministrationService.Strip(command.Role).ToLowerInvariant();
        if (role is not ("viewer" or "operator" or "admin")) throw new ApiKeyAdministrationException("invalid_role");
        string label = UserAdministrationService.Strip(command.Label);
        if (label.Length == 0 || label.EnumerateRunes().Take(121).Count() > 120)
            throw new ApiKeyAdministrationException("api_key_label_required");
        string token = "adl_" + tokens.NewSessionToken();
        string prefix = token[..12];
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var insert = new NpgsqlCommand("""
            with issued as (
                insert into auth_api_keys(key_prefix,key_hash,label,role,expires_at,report_subject_id)
                values(@prefix,@hash,@label,@role,@expires,@subject)
                returning id,key_prefix,label,role,expires_at,created_at)
            select row_to_json(issued)::text from issued
            """, connection, transaction);
        insert.Parameters.AddWithValue("prefix", prefix);
        insert.Parameters.AddWithValue("hash", tokens.Digest(token));
        insert.Parameters.AddWithValue("label", label);
        insert.Parameters.AddWithValue("role", role);
        insert.Parameters.AddWithValue("expires", NpgsqlDbType.TimestampTz, (object?)command.ExpiresAt?.ToUniversalTime() ?? DBNull.Value);
        insert.Parameters.AddWithValue("subject", NpgsqlDbType.Bigint, (object?)command.Report?.SubjectId ?? DBNull.Value);
        var item = Row((string)(await insert.ExecuteScalarAsync(ct) ?? throw new InvalidOperationException("api_key_write_result_invalid")));
        long id = item.GetProperty("id").GetInt64();
        await audit.AppendAsync(transaction, new(actor.Type, actor.Id, $"api_key_issued:{id}:{prefix}", RemoteAddress: actor.RemoteAddress), ct);
        if (command.Report is { } report)
        {
            await AssignmentAudit.AppendEventAsync(transaction, new("local_operator", null), "report_api_key_issued",
                "user", report.SubjectId, "api_key", id.ToString(CultureInfo.InvariantCulture), "Expiring read-only report verification",
                new { domain_id = report.DomainId, reports = report.Reports.Order(StringComparer.Ordinal), valid_until = command.ExpiresAt is { } expiry ? ReportKeyTime.Format(expiry) : null }, null, ct);
        }
        await transaction.CommitAsync(ct);
        // The only publication of plaintext is after the key and its audit have committed.
        return new(item, token);
    }

    public async Task<bool> RevokeAsync(BigInteger keyId, UserAdministrationActor actor, CancellationToken ct)
    {
        if (keyId < long.MinValue || keyId > long.MaxValue) return false;
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var revoke = new NpgsqlCommand("""
            update auth_api_keys set revoked_at=now(),is_active=false
            where id=@id and revoked_at is null returning key_prefix
            """, connection, transaction);
        revoke.Parameters.AddWithValue("id", (long)keyId);
        string? prefix = await revoke.ExecuteScalarAsync(ct) as string;
        if (prefix is null) return false;
        await audit.AppendAsync(transaction, new(actor.Type, actor.Id, $"api_key_revoked:{keyId}:{prefix}", RemoteAddress: actor.RemoteAddress), ct);
        await transaction.CommitAsync(ct);
        return true;
    }

    private static JsonElement Row(string json)
    {
        var row = JsonNode.Parse(json)!.AsObject();
        foreach (string field in new[] { "expires_at", "created_at", "last_used_at", "revoked_at" })
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
