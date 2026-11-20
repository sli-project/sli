using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol;

namespace Sli.Server.Storage.Direct;

internal sealed record DirectRuntimeRecord(string Route, string Authority, string PreflightDigest,
    string ArchiveRoot, JsonObject Evidence, string AuthorizedBy, DateTime AuthorizedAt,
    DateTime ExpiresAt, DateTime? RevokedAt, string AuthorizationDigest);

internal sealed class DirectRuntimeAuthorization
{
    private DirectRuntimeAuthorization(string archiveRoot) { ArchiveRoot=archiveRoot; }
    internal string ArchiveRoot { get; }

    internal static string Digest(DirectRuntimeRecord record)
    {
        var doc = new JsonObject {
            ["route"] = record.Route, ["authority"] = record.Authority,
            ["preflight_digest"] = record.PreflightDigest, ["archive_root"] = record.ArchiveRoot,
            ["evidence"] = record.Evidence.DeepClone(), ["authorized_by"] = record.AuthorizedBy,
            ["authorized_at"] = Timestamp(record.AuthorizedAt), ["expires_at"] = Timestamp(record.ExpiresAt)
        };
        var bytes = new UTF8Encoding(false, true).GetBytes(CanonicalJson.Serialize(doc, ensureAscii: false));
        return Convert.ToHexStringLower(SHA256.HashData(bytes));
    }

    private static string Timestamp(DateTime value)
    {
        if (value.Kind != DateTimeKind.Utc) throw new InvalidOperationException("storage_v2_timestamp_invalid");
        var prefix = value.ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture);
        var micros = value.Ticks % TimeSpan.TicksPerSecond / 10;
        return prefix + (micros == 0 ? "" : "." + micros.ToString("D6", CultureInfo.InvariantCulture)) + "+00:00";
    }

    internal static DirectRuntimeAuthorization Validate(DirectRuntimeRecord record, DateTime now)
    {
        if (record.RevokedAt is not null || now.Kind != DateTimeKind.Utc || now >= record.ExpiresAt ||
            record.Route != "v2" ||
            record.Authority is not ("storage-v2-transition-controller/v1" or "storage-v2-fresh-bootstrap/v1"))
            throw new InvalidOperationException("storage_v2_admission_required");
        if (record.Authority == "storage-v2-fresh-bootstrap/v1" &&
            (record.Route != "v2" || record.Evidence["kind"]?.GetValue<string>() != "fresh-event-store" ||
             !VersionOne(record.Evidence["version"])))
            throw new InvalidOperationException("storage_v2_admission_required");
        if (!string.Equals(Digest(record), record.AuthorizationDigest, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("storage_v2_admission_required");
        return new DirectRuntimeAuthorization(record.ArchiveRoot);
    }

    private static bool VersionOne(JsonNode? node)
    {
        if (node is not JsonValue value) return false;
        if (value.ToJsonString() == "true") return true;
        return decimal.TryParse(value.ToJsonString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var number) && number == 1;
    }

    internal static async Task<DirectRuntimeAuthorization?> LoadAsync(NpgsqlConnection db, NpgsqlTransaction tx, DateTime now, CancellationToken ct)
    {
        await using (var available = new NpgsqlCommand("select to_regclass('public.storage_v2_runtime_authorizations') is not null", db, tx))
            if (await available.ExecuteScalarAsync(ct) is not true) return null;
        await using var command = new NpgsqlCommand("""
            select route,authority,preflight_digest,archive_root,evidence::text,authorized_by,
                   authorized_at,expires_at,revoked_at,authorization_digest
            from storage_v2_runtime_authorizations where singleton=true
            """, db, tx);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return null;
        var record = new DirectRuntimeRecord(reader.GetString(0), reader.GetString(1), reader.GetString(2),
            reader.GetString(3), JsonNode.Parse(reader.GetString(4))!.AsObject(), reader.GetString(5),
            reader.GetDateTime(6), reader.GetDateTime(7), reader.IsDBNull(8) ? null : reader.GetDateTime(8), reader.GetString(9));
        return Validate(record, now);
    }
}
