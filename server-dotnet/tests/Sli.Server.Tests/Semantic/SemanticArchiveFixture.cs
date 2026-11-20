using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Semantic;
using Sli.Server.Storage.Direct;

namespace Sli.Server.Tests.Semantic;

internal static class SemanticArchiveFixture
{
    internal static JsonObject Authorization(string root)
    {
        var now = DateTime.UtcNow;
        var record = new DirectRuntimeRecord("v2", "storage-v2-fresh-bootstrap/v1", new string('a', 64), root,
            new JsonObject { ["kind"] = "fresh-event-store", ["version"] = 1 }, "synthetic", now.AddMinutes(-1), now.AddHours(1), null, "");
        return new() { ["route"] = record.Route, ["authority"] = record.Authority, ["preflight_digest"] = record.PreflightDigest,
            ["archive_root"] = root, ["evidence"] = record.Evidence.DeepClone(), ["authorized_by"] = record.AuthorizedBy,
            ["authorized_at"] = SemanticJson.Stamp(record.AuthorizedAt), ["expires_at"] = SemanticJson.Stamp(record.ExpiresAt),
            ["revoked_at"] = null, ["authorization_digest"] = DirectRuntimeAuthorization.Digest(record) };
    }

    internal static async Task Seed(NpgsqlConnection db, string root, CancellationToken ct)
    {
        var row = Authorization(root);
        await using var command = new NpgsqlCommand("""
            insert into storage_v2_runtime_authorizations(route,authority,preflight_digest,archive_root,evidence,authorized_by,authorized_at,expires_at,authorization_digest)
            values(@route,@authority,@preflight_digest,@archive_root,@evidence,@authorized_by,@authorized_at,@expires_at,@authorization_digest)
            on conflict(singleton) do update set archive_root=excluded.archive_root,evidence=excluded.evidence,
              authorized_at=excluded.authorized_at,expires_at=excluded.expires_at,revoked_at=null,authorization_digest=excluded.authorization_digest
            """, db);
        foreach (var field in row.Where(p => p.Key != "revoked_at"))
            if (field.Key == "evidence") command.Parameters.AddWithValue(field.Key, NpgsqlDbType.Jsonb, field.Value!.ToJsonString());
            else if (field.Key is "authorized_at" or "expires_at") command.Parameters.AddWithValue(field.Key, DateTime.Parse(field.Value!.ToString()).ToUniversalTime());
            else command.Parameters.AddWithValue(field.Key, field.Value!.ToString());
        await command.ExecuteNonQueryAsync(ct);
    }
}
