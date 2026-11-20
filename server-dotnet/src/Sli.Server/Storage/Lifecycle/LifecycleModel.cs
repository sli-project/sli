using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Server.Storage.Lifecycle;

internal sealed record LifecycleOptions(bool Once = false, int IntervalSeconds = 21600, int BatchSize = 1000);
internal static class LifecycleAdmission
{
    internal static bool Enabled(string? s) => s?.Trim().ToLowerInvariant() is "1" or "true" or "yes" or "on";
}

internal sealed partial record LifecyclePolicy(int HotDays, int WarmDays, bool ArchiveDelete, string? Profile, bool ApplyByDefault)
{
    internal static readonly LifecyclePolicy Default = new(7, 365, false, null, false);
    internal int RawDays { get; init; } = 2;
    internal int PostCollectionDays { get; init; } = 30;
    internal static readonly HashSet<string> Fields = "raw_retention_days raw_archive_enabled raw_archive_compress db_retention_days relationship_retention_days warm_retention_days backup_retention_days log_retention_days artifact_retention_days post_collection_retention_days archive_auto_delete_enabled min_free_disk_percent stop_collection_if_free_disk_percent_below stop_collection_if_free_disk_bytes_below critical_free_disk_percent cleanup_candidate_limit".Split(' ').ToHashSet(StringComparer.Ordinal);
    internal static LifecyclePolicy Read(Func<string, string?> get)
    {
        int Days(string key, int fallback) => get(key) is not { Length: > 0 } s ? fallback :
            int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out int n) && n > 0 ? n : throw new InvalidDataException("owner_storage_policy_changed");
        string? profile = get("ADLOG_STORAGE_CAPACITY_PROFILE");
        if (profile is not (null or "" or "extended" or "economy")) throw new InvalidDataException("storage_capacity_profile_invalid");
        var overrides = (get("ADLOG_STORAGE_CAPACITY_PROFILE_OVERRIDES") ?? "").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal);
        if (overrides.Any(key => !Fields.Contains(key))) throw new InvalidDataException("storage_policy_override_fields_invalid");
        bool Field(string name) => string.IsNullOrEmpty(profile) || overrides.Contains(name);
        return new(Field("db_retention_days") ? Days("ADLOG_DB_RETENTION_DAYS", Default.HotDays) : Default.HotDays, Field("warm_retention_days") ? Days("ADLOG_WARM_RETENTION_DAYS", Default.WarmDays) : Default.WarmDays,
            Field("archive_auto_delete_enabled") && LifecycleAdmission.Enabled(get("ADLOG_ARCHIVE_AUTO_DELETE_ENABLED")), profile, LifecycleAdmission.Enabled(get("ADLOG_RETENTION_APPLY_BY_DEFAULT"))) {
                RawDays = Field("raw_retention_days") ? ConfiguredDays(get("ADLOG_RAW_RETENTION_DAYS"), Default.RawDays) : Default.RawDays,
                PostCollectionDays = Field("post_collection_retention_days") ? ReadOperationalRetention(get).Days : Default.PostCollectionDays
            };
    }
}

internal static class LifecycleJson
{
    internal const int MaxBytes = 64 * 1024 * 1024;
    internal static string Canonical(JsonNode node) => CanonicalJson.Serialize(node, ensureAscii: false);
    internal static string Hash(JsonNode node) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Canonical(node))));
    internal static string Text(JsonObject row, string key) => row[key]?.ToString() ?? "";
    internal static long Number(JsonObject row, string key) => long.Parse(Text(row, key), CultureInfo.InvariantCulture);
    internal static string Stamp(DateTime utc) => utc.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
    internal static string Iso(DateTime utc) => utc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffffzzz", CultureInfo.InvariantCulture);
    internal static JsonObject Result(string status, string? reason = null) => new() { ["status"] = status, ["reason"] = reason };
    internal static string Failure(Exception error) => error switch {
        Npgsql.PostgresException { SqlState: "53300" } => "database_connections_exhausted",
        Npgsql.PostgresException { SqlState: "57P01" or "57P02" or "57P03" or "57P04" or "57P05" } => "database_unavailable",
        Npgsql.PostgresException { SqlState: "42501" } => "purge_permission_denied",
        Npgsql.PostgresException { SqlState: "57014" } => "purge_statement_timeout",
        Npgsql.PostgresException { SqlState: "55P03" } => "purge_lock_unavailable",
        Npgsql.PostgresException { SqlState: "23503" } => "purge_dependency_changed",
        Npgsql.PostgresException { SqlState: "42P01" } => "purge_schema_missing",
        Npgsql.PostgresException { SqlState: "42703" } => "purge_schema_incompatible",
        Npgsql.PostgresException { SqlState: "28P01" } => "postgres_authentication_failed",
        LifecycleBlocked e => e.Message,
        _ => "purge_verification_or_io_failed"
    };
    internal static bool DatabaseWait(string reason) => reason is "database_connections_exhausted" or "database_unavailable";
}
internal sealed class LifecycleBlocked(string reason) : Exception(reason);

// Journals contain one source batch and are replaced atomically. Their byte size
// depends on the batch payload, not the total history. A corrupt checkpoint is never a zero frontier.
internal partial class LifecycleFiles(string dataRoot)
{
    internal string Root { get; } = Path.GetFullPath(dataRoot);
    internal JsonObject? Read(string name, int? maxBytes = null)
    {
        string path = Path.Combine(Root, "runtime", name);
        if (!File.Exists(path)) return null;
        if (maxBytes is { } limit) {
            byte[] bytes = StorageLifecycleBoundedIo.ReadBytes(path, limit, "history_retention_progress_invalid");
            return JsonNode.Parse(bytes) as JsonObject ?? throw new LifecycleBlocked("history_retention_progress_invalid");
        }
        using var stream = File.OpenRead(path);
        return JsonNode.Parse(stream) as JsonObject ?? throw new LifecycleBlocked("history_retention_progress_invalid");
    }
    internal virtual void Write(string name, JsonObject payload, bool replace = true)
    {
        string path = Path.Combine(Root, "runtime", name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        byte[] bytes = Encoding.UTF8.GetBytes(LifecycleJson.Canonical(payload) + "\n");
        string temp = path + "." + Guid.NewGuid().ToString("N") + ".partial";
        try {
            using (var file = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { file.Write(bytes); file.Flush(true); }
            File.Move(temp, path, replace);
        } finally { if (File.Exists(temp)) File.Delete(temp); }
    }
    internal (string Name, long Started) StartPurge(string lane)
    {
        long started = Stopwatch.GetTimestamp();
        string name = "purge-runs/" + DateTime.UtcNow.ToString("yyyyMMddTHHmmssffffffZ", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N") + ".json";
        string[] tables = lane switch {
            "agent_inbox" => ["sli_agent_packet_inbox"],
            "agent_receipts" => ["sli_agent_receipts"],
            "semantic_outbox" => ["semantic_processing_outbox"],
            "file_audit" => ["sli_agent_packet_inbox", "sli_plugin_file_audit.access_snapshots"],
            _ => ["sli_plugin_file_audit.observations"]
        };
        var counts = new JsonObject();
        foreach (string table in tables) counts[table] = LifecyclePostgres.Table();
        Write(name, new JsonObject { ["contract"] = "sli.purge-run.v1", ["lane"] = lane, ["status"] = "running",
            ["started_at_utc"] = LifecycleJson.Iso(DateTime.UtcNow), ["tables"] = counts,
            ["duration_ms"] = 0L, ["bytes_reclaimed"] = 0L, ["logical_bytes_deleted"] = 0L, ["physical_reclaim_performed"] = false });
        return (name, started);
    }
    internal void PurgeReceipt((string Name, long Started) run, JsonObject result)
    {
        var payload = Read(run.Name)!;
        foreach (var pair in result) payload[pair.Key] = pair.Value?.DeepClone();
        bool finished = LifecycleJson.Text(payload, "status") is not ("running" or "verified_pending_commit");
        if (finished) {
            payload["finished_at_utc"] = LifecycleJson.Iso(DateTime.UtcNow);
            payload["duration_ms"] = Math.Round(Stopwatch.GetElapsedTime(run.Started).TotalMilliseconds, 3);
        }
        Write(run.Name, payload);
        if (!finished) return;
        // Retain the same 50 source-free receipts as the reference.
        foreach (string old in Directory.EnumerateFiles(Path.Combine(Root, "runtime", "purge-runs"), "*.json").OrderDescending(StringComparer.Ordinal).Skip(50)) File.Delete(old);
    }
}
