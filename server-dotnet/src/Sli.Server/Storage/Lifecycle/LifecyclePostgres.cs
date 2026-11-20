using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;

namespace Sli.Server.Storage.Lifecycle;

internal static class LifecyclePostgres
{
    internal static JsonObject Table() => new() { ["selected_count"] = 0L, ["deleted_count"] = 0L, ["logical_bytes_deleted"] = 0L, ["partitions"] = new JsonArray() };

    internal static async Task<List<JsonObject>> Rows(NpgsqlConnection db, NpgsqlTransaction? tx, string sql, CancellationToken ct, params (string Key, object Value)[] args)
        => await Rows(db, tx, null, sql, ct, args);
    internal static async Task<List<JsonObject>> Rows(NpgsqlConnection db, NpgsqlTransaction? tx, int? commandTimeout, string sql, CancellationToken ct, params (string Key, object Value)[] args)
    {
        await using var cmd = new NpgsqlCommand(sql, db, tx) { CommandTimeout = 0 };
        foreach (var (key, value) in args) cmd.Parameters.AddWithValue(key, value);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var result = new List<JsonObject>(); long size = 0;
        while (await reader.ReadAsync(ct)) {
            if (result.Count >= 100000) throw new LifecycleBlocked("history_source_batch_too_large");
            var row = new JsonObject();
            for (int i = 0; i < reader.FieldCount; i++) {
                object? value = reader.IsDBNull(i) ? null : reader.GetValue(i);
                row[reader.GetName(i)] = value switch {
                    null => null, byte[] bytes => JsonValue.Create(Convert.ToHexString(bytes)),
                    DateTime stamp => JsonValue.Create(stamp.ToUniversalTime().ToString(stamp.Microsecond == 0 && stamp.Millisecond == 0 ? "yyyy-MM-dd'T'HH:mm:sszzz" : "yyyy-MM-dd'T'HH:mm:ss.ffffffzzz", CultureInfo.InvariantCulture)),
                    string text when reader.GetDataTypeName(i) is "json" or "jsonb" => JsonNode.Parse(text),
                    _ => JsonSerializer.SerializeToNode(value)
                };
            }
            size += System.Text.Encoding.UTF8.GetByteCount(LifecycleJson.Canonical(row));
            if (size > LifecycleJson.MaxBytes) throw new LifecycleBlocked("history_source_batch_too_large");
            result.Add(row);
        }
        return result;
    }
    internal static async Task<int> Execute(NpgsqlConnection db, NpgsqlTransaction? tx, string sql, CancellationToken ct, params (string Key, object Value)[] args)
        => await Execute(db, tx, null, sql, ct, args);
    internal static async Task<int> Execute(NpgsqlConnection db, NpgsqlTransaction? tx, int? commandTimeout, string sql, CancellationToken ct, params (string Key, object Value)[] args)
    {
        await using var cmd = new NpgsqlCommand(sql, db, tx) { CommandTimeout = 0 };
        foreach (var (key, value) in args) cmd.Parameters.AddWithValue(key, value);
        return await cmd.ExecuteNonQueryAsync(ct);
    }
    internal static async Task<T> RetryDeadlock<T>(Func<Task<T>> batch, CancellationToken ct)
    {
        while (true) {
            ct.ThrowIfCancellationRequested();
            try { return await batch(); }
            catch (PostgresException error) when (error.SqlState == PostgresErrorCodes.DeadlockDetected) { }
        }
    }
    internal static async Task<List<JsonObject>> LockedRows(NpgsqlConnection db, NpgsqlTransaction tx, string sql, Action<bool>? waiting, CancellationToken ct, params (string Key,object Value)[] args)
    {
        waiting?.Invoke(true);
        try { return await Rows(db,tx,sql,ct,args); }
        finally { waiting?.Invoke(false); }
    }
    internal static async Task<bool> Lock(NpgsqlConnection db, string name, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("select pg_try_advisory_lock(hashtext(@name))", db); cmd.Parameters.AddWithValue("name", name);
        return await cmd.ExecuteScalarAsync(ct) is true;
    }
}

internal sealed class LifecycleCatalog
{
    internal JsonObject[] Entries { get; }
    internal LifecycleCatalog(JsonObject? data = null)
        : this(Semantic.EventCatalogQuality.Entries(data ?? Semantic.EventDescriptors.Load())) { }
    internal LifecycleCatalog(IEnumerable<JsonObject> entries)
    {
        Entries = entries.ToArray();
        foreach (var entry in Entries) {
            if (entry["lifecycle"]?["promotion"] is not JsonObject promotion ||
                promotion["high_volume"] is not JsonValue highVolume || !highVolume.TryGetValue<bool>(out bool enabled) || !enabled) continue;
            if (promotion["budget"] is not JsonObject budget) throw new InvalidDataException("lifecycle promotion budget must be an object");
            foreach (string field in new[] { "events_per_day_upper", "source_bytes_per_event_upper", "derived_bytes_per_object_upper" }) {
                if (!long.TryParse(budget[field]?.ToJsonString(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long value) || value < 0)
                    throw new InvalidDataException($"lifecycle promotion budget {field} must be a non-negative integer");
                if (value == 0) throw new InvalidDataException("high-volume lifecycle budget bounds must be positive");
            }
        }
        foreach (var entry in Entries) _ = Semantic.EventDescriptors.ResolveRetention(entry);
    }
    internal bool NoArchive(int key, string channel, string provider) => Entries.Any(e => e["event_id"]?.ToString() == key.ToString(CultureInfo.InvariantCulture) &&
        e["channel"]?.ToString() == channel && e["provider_name"]?.ToString() == provider && e["lifecycle"]?["promotion"]?["archive_requirement"]?.ToString() == "no_archive");

}
