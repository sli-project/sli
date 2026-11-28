using System.Globalization;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

public static class WorkstationHardware
{
    public const string Channel = "workstation-hardware";
    public const string Capability = "workstation_hardware_v1";
    public const int MaxBytes = 40 * 1024;

    // The wire allowlist and Windows projection share these field names. A null
    // section means the query could not establish which components were present.
    private static readonly (string Name, int Limit, string[] Text, string[] Numbers, string[] Flags)[] Sections =
    [
        ("computer", 1, ["manufacturer", "model", "serial"], [], []),
        ("bios", 1, ["version", "date"], [], []),
        ("security", 1, ["tpm_version"], [], ["secure_boot", "tpm_enabled"]),
        ("processor", 16, ["model"], ["cores", "threads"], []),
        ("memory", 1, [], ["size"], []),
        ("memory_module", 64, ["slot", "manufacturer", "serial"], ["size", "speed"], []),
        ("disk", 32, ["model", "type", "interface", "serial"], ["size"], []),
        ("volume", 64, ["disk_id", "mount", "bitlocker"], ["partition"], ["system"]),
        ("video", 16, ["model"], [], []),
        ("network", 32, ["name", "mac"], ["speed"], []),
        ("monitor", 16, ["model", "serial"], [], []),
    ];

    public static JsonObject? Build(JsonObject observations)
    {
        var snapshot = new JsonObject();
        foreach (var section in Sections)
        {
            snapshot[section.Name] = null;
            if (observations[section.Name] is not JsonArray source || source.Count > section.Limit) continue;
            var rows = new SortedDictionary<string, JsonObject>(StringComparer.Ordinal);
            foreach (var item in source.OfType<JsonObject>())
            {
                var id = section.Limit == 1 ? section.Name : Identity(item["id"]);
                if (id is null) continue;
                var row = new JsonObject { ["id"] = id };
                foreach (var field in section.Text)
                    row[field] = field == "disk_id" ? Identity(item[field]) : FieldText(field, item[field]);
                foreach (var field in section.Numbers)
                    row[field] = JsonRead.TryInteger(item[field], out var n) && n > 0 && n <= 9_007_199_254_740_991L ? (long?)n : null;
                foreach (var field in section.Flags)
                    row[field] = item[field] is JsonValue value && value.TryGetValue<bool>(out var flag) ? flag : null;
                rows.TryAdd(id, row);
            }
            if (rows.Count == source.Count)
                snapshot[section.Name] = new JsonArray(rows.Values.Cast<JsonNode?>().ToArray());
        }
        while (CanonicalJson.ToBytes(snapshot).Length > MaxBytes)
        {
            var largest = snapshot.Where(pair => pair.Value is JsonArray).MaxBy(pair => CanonicalJson.ToBytes(pair.Value!).Length);
            snapshot[largest.Key] = null;
        }
        return HasObservations(snapshot) ? snapshot : null;
    }

    public static bool IsValid(JsonObject snapshot)
    {
        if (snapshot.Count != Sections.Length || CanonicalJson.ToBytes(snapshot).Length > MaxBytes) return false;
        foreach (var section in Sections)
        {
            if (!snapshot.ContainsKey(section.Name)) return false;
            if (snapshot[section.Name] is null) continue;
            if (snapshot[section.Name] is not JsonArray rows || rows.Count > section.Limit) return false;
            string? previous = null;
            foreach (var item in rows)
            {
                if (item is not JsonObject row || !JsonRead.HasExactly(row, ["id", .. section.Text, .. section.Numbers, .. section.Flags])
                    || !JsonRead.TryString(row["id"], out var id) || (section.Limit == 1 ? id != section.Name : !IsDigest(id))
                    || previous is not null && string.CompareOrdinal(previous, id) >= 0) return false;
                previous = id;
                if (section.Text.Any(field => row[field] is not null && (!JsonRead.TryString(row[field], out var text)
                        || (field == "disk_id" ? !IsDigest(text) : FieldText(field, row[field]) != text)))
                    || section.Numbers.Any(field => row[field] is not null && (!JsonRead.TryInteger(row[field], out var n) || n <= 0 || n > 9_007_199_254_740_991L))
                    || section.Flags.Any(field => row[field] is not null && (row[field] is not JsonValue flag || !flag.TryGetValue<bool>(out _)))) return false;
            }
        }
        return HasObservations(snapshot);
    }

    private static bool HasObservations(JsonObject snapshot) => snapshot.Select(pair => pair.Value).OfType<JsonArray>()
        .SelectMany(rows => rows.OfType<JsonObject>()).Any(row => row.Any(pair => pair.Key != "id" && pair.Value is not null));

    private static string? FieldText(string field, JsonNode? value)
    {
        var text = Clean(value);
        return field switch
        {
            "mount" => text is [>= 'A' and <= 'Z', ':'] ? text : null,
            "bitlocker" => text is "on" or "off" ? text : null,
            "type" => text is "SSD" or "HDD" ? text : null,
            _ => text,
        };
    }

    private static bool IsDigest(string text) => text.Length == 64 && text.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static string? Identity(JsonNode? value) => Clean(value, 512) is { } key
        ? Packets.Digest(JsonValue.Create(key.ToUpperInvariant())!) : null;

    private static string? Clean(JsonNode? value, int limit = 128)
    {
        if (!JsonRead.TryString(value, out var text)) return null;
        text = WorkstationsModule.BoundedUtf8(string.Concat(text.Where(c => !char.IsControl(c) && char.GetUnicodeCategory(c) != UnicodeCategory.Format)).Trim(), limit).TrimEnd();
        return text.Length == 0 ? null : text;
    }

    public static Sample? Collect(JsonObject snapshot, string? lastSentDigest, string host, WorkstationPolicy policy,
        CapturedPosition? position, DateTimeOffset observed)
    {
        if (Packets.Digest(snapshot) == lastSentDigest) return null;
        var cursor = position?.CursorAfter ?? Cursor.Start("bookmark");
        var packet = CollectionPacket.Make(host, Channel, host, new JsonObject(),
            [new("snapshot_json", null, snapshot)], "not_proven", new JsonObject(), observed);
        return new(WorkstationsModule.ModuleId, host, "workstations", host, cursor, cursor, packet,
            ModuleVersion: WorkstationsModule.ModuleVersion, PolicyRevision: policy.Revision);
    }

    public static bool IsPacket(Envelope envelope, JsonObject payload) => envelope.ModuleId == WorkstationsModule.ModuleId
        && JsonRead.TryString((payload["header"] as JsonObject)?["channel"], out var channel) && channel == Channel;
}
