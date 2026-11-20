using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sli.Server.Operations;

// Port of source_packs.registry._load_manifest for native entry-point packs.
internal static class SourcePackManifest
{
    internal static JsonObject Load(string raw, SourceNormalizerRegistry normalizers, Func<string, JsonObject> catalog)
    {
        JsonObject data;
        try { data = JsonNode.Parse(raw) as JsonObject ?? throw new InvalidDataException("invalid source pack manifest"); }
        catch (JsonException error) { throw new InvalidDataException("invalid source pack manifest", error); }
        string schema = Text(data["schema_version"]);
        if (schema is not ("1" or "2")) throw new InvalidDataException("unsupported source pack manifest schema");
        foreach (string key in new[] { "pack_id", "version", "display_name", "entity_contract", "analysis_contract" }) Required(data, key);
        string kind = Text(data["source_kind"]).ToLowerInvariant();
        if (kind.Length == 0) kind = "event";
        if (kind is not ("event" or "context")) throw new InvalidDataException("unsupported source_kind");
        var channels = kind == "event" ? TextList(data, "channels") : new JsonArray();
        var sections = kind == "context" ? TextList(data, "sections") : new JsonArray();
        var adapters = schema == "2" && (data["adapters"] is null || data["adapters"] is JsonArray { Count: 0 })
            ? new JsonArray() : TextList(data, "adapters");
        foreach (var adapter in adapters)
            if (!OperationsCatalog.Adapters().Any(a => Text(a?["adapter_id"]) == Text(adapter)))
                throw new InvalidDataException("source pack declares unknown adapters");
        if (kind == "event")
        {
            string reference = Required(data, "event_catalog");
            if (Path.IsPathRooted(reference) || reference.Split('/', '\\').Any(p => p == ".."))
                throw new InvalidDataException("source pack path escapes config directory");
            var content = catalog(reference);
            if (content["entries"] is not JsonArray records) throw new InvalidDataException("source pack catalog requires entries");
            var identities = new HashSet<(string, string, string)>();
            foreach (var record in records.OfType<JsonObject>())
            {
                string channel = Text(record["stream"] ?? record["channel"]), provider = Text(record["provider_name"]), key = Text(record["event_key"] ?? record["event_id"]);
                if (channel.Length == 0 || provider.Length == 0 || key.Length == 0) throw new InvalidDataException("source pack catalog has incomplete event identity");
                if (!identities.Add((channel.ToLowerInvariant(), provider.ToLowerInvariant(), key.ToLowerInvariant()))) throw new InvalidDataException("source pack catalog has duplicate event identity");
            }
            string id = Required(data, "normalizer"), entry = Text(data["normalizer_entry"]);
            if (entry.Length > 0)
            {
                if (schema != "2") throw new InvalidDataException("normalizer_entry requires schema_version 2");
                // This exact bundled entry already runs in the native workstation
                // pipeline. Any other target still goes through registration and
                // cannot replace a bundled identity.
                bool nativeWorkstations = id == "windows-workstations-v1" && entry == "server.source_packs.windows_workstations:normalizer_namespace";
                try { if (!nativeWorkstations) normalizers.Register(normalizers.LoadEntry(id, entry)); }
                catch (InvalidDataException error) { throw new InvalidDataException("normalizer entry failed: " + error.Message, error); }
            }
            if (!normalizers.IsKnown(id)) throw new InvalidDataException("source pack declares unknown normalizer");
        }
        var result = PublicMetadata(raw, data);
        result["source_kind"] = kind;
        result["channels"] = channels;
        result["sections"] = sections;
        result["adapters"] = adapters;
        return result;
    }

    internal static JsonObject PublicMetadata(string raw, JsonObject data)
    {
        var result = new JsonObject();
        foreach (string key in new[] { "pack_id", "version", "display_name", "source_kind", "channels", "sections", "adapters", "entity_contract", "analysis_contract", "normalizer" }) result[key] = data[key]?.DeepClone();
        result["source_kind"] = Text(data["source_kind"]) is { Length: > 0 } kind ? kind : "event";
        result["channels"] = Text(result["source_kind"]) == "event" ? data["channels"]?.DeepClone() ?? new JsonArray() : new JsonArray();
        result["sections"] = Text(result["source_kind"]) == "context" ? data["sections"]?.DeepClone() ?? new JsonArray() : new JsonArray();
        result["adapters"] = data["adapters"]?.DeepClone() ?? new JsonArray();
        result["manifest_sha256"] = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(raw.Replace("\r\n", "\n"))));
        if (data["capabilities"] is JsonArray capabilities)
        {
            var cleaned = new JsonArray(capabilities.Select(Text).Where(s => s.Length > 0).Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
            if (cleaned.Count > 0) result["capabilities"] = cleaned;
        }
        if (data["collector"] is JsonObject collector) result["collector"] = new JsonObject { ["kind"] = collector["kind"]?.DeepClone(), ["entry"] = collector["entry"]?.DeepClone() };
        return result;
    }

    private static string Text(JsonNode? value) => value?.ToString().Trim() ?? "";
    private static string Required(JsonObject data, string key) => Text(data[key]) is { Length: > 0 } value ? value : throw new InvalidDataException("source pack requires " + key);
    private static JsonArray TextList(JsonObject data, string key)
    {
        if (data[key] is not JsonArray { Count: > 0 } values) throw new InvalidDataException("source pack requires non-empty " + key);
        string[] cleaned = values.Select(Text).Where(s => s.Length > 0).ToArray();
        if (cleaned.Length == 0 || cleaned.Distinct(StringComparer.OrdinalIgnoreCase).Count() != cleaned.Length) throw new InvalidDataException("source pack has invalid " + key);
        return new JsonArray(cleaned.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
    }
}
