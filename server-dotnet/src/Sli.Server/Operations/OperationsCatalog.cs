using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Agents.Registry;
using Sli.Server.InstallationSetup;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Operations;

public class OperationsCatalog
{
    private static readonly Regex Hostname = new(@"\A[A-Za-z0-9][A-Za-z0-9.-]{0,252}\z", RegexOptions.CultureInvariant);
    private readonly JsonArray packs = new();
    public OperationsCatalog()
    {
        var assembly = typeof(OperationsCatalog).Assembly;
        var normalizers = new SourceNormalizerRegistry(new Dictionary<string, SourceNormalizerHandlers>());
        foreach (string name in assembly.GetManifestResourceNames().Where(n => n.StartsWith("Sli.Server.Operations.Packs.", StringComparison.Ordinal)).Order(StringComparer.Ordinal))
        {
            using var stream = assembly.GetManifestResourceStream(name)!;
            using var reader = new StreamReader(stream, Encoding.UTF8);
            string raw = reader.ReadToEnd();
            packs.Add(SourcePackManifest.Load(raw, normalizers, EmbeddedCatalog));
        }
    }
    private static JsonObject EmbeddedCatalog(string reference)
    {
        string resource = reference switch
        {
            "event_catalog.json" => "Sli.Server.Semantic.Risk.event_catalog.json",
            "radius_event_catalog.json" or "file_audit_event_catalog.json" or "workstations_event_catalog.json" => "Sli.Server.Compatibility." + reference,
            _ => throw new InvalidDataException("source pack catalog is missing")
        };
        using var stream = typeof(OperationsCatalog).Assembly.GetManifestResourceStream(resource)
            ?? throw new InvalidDataException("source pack catalog is missing");
        return JsonNode.Parse(stream)!.AsObject();
    }
    internal OperationsCatalog(IEnumerable<string> manifests, SourceNormalizerRegistry normalizers, Func<string, JsonObject> catalog)
    {
        foreach (string raw in manifests) packs.Add(SourcePackManifest.Load(raw, normalizers, catalog));
        if (packs.OfType<JsonObject>().Select(p => S(p["pack_id"])).Distinct(StringComparer.Ordinal).Count() != packs.Count)
            throw new InvalidDataException("source pack ids must be unique");
    }
    public JsonArray Packs() => (JsonArray)packs.DeepClone();
    public static string ManifestSha256(ReadOnlySpan<byte> raw)
    {
        using var canonical = new MemoryStream();
        for (int i = 0; i < raw.Length; i++)
        {
            if (raw[i] == '\r' && i + 1 < raw.Length && raw[i + 1] == '\n') continue;
            canonical.WriteByte(raw[i]);
        }
        return Convert.ToHexStringLower(SHA256.HashData(canonical.ToArray()));
    }
    public JsonObject? GetPack(string packId) => packs.OfType<JsonObject>().FirstOrDefault(p => S(p["pack_id"]) == packId.Trim())?.DeepClone().AsObject();
    public static JsonObject? GetAdapter(string adapterId) => Adapters().OfType<JsonObject>().FirstOrDefault(a => S(a["adapter_id"]) == adapterId.Trim());
    public JsonArray MetadataForChannels(IEnumerable<string> channels)
    {
        var wanted = channels.Select(UnicodeCaseFold.TrimAndFold).ToHashSet(StringComparer.Ordinal);
        return new JsonArray(packs.OfType<JsonObject>()
            .Where(p => S(p["source_kind"]) == "event" && p["adapters"] is JsonArray { Count: > 0 } &&
                (p["channels"] as JsonArray ?? []).Any(c => wanted.Contains(UnicodeCaseFold.TrimAndFold(S(c)))))
            .OrderBy(p => S(p["pack_id"]), StringComparer.Ordinal).Select(p => p.DeepClone()).ToArray());
    }
    public JsonArray ValidateAdapterForChannels(string adapterId, IEnumerable<string> channels)
    {
        var metadata = MetadataForChannels(channels);
        foreach (var pack in metadata.OfType<JsonObject>())
            if (!(pack["adapters"] as JsonArray ?? []).Any(a => S(a) == adapterId))
                throw new ArgumentException($"adapter {adapterId} is not declared by source pack {S(pack["pack_id"])}");
        return metadata;
    }
    public JsonObject ValidateAdapterForPack(string adapterId, string packId)
    {
        var pack = GetPack(packId) ?? throw new ArgumentException($"unknown source pack: {packId}");
        if (GetAdapter(adapterId) is null || !(pack["adapters"] as JsonArray ?? []).Any(a => S(a) == adapterId))
            throw new ArgumentException($"adapter {adapterId} is not declared by source pack {S(pack["pack_id"])}");
        return pack;
    }
    public JsonArray PublicPacks()
    {
        var items = Packs();
        foreach (var item in items.OfType<JsonObject>()) { item.Remove("normalizer"); item.Remove("capabilities"); item.Remove("collector"); }
        return items;
    }
    public static JsonArray Adapters() => new(
        new JsonObject { ["adapter_id"] = "windows-eventlog-pywin32", ["display_name"] = "Windows Event Log via pywin32", ["transport"] = "Windows Event Log RPC", ["output_contract"] = "normalized-event-jsonl-v1" },
        new JsonObject { ["adapter_id"] = "windows-eventlog-powershell", ["display_name"] = "Windows Event Log via PowerShell", ["transport"] = "Windows Event Log RPC", ["output_contract"] = "normalized-event-jsonl-v1" },
        new JsonObject { ["adapter_id"] = "ad-context-powershell", ["display_name"] = "AD Context via repository-owned PowerShell", ["transport"] = "Active Directory read-only cmdlets", ["output_contract"] = "ad-context-bundle-v1" });

    public JsonObject Preflight(JsonObject candidate, IEnumerable<string> existing)
    {
        static string Clean(string s) => s.Trim().TrimStart('\\').TrimEnd('.');
        string Pick(params string[] keys) => keys.Select(k => S(candidate[k])).FirstOrDefault(v => v.Length > 0) ?? "";
        string hostname = Clean(Pick("hostname", "name"));
        string address = Clean(Pick("connect_address", "address", "ip") is { Length: > 0 } a ? a : hostname);
        string packId = Clean(Pick("source_pack_id") is { Length: > 0 } p ? p : "sli.windows.ad-dc");
        string adapter = Clean(Pick("adapter_id") is { Length: > 0 } x ? x : "windows-eventlog-pywin32");
        var channels = (candidate["channels"] as JsonArray ?? []).Select(x => Clean(S(x))).Where(s => s.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var issues = new JsonArray();
        void Issue(string code, string message) => issues.Add(new JsonObject { ["code"] = code, ["message"] = message });
        if (!Hostname.IsMatch(hostname) || hostname.Replace(".", "").All(char.IsDigit)) Issue("invalid_hostname", "hostname must be a DNS-safe logical controller name");
        if (address.Length == 0 || address.IndexOfAny(['\\', '/', '@', ':']) >= 0 || !(IPAddress.TryParse(address, out _) || Hostname.IsMatch(address))) Issue("invalid_connect_address", "connect_address must be a hostname or IP address");
        if (hostname.Length > 0 && existing.Any(s => s.Trim().Equals(hostname, StringComparison.OrdinalIgnoreCase))) Issue("duplicate_hostname", "hostname is already configured");
        var pack = packs.OfType<JsonObject>().FirstOrDefault(p => S(p["pack_id"]) == packId);
        if (pack is null) Issue("unknown_source_pack", "source_pack_id is not a bundled source pack");
        else
        {
            var invalid = channels.Where(c => !(pack["channels"] as JsonArray ?? []).Any(v => S(v).Equals(c, StringComparison.OrdinalIgnoreCase))).ToArray();
            if (invalid.Length > 0) Issue("unsupported_channel", $"channels are not owned by {packId}: {string.Join(", ", invalid)}");
            if (!(pack["adapters"] as JsonArray ?? []).Any(v => S(v) == adapter)) Issue("unsupported_adapter", $"adapter_id is not declared by {packId}");
        }
        if (!Adapters().Any(v => S(v?["adapter_id"]) == adapter)) Issue("unknown_adapter", "adapter_id is not a bundled source adapter");
        if (channels.Length == 0) Issue("missing_channels", "at least one explicitly selected channel is required");
        return new JsonObject { ["api_version"] = "v1", ["kind"] = "dc_onboarding_preflight", ["valid"] = issues.Count == 0,
            ["hostname"] = hostname, ["connect_address"] = address, ["source_pack_id"] = packId, ["adapter_id"] = adapter,
            ["channels"] = new JsonArray(channels.Select(c => JsonValue.Create(c)).ToArray()), ["network_actions"] = new JsonArray(),
            ["database_actions"] = new JsonArray(), ["collection_actions"] = new JsonArray(), ["issues"] = issues,
            ["next_operator_action"] = issues.Count == 0 ? "Review the plan, then explicitly add the controller to the managed configuration." : "Correct the configuration errors before any connectivity or collection check." };
    }

    internal virtual JsonArray EventEntries()
    {
        using var stream = typeof(OperationsCatalog).Assembly.GetManifestResourceStream("Sli.Server.Semantic.Risk.event_catalog.json")!;
        return JsonNode.Parse(stream)?["entries"]?.AsArray() ?? [];
    }

    public JsonObject Completeness()
    {
        try
        {
            var result = Semantic.EventCatalogQuality.Completeness(new JsonObject { ["entries"] = EventEntries().DeepClone() });
            result["status"] = "ok"; result["basis"] = "distinct_catalog_entries"; result["contains_event_payload"] = false;
            return result;
        }
        catch (Exception error)
        {
            return new() { ["status"] = "unavailable", ["basis"] = "distinct_catalog_entries", ["contains_event_payload"] = false,
                ["error_type"] = error.GetType().Name };
        }
    }
    internal static JsonObject ResourceProfile(string profileId) => PluginResourceProfiles.View(profileId);
}
