using System.Text.Json;

namespace Sli.Server.Access;

// Route-relevant authority facts, loaded only by the PostgreSQL repository.
public sealed record AccessFacts(bool IsOwner, string Role,
    IReadOnlyList<JsonElement> Packages, IReadOnlyList<JsonElement> PackageCapabilities,
    IReadOnlyList<JsonElement> DirectCapabilities, IReadOnlyList<JsonElement> AllCapabilities,
    IReadOnlyList<JsonElement> PackageReports, IReadOnlyList<JsonElement> ReportAssignments,
    IReadOnlyList<JsonElement> Definitions)
{
    public IReadOnlyList<JsonElement> Groups { get; init; } = [];
    public IReadOnlyList<JsonElement> Requests { get; init; } = [];
    public IReadOnlyList<JsonElement> Preferences { get; init; } = [];
    public DateTime EvaluatedAt { get; init; }
    // The declaration capture used for this evaluation, not a second source of grants.
    public ReportCatalogSnapshot? ReportCatalog { get; init; }
}

internal static class FactJson
{
    public static string Text(this JsonElement value, string key, string fallback = "") =>
        value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var item)
            && item.ValueKind == JsonValueKind.String ? item.GetString()! : fallback;
    public static JsonElement Get(this JsonElement value, string key) =>
        value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var item) ? item : default;
    public static IEnumerable<JsonElement> Items(this JsonElement value) =>
        value.ValueKind == JsonValueKind.Array ? value.EnumerateArray() : [];
    public static HashSet<string> Strings(this JsonElement value) =>
        value.Items().Where(i => i.ValueKind == JsonValueKind.String).Select(i => i.GetString()!).ToHashSet(StringComparer.Ordinal);
    public static JsonElement Object(this JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.String && value.GetString() != "")
        {
            using var parsed = JsonDocument.Parse(value.GetString()!);
            return parsed.RootElement.ValueKind == JsonValueKind.Object ? parsed.RootElement.Clone() : default;
        }
        return value.ValueKind == JsonValueKind.Object ? value : default;
    }
}
