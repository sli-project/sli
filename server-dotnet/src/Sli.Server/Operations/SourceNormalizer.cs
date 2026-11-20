using System.Text.Json.Nodes;

namespace Sli.Server.Operations;

// Native handlers supplied by installed code, never loaded from a manifest path.
internal sealed record SourceNormalizerHandlers
{
    internal Func<JsonObject, JsonObject>? EventFacts { get; init; }
    internal Func<JsonObject, JsonNode?>? EntitySemantics { get; init; }
    internal Func<int, string, string?>? EventLabel { get; init; }
    internal Func<JsonObject> FindingRules { get; init; } = () => new();
    internal Func<string, IReadOnlyList<int>> EventIdsForSearchFamily { get; init; } = _ => [];
    internal Func<int, string> InvestigationCategory { get; init; } = _ => "other";
    internal Func<JsonObject, string?> CorrelationId { get; init; } = _ => null;
    internal Func<string, IReadOnlyList<string>, JsonObject, JsonArray?> SemanticCoreRoleFilters { get; init; } = (_, _, _) => null;
}

internal sealed record SourceNormalizer(string NormalizerId, SourceNormalizerHandlers Handlers);

internal sealed class SourceNormalizerRegistry(IReadOnlyDictionary<string, SourceNormalizerHandlers> installedEntries)
{
    private readonly Dictionary<string, SourceNormalizer> entries = new(StringComparer.Ordinal);
    // These identities belong to the existing native bundled pipelines.
    internal static readonly IReadOnlySet<string> BundledIds = new HashSet<string>(StringComparer.Ordinal)
    {
        "windows-ad-dc-v1", "windows-nps-radius-v1", "windows-file-audit-v1", "windows-workstations-v1"
    };

    internal SourceNormalizer LoadEntry(string id, string entry)
    {
        int separator = entry.IndexOf(':');
        string module = separator < 0 ? "" : entry[..separator];
        if (separator <= 0 || separator == entry.Length - 1 ||
            !(module.StartsWith("server.source_packs.", StringComparison.Ordinal) || module.StartsWith("sli_source_packs.", StringComparison.Ordinal)))
            throw new InvalidDataException("normalizer entry is not allowed");
        if (!installedEntries.TryGetValue(entry, out var handlers))
            throw new InvalidDataException("normalizer entry is not installed");
        if (handlers.EventFacts is null) throw Missing("event_facts");
        if (handlers.EntitySemantics is null) throw Missing("entity_semantics");
        if (handlers.EventLabel is null) throw Missing("event_label");
        return new(id, handlers);

        InvalidDataException Missing(string name) => new($"normalizer {id} lacks required handler: {name}");
    }

    internal void Register(SourceNormalizer normalizer)
    {
        if (BundledIds.Contains(normalizer.NormalizerId))
            throw new InvalidDataException("normalizer id is reserved by a bundled pack");
        entries[normalizer.NormalizerId] = normalizer;
    }

    internal SourceNormalizer? Get(string? id) => entries.GetValueOrDefault(id?.Trim() ?? "");
    internal bool IsKnown(string id) => BundledIds.Contains(id) || Get(id) is not null;
}
