using System.Text.Json;

namespace Sli.Server.Storage.Direct;

internal sealed record EventStorageField(string Name, string[] Sources, int MaxLength);

internal sealed record EventStorageDefinition(int EventId, string Channel, string Provider, string Kind,
    string Layer, EventStorageField[] Fields)
{
    public string[]? ActorFields { get; init; }
    public string[]? ActorDomainFields { get; init; }
    public string[]? TargetFields { get; init; }
    public string[]? TargetDomainFields { get; init; }
    public string[] ReplicationRights { get; init; } = [];
    public Dictionary<string,string> Operations { get; init; } = [];
}

internal sealed record EventStorageCommon(int MaxLength, string[] ActorFields, string[] ActorDomainFields,
    string[] TargetFields, string[] TargetDomainFields, string[] SourceFields,
    string[] MethodFields, string[] OutcomeFields);

// The config is embedded just like the existing event catalogs: packaged servers
// and an eventual agent reader use the same versioned source file.
internal sealed record EventStorageMeaning(int Version, EventStorageCommon Common, EventStorageDefinition[] Events)
{
    internal static EventStorageMeaning Current { get; } = Load();

    private static EventStorageMeaning Load()
    {
        using var stream = typeof(EventStorageMeaning).Assembly.GetManifestResourceStream(
            "Sli.Server.Storage.event_storage_meanings.json")
            ?? throw new InvalidDataException("event_storage_meanings_missing");
        var result = JsonSerializer.Deserialize<EventStorageMeaning>(stream,
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower })
            ?? throw new InvalidDataException("event_storage_meanings_invalid");
        if (result.Version != 1 || result.Common.MaxLength is < 1 or > 512 ||
            result.Events.Any(e => e.EventId <= 0 || string.IsNullOrWhiteSpace(e.Channel) ||
                string.IsNullOrWhiteSpace(e.Provider) || string.IsNullOrWhiteSpace(e.Kind) ||
                e.Layer is not ("fact" or "summary" or "not_collected") ||
                e.Fields.Length > 4 || e.Fields.Any(f => string.IsNullOrWhiteSpace(f.Name) ||
                    f.Sources.Length == 0 || f.MaxLength < 1 || f.MaxLength > (e.Operations.Count>0 ? 4096 : 1024)) ||
                e.Operations.Values.Any(layer=>layer is not ("hot" or "fact" or "summary")) ||
                e.ReplicationRights.Any(g => !Guid.TryParseExact(g, "D", out _))) ||
            result.Events.DistinctBy(e => (e.EventId, e.Channel.ToUpperInvariant(), e.Provider.ToUpperInvariant())).Count() != result.Events.Length)
            throw new InvalidDataException("event_storage_meanings_invalid");
        return result;
    }

    internal EventStorageDefinition? Find(Direct4624Projection projection) => Events.FirstOrDefault(e =>
        e.EventId == projection.EventKind && e.Channel.Equals(projection.Channel, StringComparison.OrdinalIgnoreCase) &&
        e.Provider.Equals(projection.Provider, StringComparison.OrdinalIgnoreCase));
}
