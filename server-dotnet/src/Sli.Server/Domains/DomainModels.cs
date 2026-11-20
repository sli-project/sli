using System.Text.Json.Serialization;

namespace Sli.Server.Domains;

public sealed record DomainFreshness(
    [property: JsonPropertyName("snapshot_at_utc")] string? SnapshotAtUtc,
    [property: JsonPropertyName("published_at_utc")] string? PublishedAtUtc,
    [property: JsonPropertyName("snapshot_state")] string? SnapshotState,
    [property: JsonPropertyName("observed_at_utc")] string? ObservedAtUtc,
    [property: JsonPropertyName("default_observed_at_utc")] string? DefaultObservedAtUtc,
    [property: JsonPropertyName("event_at_utc")] string? EventAtUtc,
    [property: JsonPropertyName("last_successful_collection_utc")] string? LastSuccessfulCollectionUtc);

public sealed record DomainItem(
    [property: JsonPropertyName("id")] long Id,
    [property: JsonPropertyName("display_name")] string DisplayName,
    [property: JsonPropertyName("is_archived")] bool IsArchived,
    [property: JsonPropertyName("freshness")] DomainFreshness Freshness);

public sealed record DomainResponse([property: JsonPropertyName("items")] IReadOnlyList<DomainItem> Items);
