using System.Text.Json.Nodes;
using Sli.Server.Storage.EventReports;

namespace Sli.Server.Compatibility;

public interface ILegacyHttpReader
{
    Task<JsonObject> ReadAsync(string path, LegacyQuery query, CancellationToken ct);
}

// Retained for old bookmarks and in-process callers. Event detail has one owner;
// retired searches and off-beta modules cannot reopen the removed event stores.
internal sealed class LegacyHttpReader : ILegacyHttpReader
{
    readonly IEventReadService events;
    readonly ILogger<LegacyHttpReader> logger;
    public LegacyHttpReader(IEventReadService events, ILogger<LegacyHttpReader> logger)
    { this.events = events; this.logger = logger; }

    internal static JsonObject Provenance() => new() { ["source"] = "ai", ["authority"] = "draft_only", ["confidence"] = "not_applicable" };
    static long Number(JsonNode? obj, string key) => LegacySemantics.Number(obj, key);
    static JsonArray Array(IEnumerable<JsonObject> items) => new(items.Select(o => (JsonNode?)o.DeepClone()).ToArray());
    public Task<JsonObject> ReadAsync(string path, LegacyQuery query, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return path == "/api/events/details" ? EventDetails(query, ct)
            : throw new LegacyInputException("module_disabled", 503);
    }
    async Task<bool> Exists(long id, CancellationToken ct) => (await events.ResourcesAsync(id, ct)).Count > 0;
    async Task<JsonObject> EventDetails(LegacyQuery query, CancellationToken ct)
    {
        long id = Number(query.Filters, "event_db_id");
        if (id <= 0) throw new InvalidOperationException("storage_v2_detail_requires_exact_event_id");
        if (!await Exists(id, ct)) throw new InvalidDataException("event_not_found");
        var found = await events.DetailsAsync([id], true, Exists, ct);
        if (!found.TryGetValue(id, out var row)) throw new InvalidDataException("event_not_found");
        logger.LogInformation("event_detail_report_requested event_db_id={Id}", id);
        return new() { ["filters"] = query.Filters.DeepClone(), ["total"] = 1, ["items"] = Array([row]) };
    }
}

