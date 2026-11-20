using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Server.Infrastructure;

namespace Sli.Server.Legacy;

// The retired collector cannot read events or advance collection state.
public sealed class CollectionRuntimePipeline
{
    public CollectionRuntimePipeline(IPostgresConnectionFactory connections) { }

    internal static string? Text(JsonNode? node) => node is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
    internal static long? Number(JsonNode? node)
    {
        if (JsonRead.TryInteger(node, out var number) && number >= long.MinValue && number <= long.MaxValue) return (long)number;
        return null;
    }
    private static bool Is(JsonNode? node, bool expected) => node is JsonValue v && v.TryGetValue<bool>(out var b) && b == expected;

    public static bool ChannelBackfillCompleted(JsonObject item, bool requireQueryExhaustion = false)
    {
        if (Text(item["status"]) != "completed") return false;
        if (!requireQueryExhaustion) return true;
        var continuity = item["continuity"] as JsonObject;
        return Is(continuity?["query_exhausted"], true)
            && Is(continuity?["generation_stable_during_read"], true) && Is(continuity?["truncated"], false);
    }

    public Task<JsonObject> GetCollectionPlanAsync(string server, string[] channels, CancellationToken ct)
    {
        throw new InvalidOperationException("module_disabled");
    }

    public Task UpdateCollectionStateAsync(string server, string collectionStartUtc, JsonObject summary,
        JsonObject importStats, CancellationToken ct, bool requireQueryExhaustion = false, long? jobId = null, string? traceId = null)
    {
        throw new InvalidOperationException("module_disabled");
    }
}
