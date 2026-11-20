using System.Text.Json.Nodes;
using Sli.Server.Semantic;

namespace Sli.Server.Legacy;

// Cursor commits belong to the agent importer; the retired collector is disabled.
public sealed class LegacyPartialTimeoutWatermark
{
    public LegacyPartialTimeoutWatermark(ISemanticDatabase database) { }

    public Task CommitAsync(string server, string archiveStartUtc, string collectionStartUtc,
        JsonObject channel, long inserted, long skipped, CancellationToken ct, long? jobId = null, string? traceId = null)
    {
        throw new InvalidOperationException("module_disabled");
    }

    private static long? Record(JsonNode? row, string key) => row?[key] is null ? null : row.Number(key);
}
