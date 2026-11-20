using System.Text.Json.Nodes;
using Sli.Server.Semantic;

namespace Sli.Server.Legacy;

public sealed partial class LegacyFindings
{
    public Task<JsonObject> EnsureAsync(bool bootstrapToCurrent,CancellationToken ct)
    {
        return Task.FromResult(Disabled());
    }
    public Task<JsonObject> StatusAsync(CancellationToken ct)
    {
        return Task.FromResult(Disabled());
    }
    internal static Task<JsonObject> ReadStatusAsync(Func<string,CancellationToken,Task<JsonArray>> query,CancellationToken ct)
    {
        return Task.FromResult(Disabled());
    }
}
