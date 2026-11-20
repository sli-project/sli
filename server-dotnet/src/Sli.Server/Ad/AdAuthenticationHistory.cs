using System.Text.Json.Nodes;
using Npgsql;

namespace Sli.Server.Ad;

internal static class AdAuthenticationHistory
{
    internal static async Task<(List<JsonObject> Events,List<JsonObject> Bounds,bool Truncated)> ReadAsync(
        NpgsqlConnection db, long domain, long[] servers, DateTimeOffset start, DateTimeOffset end, CancellationToken ct,
        IConfiguration? config=null)
    {
        return (await AdAccountEvents.ReadLogonsAsync(db, domain, servers, new(start,end), ct, config), [], false);
    }
}
