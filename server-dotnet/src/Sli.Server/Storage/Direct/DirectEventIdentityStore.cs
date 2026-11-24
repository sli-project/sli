using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol.Compatibility;

namespace Sli.Server.Storage.Direct;

internal sealed record DirectEventReservation(long Id, byte[] NormalizedHash, bool Published);

internal static partial class DirectEventIdentityStore
{
    internal static async Task<DirectEventReservation> ReserveAsync(DirectRuntimeAuthorization authorization,
        NpgsqlDataSource workerDataSource, long serverId, int channelId, long recordId, DateTime timeUtc,
        JsonObject sourceRow, string identityHash, CancellationToken ct) =>
        (await ReserveBatchAsync(authorization,workerDataSource,serverId,
            [new(channelId,recordId,timeUtc,sourceRow,identityHash)],ct))[0];
    internal static string RepresentationDigest(JsonObject row) => Convert.ToHexStringLower(
        System.Security.Cryptography.SHA256.HashData(new System.Text.UTF8Encoding(false, true).GetBytes(SourceJson.SerializeSorted(row))));

}
