using Npgsql;
using Sli.Server.Agents.Consumer;

namespace Sli.Server.Storage.Direct;

// Prepared under agent admission; hot writes need no open inbox transaction.
internal sealed record DirectAdDcBatch(DirectRuntimeAuthorization Authorization,NpgsqlDataSource Worker,
    IReadOnlyList<DirectBatchProjection> Events,long Server,long Domain,IReadOnlyDictionary<string,short> Roles,
    Action<AdDcProjectionStep>? ReportStep,Guid PacketId,IReadOnlyList<int> PacketOrdinals,bool GenericEventLog)
{
    internal Task WriteAsync(CancellationToken ct)
    {
        ReportStep?.Invoke(AdDcProjectionStep.Publication);
        return Direct4624Publication.PublishBatchAsync(Authorization,Worker,Events,Roles,ct,ReportStep);
    }
    internal async Task FinalizeAsync(NpgsqlConnection db,NpgsqlTransaction tx,CancellationToken ct)
    {
        // A crash after hot commit retries the same identities and recreates jobs.
        ReportStep?.Invoke(AdDcProjectionStep.StateProjection);
        await DirectStateProjection.EnqueueAsync(db,tx,Events,ct);
        ReportStep?.Invoke(AdDcProjectionStep.HotEvents);
        // The inbox marker and all short layers commit together. A failed
        // admission rolls the marker back and leaves the packet retryable.
        await using var mark = new NpgsqlCommand("update sli_agent_packet_inbox set imported_at=clock_timestamp() where packet_id=@packet",db,tx);
        mark.Parameters.AddWithValue("packet",PacketId);
        if (await mark.ExecuteNonQueryAsync(ct)!=1) throw new InvalidOperationException("agent_inbox_marker_conflict");
        var rows = Events.Select((item,index) => {
            var row = ShortEventRow.Create(item.Reservation.Id,Domain,item.Row,item.Projection,Server);
            return row is null ? null : row with { PacketId=PacketId, PacketOrdinal=PacketOrdinals[index] };
        }).OfType<ShortEventRow>().ToArray();
        await ShortEventWriter.WriteAsync(db,tx,rows,ct,genericEventLog:GenericEventLog);
    }
}
