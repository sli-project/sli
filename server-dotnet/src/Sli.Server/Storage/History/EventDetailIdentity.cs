using System.Globalization;
using System.Text.Json.Nodes;

namespace Sli.Server.Storage.History;

internal static class EventDetailIdentity
{
    internal static void Verify(JsonObject core, JsonObject payload)
    {
        foreach (string field in new[] { "id", "server_id", "domain_id", "log_source_id", "event_id" })
            if (Integer(core,field) != Integer(payload,field)) throw new InvalidDataException("archive_core_identity_mismatch");
        if (Timestamp(core) != Timestamp(payload)) throw new InvalidDataException("archive_core_timestamp_mismatch");
    }
    static long Integer(JsonObject row,string field) => long.TryParse(row[field]?.ToString(),NumberStyles.Integer,CultureInfo.InvariantCulture,out var value) ? value : throw new InvalidDataException("event_core_identity_invalid");
    static DateTimeOffset Timestamp(JsonObject row) => SourceTimestamp.Parse(row["time_created_utc"]?.ToString() ?? throw new InvalidDataException("event_core_timestamp_invalid"),storageV2:true);
}
