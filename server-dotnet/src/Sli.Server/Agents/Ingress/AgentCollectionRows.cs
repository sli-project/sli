using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Ingress;

/// <summary>Source collection_packet_import.event_rows_from_packet; family authorization remains separate.</summary>
public static class AgentCollectionRows
{
    public static JsonArray ExtractEvents(JsonObject packet)
    {
        try
        {
            CollectionPacket.Validate(packet);
            var header=packet["header"]!.AsObject();
            var result=new JsonArray();
            foreach(var item in packet["records"]!.AsArray())
            {
                var record=item!.AsObject(); var row=record["payload"]!.AsObject();
                if (!JsonRead.TryString(record["format"],out var format) || format!="event_xml"
                    || !JsonRead.TryString(row["xml"],out _)
                    || !RecordIdsEqual(row["record_id"],record["record_id"])
                    || !JsonNode.DeepEquals(row["computer_name"],header["source"])
                    || !JsonNode.DeepEquals(row["channel"],header["channel"]))
                    throw new ArgumentException();
                result.Add(row.DeepClone());
            }
            return result;
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or ProtocolException or NullReferenceException)
        {
            throw new ProtocolException("collection_packet_event_mismatch");
        }
    }
    private static bool RecordIdsEqual(JsonNode? row, JsonNode? record)
    {
        if (JsonNode.DeepEquals(row,record)) return true;
        return row is JsonValue value && value.TryGetValue<bool>(out var flag)
            && JsonRead.TryInteger(record,out var number) && number == (flag ? 1 : 0);
    }
}