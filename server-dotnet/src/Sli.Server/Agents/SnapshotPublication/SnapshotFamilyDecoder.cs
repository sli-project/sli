using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.SnapshotPublication;

// Called inside the publication savepoint after transport has been validated.
public static class SnapshotFamilyDecoder
{
    public static IReadOnlyDictionary<string, JsonObject> Decode(SnapshotTransport transport)
    {
        try
        {
            var output = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
            foreach (var (family, bytes) in transport.Families)
            {
                var document=family == "computers_v6" ? ComputersSnapshotValidation.Parse(bytes)
                    : JsonNode.Parse(bytes) as JsonObject ?? throw new InvalidDataException();
                string key=family == "computers_v6" ? "objects" : family == "gpo_v2" ? "gpos" : "records";
                var declaration=transport.Rows.First(r => r.Payload["family"]!.GetValue<string>() == family).Payload["total_objects"]!.GetValue<int>();
                if (document[key] is not JsonArray array || array.Count != declaration) throw new InvalidDataException();
                output.Add(family,document);
            }
            return output;
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or ArgumentException or NullReferenceException or InvalidDataException)
        { throw new ProtocolException("agent_snapshot_object_count_mismatch"); }
    }
}
