using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Sli.Server.Storage.Direct;

namespace Sli.Server.Storage.History;

internal static class AgentEventPayload
{
    internal static JsonObject Verify(JsonObject summary, JsonObject retained)
    {
        try {
            if (retained["event_rows"] is not JsonArray { Count: > 0 and <= 5000 } rows || rows.Any(r=>r is not JsonObject))
                throw new InvalidDataException("agent_event_packet_rows_invalid");
            if (retained["attested_envelope"] is not JsonObject envelope || retained["attested_packet"] is not JsonObject packet ||
                Packets.Digest(envelope) != retained["envelope_sha256"]?.ToString() || envelope["packet_id"]?.ToString() != retained["packet_id"]?.ToString() ||
                Packets.Digest(packet) != envelope["payload_sha256"]?.ToString() || !JsonNode.DeepEquals(AgentCollectionRows.ExtractEvents(packet),rows))
                throw new InvalidDataException("agent_event_packet_receipt_mismatch");
            string expected = summary["normalized_hash"]!.ToString().Replace("\\x", "").ToLowerInvariant();
            var matches = rows.OfType<JsonObject>().Where(r=>RetainedEventIdentity.Legacy(r)==expected || RetainedEventIdentity.Canonical(r)==expected).ToArray();
            if (matches.Length != 1) throw new InvalidDataException("agent_event_packet_exact_identity_mismatch");
            var row = matches[0]; var data = DirectNativeEvent.Data(row);
            var items=data.Where(p=>p.Value is not null).ToDictionary(p=>p.Key,p=>p.Value!.ToString());
            string channel=row["channel"]!.GetValue<string>(), provider=row["provider_name"]?.ToString()??"";
            int kind=int.Parse(row["event_id"]!.ToString(),System.Globalization.CultureInfo.InvariantCulture);
            var profile=DirectNativeEvent.Profile(channel,provider,kind);
            var projection=new Direct4624Projection(expected,kind,items.GetValueOrDefault("LogonType"),[],items) {
                Channel=channel,Provider=provider,Normalizer=profile.Normalizer,CatalogInitiator=DirectNativeEvent.Initiator(row,items) };
            long Id(string field)=>long.Parse(summary[field]!.ToString(),System.Globalization.CultureInfo.InvariantCulture);
            string normalizedAt=summary["time_created_utc"]!.ToString();
            var source=DirectNpsArchiveRows.Event(Id("id"),Id("raw_log_file_id"),Id("server_id"),Id("domain_id"),
                summary["site_id"] is null ? null : Id("site_id"),Id("log_source_id"),DirectEventTime.Utc(normalizedAt),row,projection,normalizedAt);
            var result=(JsonObject)summary.DeepClone(); result.Remove("source_payload_state");
            foreach (var (key,value) in source) result[key]=value?.DeepClone();
            EventDetailIdentity.Verify(summary,result);
            return result;
        }
        catch (Exception error) when (error is ProtocolException or EventXmlException or ArgumentException or InvalidOperationException or NullReferenceException or FormatException) {
            throw new InvalidDataException("agent_event_packet_receipt_mismatch",error);
        }
    }
}
