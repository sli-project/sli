using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Sli.Agent.Core;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Storage.Direct;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Storage.History;

// event_source_identity: retained Python rows may predate the full native .NET row shape.
internal static class RetainedEventIdentity
{
    internal static string Legacy(JsonObject row) => Digest(row);
    static string Digest(JsonNode value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(SourceJson.SerializeSorted(value))));
    internal static string Canonical(JsonObject row)
    {
        XNamespace ns = EventXml.Namespace;
        var system = row["xml"] is null ? null : EventXml.ParseBounded(row["xml"]!.GetValue<string>()).Element(ns + "System");
        var values = new JsonObject();
        foreach (var (field, tag, attribute) in new (string,string,string?)[] {
            ("record_id","EventRecordID",null),("event_id","EventID",null),("version","Version",null),
            ("level","Level",null),("task","Task",null),("opcode","Opcode",null),("keywords","Keywords",null),
            ("provider_name","Provider","Name"),("provider_guid","Provider","Guid"),("time_created","TimeCreated","SystemTime"),
            ("channel","Channel",null),("user_id","Security","UserID"),("machine_name","Computer",null) })
        {
            var element = system?.Element(ns + tag);
            JsonNode? native = attribute is null ? JsonValue.Create(DirectNativeEvent.Text(element)) : JsonValue.Create((string?)element?.Attribute(attribute));
            JsonNode? value = row[field];
            if (field == "machine_name" && string.IsNullOrEmpty(value?.ToString())) value = native ?? row["computer_name"];
            JsonNode? Normalize(JsonNode? item)
            {
                if (item is null) return null;
                string text = item.ToString();
                if (field is "record_id" or "event_id" or "version" or "level" or "task" or "opcode" or "keywords") {
                    var number = field == "keywords" && text.StartsWith("0x",StringComparison.OrdinalIgnoreCase)
                        ? BigInteger.Parse("0"+text[2..],NumberStyles.HexNumber,CultureInfo.InvariantCulture)
                        : BigInteger.Parse(text,CultureInfo.InvariantCulture);
                    return JsonNode.Parse(number.ToString(CultureInfo.InvariantCulture));
                }
                return JsonValue.Create(field == "time_created" ? DirectEventTime.IsoUtc(text)
                    : field is "machine_name" or "provider_guid" ? UnicodeCaseFold.Fold(text) : text);
            }
            if (value is not null && native is not null && !JsonNode.DeepEquals(Normalize(value),Normalize(native)))
                throw new InvalidDataException("agent_event_packet_identity_mismatch");
            values[field] = Normalize(value ?? native);
        }
        var excluded = values.Select(p=>p.Key).Concat(new[] { "xml","properties","message","time_created_local","computer_name",
            "connect_address","transport_address","collector_host","collector_version","collected_at","collection_timestamp","collection_id" }).ToHashSet();
        var extra = new JsonObject();
        foreach (var (key,value) in row) if (!excluded.Contains(key)) extra[key] = value?.DeepClone();
        return Digest(new JsonObject { ["version"]=2,["system"]=values,["extra"]=extra });
    }
}
