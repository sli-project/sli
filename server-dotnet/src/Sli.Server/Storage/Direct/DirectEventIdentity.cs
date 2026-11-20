using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Sli.Agent.Core;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Storage.Direct;

// Frozen event_source_identity.canonical_identity after native packet attestation.
internal static class DirectEventIdentity
{
    internal static string Hash(JsonObject row)
    {
        try
        {
            string xml = row["xml"]!.GetValue<string>();
            string source = row["computer_name"]!.GetValue<string>();
            string address = row["connect_address"]!.GetValue<string>();
            if (!JsonNode.DeepEquals(row, EventXml.Parse(xml, source, address, row["channel"]!.GetValue<string>()))) throw new InvalidDataException();
            var root = EventXml.ParseBounded(xml);
            XNamespace ns = EventXml.Namespace;
            var sys = root.Element(ns + "System") ?? throw new InvalidDataException();
            // Intake turns invalid optional integers into null. Source identity
            // falls back to XML and rejects them instead of treating them as absent.
            foreach (string tag in new[] { "Version", "Level", "Task", "Opcode" })
                if (DirectNativeEvent.Text(sys.Element(ns + tag)) is { } text && !PythonInt.TryParse(text, out _))
                    throw new InvalidDataException("storage_v2_event_profile_pending");
            // Native row attestation above is the source contract. The Python
            // importer has no Event ID or XML-shape allowlist after admission.
            var xmlChannel = DirectNativeEvent.Text(sys.Element(ns + "Channel"));
            if (xmlChannel is not null && xmlChannel != row["channel"]?.GetValue<string>())
                throw new InvalidDataException("storage_v2_event_profile_pending");
            string time = row["time_created"]!.GetValue<string>();
            string normalizedTime = DirectEventTime.IsoUtc(time);
            string? machine = row["machine_name"]?.GetValue<string>() is {Length:>0} nativeMachine ? nativeMachine : source;
            string? providerGuid = (string?)sys.Element(ns + "Provider")?.Attribute("Guid");
            JsonNode? keywords = null;
            if (row["keywords"] is JsonValue keywordValue)
            {
                var text = keywordValue.GetValue<string>();
                var number=text.StartsWith("0x",StringComparison.OrdinalIgnoreCase)
                    ? BigInteger.Parse("0"+text[2..],NumberStyles.HexNumber,CultureInfo.InvariantCulture)
                    : BigInteger.Parse(text,NumberStyles.Integer,CultureInfo.InvariantCulture);
                keywords=JsonNode.Parse(number.ToString(CultureInfo.InvariantCulture));
            }
            var system = new JsonObject {
                ["record_id"] = row["record_id"]!.DeepClone(), ["event_id"] = row["event_id"]!.DeepClone(),
                ["version"] = row["version"]?.DeepClone(), ["level"] = row["level"]?.DeepClone(),
                ["task"] = row["task"]?.DeepClone(), ["opcode"] = row["opcode"]?.DeepClone(),
                ["keywords"] = keywords, ["provider_name"] = row["provider_name"]?.DeepClone(),
                ["provider_guid"] = providerGuid is null ? null : UnicodeCaseFold.Fold(providerGuid), ["time_created"] = normalizedTime,
                ["channel"] = row["channel"]!.DeepClone(), ["user_id"] = row["user_id"]?.DeepClone(),
                ["machine_name"] = UnicodeCaseFold.Fold(machine),
            };
            var identity = new JsonObject { ["version"] = 2, ["system"] = system, ["extra"] = new JsonObject() };
            return Convert.ToHexStringLower(SHA256.HashData(new UTF8Encoding(false, true).GetBytes(SourceJson.SerializeSorted(identity))));
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or NullReferenceException or FormatException or EventXmlException)
        { throw new InvalidDataException("storage_v2_event_profile_pending", e); }
    }
}
