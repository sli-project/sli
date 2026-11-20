using System.Numerics;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml;
using System.Xml.Linq;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

/// <summary>An event XML the agent refuses to parse (size, depth, DTD, malformed). Fixed code only.</summary>
public sealed class EventXmlException(string code) : AgentException(code);

/// <summary>
/// The twin of <c>sli_collect/eventlog.py: parse_event_xml</c> and <c>server/sli/storage/xml_safety.py</c>.
/// The server parses the signed XML again and requires the whole row to be equal, so every field is derived by the same rule.
/// </summary>
public static class EventXml
{
    public const string Namespace = "http://schemas.microsoft.com/win/2004/08/events/event";
    public const int MaxBytes = 4 * 1024 * 1024;
    public const int MaxDepth = 64;
    public const int MaxNodes = 100_000;

    private static readonly XNamespace Ns = Namespace;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>Bounded, DTD-free parse. Comments and processing instructions are dropped, as ElementTree does.</summary>
    public static XElement ParseBounded(string xml)
    {
        byte[] bytes;
        try
        {
            bytes = StrictUtf8.GetBytes(xml);
        }
        catch (EncoderFallbackException)
        {
            throw new EventXmlException("xml_not_utf8");
        }
        if (bytes.Length > MaxBytes) throw new EventXmlException("xml_size_limit_exceeded");
        if (ContainsIgnoreCase(bytes, "<!DOCTYPE"u8) || ContainsIgnoreCase(bytes, "<!ENTITY"u8)) throw new EventXmlException("xml_dtd_or_entity_forbidden");
        try
        {
            Scan(xml);
            using var reader = XmlReader.Create(new StringReader(xml), Settings());
            return XDocument.Load(reader, LoadOptions.PreserveWhitespace).Root ?? throw new EventXmlException("xml_malformed");
        }
        catch (XmlException)
        {
            throw new EventXmlException("xml_malformed");
        }
    }

    private static XmlReaderSettings Settings() => new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        IgnoreComments = true,
        IgnoreProcessingInstructions = true,
        IgnoreWhitespace = false,
        MaxCharactersFromEntities = 0,
    };

    private static void Scan(string xml)
    {
        using var reader = XmlReader.Create(new StringReader(xml), Settings());
        var nodes = 0;
        while (reader.Read())
        {
            if (reader.NodeType != XmlNodeType.Element) continue;
            if (++nodes > MaxNodes) throw new EventXmlException("xml_node_limit_exceeded");
            if (reader.Depth + 1 > MaxDepth) throw new EventXmlException("xml_depth_limit_exceeded");
        }
    }

    private static bool ContainsIgnoreCase(byte[] haystack, ReadOnlySpan<byte> upperNeedle)
    {
        for (var i = 0; i + upperNeedle.Length <= haystack.Length; i++)
        {
            var match = true;
            for (var j = 0; j < upperNeedle.Length && match; j++)
            {
                var b = haystack[i + j];
                if (b is >= (byte)'a' and <= (byte)'z') b -= 32;
                match = b == upperNeedle[j];
            }
            if (match) return true;
        }
        return false;
    }

    /// <summary>ElementTree's <c>.text</c>: the text before the first child element; absent when there is none.</summary>
    private static string? TextOf(XElement? element)
    {
        if (element is null) return null;
        StringBuilder? builder = null;
        foreach (var node in element.Nodes())
        {
            if (node is XElement) break;
            if (node is XText text) (builder ??= new StringBuilder()).Append(text.Value);
        }
        return builder?.ToString();
    }

    private static XElement? SystemChild(XElement root, string name) =>
        root.Descendants(Ns + "System").SelectMany(system => system.Elements(Ns + name)).FirstOrDefault();

    private static JsonNode? Integer(string? text) => PythonInt.TryParse(text, out var value) ? JsonRead.Integer(value) : null;

    /// <summary>The value of <c>System/Channel</c> as a direct child path <c>e:System/e:Channel</c> of the root, or null.</summary>
    public static string? NativeChannel(XElement root) => TextOf(root.Element(Ns + "System")?.Element(Ns + "Channel"));

    public static JsonObject Parse(string xml, string sourceName, string connectAddress, string channel)
    {
        var root = ParseBounded(xml);
        var properties = new JsonArray();
        foreach (var data in root.Descendants(Ns + "EventData").SelectMany(item => item.Elements(Ns + "Data")))
            properties.Add(TextOf(data));
        return new JsonObject
        {
            ["computer_name"] = sourceName,
            ["connect_address"] = connectAddress,
            ["channel"] = channel,
            ["provider_name"] = SystemChild(root, "Provider")?.Attribute("Name")?.Value,
            ["event_id"] = Integer(TextOf(SystemChild(root, "EventID"))),
            ["version"] = Integer(TextOf(SystemChild(root, "Version"))),
            ["level"] = Integer(TextOf(SystemChild(root, "Level"))),
            ["task"] = Integer(TextOf(SystemChild(root, "Task"))),
            ["opcode"] = Integer(TextOf(SystemChild(root, "Opcode"))),
            ["keywords"] = TextOf(SystemChild(root, "Keywords")),
            ["record_id"] = Integer(TextOf(SystemChild(root, "EventRecordID"))),
            ["time_created"] = SystemChild(root, "TimeCreated")?.Attribute("SystemTime")?.Value,
            ["machine_name"] = TextOf(SystemChild(root, "Computer")),
            ["user_id"] = SystemChild(root, "Security")?.Attribute("UserID")?.Value,
            ["message"] = null,
            ["properties"] = properties,
            ["xml"] = xml,
        };
    }
}
