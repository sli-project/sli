using System.Text;
using System.Xml.Linq;

namespace Sli.Agent.Core;

public static class NpsEventXml
{
    private static readonly XNamespace Ns = EventXml.Namespace;
    private static readonly HashSet<string> Fields = ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "FullyQualifiedSubjectUserName",
        "SubjectMachineSID", "SubjectMachineName", "FullyQualifiedSubjectMachineName", "CalledStationID", "CallingStationID", "NASIPv4Address", "NASIPv6Address",
        "NASIdentifier", "NASPortType", "NASPort", "ClientName", "ClientIPAddress", "ProxyPolicyName", "NetworkPolicyName", "AuthenticationProvider", "AuthenticationServer",
        "AuthenticationType", "EAPType", "AccountSessionIdentifier", "LoggingResult", "ReasonCode", "Reason"];

    public static string Mask(string raw)
    {
        var root = EventXml.ParseBounded(raw);
        var changed = false;
        void Drop(XElement item) { while (item.NextNode is XText tail) tail.Remove(); item.Remove(); changed = true; }
        foreach (var child in root.Elements().ToArray())
        {
            if (child.Name != Ns + "System" && child.Name != Ns + "EventData") Drop(child);
            else if (child.Name == Ns + "EventData")
            {
                var seen = new HashSet<string?>();
                foreach (var field in child.Elements().ToArray())
                {
                    var name = field.Attribute("Name")?.Value;
                    if (!seen.Add(name)) throw new AgentException("agent_nps_duplicate_field");
                    if (field.Name != Ns + "Data" || name is null || !Fields.Contains(name)) Drop(field);
                }
            }
        }
        return changed ? Serialize(root) : raw;
    }

    // ElementTree prefix allocation, whitespace/tails, empty tags and attribute escaping are wire data.
    private static string Serialize(XElement root)
    {
        var namespaces = new Dictionary<string, string>();
        void Register(XName name)
        {
            if (name.NamespaceName.Length > 0 && name.Namespace != XNamespace.Xml && !namespaces.ContainsKey(name.NamespaceName))
                namespaces[name.NamespaceName] = "ns" + namespaces.Count;
        }
        foreach (var element in root.DescendantsAndSelf())
        {
            Register(element.Name);
            foreach (var a in element.Attributes().Where(a => !a.IsNamespaceDeclaration)) Register(a.Name);
        }
        string QName(XName name) => name.NamespaceName.Length == 0 ? name.LocalName : (name.Namespace == XNamespace.Xml ? "xml" : namespaces[name.NamespaceName]) + ":" + name.LocalName;
        static string Escape(string s) => s.Replace("&", "&amp;", StringComparison.Ordinal).Replace("<", "&lt;", StringComparison.Ordinal).Replace(">", "&gt;", StringComparison.Ordinal);
        static string Attribute(string s) => Escape(s).Replace("\"", "&quot;", StringComparison.Ordinal).Replace("\t", "&#09;", StringComparison.Ordinal).Replace("\n", "&#10;", StringComparison.Ordinal).Replace("\r", "&#13;", StringComparison.Ordinal);
        var text = new StringBuilder();
        void Write(XElement element, bool first = false)
        {
            var name = QName(element.Name);
            text.Append('<').Append(name);
            if (first) foreach (var p in namespaces.OrderBy(p => p.Value, StringComparer.Ordinal)) text.Append(" xmlns:").Append(p.Value).Append("=\"").Append(Attribute(p.Key)).Append('"');
            foreach (var a in element.Attributes().Where(a => !a.IsNamespaceDeclaration)) text.Append(' ').Append(QName(a.Name)).Append("=\"").Append(Attribute(a.Value)).Append('"');
            if (!element.Nodes().Any()) { text.Append(" />"); return; }
            text.Append('>');
            foreach (var node in element.Nodes()) { if (node is XElement child) Write(child); else if (node is XText t) text.Append(Escape(t.Value)); }
            text.Append("</").Append(name).Append('>');
        }
        Write(root, true);
        return text.ToString();
    }
}
