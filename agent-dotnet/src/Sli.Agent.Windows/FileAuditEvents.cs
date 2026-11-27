using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;

namespace Sli.Agent.Windows;

public interface IFileAuditEventSource
{
    SourceBatch Read(JsonObject progress, int limit);
}
public sealed class FileAuditJournalGap() : AgentException("file_audit_journal_gap");

internal static class FileAuditEvents
{
    private static readonly XNamespace Ns = EventXml.Namespace;
    private static readonly HashSet<string> Fields = ["SubjectUserSid","SubjectLogonId","TargetUserSid","TargetLogonId","LogonType","ObjectName","ObjectType","HandleId","ProcessId","ProcessName","AccessMask","AccessList","AccessReason","ShareName","ShareLocalPath","RelativeTargetName","IpAddress","IpPort","OldSd","NewSd","OldSdValue","NewSdValue","ObjectServer","PrivilegeList"];
    private static readonly HashSet<string> Technical = ["SubjectUserSid","SubjectLogonId","TargetUserSid","TargetLogonId","LogonType","HandleId","ProcessId","AccessMask","IpAddress","IpPort"];
    public static (JsonObject Row, Dictionary<string,string> Data) Parse(string raw, string host)
    {
        var root = EventXml.ParseBounded(raw);
        if (root.Name != Ns + "Event" || EventXml.NativeChannel(root) != "Security") throw new AgentException("file_audit_channel_invalid");
        var data = new Dictionary<string,string>();
        foreach (var item in root.Elements(Ns + "EventData").Elements(Ns + "Data"))
            if (!data.TryAdd(item.Attribute("Name")?.Value ?? "", string.Concat(item.Nodes().TakeWhile(n => n is not XElement).OfType<XText>().Select(t => t.Value)))) throw new AgentException("file_audit_duplicate_field");
        return (EventXml.Parse(raw, host, "localhost", "Security"), data);
    }
    public static (bool Allowed, JsonObject[] Scopes, string? Path) Admit(JsonObject row, Dictionary<string,string> data, FileAuditPolicy p)
    {
        var id = row["event_id"]?.GetValue<int>() ?? -1;
        var provider = id == 1102 ? "Microsoft-Windows-Eventlog" : FileAuditPolicy.Provider;
        var known = p.Workstation
            ? FileAuditPolicy.Events.Contains(id) || FileAuditPolicy.ContextEvents.Contains(id) || p.OptionalEvents && id is 4658 or 4664
            : p.IsServerFileEvent(id);
        if (row["provider_name"]?.ToString() != provider || !known) return (false, [], null);
        string? path = null;
        JsonObject[] scopes = [];
        if (!FileAuditPolicy.ContextEvents.Contains(id) && id != 4660)
        {
            var share = data.GetValueOrDefault("ShareName", "").Split('\\').Last();
            path = data.GetValueOrDefault("ObjectName");
            if (string.IsNullOrEmpty(path)) path = data.GetValueOrDefault("ShareLocalPath");
            if (path?.StartsWith(@"\??\",StringComparison.Ordinal) == true) path = path[4..];
            try
            {
                if (!string.IsNullOrEmpty(path))
                {
                    path = FileAuditPolicy.LocalPath(path);
                    if (id == 5145)
                    {
                        var relative = data.GetValueOrDefault("RelativeTargetName", "");
                        if (relative.StartsWith('\\') || relative.StartsWith('/') || relative.Contains(':')) return (false,[],null);
                        path = FileAuditPolicy.LocalPath(path.TrimEnd('\\') + "\\" + relative);
                    }
                }
                scopes = p.Roots.OfType<JsonObject>().Where(r => (share == "" || share.Equals(r["share_name"]!.ToString(),StringComparison.OrdinalIgnoreCase))
                    && (!string.IsNullOrEmpty(path) && FileAuditPolicy.InRoot(path,r["path"]!.ToString()) || string.IsNullOrEmpty(path) && share != "" && id is 5142 or 5143 or 5144)).ToArray();
            }
            catch (AgentException) { path = null; }
        }
        if (p.Workstation && !FileAuditPolicy.ContextEvents.Contains(id))
        {
            var sid = data.GetValueOrDefault("SubjectUserSid", "");
            if (sid == "" || new[] {"S-1-0-0","S-1-5-7","S-1-5-18","S-1-5-19","S-1-5-20"}.Contains(sid)
                || new[] {"S-1-5-80-","S-1-5-82-","S-1-5-90-","S-1-5-96-"}.Any(prefix => sid.StartsWith(prefix,StringComparison.Ordinal))
                || data.GetValueOrDefault("SubjectUserName", "").EndsWith('$') || p.Value["service_account_exclusions"]!.AsArray().Any(s => s!.ToString() == sid)) return (false,scopes,path);
        }
        if (FileAuditPolicy.ContextEvents.Contains(id)) return (id != 4624 || data.GetValueOrDefault("LogonType") == "3",scopes,path);
        if (id == 4660) return (true,scopes,path);
        if (scopes.Length == 0 && p.Workstation && id is 4656 or 4659 or 4663 or 4658 && Number(data.GetValueOrDefault("HandleId")) is > 0) return (true,[],null);
        if (scopes.Length == 0) return (false,scopes,path);
        var flags = Number(row["keywords"]?.ToString()) ?? 0;
        var failure = (flags & 0x10000000000000) != 0 && (flags & 0x20000000000000) == 0;
        return (id != 5145 || failure || scopes.Any(r => r["important"]!.GetValue<bool>()),scopes,path);
    }
    private static ulong? Number(string? text) => text is not null && ulong.TryParse(text.StartsWith("0x",StringComparison.OrdinalIgnoreCase) ? text[2..] : text,
        text.StartsWith("0x",StringComparison.OrdinalIgnoreCase) ? NumberStyles.HexNumber : NumberStyles.Integer,CultureInfo.InvariantCulture,out var n) ? n : null;

    internal static (string Sid, ulong Logon, ulong Process, ulong Handle)? Handle(Dictionary<string,string> data) =>
        data.GetValueOrDefault("SubjectUserSid") is { Length: > 0 } sid
        && Number(data.GetValueOrDefault("SubjectLogonId")) is { } logon
        && Number(data.GetValueOrDefault("ProcessId")) is { } process
        && Number(data.GetValueOrDefault("HandleId")) is > 0 and var handle
            ? (sid,logon,process,handle) : null;

    public static JsonObject? PermissionsAction(JsonObject row, Dictionary<string,string> data, JsonObject[] scopes, string? path)
    {
        const ulong auditSuccess = 0x20000000000000;
        const ulong auditFailure = 0x10000000000000;
        var flags = Number(row["keywords"]?.GetValue<string>()) ?? 0;
        if (row["event_id"]?.GetValue<int>() != 4670 || scopes.Length != 1 || path is null
            || (flags & (auditSuccess | auditFailure)) != auditSuccess
            || data.GetValueOrDefault("ObjectType") != "File" || data.GetValueOrDefault("ObjectServer") != "Security"
            || string.IsNullOrEmpty(data.GetValueOrDefault("ObjectName"))) return null;
        string root = UnicodeLower.Lower(scopes[0]["path"]!.GetValue<string>());
        string candidate = UnicodeLower.Lower(path);
        if (candidate != root && !candidate.StartsWith(root.TrimEnd('\\')+"\\",StringComparison.Ordinal)) return null;

        var sid = data.GetValueOrDefault("SubjectUserSid", "");
        var oldDescriptor = data.GetValueOrDefault("OldSd", "");
        var newDescriptor = data.GetValueOrDefault("NewSd", "");
        if (sid.Length > 184 || !Regex.IsMatch(sid,"\\AS-1-(?:[0-9]+-)*[0-9]+\\z")
            || string.IsNullOrWhiteSpace(oldDescriptor) || string.IsNullOrWhiteSpace(newDescriptor)
            || oldDescriptor is "-" || newDescriptor is "-" || oldDescriptor == newDescriptor
            || !Iso8601.TryParseUtc(row["time_created"]?.GetValue<string>(), out var at)) return null;
        var time = Iso8601.Format(at);
        var minute = Iso8601.Format(new DateTimeOffset(at.UtcTicks - at.UtcTicks % TimeSpan.TicksPerMinute, TimeSpan.Zero));
        return new JsonObject {
            ["contract"]=FileAuditPolicy.ActionContract, ["record_id"]=row["record_id"]!.DeepClone(),
            ["event_id"]=4670, ["computer_name"]=row["computer_name"]!.DeepClone(), ["channel"]="Security",
            ["provider_name"]=FileAuditPolicy.Provider, ["collection_scope_id"]=scopes[0]["collection_scope_id"]!.DeepClone(),
            ["path"]=path, ["old_path"]=null, ["operation"]="permissions", ["subject_user_sid"]=sid, ["client_ip"]=null,
            ["minute_utc"]=minute, ["time_created"]=time, ["first_seen_utc"]=time, ["last_seen_utc"]=time,
            ["count"]=1, ["outcome"]="success"
        };
    }

    public static string Mask(string raw, bool scoped)
    {
        static void Drop(XElement element)
        {
            // ElementTree removes the element's tail with it; LINQ stores that tail as sibling text nodes.
            while (element.NextNode is XText tail) tail.Remove();
            element.Remove();
        }
        var root = EventXml.ParseBounded(raw); root.RemoveAttributes();
        foreach (var child in root.Elements().ToArray()) if (child.Name != Ns + "System" && child.Name != Ns + "EventData") Drop(child);
        var fields = scoped ? Fields : Technical;
        var system = new Dictionary<string,string[]> { ["Provider"]=["Name","Guid"],["EventID"]=["Qualifiers"],["Version"]=[],["Level"]=[],["Task"]=[],["Opcode"]=[],["Keywords"]=[],["EventRecordID"]=[],["TimeCreated"]=["SystemTime"],["Channel"]=[],["Computer"]=[],["Security"]=["UserID"] };
        foreach (var parent in root.Elements()) foreach (var item in parent.Elements().ToArray())
        {
            var valid = parent.Name == Ns + "System" ? system.ContainsKey(item.Name.LocalName) && item.Name.Namespace == Ns : item.Name == Ns + "Data" && fields.Contains(item.Attribute("Name")?.Value ?? "");
            if (!valid) { Drop(item); continue; }
            var attrs = parent.Name == Ns + "System" ? system[item.Name.LocalName] : ["Name"];
            foreach (var a in item.Attributes().ToArray()) if (!attrs.Contains(a.Name.ToString())) a.Remove();
            foreach (var child in item.Elements().ToArray()) Drop(child);
        }
        // ElementTree's deterministic ns0 serialization is part of the signed wire payload.
        static string Escape(string s) => s.Replace("&","&amp;",StringComparison.Ordinal).Replace("<","&lt;",StringComparison.Ordinal).Replace(">","&gt;",StringComparison.Ordinal);
        var b = new StringBuilder();
        void Write(XElement e, bool first = false)
        {
            b.Append("<ns0:").Append(e.Name.LocalName);
            if (first) b.Append(" xmlns:ns0=\"").Append(EventXml.Namespace).Append('"');
            foreach (var a in e.Attributes()) b.Append(' ').Append(a.Name).Append("=\"").Append(Escape(a.Value).Replace("\"","&quot;",StringComparison.Ordinal).Replace("\t","&#09;",StringComparison.Ordinal).Replace("\n","&#10;",StringComparison.Ordinal).Replace("\r","&#13;",StringComparison.Ordinal)).Append('"');
            if (!e.Nodes().Any()) { b.Append(" />"); return; }
            b.Append('>');
            foreach (var n in e.Nodes()) { if (n is XElement child) Write(child); else if (n is XText t) b.Append(Escape(t.Value)); }
            b.Append("</ns0:").Append(e.Name.LocalName).Append('>');
        }
        Write(root,true); return b.ToString();
    }
}
