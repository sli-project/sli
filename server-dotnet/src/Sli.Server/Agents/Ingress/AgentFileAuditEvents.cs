using System.Numerics;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Agents.Ingress;

/// <summary>File audit evidence scope and privacy checks, corresponding to file_audit_events.py.</summary>
internal static class AgentFileAuditEvents
{
    private static readonly XNamespace Ns=EventXml.Namespace;
    private static readonly HashSet<string> Fields=["SubjectUserSid","SubjectLogonId","TargetUserSid","TargetLogonId","LogonType","ObjectName","ObjectType","HandleId","ProcessId","ProcessName","AccessMask","AccessList","AccessReason","ShareName","ShareLocalPath","RelativeTargetName","IpAddress","IpPort","OldSd","NewSd","OldSdValue","NewSdValue","ObjectServer","PrivilegeList"];
    private static readonly HashSet<string> Reduced=["SubjectUserSid","SubjectLogonId","TargetUserSid","TargetLogonId","LogonType","HandleId","ProcessId","AccessMask","IpAddress","IpPort"];
    private static readonly Dictionary<string,string[]> SystemFields=new() { ["Provider"]=["Name","Guid"], ["EventID"]=["Qualifiers"], ["Version"]=[], ["Level"]=[], ["Task"]=[], ["Opcode"]=[], ["Keywords"]=[], ["EventRecordID"]=[], ["TimeCreated"]=["SystemTime"], ["Channel"]=[], ["Computer"]=[], ["Security"]=["UserID"] };
    public static void Validate(JsonObject row,FileAuditPolicy policy,string source,string? objectKind=null)
    {
        static void Require(bool value) { if (!value) throw new ArgumentException(); }
        string xml=row["xml"]!.GetValue<string>(); var root=EventXml.ParseBounded(xml);
        Require(root.Name==Ns+"Event" && EventXml.NativeChannel(root)=="Security");
        var data=new Dictionary<string,string>();
        foreach(var item in root.Elements(Ns+"EventData").SelectMany(x=>x.Elements(Ns+"Data")))
        {
            string name=item.Attribute("Name")?.Value ?? "";
            Require(!data.ContainsKey(name)); var text=new StringBuilder();
            foreach(var child in item.Nodes()) { if(child is XElement) break; if(child is XText part) text.Append(part.Value); }
            data.Add(name,text.ToString());
        }
        Require(JsonNode.DeepEquals(EventXml.Parse(xml,source,"localhost","Security"),row));
        Require(JsonRead.TryInteger(row["event_id"],out var eventId) && eventId>=0 && eventId<=int.MaxValue);
        int id=(int)eventId; string provider=id==1102 ? "Microsoft-Windows-Eventlog" : FileAuditPolicy.Provider;
        Require(row["provider_name"]?.GetValue<string>()==provider);
        bool context=FileAuditPolicy.ContextEvents.Contains(id);
        bool optional=(id is 4658 or 4664) && policy.Value["optional_events"]!.GetValue<bool>();
        Require(context || optional || FileAuditPolicy.Events.Contains(id));
        var scopes=ScopeAndPath(id,data,policy,out _);
        if (objectKind is not null)
            Require(id==4663 && scopes.Count==1 && data.GetValueOrDefault("ObjectType")=="File");
        bool workstation=policy.Workstation;
        if (workstation && !context)
        {
            string sid=data.GetValueOrDefault("SubjectUserSid",""); string name=data.GetValueOrDefault("SubjectUserName","");
            Require(sid.Length>0 && !new[]{"S-1-0-0","S-1-5-7","S-1-5-18","S-1-5-19","S-1-5-20"}.Contains(sid)
                && !new[]{"S-1-5-80-","S-1-5-82-","S-1-5-90-","S-1-5-96-"}.Any(sid.StartsWith)
                && !name.EndsWith('$') && !policy.Value["service_account_exclusions"]!.AsArray().Any(x=>x!.GetValue<string>()==sid));
        }
        if (context) Require(id!=4624 || data.GetValueOrDefault("LogonType")=="3");
        else if (id!=4660)
        {
            bool handle=id is 4656 or 4659 or 4663 or 4658 && PositiveNumber(data.GetValueOrDefault("HandleId"));
            Require(scopes.Count>0 || handle);
            if (id==5145 && !Failure(row["keywords"]?.GetValue<string>())) Require(scopes.Any(r=>r["important"]!.GetValue<bool>()));
        }
        var allowed=scopes.Count>0 ? Fields : Reduced;
        Require(!root.Attributes().Any(a=>!a.IsNamespaceDeclaration));
        foreach(var child in root.Elements())
        {
            Require(child.Name==Ns+"System" || child.Name==Ns+"EventData");
            if (child.Name==Ns+"System") foreach(var item in child.Elements())
            {
                Require(item.Name.Namespace==Ns && SystemFields.TryGetValue(item.Name.LocalName,out _));
                var attrs=SystemFields[item.Name.LocalName];
                Require(!item.HasElements && item.Attributes().All(a=>a.IsNamespaceDeclaration || a.Name.NamespaceName=="" && attrs.Contains(a.Name.LocalName)));
            }
            else foreach(var item in child.Elements())
                Require(item.Name==Ns+"Data" && item.Attribute("Name") is { } name && allowed.Contains(name.Value)
                    && !item.HasElements && item.Attributes().All(a=>a.IsNamespaceDeclaration || a.Name=="Name"));
        }
    }
    internal static List<JsonObject> ScopeAndPath(int id,Dictionary<string,string> data,FileAuditPolicy policy,out string? selectedPath)
    {
        selectedPath=null;
        if (FileAuditPolicy.ContextEvents.Contains(id) || id==4660) return [];
        string share=data.GetValueOrDefault("ShareName","").Split('\\').Last();
        string path=data.GetValueOrDefault("ObjectName",""); if (path.Length==0) path=data.GetValueOrDefault("ShareLocalPath","");
        if (path.StartsWith("\\??\\",StringComparison.Ordinal)) path=path[4..];
        try
        {
            if (path.Length>0)
            {
                path=AgentFileAuditPolicy.NormalizePath(path);
                if (id==5145)
                {
                    string relative=data.GetValueOrDefault("RelativeTargetName","");
                    if (relative.StartsWith('\\') || relative.StartsWith('/') || relative.Length>=2 && relative[1]==':') return [];
                    path=AgentFileAuditPolicy.NormalizePath(path.TrimEnd('\\')+"\\"+relative);
                }
            }
            selectedPath=path.Length==0 ? null : path;
            return policy.Roots.OfType<JsonObject>().Where(r=>
            {
                string root=r["path"]!.GetValue<string>(); string folded=UnicodeLower.Lower(path); string rootFolded=UnicodeLower.Lower(root);
                return (share.Length==0 || UnicodeCaseFold.Fold(share)==UnicodeCaseFold.Fold(r["share_name"]!.GetValue<string>()))
                    && (path.Length>0 && (folded==rootFolded || folded.StartsWith(rootFolded.TrimEnd('\\')+"\\",StringComparison.Ordinal))
                        || path.Length==0 && share.Length>0 && id is 5142 or 5143 or 5144);
            }).ToList();
        }
        catch (AgentException) { return []; }
    }
    private static bool PositiveNumber(string? text)
    {
        return TryBaseZero(text,out var number) && number>0 && number<=ulong.MaxValue;
    }
    private static bool Failure(string? text)
    {
        if (!TryBaseZero(text ?? "0",out var n)) return false;
        return (n & 0x10000000000000L)!=0 && (n & 0x20000000000000L)==0;
    }
    internal static bool TryBaseZero(string? text,out BigInteger value)
    {
        value=0; if (text is null) return false;
        var normalized=new StringBuilder();
        foreach(var rune in text.EnumerateRunes()) { int digit=System.Globalization.CharUnicodeInfo.GetDecimalDigitValue(rune.ToString(),0); normalized.Append(digit>=0 ? ((char)('0'+digit)).ToString() : rune.ToString()); }
        text=normalized.ToString().Trim(); bool negative=false;
        if (text.StartsWith('+') || text.StartsWith('-')) { negative=text[0]=='-'; text=text[1..]; }
        int radix=text.StartsWith("0x",StringComparison.OrdinalIgnoreCase) ? 16 : text.StartsWith("0o",StringComparison.OrdinalIgnoreCase) ? 8 : text.StartsWith("0b",StringComparison.OrdinalIgnoreCase) ? 2 : 10;
        if (radix==10)
        {
            if (!PythonInt.TryParse(text,out value)) return false;
            var digits=text.Replace("_","").EnumerateRunes().ToArray();
            if (digits.Length>1 && System.Globalization.CharUnicodeInfo.GetDecimalDigitValue(digits[0].ToString(),0)==0 && value!=0) return false;
        }
        else
        {
            string digits=text[2..]; if (digits.StartsWith('_')) digits=digits[1..];
            if (digits.Length==0 || digits.StartsWith('_') || digits.EndsWith('_') || digits.Contains("__",StringComparison.Ordinal)) return false;
            foreach(char c in digits)
            {
                if (c=='_') continue;
                int digit=c is >= '0' and <= '9' ? c-'0' : c is >= 'a' and <= 'f' ? c-'a'+10 : c is >= 'A' and <= 'F' ? c-'A'+10 : -1;
                if (digit<0 || digit>=radix) return false; value=value*radix+digit;
            }
        }
        if (negative) value=-value; return true;
    }
}
