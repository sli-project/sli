using System.Globalization;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml;
using System.Xml.Linq;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Registry;
using Sli.Server.Semantic.Detections;

namespace Sli.Server.Semantic.Password;

public sealed class PasswordFailure(string code) : Exception(code)
{
    internal enum ContextCheck { Shape, EntityOrder, EntityFormat, MissingEntity, MissingBarrierEntity }
    internal ContextCheck? Check { get; init; }
    internal enum WindowCheck { MetadataRecord, MetadataShape, CountBound, CandidateCount, EventRecords, DuplicateNative, EventTimeRange, WatermarkRegression, AttemptClock, ReadFrom, FinalizableThrough }
    internal WindowCheck? WindowCondition { get; init; }
    internal IReadOnlyDictionary<string,int>? ProposalDiagnostics { get; init; }
    internal bool? WatermarkMatches { get; init; }
    internal int? StateBytes { get; init; }
    internal PasswordProofBudget? ProofBudget { get; init; }
}

internal enum PasswordProofPhase { Reader, RetainedChain, Emission, Checkpoint, NativeVerification }

internal sealed record PasswordProofBudget(PasswordProofPhase Phase,long? References=null,long? XmlBytes=null,long? DocumentBytes=null,
    int ReferenceLimit=PasswordProofBudget.MaxReferences)
{
    internal const int MaxReferences=10000,MaxXmlBytes=33554432,MaxDocumentBytes=4194304;
    internal static void Check(PasswordProofPhase phase,long references,long xmlBytes,int referenceLimit=MaxReferences)
    {
        if(references>referenceLimit||xmlBytes>MaxXmlBytes)
            throw new PasswordFailure("password_v2_proof_bound") { ProofBudget=new(phase,references,xmlBytes,ReferenceLimit:referenceLimit) };
    }

    internal JsonObject Document => new() {
        ["phase"]=Phase.ToString(),
        ["limit"]=DocumentBytes>MaxDocumentBytes?"document_bytes":References>ReferenceLimit?"references":XmlBytes>MaxXmlBytes?"xml_bytes":"native_proof",
        ["references"]=References,["xml_bytes"]=XmlBytes,["document_bytes"]=DocumentBytes,
        ["max_references"]=ReferenceLimit,["max_xml_bytes"]=MaxXmlBytes,["max_document_bytes"]=MaxDocumentBytes
    };
}

internal static class PasswordJson
{
    private static readonly char[] PythonWhitespace="\u0009\u000A\u000B\u000C\u000D\u001C\u001D\u001E\u001F\u0020\u0085\u00A0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u2028\u2029\u202F\u205F\u3000".ToCharArray();
    internal static string Trim(string value)=>value.Trim(PythonWhitespace);
    internal static string Hash(JsonNode? node)=>Convert.ToHexStringLower(SHA256.HashData(CanonicalJson.ToBytes(node)));
    internal static int SpacedSize(JsonNode? node)
    {
        int Spaces(JsonNode? value)=>value switch {JsonObject o=>o.Count+Math.Max(0,o.Count-1)+o.Sum(p=>Spaces(p.Value)),JsonArray a=>Math.Max(0,a.Count-1)+a.Sum(Spaces),_=>0};
        return checked(CanonicalJson.Length(node)+Spaces(node));
    }
    internal static string Stamp(DateTimeOffset value)=>value.UtcDateTime.ToString(value.Ticks%TimeSpan.TicksPerSecond==0?"yyyy-MM-dd'T'HH:mm:ss'+00:00'":"yyyy-MM-dd'T'HH:mm:ss.ffffff'+00:00'",CultureInfo.InvariantCulture);
    internal static DateTimeOffset Time(JsonNode? node)
    {
        string value=node!.GetValue<string>();
        if(!(value.EndsWith('Z') || value.Length>=6 && value[^3]==':' && value[^6] is '+' or '-'))throw new PasswordFailure("password_v2_time_invalid");
        // datetime.fromisoformat truncates fractional seconds to microseconds.
        int dot=value.IndexOf('.',Math.Max(0,value.IndexOf('T')));
        if(dot>=0){int end=dot+1;while(end<value.Length&&char.IsAsciiDigit(value[end]))end++;if(end-dot-1>6)value=value.Remove(dot+7,end-dot-7);}
        var parsed=DateTimeOffset.Parse(value,CultureInfo.InvariantCulture,DateTimeStyles.None).ToUniversalTime();
        return parsed;
    }
    internal static JsonArray Array<T>(IEnumerable<T> values,Func<T,JsonNode?> map)=>new(values.Select(map).ToArray());
    internal static JsonObject Obj(JsonNode? node)=>(JsonObject)(node??throw new PasswordFailure("password_v2_document_invalid"));
    internal static string Text(JsonNode? node)=>node!.GetValue<string>();
    internal static bool Hex(string text)=>text.Length==64&&text.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f');
}

public sealed record PasswordScope(string InstallationId,string PluginId,string SourceInstanceId,string SourceGeneration,string CollectionScopeId)
{
    public JsonObject Document=>new(){["installation_id"]=InstallationId,["plugin_id"]=PluginId,["source_instance_id"]=SourceInstanceId,["source_generation"]=SourceGeneration,["collection_scope_id"]=CollectionScopeId};
    public void Validate()
    {
        if(!Guid.TryParseExact(InstallationId,"D",out var id)||id.ToString("D")!=InstallationId||PluginId!="sli.windows.ad-dc"||CollectionScopeId!=""||SourceInstanceId.EnumerateRunes().Count() is <1 or >256||SourceGeneration.EnumerateRunes().Count() is <1 or >512||SourceInstanceId!=PasswordJson.Trim(SourceInstanceId)||SourceGeneration!=PasswordJson.Trim(SourceGeneration))throw new PasswordFailure("password_v2_rule_scope");
    }
    public static PasswordScope Read(JsonNode? node)=>new(PasswordJson.Text(node!["installation_id"]),PasswordJson.Text(node["plugin_id"]),PasswordJson.Text(node["source_instance_id"]),PasswordJson.Text(node["source_generation"]),PasswordJson.Text(node["collection_scope_id"]));
}

public sealed record PasswordWitness(PasswordScope Scope,long NativeId,string Sha256,DateTimeOffset At,string XmlSha256,int XmlBytes)
{
    public JsonObject Ref=>new(){["storage_kind"]="core_event",["native_id"]=NativeId.ToString(CultureInfo.InvariantCulture),["sha256"]=Sha256,["scope"]=Scope.Document};
    public JsonArray Params=>new(Scope.InstallationId,Scope.PluginId,Scope.SourceInstanceId,Scope.SourceGeneration,Scope.CollectionScopeId,"core_event",NativeId.ToString(CultureInfo.InvariantCulture),Sha256);
    public JsonObject Document=>new(){["ref"]=Ref,["at"]=PasswordJson.Stamp(At),["xml_sha256"]=XmlSha256,["xml_bytes"]=XmlBytes};
    public JsonArray Compact=>new(NativeId.ToString(CultureInfo.InvariantCulture),Sha256,PasswordJson.Stamp(At),XmlBytes,XmlSha256);
    public static PasswordWitness Read(JsonNode? node)
    {
        if(PasswordJson.Text(node!["ref"]!["storage_kind"])!="core_event")throw new PasswordFailure("password_v2_native_invalid");
        return Checked(PasswordScope.Read(node["ref"]!["scope"]),PasswordJson.Text(node["ref"]!["native_id"]),PasswordJson.Text(node["ref"]!["sha256"]),PasswordJson.Time(node["at"]),PasswordJson.Text(node["xml_sha256"]),node["xml_bytes"]!.GetValue<int>());
    }
    internal static PasswordWitness FromCompact(PasswordScope scope,JsonNode? row)=>Checked(scope,PasswordJson.Text(row![0]),PasswordJson.Text(row[1]),PasswordJson.Time(row[2]),PasswordJson.Text(row[4]),row[3]!.GetValue<int>());
    private static PasswordWitness Checked(PasswordScope scope,string native,string hash,DateTimeOffset at,string xmlHash,int bytes)
    {
        scope.Validate();if(!long.TryParse(native,NumberStyles.None,CultureInfo.InvariantCulture,out long id)||id<=0||id.ToString(CultureInfo.InvariantCulture)!=native||!PasswordJson.Hex(hash)||!PasswordJson.Hex(xmlHash)||bytes is <1 or >4194304)throw new PasswordFailure("password_v2_native_invalid");
        return new(scope,id,hash,at,xmlHash,bytes);
    }
}

public sealed record PasswordMember(PasswordWitness Witness,string? ClientKind,string? ClientKey,string? TargetKey,string? Failure,string? Reason)
{
    public string? Entity=>Reason!=null||Failure==null||ClientKey==null||TargetKey==null?null:PasswordJson.Hash(new JsonArray(ClientKind,ClientKey,TargetKey));
    public string? EntityFor(PasswordRule rule)
    {
        if (Reason == "successful_logon") {
            if (ClientKind != "ip" || ClientKey is null || TargetKey is null) return null;
            if (rule.Kind == "spray") return ClientKey;
            return rule.NormalizedAccounts ? PasswordJson.Hash(new JsonArray(ClientKind,ClientKey,TargetKey)) : null;
        }
        return rule.Kind == "spray" ? Reason == null && Failure != null && ClientKind == "ip" && TargetKey != null ? ClientKey : null : Entity;
    }
    public JsonObject Document=>new(){["witness"]=Witness.Document,["client_kind"]=ClientKind,["client_key"]=ClientKey,["target_key"]=TargetKey,["failure"]=Failure,["reason"]=Reason};
    internal static PasswordMember Read(JsonNode? node)=>new(PasswordWitness.Read(node!["witness"]),node["client_kind"]?.GetValue<string>(),node["client_key"]?.GetValue<string>(),node["target_key"]?.GetValue<string>(),node["failure"]?.GetValue<string>(),node["reason"]?.GetValue<string>());
}

public sealed record PasswordNative(PasswordWitness Witness,int EventId,string SourceXml,PasswordMember Member)
{
    internal string? NameTargetKey { get; init; }
    internal string? BruteSuccessNameEntity => Member.Reason == "successful_logon" && NameTargetKey is not null && NameTargetKey != Member.TargetKey
        ? PasswordJson.Hash(new JsonArray(Member.ClientKind, Member.ClientKey, NameTargetKey)) : null;
    internal bool SameTarget(PasswordNative other) => Member.TargetKey == other.Member.TargetKey ||
        NameTargetKey is not null && NameTargetKey == other.NameTargetKey &&
        (Member.TargetKey == NameTargetKey || other.Member.TargetKey == other.NameTargetKey);
    internal bool ProvesEntity(PasswordRule rule, string entity) => Member.EntityFor(rule) == entity ||
        rule.NormalizedAccounts && rule.Kind == "brute" && BruteSuccessNameEntity == entity;

    public static PasswordNative Parse(PasswordScope scope,long id,string hash,int eventId,DateTimeOffset at,string xml,bool normalizeAccount=false)
    {
        scope.Validate();byte[] payload=new UTF8Encoding(false,true).GetBytes(xml);
        if(payload.Length>4194304||xml.Contains("<!DOCTYPE",StringComparison.OrdinalIgnoreCase)||xml.Contains("<!ENTITY",StringComparison.OrdinalIgnoreCase))throw new PasswordFailure("password_v2_native_invalid");
        if(id<=0||!PasswordJson.Hex(hash)||eventId is not (4624 or 4625 or 4771 or 4776)||at.Ticks%10!=0)throw new PasswordFailure("password_v2_native_invalid");
        Dictionary<string,string> fields;
        if (xml.StartsWith('{')) {
            var doc = DetectionNative.ShortDocument(scope, id, eventId, at, xml);
            fields = doc["fields"]!.AsObject().ToDictionary(p => p.Key, p => p.Value?.GetValue<string>() ?? "", StringComparer.Ordinal);
        } else {
        using var reader=XmlReader.Create(new StringReader(xml),new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=4194304,IgnoreComments=true});
        int nodes=0;while(reader.Read())if(reader.NodeType==XmlNodeType.Element&&++nodes>100000||reader.Depth>=64)throw new PasswordFailure("password_v2_native_invalid");
        var root=XElement.Parse(xml);XNamespace ns="http://schemas.microsoft.com/win/2004/08/events/event";var system=root.Element(ns+"System");
        if(root.Name!=ns+"Event"||system?.Element(ns+"EventID")?.Value!=eventId.ToString(CultureInfo.InvariantCulture))throw new PasswordFailure("password_v2_native_event_mismatch");
        if(PasswordJson.Time(JsonValue.Create((string?)system.Element(ns+"TimeCreated")?.Attribute("SystemTime")))!=at)throw new PasswordFailure("password_v2_native_time_mismatch");
        fields=new Dictionary<string,string>(StringComparer.Ordinal);
        foreach(var item in root.Element(ns+"EventData")?.Elements()??[]) {
            string? name=(string?)item.Attribute("Name");if(item.Name!=ns+"Data"||string.IsNullOrEmpty(name)||item.HasElements||!fields.TryAdd(name,item.Value))throw new PasswordFailure("password_v2_native_fields_invalid");
        }
        }
        string Get(string key)=>fields.GetValueOrDefault(key,"");
        string account=UnicodeCaseFold.TrimAndFold(Get("TargetUserName")),domain=UnicodeCaseFold.TrimAndFold(Get("TargetDomainName"));
        if (normalizeAccount && account.IndexOf('\\') is int separator && separator > 0 && account[..separator] == domain)
            account = account[(separator + 1)..];
        string? target=account is not ("" or "-" or "n/a")&&account.EnumerateRunes().Count()<=256&&domain.EnumerateRunes().Count()<=256?PasswordJson.Hash(new JsonArray(domain,account)):null;
        string? nameTarget = normalizeAccount ? target : null;
        if (normalizeAccount) {
            string sid = Get("TargetUserSid").Trim().ToUpperInvariant();
            if (sid is "" or "-" or "S-1-0-0") sid = Get("TargetSid").Trim().ToUpperInvariant();
            if (System.Text.RegularExpressions.Regex.IsMatch(sid, @"\AS-1-5-21(?:-[0-9]{1,10}){4}\z"))
                target = PasswordJson.Hash(new JsonArray("sid",sid));
        }
        var addresses=new HashSet<string>(StringComparer.Ordinal);
        foreach(string key in new[]{"IpAddress","ClientAddress","SourceNetworkAddress"}) {
            string text=PasswordJson.Trim(Get(key));if(!StrictIp(text,out var ip,out var zone))continue;
            if(ip!.IsIPv4MappedToIPv6){ip=ip.MapToIPv4();zone=null;}byte[] bytes=ip.GetAddressBytes();
            if(ip.Equals(IPAddress.Any)||ip.Equals(IPAddress.IPv6Any)||IPAddress.IsLoopback(ip)||ip.IsIPv6Multicast||bytes.Length==4&&bytes[0] is >=224 and <=239)continue;
            addresses.Add(CanonicalAddress(ip)+(zone==null?"":"%"+zone));
        }
        string? kind=null,client=null,reason=null;
        if(addresses.Count>1)reason="conflicting_client";
        else if(addresses.Count==1){kind="ip";client=PasswordJson.Hash(new JsonArray("ip",addresses.Single()));}
        else {
            string host=UnicodeCaseFold.Fold(PasswordJson.Trim(Get(eventId==4776?"Workstation":eventId==4625?"WorkstationName":"")).TrimStart('\\'));
            if(host is not ("" or "-" or "n/a")&&host.EnumerateRunes().Count()<=256){kind="host";client=PasswordJson.Hash(new JsonArray("host",host));}else reason="missing_client";
        }
        var (failure,statusReason)=Classify(fields,eventId);reason=target==null?"missing_target":failure==null?statusReason:reason;
        if(eventId==4624){failure="other_failure";reason=target!=null&&client!=null&&kind=="ip"?"successful_logon":"missing_client";}
        var witness=new PasswordWitness(scope,id,hash,at.ToUniversalTime(),Convert.ToHexStringLower(SHA256.HashData(payload)),payload.Length);
        return new(witness,eventId,xml,new(witness,kind,client,target,failure,reason)) { NameTargetKey = nameTarget };
    }
    internal static bool StrictIp(string text,out IPAddress? value,out string? zone)
    {
        value=null;zone=null;
        if(text.Contains(':')) {
            int percent=text.IndexOf('%');if(percent>=0){zone=text[(percent+1)..];if(zone.Length==0||zone.Contains('%'))return false;text=text[..percent];}
            if(text.Contains('.')){string tail=text[(text.LastIndexOf(':')+1)..];if(!StrictIp(tail,out _,out _))return false;}
            return IPAddress.TryParse(text,out value)&&value.AddressFamily==System.Net.Sockets.AddressFamily.InterNetworkV6;
        }
        var pieces=text.Split('.');if(pieces.Length!=4||pieces.Any(p=>p.Length==0||p.Length>1&&p[0]=='0'||!p.All(char.IsAsciiDigit)||!byte.TryParse(p,out _)))return false;
        return IPAddress.TryParse(text,out value);
    }
    internal static string CanonicalAddress(IPAddress ip)
    {
        byte[] bytes=ip.GetAddressBytes();if(bytes.Length==4)return ip.ToString();
        var words=Enumerable.Range(0,8).Select(i=>(bytes[2*i]<<8)|bytes[2*i+1]).ToArray();int bestStart=-1,bestLength=1;
        for(int i=0;i<8;){if(words[i]!=0){i++;continue;}int start=i;while(i<8&&words[i]==0)i++;if(i-start>bestLength){bestStart=start;bestLength=i-start;}}
        string Join(IEnumerable<int> part)=>string.Join(':',part.Select(w=>w.ToString("x",CultureInfo.InvariantCulture)));
        return bestStart<0?Join(words):Join(words.Take(bestStart))+"::"+Join(words.Skip(bestStart+bestLength));
    }
    private static (string?,string?) Classify(Dictionary<string,string> fields,int eventId)
    {
        var codes=new Dictionary<string,BigInteger>();foreach(string key in new[]{"Status","SubStatus","FailureCode","ResultCode"})if(fields.TryGetValue(key,out string? text)&&PasswordJson.Trim(text).Length>0){if(!TryHex(text,out var code))return(null,"unclassified_failure");codes[key]=code;}
        var primary=(eventId==4771?new[]{"FailureCode","Status","ResultCode"}:new[]{"Status","ResultCode"}).Where(codes.ContainsKey).Select(k=>codes[k]).Distinct().ToArray();BigInteger sub=codes.GetValueOrDefault("SubStatus");
        if(primary.Length>1||eventId!=4771&&codes.ContainsKey("FailureCode")||eventId!=4625&&sub!=0)return(null,"ambiguous_failure");
        if(primary.Length==0)return(null,"unclassified_failure");BigInteger effective=primary[0];
        if(eventId==4625&&sub!=0){if(effective==0xc000006d)effective=sub;else if(effective!=sub)return(null,"ambiguous_failure");}
        if(effective==0)return(null,"unclassified_failure");
        return(effective==(eventId==4771?0x18UL:0xc000006aUL)?"known_bad_password":effective==(eventId==4771?6UL:0xc0000064UL)?"unknown_account":"other_failure",null);
    }
    private static bool TryHex(string text,out BigInteger number)
    {
        number=0;text=PasswordJson.Trim(text);bool negative=text.StartsWith('-');if(text.StartsWith('+')||negative)text=text[1..];
        bool prefix=text.StartsWith("0x",StringComparison.OrdinalIgnoreCase);if(prefix)text=text[2..];if(prefix&&text.StartsWith('_'))text=text[1..];
        if(text.Length==0||text.StartsWith('_')||text.EndsWith('_')||text.Contains("__",StringComparison.Ordinal))return false;
        var digits=new StringBuilder(text.Length);foreach(char c in text){if(c=='_')continue;if(char.IsAsciiHexDigit(c))digits.Append(c);else{int digit=CharUnicodeInfo.GetDecimalDigitValue(c);if(digit<0)return false;digits.Append((char)('0'+digit));}}
        if(!BigInteger.TryParse("0"+digits,NumberStyles.AllowHexSpecifier,CultureInfo.InvariantCulture,out number))return false;if(negative)number=-number;return true;
    }
}
