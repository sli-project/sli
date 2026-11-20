using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;

namespace Sli.Server.Agents.Ingress;

// Source sli_agent/signature_contract.py: packet_entries. This binds an agent measurement;
// it does not inspect the file or independently verify Authenticode.
internal static class WorkstationSignatureEvidence
{
    private static readonly XNamespace Ns=EventXml.Namespace;
    private static readonly UTF8Encoding Utf8=new(false,true);
    private static readonly Regex Reserved=new(@"\A(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?\z",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant,TimeSpan.FromSeconds(1));
    private static readonly HashSet<string> Reasons=new(["timeout","unsupported","unsafe_path","too_large","changed","verification_failed"],StringComparer.Ordinal);
    private static ArgumentException Invalid()=>new("workstation_signature_invalid");
    private static string Text(JsonNode? node)=>JsonRead.TryString(node,out var value)?value:throw Invalid();
    private static bool Hash(JsonNode? node)=>JsonRead.TryString(node,out var s)&&s.Length==64&&s.All(c=>c is >= 'a' and <= 'f' or >= '0' and <= '9');
    private static bool Space(char c)=>char.IsWhiteSpace(c)||c is '\u001c' or '\u001d' or '\u001e' or '\u001f';
    private static bool LocalPath(string path)
    {
        if(path.Length==0||Space(path[0])||Space(path[^1]))return false;
        int bytes;try{bytes=Utf8.GetByteCount(path);}catch(EncoderFallbackException){return false;}
        if(bytes is <1 or >512||path.Length<4||path[0] is not (>= 'A' and <= 'Z' or >= 'a' and <= 'z')||path[1]!=':'||path[2]!='\\')return false;
        foreach(var part in path[3..].Split('\\')) {
            if(part.Length==0||part is "." or ".."||part.EndsWith(' ')||part.EndsWith('.')||part.Contains('~')||Reserved.IsMatch(part))return false;
            if(part.Any(c=>c<32||c==127||"/:\"<>|?*%".Contains(c)))return false;
        }
        return true;
    }
    private static string? DirectText(XElement? element)=>element?.Nodes().TakeWhile(n=>n is not XElement).OfType<XText>().Select(x=>x.Value).DefaultIfEmpty(null).Aggregate((string?)null,(a,b)=>a is null?b:a+b);
    private static long UtcTicks(string value)
    {
        if(!PythonIsoDateTime.TryParse(value,out var t)||!t.IsAware)throw Invalid();return t.WallTime.Ticks-t.Offset!.Value.Ticks;
    }
    private static void Measurement(JsonObject m,string packetTime)
    {
        if(!JsonRead.HasExactly(m,"scope","observed_at_utc","status","reason","sha256_before","sha256_after","identity_before","identity_after","signer_sha256","kind")||Text(m["scope"])!="file_at_measurement")throw Invalid();
        string observed=Text(m["observed_at_utc"]);if(JsonRead.CodePoints(observed)>40)throw Invalid();
        long delta=UtcTicks(observed)-UtcTicks(packetTime);if(delta < -TimeSpan.TicksPerSecond||delta > 5*TimeSpan.TicksPerSecond)throw Invalid();
        string status=Text(m["status"]);
        if(status=="unavailable") {
            if(!JsonRead.TryString(m["reason"],out var reason)||!Reasons.Contains(reason)||new[]{"sha256_before","sha256_after","identity_before","identity_after","signer_sha256","kind"}.Any(k=>!JsonRead.IsNull(m[k])))throw Invalid();
        } else if(status is "signed" or "unsigned") {
            if(!JsonRead.IsNull(m["reason"])||!Hash(m["sha256_before"])||!Hash(m["identity_before"])||!JsonNode.DeepEquals(m["sha256_before"],m["sha256_after"])||!JsonNode.DeepEquals(m["identity_before"],m["identity_after"]))throw Invalid();
            if(status=="signed") {if(!JsonRead.TryString(m["kind"],out var kind)||kind is not ("embedded" or "catalog")||!Hash(m["signer_sha256"]))throw Invalid();}
            else if(Text(m["kind"])!="none"||!JsonRead.IsNull(m["signer_sha256"]))throw Invalid();
        } else throw Invalid();
    }
    public static Dictionary<BigInteger,JsonObject> Validate(JsonNode? entries,JsonArray rows,string packetTime)
    {
        var result=new Dictionary<BigInteger,JsonObject>();if(entries is null)return result;
        if(entries is not JsonArray array||array.Count>2)throw Invalid();
        foreach(var node in array){
            if(node is not JsonObject entry||!JsonRead.HasExactly(entry,"contract","record_id","source_sha256","path","measurement")||Text(entry["contract"])!="sli.workstation-file-signature.v1"||!JsonRead.TryInteger(entry["record_id"],out var id)||id<0||result.ContainsKey(id)||!Hash(entry["source_sha256"]))throw Invalid();
            string path=Text(entry["path"]);if(!LocalPath(path))throw Invalid();
            var matches=rows.OfType<JsonObject>().Where(row=>JsonRead.TryInteger(row["record_id"],out var n)&&n==id).ToArray();if(matches.Length!=1)throw Invalid();
            var row=matches[0];string xml=Text(row["xml"]);var root=EventXml.ParseBounded(xml);var system=root.Element(Ns+"System");
            if(system is null||DirectText(system.Element(Ns+"EventID"))!="4688"||DirectText(system.Element(Ns+"EventRecordID"))!=id.ToString(System.Globalization.CultureInfo.InvariantCulture)||DirectText(system.Element(Ns+"Channel"))!="Security"||system.Element(Ns+"Provider")?.Attribute("Name")?.Value!="Microsoft-Windows-Security-Auditing")throw Invalid();
            var paths=root.Elements(Ns+"EventData").SelectMany(x=>x.Elements(Ns+"Data")).Where(x=>x.Attribute("Name")?.Value=="NewProcessName").ToArray();
            if(paths.Length!=1||DirectText(paths[0])!=path||!PythonMetadataEquality.Equal(row["event_id"],JsonValue.Create(4688))||Text(row["channel"])!="Security"||Text(row["provider_name"])!="Microsoft-Windows-Security-Auditing"||Text(entry["source_sha256"])!=Convert.ToHexStringLower(SHA256.HashData(Utf8.GetBytes(xml))))throw Invalid();
            if(entry["measurement"] is not JsonObject measurement)throw Invalid();Measurement(measurement,packetTime);result.Add(id,(JsonObject)entry.DeepClone());
        }
        return result;
    }
}
