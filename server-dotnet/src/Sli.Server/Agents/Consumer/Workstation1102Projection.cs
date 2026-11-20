using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Agents.Registry;
using Sli.Server.Agents.Ingress;

namespace Sli.Server.Agents.Consumer;

public sealed class WorkstationPendingException(string code) : Exception(code) { public string Code { get; }=code; }
public sealed record WorkstationObservation(string Id,JsonObject Document,string Hash,string SourceXml,DateTimeOffset ObservedAt);

// Source: plugins/workstations/importer.py and normalizers.py. Unmatched events are ignored.
public static class Workstation1102Projection
{
    private static readonly UTF8Encoding Utf8=new(false,true);
    private static readonly XNamespace Ns=EventXml.Namespace;
    public static IReadOnlyList<WorkstationObservation> Build(JsonObject packet,JsonArray storedRows,string agentKey,long entityId,long? adComputerId)
    {
        CollectionPacket.Validate(packet);
        if(entityId<=0||adComputerId<=0||UnicodeCaseFold.TrimAndFold(agentKey).Length==0) throw new InvalidDataException();
        var header=packet["header"]!.AsObject(); string channel=Text(header["channel"]),source=Text(header["source"]),generation=Text(header["generation"]);
        if(UnicodeCaseFold.TrimAndFold(generation).Length==0||JsonRead.CodePoints(generation)>512||storedRows.Count>500) throw new InvalidDataException();
        var context=packet["context"]!.AsObject();
        if(context.ContainsKey("workstations") && context["workstations"] is not JsonObject) throw new InvalidDataException();
        var station=context["workstations"] as JsonObject;
        var protection=WorkstationProtectionState.Prepare(packet);
        var records=packet["records"]!.AsArray();
        if(records.Count!=storedRows.Count) throw new InvalidDataException();
        Dictionary<BigInteger,JsonObject> signatures;
        try { signatures=WorkstationSignatureEvidence.Validate(station?["process_signatures"],storedRows,Text(header["observed_at_utc"])); }
        catch(ArgumentException error) { throw new InvalidDataException("workstation_signature_invalid",error); }
        long totalBytes=0; var output=new List<WorkstationObservation>();
        for(int i=0;i<records.Count;i++)
        {
            var record=records[i]!.AsObject(); var row=record["payload"]!.AsObject(); var stored=storedRows[i];
            if(Text(record["format"])!="event_xml" || !WorkstationJsonEquality.Equals(row,stored) || !Equal(row["record_id"],record["record_id"]) || Text(row["computer_name"])!=source || Text(row["channel"])!=channel) throw new InvalidDataException();
            if(!JsonRead.TryInteger(row["record_id"],out var id) || id<0) throw new InvalidDataException();
            string xml=Text(row["xml"]); byte[] bytes=Utf8.GetBytes(xml); totalBytes+=bytes.Length;
            if(bytes.Length>1048576 || totalBytes>8*1024*1024) throw new InvalidDataException();
            var native=EventXml.Parse(xml,source,"",channel);
            foreach(string key in new[]{"event_id","provider_name","record_id","time_created"}) if(!Equal(row[key],native[key])) throw new InvalidDataException();
            var root=EventXml.ParseBounded(xml); string? xmlChannel=EventXml.NativeChannel(root);
            if(xmlChannel is not null && xmlChannel!=channel) throw new InvalidDataException();
            var data=new Dictionary<string,string?>();
            foreach(var element in root.Descendants(Ns+"EventData").SelectMany(x=>x.Elements(Ns+"Data"))) {
                var key=element.Attribute("Name")?.Value; if(string.IsNullOrEmpty(key)) continue;
                if(!data.TryAdd(key,ElementText(element))) throw new InvalidDataException();
            }
            string foldedChannel=UnicodeCaseFold.Fold(channel),provider=UnicodeCaseFold.Fold(Text(native["provider_name"]));
            if(!JsonRead.TryInteger(native["event_id"],out var eventId)) throw new InvalidDataException();
            var facts=new JsonObject(); string semantic; string family="protection"; JsonObject? logonRoles=null,logonQuality=null; int maskedCount=0;
            if(((eventId==4624||eventId==4625||eventId==4634||eventId==4647||eventId==4688||eventId==4697||eventId==4698||eventId==4699||eventId==4700||eventId==4701||eventId==4702||eventId==4719||eventId==4732||eventId==4733) && foldedChannel=="security" && provider=="microsoft-windows-security-auditing") || (eventId==7045 && foldedChannel=="system" && provider=="service control manager")) {
                if((eventId==4732||eventId==4733) && SourceText(data,"TargetSid")!="S-1-5-32-544") continue;
                family=(eventId==4688||eventId==4697||eventId==7045||eventId==4698||eventId==4699||eventId==4700||eventId==4701||eventId==4702)?"processes":(eventId==4719||eventId==4732||eventId==4733)?"protection":"logons"; (semantic,logonRoles,facts,logonQuality)=WorkstationLogonProjection.Build((int)eventId,channel,Text(native["provider_name"]),data,agentKey,adComputerId);
            } else if(eventId==4104 && foldedChannel=="microsoft-windows-powershell/operational" && provider=="microsoft-windows-powershell") {
                semantic="powershell.script_block.observed"; bool scriptTruncated=false;
                if(data.TryGetValue("ScriptBlockText",out var script) && script is not null){var masked=ScriptSecrets.Mask(script);facts["script_block_text"]=masked.Text;maskedCount=masked.Count;scriptTruncated=masked.Truncated;if(masked.Text.StartsWith(ScriptSecrets.MaskFailed,StringComparison.Ordinal))facts["script_masking_failed"]=true;}
                if(data.TryGetValue("SecretsMasked",out var count) && count is {Length:>0 and <=4} && count.All(c=>c is >= '0' and <= '9') && int.TryParse(count,out var agentCount) && agentCount<=8192)maskedCount+=agentCount;
                facts["secrets_masked"]=maskedCount;string? blockId=SourceText(data,"ScriptBlockId");if(blockId is not null)facts["script_block_id"]=blockId;facts["script_block_text_truncated"]=data.GetValueOrDefault("ScriptBlockTextTruncated")=="true" || scriptTruncated;
            } else if(eventId==1102 && foldedChannel=="security" && provider=="microsoft-windows-eventlog") {
                semantic="security.audit.cleared"; facts["log_cleared"]=true;
            } else if((eventId==7036||eventId==7040) && foldedChannel=="system" && provider=="service control manager") {
                semantic=eventId==7036?"service.state.changed":"service.start_type.changed";
                void Put(string key,params string[] names) { var value=SourceText(data,names); if(value is not null) facts[key]=value; }
                Put("service_name","ServiceName","param4","param1"); Put("service_display_name","param1","ServiceName");
                if(eventId==7036) Put("service_state","State","param2");
                else { Put("start_type","StartType","param3"); Put("previous_start_type","OldStartType","param2"); }
            } else if((eventId==5001||eventId==5010||eventId==5012) && foldedChannel=="microsoft-windows-windows defender/operational" && provider=="microsoft-windows-windows defender") {
                semantic="security.protection.disabled";facts["protection_component"]=eventId==5001?"real_time":eventId==5010?"malware_scanning":"virus_scanning";
            } else if((eventId==6416 && foldedChannel=="security" && provider=="microsoft-windows-security-auditing")
                || ((eventId==400||eventId==410||eventId==420) && foldedChannel=="microsoft-windows-kernel-pnp/configuration" && provider=="microsoft-windows-kernel-pnp")
                || ((eventId==2003||eventId==2100||eventId==2101) && foldedChannel=="microsoft-windows-driverframeworks-usermode/operational" && provider=="microsoft-windows-driverframeworks-usermode")) {
                family="usb";semantic="device.external.observed";
                string? device=SourceText(data,"DeviceId","DeviceInstanceId","InstanceId","DeviceInstanceID");
                string? deviceClass=SourceText(data,"ClassId","ClassGuid","ClassName");
                string? removable=SourceText(data,"Removable","IsRemovable");
                string? foldedClass=deviceClass is null?null:UnicodeCaseFold.Fold(deviceClass);
                bool storage=HasStoragePrefix(device) || (removable is "true" or "1") && foldedClass is "diskdrive" or "volume" or "{4d36e967-e325-11ce-bfc1-08002be10318}" or "{71a27cdd-812a-11d0-bec7-08002be2092f}";
                if(foldedChannel!="security" && !storage) continue;
                void Put(string key,string? value) { if(value is not null) facts[key]=value; }
                Put("device_id",device); Put("device_class",deviceClass); Put("device_location",SourceText(data,"LocationInformation","Location"));
                Put("device_description",SourceText(data,"DeviceDescription","DeviceName")); facts["storage_evidence"]=storage;
            } else continue;
            string timestamp=Text(native["time_created"]).Replace("Z","+00:00",StringComparison.Ordinal);
            if(!PythonIsoDateTime.TryParse(timestamp,out var parsed) || !parsed.IsAware || !parsed.TryToUtc(out var time)) throw new InvalidDataException();
            bool mutated=data.GetValueOrDefault("CollectionFieldsTruncated")=="true" || data.GetValueOrDefault("ScriptBlockTextTruncated")=="true" || (eventId==4104 && maskedCount>0);
            var observation=new JsonObject {
                ["agent_key"]=agentKey,["entity_id"]=entityId,["ad_computer_id"]=adComputerId,
                ["family"]=family,["semantic_type"]=semantic,["roles"]=logonRoles ?? new JsonObject{["source_host"]=agentKey},
                ["facts"]=facts,["quality"]=logonQuality ?? new JsonObject{["raw_event_mutated"]=mutated,["observation_only"]=family=="usb",["ad_enrichment"]=adComputerId is not null?"available":"not_collected",["coverage"]="not_proven"},
                ["event_id"]=native["event_id"]?.DeepClone(),["channel"]=channel,["provider_name"]=native["provider_name"]?.DeepClone(),["generation"]=generation,
                ["record_id"]=JsonRead.Integer(id),["observed_at"]=Iso8601.Format(time),["keywords"]=native["keywords"]?.DeepClone(),
                ["source_sha256"]=Convert.ToHexStringLower(SHA256.HashData(bytes))
            };
            if(signatures.TryGetValue(id,out var signature)) observation["file_signature"]=signature.DeepClone();
            var identity=new JsonArray(JsonValue.Create(agentKey),JsonValue.Create(channel),JsonValue.Create(generation),JsonRead.Integer(id));
            output.Add(new WorkstationObservation(Packets.Digest(identity),observation,Packets.Digest(observation),xml,time));
        }
        return output;
    }
    private static string Text(JsonNode? n)=>JsonRead.TryString(n,out var value)?value:throw new InvalidDataException();
    // Generated from CPython 3.14.6 Unicode16 uppercase for just the two ASCII storage prefixes.
    // Non-ASCII characters capable of producing prefix letters are ß->SS, ſ->S, ﬅ/ﬆ->ST.
    private static bool HasStoragePrefix(string? value)
    {
        if(value is null) return false;
        const string usb="USBSTOR\\",uasp="UASPSTOR\\"; var prefix=new StringBuilder();
        foreach(var rune in value.EnumerateRunes()) {
            string upper=rune.Value switch {
                >= 'a' and <= 'z' => ((char)(rune.Value-'a'+'A')).ToString(),
                0x00DF => "SS", 0x017F => "S", 0xFB05 or 0xFB06 => "ST",
                <= 0x7F => ((char)rune.Value).ToString(), _ => "\uFFFD"
            };
            foreach(char c in upper) {prefix.Append(c);string candidate=prefix.ToString();
                if(candidate==usb||candidate==uasp) return true;
                if(!usb.StartsWith(candidate,StringComparison.Ordinal) && !uasp.StartsWith(candidate,StringComparison.Ordinal)) return false;
            }
        }
        return false;
    }
    private static string? SourceText(IReadOnlyDictionary<string,string?> data,params string[] keys)
    {
        static bool Space(char c)=>c is '\u0009' or '\u000A' or '\u000B' or '\u000C' or '\u000D' or '\u001C' or '\u001D' or '\u001E' or '\u001F' or '\u0020' or '\u0085' or '\u00A0' or '\u1680' or '\u2000' or '\u2001' or '\u2002' or '\u2003' or '\u2004' or '\u2005' or '\u2006' or '\u2007' or '\u2008' or '\u2009' or '\u200A' or '\u2028' or '\u2029' or '\u202F' or '\u205F' or '\u3000';
        foreach(string key in keys) {
            if(!data.TryGetValue(key,out var value) || value is null) continue;
            int start=0,end=value.Length; while(start<end&&Space(value[start])) start++; while(end>start&&Space(value[end-1])) end--;
            if(start==end) continue; string trimmed=value[start..end]; if(trimmed=="-") continue;
            var result=new StringBuilder(); foreach(var rune in trimmed.EnumerateRunes().Take(512)) result.Append(rune.ToString()); return result.ToString();
        }
        return null;
    }
    private static string? ElementText(XElement element) { var values=element.Nodes().TakeWhile(n=>n is not XElement).OfType<XText>().Select(x=>x.Value).ToArray(); return values.Length==0?null:string.Concat(values); }
    private static bool Equal(JsonNode? left,JsonNode? right)
    {
        if(JsonNode.DeepEquals(left,right)) return true;
        if(JsonRead.TryInteger(left,out BigInteger integer)) return Matches(right,integer);
        if(JsonRead.TryInteger(right,out integer)) return Matches(left,integer);
        return false;
    }
    private static bool Matches(JsonNode? value,BigInteger n)
    {
        if(value is JsonValue v && v.TryGetValue<bool>(out var flag)) return n==(flag?1:0);
        return value is JsonValue scalar && scalar.GetValueKind()==System.Text.Json.JsonValueKind.Number
            && double.TryParse(value.ToJsonString(),System.Globalization.NumberStyles.Float,System.Globalization.CultureInfo.InvariantCulture,out var d)
            && double.IsFinite(d) && Math.Truncate(d)==d && new BigInteger(d)==n;
    }
}

