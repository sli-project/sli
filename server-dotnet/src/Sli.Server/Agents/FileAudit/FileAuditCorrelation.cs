using System.Net;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Registry;
using Sli.Server.Agents.Ingress;

namespace Sli.Server.Agents.FileAudit;

// File-audit correlation.py: bounded preceding evidence; no ingestion or acknowledgement.
internal static class FileAuditCorrelation
{
    private static string? S(JsonNode? n)=>n?.GetValue<string>();
    private static long I(JsonNode? n)=>JsonRead.TryInteger(n,out var value) ? checked((long)value) : throw new InvalidDataException();
    private static ulong N(JsonNode? n)=>n is null?0:JsonRead.TryInteger(n,out var value) ? checked((ulong)value) : throw new InvalidDataException();
    private static DateTimeOffset T(JsonNode? n)=>DateTimeOffset.Parse(S(n)!,System.Globalization.CultureInfo.InvariantCulture);
    private static bool Eq(JsonNode? a,JsonNode? b)=>PythonMetadataEquality.Equal(a,b);
    private static JsonObject Ref(JsonObject item,string role)=>new() { ["evidence_key"]=item["evidence_key"]!.DeepClone(), ["core_evidence_ref"]=item["core_evidence_ref"]!.DeepClone(), ["role"]=role };
    private static List<JsonObject> Available(JsonObject item,IEnumerable<JsonObject> contexts)
    {
        var now=T(item["observed_at"]); long record=I(item["record_id"]);
        var available=contexts.Where(x=>new[]{"agent_id","source_instance_id","generation","policy_revision"}.All(k=>Eq(x[k],item[k]))
            && I(x["record_id"])<record && T(x["observed_at"])>=now.AddSeconds(-300) && T(x["observed_at"])<=now).ToList();
        long boot=available.Where(x=>I(x["event_id"]) is 4608 or 1102).Select(x=>I(x["record_id"])).DefaultIfEmpty().Max();
        return available.Where(x=>I(x["record_id"])>boot).ToList();
    }
    private static List<JsonObject> Related(JsonObject item,IEnumerable<JsonObject> contexts)
    {
        string[] fields=["subject_user_sid","logon_id_numeric","server_process_id","handle_id"];
        return Available(item,contexts).Where(x=>I(x["event_id"]) is 4656 or 4659 or 4663 or 4658 or 4660
            && fields.All(k=>Eq(x["facts"]![k],item["facts"]![k]))).ToList();
    }
    private static bool HasHandle(JsonObject facts)=>N(facts["handle_id"])!=0 && new[]{"subject_user_sid","logon_id_numeric","server_process_id","handle_id"}.All(k=>facts[k] is not null);
    public static (string State,JsonObject? Chosen) DeleteContext(JsonObject item,IEnumerable<JsonObject> contexts)
    {
        var facts=item["facts"]!.AsObject();
        if(S(facts["outcome"])!="success") return ("partial",null);
        if(!HasHandle(facts)) return ("ambiguous",null);
        var related=Related(item,contexts); long boundary=related.Where(x=>I(x["event_id"]) is 4658 or 4660).Select(x=>I(x["record_id"])).DefaultIfEmpty().Max();
        if(related.Any(x=>I(x["record_id"])>boundary && I(x["event_id"])!=4660 && string.IsNullOrEmpty(S(x["path"])))) return ("ambiguous",null);
        var candidates=related.Where(x=>I(x["record_id"])>boundary && !string.IsNullOrEmpty(S(x["path"])) && S(x["facts"]!["outcome"])=="success").ToList();
        int count=candidates.Select(x=>UnicodeCaseFold.Fold(S(x["path"])!)).Distinct().Count();
        if(count!=1) return (count>0 || boundary>0 ? "ambiguous" : "partial",null);
        return ("complete",candidates.MaxBy(x=>I(x["record_id"])));
    }
    private static (JsonObject Open,JsonObject Previous)? Rename(JsonObject item,IEnumerable<JsonObject> contexts)
    {
        var f=item["facts"]!.AsObject();
        if(I(item["event_id"])!=4663 || S(f["outcome"])!="success" || string.IsNullOrEmpty(S(item["path"])) || !HasHandle(f) || (N(f["access_mask"]) & 0x10006)==0) return null;
        var related=Related(item,contexts); long boundary=related.Where(x=>I(x["event_id"]) is 4656 or 4658 or 4660).Select(x=>I(x["record_id"])).DefaultIfEmpty().Max();
        var opened=related.FirstOrDefault(x=>I(x["record_id"])==boundary && I(x["event_id"])==4656 && S(x["facts"]!["outcome"])=="success" && !string.IsNullOrEmpty(S(x["path"])));
        if(opened is null || (N(opened["facts"]!["access_mask"]) & 0x10000)==0) return null;
        var previous=related.Where(x=>I(x["record_id"])>boundary && I(x["event_id"])==4663).ToList();
        string path=UnicodeCaseFold.Fold(S(opened["path"])!);
        if(previous.Count==0 || previous.Any(x=>string.IsNullOrEmpty(S(x["path"])) || UnicodeCaseFold.Fold(S(x["path"])!)!=path || S(x["facts"]!["outcome"])!="success") || UnicodeCaseFold.Fold(S(item["path"])!)==path) return null;
        var deleted=previous.Where(x=>(N(x["facts"]!["access_mask"]) & 0x10000)!=0).MaxBy(x=>I(x["record_id"]));
        return deleted is null ? null : (opened,deleted);
    }
    private static string? Address(string? text)
    {
        if(string.IsNullOrEmpty(text) || text.Any(char.IsWhiteSpace)) return null;
        var parts=text.Split('%'); if(parts.Length>2 || parts.Length==2 && parts[1].Length==0) return null;
        string address=parts[0];
        if(address.Contains('.'))
        {
            string dotted=address[(address.LastIndexOf(':')+1)..]; var octets=dotted.Split('.');
            if(octets.Length!=4 || octets.Any(x=>x.Length==0 || x.Length>3 || x.Length>1 && x[0]=='0' || x.Any(c=>!char.IsAsciiDigit(c)) || !int.TryParse(x,out int n) || n>255)) return null;
        }
        if(!IPAddress.TryParse(address,out var ip)) return null;
        if(ip.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork) return parts.Length==1 && address.Count(c=>c=='.')==3 ? ip.ToString() : null;
        byte[] bytes=ip.GetAddressBytes(); var groups=new int[8]; for(int i=0;i<8;i++) groups[i]=(bytes[i*2]<<8)|bytes[i*2+1];
        int bestStart=-1,bestLength=1;
        for(int i=0;i<8;) { if(groups[i]!=0){i++;continue;} int j=i;while(j<8 && groups[j]==0) j++; if(j-i>bestLength){bestStart=i;bestLength=j-i;} i=j; }
        string formatted;
        if(bestStart<0) formatted=string.Join(':',groups.Select(x=>x.ToString("x")));
        else { string left=string.Join(':',groups.Take(bestStart).Select(x=>x.ToString("x"))); string right=string.Join(':',groups.Skip(bestStart+bestLength).Select(x=>x.ToString("x"))); formatted=left+"::"+right; }
        return formatted+(parts.Length==2 ? "%"+parts[1] : "");
    }
    public static JsonArray ProjectActions(JsonObject item,JsonArray prior,string objectType="unknown")
    {
        var contexts=prior.OfType<JsonObject>().ToList(); var f=item["facts"]!.AsObject(); long id=I(item["event_id"]);
        if(FileAuditPolicy.ContextEvents.Contains((int)id) || id==4658) return [];
        var scopes=item["scopes"]!.AsArray().OfType<JsonObject>().ToList(); string? path=S(item["path"]); string state="complete";
        var evidence=new JsonArray(Ref(item,"primary")); var operations=new List<string>();
        if(id==4660) { var (status,chosen)=DeleteContext(item,contexts); state=status; if(chosen is null) return []; scopes=chosen["scopes"]!.AsArray().OfType<JsonObject>().ToList(); path=S(chosen["path"]); evidence.Add(Ref(chosen,"handle_context")); operations.Add("delete"); }
        else if(id==4663) {
            if(S(f["outcome"])!="success") return []; var mask=N(f["access_mask"]);
            if((mask&1)!=0 && objectType!="directory") operations.Add("read"); if((mask&6)!=0) operations.Add("write"); if((mask&0x10000)!=0) operations.Add("delete_right");
            var rename=Rename(item,contexts); if(rename is not null) { var (opened,previous)=rename.Value; var admitted=opened["scopes"]!.AsArray().OfType<JsonObject>().Select(x=>S(x["collection_scope_id"])).Intersect(previous["scopes"]!.AsArray().OfType<JsonObject>().Select(x=>S(x["collection_scope_id"]))).ToHashSet(); scopes=scopes.Where(x=>admitted.Contains(S(x["collection_scope_id"]))).ToList(); operations=["rename"]; evidence.Add(Ref(opened,"handle_context")); evidence.Add(Ref(previous,"handle_context")); }
        }
        else operations.Add(id switch { 4656 or 5140 or 5145 or 5168=>"access_check",4659=>"delete_right",4670=>"permissions",5142 or 5143 or 5144=>"share_change",4907=>"audit_change",_=>"unknown" });
        string? ip=null,ipSource=null;
        if(id is 5140 or 5145 or 5168 && Address(S(f["ip_address"])) is { } direct) { ip=direct; ipSource=$"event:{id}"; }
        var available=Available(item,contexts);
        if(ip is null && !string.IsNullOrEmpty(S(f["subject_user_sid"])) && N(f["logon_id_numeric"])!=0) {
            var logons=available.Where(x=>I(x["event_id"])==4624 && S(x["facts"]!["outcome"])=="success" && Eq(x["facts"]!["subject_user_sid"],f["subject_user_sid"]) && Eq(x["facts"]!["logon_id_numeric"],f["logon_id_numeric"])).ToList();
            var addresses=logons.Select(x=>S(x["facts"]!["ip_address"])).Distinct().ToList();
            if(addresses.Count==1 && !available.Any(x=>I(x["event_id"])==4634 && Eq(x["facts"]!["logon_id_numeric"],f["logon_id_numeric"])) && Address(addresses[0]) is { } parsed) { ip=parsed;ipSource="event:4624";evidence.Add(Ref(logons[^1],"logon_context")); }
        }
        var result=new JsonArray(); bool excluded=item["excluded"]!.GetValue<bool>(); string outcome=S(f["outcome"])!;
        foreach(var scope in scopes) foreach(var operation in operations) {
            if(operation=="read" && (!scope["important"]!.GetValue<bool>() || excluded)) continue;
            if(excluded && operation is "write" or "delete_right" or "delete" or "rename" && outcome!="failure") continue;
            string quality=operation=="delete_right" || operation=="read" && objectType=="unknown" ? "partial" : state;
            string action=Packets.Digest(new JsonArray(item["evidence_key"]!.DeepClone(),scope["collection_scope_id"]!.DeepClone(),operation,1));
            result.Add(new JsonObject { ["action_id"]=action,["agent_id"]=item["agent_id"]!.DeepClone(),["source_instance_id"]=item["source_instance_id"]!.DeepClone(),["collection_scope_id"]=scope["collection_scope_id"]!.DeepClone(),["observed_at"]=item["observed_at"]!.DeepClone(),["subject_sid"]=f["subject_user_sid"]?.DeepClone(),["logon_id"]=f["logon_id"]?.DeepClone(),["path"]=path,["share_name"]=scope["share_name"]!.DeepClone(),["object_type"]=objectType,["access_mask"]=f["access_mask"]?.DeepClone(),["operation"]=operation,["outcome"]=outcome,["denial_layer"]=outcome=="failure" ? id==4656?"ntfs":id is 5145 or 5168?"smb":null : null,["client_ip"]=ip,["client_ip_source"]=ipSource,["server_process_id"]=f["server_process_id"]?.DeepClone(),["handle_id"]=f["handle_id"] is null?null:N(f["handle_id"]).ToString(System.Globalization.CultureInfo.InvariantCulture),["correlation_state"]=quality,["projection_version"]=1,["contract_version"]=1,["evidence"]=evidence.DeepClone() });
        }
        return result;
    }
}
