using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Agents.Ingress;

internal static class AgentWorkstationEvidence
{
    private static readonly XNamespace Ns=EventXml.Namespace;
    private static void Require(bool value) { if (!value) throw new ArgumentException(); }
    public static void Validate(JsonArray rows,JsonObject context,WorkstationPolicy policy,string channel,string version,string observed)
    {
        int index=Array.IndexOf(WorkstationPolicy.Channels,channel); Require(index>=0);
        foreach(var node in rows)
        {
            var row=node!.AsObject(); var root=EventXml.ParseBounded(row["xml"]!.GetValue<string>()); var data=new Dictionary<string,string?>();
            foreach(var field in root.Descendants(Ns+"EventData").SelectMany(x=>x.Elements(Ns+"Data")))
            {
                string? name=field.Attribute("Name")?.Value;
                if (!string.IsNullOrEmpty(name)) { Require(!data.ContainsKey(name)); data.Add(name,Text(field)); }
            }
            Require(Allowed(row,data,policy,index));
            if (new[]{1102,7036,7040,4104}.Any(id=>PythonMetadataEquality.Equal(row["event_id"],JsonValue.Create(id))))
            {
                Require(version==WorkstationsModule.ModuleVersion);
                foreach(var pair in data) Require(Encoding.UTF8.GetByteCount(pair.Value ?? "") <= (pair.Key=="ScriptBlockText" ? 8192 : 512));
            }
        }
        ValidateSignatures(context["process_signatures"],rows,observed);
    }
    private static string? Text(XElement? node)
    {
        if (node is null) return null; var b=new StringBuilder(); bool any=false;
        foreach(var item in node.Nodes()) { if (item is XElement) break; if (item is XText t) { b.Append(t.Value); any=true; } }
        return any ? b.ToString() : null;
    }
    private static bool Allowed(JsonObject row,Dictionary<string,string?> data,WorkstationPolicy policy,int index)
    {
        var match=WorkstationPolicy.ChannelEvents[index].Where(id=>PythonMetadataEquality.Equal(row["event_id"],JsonValue.Create(id))).Select(id=>(int?)id).FirstOrDefault();
        if(match is null) return false; int id=match.Value;
        string provider=id==1102 ? "Microsoft-Windows-Eventlog" : WorkstationPolicy.Providers[index];
        if (!WorkstationPolicy.ChannelEvents[index].Contains(id) || !JsonRead.TryString(row["provider_name"],out var actual)
            || UnicodeCaseFold.Fold(actual)!=UnicodeCaseFold.Fold(provider)) return false;
        string family=WorkstationPolicy.FamilyEvents.First(pair=>pair.Value.Contains(id)).Key;
        if (!policy.FamilyEnabled(family) || id is 4732 or 4733 && data.GetValueOrDefault("TargetSid")!="S-1-5-32-544") return false;
        if (id is 7036 or 7040)
        {
            var names=WorkstationsModule.ProtectedServices.Concat((policy.Value["protected_services"] as JsonArray ?? []).Select(x=>x!.GetValue<string>())).Select(UnicodeCaseFold.TrimAndFold).ToHashSet();
            string service=data.GetValueOrDefault("ServiceName") ?? (id==7040 ? data.GetValueOrDefault("param4") : null) ?? data.GetValueOrDefault("param1") ?? "";
            if (!names.Contains(UnicodeCaseFold.TrimAndFold(service))) return false;
        }
        foreach(var filter in new[]{policy.Value,policy.Value["family_filters"]?[family] as JsonObject ?? new JsonObject()})
        {
            if (filter["allow_event_ids"] is JsonArray allow && !allow.Any(x=>JsonRead.TryInteger(x,out var n) && n==id)
                || filter["deny_event_ids"] is JsonArray deny && deny.Any(x=>JsonRead.TryInteger(x,out var n) && n==id)) return false;
            if (id==4688)
            {
                string path=UnicodeCaseFold.Fold((data.GetValueOrDefault("NewProcessName") ?? "").Replace('\\','/'));
                if (filter["allow_process_paths"] is JsonArray paths && paths.Count>0 && !paths.Any(x=>Glob(path,x!.GetValue<string>()))
                    || filter["deny_process_paths"] is JsonArray excluded && excluded.Any(x=>Glob(path,x!.GetValue<string>()))) return false;
            }
        }
        return true;
    }
    private static bool Glob(string path,string raw)
    {
        int[] pattern=UnicodeCaseFold.Fold(raw.Replace('\\','/')).EnumerateRunes().Select(x=>x.Value).ToArray();
        int[] input=path.EnumerateRunes().Select(x=>x.Value).ToArray();
        bool[] prior=new bool[input.Length+1]; prior[0]=true;
        for(int i=0;i<pattern.Length;i++)
        {
            int token=pattern[i]; bool[] next=new bool[input.Length+1];
            if (token=='*')
            {
                next[0]=prior[0]; for(int j=1;j<next.Length;j++) next[j]=prior[j] || next[j-1];
            }
            else
            {
                int end=-1,start=i+1; bool negate=false;
                if (token=='[')
                {
                    if (start<pattern.Length && pattern[start]=='!') { negate=true; start++; }
                    int scan=start; if (scan<pattern.Length && pattern[scan]==']') scan++;
                    for(;scan<pattern.Length;scan++) if (pattern[scan]==']') { end=scan; break; }
                }
                for(int j=1;j<next.Length;j++)
                {
                    bool match=token=='?' || token==input[j-1];
                    if (end>=0)
                    {
                        bool member=false;
                        for(int k=start;k<end;k++)
                        {
                            if (k+2<end && pattern[k+1]=='-') { if (pattern[k]<=input[j-1] && input[j-1]<=pattern[k+2]) member=true; k+=2; }
                            else if (pattern[k]==input[j-1]) member=true;
                        }
                        match=negate ? !member : member;
                    }
                    next[j]=prior[j-1] && match;
                }
                if (end>=0) i=end;
            }
            prior=next;
        }
        return prior[input.Length];
    }
    private static void ValidateSignatures(JsonNode? entries,JsonArray rows,string packetTime) => WorkstationSignatureEvidence.Validate(entries,rows,packetTime);
}
