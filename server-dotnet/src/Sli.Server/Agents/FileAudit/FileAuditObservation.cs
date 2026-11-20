using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;

namespace Sli.Server.Agents.FileAudit;

// Only called after packet and original-policy attestation in the import transaction.
internal static class FileAuditObservation
{
    public static JsonObject Build(JsonObject row, FileAuditPolicy policy, string agent, string source, string generation, string revision, string reference)
    {
        string raw=row["xml"]!.GetValue<string>();
        string boundSource=policy.Value["source_name"]?.GetValue<string>() ?? source;
        AgentFileAuditEvents.Validate(row,policy,boundSource);
        var root=EventXml.ParseBounded(raw); XNamespace ns=EventXml.Namespace;
        var data=new Dictionary<string,string>();
        foreach(var item in root.Elements(ns+"EventData").SelectMany(x=>x.Elements(ns+"Data")))
            data.Add(item.Attribute("Name")!.Value,item.Value);
        int id=row["event_id"]!.GetValue<int>();
        var scopes=AgentFileAuditEvents.ScopeAndPath(id,data,policy,out var path);
        bool context=FileAuditPolicy.ContextEvents.Contains(id);
        long record=row["record_id"]!.GetValue<long>();
        int version=row["version"]?.GetValue<int>() ?? 0;
        string evidence=context ? Packets.Digest(new JsonArray(agent,source,"Security",generation,record)) : FileAuditEvidence.EvidenceKey(agent,source,generation,record,id,version);
        JsonObject facts;
        if(context)
        {
            string? sid=data.GetValueOrDefault("TargetUserSid"); if(string.IsNullOrEmpty(sid)) sid=data.GetValueOrDefault("SubjectUserSid");
            string? logon=data.GetValueOrDefault("TargetLogonId"); if(string.IsNullOrEmpty(logon)) logon=data.GetValueOrDefault("SubjectLogonId");
            JsonNode? number=FileAuditEvidence.TryNumber(logon,out var n) && n>=0 && n<=ulong.MaxValue ? JsonValue.Create((ulong)n) : null;
            var rawFacts=FileAuditEvidence.NativeFacts(new JsonObject { ["event_id"]=4663, ["channel"]="Security", ["provider_name"]=FileAuditPolicy.Provider, ["keywords"]=row["keywords"]?.DeepClone() },new JsonObject());
            facts=new JsonObject { ["subject_user_sid"]=sid, ["logon_id_numeric"]=number, ["ip_address"]=data.GetValueOrDefault("IpAddress"), ["outcome"]=rawFacts["outcome"]!.DeepClone() };
        }
        else
        {
            var values=new JsonObject(); foreach(var (key,value) in data) values[key]=value;
            facts=FileAuditEvidence.NativeFacts(row,values);
        }
        var projectedScopes=new JsonArray();
        foreach(var scope in scopes) projectedScopes.Add(new JsonObject { ["collection_scope_id"]=scope["collection_scope_id"]!.DeepClone(), ["share_name"]=scope["share_name"]!.DeepClone(), ["important"]=scope["important"]!.DeepClone() });
        var instant=DateTimeOffset.Parse(row["time_created"]!.GetValue<string>(),CultureInfo.InvariantCulture,DateTimeStyles.RoundtripKind).ToUniversalTime();
        string observed=instant.ToString(instant.Ticks%TimeSpan.TicksPerSecond==0 ? "yyyy-MM-dd'T'HH:mm:sszzz" : "yyyy-MM-dd'T'HH:mm:ss.ffffffzzz",CultureInfo.InvariantCulture);
        return new JsonObject { ["evidence_key"]=evidence,["agent_id"]=agent,["source_instance_id"]=source,["generation"]=generation,
            ["record_id"]=record,["event_id"]=id,["event_version"]=version,["provider"]=row["provider_name"]!.DeepClone(),["channel"]="Security",
            ["observed_at"]=observed,["policy_revision"]=revision,["core_evidence_ref"]=reference,
            ["payload_sha256"]=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(raw))),["facts"]=facts,["path"]=path,["scopes"]=projectedScopes,
            ["correlation_state"]="not_attempted",["excluded"]=policy.Value["service_account_exclusions"]!.AsArray().Any(x=>x?.GetValue<string>()==data.GetValueOrDefault("SubjectUserSid")) };
    }
}
