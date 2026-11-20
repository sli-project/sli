using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Agents.Ingress;

namespace Sli.Server.Agents.FileAudit;

// Source: file_audit/rules.py permission_findings and acl.py token_for.
public static class FileAuditPermissionRules
{
    private static string S(JsonNode? value) => value!.GetValue<string>();
    private static bool B(JsonNode? value) => value is JsonValue v && v.TryGetValue<bool>(out var flag) && flag;
    private static string Fold(string path) => UnicodeLower.Lower(path.Replace('/','\\'));
    private static bool InRoot(string path,string root) { path=Fold(AgentFileAuditPolicy.NormalizePath(path)); root=Fold(AgentFileAuditPolicy.NormalizePath(root)); return path==root || path.StartsWith(root.TrimEnd('\\')+"\\",StringComparison.Ordinal); }
    private static JsonObject Finding(string code,JsonObject snapshot,string? subject,JsonObject details,string state="observed")
    {
        string agent=S(snapshot["agent_id"]),source=S(snapshot["source_instance_id"]),scope=S(snapshot["collection_scope_id"]);
        var actionIds=new JsonArray(); var snapshotIds=new JsonArray(S(snapshot["snapshot_id"]));
        var identity=new JsonArray(code,1,new JsonArray(agent,source,scope),subject,actionIds.DeepClone(),snapshotIds.DeepClone(),details.DeepClone());
        return new JsonObject { ["result_id"]=Packets.Digest(identity),["rule_code"]=code,["rule_version"]=1,["agent_id"]=agent,["source_instance_id"]=source,["collection_scope_id"]=scope,["subject_sid"]=subject,["observed_at"]=S(snapshot["observed_at_utc"]),["conclusion_state"]=state,["action_ids"]=actionIds,["snapshot_ids"]=snapshotIds,["details"]=details };
    }
    internal static (HashSet<string> Token,bool Complete) Token(string sid,JsonObject principal,JsonObject localGroups)
    {
        var token=new HashSet<string>(StringComparer.Ordinal) { sid,"S-1-1-0" };
        bool complete=B(principal["complete"]) && B(localGroups["complete"]);
        if(complete) { if(principal["group_sids"] is JsonArray groups) foreach(var group in groups) token.Add(S(group)); if(sid!="S-1-5-7") token.Add("S-1-5-11"); }
        var local=localGroups["groups"]!.AsArray();
        for(int i=0;i<=local.Count;i++) { int previous=token.Count; foreach(var item in local.OfType<JsonObject>()) if(item["member_sids"]!.AsArray().Any(s=>token.Contains(S(s)))) token.Add(S(item["group_sid"])); if(token.Count==previous) break; }
        return (token,complete);
    }
    public static JsonArray Evaluate(JsonObject snapshot,JsonObject config,JsonObject principals)
    {
        string scope=S(snapshot["collection_scope_id"]); var root=config["roots"]!.AsArray().OfType<JsonObject>().FirstOrDefault(r=>S(r["collection_scope_id"])==scope);
        var share=snapshot["share"]!.AsObject();
        if(root is null || Fold(S(share["path"]))!=Fold(S(root["path"]))) throw new InvalidDataException("file_audit_snapshot_scope_invalid");
        var shareAcl=FileAuditAcl.Parse(S(share["dacl"])); bool shareKnown=shareAcl.Complete && B(share["complete"]);
        var objects=snapshot["objects"]!.AsArray().OfType<JsonObject>().Select(o=>(Layer:"ntfs",Object:o)).ToList();
        if(config["source_kind"]?.GetValue<string>()!="workstation") objects.Add(("smb",new JsonObject { ["path"]=S(root["path"]),["dacl"]=S(share["dacl"]) }));
        var results=new List<JsonObject>();
        foreach(var (layer,obj) in objects)
        {
            string path=S(obj["path"]); if(!InRoot(path,S(root["path"]))) throw new InvalidDataException("file_audit_snapshot_scope_invalid");
            var acl=FileAuditAcl.Parse(S(obj["dacl"]));
            if(!acl.Complete) { results.Add(Finding("file-audit.acl-review",snapshot,null,new JsonObject { ["path"]=path,["layer"]=layer,["reason"]="unsupported_descriptor" },"requires_review")); continue; }
            foreach(string sid in acl.Aces.Where(a=>a.Kind=="A" && !a.InheritOnly).Select(a=>a.Sid).Distinct().Order(StringComparer.Ordinal))
            {
                if(config["service_account_exclusions"]!.AsArray().Any(x=>S(x)==sid)) continue;
                var principal=principals[sid] as JsonObject ?? new JsonObject(); var (token,complete)=Token(sid,principal,snapshot["local_groups"]!.AsObject());
                uint mask=FileAuditAcl.AccessMask(acl.Aces,new HashSet<string>(StringComparer.Ordinal) { sid,"S-1-1-0" }); if(mask==0) continue;
                if(principal.Count==0 && sid.StartsWith("S-1-5-21-",StringComparison.Ordinal)) results.Add(Finding("file-audit.acl-review",snapshot,sid,new JsonObject { ["path"]=path,["layer"]=layer,["reason"]="principal_not_observed" },"requires_review"));
                bool broad=sid=="S-1-1-0" || principal["kind"]?.GetValue<string>()=="group" && B(principal["domain_users"]);
                bool direct=principal["kind"]?.GetValue<string>()=="user" && acl.Aces.Any(a=>a.Sid==sid && a.Kind=="A" && !a.Inherited && !a.InheritOnly);
                var codes=new List<string>(); if(broad && (mask & 0xd0046u)!=0) codes.Add("file-audit.broad-write"); if(direct) codes.Add("file-audit.direct-user-rights");
                if(principal["kind"]?.GetValue<string>()=="user" && principal["enabled"] is JsonValue enabled && enabled.TryGetValue<bool>(out bool flag) && !flag) codes.Add("file-audit.disabled-account-rights");
                uint? effective=layer=="ntfs" && complete && shareKnown ? FileAuditAcl.AccessMask(acl.Aces,token) & FileAuditAcl.AccessMask(shareAcl.Aces,token) : null;
                foreach(string code in codes) results.Add(Finding(code,snapshot,sid,new JsonObject { ["path"]=path,["layer"]=layer,["ntfs_mask"]=layer=="ntfs"?JsonValue.Create(mask):null,["share_mask"]=layer=="smb"?JsonValue.Create(mask):null,["effective_smb_mask"]=effective is null?null:JsonValue.Create(effective.Value),["effective_smb_state"]=effective is null?"requires_review":"dacl_model",["limitations"]=new JsonArray("privileges_and_conditional_aces_not_evaluated"),["coverage_state"]=S(snapshot["completeness"]),["membership_complete"]=complete,["snapshot_sha256"]=S(snapshot["snapshot_sha256"]),["principal"]=principal.DeepClone() }));
            }
        }
        return new JsonArray(results.OrderBy(x=>S(x["result_id"]),StringComparer.Ordinal).Cast<JsonNode?>().ToArray());
    }
}

