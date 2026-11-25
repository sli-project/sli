using System.Text.Json;
using Sli.Server.Access;

namespace Sli.Server.Agents.FileAudit;

// Restricted to file-audit.manage; does not widen the global composer.
public static class FileAuditAccess
{
    private const string Capability="file-audit.audit.manage";
    private static readonly string[] Dimensions=["plugin_ids","source_instance_ids","device_ids","entity_ids","collection_scope_ids"];
    public static bool Allowed(CapabilityDecisionSet access,string role,string principalType,long principalId,string agent,string source,string scope)
    {
        if(principalId<=0 || principalType is not ("session" or "api_key") || !(role=="admin" || principalType=="session" && access.IsOwner)
            || new[]{agent,source,scope}.Any(s=>string.IsNullOrWhiteSpace(s) || s.Length>256)) return false;
        if(access.IsOwner) return true;
        var policies=access.Policies.Where(p=>p.CapabilityKey==Capability).ToArray();
        if(policies.Any(p=>p.Effect=="deny" && (!p.Valid || p.Global))) return false;
        if(policies.Any(p=>p.Effect=="deny" && p.Valid && !p.Global && Matches(p.Scope,agent,source,scope))) return false;
        if(access.Capabilities.Contains(Capability)) return true;
        return policies.Any(p=>p.Effect=="allow" && p.Valid && !p.Global && Matches(p.Scope,agent,source,scope));
    }
    internal static IEnumerable<string> DiscoveryScopes(CapabilityDecisionSet access)
    {
        // Each restricted policy either names a scope or applies equally to all unnamed scopes.
        var named = new HashSet<string>(StringComparer.Ordinal);
        foreach (var policy in access.Policies.Where(p=>p.CapabilityKey==Capability && p.Valid && !p.Global))
        {
            if (policy.Scope.ValueKind!=JsonValueKind.Object || !policy.Scope.TryGetProperty("clauses",out var clauses)
                || clauses.ValueKind!=JsonValueKind.Array) continue;
            foreach (var clause in clauses.EnumerateArray().Where(ValidClauseObject))
                if (clause.TryGetProperty("collection_scope_ids",out var ids))
                    foreach (var id in ids.EnumerateArray()) named.Add(id.GetString()!);
        }
        string unnamed;
        do { unnamed=Guid.NewGuid().ToString("D"); } while (!named.Add(unnamed));
        return named;
    }

    private static bool ValidClauseObject(JsonElement value) => value.ValueKind==JsonValueKind.Object && ValidClause(value);

    private static bool Matches(JsonElement value,string agent,string source,string scope)
    {
        if(value.ValueKind!=JsonValueKind.Object || !value.TryGetProperty("mode",out var mode) || mode.ValueKind!=JsonValueKind.String
            || value.EnumerateObject().Any(p=>p.Name is not ("mode" or "clauses" or "decision_id" or "policy_revision"))) return false;
        foreach(string key in new[]{"decision_id","policy_revision"}) if(value.TryGetProperty(key,out var metadata) && (metadata.ValueKind!=JsonValueKind.String || string.IsNullOrWhiteSpace(metadata.GetString()) || metadata.GetString()!.Length>256)) return false;
        var m=mode.GetString(); var clauses=value.TryGetProperty("clauses",out var c)?c:default;
        if(clauses.ValueKind is not (JsonValueKind.Array or JsonValueKind.Undefined)) return false;
        var items=clauses.ValueKind==JsonValueKind.Array?clauses.EnumerateArray().ToArray():[];
        if(m is not ("none" or "all" or "restricted") || items.Length>100 || (m=="restricted")!=(items.Length>0) || items.Any(x=>!ValidClause(x))) return false;
        if(m=="all") return true; if(m=="none") return false;
        var expected=new Dictionary<string,string?> { ["plugin_ids"]="sli.file-audit",["source_instance_ids"]=source,["device_ids"]=agent,["entity_ids"]=null,["collection_scope_ids"]=scope };
        return items.Any(clause=>clause.EnumerateObject().All(p=>p.Value.GetArrayLength()==0 || expected[p.Name] is string wanted && p.Value.EnumerateArray().Any(x=>x.ValueKind==JsonValueKind.String && x.GetString()==wanted)));
    }
    private static bool ValidClause(JsonElement clause)
    {
        if(clause.ValueKind!=JsonValueKind.Object || clause.EnumerateObject().Any(p=>!Dimensions.Contains(p.Name))) return false;
        bool populated=false;
        foreach(var property in clause.EnumerateObject())
        {
            var v=property.Value; if(v.ValueKind!=JsonValueKind.Array || v.GetArrayLength()>100) return false; populated|=v.GetArrayLength()>0;
            if(property.Name=="entity_ids") { if(v.EnumerateArray().Any(x=>x.ValueKind!=JsonValueKind.Number || !x.TryGetInt64(out var n) || n<=0) || v.EnumerateArray().Select(x=>x.GetInt64()).Distinct().Count()!=v.GetArrayLength()) return false; }
            else if(v.EnumerateArray().Any(x=>x.ValueKind!=JsonValueKind.String || string.IsNullOrEmpty(x.GetString()) || x.GetString()!.Length>256 || x.GetString()!.Trim()!=x.GetString()) || v.EnumerateArray().Select(x=>x.GetString()).Distinct().Count()!=v.GetArrayLength()) return false;
        }
        return populated;
    }
}
