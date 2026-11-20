using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Registry;
using Sli.Server.Agents.Ingress;
using Sli.Agent.Protocol.Compatibility;

namespace Sli.Server.Agents.Control;

public static class AgentModuleAssignmentRules
{
    public static long NextRevision(long current, long expected)
    {
        if (current != expected) throw new AgentControlException("agent_policy_revision_conflict",409);
        if (current >= 9007199254740991) throw new AgentControlException("agent_policy_revision_exhausted",409);
        return current+1;
    }

    public static bool SameSnapshotIdentity(JsonObject current, JsonObject next)
        => new[] { "source_instance_id", "domain_sid", "domain_dns", "scope" }
            .All(key => JsonNode.DeepEquals(current[key], next[key]));
    // Source sli_agent.workstations._policy normalizes filter defaults as well
    // as validating them; the runtime parser alone intentionally keeps input.
    public static JsonObject NormalizeWorkstation(JsonObject input)
    {
        foreach (var key in new[] { "deny_event_ids", "allow_process_paths", "deny_process_paths" })
            if (input.ContainsKey(key) && input[key] is not JsonArray) throw new AgentException("agent_workstations_config_invalid");
        var shadow=(JsonObject)input.DeepClone();
        void Bound(JsonNode? node,int maximum,Action<string> replace)
        {
            if (node is not JsonValue v || !v.TryGetValue<string>(out var text) || AgentControlJson.Strip(text).Length==0
                || text.EnumerateRunes().Count()>maximum) throw new AgentException("agent_workstations_config_invalid");
            if (text.Length>maximum) replace(new string('a',text.EnumerateRunes().Count()));
        }
        foreach(string key in new[] { "allow_process_paths","deny_process_paths","protected_services" })
            if (shadow[key] is JsonArray array) for(int n=0;n<array.Count;n++)
            { int index=n;Bound(array[n],key=="protected_services"?256:512,value=>array[index]=value); }
        if (shadow["channel_generations"] is JsonObject generations)
            foreach(var key in generations.Select(x=>x.Key).ToArray()) Bound(generations[key],128,value=>generations[key]=value);
        if (shadow["family_filters"] is JsonObject shadowFilters)
            foreach(var filter in shadowFilters.Select(x=>x.Value).OfType<JsonObject>())
                foreach(string key in new[] { "allow_process_paths","deny_process_paths" })
                    if(filter[key] is JsonArray paths) for(int n=0;n<paths.Count;n++)
                    { int index=n;Bound(paths[n],512,value=>paths[index]=value); }
        var validated=WorkstationPolicy.Parse(shadow).Value;
        var result=new JsonObject
        {
            ["policy_revision"]="1", ["allow_event_ids"]=null, ["deny_event_ids"]=new JsonArray(),
            ["allow_process_paths"]=new JsonArray(), ["deny_process_paths"]=new JsonArray(),
            ["rate_limits"]=new JsonObject(), ["rate_window_seconds"]=60, ["batch_size"]=32,
            ["channel_generations"]=new JsonObject(), ["protected_services"]=new JsonArray(),
            ["families"]=new JsonObject(), ["family_filters"]=new JsonObject()
        };
        foreach (var (key,value) in validated) result[key]=value?.DeepClone();
        foreach (var (key,value) in input) if (key!="rate_limits") result[key]=value?.DeepClone();
        var families=new JsonObject();
        foreach (var family in WorkstationPolicy.FamilyEvents.Keys)
            families[family]=result["families"]?[family]?.DeepClone() ?? JsonValue.Create(true);
        result["families"]=families;
        foreach (string key in new[] { "allow_process_paths", "deny_process_paths" })
            result[key]=new JsonArray(result[key]!.AsArray().Select(value =>
                (JsonNode?)JsonValue.Create(UnicodeCaseFold.Fold(value!.GetValue<string>().Replace('\\','/')))).ToArray());
        var filters=result["family_filters"]!.AsObject(); var normalized=new JsonObject();
        foreach (var (family,value) in filters)
        {
            var nested=NormalizeWorkstation(value!.AsObject());
            var keys=family=="processes" ? new[] { "allow_event_ids","deny_event_ids","allow_process_paths","deny_process_paths" }
                : new[] { "allow_event_ids","deny_event_ids" };
            var filter=new JsonObject();foreach(var key in keys) filter[key]=nested[key]?.DeepClone();
            normalized[family]=filter;
        }
        result["family_filters"]=normalized;
        return result;
    }    public static JsonObject NormalizeAd(JsonObject input,bool history)
    {
        if (input.ContainsKey("history_before_utc") != history) throw new AgentException("agent_ad_dc_config_invalid");
        try { return AgentAdDcValidator.NormalizePolicy(input,history); }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException) { throw new AgentException("agent_ad_dc_config_invalid"); }
    }
    public static void ValidateChannelOwnership(JsonArray assignments)
    {
        try
        {
            var known=new[] { "sli.file-audit","sli.workstations","sli.windows.ad-dc","sli.windows.ad-dc-history",NpsPolicy.Nps,NpsPolicy.Accounting,SnapshotPolicy.Ad,SnapshotPolicy.Gpo };
            var active=new Dictionary<string,JsonObject>();
            foreach(string id in known)
            {
                var matches=assignments.OfType<JsonObject>().Where(item=>item["module_id"] is JsonValue v && v.TryGetValue<string>(out var name) && name==id).ToArray();
                if (matches.Length>1) throw new InvalidOperationException();
                if (matches.Length==0) continue;
                var item=matches[0];
                if (!item.ContainsKey("enabled")) continue;
                if (item["enabled"] is not JsonValue flag || !flag.TryGetValue<bool>(out var on)) throw new InvalidOperationException();
                if (on) active[id]=item["config"] as JsonObject ?? new JsonObject();
            }
            if (active.TryGetValue("sli.file-audit",out var file)) _=AgentFileAuditPolicy.Parse(file);
            JsonObject? workstation=null;
            if (active.TryGetValue("sli.workstations",out var ws)) workstation=NormalizeWorkstation(ws);
            if (active.TryGetValue("sli.windows.ad-dc",out var dc)) _=NormalizeAd(dc,false);
            if (active.TryGetValue("sli.windows.ad-dc-history",out var history))
            {
                var h=NormalizeAd(history,true);
                if (dc is null || !JsonNode.DeepEquals(dc["source_name"],h["source_name"]) || !JsonNode.DeepEquals(dc["connect_address"],h["connect_address"])) throw new InvalidOperationException();
            }
            foreach(var id in new[] { NpsPolicy.Nps,NpsPolicy.Accounting }) if (active.TryGetValue(id,out var c)) _=NormalizeNps(id,c);
            foreach(var id in new[] { SnapshotPolicy.Ad,SnapshotPolicy.Gpo }) if (active.TryGetValue(id,out var c)) _=SnapshotIngressPolicy.Parse(id,c);
            if (dc is not null && ws is not null) throw new InvalidOperationException();
            if (file is not null)
            {
                bool local=file["source_kind"]?.GetValue<string>()=="workstation";
                if (local && ws is null) throw new InvalidOperationException();
                if (!local && workstation is not null && WorkstationPolicy.FamilyEvents.Any(family =>
                    workstation["families"]![family.Key]!.GetValue<bool>() && family.Value.Intersect(WorkstationPolicy.ChannelEvents[0]).Any()))
                    throw new InvalidOperationException();
                if (active.TryGetValue(NpsPolicy.Nps,out var nps) && NormalizeNps(NpsPolicy.Nps,nps).Active) throw new InvalidOperationException();
            }
        }
        catch (Exception ex) when (ex is AgentException or ProtocolException or InvalidOperationException or ArgumentException or FormatException or OverflowException or System.Text.Json.JsonException)
        { throw new AgentControlException("agent_channel_owner_conflict",409); }
    }    public static string NormalizeDomain(string value)
    {
        string domain=UnicodeLower.Lower(AgentControlJson.Strip(value));
        if (domain.Length>253 || !System.Text.RegularExpressions.Regex.IsMatch(domain,@"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\z",System.Text.RegularExpressions.RegexOptions.CultureInvariant))
            throw new AgentControlException("invalid_password_domain_metadata");
        return domain;
    }    public static NpsPolicy NormalizeNps(string module,JsonObject input)
    {
        var policy=NpsPolicy.Parse(module,input);
        var required=module==NpsPolicy.Nps ? new[] { "source_instance_id","policy_revision","source_name","connect_address","event_generation" }
            : new[] { "source_instance_id","policy_revision","accounting_directory","subscription_id","source_timezone_id" };
        foreach (var key in required)
            if (AgentControlJson.Strip(policy.Value[key]!.GetValue<string>()).Length==0) throw new AgentException("agent_nps_config_invalid");
        return policy;
    }}
