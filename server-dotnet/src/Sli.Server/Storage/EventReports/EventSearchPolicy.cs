using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Agent.Protocol;

namespace Sli.Server.Storage.EventReports;

internal sealed record EventSearchPolicy(JsonElement Definition,string[] Fields,JsonElement[] Scopes,string Binding)
{
    internal static readonly string[] BaseFields=["id","time_created_utc","event_id","channel"];
    internal static readonly string[] GroupFields=["action","provider","channel","event_id","outcome","reason","logon_type","account","source_station","ip","related_object","server_id","domain_id","task_identity","process_identity","file_identity"];
    internal static readonly string[] OptionalFields=[..GroupFields,"group_identity_complete","title","account_kind","source_payload_state"];
    internal static EventSearchPolicy Authorize(AccessFacts facts,AccessDecision access,EventSearchInput input,string action="view",string[]? requestedFields=null)
    {
        if(action is not ("view" or "export")) throw new EventSearchException("unsupported_action");
        var report=access.Reports.FirstOrDefault(r=>r.ReportKey=="events.explorer" && r.Allowed) ?? throw new EventSearchException("policy_denied");
        var publication=facts.Definitions.FirstOrDefault(d=>d.Text("report_key")=="events.explorer");
        var definition=publication.Get("definition_json").Object();
        if(publication.Text("dataset_key")!="events.v2" || publication.Text("dataset_status")!="published" || !definition.Get("actions").Strings().Contains(action)) throw new EventSearchException("policy_denied");
        if(action=="export" && (!access.Capabilities.Capabilities.Contains("reports.export") || definition.Text("export_policy")!="controlled")) throw new EventSearchException("policy_denied");
        var fieldDefs=publication.Get("fields_json").Items().ToDictionary(f=>f.Text("key"),f=>f.Text("category"));
        if(definition.Get("columns").ValueKind!=JsonValueKind.Array) throw new EventSearchException("policy_denied");
        var baseColumns=definition.Get("columns").Items().Select(c=>c.ValueKind==JsonValueKind.String?c.GetString()!:c.Text("key")).ToArray();
        var extensions=definition.Get("evsearch_columns");
        if(baseColumns.Length==0 || baseColumns.Distinct().Count()!=baseColumns.Length || baseColumns.Any(c=>!fieldDefs.ContainsKey(c)) ||
            extensions.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Array) || extensions.Items().Any(v=>v.ValueKind!=JsonValueKind.String || !fieldDefs.ContainsKey(v.GetString()!)) || extensions.Items().Select(v=>v.ToString()).Distinct().Count()!=extensions.Items().Count()) throw new EventSearchException("policy_denied");
        var columns=baseColumns.Concat(extensions.Strings()).ToHashSet();
        var baseGrants=report.Grants.Where(g=>g.AllowedActions.Contains("view")).ToArray();
        var required=input.Conditions.Select(c=>c.Field).ToHashSet();
        if(input.Q is not null)
        {
            required.Add("q"); var qfields=definition.Get("evsearch_q_fields").Strings();
            if(qfields.Count==0 || definition.Get("evsearch_q_fields").Items().Any(v=>v.ValueKind!=JsonValueKind.String) || qfields.Any(f=>!EventSearchSql.TextFields.Contains(f))) throw new EventSearchException("unsupported_field");
            required.UnionWith(qfields);
        }
        if(input.ExcludeMachine) required.UnionWith(["account","account_kind"]);
        if(input.Question is not null)
        {
            var deps=definition.Get("evsearch_questions").Get(input.Question).Strings();
            if(deps.Count==0 || input.Question is "admin_logons" or "new_admins") throw new EventSearchException("unsupported_question");
            required.UnionWith(deps); required.UnionWith(["provider","channel","event_id"]);
            if(input.Question=="failed_logons") required.Add("outcome");
        }
        if(definition.Get("filters").ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Null or JsonValueKind.Array)) throw new EventSearchException("history_predicate_unavailable");
        foreach(var filter in definition.Get("filters").Items()) { if(filter.ValueKind!=JsonValueKind.Object) throw new EventSearchException("history_predicate_unavailable"); if(filter.Get("field").ValueKind!=JsonValueKind.Undefined) required.Add(filter.Text("field")); }
        bool Allowed(IEnumerable<string> requested)
        {
            var keys=requested.ToHashSet();
            if(!keys.IsSubsetOf(columns) || keys.Any(k=>!fieldDefs.TryGetValue(k,out var cat) || cat.Length==0)) return false;
            var cats=keys.Select(k=>fieldDefs[k]).ToHashSet();
            var qualified=report.Grants.Where(g=>g.AllowedActions.Contains(action) && cats.IsSubsetOf(g.FieldCategories)).ToArray();
            // Union only grants that each contain the entire category set.
            return baseGrants.Length>0 && baseGrants.All(g=>Covers(qualified.Select(q=>q.Scope),g.Scope));
        }
        var fields=(requestedFields??BaseFields).ToList();
        if(fields.Count==0 || !Allowed(fields.Concat(required))) throw new EventSearchException("policy_denied");
        foreach(string f in requestedFields is null ? OptionalFields.Distinct() : [])
        {
            if(fields.Contains(f) || f=="group_identity_complete" && !GroupFields.All(fields.Contains) || f=="title" && !fields.Contains("provider")) continue;
            if(Allowed(fields.Concat(required).Append(f))) fields.Add(f);
        }
        var scopes=baseGrants.Select(g=>g.Scope).ToArray();
        if(scopes.Any(s=>ReportScopeResolver.ParseScope(s).Invalid)) throw new EventSearchException("policy_denied");
        var binding=Hash(JsonSerializer.SerializeToNode(new { definition=publication,grants=baseGrants,capabilities=access.Capabilities.Policies,
            available=access.Capabilities.Capabilities.Order(StringComparer.Ordinal),owner=facts.IsOwner }));
        return new(definition,fields.ToArray(),scopes,binding);
    }
    static bool Covers(IEnumerable<JsonElement> larger,JsonElement smaller)
    {
        var a=larger.Select(ReportScopeResolver.ParseScope).ToArray(); var b=ReportScopeResolver.ParseScope(smaller);
        if(a.Any(s=>s.Invalid) || b.Invalid) return false;
        if(a.Any(s=>s.All)) return true; if(b.All) return false;
        string[] dims=["plugin_ids","source_instance_ids","device_ids","entity_ids","collection_scope_ids"];
        return b.Clauses.Count>0 && b.Clauses.All(bc=>a.SelectMany(s=>s.Clauses).Any(ac=>dims.All(d=>
            !ac.Get(d).Items().Any() || bc.Get(d).Items().Any() && bc.Get(d).Items().Select(v=>v.ToString()).ToHashSet().IsSubsetOf(ac.Get(d).Items().Select(v=>v.ToString()).ToHashSet()))));
    }
    internal static string Hash(JsonNode? value) => Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(CanonicalJson.ToBytes(value)));
}
