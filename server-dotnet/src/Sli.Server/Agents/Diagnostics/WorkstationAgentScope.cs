using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Agents.Control;

namespace Sli.Server.Agents.Diagnostics;

public sealed record WorkstationPredicate(string Sql,IReadOnlyList<NpgsqlParameter> Parameters)
{
    public bool UnresolvedScope { get; init; }
}

// Reader-specific implementation of frozen workstations.access.station_predicate:
// grant fields/actions/scope remain atomic; capability deny scopes are independent.
public static class WorkstationAgentScope
{
    private static readonly string[] Fields=["identity_basic","technical","security","privilege"];
    private static readonly string[] Legacy=["workstations.logons","workstations.processes","workstations.usb","workstations.protection"];
    private static readonly Dictionary<string,string> Columns=new(StringComparer.Ordinal)
    { ["plugin_ids"]="r.plugin_id",["source_instance_ids"]="r.source_instance_id",["entity_ids"]="r.entity_id",["device_ids"]="r.device_id",["collection_scope_ids"]="r.collection_scope_id" };
    private static InvalidDataException Invalid()=>new("invalid_workstation_scope");
    public static WorkstationPredicate Build(AccessFacts facts,AccessDecision access,bool inventory=false,string? reportKey=null,bool reportOnly=false)
    {
        var parameters=new List<NpgsqlParameter>();bool unresolved=false;
        string Param(string[] values){string name="ws"+parameters.Count.ToString(CultureInfo.InvariantCulture);parameters.Add(new(name,values));return "@"+name;}
        string Exists(JsonElement raw)=>"exists(select 1 from "+(inventory?"station_resources r where r.station_id=s.station_id":"resources r where r.agent_key=a.agent_key")+" and ("+Compile(raw,Param)+"))";
        string Union(IEnumerable<JsonElement> scopes)
        {
            var sql=new List<string>();foreach(var scope in scopes)
                try{sql.Add(Exists(scope));}catch(Exception e)when(e is InvalidDataException or JsonException or InvalidOperationException){unresolved=true;}
            return sql.Count==0?"FALSE":"("+string.Join(" OR ",sql)+")";
        }
        string Grants(Func<string,bool> selected)=>Union(access.Reports.Where(r=>r.Allowed&&selected(r.ReportKey)).SelectMany(r=>r.Grants)
            .Where(g=>g.AllowedActions.Contains("view")&&Fields.All(g.FieldCategories.Contains)).Select(g=>g.Scope));
        string Capability(bool legacy)
        {
            if(access.Capabilities.IsOwner)return "TRUE";
            var rows=access.Capabilities.Policies.Select((p,i)=>(Policy:p,Raw:facts.DirectCapabilities[i])).Where(p=>p.Policy.CapabilityKey=="workstations.read").ToArray();
            if(rows.Any(r=>r.Policy.Effect=="deny"&&!r.Policy.Valid))return "FALSE";
            JsonElement Scope((CapabilityPolicy Policy,JsonElement Raw) row)
            {
                if(row.Policy.Global)return JsonSerializer.SerializeToElement(new{kind="all"});
                var s=row.Raw.Get("scope_json").Object();
                // Source normalizes capability channels before adapting to scopes.
                if(s.Text("kind")=="channel")return JsonSerializer.SerializeToElement(new{kind="channel",values=s.Get("values").Items().Select(v=>AssignmentValidation.Strip(v.GetString()!)).ToArray()});
                return s;
            }
            var deny=rows.Where(r=>r.Policy.Effect=="deny").Select(Scope).ToArray();
            try{foreach(var s in deny)_=Compile(s,_=>"@validation_only");}
            catch(Exception e)when(e is InvalidDataException or JsonException or InvalidOperationException){return "FALSE";}
            string denied=Union(deny);
            string allowed=legacy||access.Capabilities.Capabilities.Contains("workstations.read")?"TRUE":Union(rows.Where(r=>r.Policy.Effect=="allow"&&r.Policy.Valid).Select(Scope));
            return "("+allowed+" AND NOT "+denied+")";
        }
        string legacy=reportKey=="workstations.overview"?"FALSE":Grants(k=>Legacy.Contains(k)&&(reportKey is null||k==reportKey)),current=reportKey is not null&&reportKey!="workstations.overview"?"FALSE":Grants(k=>k=="workstations.overview");
        if(legacy=="FALSE"&&current=="FALSE")throw new AgentControlException("workstation_access_denied",403);
        if(reportOnly)return new("("+legacy+" OR "+current+")",parameters){UnresolvedScope=unresolved};
        return new("(("+legacy+" AND "+Capability(true)+") OR ("+current+" AND "+Capability(false)+"))",parameters);
    }
    private static string[] Strings(JsonNode? value,bool allowEmpty=false)
    {
        if(value is not JsonArray a||a.Count>100||!allowEmpty&&a.Count==0)throw Invalid();
        var result=new List<string>();foreach(var node in a)
        {
            string? text=AgentDiagnosticRules.Text(node);
            if(text is null||text.EnumerateRunes().Count() is <1 or >256||AssignmentValidation.Strip(text)!=text)throw Invalid();result.Add(text);
        }
        if(result.Distinct(StringComparer.Ordinal).Count()!=result.Count)throw Invalid();return result.ToArray();
    }
    private static string Positive(JsonNode? value)
    {if(!JsonRead.TryInteger(value,out var n)||n<=0)throw Invalid();return n.ToString(CultureInfo.InvariantCulture);}
    private static string Compile(JsonElement raw,Func<string[],string> param)
    {
        var o=JsonNode.Parse(raw.GetRawText()) as JsonObject??throw Invalid();
        string? kind=AgentDiagnosticRules.Text(o["kind"]);
        if(kind=="agent")
        {if(!AgentDiagnosticRules.Keys(o,"kind","ids"))throw Invalid();return "r.agent_key = ANY("+param(Strings(o["ids"]))+")";}
        if(kind=="ou")
        {if(!AgentDiagnosticRules.Keys(o,"kind","domain_id","values"))throw Invalid();string domain=Positive(o["domain_id"]);string[] paths=Strings(o["values"]);return "r.collection_scope_id = ANY("+param(["ad-domain:"+domain])+") AND r.ou_path = ANY("+param(paths)+")";}
        if(!o.ContainsKey("mode"))
        {
            if(kind=="all"&&AgentDiagnosticRules.Keys(o,"kind"))return "TRUE";
            if(kind is not("domain" or "server" or "channel"))throw Invalid();
            string key=kind=="channel"?"values":"ids";
            if(!AgentDiagnosticRules.Keys(o,"kind",key)||o[key] is not JsonArray ids||ids.Count is <1 or >100)throw Invalid();
            var clauses=new JsonArray();
            foreach(var n in ids)
            {
                string text=kind=="channel"?AgentDiagnosticRules.Text(n)??throw Invalid():Positive(n);
                if(kind=="channel"&&AssignmentValidation.Strip(text).Length==0)throw Invalid();
                string dim=kind=="server"?"device_ids":"collection_scope_ids";
                clauses.Add(new JsonObject{[dim]=new JsonArray((kind=="domain"?"ad-domain":kind)+":"+text)});
            }
            o=new JsonObject{["mode"]="restricted",["clauses"]=clauses};
        }
        if(o.Any(p=>p.Key is not("mode" or "clauses" or "decision_id" or "policy_revision")))throw Invalid();
        foreach(string key in new[]{"decision_id","policy_revision"})if(o.ContainsKey(key)&&(AgentDiagnosticRules.Text(o[key]) is not string s||AssignmentValidation.Strip(s).Length==0||s.EnumerateRunes().Count()>256))throw Invalid();
        string? mode=AgentDiagnosticRules.Text(o["mode"]);
        if(o.ContainsKey("clauses")&&o["clauses"] is not JsonArray)throw Invalid();
        var values=o["clauses"]?.AsArray()??new JsonArray();
        if(mode is not("all" or "none" or "restricted")||values.Count>100||(mode=="restricted")!=(values.Count>0)||mode=="none")throw Invalid();
        var sql=new List<string>();
        foreach(var node in values)
        {
            if(node is not JsonObject clause||clause.Any(p=>!Columns.ContainsKey(p.Key)))throw Invalid();
            var predicates=new List<string>();
            foreach(var p in clause)
            {
                if(p.Value is not JsonArray a||a.Count>100)throw Invalid();
                if(a.Count==0)continue;
                string[] items;
                if(p.Key=="entity_ids")
                {items=a.Select(Positive).ToArray();if(items.Distinct().Count()!=items.Length)throw Invalid();}
                else items=Strings(a);
                // Text-array→numeric[] retains Python arbitrary positive entity IDs;
                // values are parameters, never SQL fragments or authority fields.
                predicates.Add(Columns[p.Key]+(p.Key=="entity_ids"?"::numeric":"")+" = ANY("+param(items)+(p.Key=="entity_ids"?"::numeric[]":"")+")");
            }
            if(predicates.Count==0)throw Invalid();sql.Add("("+string.Join(" AND ",predicates)+")");
        }
        return mode=="all"?"TRUE":"("+string.Join(" OR ",sql)+")";
    }
}
