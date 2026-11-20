using System.Text.Json.Nodes;
using static Sli.Server.Gpo.GpoJson;

namespace Sli.Server.Gpo;

// Bounded snapshot DACL interpretation, preserving ACE order and unknown evidence.
internal static class GpoEffectiveAccess
{
    const string Empty="00000000-0000-0000-0000-000000000000",Apply="edacfd8f-ffb3-11d1-b41d-00a0c968f939";
    internal sealed record Membership(Dictionary<string,Dictionary<string,string[]>> Paths,bool Incomplete,bool DepthLimited,int Cycles,bool Truncated);
    internal static Membership Resolve(JsonObject[] entities,JsonObject[] relations,int maxDepth=16,int maxSteps=200000)
    {
        var nodes=entities.ToDictionary(n=>n.Text("record_key"));var parents=new Dictionary<string,SortedSet<string>>();bool incomplete=false,depth=false;int cycles=0,steps=0;
        foreach(var r in relations)
        {
            string child=r.Text("source_record_key"),parent=r.Text("target_record_key");
            if(!nodes.ContainsKey(child)||!nodes.TryGetValue(parent,out var target)||target["attributes"].Text("group_category") is not ("Security" or "Distribution")) { incomplete=true;continue; }
            if(target["attributes"].Text("group_category")=="Security") { if(!parents.TryGetValue(child,out var p)) parents[child]=p=new(StringComparer.Ordinal);p.Add(parent); }
        }
        var paths=new Dictionary<string,Dictionary<string,string[]>>();
        foreach(var (key,principal) in nodes.OrderBy(n=>n.Key,StringComparer.Ordinal))
        {
            if(principal["identity"].Text("kind") is not ("ad_user" or "ad_computer")) continue;
            var found=new Dictionary<string,string[]>();var queue=new Queue<(string Key,string[] Path)>();queue.Enqueue((key,[key]));var visited=new HashSet<string>{key};
            while(queue.Count>0)
            {
                var (current,path)=queue.Dequeue();if(++steps>maxSteps) return new(paths,true,depth,cycles,true);
                string sid=nodes[current]["identity"].Text("object_sid");if(sid.Length>0) found[sid.ToUpperInvariant()]=path;else incomplete=true;
                var a=nodes[current]["attributes"];foreach(string field in new[]{"unresolved_group_dns","unresolved_parent_dns","unresolved_primary_group_sid"}) if(a?[field] is {} v && v.ToString() is not ("" or "[]" or "false" or "0")) incomplete=true;
                if(!parents.TryGetValue(current,out var ancestors)) continue;
                foreach(string parent in ancestors)
                {
                    if(path.Contains(parent)) { cycles++;continue; }if(visited.Contains(parent)) continue;
                    if(path.Length-1>=maxDepth) { depth=true;continue; }visited.Add(parent);queue.Enqueue((parent,[..path,parent]));
                }
            }
            paths[key]=found;
        }
        return new(paths,incomplete||depth,depth,cycles,false);
    }
    internal static HashSet<string> Rights(JsonObject ace)
    {
        var rights=new HashSet<string>();if((ace.Number("propagation_flags")&2)!=0) return rights;
        long mask=ace.Number("access_mask");if((mask&0x10000000)!=0) mask|=0xF01FF;if((mask&0x80000000)!=0) mask|=0x20094;if((mask&0x40000000)!=0) mask|=0x20028;
        string type=ace.Text("object_type").ToLowerInvariant();if(type.Length==0) type=Empty;bool all=type==Empty;
        if((mask&0x20000)!=0) rights.Add("read_control");if((mask&0x10)!=0&&all) rights.Add("read_property");if((mask&0x100)!=0&&(all||type==Apply)) rights.Add("apply");
        if((mask&0x20)!=0&&all) rights.Add("edit");if((mask&0x40000)!=0) rights.Add("modify_permissions");if((mask&0x80000)!=0) rights.Add("modify_owner");return rights;
    }
    internal static string Risk(string sid,string kind,string domain)
    {
        sid=sid.ToUpperInvariant();if(new[]{"S-1-1-0","S-1-5-11","S-1-5-32-545",domain+"-513",domain+"-515"}.Contains(sid)) return "broad_edit";
        if(new[]{"S-1-5-18","S-1-5-32-544",domain+"-500",domain+"-512",domain+"-518",domain+"-519"}.Contains(sid)) return "admin_edit";
        return kind=="ad_group"?"non_admin_group_edit":kind is "ad_user" or "ad_computer"?"direct_principal_edit":"unknown_trustee_edit";
    }
    internal static JsonObject Analyze(JsonObject snapshot,JsonObject graph,string mode,string query="",int maxRows=2000,int maxDepth=16)
    {
        var entities=graph.Rows("entities").ToArray();var nodes=entities.ToDictionary(n=>n.Text("record_key"));var bySid=entities.GroupBy(n=>n["identity"].Text("object_sid").ToUpperInvariant()).ToDictionary(g=>g.Key,g=>g.Last());
        var resolved=Resolve(entities,graph.Rows("relations").ToArray(),maxDepth);var matching=new HashSet<string>();
        if(query.Length>0) foreach(var (key,token) in resolved.Paths)
        {
            var evidence=new JsonArray(key,Array(token.Keys.Select(k=>(JsonNode)JsonValue.Create(k)!)),Array(token.Values.SelectMany(x=>x).Distinct().Select(k=>nodes[k]["attributes"]?["display_name"]??JsonValue.Create(""))));
            if(Contains(evidence,query)) matching.Add(key);
        }
        bool graphPartial=graph.Text("state")!="ok"||resolved.Incomplete||!graph.True("computers_collected"),partial=graphPartial,truncated=false;int evaluations=0;var rows=new List<JsonObject>();
        string domain=snapshot["domain"].Text("sid").ToUpperInvariant();
        var acl=snapshot.Rows("acl").GroupBy(a=>a.Text("gpo_id")).ToDictionary(g=>g.Key,g=>g.OrderBy(a=>a.Number("ace_index")).ToArray());
        void Add(JsonObject row) { if(Contains(row,query)) rows.Add(row); }
        foreach(var gpo in snapshot.Rows("gpos"))
        {
            var aces=acl.GetValueOrDefault(gpo.Text("id"))??[];string aclState=gpo["source_states"]?["acl"].Text("status")??"";if(aclState.Length==0) aclState="not_collected";
            bool unsupported=aces.Any(a=>(a.Number("access_mask")&0x30)!=0&&a.Text("object_type")!=Empty);partial|=unsupported;
            var basis=new JsonObject { ["gpo_id"]=gpo["id"]?.DeepClone(),["gpo_guid"]=gpo["guid"]?.DeepClone(),["gpo_name"]=gpo["display_name"]?.DeepClone(),["wmi_filter_id"]=gpo["wmi_filter_id"]?.DeepClone(),["graph_run_id"]=graph["source"]?["run_id"]?.DeepClone(),["graph_observed_at"]=graph["source"]?["observed_at_utc"]?.DeepClone() };
            if(aclState!="observed"||graph.Text("state")=="not_collected")
            {
                partial=true;var row=basis.Copy();row["id"]=gpo.Text("id")+":unknown";row["outcome"]=aclState=="not_collected"||graph.Text("state")=="not_collected"?"not_collected":"unknown";Add(row);
                if(rows.Count>=maxRows) { truncated=true;break; }continue;
            }
            var emitted=new HashSet<string>();bool gpoMatches=Contains(new JsonArray(basis.DeepClone(),Array(aces),Array(aces.Select(a=>bySid.GetValueOrDefault(a.Text("trustee_sid").ToUpperInvariant())?["attributes"]?["display_name"]??JsonValue.Create("")))),query);
            foreach(var (key,originalToken) in resolved.Paths)
            {
                if(!gpoMatches&&!matching.Contains(key)) continue;
                var token=new Dictionary<string,string[]>(originalToken) { ["S-1-1-0"]=[key],["S-1-5-11"]=[key] };
                var decisions=new Dictionary<string,(bool Allowed,JsonObject Ace,string[] Path)>();
                foreach(var ace in aces)
                {
                    if(++evaluations>200000) { truncated=true;break; }
                    if(!token.TryGetValue(ace.Text("trustee_sid").ToUpperInvariant(),out var path)) continue;
                    emitted.Add(ace.Text("id"));foreach(string right in Rights(ace)) decisions.TryAdd(right,(ace.Text("access_control_type")=="Allow",ace,path));
                }
                if(truncated) break;
                foreach(string right in mode=="filtering"?new[]{"apply"}:new[]{"edit","modify_permissions","modify_owner"})
                {
                    if(!decisions.TryGetValue(right,out var d)) continue;
                    bool readOk=new[]{"read_control","read_property"}.All(r=>decisions.TryGetValue(r,out var read)&&read.Allowed);
                    var principal=nodes[key];var trustee=bySid.GetValueOrDefault(d.Ace.Text("trustee_sid").ToUpperInvariant());
                    var names=d.Path.Select(k=>nodes[k]["attributes"].Text("display_name") is {Length:>0} name?name:nodes[k]["identity"].Text("object_sid") is {Length:>0} sid?sid:k).ToList();
                    if(d.Ace.Text("trustee_sid").ToUpperInvariant() is "S-1-1-0" or "S-1-5-11") names.Add(d.Ace.Text("trustee_sid"));names.Add(gpo.Text("display_name")+" [ACE "+d.Ace.Number("ace_index")+"]");
                    var row=basis.Copy();row["id"]=gpo.Text("id")+":"+key+":"+right;row["principal"]=principal["attributes"].Text("display_name") is {Length:>0} name2?name2:key;
                    row["principal_sid"]=principal["identity"]?["object_sid"]?.DeepClone();row["principal_type"]=principal["identity"]?["kind"]?.DeepClone();
                    row["trustee_sid"]=d.Ace["trustee_sid"]?.DeepClone();row["right"]=right;row["outcome"]=graphPartial||unsupported?"unknown":d.Allowed&&(mode!="filtering"||readOk)?"allowed":"denied";
                    row["path"]=string.Join(" → ",names);row["path_keys"]=Array(d.Path.Select(k=>(JsonNode)JsonValue.Create(k)!));row["ace_id"]=d.Ace["id"]?.DeepClone();row["ace_index"]=d.Ace["ace_index"]?.DeepClone();
                    row["read_ace_ids"]=mode=="filtering"?Array(new[]{"read_control","read_property"}.Where(decisions.ContainsKey).Select(r=>decisions[r].Ace.Text("id")).Distinct().Order(StringComparer.Ordinal).Select(k=>(JsonNode)JsonValue.Create(k)!)):new JsonArray();
                    row["inherited"]=d.Ace["inherited"]?.DeepClone();row["risk"]=mode!="filtering"&&d.Allowed?Risk(d.Ace.Text("trustee_sid"),trustee?["identity"].Text("kind")??"",domain):"none";Add(row);
                    if(rows.Count>=maxRows) { truncated=true;break; }
                }
                if(truncated) break;
            }
            if(truncated) break;if(!gpoMatches) continue;
            foreach(var ace in aces)
            {
                var rights=Rights(ace);rights.IntersectWith(mode=="filtering"?["apply"]:["edit","modify_permissions","modify_owner"]);if(rights.Count==0||emitted.Contains(ace.Text("id"))) continue;
                var trustee=bySid.GetValueOrDefault(ace.Text("trustee_sid").ToUpperInvariant());partial=true;
                foreach(string right in rights.Order(StringComparer.Ordinal))
                {
                    var row=basis.Copy();row["id"]=ace.Text("id")+":"+right;row["trustee_sid"]=ace["trustee_sid"]?.DeepClone();row["right"]=right;row["outcome"]="unknown";row["ace_id"]=ace["id"]?.DeepClone();row["ace_index"]=ace["ace_index"]?.DeepClone();row["inherited"]=ace["inherited"]?.DeepClone();
                    row["path"]=(trustee?["attributes"].Text("display_name") is {Length:>0} tn?tn:ace.Text("trustee_sid"))+" → "+gpo.Text("display_name")+" [ACE "+ace.Number("ace_index")+"]";
                    row["risk"]=mode!="filtering"&&ace.Text("access_control_type")=="Allow"?Risk(ace.Text("trustee_sid"),trustee?["identity"].Text("kind")??"",domain):"none";Add(row);if(rows.Count>=maxRows) { truncated=true;break; }
                }
                if(truncated) break;
            }
            if(truncated) break;
        }
        return new JsonObject { ["items"]=Array(rows.Take(maxRows)),["state"]=partial||truncated?"partial":rows.Count>0?"ok":"empty",["coverage"]=new JsonObject { ["graph"]=graph["source"]?.DeepClone(),["graph_state"]=graph["state"]?.DeepClone(),["computers_collected"]=graph.True("computers_collected"),["cycles"]=resolved.Cycles,["depth_limited"]=resolved.DepthLimited,["max_depth"]=maxDepth,["truncated"]=truncated||resolved.Truncated||graph.True("truncated"),["missing_records"]=graph.True("missing_records") } };
    }
    internal static string[] DnSuffixes(string dn)
    {
        var values=new List<string>{dn};bool escaped=false,quoted=false;
        for(int i=0;i<dn.Length;i++) if(escaped) escaped=false;else if(dn[i]=='\\') escaped=true;else if(dn[i]=='"') quoted=!quoted;else if(dn[i]==','&&!quoted) values.Add(dn[(i+1)..]);return values.ToArray();
    }
    internal static JsonObject LinkedScopes(JsonObject s,string query="",int maxRows=2000)
    {
        var scopes=s.Rows("scopes").ToDictionary(x=>x.Text("id"));var byDn=scopes.Values.GroupBy(x=>x.Text("distinguished_name").ToLowerInvariant()).ToDictionary(g=>g.Key,g=>g.Last());
        var gpos=s.Rows("gpos").ToDictionary(x=>x.Text("id"));var filters=s.Rows("wmi_filters").ToDictionary(x=>x.Text("id"));var rows=new List<JsonObject>();
        bool observed=s["source_states"]?["links"].Text("status")=="observed",partial=!observed,truncated=false;int evaluations=0;
        foreach(var link in s.Rows("links"))
        {
            if(!scopes.TryGetValue(link.Text("scope_id"),out var root)||!gpos.TryGetValue(link.Text("gpo_id"),out var gpo)) { partial=true;continue; }
            string rootDn=root.Text("distinguished_name").ToLowerInvariant();
            foreach(var scope in scopes.Values)
            {
                if(++evaluations>200000) { truncated=true;break; }string dn=scope.Text("distinguished_name").ToLowerInvariant();bool direct=scope.Text("id")==root.Text("id");
                bool descendant=root.Text("scope_type") is "domain" or "ou"&&scope.Text("scope_type")=="ou"&&rootDn.Length>0&&dn.EndsWith(","+rootDn,StringComparison.Ordinal);
                if(!direct&&!descendant) continue;
                var suffixes=DnSuffixes(dn);int index=System.Array.IndexOf(suffixes,rootDn);var relevant=index>=0?suffixes.Take(index+1).ToArray():[rootDn];var chain=relevant.Reverse().Where(byDn.ContainsKey).Select(x=>byDn[x]).ToArray();
                bool blocked=!direct&&chain.Any(c=>c.Text("id")!=root.Text("id")&&c.True("gpo_inheritance_blocked"));
                bool known=chain.Length==relevant.Length&&link["enabled"] is not null&&link["enforced"] is not null&&chain.All(c=>c["gpo_inheritance_blocked"]?.GetValueKind() is System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False);
                string outcome=!known||!observed?"unknown":!link.True("enabled")?"disabled":blocked&&!link.True("enforced")?"blocked":"linked";
                var wmi=filters.GetValueOrDefault(gpo.Text("wmi_filter_id"));string wmiState=gpo.Text("wmi_filter_id").Length==0?"not_applicable":wmi?["source_state"].Text("status") is {Length:>0} ws?ws:"not_collected";partial|=!known||wmiState is not ("observed" or "not_applicable");
                var row=new JsonObject { ["id"]=link.Text("id")+":"+scope.Text("id"),["gpo_id"]=gpo["id"]?.DeepClone(),["gpo_guid"]=gpo["guid"]?.DeepClone(),["gpo_name"]=gpo["display_name"]?.DeepClone(),["scope_name"]=scope["name"]?.DeepClone(),["scope_type"]=scope["scope_type"]?.DeepClone(),["scope_dn"]=scope["distinguished_name"]?.DeepClone(),["link_id"]=link["id"]?.DeepClone(),["order"]=link["order"]?.DeepClone(),["enabled"]=link["enabled"]?.DeepClone(),["enforced"]=link["enforced"]?.DeepClone(),["inherited"]=!direct,["inheritance_blocked"]=scope["gpo_inheritance_blocked"]?.DeepClone(),["outcome"]=outcome,["path"]=chain.Length>0?string.Join(" → ",chain.Select(c=>c.Text("name") is {Length:>0} n?n:c.Text("id"))):root.Text("name"),["gpo_status"]=gpo["gpo_status"]?.DeepClone(),["wmi_filter_id"]=gpo["wmi_filter_id"]?.DeepClone(),["wmi_name"]=wmi?["name"]?.DeepClone(),["wmi_queries"]=Array(wmi.Rows("queries").Select(q=>(JsonNode)JsonValue.Create(q.Text("namespace")+": "+q.Text("query"))!)),["wmi_state"]=wmiState };
                if(Contains(row,query)) rows.Add(row);if(rows.Count>=maxRows) { truncated=true;break; }
            }
            if(truncated) break;
        }
        return new JsonObject { ["items"]=Array(rows),["state"]=partial||truncated?"partial":rows.Count>0?"ok":"empty",["coverage"]=new JsonObject { ["links_state"]=s["source_states"]?["links"]?.DeepClone(),["truncated"]=truncated } };
    }
}
