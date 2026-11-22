using System.Text.Json.Nodes;
using System.Globalization;
using static Sli.Server.Gpo.GpoJson;

namespace Sli.Server.Gpo;

internal static class GpoInventory
{
    internal static JsonArray Reasons(JsonObject g,JsonObject snapshot)
    {
        var output=new List<JsonObject>();var states=g["source_states"] as JsonObject??new();
        string Label(string s)=>s=="sysvol_gpt"?"SYSVOL / GPT.INI":s;
        bool Hard(string s)=>s is "failed" or "access_denied" or "parse_error";
        // The agent names GPT.INI "gpt"; older snapshots used "sysvol_gpt".
        string State(string name)=>(states[name]??(name=="sysvol_gpt"?states["gpt"]:null)).Text("status");
        void Add(string code,string fact)
        {
            var r=Metadata["reasons"]![code]!.AsObject().Copy();r["code"]=code;r["fact"]=fact;r["next_action"]=r["next"]!.DeepClone();
            r["priority"]=r.Text("category") switch { "deviation"=>"high","unverified"=>"medium",_=>"low" };output.Add(r);
        }
        var failed=states.Where(p=>p.Value is JsonObject&&Hard(p.Value.Text("status"))).ToArray();
        if(failed.Length>0) Add("source_failed",string.Join("; ",failed.Select(p=>Label(p.Key)+": "+p.Value.Text("status"))));
        var unverified=states.Where(p=>new[]{"directory","links","report","permissions","sysvol_gpt"}.Contains(p.Key)&&p.Value is JsonObject&&p.Value.Text("status")!="observed"&&!Hard(p.Value.Text("status"))).ToArray();
        if(unverified.Length>0) Add("source_unverified",string.Join("; ",unverified.Select(p=>Label(p.Key))));
        var mismatch=new List<string>();
        foreach(string side in new[]{"computer","user"})
        {
            var s=g[side];if(Numeric(s?["directory_version"],out double a)&&Numeric(s?["sysvol_version"],out double b)&&a!=b) mismatch.Add($"{side}: AD {s.Text("directory_version")}, SYSVOL {s.Text("sysvol_version")}");
        }
        if(mismatch.Count>0) Add("version_mismatch",string.Join("; ",mismatch));
        var gpt=g["gpt"];if(gpt.Text("status") is "failed" or "access_denied" or "no_record" or "missing_in_source") Add("gpt_unavailable",gpt.Text("status")+": "+(gpt.Text("detail") is {Length:>0} d?d:"GPT.INI не прочитан"));
        if(g.Rows("unresolved_link_references").Any()) Add("unresolved_link",string.Join("; ",g.Rows("unresolved_link_references").Select(x=>x.Text("raw_gpc_dn"))));
        var wmi=states["wmi_filter"];
        if(g.Text("wmi_filter_id").Length>0&&wmi.Text("status") is "no_record" or "failed" or "partial") Add("unresolved_wmi",wmi.Text("detail") is {Length:>0} detail?detail:g.Text("wmi_filter_id"));
        if(g.Text("gpo_status")=="AllSettingsDisabled") Add("all_settings_disabled","GpoStatus = AllSettingsDisabled");
        if((g["link_ids"] as JsonArray)?.Count is not >0&&snapshot["source_states"]?["links"].Text("status")=="observed"&&State("links")=="observed") Add("unlinked","0 наблюдаемых ссылок при source links = observed");
        var empty=new List<string>();if(State("report")=="observed") foreach(string side in new[]{"computer","user"}) if(g[side].True("enabled")&&Numeric(g[side]?["settings_count"],out double count)&&count==0) empty.Add(side=="computer"?"Computer":"User");
        if(empty.Count>0) Add("empty_enabled_side",string.Join(" и ",empty)+": 0 нормализованных настроек");
        foreach(var r in output.Where(r=>r.Text("code")=="version_mismatch")) if(State("report")!="observed"||State("sysvol_gpt")!="observed") { r["category"]="unverified";r["priority"]="medium"; }
        return Array(output.OrderBy(Score));
    }
    static bool Numeric(JsonNode? n,out double value) { value=0;return n?.GetValueKind()!=System.Text.Json.JsonValueKind.True&&n?.GetValueKind()!=System.Text.Json.JsonValueKind.False&&double.TryParse(n?.ToString(),NumberStyles.Float,CultureInfo.InvariantCulture,out value); }
    static int Score(JsonObject reason)=>(reason.Text("category") switch { "deviation"=>0,"unverified"=>1,_=>2 })*100+(int)reason.Number("rank");
    internal static bool VersionMismatch(JsonObject policy) => policy.Rows("reasons").Any(reason => reason.Text("code")=="version_mismatch");

    internal static JsonObject Versions(JsonObject policy)
    {
        var versions=new JsonObject();
        foreach(string side in new[]{"computer","user"})
            foreach(string field in new[]{"directory_version","sysvol_version"})
                if(long.TryParse(policy[side].Text(field),NumberStyles.Integer,CultureInfo.InvariantCulture,out long value)&&value>=0)
                    versions[side+"_"+field]=value;
        return versions;
    }

    internal static JsonObject ListRow(JsonObject policy)
    {
        var row=Row(policy);
        foreach(var version in Versions(policy)) row[version.Key]=version.Value?.DeepClone();
        foreach(string side in new[]{"computer","user"})
            row[side+"_setting_count"]=policy[side]?["settings_count"]?.DeepClone();
        if(row.Number("setting_count")==0&&policy["source_states"]?["report"].Text("status")!="observed") row["setting_count"]=null;
        row["unlinked"]=policy.Rows("reasons").Any(reason=>reason.Text("code")=="unlinked");
        if(row.Number("link_count")==0&&!row.True("unlinked")) row["link_count"]=null;
        return row;
    }
    internal static JsonObject Row(JsonObject g)
    {
        var reasons=g.Rows("reasons").ToArray();var row=new JsonObject();
        foreach(string key in new[]{"id","guid","display_name","gpo_status","modification_time","creation_time","wmi_filter_id","reasons"}) row[key]=g[key]?.DeepClone();
        foreach(var (key,source) in new[]{("link_count","link_ids"),("setting_count","setting_ids"),("permission_count","permission_ids")}) row[key]=(g[source] as JsonArray)?.Count??0;
        row["reason_count"]=reasons.Count(r=>r.Text("category")=="deviation");
        foreach(var (key,cat) in new[]{("reason_titles","deviation"),("unverified_titles","unverified"),("assignment_titles","assignment")}) { string titles=string.Join(", ",reasons.Where(r=>r.Text("category")==cat).Select(r=>r.Text("title")));row[key]=titles.Length==0?null:JsonValue.Create(titles); }
        row["priority"]=reasons.FirstOrDefault()?.Text("priority")??"none";row["next_step"]=reasons.FirstOrDefault()?["next"]?.DeepClone();row["owner"]=g["owner"]?["name"]?.DeepClone();return row;
    }
    internal static (JsonArray Items,int Total,bool NotEvaluated) Filter(JsonObject snapshot,string view,string query="",bool nameOnly=false)
    {
        bool linksObserved=snapshot["source_states"]?["links"].Text("status")=="observed";
        bool unlinked=view is "unlinked" or "unlinked_version_mismatch";
        if(unlinked&&!linksObserved) return (new(),0,true);
        var rows=new List<JsonObject>();
        foreach(var original in snapshot.Rows("gpos"))
        {
            var g=original.Copy();g["reasons"]=Reasons(g,snapshot);
            if(view is "attention" or "unverified" or "assignment"&&!g.Rows("reasons").Any(r=>r.Text("category")==(view=="attention"?"deviation":view))) continue;
            bool linked=(g["link_ids"] as JsonArray)?.Count>0;
            if(view=="linked"&&!linked||unlinked&&(linked||g["source_states"]?["links"].Text("status")!="observed")) continue;
            if(view is "version_mismatch" or "unlinked_version_mismatch"&&!VersionMismatch(g)) continue;
            if(nameOnly?Fold(g.Text("display_name")).Contains(Fold(query),StringComparison.Ordinal):Contains(g,query)) rows.Add(g);
        }
        rows=rows.OrderBy(g=>g.Rows("reasons").Select(Score).DefaultIfEmpty(1000).Min()).ToList();return (Array(rows.Take(10000)),rows.Count,false);
    }
    internal static JsonArray Quality(JsonObject s)
    {
        var rows=new JsonArray();
        void Add(string type,string id,string name,string source,JsonNode? state)
        {
            if(state is not JsonObject o||o.Text("status") is "observed" or "not_applicable") return;
            string error=o["error"] is JsonObject e?e.Text("message") is {Length:>0} m?m:e.ToJsonString():o.Text("error");
            rows.Add(new JsonObject { ["_kind"]="quality",["row_id"]="quality:"+rows.Count,["entity_type"]=type,["entity_id"]=id,["entity_name"]=name,["source"]=source,["status"]=o["status"]?.DeepClone(),["detail"]=o.Text("detail") is {Length:>0} d?d:error.Length>0?error:"Источник не дал полного наблюдения",["observed_at"]=o["observed_at"]?.DeepClone(),["raw"]=o.DeepClone() });
        }
        if(s["source_states"] is JsonObject root) foreach(var p in root) Add("snapshot","snapshot","Снимок",p.Key,p.Value);
        foreach(string family in new[]{"gpos","scopes"}) foreach(var row in s.Rows(family)) if(row["source_states"] is JsonObject states) foreach(var p in states) Add(family=="gpos"?"gpo":"scope",row.Text("id"),row.Text(family=="gpos"?"display_name":"name"),p.Key,p.Value);
        foreach(var (family,type,source) in new[]{("links","link","link"),("settings","setting","setting_xml"),("permissions","permission","permission"),("wmi_filters","wmi","wmi_filter")})
            foreach(var r in s.Rows(family)) Add(type,r.Text("id"),type switch { "link"=>r.Text("gpo_name")+" → "+r.Text("scope_name"),"setting"=>r.Text("gpo_name")+": "+r.Text("setting_name"),"permission"=>r.Text("gpo_name")+": "+r.Text("trustee_name"),_=>r.Text("name") },source,r["source_state"]);
        return rows;
    }
}
