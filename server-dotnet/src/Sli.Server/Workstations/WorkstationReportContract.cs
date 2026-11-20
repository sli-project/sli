using System.Globalization;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Sli.Server.Access;
namespace Sli.Server.Workstations;

public sealed record WorkstationRequest(string Key,JsonObject Parameters,int Limit,string? Cursor,string? RowId)
{
    public bool Overview=>Key=="workstations.overview";
    public string Family=>Key["workstations.".Length..];
}
public static class WorkstationReportContract
{
    static readonly JsonObject Definitions=JsonNode.Parse(new StreamReader(typeof(WorkstationReportContract).Assembly.GetManifestResourceStream("Sli.Server.Workstations.definitions.json")!).ReadToEnd())!.AsObject();
    public static IEnumerable<string> Keys=>Definitions.Select(p=>p.Key);
    public static readonly string[] Fields=["identity_basic","technical","security","privilege"];
    internal static readonly string[] Reasons=["protection_disabled","local_admin_added","password_failures","suspicious_process_path","service_or_task_changed","removable_media_first_seen","logon_outside_policy","server_silent","protection_stale","workstation_silent"];
    public static void Admit(AccessDecision access,string key)
    {
        var report=access.Reports.FirstOrDefault(r=>r.ReportKey==key&&r.Allowed);
        if(report is null)throw new WorkstationException("report_access_denied",403);
        if(!report.Grants.Any(g=>g.AllowedActions.Contains("view")&&Fields.All(g.FieldCategories.Contains)))throw new WorkstationException("report_field_categories_not_allowed",403);
    }
    public static JsonObject Declaration(string key)
    {
        var result=Definitions[key]?.DeepClone().AsObject()??throw new WorkstationException("report_not_found",404);
        result["access"]=Access();result["filter_options"]=new JsonObject();
        foreach(var view in result["views"]!.AsArray())view!["access"]=new JsonObject{["allowed"]=true};
        if(result["detail"] is JsonObject detail)detail["access"]=new JsonObject{["allowed"]=true};
        return result;
    }
    internal static JsonObject Access()=>new(){["allowed"]=true,["hidden_categories"]=new JsonArray(),["reason"]=null};
    public static WorkstationRequest Parse(string key,IQueryCollection query,string? rowId=null,DateTimeOffset? now=null)
    {
        var definition=Definitions[key]?.AsObject()??throw new WorkstationException("report_not_found",404);
        var declared=definition["params"]!.AsArray().OfType<JsonObject>().ToArray();
        var allowed=declared.Select(p=>p.Text("key")!).Concat(["from","to","cursor","limit","sort","direction","tz","tab"]).ToHashSet();
        var unknown=query.Keys.Where(k=>!allowed.Contains(k)).Order(StringComparer.Ordinal).FirstOrDefault();
        if(unknown is not null)throw new WorkstationException("report_parameter_unknown:"+unknown);
        string? First(string k)=>query[k].FirstOrDefault()?.Trim() is {Length:>0} s?s:null;
        string timezone=First("tz")??"UTC";TimeZoneInfo zone;
        try{zone=TimeZoneInfo.FindSystemTimeZoneById(timezone);}catch(Exception e)when(e is TimeZoneNotFoundException or InvalidTimeZoneException){throw new WorkstationException("report_timezone_invalid");}
        var parameters=new JsonObject();
        foreach(var p in declared)
        {
            string name=p.Text("key")!,kind=p.Text("kind")!;string? v=First(name)??p.Text("default");
            if(kind=="period")
            {
                var current=now??DateTimeOffset.UtcNow;DateTimeOffset start,end;
                if(v is "24h" or "7d" or "30d" or "90d"){end=current;start=end.AddDays(v=="24h"?-1:-int.Parse(v![..^1],CultureInfo.InvariantCulture));}
                else if(v=="custom")
                {
                    try
                    {
                        string from=First("from")??"",to=First("to")??"";
                        if(from.Contains('T')||to.Contains('T')){start=Ws.Time(from);end=Ws.Time(to);}
                        else{var a=DateTime.ParseExact(from,"yyyy-MM-dd",CultureInfo.InvariantCulture);var b=DateTime.ParseExact(to,"yyyy-MM-dd",CultureInfo.InvariantCulture).AddDays(1);start=TimeZoneInfo.ConvertTimeToUtc(a,zone);end=TimeZoneInfo.ConvertTimeToUtc(b,zone);}
                        if(start>=end)throw new FormatException();
                    }
                    catch(Exception e)when(e is FormatException or ArgumentException or WorkstationException){throw new WorkstationException("report_period_invalid");}
                }
                else throw new WorkstationException("report_period_invalid");
                if(end-start>TimeSpan.FromDays(p.Number("max_days")))throw new WorkstationException("report_period_too_wide");
                parameters[name]=new JsonObject{["preset"]=v,["from_utc"]=start.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),["to_utc"]=end.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")};continue;
            }
            if(v is null){if(p["required"]?.GetValue<bool>()==true)throw new WorkstationException("report_parameter_required:"+name);continue;}
            if(v.EnumerateRunes().Count()>(p["max_length"] is null?256:p.Number("max_length")))throw new WorkstationException("report_parameter_invalid:"+name);
            if(kind is "int" or "domain")
            {if(!long.TryParse(v,NumberStyles.Integer,CultureInfo.InvariantCulture,out long n)||n<=0)throw new WorkstationException("report_parameter_invalid:"+name);parameters[name]=n;}
            else
            {if(kind=="choice"&&p["options"] is JsonArray options&&!options.Any(o=>o.Text("value")==v))throw new WorkstationException("report_parameter_invalid:"+name);parameters[name]=v;}
        }
        if(!int.TryParse(First("limit")??definition["limits"]!["default"]!.ToString(),out int limit)||limit<1||limit>definition["limits"]!.Number("max"))throw new WorkstationException("report_limit_invalid");
        if(First("direction") is {} direction&&direction is not("asc" or "desc"))throw new WorkstationException("report_sort_invalid");
        if(First("sort") is {} sort&&!definition["columns"]!.AsArray().Any(c=>c.Text("key")==sort&&c?["sortable"]?.GetValue<bool>()==true))throw new WorkstationException("report_sort_invalid");
        if(First("tab") is {} tab&&!definition["views"]!.AsArray().Any(c=>c.Text("key")==tab))throw new WorkstationException("report_tab_invalid");
        string? cursor=First("cursor");bool overview=key=="workstations.overview";
        if(cursor is not null&&(overview?cursor.Length>256:!Ws.IsHash(cursor)))throw new WorkstationException(overview?"workstation_request_invalid":"workstation_report_cursor_invalid");
        if(rowId is not null&&!System.Text.RegularExpressions.Regex.IsMatch(rowId,@"\A[A-Za-z0-9_.:-]{1,128}\z"))throw new WorkstationException("report_not_found",404);
        if(rowId is not null&&(overview?rowId.Length is <1 or >128:!Ws.IsHash(rowId)))throw new WorkstationException(overview?"workstation_request_invalid":"workstation_report_id_invalid");
        if(overview&&parameters["finding_id"] is not null&&(!Ws.IsHash(parameters.Text("finding_id"))||parameters.Number("evidence_index") is <1 or >100))throw new WorkstationException("workstation_evidence_invalid");
        return new(key,parameters,limit,cursor,rowId);
    }
    internal static JsonObject Result(string key,string state="partial",JsonArray? items=null,JsonObject? coverage=null,JsonObject? window=null,JsonArray? limitations=null)
    {
        coverage??=new();limitations??=new();
        string reason=coverage.Text("reason")??(state=="partial"?"coverage_incomplete":state=="not_collected"?"collection_not_confirmed":state=="error"?"source_or_storage_error":"query_completed");
        return new JsonObject{["contract_id"]="sli.report-result.v2",["report_key"]=key,["state"]=state,
            ["state_message"]=Message("reports.state."+state),
            ["state_details"]=new JsonObject{["reason"]=reason,["source"]=coverage["source"]?.DeepClone(),["stage"]="query",["limitations"]=limitations.DeepClone(),["missing_sources"]=new JsonArray(),["missing_domains"]=new JsonArray(),["observed_at_utc"]=null,["stale_since_utc"]=null,["source_issues"]=new JsonArray()},
            ["items"]=items??new(),["has_more"]=false,["next_cursor"]=null,["filtered_count"]=null,["metrics"]=new JsonArray(),["series"]=new JsonObject(),["coverage"]=coverage,["filter_options"]=new JsonObject(),["limitations"]=limitations,["window"]=window??new(),["collections"]=new JsonObject(),["access"]=Access()};
    }
    static readonly Lazy<JsonObject> Messages=new(()=>JsonNode.Parse(new StreamReader(typeof(WorkstationReportContract).Assembly.GetManifestResourceStream("Sli.Server.Access.Administration.server.ru.json")!).ReadToEnd())!.AsObject());
    internal static JsonObject Message(string key)=>new(){["key"]=key,["params"]=new JsonObject(),["text"]=Messages.Value[key]?.DeepClone()??JsonValue.Create(key)};
    internal static JsonObject Check(string id,long? count)=>new(){["check_id"]=id,["rule_version"]=1,["order"]=int.Parse(id[1..]),["severity"]=int.Parse(id[1..])<=3?"high":int.Parse(id[1..])<=8?"medium":"low",["reason_code"]=Reasons[int.Parse(id[1..])-1],
        ["title_key"]=$"workstations.checks.{id}.title",["why_key"]=$"workstations.checks.{id}.why",["action_key"]=$"workstations.checks.{id}.action",["remediation_key"]=$"workstations.checks.{id}.remediation",
        ["quality"]=Ws.Quality("partial"),["counts"]=new JsonObject{["stations"]=Ws.Count(count>0?count:null,count>0?"at_least":"unknown"),["new_since_previous_login"]=Ws.Count(null,"unknown")},["reasons"]=new JsonArray()};
}
