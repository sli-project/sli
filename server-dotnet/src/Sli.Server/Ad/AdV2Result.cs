using System.Text.Json.Nodes;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

internal static class AdV2Result
{
    internal static void Finish(JsonObject result)
    {
        var coverage=result["coverage"] as JsonObject??new();string state=result.Text("state")??"error";var issues=(JsonArray)(coverage["source_issues"]?.DeepClone()??new JsonArray());var missingSources=(JsonArray)(coverage["missing_sources"]?.DeepClone()??new JsonArray());var missingDomains=(JsonArray)(coverage["missing_domains"]?.DeepClone()??new JsonArray());
        foreach(var domain in coverage["domains"] as JsonArray??[])
        {
            if(domain is not JsonObject row)continue;var statuses=new[]{row.Text("run_status"),row.Text("section_status"),row.Text("state")};
            if(!statuses.Any(s=>s is "failed" or "cancelled" or "error" or "unavailable" or "timeout" or "denied" or "partial" or "skipped" or "not_collected")&&!(row.ContainsKey("run_status")&&row.Text("run_status") is null))continue;
            if(row["domain_id"] is {} id&&!missingDomains.Any(n=>JsonNode.DeepEquals(n,id)))missingDomains.Add(id.DeepClone());if(row.Text("section_name") is {} section&&!missingSources.Any(n=>n?.ToString()==section))missingSources.Add(section);
            string source=string.Join(':',new[]{row.Text("domain_id"),row.Text("section_name")}.Where(s=>s is not null));
            if(source.Length>0){var issue=Obj(new{source,reason=row.Text("reason_code")??(statuses.Contains("denied")?"access_denied":statuses.Any(s=>s is "failed" or "cancelled" or "error" or "unavailable" or "timeout")?"source_failed":statuses.Contains("partial")?"source_partial":"source_missing"),since_utc=row.Text("since_utc")??row.Text("failed_since_utc")});if(row.Text("domain_name") is {} name)issue["source_name"]=name;issues.Add(issue);}
        }
        foreach(var(key,reason)in new[]{("failed","source_failed"),("partial","source_partial"),("missing","source_missing"),("stale","snapshot_old")})foreach(var source in coverage[key] as JsonArray??[])if(source?.GetValueKind()==System.Text.Json.JsonValueKind.String&&!issues.Any(i=>i!.Text("source")==source.ToString()))issues.Add(Obj(new{source=source.ToString(),reason,since_utc=coverage.Text("since_utc")}));
        foreach(var source in missingSources)if(source?.GetValueKind()==System.Text.Json.JsonValueKind.String&&!issues.Any(i=>i!.Text("source")==source.ToString()||i.Text("source")?.Split(':')[^1]==source.ToString()))issues.Add(Obj(new{source=source.ToString(),reason="source_missing",since_utc=coverage.Text("since_utc")}));
        var observed=coverage["observed_at_utc"]??coverage["latest_observed_at_utc"];string? stale=coverage.Text("stale_since_utc");if(AdInventoryRows.Date(observed) is {} at&&coverage.Int("freshness_threshold_seconds")>0&&at.AddSeconds(coverage.Int("freshness_threshold_seconds"))<DateTimeOffset.UtcNow)stale=AdInventoryRows.PythonIso(at.AddSeconds(coverage.Int("freshness_threshold_seconds")));
        if(state is not ("denied" or "error" or "not_collected"))
        {
            string? sourceState=coverage.Text("state");bool data=result["items"] is JsonArray{Count:>0}||(result["collections"] as JsonObject??new()).Any(p=>p.Value is JsonArray{Count:>0});
            if(sourceState is "failed" or "error" or "unavailable")state="error";
            else if(sourceState=="not_collected")state=data?"partial":"not_collected";
            else if(sourceState=="processing"||coverage.Int("unprocessed_events")>0||coverage["activity"].Int("unprocessed_events")>0)state="processing";
            else if((sourceState=="stale"||stale is not null)&&state is "ok" or "empty" or "stale")state="stale";
            else if(state is "ok" or "empty"&&(missingSources.Count>0||missingDomains.Count>0||coverage.Text("completeness")=="not_proven"||sourceState is "partial" or "unknown" or "inactive" or "empty_unverified" or "coverage_unverified"))state="partial";
        }
        string resultReason=coverage.Text("reason")??(state=="partial"&&AdInventoryRows.Bool(coverage["truncated"])==true?"result_truncated":state switch{"ok"=>"query_completed","empty"=>"query_completed_zero_rows","denied"=>"access_denied","not_collected"=>"collection_not_confirmed","partial"=>"coverage_incomplete","processing"=>"import_or_projection_pending","stale"=>"freshness_exceeded",_=>"source_or_storage_error"});
        result["state"]=state;result["state_message"]=AdPresentation.Message("reports.state."+state);result["state_details"]=new JsonObject{["reason"]=resultReason,["source"]=coverage["source"]?.DeepClone(),["stage"]=coverage.Text("stage")??"query",["limitations"]=result["limitations"]?.DeepClone()??new JsonArray(),["missing_sources"]=missingSources,["missing_domains"]=missingDomains,["observed_at_utc"]=observed?.DeepClone(),["stale_since_utc"]=stale,["source_issues"]=issues};
    }
}
