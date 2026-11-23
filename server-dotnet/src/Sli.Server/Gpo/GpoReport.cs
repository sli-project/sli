using System.Text.Json.Nodes;
using static Sli.Server.Gpo.GpoJson;

namespace Sli.Server.Gpo;

internal static class GpoReport
{
    static JsonObject Limitation(string code,string text)=>new() { ["code"]=code,["text"]=text };
    internal static JsonObject Result(string state,JsonArray? items=null,JsonObject? coverage=null,JsonObject? collections=null,JsonArray? limitations=null,int? count=null,JsonArray? metrics=null,JsonObject? window=null)
    {
        items??=new();coverage??=new();limitations??=new();collections??=new();var missing=coverage["missing_sources"] as JsonArray??new();var issues=new JsonArray();
        foreach(var source in missing) issues.Add(new JsonObject { ["source"]=source?.DeepClone(),["reason"]="source_missing",["since_utc"]=null });
        var observed=coverage["observed_at_utc"]??coverage["latest_observed_at_utc"];var stale=coverage["stale_since_utc"];
        if(observed is not null&&coverage.Number("freshness_threshold_seconds")>0&&Stamp(observed.ToString()).AddSeconds(coverage.Number("freshness_threshold_seconds"))<DateTimeOffset.UtcNow) stale=JsonValue.Create(Iso(Stamp(observed.ToString()).AddSeconds(coverage.Number("freshness_threshold_seconds"))));
        if(state is not ("denied" or "error" or "not_collected"))
        {
            string cs=coverage.Text("state");
            if(cs is "failed" or "error" or "unavailable") state="error";
            else if(cs=="not_collected") state=items.Count>0||collections.Any(p=>(p.Value as JsonArray)?.Count>0)?"partial":"not_collected";
            else if(cs=="processing") state="processing";
            else if((cs=="stale"||stale is not null)&&state is "ok" or "empty" or "stale") state="stale";
            else if(state is "ok" or "empty"&&(missing.Count>0||cs is "partial" or "unknown" or "inactive" or "empty_unverified" or "coverage_unverified")) state="partial";
        }
        string reason=coverage.Text("reason");if(reason.Length==0) reason=state switch { "ok"=>"query_completed","empty"=>"query_completed_zero_rows","not_collected"=>"collection_not_confirmed","partial"=>coverage.True("truncated")?"result_truncated":"coverage_incomplete","stale"=>"freshness_exceeded","processing"=>"import_or_projection_pending","denied"=>"access_denied",_=>"source_or_storage_error" };
        return new JsonObject { ["contract_id"]="sli.report-result.v2",["report_key"]="ad.gpo.v2",["state"]=state,["state_message"]=Metadata["messages"]!["ru"]!["reports.state."+state]!.DeepClone(),
            ["state_details"]=new JsonObject { ["reason"]=reason,["source"]=coverage["source"]?.DeepClone(),["stage"]=coverage["stage"]?.DeepClone()??JsonValue.Create("query"),["limitations"]=limitations.DeepClone(),["missing_sources"]=missing.DeepClone(),["missing_domains"]=coverage["missing_domains"]?.DeepClone()??new JsonArray(),["observed_at_utc"]=observed?.DeepClone(),["stale_since_utc"]=stale?.DeepClone(),["source_issues"]=issues },
            ["items"]=items,["has_more"]=false,["next_cursor"]=null,["filtered_count"]=count is null?null:JsonValue.Create(count.Value),["metrics"]=metrics??new JsonArray(),["series"]=new JsonObject(),["coverage"]=coverage,["filter_options"]=new JsonObject(),["limitations"]=limitations,["window"]=window??new JsonObject(),["collections"]=collections };
    }
    internal static async Task<JsonObject> QueryAsync(IGpoReadStore store,long[]? domains,GpoRequest request,CancellationToken ct)
    {
        if(request.Tab=="changes"&&request.PolicyId is null)
        {
            var h=await store.HistoryAsync(domains,request.From,request.To,request.Query,ct);var ls=new JsonArray();string state=h.Text("state");
            if(state=="unavailable") ls.Add(Limitation("history_unavailable","Подтверждённая история изменений недоступна."));
            else if(state=="not_collected") ls.Add(Limitation("history_not_collected","Подтверждённая история изменений за выбранный период ещё не собрана."));
            else if(state=="partial") ls.Add(Limitation("history_partial","История покрывает выбранный период не полностью. Пустой список не доказывает отсутствие изменений."));
            if((h["coverage"]?["reasons"] as JsonArray)?.Any(r=>r?.ToString()=="history_starts_later")==true) ls.Add(Limitation("history_starts_later","Сбор подтверждённой истории начался позже начала выбранного периода."));
            return Result(state=="unavailable"?"error":state,coverage:h["coverage"]!.AsObject().Copy(),collections:new JsonObject { ["changes"]=h["items"]!.DeepClone() },limitations:ls,count:h.Rows("items").Count(),window:new JsonObject { ["from_utc"]=request.From.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),["to_utc_exclusive"]=request.To.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'") });
        }
        var pair=await store.PairAsync(domains,ct);
        if(pair.Text("state")=="not_collected") return Result("not_collected",limitations:new JsonArray(Limitation("not_collected","Снимок групповых политик для разрешённых доменов ещё не собран.")));
        if(pair["current"] is not JsonObject snapshot)
        {
            string state=Sli.Server.Reporting.V2.ReportResult.SourceState(pair.Text("state"));
            return Result(state is "denied" or "processing" or "error"?state:"error",coverage:new JsonObject { ["reason"]="gpo_snapshot_unavailable" });
        }
        if(request.PolicyId is { } policyId) return await GpoPolicyCard.QueryAsync(store,pair,snapshot,policyId,request,ct);
        if(request.Tab is "filtering" or "delegation" or "linked_scopes")
        {
            var effectiveSnapshot=snapshot;var matches=snapshot.Rows("gpos").Where(g=>request.Query.Length>0&&Fold(g.Text("display_name")+" "+g.Text("id")+" "+g.Text("guid")).Contains(Fold(request.Query),StringComparison.Ordinal)).ToArray();
            if(matches.Length>0) { effectiveSnapshot=snapshot.Copy();var ids=matches.Select(g=>g.Text("id")).ToHashSet();effectiveSnapshot["gpos"]=Array(matches);effectiveSnapshot["links"]=Array(snapshot.Rows("links").Where(l=>ids.Contains(l.Text("gpo_id")))); }
            var data=request.Tab=="linked_scopes"?GpoEffectiveAccess.LinkedScopes(effectiveSnapshot,request.Query):GpoEffectiveAccess.Analyze(effectiveSnapshot,await store.GraphAsync(effectiveSnapshot,domains,ct),request.Tab,request.Query);
            var rows=Array(data.Rows("items").Where(r=>Contains(r,request.Query)));string state=data.Text("state");if(state=="ok"&&rows.Count==0) state="empty";if(snapshot.Text("collection_status") is not ("complete" or "completed")) state="partial";
            var coverage=data["coverage"]!.AsObject().Copy();coverage["observed_at_utc"]=snapshot["observed_at"]?.DeepClone();coverage["freshness_threshold_seconds"]=129600;coverage["passport"]="docs/GPO_REPORT_PASSPORT.md";
            var times=new[]{snapshot.Text("observed_at"),coverage["graph"].Text("observed_at_utc")}.Where(t=>t.Length>0).Select(Stamp).ToArray();
            DateTimeOffset? stale=times.Length>0?times.Min().AddHours(36):null;
            if(state is "ok" or "empty"&&stale<DateTimeOffset.UtcNow) state="stale";coverage["stale_since_utc"]=state=="stale"&&stale.HasValue?JsonValue.Create(Iso(stale.Value)):null;
            var limitations=new JsonArray(
                Limitation("effective_boundary","Показаны права GPC по DACL и членству в снимке AD, а не RSoP. SYSVOL ACL, SIDHistory, токен входа, внешние группы, владелец и WMI на клиенте не проверяются; разрешение по ACL не доказывает применение или возможность изменения всей GPO."),
                Limitation("effective_snapshots","Граф членства выбран в том же разрешённом домене не позднее снимка GPO. Даты источников могут различаться; отсутствие пути не доказывает отсутствие прав."),
                Limitation("effective_links","Связи OU/домена показывают наследование, блокировку и принудительность. Связи сайта показаны напрямую: принадлежность компьютера сайту, конфликты настроек и WMI на клиенте не вычисляются."));
            if(coverage.True("truncated")) limitations.Add(Limitation(request.Tab+"_truncated","Достигнут предел строк или шагов обхода; часть путей может отсутствовать."));
            return Result(state,coverage:coverage,collections:new JsonObject { [request.Tab]=rows },limitations:limitations);
        }
        var listed=GpoInventory.Filter(snapshot,request.View,request.Query,request.Tab=="gpos");
        var items=listed.Items.OfType<JsonObject>().Select(g=>request.Tab=="gpos"?GpoInventory.ListRow(g):GpoInventory.Row(g)).ToArray();
        if(request.Sort is not null)
        {
            string path=Metadata["declaration"].Rows("columns").Single(c=>c.Text("key")==request.Sort).Text("path");var present=items.Where(i=>i[path] is not null&&i.Text(path).Length>0);
            var ordered=path.EndsWith("_count",StringComparison.Ordinal)?(request.Direction=="desc"?present.OrderByDescending(i=>i.Number(path)):present.OrderBy(i=>i.Number(path))).ToArray():(request.Direction=="desc"?present.OrderByDescending(i=>i.Text(path),StringComparer.OrdinalIgnoreCase):present.OrderBy(i=>i.Text(path),StringComparer.OrdinalIgnoreCase)).ToArray();items=[..ordered,..items.Where(i=>i[path] is null||i.Text(path).Length==0)];
        }
        var limits=new JsonArray(Limitation("not_rsop","Это состав политик домена, а не результирующая политика (RSoP) конкретного компьютера или пользователя."),Limitation("no_deletion_claims","Отсутствие объекта в снимке не доказывает его удаление."));
        if(listed.NotEvaluated) limits.Add(Limitation("links_not_observed","Связи политик в этом снимке не наблюдались, поэтому «без связей» не оценивается."));
        if(pair.Text("state")=="partial") limits.Add(Limitation("single_snapshot","Есть только один снимок: изменения между снимками пока не вычисляются."));
        var collections=new JsonObject();string? tab=request.Tab;
        if(tab is "scopes" or "settings" or "permissions" or "wmi" or "quality")
        {
            var rows=tab=="quality"?GpoInventory.Quality(snapshot).OfType<JsonObject>():snapshot.Rows(tab=="wmi"?"wmi_filters":tab);
            var selected=rows.Where(r=>Contains(r,request.Query)).Take(tab=="quality"?int.MaxValue:10000).Select(r=>r.Copy()).ToArray();
            foreach(var row in selected) { if(tab=="scopes") row["link_count"]=(row["direct_link_ids"] as JsonArray)?.Count??0;if(tab=="wmi") row["used_by"]=(row["used_by_gpo_ids"] as JsonArray)?.Count??0;if(tab=="permissions") row["trustee"]=row.Text("trustee_name") is {Length:>0} name?name:row.Text("trustee_sid"); }
            if(tab!="quality") selected=selected.Take(2000).ToArray();collections[tab]=Array(selected);
            if(selected.Length>=2000) limits.Add(Limitation(tab+"_truncated","Показаны первые 2000 строк; уточните поиск."));
        }
        var metrics=new JsonArray();foreach(var option in Metadata["declaration"].Rows("params").Single(p=>p.Text("key")=="view").Rows("options"))
        { string key=option.Text("value");int count=GpoInventory.Filter(snapshot,key).Total;metrics.Add(new JsonObject { ["key"]=key,["label"]=option["label"]?.DeepClone(),["value"]=count,["tone"]=key=="attention"&&count>0?"warning":key=="all"?"accent":"neutral",["filter"]=new JsonObject { ["view"]=key } }); }
        var missing=snapshot["source_states"] is JsonObject ss?ss.Where(p=>p.Value is JsonObject&&p.Value.Text("status") is not ("observed" or "no_record" or "not_applicable")).Select(p=>(JsonNode)JsonValue.Create(p.Key)!):[];
        string status=snapshot.Text("collection_status");string resultState=items.Length==0&&!listed.NotEvaluated?"empty":"ok";if(status.Length>0&&status is not ("complete" or "completed")||listed.NotEvaluated) resultState="partial";
        return Result(resultState,Array(items),new JsonObject { ["state"]=status.Length>0?status:"unknown",
            ["observed_at_utc"]=(pair["observed_at_utc"] ?? snapshot["observed_at"])?.DeepClone(),
            ["snapshot_id"]=pair["snapshot_id"]?.DeepClone(),["domain_id"]=pair["domain_id"]?.DeepClone(),
            ["snapshots"]=pair["state"]?.DeepClone(),["missing_sources"]=Array(missing) },collections,limits,listed.Total,metrics);
    }
}
