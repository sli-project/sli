using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Storage.Lifecycle;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

internal static class AdSnapshotHistory
{
    internal static JsonObject Coverage(List<JsonObject> confirmations,long[] domains,string[] families,DateTimeOffset start,DateTimeOffset end,DateTimeOffset cutoff)
    {
        var reasons=new HashSet<string>();if(start<cutoff)reasons.Add("outside_retention");var starts=new List<DateTimeOffset>();var ends=new List<DateTimeOffset>();
        foreach(long domain in domains)foreach(string family in families)
        {
            var rows=confirmations.Where(r=>r.Int("domain_id")==domain&&r.Text("family")==family).OrderBy(r=>r.Time("observed_at")).ToArray();if(rows.Length==0){reasons.Add("history_not_collected");continue;}
            starts.Add(rows[0].Time("observed_at"));ends.Add(rows[^1].Time("observed_at"));if(starts[^1]>start)reasons.Add("history_starts_later");if(ends[^1]<end)reasons.Add("history_ends_earlier");JsonObject? prior=null;
            foreach(var row in rows)
            {var at=row.Time("observed_at");if(start<=at&&at<end&&row.Text("coverage_state")!="complete")reasons.Add("partial_snapshot_pair");if(prior is not null&&at>=start&&at<=end){if(row.Text("previous_manifest_id")!=prior.Text("manifest_id"))reasons.Add("history_gap");if(at-prior.Time("observed_at")>TimeSpan.FromHours(12))reasons.Add("snapshot_schedule_gap");}prior=row;}
        }
        return Obj(new{state=starts.Count==0?"not_collected":reasons.Count>0?"partial":"complete",reasons=reasons.Order(StringComparer.Ordinal),history_from_utc=starts.Count>0?AdInventoryRows.PythonIso(starts.Max()):null,history_to_utc=ends.Count>0?AdInventoryRows.PythonIso(ends.Min()):null,retained_from_utc=AdInventoryRows.PythonIso(cutoff)});
    }
    internal static async Task<JsonObject> ReadAsync(NpgsqlConnection db,AdV2Request request,IConfiguration config,CancellationToken ct)
    {
        JsonObject Failure()=>AdV2Store.Result(request.Key,"error",coverage:Obj(new{state="unavailable"}));
        var period=request.Params["period"]!;var start=period.Time("from_utc");var end=period.Time("to_utc");if(start>=end||(end-start).TotalDays>3650)throw new AdInputException("report_period_invalid");
        try
        {
            var settings=await AdJson.ReadAsync(db,"select value from platform_settings where key='ad.snapshot_history_days'",ct);string raw=settings.FirstOrDefault()?.Text("value")??Environment.GetEnvironmentVariable("SLI_AD_SNAPSHOT_HISTORY_DAYS")??"365";
            if(!int.TryParse(raw,out int days)||days is <7 or >3650)throw new InvalidDataException("ad_snapshot_history_days_must_be_7_to_3650");var cutoff=DateTimeOffset.UtcNow.AddDays(-days);string[] families=["users_v2","computers_v6"];
            var confirmations=await AdJson.ReadAsync(db,"""
                select manifest_id::text,previous_manifest_id::text,domain_id,family,batch_id,record_count,records_sha256,observed_at,coverage_state
                from public.ad_snapshot_history_confirmations where domain_id=any($1) and family=any($2) and observed_at>=$3 and observed_at<=$4 order by observed_at,manifest_id,family limit 50001
                """,ct,request.Domains,families,(start>cutoff?start:cutoff).AddHours(-12),end.AddHours(12));
            if(confirmations.Count>50000)return Failure();
            var coverage=Coverage(confirmations,request.Domains,families,start,end,cutoff);coverage["history_days"]=days;var eligible=confirmations.Where(r=>r.Time("observed_at")>=(start>cutoff?start:cutoff)&&r.Time("observed_at")<end).ToArray();long count=eligible.Sum(r=>r.Int("record_count"));var items=new List<JsonObject>();int scanned=0;bool truncated=false;
            foreach(var confirmation in eligible.Reverse())
            {
                if(confirmation.Int("record_count")==0)continue;string batch=confirmation.Text("batch_id")!;if(batch.Length!=64||batch.Any(c=>!(c is >= '0' and <= '9' or >= 'a' and <= 'f')))throw new InvalidDataException("snapshot_history_batch_identity_invalid");
                long domain=confirmation.Int("domain_id");string family=confirmation.Text("family")!;
                var rows=await SnapshotChangeStore.ReadAsync(db,batch,domain,family,confirmation.Time("observed_at"),ct);
                var pairs=new JsonArray();foreach(var row in rows)pairs.Add(new JsonArray(row.Text("record_id"),row.Text("payload_json")));
                if(rows.Count!=confirmation.Int("record_count")||AdJobPlugin.Digest(pairs)!=confirmation.Text("records_sha256"))throw new InvalidDataException("snapshot_history_report_readback_mismatch");
                foreach(var row in rows)
                {
                    string payload=row.Text("payload_json")!;var item=JsonNode.Parse(payload)!.AsObject();if(AdJobPlugin.Digest(new JsonArray(batch,item.DeepClone()))!=row.Text("record_id"))throw new InvalidDataException("snapshot_history_record_hash_mismatch");
                    if(request.Params.Text("q") is {} query&&!payload.Contains(query,StringComparison.OrdinalIgnoreCase))continue;
                    item["id"]=row["record_id"]?.DeepClone();foreach(string key in new[]{"domain_id","manifest_id","previous_manifest_id"})item[key]=confirmation[key]?.DeepClone();item["observed_at"]=AdInventoryRows.PythonIso(confirmation.Time("observed_at"));items.Add(item);
                }
                scanned+=rows.Count;if(items.Count>2000||scanned>=50000){truncated=items.Count>2000||scanned<count;break;}
            }
            if(truncated){coverage["state"]="partial";coverage["reasons"]!.AsArray().Add("history_truncated");coverage["reasons"]=Array(coverage["reasons"]!.AsArray().Select(n=>n!.ToString()).Distinct().Order(StringComparer.Ordinal));}
            string state=coverage.Text("state") is "partial" or "not_collected"?coverage.Text("state")!:items.Count>0?"ok":"empty";var result=AdV2Store.Result(request.Key,state,coverage:coverage);result["collections"]!["changes"]=Array(items.Take(2000));result["filtered_count"]=Math.Min(2000,items.Count);result["window"]=Obj(new{from_utc=period.Text("from_utc"),to_utc_exclusive=period.Text("to_utc")});
            if(state is "partial" or "not_collected")result["limitations"]!.AsArray().Add(Obj(new{code="history_"+state,text=state=="partial"?"История покрывает выбранный период не полностью. Пустой список не доказывает отсутствие изменений.":"Подтверждённая история изменений за выбранный период ещё не собрана."}));return result;
        }
        catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}
        catch(Exception e)when(e is NpgsqlException or IOException or InvalidOperationException or System.Text.Json.JsonException or HttpRequestException or TimeoutException or OperationCanceledException or FormatException)
        {var result=Failure();result["limitations"]!.AsArray().Add(Obj(new{code="history_unavailable",text="Подтверждённая история изменений недоступна."}));return result;}
    }
}
