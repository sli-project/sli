using System.Text.Json.Nodes;
using static Sli.Server.Gpo.GpoJson;

namespace Sli.Server.Gpo;

internal static class GpoChangeHistory
{
    internal static JsonObject Coverage(IEnumerable<JsonObject> confirmations,long[] domains,DateTimeOffset from,DateTimeOffset to,DateTimeOffset cutoff)
    {
        var reasons=new SortedSet<string>(StringComparer.Ordinal);if(from<cutoff) reasons.Add("outside_retention");var starts=new List<DateTimeOffset>();var ends=new List<DateTimeOffset>();
        foreach(long domain in domains)
        {
            var rows=confirmations.Where(c=>c.Number("domain_id")==domain&&c.Text("family")=="gpo_v2").OrderBy(c=>Stamp(c.Text("observed_at"))).ToArray();
            if(rows.Length==0) { reasons.Add("history_not_collected");continue; }
            starts.Add(Stamp(rows[0].Text("observed_at")));ends.Add(Stamp(rows[^1].Text("observed_at")));
            if(starts[^1]>from) reasons.Add("history_starts_later");if(ends[^1]<to) reasons.Add("history_ends_earlier");JsonObject? previous=null;
            foreach(var row in rows)
            {
                var observed=Stamp(row.Text("observed_at"));if(from<=observed&&observed<to&&row.Text("coverage_state")!="complete") reasons.Add("partial_snapshot_pair");
                if(previous is not null&&observed>=from&&observed<=to)
                {
                    if(row.Text("previous_manifest_id")!=previous.Text("manifest_id")) reasons.Add("history_gap");if(observed-Stamp(previous.Text("observed_at"))>TimeSpan.FromHours(12)) reasons.Add("snapshot_schedule_gap");
                }
                previous=row;
            }
        }
        return new JsonObject { ["state"]=starts.Count==0?"not_collected":reasons.Count>0?"partial":"complete",["reasons"]=Array(reasons.Select(r=>(JsonNode)JsonValue.Create(r)!)),["history_from_utc"]=starts.Count>0?JsonValue.Create(Iso(starts.Max())):null,["history_to_utc"]=ends.Count>0?JsonValue.Create(Iso(ends.Min())):null,["retained_from_utc"]=Iso(cutoff) };
    }
    internal static async Task<JsonObject> ReadAsync(List<JsonObject> confirmations,long[] domains,DateTimeOffset from,DateTimeOffset to,DateTimeOffset cutoff,int days,string query,
        Func<string,long,string,DateTimeOffset,CancellationToken,Task<List<JsonObject>>> read,CancellationToken ct)
    {
        var coverage=Coverage(confirmations,domains,from,to,cutoff);coverage["history_days"]=days;
        var eligible=confirmations.Where(c=>Stamp(c.Text("observed_at"))>=(from>cutoff?from:cutoff)&&Stamp(c.Text("observed_at"))<to).Reverse().ToArray();
        long count=eligible.Sum(c=>c.Number("record_count")),scanned=0;bool truncated=false;var rows=new JsonArray();
        foreach(var confirmation in eligible)
        {
            if(confirmation.Number("record_count")==0) continue;string batch=confirmation.Text("batch_id");
            if(batch.Length!=64||batch.Any(c=>!"0123456789abcdef".Contains(c))) throw new InvalidDataException("snapshot_history_batch_identity_invalid");
            var records=await read(batch,confirmation.Number("domain_id"),"gpo_v2",Stamp(confirmation.Text("observed_at")),ct);
            var pairs=new JsonArray(records.Select(r=>(JsonNode)new JsonArray(r.Text("record_id"),r.Text("payload_json"))).ToArray());
            if(records.Count!=confirmation.Number("record_count")||Hash(pairs)!=confirmation.Text("records_sha256")) throw new InvalidDataException("snapshot_history_report_readback_mismatch");
            foreach(var record in records)
            {
                var payload=JsonNode.Parse(record.Text("payload_json"))!.AsObject();if(Hash(new JsonArray(batch,payload.DeepClone()))!=record.Text("record_id")) throw new InvalidDataException("snapshot_history_record_hash_mismatch");
                if(query.Length>0&&!Fold(record.Text("payload_json")).Contains(Fold(query),StringComparison.Ordinal)) continue;
                payload["id"]=record["record_id"]?.DeepClone();payload["domain_id"]=confirmation["domain_id"]?.DeepClone();payload["manifest_id"]=confirmation["manifest_id"]?.DeepClone();payload["previous_manifest_id"]=confirmation["previous_manifest_id"]?.DeepClone()??JsonValue.Create("None");payload["observed_at"]=Iso(Stamp(confirmation.Text("observed_at")));rows.Add(payload);
            }
            scanned+=records.Count;if(rows.Count>2000||scanned>=50000) { truncated=rows.Count>2000||scanned<count;break; }
        }
        if(truncated) { coverage["state"]="partial";coverage["reasons"]=Array(coverage["reasons"]!.AsArray().Select(x=>x!.ToString()).Append("history_truncated").Distinct().Order(StringComparer.Ordinal).Select(x=>(JsonNode)JsonValue.Create(x)!)); }
        string state=coverage.Text("state");if(state is not ("partial" or "not_collected")) state=rows.Count>0?"ok":"empty";
        return new JsonObject { ["state"]=state,["items"]=Array(rows.OfType<JsonObject>().Take(2000)),["coverage"]=coverage,["truncated"]=truncated };
    }
}

