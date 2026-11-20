using System.Text.Json.Nodes;

namespace Sli.Server.Vpn;

public static class VpnOverlap
{
    public static async Task<JsonObject> Read(IVpnReadSession db,VpnAccess access,VpnQuery q,IQueryCollection query,CancellationToken ct)
    {
        if(q.To-q.From>TimeSpan.FromDays(90)) throw new VpnInputException("vpn_overlap_window_invalid");
        if(!access.Branch("sessions",q.Domain,q.Action).Allowed) return VpnReports.Result("vpn.connections","denied");
        long account=0;if(query.ContainsKey("overlap_account") && (!long.TryParse(query["overlap_account"],out account)||account<=0)) throw new VpnInputException("report_parameter_invalid:overlap_account");
        int minimum=VpnReports.ParseInt(query["overlap_min_seconds"].FirstOrDefault()??"0","report_parameter_invalid:overlap_min_seconds");
        string complete=query["overlap_complete"].FirstOrDefault()??"false";if(complete is not ("true" or "false")) throw new VpnInputException("report_parameter_invalid:overlap_complete");
        try
        {
            var coverage=(await db.ReadAsync(VpnSql.Coverage,[q.Domain],ct)).FirstOrDefault();if(coverage is null || coverage.Number("projected_session_count")==0) return VpnReports.Result("vpn.connections","not_collected");
            var rows=await db.ReadAsync("""
                select session_row_id,entity_id,domain_id,generation,lifecycle_state,completeness,started_at_utc,stopped_at_utc,last_observed_at_utc
                from radius_vpn_session_rows_v1 where domain_id=$1 and ($2=0 or entity_id=$2)
                  and ((started_at_utc<$3 and ((stopped_at_utc is not null and stopped_at_utc>$4)
                        or (stopped_at_utc is null and last_observed_at_utc>$4)))
                       or (started_at_utc is null and last_observed_at_utc>=$4 and last_observed_at_utc<$3))
                order by started_at_utc,session_row_id limit 5001
                """,[q.Domain,account,q.To,q.From],ct);
            var data=Analyze(rows.Take(5000).ToList(),q,minimum,complete=="true");bool truncated=rows.Count>5000 || data.Flag("truncated");
            string state=truncated || data.Number("unknown_identity_count")>0 || data.Number("invalid_interval_count")>0 || VpnSessions.CoverageState(coverage)!="available"?"partial":"ok";
            var result=VpnReports.Result("vpn.connections",state);result["collections"]=VpnJson.Obj(new {session_overlap=data["items"]!.DeepClone()});
            coverage["state"]=VpnSessions.CoverageState(coverage);coverage["unknown_identity_count"]=data["unknown_identity_count"]!.DeepClone();coverage["invalid_interval_count"]=data["invalid_interval_count"]!.DeepClone();coverage["truncated"]=truncated;result["coverage"]=coverage;
            var metrics=new JsonArray();foreach(var (key,label,field) in new[]{("overlap_accounts","Аккаунтов с перекрытиями","accounts"),("overlap_concurrent","Максимум одновременных сессий","max_concurrent"),("overlap_seconds","Подтверждённое перекрытие, с","confirmed_seconds"),("overlap_incomplete","Неполных сессий","incomplete_sessions")}) metrics.Add(VpnJson.Obj(new {key,label,value=truncated?null:data["metrics"]?[field]?.DeepClone(),quality=truncated?"unknown":data["metrics"].Number(field)>0?"observed":"unknown"}));result["metrics"]=metrics;
            result["window"]=VpnJson.Obj(new {from_utc=VpnJson.Iso(q.From),to_utc_exclusive=VpnJson.Iso(q.To),source_domain_id=q.Domain});
            result["branches"]=VpnJson.Obj(new {accounting=new {state,reason=state=="ok"?"available":"partial",limits=new {max_period_days=90,max_session_rows=5000,max_pairs=5000}}});return result;
        }
        catch(Exception e) when(VpnAuthorizations.IsTimeout(e) && !ct.IsCancellationRequested)
        {
            var result=VpnReports.Result("vpn.connections","partial");
            result["collections"]=VpnJson.Obj(new {session_overlap=Array.Empty<object>()});
            result["coverage"]=VpnJson.Obj(new {state="partial",read_incomplete=true,completeness="not_proven"});
            result["branches"]=VpnJson.Obj(new {accounting=new {state="partial",reason="source_read_timeout",limits=new {max_period_days=90,max_session_rows=5000,max_pairs=5000}}});
            result["metrics"]=VpnJson.Array(new[]{("overlap_accounts","Аккаунтов с перекрытиями"),("overlap_concurrent","Максимум одновременных сессий"),("overlap_seconds","Подтверждённое перекрытие, с"),("overlap_incomplete","Неполных сессий")}.Select(m=>VpnJson.Obj(new {key=m.Item1,label=m.Item2,value=(long?)null,quality="unknown"})));
            result["window"]=VpnJson.Obj(new {from_utc=VpnJson.Iso(q.From),to_utc_exclusive=VpnJson.Iso(q.To),source_domain_id=q.Domain});
            return result;
        }
    }
    public static JsonObject Analyze(List<JsonObject> rows,VpnQuery q,int minimum=0,bool completeOnly=false)
    {
        var intervals=new List<(DateTimeOffset Start,DateTimeOffset End,bool Complete,JsonObject Row)>();var seen=new HashSet<string>();int unknown=0,incomplete=0,invalid=0;
        foreach(var row in rows)
        {
            string key=$"{row.Text("domain_id")}:{row.Text("entity_id")}:{row.Text("session_row_id")}:{row.Text("generation")}";if(!seen.Add(key)) continue;
            if(row.Number("domain_id")<=0 || row.Number("entity_id")<=0 || row.Text("session_row_id")=="" || row.Number("generation")<=0) {unknown++;continue;}
            var a=row.At("started_at_utc");var stop=row.At("stopped_at_utc");var b=stop??row.At("last_observed_at_utc");bool complete=stop is not null && row.Text("completeness")=="complete";
            if(!complete) incomplete++;if(completeOnly && !complete) continue;
            if(a is null || b is null || b<=a) {invalid++;continue;}
            var start=a>q.From?a.Value:q.From!.Value;var end=b<q.To?b.Value:q.To!.Value;if(end>start) intervals.Add((start,end,complete,row));
        }
        var items=new List<JsonObject>();int accounts=0,maxConcurrent=0;long seconds=0;bool truncated=false;
        foreach(var group in intervals.GroupBy(x=>(x.Row.Number("domain_id"),x.Row.Number("entity_id"))).OrderBy(g=>g.Key))
        {
            var active=new List<(DateTimeOffset Start,DateTimeOffset End,bool Complete,JsonObject Row)>();var confirmed=new List<(DateTimeOffset Start,DateTimeOffset End)>();bool hasPairs=false;
            foreach(var current in group.OrderBy(x=>x.Start).ThenBy(x=>x.Row.Text("session_row_id"),StringComparer.Ordinal))
            {
                active.RemoveAll(x=>x.End<=current.Start);
                foreach(var other in active)
                {
                    var start=current.Start>other.Start?current.Start:other.Start;var end=current.End<other.End?current.End:other.End;long duration=(long)(end-start).TotalSeconds;
                    if(duration<Math.Max(1,minimum)) continue;if(items.Count>=5000) {truncated=true;break;}hasPairs=true;
                    if(current.Complete && other.Complete) confirmed.Add((start,end));
                    var a=other.Row;var b=current.Row;items.Add(VpnJson.Obj(new {row_id=a.Text("session_row_id")+":"+b.Text("session_row_id"),domain_id=group.Key.Item1,entity_id=group.Key.Item2,generation_a=a.Number("generation"),generation_b=b.Number("generation"),session_a=a.Text("session_row_id"),session_b=b.Text("session_row_id"),start_a=VpnJson.Iso(a.At("started_at_utc")),end_a=VpnJson.Iso(a.At("stopped_at_utc")),start_b=VpnJson.Iso(b.At("started_at_utc")),end_b=VpnJson.Iso(b.At("stopped_at_utc")),completeness_a=a.Text("completeness"),completeness_b=b.Text("completeness"),last_a=VpnJson.Iso(a.At("last_observed_at_utc")),last_b=VpnJson.Iso(b.At("last_observed_at_utc")),overlap_start_utc=VpnJson.Iso(start),overlap_end_utc=VpnJson.Iso(end),overlap_seconds=duration,interval_quality=current.Complete && other.Complete?"confirmed":"observed"}));
                }
                if(truncated) break;active.Add(current);
            }
            if(hasPairs)
            {
                accounts++;seconds+=VpnConnections.UnionSeconds(confirmed);int current=0;
                foreach(var edge in group.SelectMany(x=>new[]{(At:x.Start,Delta:1),(At:x.End,Delta:-1)}).OrderBy(x=>x.At).ThenBy(x=>x.Delta)) {current+=edge.Delta;maxConcurrent=Math.Max(maxConcurrent,current);}
            }
            if(truncated) break;
        }
        return VpnJson.Obj(new {items,metrics=truncated?(object)new {}:new {accounts,max_concurrent=maxConcurrent,confirmed_seconds=seconds,incomplete_sessions=incomplete},unknown_identity_count=unknown,invalid_interval_count=invalid,truncated});
    }
}
