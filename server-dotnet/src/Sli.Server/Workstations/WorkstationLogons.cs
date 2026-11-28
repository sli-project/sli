using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.InstallationSetup;
namespace Sli.Server.Workstations;
internal static partial class WorkstationEvaluators
{
    static string? Ou(string? value)
    {
        if(value is not {Length:>=1 and <=512}||value.EndsWith('\\'))return null;
        var parts=new List<string>();var current=new System.Text.StringBuilder();bool escaped=false;
        foreach(char c in value){if(c==','&&!escaped){parts.Add(current.ToString().Trim());current.Clear();continue;}current.Append(c);escaped=c=='\\'&&!escaped;}
        if(current.Length>0)parts.Add(current.ToString().Trim());
        if(parts.Count==0||!parts[0].StartsWith("ou=",StringComparison.OrdinalIgnoreCase)||!parts[^1].StartsWith("dc=",StringComparison.OrdinalIgnoreCase)||parts.Any(p=>!p.Contains('=')||p[(p.IndexOf('=')+1)..].Length==0))return null;
        return string.Join(',',parts).ToLowerInvariant();
    }
    internal static JsonObject ValidatePolicy(string raw)
    {
        try
        {
            if (raw.Length > 1040) throw new FormatException();
            var value=JsonNode.Parse(raw)!.AsObject();
            if (value.Any(entry => entry.Key is not ("version" or "policies" or "enabled"))
                || value.ContainsKey("enabled") && value["enabled"]?.GetValueKind() is not (JsonValueKind.True or JsonValueKind.False)
                || value.Number("version") is <1 or >=int.MaxValue || value["version"]?.GetValueKind() != JsonValueKind.Number
                || value["policies"] is not JsonArray policies) throw new FormatException();
            int limit = InstallationSettings.LogonPolicyLengthLimit(value);
            if (raw.Length > limit) throw new FormatException();
            var scopes=new HashSet<string>();
            foreach(var node in policies)
            {
                if(node is not JsonObject r||r.Count!=6||new[]{"scope","timezone","weekdays","start","end","include_cached_interactive"}.Any(k=>!r.ContainsKey(k))||r["scope"] is not JsonObject scope)throw new FormatException();
                if(scope.Text("kind")=="station")
                {if(scope.Count!=2||scope.Text("station_id") is not {Length:>=1 and <=256} station||station.Trim()!=station)throw new FormatException();}
                else if(scope.Text("kind")=="ou")
                {if(scope.Count!=3||scope.Number("domain_id")<=0||Ou(scope.Text("ou_path")) is not {} ou)throw new FormatException();scope["ou_path"]=ou;}
                else throw new FormatException();
                if(!scopes.Add(Ws.Hash(scope))||r["include_cached_interactive"]?.GetValueKind() is not(JsonValueKind.True or JsonValueKind.False)||r["weekdays"] is not JsonArray days||days.Count is <1 or >7||days.Any(d=>d?.GetValueKind()!=JsonValueKind.Number||!int.TryParse(d.ToString(),out int n)||n is <0 or >6)||days.Select(d=>d!.ToString()).Distinct().Count()!=days.Count)throw new FormatException();
                _=TimeZoneInfo.FindSystemTimeZoneById(r.Text("timezone")!);
                if(new[]{"start","end"}.Any(k=>!Regex.IsMatch(r.Text(k)??"",@"\A(?:[01][0-9]|2[0-3]):[0-5][0-9]\z"))||r.Text("start")==r.Text("end"))throw new FormatException();
            }
            if (Sli.Agent.Protocol.CanonicalJson.Serialize(value, false).Length > limit) throw new FormatException();
            return value;
        }
        catch(Exception e)when(e is FormatException or System.Text.Json.JsonException or InvalidOperationException or ArgumentException or TimeZoneNotFoundException){throw new WorkstationException("workstation_logon_policy_invalid");}
    }
    internal static async Task<JsonObject?> LoadPolicy(NpgsqlConnection db,CancellationToken ct)=>await Ws.Scalar(db,"select value from public.platform_settings where key='workstations.logon_policy'",ct) is string raw?ValidatePolicy(raw):null;
    static JsonObject? SelectPolicy(JsonObject? config,JsonObject station)
    {
        if (config?["enabled"]?.GetValueKind() == JsonValueKind.False) return null;
        var policies=config?["policies"]?.AsArray().OfType<JsonObject>().ToArray()??[];
        return policies.FirstOrDefault(p=>p["scope"].Text("kind")=="station"&&p["scope"].Text("station_id")==station.Text("station_id"))??policies.FirstOrDefault(p=>p["scope"].Text("kind")=="ou"&&p["scope"].Number("domain_id")==station.Number("domain_id")&&Ou(p["scope"].Text("ou_path"))==Ou(station["metadata"].Text("ou_path")));
    }
    internal static JsonObject? EvaluateLogon(JsonObject row,JsonObject station,JsonObject? config)
    {
        if(!Native(row,"logons",4624))return null;
        var body=row["observation"]!;string? type=body["facts"]?["logon_type"]?.ToString();bool known=int.TryParse(type,out int logon)&&logon is >=2 and <=13&&type==logon.ToString(CultureInfo.InvariantCulture);
        if(known&&type is not("2" or "10" or "11"))return null;
        var policy=SelectPolicy(config,station);string? reason=!known?"logon_type_unknown":policy is null?"logon_policy_not_configured":null;
        if(reason is not null)return new(){["outside"]=null,["quality"]=Ws.Quality("not_collected",reason),["params"]=new JsonObject()};
        var instant=Ws.Time(row.Text("observed_at"));var local=TimeZoneInfo.ConvertTime(instant,TimeZoneInfo.FindSystemTimeZoneById(policy!.Text("timezone")!));
        string clock=local.ToString("HH:mm",CultureInfo.InvariantCulture),start=policy.Text("start")!,end=policy.Text("end")!;var day=local.Date;
        bool inside;
        if(string.CompareOrdinal(start,end)<0)inside=string.CompareOrdinal(start,clock)<=0&&string.CompareOrdinal(clock,end)<0;
        else{inside=string.CompareOrdinal(clock,start)>=0||string.CompareOrdinal(clock,end)<0;if(string.CompareOrdinal(clock,end)<0)day=day.AddDays(-1);}
        inside&=policy!["weekdays"]!.AsArray().Any(d=>d!.GetValue<int>()==((int)day.DayOfWeek+6)%7);
        bool outside=!inside;if(type=="11"&&!policy["include_cached_interactive"]!.GetValue<bool>())outside=false;
        var scope=policy["scope"]!;var p=new JsonObject{["local_time"]=local.ToString(local.Ticks%TimeSpan.TicksPerSecond==0?"yyyy-MM-dd'T'HH:mm:sszzz":"yyyy-MM-dd'T'HH:mm:ss.ffffffzzz",CultureInfo.InvariantCulture),["timezone"]=policy["timezone"]!.DeepClone(),["logon_type"]=logon,["policy_version"]=config!["version"]!.DeepClone(),["policy_sha256"]=Ws.Hash(config),["window_start"]=start,["window_end"]=end,["weekdays"]=string.Join(',',policy["weekdays"]!.AsArray().Select(d=>d!.ToString())),["include_cached_interactive"]=policy["include_cached_interactive"]!.DeepClone(),["scope_kind"]=scope["kind"]!.DeepClone(),["scope_id"]=(scope["station_id"]??scope["ou_path"])?.DeepClone(),["domain_id"]=scope["domain_id"]?.DeepClone(),["scope_basis"]="current_inventory"};
        return new(){["outside"]=outside,["quality"]=Ws.Quality("complete"),["params"]=p};
    }
    static async Task LogonPolicy(NpgsqlConnection db,string stationId,JsonObject fact,JsonObject? config,CancellationToken ct)
    {
        if(fact.Text("kind") is not("observations" or "station_inventory"))return;
        var station=(await Ws.Rows(db,"select station_id,agent_key,domain_id,metadata from sli_plugin_workstations.station_inventory where station_id=@p0",ct,stationId)).SingleOrDefault()??throw new WorkstationException("workstation_projection_station_missing");
        bool configured=SelectPolicy(config,station) is not null;
        var state=new JsonObject{["policy_version"]=config?["version"]?.DeepClone(),["policy_sha256"]=config is null?null:Ws.Hash(config),["quality"]=Ws.Quality(configured?"partial":"not_collected",configured?"coverage_incomplete":"logon_policy_not_configured"),["stations"]=Ws.Count(null,"unknown")};
        await Ws.Exec(db,"""
            insert into sli_plugin_workstations.station_summary(station_id,counters,as_of_utc) values(@p0,jsonb_build_object('C07',@p1::jsonb),transaction_timestamp())
            on conflict(station_id) do update set counters=station_summary.counters||excluded.counters,as_of_utc=excluded.as_of_utc,revision=station_summary.revision+1,updated_at=now()
            where station_summary.counters->'C07' is distinct from excluded.counters->'C07'
            """,ct,stationId,state);
        if(fact.Text("kind")!="observations")return;var row=fact["payload"]!.AsObject();if(row.Text("agent_key")!=station.Text("agent_key"))throw new WorkstationException("workstation_projection_input_conflict");
        var evaluated=EvaluateLogon(row,station,config);if(evaluated is null)return;
        if(!Ws.IsHash(row.Text("id")))throw new WorkstationException("workstation_c07_observation_id_invalid");
        string id=Ws.Hash(new JsonArray("workstations.C07",1,stationId,row.Text("id"))),condition=Ws.Hash(new JsonArray(evaluated["outside"]?.DeepClone(),evaluated["quality"]!.DeepClone(),evaluated["params"]!.DeepClone()));
        if(evaluated["outside"]?.GetValue<bool>()!=true)
        {
            bool clear=evaluated["outside"]?.GetValue<bool>()==false;
            await Ws.Exec(db,"""
                update sli_plugin_workstations.check_findings set status=case when @p0 then 'resolved' else status end,
                resolved_at=case when @p0 then coalesce(resolved_at,transaction_timestamp()) else resolved_at end,
                quality=@p1::jsonb,condition_sha256=@p2,reason_params=case when @p0 then @p3::jsonb else reason_params end,
                revision=revision+1,materially_changed_at=transaction_timestamp() where id=@p4 and condition_sha256<>@p2
                """,ct,clear,evaluated["quality"]!,condition,evaluated["params"]!,id);return;
        }
        var now=await Now(db,ct);var finding=Finding("C07",stationId,id,null,evaluated["params"]!.DeepClone().AsObject(),new(Ref(row)),Ws.Time(row.Text("observed_at")),now);finding.Remove("subject_ref");finding.Remove("subject_id");finding["quality"]=evaluated["quality"]!.DeepClone();finding["condition_sha256"]=condition;
        await Ws.Insert(db,"check_findings",finding,"""
            on conflict(id) do update set condition_sha256=excluded.condition_sha256,status='active',resolved_at=null,reason_params=excluded.reason_params,quality=excluded.quality,evidence_refs=excluded.evidence_refs,materially_changed_at=excluded.materially_changed_at,revision=check_findings.revision+1 where check_findings.condition_sha256<>excluded.condition_sha256
            """,ct);
    }
    static async Task LastLogin(NpgsqlConnection db,string station,JsonObject fact,CancellationToken ct)
    {
        if(fact.Text("kind")!="observations")return;
        var row=fact["payload"]!.AsObject();var o=row["observation"]!;var f=o["facts"]!;string? type=f["logon_type"]?.ToString();
        if(!Native(row,"logons",4624)||type is not("2" or "10" or "11"))return;
        string? id=row.Text("id"),source=o.Text("source_sha256");
        if(!Ws.IsHash(id)||!Ws.IsHash(source)||o.Text("agent_key")!=row.Text("agent_key"))throw new WorkstationException("workstation_projection_input_conflict");
        var instant=Ws.Time(row.Text("observed_at"));var account=new JsonObject();foreach(string key in new[]{"name","domain","sid"})account[key]=f.Text("logon_user_"+key) is {Length:>0 and <=256} v?v:null;
        var state=new JsonObject{["observation_id"]=id,["observed_at"]=Ws.Stamp(instant),["logon_type"]=int.Parse(type),["account"]=account,["current_state"]="unknown",["evidence_ref"]=Ref(row)};
        await RequireAgent(db,station,row,ct);
        var previous=(await Ws.Rows(db,"select last_interactive_login from sli_plugin_workstations.station_summary where station_id=@p0 for update",ct,station)).SingleOrDefault()?["last_interactive_login"] as JsonObject;
        if(previous is {Count:>0}&&(Ws.Time(previous.Text("observed_at"))>instant||Ws.Time(previous.Text("observed_at"))==instant&&string.CompareOrdinal(previous.Text("observation_id"),id)>=0))return;
        await Ws.Exec(db,"insert into sli_plugin_workstations.station_summary(station_id,last_interactive_login,as_of_utc) values(@p0,@p1::jsonb,transaction_timestamp()) on conflict(station_id) do update set last_interactive_login=excluded.last_interactive_login,as_of_utc=greatest(station_summary.as_of_utc,excluded.as_of_utc),revision=station_summary.revision+1,updated_at=now()",ct,station,state);
    }
}
