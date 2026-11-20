using System.Text.Json.Nodes;
using Npgsql;
namespace Sli.Server.Workstations;
internal static partial class WorkstationEvaluators
{
    internal static JsonObject? DeviceEvent(JsonObject row)
    {
        var o=row["observation"]!;var f=o["facts"]!;string? device=f.Text("device_id");long n=row.Number("event_id");
        bool native=Native(row,"usb",6416)||new long[]{400,410,420}.Contains(n)&&Native(row,"usb",(int)n,"Microsoft-Windows-Kernel-PnP/Configuration","Microsoft-Windows-Kernel-PnP")||new long[]{2003,2100,2101}.Contains(n)&&Native(row,"usb",(int)n,"Microsoft-Windows-DriverFrameworks-UserMode/Operational","Microsoft-Windows-DriverFrameworks-UserMode");
        if(!native||f["storage_evidence"]?.ToString()!="true"||string.IsNullOrWhiteSpace(device)||device.Trim()=="-"||device.Length>=512)return null;
        if(!Ws.IsHash(row.Text("id")))throw new WorkstationException("workstation_c06_observation_id_invalid");
        device=device.Trim().ToUpperInvariant();string? description=f.Text("device_description");if(description?.Length>512)description=description[..512];
        return new(){["device_key"]=Ws.Hash(new JsonArray("station_instance",device)),["device_id"]=device,["description"]=description,["at"]=Ws.Stamp(Ws.Time(row.Text("observed_at"))),["ref"]=Ref(row)};
    }
    internal static JsonObject MergeDevice(string station,JsonObject current,JsonObject? previous)
    {
        var first=Ws.Time(current.Text("at"));var last=first;var firstRef=current["ref"]!.DeepClone();var lastRef=firstRef.DeepClone();string? description=current.Text("description");
        if(previous is not null)
        {
            var a=Ws.Time(previous.Text("first_seen_at"));var b=Ws.Time(previous.Text("last_seen_at"));
            if(a<first||a==first&&string.CompareOrdinal(previous["first_ref"].Text("observation_id"),firstRef.Text("observation_id"))<0){first=a;firstRef=previous["first_ref"]!.DeepClone();}
            if(b>last||b==last&&string.CompareOrdinal(previous["last_ref"].Text("observation_id"),lastRef.Text("observation_id"))>0){last=b;lastRef=previous["last_ref"]!.DeepClone();description=previous.Text("description");}
        }
        return new(){["station_id"]=station,["device_key"]=current["device_key"]!.DeepClone(),["device_id"]=current["device_id"]!.DeepClone(),["description"]=description,["identity_quality"]="station_instance",["storage_evidence"]=true,["first_seen_at"]=Ws.Stamp(first),["last_seen_at"]=Ws.Stamp(last),["first_ref"]=firstRef,["last_ref"]=lastRef};
    }
    static async Task Device(NpgsqlConnection db,string station,JsonObject fact,CancellationToken ct)
    {
        if(fact.Text("kind")!="observations"||DeviceEvent(fact["payload"]!.AsObject()) is not {} current)return;
        var detected=await Now(db,ct);
        var previous=(await Ws.Rows(db,"select * from sli_plugin_workstations.device_seen where station_id=@p0 and device_key=@p1 for update",ct,station,current.Text("device_key"))).SingleOrDefault();
        var row=MergeDevice(station,current,previous);
        await Ws.Insert(db,"device_seen",row,"on conflict(station_id,device_key) do update set description=excluded.description,first_seen_at=excluded.first_seen_at,last_seen_at=excluded.last_seen_at,first_ref=excluded.first_ref,last_ref=excluded.last_ref",ct);
        await Ws.Exec(db,"insert into sli_plugin_workstations.device_seen_occurrences(station_id,device_key,observed_at) values(@p0,@p1,@p2) on conflict do nothing",ct,station,current.Text("device_key"),Ws.Time(current.Text("at")));
        var p=new JsonObject{["first_seen_at"]=row["first_seen_at"]!.DeepClone(),["last_seen_at"]=row["last_seen_at"]!.DeepClone(),["history_start_at"]=row["first_seen_at"]!.DeepClone(),["baseline_status"]="unknown",["identity_quality"]="station_instance",["cross_station_status"]="unavailable",["actor_status"]="unknown"};
        var refs=new JsonArray(row["first_ref"]!.DeepClone());if(!JsonNode.DeepEquals(row["last_ref"],refs[0]))refs.Add(row["last_ref"]!.DeepClone());
        var subject=new JsonObject{["kind"]="workstation_device",["station_id"]=station,["device_id"]=row["device_id"]!.DeepClone(),["description"]=row["description"]?.DeepClone(),["identity_quality"]="station_instance",["serial"]=null};
        string episode=Ws.Hash(new JsonArray("workstations.C06",1,station,row.Text("device_key")));
        var finding=Finding("C06",station,episode,subject,p,refs,Ws.Time(row.Text("first_seen_at")),detected,qualityReason:"device_history_incomplete");finding["subject_id"]=row["device_key"]!.DeepClone();finding["last_observed_at"]=row["last_seen_at"]!.DeepClone();finding["condition_sha256"]=Ws.Hash(new JsonArray(station,row.Text("device_key"),p.Text("first_seen_at")));
        await Ws.Insert(db,"check_findings",finding,"""
            on conflict(id) do update set subject_ref=excluded.subject_ref,condition_sha256=excluded.condition_sha256,fact_at=excluded.fact_at,last_observed_at=excluded.last_observed_at,reason_params=excluded.reason_params,quality=excluded.quality,evidence_refs=excluded.evidence_refs,
            revision=check_findings.revision+case when check_findings.condition_sha256<>excluded.condition_sha256 then 1 else 0 end,
            materially_changed_at=case when check_findings.condition_sha256<>excluded.condition_sha256 then excluded.materially_changed_at else check_findings.materially_changed_at end
            """,ct);
    }
}
