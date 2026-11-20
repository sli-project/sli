using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
namespace Sli.Server.Workstations;

// Crash-visible source-free receipt. Failure to persist it prevents deletion.
internal sealed class WorkstationPurgeRun
{
    readonly Stopwatch watch=Stopwatch.StartNew();readonly string directory;readonly string path;
    readonly JsonObject payload=new(){["contract"]="sli.purge-run.v1",["lane"]="workstations",["started_at_utc"]=Ws.Stamp(DateTimeOffset.UtcNow),["status"]="running",["tables"]=new JsonObject{["sli_plugin_workstations.observations"]=new JsonObject{["selected_count"]=0,["deleted_count"]=0,["logical_bytes_deleted"]=0,["partitions"]=new JsonArray()}},["duration_ms"]=0,["bytes_reclaimed"]=0,["logical_bytes_deleted"]=0,["physical_reclaim_performed"]=false};
    internal WorkstationPurgeRun(string? root=null)
    {
        root??=Environment.GetEnvironmentVariable("ADLOG_DATA_DIR")??Environment.GetEnvironmentVariable("SLI_DATA_DIR")??(Directory.Exists(Path.Combine(Environment.CurrentDirectory,"..","sli_data"))?Path.Combine(Environment.CurrentDirectory,"..","sli_data"):Path.Combine(Environment.CurrentDirectory,"data"));
        directory=Path.Combine(root,"runtime","purge-runs");Directory.CreateDirectory(directory);path=Path.Combine(directory,DateTimeOffset.UtcNow.ToString("yyyyMMdd'T'HHmmssffffff'Z'")+"-"+Guid.NewGuid().ToString("N")+".json");Write();
    }
    void Write()
    {
        string temp=Path.ChangeExtension(path,".tmp");
        using(var stream=new FileStream(temp,FileMode.Create,FileAccess.Write,FileShare.None)){var bytes=System.Text.Encoding.UTF8.GetBytes(payload.ToJsonString());stream.Write(bytes);stream.Flush(true);}
        File.Move(temp,path,true);
    }
    internal void Finish(int selected,int deleted,long bytes,int days,DateTimeOffset cutoff,Exception? error=null)
    {
        payload["finished_at_utc"]=Ws.Stamp(DateTimeOffset.UtcNow);payload["duration_ms"]=watch.Elapsed.TotalMilliseconds;
        payload["status"]=error is null?(selected==50?"partial":"success"):"blocked";payload["transaction"]=error is null?"caller_owned_unconfirmed":"caller_rollback_required";
        var table=payload["tables"]!["sli_plugin_workstations.observations"]!;table["selected_count"]=selected;table["deleted_count"]=deleted;table["logical_bytes_deleted"]=bytes;payload["logical_bytes_deleted"]=bytes;
        if(error is null){payload["moved"]=deleted;payload["retention_days"]=days;payload["cutoff_utc"]=Ws.Stamp(cutoff);payload["continuation"]=selected==50?new JsonObject{["before_utc"]=Ws.Stamp(cutoff)}:null;}
        else payload["reason"]=Reason(error);
        Write();foreach(string old in Directory.EnumerateFiles(directory,"*.json").OrderDescending(StringComparer.Ordinal).Skip(50))File.Delete(old);
    }
    internal static string Reason(Exception e)=>e is PostgresException p?p.SqlState switch{"57014"=>"purge_statement_timeout","55P03"=>"purge_lock_unavailable","42501"=>"purge_permission_denied","23503"=>"purge_dependency_changed","42P01"=>"purge_schema_missing","42703"=>"purge_schema_incompatible","28P01"=>"postgres_authentication_failed",_=>"purge_verification_or_io_failed"}:e.Message is "workstation_observation_hash_mismatch" or "workstation_source_hash_mismatch" or "workstation_history_receipt_mismatch" or "workstation_delete_count_mismatch" or "workstation_history_unavailable" or "workstation_history_durability_unverified" or "workstation_retention_plan_changed" or "workstation_delete_readback_mismatch"?e.Message:"purge_verification_or_io_failed";
}
