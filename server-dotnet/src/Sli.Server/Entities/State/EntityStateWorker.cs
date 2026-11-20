using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using System.Text.Json.Nodes;

namespace Sli.Server.Entities.State;

// The non-pooled session carrying the global advisory lock also executes
// every protected claim, apply, completion and failure transaction.
public sealed class EntityStateWorker(EntityStateWorkerRuntime runtime)
{
    public async Task<int> RunAsync(bool once,int pollSeconds,int limit,CancellationToken ct,Action<JsonObject>? onResult=null)
    {
        pollSeconds=Math.Clamp(pollSeconds,1,300);limit=Math.Clamp(limit,1,16);
        var workerId=$"entity-state-runtime-{Environment.MachineName}-{Environment.ProcessId}";var started=DateTime.UtcNow;
        await using var lockConnection=await runtime.DataSource.OpenConnectionAsync(ct);
        await using(var role=new NpgsqlCommand("set role adlog_storage_worker",lockConnection))await role.ExecuteNonQueryAsync(ct);
        await using(var command=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_entity_state_worker'))",lockConnection))
            if(await command.ExecuteScalarAsync(ct) is not true) {
                onResult?.Invoke(new JsonObject { ["worker_id"]=workerId,["status"]="skipped",["reason"]="entity_state_worker_lock_held" });
                return 0;
            }
        try {
            var projector=new EntityStateProjector();
            while(!ct.IsCancellationRequested) {
                await HeartbeatAsync(lockConnection,workerId,"running","poll",pollSeconds,started,new JsonObject { ["limit"]=limit },ct);
                try {
                    var result=await projector.RunOnceAsync(lockConnection,limit,ct);
                    var actions=new JsonObject();foreach(var pair in result.Actions)actions[pair.Key]=pair.Value;
                    var summary=new JsonObject { ["status"]=result.Failed==0?"ok":"partial",["worker_id"]=$"entity-state-{Environment.MachineName}-{Environment.ProcessId}",["claimed"]=result.Claimed,["completed"]=result.Completed,["failed"]=result.Failed,["quarantined"]=result.Quarantined,["actions"]=actions };
                    var output=(JsonObject)summary.DeepClone();output["runtime_worker_id"]=workerId;onResult?.Invoke(output);
                    await HeartbeatAsync(lockConnection,workerId,result.Failed==0?"idle":"failed","sleep",pollSeconds,started,new JsonObject { ["last_result"]=summary },ct);
                    if(once)return result.Failed==0?0:1;
                } catch(OperationCanceledException) when(ct.IsCancellationRequested){throw;}
                catch(NpgsqlException error) when(error is not PostgresException) { throw; }
                catch(Exception) {
                    if(lockConnection.State!=System.Data.ConnectionState.Open)throw;
                    await HeartbeatAsync(lockConnection,workerId,"failed","sleep",pollSeconds,started,new JsonObject { ["error_type"]="entity_state_worker_failed" },ct);
                    if(once)return 1;
                }
                await Task.Delay(TimeSpan.FromSeconds(pollSeconds),ct);
            }
            return 0;
        } finally {
            await using var unlock=new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_entity_state_worker'))",lockConnection);
            await unlock.ExecuteScalarAsync(CancellationToken.None);
        }
    }
    private static async Task HeartbeatAsync(NpgsqlConnection db,string workerId,string status,string phase,int interval,DateTime started,JsonObject details,CancellationToken ct)
    {
        try {
            await using var tx=await db.BeginTransactionAsync(ct);
            await using(var role=new NpgsqlCommand("set local role adlog_storage_worker",db,tx))await role.ExecuteNonQueryAsync(ct);
            await using var command=new NpgsqlCommand("""
                insert into runtime_worker_heartbeats(worker_name,worker_id,process_pid,status,phase,expected_interval_seconds,details_json,started_at,heartbeat_at,updated_at)
                values('entity_state',@worker,@pid,@status,@phase,@interval,@details,@started,now(),now())
                on conflict(worker_name) do update set worker_id=excluded.worker_id,process_pid=excluded.process_pid,status=excluded.status,
                  phase=excluded.phase,expected_interval_seconds=excluded.expected_interval_seconds,details_json=excluded.details_json,
                  started_at=case when runtime_worker_heartbeats.worker_id=excluded.worker_id then runtime_worker_heartbeats.started_at else excluded.started_at end,
                  heartbeat_at=now(),updated_at=now()
                """,db,tx);
            command.Parameters.AddWithValue("worker",workerId);command.Parameters.AddWithValue("pid",Environment.ProcessId);command.Parameters.AddWithValue("status",status);command.Parameters.AddWithValue("phase",phase);
            command.Parameters.AddWithValue("interval",interval);command.Parameters.AddWithValue("started",started);command.Parameters.AddWithValue("details",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(details,ensureAscii:false));
            await command.ExecuteNonQueryAsync(ct);await tx.CommitAsync(ct);
        } catch(OperationCanceledException) when(ct.IsCancellationRequested){throw;}
        catch(NpgsqlException error) when(error is not PostgresException) { throw; }
        catch(Exception){ if(db.State!=System.Data.ConnectionState.Open)throw; /* Source heartbeat failures never stop projection. */ }
    }
}
