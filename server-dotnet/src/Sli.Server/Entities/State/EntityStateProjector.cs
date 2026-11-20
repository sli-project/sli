using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;

namespace Sli.Server.Entities.State;

internal sealed record EntityStateJob(Guid Id,Guid Lease,long EventId,int Attempt,int Maximum,JsonArray Candidates);
public sealed record EntityStateCycleResult(int Claimed,int Completed,int Failed,int Quarantined,IReadOnlyDictionary<string,int> Actions);

// Port of entity_state_projector and entity_state_runtime. Transactions are
// deliberately separated: claim, apply+fenced completion, and failure recording.
public sealed class EntityStateProjector
{
    internal async Task<EntityStateJob?> ClaimAsync(NpgsqlConnection db,CancellationToken ct)
    {
        await using var tx=await db.BeginTransactionAsync(ct);await SetRoleAsync(db,tx,ct);
        string sql="""
            with candidates as (
              select job.job_id from entity_state_projection_jobs job
              where job.job_schema_version=1 and job.attempt_count<job.max_attempts and job.available_at<=now()
                and (job.status in ('queued','failed') or (job.status='running' and job.lease_until<now()))
                and exists(select 1 from event_hot event where event.event_id=job.source_event_db_id and event.source_sha256 is not null)
                and not exists(select 1 from jsonb_array_elements(job.candidate_states) candidate
                    left join entities_v2_active entity on entity.id=resolve_entity_identity_v2((candidate->>'entity_id')::integer)
                    where entity.id is null)
              order by job.source_event_db_id for update skip locked limit 1
            )
            update entity_state_projection_jobs job set status='running',attempt_count=job.attempt_count+1,
                lease_token=@token,lease_until=now()+interval '300 seconds',heartbeat_at=now(),last_error=null,updated_at=now()
            from candidates where job.job_id=candidates.job_id
            returning job.job_id,job.lease_token,job.source_event_db_id,job.attempt_count,job.max_attempts,job.candidate_states::text
            """;
        var token=Guid.NewGuid();await using var cmd=new NpgsqlCommand(sql,db,tx);cmd.Parameters.AddWithValue("token",token);
        EntityStateJob? result=null;
        await using(var r=await cmd.ExecuteReaderAsync(ct))if(await r.ReadAsync(ct)) {
            var payload=JsonNode.Parse(r.GetString(5)) as JsonArray ?? throw new InvalidDataException("entity_state_payload_invalid");
            result=new(r.GetGuid(0),r.GetGuid(1),r.GetInt64(2),r.GetInt32(3),r.GetInt32(4),payload);
        }
        await tx.CommitAsync(ct);return result;
    }
    internal async Task<IReadOnlyDictionary<string,int>> CompleteAsync(NpgsqlConnection db,EntityStateJob job,CancellationToken ct)
    {
        if(job.Candidates.Count is <1 or >64)throw new InvalidDataException("entity_state_payload_invalid");
        var counters=new Dictionary<string,int>(StringComparer.Ordinal){{"insert",0},{"replace",0},{"same",0},{"older",0},{"conflict",0}};
        await using var tx=await db.BeginTransactionAsync(ct);await SetRoleAsync(db,tx,ct);
        foreach(var node in job.Candidates) {
            if(node is not JsonObject candidate)throw new InvalidDataException("entity_state_payload_invalid");
            string action=await ApplyAsync(db,tx,candidate,ct);counters[action]++;
        }
        await using(var done=new NpgsqlCommand("""
            update entity_state_projection_jobs set status='completed',completed_at=now(),lease_token=null,lease_until=null,
                heartbeat_at=now(),updated_at=now() where job_id=@id and status='running' and lease_token=@token returning job_id
            """,db,tx)) {
            done.Parameters.AddWithValue("id",job.Id);done.Parameters.AddWithValue("token",job.Lease);
            if(await done.ExecuteScalarAsync(ct) is null)throw new InvalidOperationException("entity_state_lease_lost");
        }
        await tx.CommitAsync(ct);return counters;
    }
    internal async Task<bool> HeartbeatAsync(NpgsqlConnection db,EntityStateJob job,int leaseSeconds,CancellationToken ct)
    {
        int seconds=Math.Clamp(leaseSeconds,60,3600);
        await using var tx=await db.BeginTransactionAsync(ct);await SetRoleAsync(db,tx,ct);
        await using var cmd=new NpgsqlCommand("""
            update entity_state_projection_jobs set heartbeat_at=now(),lease_until=now()+(@seconds*interval '1 second'),updated_at=now()
            where job_id=@id and status='running' and lease_token=@token returning job_id
            """,db,tx);
        cmd.Parameters.AddWithValue("seconds",seconds);cmd.Parameters.AddWithValue("id",job.Id);cmd.Parameters.AddWithValue("token",job.Lease);
        bool updated=await cmd.ExecuteScalarAsync(ct) is not null;await tx.CommitAsync(ct);return updated;
    }
    private static async Task<string> ApplyAsync(NpgsqlConnection db,NpgsqlTransaction tx,JsonObject input,CancellationToken ct)
    {
        var candidate=(JsonObject)input.DeepClone();int entity=checked((int)RequiredLong(candidate,"entity_id"));
        await using(var resolve=new NpgsqlCommand("select resolve_entity_identity_v2(@id)",db,tx)) {
            resolve.Parameters.AddWithValue("id",entity);if(await resolve.ExecuteScalarAsync(ct) is not int effective)throw new InvalidOperationException("entity_state_identity_unavailable");entity=effective;
        }
        candidate["entity_id"]=entity;string type=RequiredText(candidate,"state_type"),severity=RequiredText(candidate,"severity"),status=RequiredText(candidate,"status"),summary=RequiredText(candidate,"summary"),rule=RequiredText(candidate,"rule_id"),version=RequiredText(candidate,"rule_version");
        long eventId=RequiredLong(candidate,"source_event_db_id");string observed=RequiredText(candidate,"observed_at_utc");
        var details=ReadDetails(candidate);
        var history=(JsonObject)details.DeepClone();history["rule_id"]=candidate["rule_id"]?.DeepClone();history["rule_version"]=candidate["rule_version"]?.DeepClone();
        history["projection_status"]=candidate.ContainsKey("projection_status")?candidate["projection_status"]?.DeepClone():JsonValue.Create("normal");
        await using(var insert=new NpgsqlCommand("""
            insert into entity_states(entity_id,state_type,severity,status,observed_at_utc,summary,evidence_event_id,details_json)
            values(@entity,@type,@severity,@status,@observed,@summary,@event,@details)
            on conflict(entity_id,state_type,evidence_event_id) do nothing
            """,db,tx)) {
            insert.Parameters.AddWithValue("entity",entity);insert.Parameters.AddWithValue("type",type);insert.Parameters.AddWithValue("severity",severity);insert.Parameters.AddWithValue("status",status);
            insert.Parameters.AddWithValue("observed",observed);insert.Parameters.AddWithValue("summary",summary);insert.Parameters.AddWithValue("event",eventId);
            insert.Parameters.AddWithValue("details",NpgsqlDbType.Text,SourceJson.SerializeSorted(history));await insert.ExecuteNonQueryAsync(ct);
        }
        // A missing row cannot be locked by SELECT FOR UPDATE. Let the unique
        // key serialize first insertions, then resolve against the winning row.
        if(await InsertCurrentAsync(db,tx,candidate,ct))return "insert";
        JsonObject? current=null;
        await using(var select=new NpgsqlCommand("""
            select status,projection_status,observed_at,source_event_db_id,rule_id,rule_version,details_json::text
            from entity_state_current where entity_id=@entity and state_type=@type for update
            """,db,tx)) {
            select.Parameters.AddWithValue("entity",entity);select.Parameters.AddWithValue("type",type);
            await using var r=await select.ExecuteReaderAsync(ct);if(await r.ReadAsync(ct))current=new JsonObject {
                ["entity_id"]=entity,["state_type"]=type,["status"]=r.GetString(0),["projection_status"]=r.GetString(1),
                ["observed_at_utc"]=r.GetDateTime(2).ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'",CultureInfo.InvariantCulture),
                ["source_event_db_id"]=r.GetInt64(3),["rule_id"]=r.GetString(4),["rule_version"]=r.GetString(5),["details_json"]=JsonNode.Parse(r.GetString(6)) };
        }
        if(current is null)throw new InvalidOperationException("entity_state_current_disappeared");
        var (action,result)=EntityStateResolution.Resolve(current,candidate);
        if(action is "older" or "same")return action;
        await WriteCurrentAsync(db,tx,result,false,ct);return action;
    }
    private static Task<bool> InsertCurrentAsync(NpgsqlConnection db,NpgsqlTransaction tx,JsonObject result,CancellationToken ct)
        =>WriteCurrentAsync(db,tx,result,true,ct);
    private static async Task<bool> WriteCurrentAsync(NpgsqlConnection db,NpgsqlTransaction tx,JsonObject result,bool insertOnly,CancellationToken ct)
    {
        int entity=checked((int)RequiredLong(result,"entity_id"));string type=RequiredText(result,"state_type");
        var resultDetails=ReadDetails(result);
        if(result["conflict_statuses"] is JsonArray conflicts)resultDetails["conflict_statuses"]=conflicts.DeepClone();
        var sql=insertOnly?"""
            insert into entity_state_current(entity_id,state_type,status,projection_status,observed_at,source_event_db_id,rule_id,rule_version,details_json)
            values(@entity,@type,@status,@projection,@observed::timestamptz,@event,@rule,@version,@details)
            on conflict(entity_id,state_type) do nothing returning entity_id
            """:"""
            update entity_state_current set status=@status,projection_status=@projection,observed_at=@observed::timestamptz,
                source_event_db_id=@event,rule_id=@rule,rule_version=@version,details_json=@details,updated_at=now()
            where entity_id=@entity and state_type=@type returning entity_id
            """;
        await using var upsert=new NpgsqlCommand(sql,db,tx);
        upsert.Parameters.AddWithValue("entity",entity);upsert.Parameters.AddWithValue("type",type);upsert.Parameters.AddWithValue("status",RequiredText(result,"status"));
        string projection=EntityStateResolution.Text(result,"projection_status");upsert.Parameters.AddWithValue("projection",projection.Length==0?"normal":projection);
        upsert.Parameters.AddWithValue("observed",RequiredText(result,"observed_at_utc"));upsert.Parameters.AddWithValue("event",RequiredLong(result,"source_event_db_id"));
        upsert.Parameters.AddWithValue("rule",RequiredText(result,"rule_id"));upsert.Parameters.AddWithValue("version",RequiredText(result,"rule_version"));
        upsert.Parameters.AddWithValue("details",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(resultDetails,ensureAscii:false));return await upsert.ExecuteScalarAsync(ct) is not null;
    }
    internal async Task<string> FailAsync(NpgsqlConnection db,EntityStateJob job,Exception error,CancellationToken ct)
    {
        bool terminal=job.Attempt>=job.Maximum;string state=terminal?"quarantined":"failed";
        int delay=Math.Min(3600,30*(1<<Math.Clamp(job.Attempt-1,0,7)));
        // Python stores str(error)[:1000]; bound by Unicode scalars, not UTF-16 units.
        // Connection-level exceptions may carry credentials and occur outside a
        // successful claim/apply operation; do not persist their full text.
        string diagnostic=error is NpgsqlException and not PostgresException
            ? "entity_state_connection_failed" : error.Message;
        string message=string.Concat(diagnostic.EnumerateRunes().Take(1000).Select(r=>r.ToString()));
        await using var tx=await db.BeginTransactionAsync(ct);await SetRoleAsync(db,tx,ct);
        await using var cmd=new NpgsqlCommand("""
            update entity_state_projection_jobs set status=@state,available_at=now()+(@seconds*interval '1 second'),
              lease_token=null,lease_until=null,last_error=@error,updated_at=now()
            where job_id=@id and status='running' and lease_token=@token returning status
            """,db,tx);
        cmd.Parameters.AddWithValue("state",state);cmd.Parameters.AddWithValue("seconds",delay);cmd.Parameters.AddWithValue("error",message);
        cmd.Parameters.AddWithValue("id",job.Id);cmd.Parameters.AddWithValue("token",job.Lease);
        if(await cmd.ExecuteScalarAsync(ct) is not string saved)throw new InvalidOperationException("entity_state_lease_lost");
        await tx.CommitAsync(ct);return saved;
    }
    internal async Task<EntityStateCycleResult> RunOnceAsync(NpgsqlConnection db,int limit,CancellationToken ct)
    {
        limit=Math.Clamp(limit,1,16);int claimed=0,completed=0,failed=0,quarantined=0;
        var actions=new Dictionary<string,int>(StringComparer.Ordinal){{"insert",0},{"replace",0},{"same",0},{"older",0},{"conflict",0}};
        for(int i=0;i<limit;i++) {
            var job=await ClaimAsync(db,ct);if(job is null)break;claimed++;
            try {var result=await CompleteAsync(db,job,ct);completed++;foreach(var entry in result)actions[entry.Key]+=entry.Value;}
            catch(OperationCanceledException) when(ct.IsCancellationRequested){throw;}
            catch(Exception error){var state=await FailAsync(db,job,error,ct);failed++;if(state=="quarantined")quarantined++;}
        }
        return new(claimed,completed,failed,quarantined,actions);
    }
    private static async Task SetRoleAsync(NpgsqlConnection db,NpgsqlTransaction tx,CancellationToken ct)
    {await using var c=new NpgsqlCommand("set local role adlog_storage_worker",db,tx);await c.ExecuteNonQueryAsync(ct);}
    private static string RequiredText(JsonObject o,string key)=>o.ContainsKey(key)?EntityStateResolution.Coerce(o[key]):throw new InvalidDataException("entity_state_payload_invalid");
    internal static JsonObject ReadDetails(JsonObject candidate)
    {
        var input=candidate["details"];
        if(input is null || input is JsonValue && EntityStateResolution.Text(candidate,"details").Length==0)return new();
        if(input is JsonObject obj)return (JsonObject)obj.DeepClone();
        if(input is JsonArray pairs) {
            var result=new JsonObject();
            foreach(var item in pairs) {
                if(item is not JsonArray { Count: 2 } pair || !JsonRead.TryString(pair[0],out var key))
                    throw new InvalidDataException("entity_state_details_invalid");
                result[key]=pair[1]?.DeepClone();
            }
            return result;
        }
        throw new InvalidDataException("entity_state_details_invalid");
    }
    private static long RequiredLong(JsonObject o,string key)
    {
        if(!o.ContainsKey(key))throw new InvalidDataException("entity_state_payload_invalid");
        var n=EntityStateResolution.PythonInteger(o[key]);
        return n>=long.MinValue && n<=long.MaxValue?(long)n:throw new InvalidDataException("entity_state_payload_invalid");
    }
}
