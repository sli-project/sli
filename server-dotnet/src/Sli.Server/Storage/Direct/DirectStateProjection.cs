using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Agents.Consumer;
using Sli.Server.Auth.Lifecycle.Security;

namespace Sli.Server.Storage.Direct;

// Bounded port of state_for_entity_link and enqueue_projection_job for the
// pinned source catalogue. Caller owns the inbox transaction.
internal static class DirectStateProjection
{
    internal static Guid JobId(long eventId)=>AuthAudit.Uuid5("adlog:entity-state:v1:event:"+eventId.ToString(CultureInfo.InvariantCulture));
    internal static JsonObject? Candidate(JsonObject row,Direct4624Projection projection,long eventId,int entityId,string role="target")
    {
        if(projection.Normalizer!="event_catalog" || role is not ("target" or "affected"))return null;
        var rule=(projection.Channel,projection.EventKind) switch {
            ("Security",4720) => ("account.lifecycle","created","account-created-4720","Создан пользователь"),
            ("Security",4722) => ("account.access","enabled","account-enabled-4722","Включена учетная запись"),
            ("Security",4740) => ("account.access","locked","account-locked-4740","Блокировка учетной записи"),
            ("Microsoft-Windows-TaskScheduler/Operational",140)=>("scheduled_task.configuration","changed","scheduled-task-changed-140","Task Scheduler: задача изменена"),
            _ => default
        };
        if(rule.Item1 is null)return null;
        var card=DirectNativeEvent.Card(row);
        if(card["known"]?.GetValue<bool>() is not true || card["catalog_match"]?.GetValue<bool>() is not true)return null;
        var text=row["time_created"]!.GetValue<string>();
        if(!PythonIsoDateTime.TryParse(text.Replace("Z","+00:00",StringComparison.Ordinal),out var parsed) || !parsed.IsAware || !parsed.TryToUtc(out var utc))return null;
        long micros=utc.Ticks%TimeSpan.TicksPerSecond/10;
        string observed=utc.ToString("yyyy-MM-dd'T'HH:mm:ss",CultureInfo.InvariantCulture)+(micros==0?"":"."+micros.ToString("D6",CultureInfo.InvariantCulture))+"Z";
        return new JsonObject {
            ["entity_id"]=entityId,["state_type"]=rule.Item1,["severity"]=card["severity"]?.DeepClone(),["status"]=rule.Item2,
            ["observed_at_utc"]=observed,["summary"]=card["title"]?.DeepClone(),["source_event_db_id"]=eventId,
            ["rule_id"]=rule.Item3,["rule_version"]="entity-state-1.0",["projection_status"]="normal",
            ["details"]=new JsonObject { ["catalog_key"]=new JsonObject { ["provider"]=projection.Provider,["channel"]=projection.Channel,["event_id"]=projection.EventKind },["entity_role"]=role,["catalog_match"]=true }
        };
    }
    internal static async Task EnqueueAsync(NpgsqlConnection db,NpgsqlTransaction tx,IReadOnlyList<DirectBatchProjection> batch,CancellationToken ct)
    {
        var jobs=new List<(long Event,JsonArray Candidates)>();
        foreach(var item in batch.OrderBy(x=>x.Reservation.Id)) {
            var candidates=new List<JsonObject>();
            for(int i=0;i<item.Projection.Entities.Count;i++) {
                if(item.Projection.Entities[i].Role is not ("target" or "affected"))continue;
                var candidate=Candidate(item.Row,item.Projection,item.Reservation.Id,item.Entities[i].EffectiveId,item.Projection.Entities[i].Role);
                if(candidate is not null)candidates.Add(candidate);
            }
            if(candidates.Count==0)continue;
            if(candidates.Count>64)throw new InvalidDataException("entity_state_candidates_invalid");
            var array=new JsonArray(candidates.OrderBy(x=>(int)x["entity_id"]!).ThenBy(x=>(string?)x["state_type"],StringComparer.Ordinal).ThenBy(x=>(string?)x["rule_id"],StringComparer.Ordinal).Select(x=>(JsonNode?)x).ToArray());
            jobs.Add((item.Reservation.Id,array));
        }
        await EnqueueBatchAsync(db,tx,jobs,ct);
    }
    internal static Task EnqueueCandidatesAsync(NpgsqlConnection db,NpgsqlTransaction tx,long eventId,JsonArray array,CancellationToken ct) =>
        EnqueueBatchAsync(db,tx,[(eventId,array)],ct);

    private static async Task EnqueueBatchAsync(NpgsqlConnection db,NpgsqlTransaction tx,IReadOnlyList<(long Event,JsonArray Candidates)> jobs,CancellationToken ct)
    {
        if(jobs.Count==0)return;
        if(jobs.Any(job=>job.Candidates.Count is <1 or >64 || job.Candidates.Any(x=>x is not JsonObject o || (long?)o["source_event_db_id"]!=job.Event)))
            throw new InvalidDataException("entity_state_candidates_invalid");
        var rows=new JsonArray(jobs.Select(job=>(JsonNode?)new JsonObject {
            ["job_id"]=JobId(job.Event).ToString(),["source_event_db_id"]=job.Event,["candidate_states"]=job.Candidates.DeepClone()
        }).ToArray());
        await using(var insert=new NpgsqlCommand("""
            insert into entity_state_projection_jobs(job_id,job_schema_version,source_event_db_id,candidate_states)
            select w.job_id,1,w.source_event_db_id,w.candidate_states from jsonb_to_recordset(@rows)
                w(job_id uuid,source_event_db_id bigint,candidate_states jsonb)
            on conflict(source_event_db_id) do nothing
            """,db,tx)) {
            insert.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(rows,ensureAscii:false));await insert.ExecuteNonQueryAsync(ct);
        }
        var expected=jobs.ToDictionary(x=>x.Event,x=>x.Candidates);
        await using var verify=new NpgsqlCommand("select source_event_db_id,candidate_states::text from entity_state_projection_jobs where source_event_db_id=any(@events)",db,tx);
        verify.Parameters.AddWithValue("events",expected.Keys.ToArray());
        await using var reader=await verify.ExecuteReaderAsync(ct);int count=0;
        while(await reader.ReadAsync(ct)) {
            if(!WorkstationJsonEquality.Equals(JsonNode.Parse(reader.GetString(1)),expected[reader.GetInt64(0)]))throw new InvalidOperationException("entity_state_job_replay_conflict");
            count++;
        }
        if(count!=expected.Count)throw new InvalidOperationException("entity_state_job_replay_conflict");
    }
}
