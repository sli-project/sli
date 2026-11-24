using Sli.Server.Infrastructure;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Jobs;

namespace Sli.Server.Vpn;

public sealed class RadiusJobs : ICoreJobPlugin
{
    public void Register(CoreJobPluginCatalog catalog)
    {
        foreach(string handler in new[]{"radius-acquisition","radius-session-observation"})
            catalog.Add("sli.remote-access",handler,new(StageAsync,PublishAsync),ScheduleAsync);
    }
    internal static Task<List<JsonObject>> Rows(NpgsqlConnection db,string sql,CancellationToken ct,params object?[] values)
        => Rows(db,null,sql,ct,values);

    internal static async Task<List<JsonObject>> Rows(NpgsqlConnection db,NpgsqlTransaction? tx,string sql,CancellationToken ct,params object?[] values)
    {
        SqlArguments.Validate(values);
        await using var cmd=new NpgsqlCommand(sql,db,tx);
        foreach(var value in values) cmd.Parameters.Add(PostgresVpnStore.Parameter(value));
        var result=new List<JsonObject>();await using var reader=await cmd.ExecuteReaderAsync(ct);
        while(await reader.ReadAsync(ct))
        {
            var row=new JsonObject();for(int i=0;i<reader.FieldCount;i++) row[reader.GetName(i)]=reader.IsDBNull(i)?null:System.Text.Json.JsonSerializer.SerializeToNode(reader.GetValue(i));result.Add(row);
        }
        return result;
    }
    internal static async Task<object?> Scalar(NpgsqlConnection db,string sql,CancellationToken ct,params object?[] values)
    {SqlArguments.Validate(values); await using var cmd=new NpgsqlCommand(sql,db);foreach(var value in values) cmd.Parameters.Add(PostgresVpnStore.Parameter(value));return await cmd.ExecuteScalarAsync(ct); }
    internal static async Task<int> Execute(NpgsqlConnection db,string sql,CancellationToken ct,params object?[] values)
    {SqlArguments.Validate(values); await using var cmd=new NpgsqlCommand(sql,db);foreach(var value in values) cmd.Parameters.Add(PostgresVpnStore.Parameter(value));return await cmd.ExecuteNonQueryAsync(ct); }
    static object?[] Fence(JsonObject job)=>[Guid.Parse(job.Text("job_id")),Guid.Parse(job.Text("lease_token")),job.Number("lease_generation")];
    static JsonObject Envelope(JsonObject job,bool blocked,long[] ids)=>VpnJson.Obj(new {output_contract=job.Text("result_contract"),evidence_refs=Array.Empty<object>(),continuation=(object?)null,coverage_state=blocked?"not_collected":"partial",status=blocked?"blocked":"partial",error_code=blocked?"acquisition_disabled":null,delivery_ids=ids});
    public static async Task ScheduleAsync(NpgsqlConnection db,CoreJobQueue queue,CoreJobRegistry registry,string profile,CancellationToken ct)
    {
        if(profile!="light") return;
        string source=Environment.GetEnvironmentVariable("SLI_CORE_JOB_RADIUS_SOURCE_INSTANCE_ID")??"";
        if(source=="") throw new CoreJobContractException("radius_pilot_source_required");
        if(await Scalar(db,"select public.read_radius_job_source_v1($1)",ct,source) is string json && JsonNode.Parse(json) is JsonObject data)
            foreach(var spec in CoreJobScheduler.Create(registry,profile,data,DateTimeOffset.UtcNow)) await queue.EnqueueAsync(spec,ct);
    }
    public static async Task<JsonObject> StageAsync(NpgsqlConnection db,JsonObject job,CancellationToken ct)
    {
        if(job.Text("handler_id")=="radius-acquisition") return Envelope(job,true,[]);
        var rows=await Rows(db,"select delivery_id from public.read_radius_job_input_v1($1,$2,$3)",ct,Fence(job));
        long[] ids=rows.Select(r=>r.Number("delivery_id")).ToArray();ValidateIds(job,ids,false);return Envelope(job,false,ids);
    }
    public static long[] ValidateResult(JsonObject job,JsonObject result)
    {
        if(result["delivery_ids"] is not JsonArray values) throw new VpnInputException("job_result_invalid");
        var ids=new List<long>();foreach(var value in values)
        { if(value is not JsonValue v || !v.TryGetValue<long>(out long id) || id<=0) throw new VpnInputException("job_result_invalid");ids.Add(id); }
        ValidateIds(job,ids.ToArray(),true);return ids.ToArray();
    }
    static void ValidateIds(JsonObject job,long[] ids,bool publish)
    {
        long budget=job["budget"].Number("max_records");if(ids.Length>(publish?Math.Min(50,budget):budget)) throw new VpnInputException("job_row_budget_exceeded");
        if(ids.Distinct().Count()!=ids.Length || ids.Any(id=>id<=0)) throw new VpnInputException("job_result_invalid");
        if(job["pinned_input"]?["delivery_ids"] is not JsonArray pin || !ids.ToHashSet().SetEquals(pin.Select(x=>x!.GetValue<long>()))) throw new VpnInputException("radius_input_changed");
    }
    public static async Task PublishAsync(NpgsqlConnection db,JsonObject job,JsonObject result,CancellationToken ct)
    {
        if(result.Text("status") is "blocked" or "cancelled") return;
        if(job.Text("handler_id")=="radius-acquisition") throw new VpnInputException("acquisition_disabled");
        var ids=ValidateResult(job,result);if(ids.Length==0) return;
        string subscription=job["pinned_input"].Text("subscription_id");if(subscription.Length is <1 or >512) throw new VpnInputException("consumer_subscription_invalid");
        await ConsumeAsync(db, subscription, ids, $"core-job:{job.Text("job_id")}:{job.Number("lease_generation")}", job["budget"].Number("max_records"), ct);
    }
    public static async Task<string> FailAsync(NpgsqlConnection db, long deliveryId, Guid leaseToken, string errorCode, int retryDelaySeconds, CancellationToken ct)
    {
        string code = (errorCode ?? "").Trim();
        if (!System.Text.RegularExpressions.Regex.IsMatch(code, @"\A[a-z][a-z0-9_]{0,119}\z")) throw new VpnInputException("error_code_invalid");
        if (retryDelaySeconds is < 0 or > 3600) throw new VpnInputException("retry_delay_invalid");
        if (deliveryId <= 0) throw new VpnInputException("delivery_id_invalid");
        await using var transaction = await db.BeginTransactionAsync(ct);
        await Execute(db, "set local role adlog_radius_session_consumer", ct);
        // Quarantine remains owned by the existing claim policy, not a new retry cap.
        string state = await Scalar(db, """
            update acquisition_delivery_outbox
            set delivery_state='failed', available_at=now()+($1 * interval '1 second'),
                lease_token=null,lease_until=null,heartbeat_at=now(),
                last_error_code=$2,updated_at=now()
            where delivery_id=$3 and delivery_state='leased' and lease_token=$4
            returning delivery_state
            """, ct, retryDelaySeconds, code, deliveryId, leaseToken) as string ?? throw new VpnInputException("delivery_lease_lost");
        await transaction.CommitAsync(ct);
        return state;
    }
    internal static async Task<JsonObject> ConsumeAsync(NpgsqlConnection db, string subscription, long[]? ids, string holder, long remaining, CancellationToken ct)
    {
        var lease=await PluginRuntimeAdmissionExecutor.AcquireAsync(db,Guid.NewGuid(),PluginRuntimeAdmissionExecutor.Consumer,holder,ct,activateRole:false);
        var result=await ConsumeDeliveriesAsync(db,subscription,ids,remaining,ct);
        if(!await PluginRuntimeAdmissionExecutor.ReleaseAsync(db,lease,holder,"completed",ct,activateRole:false)) throw new VpnInputException("component_lease_release_invalid");
        // The core publisher owns commit/rollback and the result fence.
        return result;
    }
    internal static async Task<JsonObject> ConsumeDeliveriesAsync(NpgsqlConnection db, string subscription, long[]? ids, long remaining, CancellationToken ct)
    {
        // A standalone cycle selects its input only after component admission.
        // Core jobs already supply their fenced, pinned delivery IDs.
        if(ids is null) ids=(await Rows(db,"""
            select delivery_id from acquisition_delivery_outbox where subscription_id=$1 and attempt_count<5
              and available_at<=now() and (delivery_state in ('queued','failed') or (delivery_state='leased' and lease_until<=now()))
            order by available_at,created_at,delivery_id for update skip locked limit 50
            """,ct,subscription)).Select(d=>d.Number("delivery_id")).ToArray();
        await Execute(db,RadiusConsumerSql.Quarantine,ct,subscription,5);
        Guid token=Guid.NewGuid();var claimed=await Rows(db,"""
            with candidates as (
                select delivery_id from acquisition_delivery_outbox
                where subscription_id=$1 and attempt_count<5 and available_at<=now() and delivery_id=any($2)
                  and (delivery_state in ('queued','failed') or (delivery_state='leased' and lease_until<=now()))
                order by available_at,created_at,delivery_id for update skip locked limit $3
            ), claimed as (update acquisition_delivery_outbox delivery set delivery_state='leased',attempt_count=delivery.attempt_count+1,
                lease_token=$4,lease_until=now()+interval '120 seconds',heartbeat_at=now(),last_error_code=null,updated_at=now()
              from candidates where delivery.delivery_id=candidates.delivery_id
              returning delivery.delivery_id) select delivery_id from claimed
            """,ct,subscription,ids,ids.Length,token);
        if(!ids.ToHashSet().SetEquals(claimed.Select(r=>r.Number("delivery_id")))) throw new VpnInputException("radius_input_changed");
        var outcomes=new JsonObject();
        foreach(var row in claimed)
            remaining-=await ProcessDeliveryAsync(db,subscription,row.Number("delivery_id"),token,remaining,ct,outcomes);
        return new JsonObject { ["status"]="completed", ["claimed"]=claimed.Count, ["processed"]=claimed.Count, ["outcomes"]=outcomes };
    }
    // Shared projection and receipt rules; the caller owns the delivery transaction.
    // The recurring host has no record/time budget. Core jobs retain their pinned budget.
    internal static async Task<long> ProcessDeliveryAsync(NpgsqlConnection db,string subscription,long id,Guid token,long? remaining,CancellationToken ct,JsonObject? outcomes=null)
    {
            long consumed=0;var delivery=(await Rows(db,RadiusConsumerSql.Delivery,ct,id,subscription,token)).SingleOrDefault()??throw new VpnInputException("delivery_lease_lost");
            var prior=(await Rows(db,RadiusConsumerSql.Prior,ct,id)).SingleOrDefault();
            string outcome=prior?.Text("outcome")??(delivery.Text("identity_state")!="exact"?"identity_unresolved":delivery.Text("timestamp_state")!="ready"?"timestamp_unresolved":"projected");int count=(int)(prior?.Number("projected_row_count")??0);
            if(prior is null && outcome=="projected")
            {
                string key=delivery.Text("session_identity_key").Trim();if(key=="") throw new VpnInputException("exact_session_key_required");
                await Scalar(db,RadiusConsumerSql.ProjectionLock,ct,key);
                bool overlay=await Scalar(db,RadiusConsumerSql.OverlayReadable,ct) is true;
                int? maximum=remaining is null?null:(int)Math.Min(10000,remaining.Value);
                string sql=overlay?RadiusConsumerSql.ObservationsOverlay:RadiusConsumerSql.Observations;
                var observations=maximum is null
                    ?await Rows(db,sql.Replace("limit $4","",StringComparison.Ordinal),ct,subscription,key,id)
                    :await Rows(db,sql,ct,subscription,key,id,maximum.Value+1);
                if(maximum is not null && observations.Count>maximum.Value) throw new VpnInputException("session_observation_limit_exceeded");consumed=observations.Count;
                var folded=RadiusSessionFold.Fold(observations);await Execute(db,RadiusConsumerSql.DeleteProjection,ct,key);
                foreach(var session in folded)
                {
                    await using var insert=new NpgsqlCommand(RadiusConsumerSql.InsertProjection,db);
                    string[] fields=["session_row_id","session_identity_key","exact_principal_key","generation","lifecycle_state","completeness","started_at_utc","last_observed_at_utc","stopped_at_utc","duration_seconds","observation_count","anomalies"];
                    foreach(string field in fields)
                    {
                        object? value=field.EndsWith("_utc",StringComparison.Ordinal)?session.At(field):field=="anomalies"?session[field]!.AsArray().Select(x=>x!.ToString()).ToArray():field is "generation" or "observation_count"?(int)session.Number(field):field=="duration_seconds"?session[field] is null?null:session.Number(field):session.Text(field);
                        var parameter=PostgresVpnStore.Parameter(value);if(field=="duration_seconds") {parameter.NpgsqlDbType=NpgsqlTypes.NpgsqlDbType.Bigint;parameter.Value=value??DBNull.Value;}insert.Parameters.Add(parameter);
                    }
                    insert.Parameters.AddWithValue("sli.radius-session-read-model.v1");await insert.ExecuteNonQueryAsync(ct);
                }
                count=folded.Count;
            }
            if(prior is null) await Execute(db,RadiusConsumerSql.Receipt,ct,id,Guid.Parse(delivery.Text("observation_id")),outcome,count,"sli.radius-session-consumer.v1");
            if(await Execute(db,RadiusConsumerSql.Delivered,ct,id,token)!=1) throw new VpnInputException("delivery_lease_lost");
            if(outcomes is not null) outcomes[outcome]=(outcomes[outcome]?.GetValue<int>()??0)+1;
        return consumed;
    }

}
