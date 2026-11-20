using System.Text.Json.Nodes;

namespace Sli.Server.Vpn;

public sealed partial class RadiusReconciliationControl
{
    internal async Task LockInputsAsync(Scope scope, JsonObject plan, Dictionary<int,bool> markers)
    {
        var expected = plan["baseline"]!.AsObject();
        var current = await ReadScopedBaselineAsync(scope,true);
        // Privilege/cursor drift must stop before reading migration state or executing DDL.
        foreach (string key in BaselineKeys.Except(["attempt_count","overlay_count"]))
            if (!JsonNode.DeepEquals(expected[key],current[key])) throw Error("plan_input_drift");
        if (!Markers(await Query(RadiusReconciliationSql.Markers)).OrderBy(x=>x.Key).SequenceEqual(markers.OrderBy(x=>x.Key))) throw Error("plan_input_drift");
        await ReadOutputCountsAsync(scope,current);
        ValidateLockedBaseline(expected,current);
        var (_,discovery) = await BuildBatchesAsync(scope);
        if (!JsonNode.DeepEquals(discovery,plan["reconciliation"]?["identity_evidence_discovery"])) throw Error("plan_input_drift");
    }
    internal async Task<JsonObject> PostconditionAsync(Guid[] observationIds)
    {
        if (observationIds.Length!=83 || observationIds.Distinct().Count()!=83) throw Error("postcondition_scope_invalid");
        return (await Query(RadiusReconciliationSql.Postcondition,Enumerable.Repeat<object?>(observationIds,7).ToArray())).Single();
    }
    internal static void ValidatePostcondition(JsonObject plan, JsonObject result)
    {
        var expected=plan["reconciliation"]!.AsObject();
        foreach (var (actualKey,expectedKey) in new[] {("attempt_count","terminal_candidate_count"),("projected_attempt_count","projected_count"),
            ("still_unresolved_attempt_count","still_unresolved_count"),("overlay_count","projected_count"),
            ("original_unresolved_observation_count","terminal_candidate_count"),("original_unresolved_receipt_count","terminal_candidate_count")})
            if (Number(result,actualKey)!=Number(expected,expectedKey)) throw Error("postcondition_failed");
        if (Number(result,"projection_row_count")<1) throw Error("postcondition_failed");
    }
    // Append-only writes under the restricted writer role; original evidence and receipts are read only.
    internal async Task WriteBatchAsync(Batch batch)
    {
        await Query("set local role adlog_radius_session_reconciliation_writer");
        foreach (var attempt in batch.Attempts.Cast<JsonObject>())
        {
            Guid id=Guid.Parse(Text(attempt,"observation_id")),uid=Guid.Parse(Text(attempt,"evidence_uid"));
            var originals=await Query("""
                select observation.evidence_uid::text,observation.identity_state,
                  exists(select 1 from radius_session_projection_receipts receipt
                    where receipt.observation_id=observation.observation_id and receipt.outcome='identity_unresolved') as terminal
                from radius_accounting_session_observations observation where observation_id=$1
                """,id);
            if (originals.Count!=1 || Text(originals[0],"evidence_uid")!=uid.ToString("D") || Text(originals[0],"identity_state")!="unresolved" || !Flag(originals[0],"terminal"))
                throw Error("terminal_unresolved_receipt_required");
            if ((await Query("select attempt_key from radius_session_identity_overlays where observation_id=$1",id)).Count!=0)
                throw Error("observation_already_resolved");
            batch.Proposals.TryGetValue(id.ToString("D"),out var proposal);
            if (proposal is not null)
            {
                long entity=long.Parse(Text(proposal,"exact_principal_key")[7..],System.Globalization.CultureInfo.InvariantCulture);
                if (!Flag((await Query("select exists(select 1 from entities_v2 where id=$1) as present",entity)).Single(),"present")) throw Error("exact_entity_not_found");
            }
            await Query("""
                insert into radius_session_reconciliation_attempts(attempt_key,observation_id,evidence_uid,outcome,
                  evidence_corpus_sha256,resolver_contract_id,resolution_input_sha256,writer_contract_id)
                values($1,$2,$3,$4,$5,$6,$7::text,$8)
                """,Text(attempt,"attempt_key"),id,uid,Text(attempt,"outcome"),Text(attempt,"evidence_corpus_sha256"),Resolver,
                proposal is null?null:Text(attempt,"resolution_input_sha256"),"sli.radius-session-reconciliation-writer.v1");
            if (proposal is not null)
                await Query("""
                    insert into radius_session_identity_overlays(observation_id,attempt_key,evidence_uid,session_identity_key,
                      exact_principal_key,resolution_input_sha256,resolver_contract_id) values($1,$2,$3,$4,$5,$6,$7)
                    """,id,Text(attempt,"attempt_key"),uid,Text(proposal,"session_identity_key"),Text(proposal,"exact_principal_key"),Text(proposal,"resolution_input_sha256"),Resolver);
        }
        await Query("reset role");
    }
    internal async Task RebuildAsync(Scope scope, Guid[] projectedIds)
    {
        if (projectedIds.Length==0) return;
        var requests=await Query(RadiusReconciliationSql.ProjectionRequests,scope.Subscription,projectedIds);
        if (requests.Count!=projectedIds.Length) throw Error("delivered_overlay_required");
        await Query("set local role adlog_radius_session_consumer");
        if (!Flag((await Query(RadiusConsumerSql.OverlayReadable+" as readable")).Single(),"readable"))
            throw Error("overlay_read_required");
        foreach (string key in requests.Select(r=>Text(r,"session_identity_key")).Distinct().Order(StringComparer.Ordinal))
        {
            await Query(RadiusConsumerSql.ProjectionLock,key);
            // All delivered observations of the resolved session participate; no arbitrary observation cap.
            string sql=RadiusConsumerSql.ObservationsOverlay.Replace("limit $4","",StringComparison.Ordinal);
            var observations=await Query(sql,scope.Subscription,key,requests.First(r=>Text(r,"session_identity_key")==key)["delivery_id"]!.GetValue<long>());
            var folded=RadiusSessionFold.Fold(observations);
            await Query(RadiusConsumerSql.DeleteProjection,key);
            foreach (var session in folded)
                await Query(RadiusConsumerSql.InsertProjection,Text(session,"session_row_id"),key,Text(session,"exact_principal_key"),
                    (int)Number(session,"generation"),Text(session,"lifecycle_state"),Text(session,"completeness"),session.At("started_at_utc"),
                    session.At("last_observed_at_utc"),session.At("stopped_at_utc"),session["duration_seconds"] is null?null:Number(session,"duration_seconds"),
                    (int)Number(session,"observation_count"),session["anomalies"]!.AsArray().Select(x=>x!.GetValue<string>()).ToArray(),"sli.radius-session-read-model.v1");
        }
        await Query("reset role");
    }
    internal async Task<JsonObject> ApplyBatchesAsync(Scope scope, JsonObject plan, IReadOnlyList<Batch> batches)
    {
        var receipts=new JsonArray();
        foreach (var batch in batches)
        {
            await WriteBatchAsync(batch);
            Guid[] projected=batch.Attempts.Cast<JsonObject>().Where(a=>Text(a,"outcome")=="projected").Select(a=>Guid.Parse(Text(a,"observation_id"))).ToArray();
            await RebuildAsync(scope,projected);
            receipts.Add(new JsonObject { ["attempt_count"]=batch.Attempts.Count,["overlay_count"]=projected.Length,["projected_count"]=projected.Length,["still_unresolved_count"]=batch.Attempts.Count-projected.Length });
            progress?.Invoke($"radius_reconciliation applied_batch={receipts.Count} attempts={batch.Attempts.Count}");
        }
        var ids=batches.SelectMany(b=>b.Attempts.Cast<JsonObject>()).Select(a=>Guid.Parse(Text(a,"observation_id"))).ToArray();
        var postcondition=await PostconditionAsync(ids); ValidatePostcondition(plan,postcondition);
        var reconciliation=(JsonObject)plan["reconciliation"]!.DeepClone();
        reconciliation["batches"]=receipts;
        reconciliation["attempt_count"]=batches.Sum(b=>b.Attempts.Count);
        reconciliation["overlay_count"]=batches.Sum(b=>b.Proposals.Count);
        foreach (string key in new[]{"projection_row_count","original_unresolved_observation_count","original_unresolved_receipt_count"}) reconciliation[key]=postcondition[key]!.DeepClone();
        return new JsonObject { ["status"]="passed",["reconciliation"]=reconciliation,
            ["cursor_revision_before"]=plan["baseline"]!["cursor_revision"]!.DeepClone(),["cursor_revision_after_locked_write"]=plan["baseline"]!["cursor_revision"]!.DeepClone(),
            ["source_contacted"]=false,["production_database_changed"]=true,["queue_or_lease_changed"]=false,["runtime_enabled"]=false,["autostart_enabled"]=false };
    }
    public async Task<JsonObject> ApplyAsync(JsonObject plan, string disposableAcceptance)
    {
        var fresh=await BuildPlanAsync(disposableAcceptance); ValidatePlan(plan,fresh);
        var (scope,baseline,markers)=await ReadBaselineAsync(false);
        await LockInputsAsync(scope,plan,markers);
        var applied=await ApplyMigrationsAsync(markers,baseline);
        var (batches,discovery)=await BuildBatchesAsync(scope);
        if (!JsonNode.DeepEquals(Reconciliation(batches,discovery),plan["reconciliation"]) || AuthorizedBlockers(batches.Select(b=>b.Summary)).Length!=0)
            throw Error("plan_input_drift");
        var result=await ApplyBatchesAsync(scope,plan,batches);
        result["applied_migrations"]=new JsonArray(applied.Select(v=>(JsonNode)JsonValue.Create(v)!).ToArray());
        return result;
    }
}
