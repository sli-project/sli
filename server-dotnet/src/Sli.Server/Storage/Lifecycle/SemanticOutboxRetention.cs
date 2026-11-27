using System.Data;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using static Sli.Server.Storage.Lifecycle.LifecyclePostgres;

namespace Sli.Server.Storage.Lifecycle;

internal sealed class SemanticOutboxRetention(NpgsqlDataSource maintenance, LifecycleFiles files, string mode, Action<bool>? waiting = null)
{
    internal Task<JsonObject> RunAsync(DateTime cutoff, Guid after, int limit, CancellationToken ct) =>
        RetryDeadlock(() => RunBatchAsync(cutoff, after, limit, ct), ct);

    async Task<JsonObject> RunBatchAsync(DateTime cutoff, Guid after, int limit, CancellationToken ct)
    {
        if (cutoff.Kind != DateTimeKind.Utc || limit is < 1 or > 1000) throw new ArgumentException("outbox_retention_batch_invalid");
        if (mode is not (SemanticRuntimeSettings.FactsMode or SemanticRuntimeSettings.InvestigationMode or SemanticRuntimeSettings.FindingsMode))
            throw new ArgumentException("outbox_retention_mode_invalid");
        var result = new JsonObject { ["status"] = "blocked", ["schema_ready"] = false,
            ["cutoff_utc"] = LifecycleJson.Iso(cutoff), ["selected_count"] = 0L, ["deleted_count"] = 0L,
            ["held_count"] = 0L, ["held_reasons"] = new JsonObject(), ["last_scanned_job_id"] = after.ToString(),
            ["physical_reclaim_performed"] = false };
        var audit = files.StartPurge("semantic_outbox"); bool pending = false;
        await using var db = await maintenance.OpenConnectionAsync(ct);
        await using var tx = await db.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct);
        try {
            // Stay closed until the deletion and coverage capabilities are installed.
            var ready = await Rows(db, tx, """
                select bool_and(coalesce(has_table_privilege(current_user,to_regclass(relation),privilege),false)) as ready
                from (values ('public.semantic_processing_outbox','SELECT'),('public.semantic_processing_outbox','UPDATE'),
                  ('public.semantic_processing_outbox','DELETE'),('public.semantic_producer_coverage','SELECT'),
                  ('public.semantic_producer_coverage','INSERT'),('public.semantic_producer_coverage','UPDATE'),
                  ('public.entity_identity_semantic_replays_v2','SELECT')) required(relation,privilege)
                """, ct);
            if (ready[0]["ready"]?.GetValue<bool>() != true) {
                result["reason"] = "outbox_retention_schema_not_ready";
                result["message"] = "Очистка завершённых заданий ожидает обновления прав схемы хранения.";
                await tx.RollbackAsync(ct); result["transaction"] = "rolled_back";
                files.PurgeReceipt(audit, result); return result;
            }
            result["schema_ready"] = true;
            // Discovery may scan an old UUID range. Only recheck this page under
            // the writer fence, so an empty or sparse range cannot stall enqueue.
            var candidates = await Rows(db, tx, """
                select job_id from public.semantic_processing_outbox
                where status='completed' and job_id>@after and greatest(created_at,updated_at,completed_at)<@cutoff
                order by job_id limit @limit
                """, ct, ("after", after), ("cutoff", cutoff), ("limit", limit));
            if (candidates.Count == 0) {
                result["status"] = "complete"; result["transaction"] = "committed";
                await tx.CommitAsync(ct); files.PurgeReceipt(audit, result); return result;
            }
            var candidateIds = candidates.Select(row => Guid.Parse(LifecycleJson.Text(row,"job_id"))).ToArray();
            result["last_scanned_job_id"] = candidateIds[^1].ToString();
            await Execute(db, tx, "set local statement_timeout=0; set local lock_timeout=0", ct);
            waiting?.Invoke(true);
            try {
                // Freeze leases, repairs and new references while taking a fresh classification snapshot.
                await Execute(db, tx, "lock table public.semantic_processing_outbox,public.semantic_producer_coverage in share row exclusive mode", ct);
            } finally { waiting?.Invoke(false); }
            var dependencies = await Rows(db, tx, "select conrelid::regclass::text as relation,confdeltype::text as action from pg_constraint where contype='f' and confrelid='public.semantic_processing_outbox'::regclass", ct);
            if (dependencies.Any(d => LifecycleJson.Text(d,"relation") is not ("entity_identity_semantic_replays_v2" or "public.entity_identity_semantic_replays_v2") || LifecycleJson.Text(d,"action") is not ("a" or "r")))
                throw new LifecycleBlocked("unknown_outbox_dependency");
            var rows = await Rows(db, tx, """
                with jobs as materialized (
                  select job_id,source_event_id from public.semantic_processing_outbox
                  where job_id=any(@ids) and status='completed' and greatest(created_at,updated_at,completed_at)<@cutoff
                )
                select j.job_id,case
                  when exists(select 1 from public.entity_identity_semantic_replays_v2 r where r.replay_job_id=j.job_id) then 'evidence_reference'
                  when exists(select 1 from public.semantic_processing_outbox r where r.source_event_id=j.source_event_id
                    and r.payload_json->>'original_job_id'=j.job_id::text) then 'repair_reference'
                  else 'eligible' end as classification
                from jobs j order by j.job_id
                """, ct, ("ids", candidateIds), ("cutoff", cutoff));
            result["selected_count"] = (long)rows.Count;
            var ids = rows.Where(r => LifecycleJson.Text(r,"classification") == "eligible").Select(r => Guid.Parse(LifecycleJson.Text(r,"job_id"))).ToArray();
            foreach (var held in rows.Where(r => LifecycleJson.Text(r,"classification") != "eligible").GroupBy(r => LifecycleJson.Text(r,"classification")))
                result["held_reasons"]![held.Key] = held.LongCount();
            result["held_count"] = (long)(rows.Count - ids.Length);
            // Record completed source event ids (not UUID job ids) before their
            // only success receipt disappears. Preserve version and existing
            // mode coverage; never turn quarantine into a success receipt.
            await Execute(db, tx, """
                insert into public.semantic_producer_coverage(runtime_mode,processor_version,decided_ids)
                select @mode,processor_version,range_agg(int8range(source_event_id,source_event_id,'[]'))
                from public.semantic_processing_outbox where job_id=any(@ids) and status='completed' group by processor_version
                on conflict(runtime_mode,processor_version) do update
                  set decided_ids=semantic_producer_coverage.decided_ids+excluded.decided_ids
                """, ct, ("mode", mode), ("ids", ids));
            // A scalar containment join filter can retain a detoasted copy of
            // coverage for every job. Compare the whole batch once per version.
            if ((await Rows(db, tx, """
                with required as materialized (
                  select processor_version,range_agg(int8range(source_event_id,source_event_id,'[]')) as decided_ids
                  from public.semantic_processing_outbox where job_id=any(@ids) and status='completed'
                  group by processor_version
                )
                select r.processor_version from required r
                where not exists(select 1 from public.semantic_producer_coverage p where p.runtime_mode=@mode
                  and p.processor_version=r.processor_version and p.decided_ids @> r.decided_ids)
                """, ct, ("ids", ids), ("mode", mode))).Count > 0) throw new LifecycleBlocked("outbox_retention_coverage_unconfirmed");
            var deleted = await Rows(db, tx, "delete from public.semantic_processing_outbox where job_id=any(@ids) returning job_id", ct, ("ids", ids));
            if (!deleted.Select(r => Guid.Parse(LifecycleJson.Text(r,"job_id"))).Order().SequenceEqual(ids.Order()))
                throw new LifecycleBlocked("outbox_retention_delete_mismatch");
            if ((await Rows(db, tx, "select job_id from public.semantic_processing_outbox where job_id=any(@ids)", ct, ("ids", ids))).Count != 0)
                throw new LifecycleBlocked("outbox_retention_readback_mismatch");
            result["deleted_count"] = (long)deleted.Count;
            result["status"] = "verified_pending_commit"; files.PurgeReceipt(audit, result);
            pending = true; await tx.CommitAsync(ct); pending = false;
            result["status"] = candidates.Count == limit ? "partial" : "complete"; result["transaction"] = "committed";
        } catch (Exception error) {
            try { await tx.RollbackAsync(CancellationToken.None); } catch { }
            result["status"] = "blocked"; result["reason"] = LifecycleJson.Failure(error);
            result["transaction"] = pending ? "commit_unconfirmed" : "rolled_back"; result["deleted_count"] = 0L;
            files.PurgeReceipt(audit, result); throw;
        }
        files.PurgeReceipt(audit, result); return result;
    }
}
