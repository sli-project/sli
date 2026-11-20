using System.Data;
using System.Text.Json.Nodes;
using Npgsql;
using static Sli.Server.Storage.Lifecycle.LifecyclePostgres;

namespace Sli.Server.Storage.Lifecycle;

internal sealed class InboxRetention(NpgsqlDataSource maintenance, LifecycleFiles files, Action<bool>? waiting = null)
{
    internal Task<JsonObject> RunAsync(DateTime cutoff, Guid after, int limit, CancellationToken ct, DateTime? afterReceivedAt = null) =>
        RetryDeadlock(() => RunBatchAsync(cutoff, afterReceivedAt ?? DateTime.SpecifyKind(DateTime.MinValue, DateTimeKind.Utc), after, limit, ct), ct);

    async Task<JsonObject> RunBatchAsync(DateTime cutoff, DateTime afterReceivedAt, Guid after, int limit, CancellationToken ct)
    {
        if (cutoff.Kind != DateTimeKind.Utc || afterReceivedAt.Kind != DateTimeKind.Utc || limit is < 1 or > 1000) throw new ArgumentException("inbox_retention_batch_invalid");
        var result = new JsonObject { ["status"] = "blocked", ["schema_ready"] = false,
            ["selected_count"] = 0L, ["deleted_count"] = 0L, ["payloads_cleared"] = 0L, ["held_count"] = 0L, ["held_reasons"] = new JsonObject(),
            ["last_scanned_packet_id"] = after.ToString(),
            ["last_scanned_received_at"] = LifecycleJson.Iso(afterReceivedAt),
            ["physical_reclaim_performed"] = false, ["tables"] = new JsonObject { ["sli_agent_packet_inbox"] = Table() } };
        var audit = files.StartPurge("agent_inbox");
        await using var db = await maintenance.OpenConnectionAsync(ct);
        await using var tx = await db.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct);
        bool pending = false;
        try {
            // Allocations retain exact event ids after core deletion. Until the
            // narrow read grants are installed, never infer safety from absence.
            var ready = await Rows(db, tx, """
                select has_table_privilege(current_user,'public.storage_v2_event_identity_allocations','SELECT')
                  and has_table_privilege(current_user,'public.sli_agent_packet_quarantine','SELECT') as ready
                """, ct);
            if (ready[0]["ready"]?.GetValue<bool>() != true) {
                result["reason"] = "inbox_retention_schema_not_ready";
                result["message"] = "Очистка пакетов ожидает обновления прав схемы хранения.";
                await tx.RollbackAsync(ct); result["transaction"] = "rolled_back";
                files.PurgeReceipt(audit, result); return result;
            }
            result["schema_ready"] = true;
            // File evidence can be attached without referencing inbox directly.
            // Keep its fences, but never lock agents across the packet batch.
            List<JsonObject> rows;
            waiting?.Invoke(true);
            try {
                await Execute(db, tx, "select public.lock_storage_lifecycle_tables_v319('file_actions'); select public.lock_storage_lifecycle_tables_v319('file')", ct);
                var dependencies = await Rows(db, tx, "select conrelid::regclass::text as relation,confdeltype::text as action from pg_constraint where contype='f' and confrelid='public.sli_agent_packet_inbox'::regclass", ct);
                if (dependencies.Any(d => !DependencyAllowed(LifecycleJson.Text(d, "relation").Split('.').Last().Trim('"'), LifecycleJson.Text(d, "action"))))
                    throw new LifecycleBlocked("unknown_inbox_dependency");
                rows = await Rows(db, tx, ShortPacketSql, ct,
                    ("after_received", afterReceivedAt), ("after", after), ("limit", limit), ("cutoff", cutoff));
            } finally { waiting?.Invoke(false); }
            result["selected_count"] = (long)rows.Count;
            result["last_scanned_packet_id"] = rows.Count == 0 ? after.ToString() : LifecycleJson.Text(rows[^1], "packet_id");
            if (rows.Count > 0) result["last_scanned_received_at"] = rows[^1]["received_at"]!.DeepClone();
            var eligible = rows.Where(r => LifecycleJson.Text(r, "classification") == "eligible").ToArray();
            var payloads = rows.Where(r => LifecycleJson.Text(r, "classification") == "payload_only").ToArray();
            foreach (var group in rows.Where(r => LifecycleJson.Text(r, "classification") is not ("eligible" or "payload_only")).GroupBy(r => LifecycleJson.Text(r, "classification")))
                result["held_reasons"]![group.Key] = group.LongCount();
            result["held_count"] = (long)(rows.Count - eligible.Length - payloads.Length);
            Guid[] clearIds = payloads.Select(r => Guid.Parse(LifecycleJson.Text(r, "packet_id"))).ToArray();
            result["payloads_cleared"] = (long)await Execute(db, tx,
                "update public.sli_agent_packet_inbox set packet=null,event_rows=null where packet_id=any(@ids) and (packet is not null or event_rows is not null)", ct, ("ids", clearIds));
            Guid[] ids = eligible.Select(r => Guid.Parse(LifecycleJson.Text(r, "packet_id"))).ToArray();
            var deleted = await Rows(db, tx, "delete from public.sli_agent_packet_inbox where packet_id=any(@ids) returning packet_id", ct, ("ids", ids));
            if (!deleted.Select(r => Guid.Parse(LifecycleJson.Text(r, "packet_id"))).Order().SequenceEqual(ids.Order()))
                throw new LifecycleBlocked("inbox_retention_delete_mismatch");
            if ((await Rows(db, tx, "select packet_id from public.sli_agent_packet_inbox where packet_id=any(@ids)", ct, ("ids", ids))).Count != 0)
                throw new LifecycleBlocked("inbox_retention_readback_mismatch");
            result["deleted_count"] = (long)deleted.Count;
            result["tables"]!["sli_agent_packet_inbox"]!["selected_count"] = (long)rows.Count;
            result["tables"]!["sli_agent_packet_inbox"]!["deleted_count"] = (long)deleted.Count;
            result["status"] = "verified_pending_commit"; files.PurgeReceipt(audit, result);
            pending = true; await tx.CommitAsync(ct); pending = false;
            result["status"] = rows.Count == limit ? "partial" : "complete"; result["transaction"] = "committed";
        } catch (Exception error) {
            try { await tx.RollbackAsync(CancellationToken.None); } catch { }
            result["status"] = "blocked"; result["reason"] = LifecycleJson.Failure(error);
            result["transaction"] = pending ? "commit_unconfirmed" : "rolled_back";
            result["deleted_count"] = 0L; result["tables"]!["sli_agent_packet_inbox"]!["deleted_count"] = 0L;
            result["payloads_cleared"] = 0L;
            files.PurgeReceipt(audit, result); throw;
        }
        files.PurgeReceipt(audit, result); return result;
    }

    internal static bool DependencyAllowed(string relation, string action) =>
        relation == "sli_agent_stream_receipts" && action == "c" ||
        relation is "sli_agent_packet_quarantine" or "retention_holds" && action is "a" or "r";

    // Imported short events already carry their attested origin and evidence.
    // Do not expand event_rows or resolve legacy allocations on this path.
    internal const string ShortPacketSql = """
        with packets as materialized (
          select i.packet_id,i.received_at,i.imported_at,i.module_disabled_at,i.envelope,i.event_rows
          from public.sli_agent_packet_inbox i
          where (i.received_at,i.packet_id)>(@after_received,@after)
          order by i.received_at,i.packet_id limit @limit for update of i skip locked
        )
        select i.packet_id,i.received_at,case
          when i.imported_at is null and i.module_disabled_at is null and not exists(select 1 from public.sli_agents a
            where a.id::text=i.envelope->>'agent_id' and a.status in ('replaced','disabled')) then 'not_imported'
          when exists(select 1 from public.sli_agent_packet_quarantine q where q.packet_id=i.packet_id) then 'quarantine'
          when exists(select 1 from sli_plugin_file_audit.retention_holds h where h.packet_id=i.packet_id) then 'evidence_reference'
          when i.envelope->>'module_id'='sli.file-audit' and exists(
            select 1 from sli_plugin_file_audit.observations o
            join sli_plugin_file_audit.action_evidence ae on ae.evidence_key=o.evidence_key
            join sli_plugin_file_audit.rule_actions ra on ra.action_id=ae.action_id
            where o.agent_id::text=i.envelope->>'agent_id' and o.source_instance_id=i.envelope->>'source_instance_id'
              and o.generation=i.envelope->>'generation' and exists(
                select 1 from jsonb_array_elements(i.event_rows) r where r->>'record_id'=o.record_id::text)) then 'evidence_reference'
          when not exists(select 1 from public.sli_agent_receipts r where r.packet_id=i.packet_id
            and r.receipt->>'status'='committed' and r.envelope=i.envelope) then 'receipt_unconfirmed'
          when i.envelope->>'module_id'='sli.file-audit' and i.module_disabled_at is null and not exists(
            select 1 from sli_plugin_file_audit.payload_expirations x where x.packet_id=i.packet_id) then 'file_payload_pending'
          when i.received_at<@cutoff and (coalesce(i.imported_at,i.module_disabled_at) is null or coalesce(i.imported_at,i.module_disabled_at)<@cutoff) then 'eligible'
          when i.imported_at is not null then 'payload_only'
          else 'within_seven_days' end as classification
        from packets i order by i.received_at,i.packet_id
        """;

}
