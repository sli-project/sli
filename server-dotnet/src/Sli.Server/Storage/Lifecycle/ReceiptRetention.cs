using System.Data;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using static Sli.Server.Storage.Lifecycle.LifecyclePostgres;

namespace Sli.Server.Storage.Lifecycle;

internal sealed class ReceiptRetention(NpgsqlDataSource maintenance, LifecycleFiles files, Action<bool>? waiting = null)
{
    internal Task<JsonObject> RunAsync(DateTime cutoff, Guid after, int limit, CancellationToken ct) =>
        RetryDeadlock(() => RunBatchAsync(cutoff, after, limit, ct), ct);

    async Task<JsonObject> RunBatchAsync(DateTime cutoff, Guid after, int limit, CancellationToken ct)
    {
        if (cutoff.Kind != DateTimeKind.Utc || limit is < 1 or > 1000) throw new ArgumentException("receipt_retention_batch_invalid");
        var result = new JsonObject { ["status"] = "blocked", ["schema_ready"] = false,
            ["selected_count"] = 0L, ["deleted_count"] = 0L, ["held_count"] = 0L, ["held_reasons"] = new JsonObject(),
            ["last_scanned_packet_id"] = after.ToString(), ["physical_reclaim_performed"] = false };
        var audit = files.StartPurge("agent_receipts"); bool pending = false;
        await using var db = await maintenance.OpenConnectionAsync(ct);
        await using var tx = await db.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct);
        try {
            var ready = await Rows(db, tx, """
                select exists(select 1 from pg_attribute where attrelid='public.sli_agents'::regclass
                  and attname='receipt_summary' and atttypid='jsonb'::regtype and not attisdropped
                  and has_column_privilege(current_user,attrelid,attnum,'SELECT')
                  and has_column_privilege(current_user,attrelid,attnum,'UPDATE'))
                  and has_table_privilege(current_user,'public.sli_agent_receipts','DELETE')
                  and has_column_privilege(current_user,'public.sli_agent_snapshot_chunks','packet_id','SELECT') as ready
                """, ct);
            if (ready[0]["ready"]?.GetValue<bool>() != true) {
                result["reason"] = "receipt_retention_schema_not_ready";
                result["message"] = "Свёртка квитанций ожидает обновления схемы хранения.";
                await tx.RollbackAsync(ct); result["transaction"] = "rolled_back";
                files.PurgeReceipt(audit, result); return result;
            }
            result["schema_ready"] = true;
            await Execute(db, tx, "set local statement_timeout=0; set local lock_timeout=0", ct);
            // Ingress locks the agent before writing its receipts. Take the same
            // order, then reclassify after locking receipts.
            var page = await Rows(db, tx, "select packet_id,agent_id from public.sli_agent_receipts where packet_id>@after order by packet_id limit @limit", ct,
                ("after", after), ("limit", limit));
            Guid[] ids = page.Select(r => Guid.Parse(LifecycleJson.Text(r,"packet_id"))).ToArray();
            Guid[] agents = page.Select(r => Guid.Parse(LifecycleJson.Text(r,"agent_id"))).Distinct().Order().ToArray();
            await LockedRows(db, tx, "select id from public.sli_agents where id=any(@agents) order by id for no key update", waiting, ct, ("agents", agents));
            // Keep pending inbox references visible before compacting their receipt.
            await LockedRows(db, tx, "lock table public.sli_agent_packet_inbox in share mode", waiting, ct);
            await LockedRows(db, tx, "lock table public.sli_agent_receipts in share row exclusive mode", waiting, ct);
            // Never cascade an unknown dependency into evidence loss.
            var dependencies = await Rows(db, tx, "select conrelid::regclass::text as relation,confdeltype::text as action from pg_constraint where contype='f' and confrelid='public.sli_agent_receipts'::regclass", ct);
            if (dependencies.Any(d => LifecycleJson.Text(d,"relation").Split('.').Last().Trim('"') is not
                ("sli_agent_packet_inbox" or "sli_agent_snapshot_chunks" or "payload_expirations") || LifecycleJson.Text(d,"action") is not ("a" or "r")))
                throw new LifecycleBlocked("unknown_receipt_dependency");
            var rows = await Rows(db, tx, """
                select r.*,greatest(coalesce((select sequence from public.sli_agent_receipts p
                    where p.agent_id=r.agent_id and p.module_id=r.module_id and p.sequence<r.sequence order by sequence desc limit 1),0),
                  coalesce((select max(least((span->>1)::bigint,r.sequence-1)) from public.sli_agents a,
                    lateral jsonb_array_elements(coalesce(a.receipt_summary->r.module_id->'ranges','[]'::jsonb)) span
                    where a.id=r.agent_id and (span->>0)::bigint<r.sequence),0)) as previous_sequence,case
                  when r.received_at>=@cutoff then 'within_seven_days'
                  when exists(select 1 from public.sli_agent_packet_inbox i where i.packet_id=r.packet_id) then 'inbox_present'
                  when exists(select 1 from public.sli_agent_snapshot_chunks s where s.packet_id=r.packet_id) then 'snapshot_reference'
                  when exists(select 1 from sli_plugin_file_audit.payload_expirations x where x.packet_id=r.packet_id) then 'file_payload_reference'
                  else 'eligible' end as classification
                from public.sli_agent_receipts r where packet_id=any(@ids) order by packet_id
                """, ct, ("ids", ids), ("cutoff", cutoff));
            result["selected_count"] = (long)rows.Count;
            result["last_scanned_packet_id"] = page.Count == 0 ? after.ToString() : LifecycleJson.Text(page[^1],"packet_id");
            foreach (var row in rows.Where(r => LifecycleJson.Text(r,"classification") == "eligible")) {
                var envelope = row["envelope"]!.AsObject();
                if (row["receipt"]?["status"]?.ToString() != "committed" || envelope["agent_id"]?.ToString() != LifecycleJson.Text(row,"agent_id")
                    || envelope["module_id"]?.ToString() != LifecycleJson.Text(row,"module_id")
                    || envelope["packet_id"]?.ToString() != LifecycleJson.Text(row,"packet_id")
                    || envelope["sequence"]?.ToString() != LifecycleJson.Text(row,"sequence")
                    || Packets.Digest(envelope) != LifecycleJson.Text(row,"envelope_sha256")) row["classification"] = "receipt_unconfirmed";
            }
            foreach (var held in rows.Where(r => LifecycleJson.Text(r,"classification") != "eligible").GroupBy(r => LifecycleJson.Text(r,"classification")))
                result["held_reasons"]![held.Key] = held.LongCount();
            var eligible = rows.Where(r => LifecycleJson.Text(r,"classification") == "eligible").ToArray();
            result["held_count"] = (long)(rows.Count-eligible.Length);
            foreach (var group in eligible.GroupBy(r => (Agent: Guid.Parse(LifecycleJson.Text(r,"agent_id")), Module: LifecycleJson.Text(r,"module_id")))) {
                var prior = await Rows(db, tx, "select receipt_summary->@module as summary from public.sli_agents where id=@agent", ct,
                    ("agent", group.Key.Agent), ("module", group.Key.Module));
                var summary = AgentReceiptSummary.Merge(prior[0]["summary"] as JsonObject, group);
                await using var update = new NpgsqlCommand("update public.sli_agents set receipt_summary=jsonb_set(receipt_summary,array[@module],@summary) where id=@agent returning receipt_summary->@module", db, tx) { CommandTimeout = 0 };
                update.Parameters.AddWithValue("agent", group.Key.Agent); update.Parameters.AddWithValue("module", group.Key.Module);
                update.Parameters.AddWithValue("summary", NpgsqlDbType.Jsonb, summary.ToJsonString());
                var saved = await update.ExecuteScalarAsync(ct);
                if (saved is not string text || !JsonNode.DeepEquals(summary, JsonNode.Parse(text))) throw new LifecycleBlocked("receipt_summary_readback_mismatch");
            }
            Guid[] removed = eligible.Select(r => Guid.Parse(LifecycleJson.Text(r,"packet_id"))).ToArray();
            var deleted = await Rows(db, tx, "delete from public.sli_agent_receipts where packet_id=any(@ids) returning packet_id", ct, ("ids", removed));
            if (!deleted.Select(r => Guid.Parse(LifecycleJson.Text(r,"packet_id"))).Order().SequenceEqual(removed.Order()))
                throw new LifecycleBlocked("receipt_retention_delete_mismatch");
            if ((await Rows(db, tx, "select packet_id from public.sli_agent_receipts where packet_id=any(@ids)", ct, ("ids", removed))).Count != 0)
                throw new LifecycleBlocked("receipt_retention_readback_mismatch");
            result["deleted_count"] = (long)deleted.Count;
            result["status"] = "verified_pending_commit"; files.PurgeReceipt(audit, result);
            pending = true; await tx.CommitAsync(ct); pending = false;
            result["status"] = page.Count == limit ? "partial" : "complete"; result["transaction"] = "committed";
        } catch (Exception error) {
            try { await tx.RollbackAsync(CancellationToken.None); } catch { }
            result["status"] = "blocked"; result["reason"] = LifecycleJson.Failure(error);
            result["transaction"] = pending ? "commit_unconfirmed" : "rolled_back"; result["deleted_count"] = 0L;
            files.PurgeReceipt(audit, result); throw;
        }
        files.PurgeReceipt(audit, result); return result;
    }
}
