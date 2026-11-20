using Npgsql;
using System.Text.Json.Nodes;
using Sli.Server.Jobs;

namespace Sli.Server.Vpn;

internal static class RadiusObservationCycle
{
    internal const string Subscription = "vpn-radius-session-observations-radius01-v1";

    internal static async Task<JsonObject> RunAsync(NpgsqlConnection db, Func<JsonObject, Task> progress, CancellationToken ct, string subscription = Subscription)
    {
        // Session role is safe here: this connection belongs to one ephemeral login and never pools.
        await RadiusJobs.Execute(db, "set role adlog_radius_session_consumer; set statement_timeout=0; set lock_timeout=0", ct);
        long claimed = 0, processed = 0, cursor = 0;
        Guid lease = Guid.NewGuid(); string holder = $"radius-session-observation:{Environment.ProcessId}";
        var admission = (await RadiusJobs.Rows(db, "select lease_uid,component_id,admission_mode,expires_at_utc from public.acquire_plugin_component_lease_v1($1,'sli.remote-access','radius-session-observation','delivery_claim',$2)", ct, lease, holder)).SingleOrDefault();
        if (admission is null || admission.Text("lease_uid") != lease.ToString("D") || admission.Text("component_id") != "radius-session-observation" || admission.Text("admission_mode") is not ("open" or "drain_only") || admission.At("expires_at_utc") is null)
            throw new VpnInputException("component_lease_result_invalid");
        string outcome = "failed";
        JsonObject State(string status) => new() { ["status"] = status, ["claimed"] = claimed, ["processed"] = processed, ["cursor_delivery_id"] = cursor, ["contains_secret_material"] = false };
        try {
            cursor = Convert.ToInt64(await RadiusJobs.Scalar(db, """
                select coalesce(max(receipt.delivery_id),0) from radius_session_projection_receipts receipt
                join acquisition_delivery_outbox delivery using(delivery_id) where delivery.subscription_id=$1
                """, ct, subscription));
            await RadiusJobs.Execute(db, RadiusConsumerSql.Quarantine, ct, subscription, 5);
            // A snapshot of ready ids defines this cycle. Arrivals during it belong to the next cycle.
            // No maximum batch count: each receipt commits its own durable cursor.
            var ids = await RadiusJobs.Rows(db, """
                select delivery_id from acquisition_delivery_outbox where subscription_id=$1 and attempt_count<5
                  and available_at<=now() and (delivery_state in ('queued','failed') or (delivery_state='leased' and lease_until<=now()))
                order by available_at,created_at,delivery_id
                """, ct, subscription);
            await progress(State("running"));
            foreach (var row in ids) {
                ct.ThrowIfCancellationRequested();
                long id = row.Number("delivery_id"); Guid token = Guid.NewGuid();
                // Commit the claim first, so a crash or rollback retains the attempt and its lease.
                if (await RadiusJobs.Scalar(db, """
                    with candidate as (
                        select delivery_id from acquisition_delivery_outbox where delivery_id=$1 and subscription_id=$2
                          and attempt_count<5 and available_at<=now()
                          and (delivery_state in ('queued','failed') or (delivery_state='leased' and lease_until<=now()))
                        for update skip locked
                    ) update acquisition_delivery_outbox d set delivery_state='leased',attempt_count=d.attempt_count+1,
                        lease_token=$3,lease_until=now()+interval '120 seconds',heartbeat_at=now(),last_error_code=null,updated_at=now()
                    from candidate where d.delivery_id=candidate.delivery_id returning d.delivery_id
                    """, ct, id, subscription, token) is null) continue;
                claimed++; await progress(State("running"));
                try {
                    await using var tx = await db.BeginTransactionAsync(ct);
                    await RadiusJobs.ProcessDeliveryAsync(db, subscription, id, token, null, ct);
                    await tx.CommitAsync(ct);
                }
                catch (Exception) {
                    // ProcessDelivery's transaction has rolled back before recording a retry.
                    await RadiusJobs.Execute(db, """
                        update acquisition_delivery_outbox set delivery_state=case when attempt_count>=5 then 'quarantined' else 'failed' end,
                          available_at=case when attempt_count>=5 then now() else now()+interval '30 seconds' end,
                          lease_token=null,lease_until=null,heartbeat_at=now(),last_error_code='consumer_processing_failed',updated_at=now()
                        where delivery_id=$1 and delivery_state='leased' and lease_token=$2
                        """, CancellationToken.None, id, token);
                    throw;
                }
                processed++; cursor = Math.Max(cursor, id); await progress(State("running"));
            }
            outcome = "completed";
            return State("completed");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { outcome = "cancelled"; throw; }
        finally {
            if (await RadiusJobs.Scalar(db, "select public.release_plugin_component_lease_v1($1,$2,$3)", CancellationToken.None, lease, holder, outcome) is not true)
                throw new VpnInputException("component_lease_release_invalid");
        }
    }
}
