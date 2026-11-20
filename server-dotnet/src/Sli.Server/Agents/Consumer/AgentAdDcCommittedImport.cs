using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Control;
using Sli.Server.Sources;
using Sli.Server.Storage.Direct;

namespace Sli.Server.Agents.Consumer;

public sealed partial class AgentWorkstationInboxConsumer
{
    private static async Task<AgentInboxStep> ProcessAdDcCommittedAsync(NpgsqlConnection db,NpgsqlTransaction claim,
        Inbox row,DirectAdDcRuntime direct,CancellationToken ct,Action<AdDcProjectionStep>? progress)
    {
        // The host retains its separate process/session lock. Do not leave an
        // inbox transaction open while waiting for the OS import queue.
        await claim.CommitAsync(ct);
        Guid agent=Guid.Empty;
        bool locked=false,lockAttempted=false,pluginLockAttempted=false,success=false,quarantined=false;
        string? reason=null,diagnostic=null;
        var clock=Stopwatch.StartNew(); var timings=new JsonObject(); double last=0;
        var step=AdDcProjectionStep.ImportQueueWait;
        void Report(AdDcProjectionStep next) {
            double now=clock.Elapsed.TotalMilliseconds;
            timings[step.ToString()]=(timings[step.ToString()]?.GetValue<double>() ?? 0)+now-last;
            step=next;last=now;
            progress?.Invoke(next);
        }
        try {
            agent=Guid.Parse(Text(row.Envelope["agent_id"]));
            using var queue=await new PostgresImportQueue().AcquireAsync(Text(row.Packet["header"]?["source"]),ct);
            using var admission=AgentAssignmentPluginAdmission.Enter("sli.ad",
                Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"),Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR"));
            DirectAdDcBatch? batch;
            await using(var tx=await db.BeginTransactionAsync(ct)) {
                // Recheck after releasing the claim. A concurrent owner may have
                // imported or quarantined this packet while the queue was busy.
                await using(var pending=new NpgsqlCommand("""
                    select imported_at is null and module_disabled_at is null and not exists(select 1 from sli_agent_packet_quarantine q where q.packet_id=i.packet_id)
                    from sli_agent_packet_inbox i where packet_id=@packet for update
                    """,db,tx)) {
                    pending.Parameters.AddWithValue("packet",row.PacketId);
                    if(await pending.ExecuteScalarAsync(ct) is not true) {
                        await tx.CommitAsync(ct);
                        return new(true,false,"agent_packet_already_processed",row.Received,row.PacketId) { TransactionCompleted=true };
                    }
                }
                Report(AdDcProjectionStep.AgentAssignment);
                // Same ordering as revoke, replacement and assignment: agent row,
                // then advisory lock. Never take the agent row again after this
                // transaction: a revoker may own it while waiting for our session.
                await using(var agentRow=new NpgsqlCommand("select id from sli_agents where id=@id for key share",db,tx)) {
                    agentRow.Parameters.AddWithValue("id",agent);
                    if(await agentRow.ExecuteScalarAsync(ct) is null)throw new InvalidOperationException("agent_disabled");
                }
                lockAttempted=true;
                await AgentManagementService.LockImportAsync(db,tx,agent,ct,session:true);locked=true;
                batch=await DirectAdDcPacket.PrepareImportAsync(db,tx,direct.Worker,row.PacketId,row.Envelope,row.Packet,row.Rows,direct.CatalogPath,ct,Report);
                // Preserve the existing plugin fence across the transaction gap.
                pluginLockAttempted=true;
                await using(var pluginLock=new NpgsqlCommand("select pg_advisory_lock(hashtext('ad_log_reports_plugin_runtime_v76'))",db,tx))
                    await pluginLock.ExecuteNonQueryAsync(ct);
                await tx.CommitAsync(ct);
            }
            // All agent admission/attestation checks completed. The advisory lock
            // serializes revocation until hot commit and the durable inbox marker.
            // AD/DC never requests archival publication; no archive is a prerequisite.
            if(batch is not null)await batch.WriteAsync(ct);
            await using(var tx=await db.BeginTransactionAsync(ct)) {
                // No row lock here: a revoker can hold it while waiting for our
                // advisory lock. Its status change cannot commit before we finish.
                if(!await DirectAdDcPacket.AgentImportableAsync(db,tx,agent,row.PacketId,ct))throw new InvalidOperationException("agent_disabled");
                
                if (batch?.PacketId is null) {
                    await using var mark=new NpgsqlCommand("update sli_agent_packet_inbox set imported_at=clock_timestamp() where packet_id=@packet and imported_at is null",db,tx);
                    mark.Parameters.AddWithValue("packet",row.PacketId);
                    if(await mark.ExecuteNonQueryAsync(ct)!=1)throw new InvalidOperationException("agent_inbox_marker_conflict");
                }
                if(batch is not null)await batch.FinalizeAsync(db,tx,ct);
                await tx.CommitAsync(ct);
            }
            success=true;
        }
        catch(OperationCanceledException) when(ct.IsCancellationRequested) { throw; }
        catch(DirectSourceConflict error) {
            reason=error.Reason;diagnostic=AdDcProjectionFailure.Describe(error,step);
            await using var tx=await db.BeginTransactionAsync(ct);
            await using var quarantine=new NpgsqlCommand("insert into sli_agent_packet_quarantine(packet_id,reason_code,event_ordinal) values(@packet,@reason,@ordinal) on conflict(packet_id) do nothing",db,tx);
            quarantine.Parameters.AddWithValue("packet",row.PacketId);quarantine.Parameters.AddWithValue("reason",error.Reason);quarantine.Parameters.AddWithValue("ordinal",error.Ordinal);
            await quarantine.ExecuteNonQueryAsync(ct);await tx.CommitAsync(ct);quarantined=true;
        }
        catch(Exception error) {
            reason=error is InvalidOperationException && error.Message is "agent_storage_unavailable" or "agent_disabled" or "agent_module_not_assigned" or "agent_packet_attestation_invalid" or "agent_plugin_disabled" or "agent_ad_dc_source_not_bound" or "agent_ad_dc_source_not_configured" or "agent_ad_dc_channel_not_configured"
                ? error.Message : "agent_ad_dc_projection_failed";
            diagnostic=AdDcProjectionFailure.Describe(error,step);
            if(AdDcProjectionFailure.IsPermanent(error)) {
                reason=error.Message;
                await using var tx=await db.BeginTransactionAsync(ct);
                await using var quarantine=new NpgsqlCommand("insert into sli_agent_packet_quarantine(packet_id,reason_code,event_ordinal) values(@packet,@reason,0) on conflict(packet_id) do nothing",db,tx);
                quarantine.Parameters.AddWithValue("packet",row.PacketId);quarantine.Parameters.AddWithValue("reason",reason);
                await quarantine.ExecuteNonQueryAsync(ct);await tx.CommitAsync(ct);quarantined=true;
            }
        }
        finally {
            // Cancellation can arrive after PostgreSQL grants a session lock.
            // Try the unlock even if its acquisition did not return successfully.
            try {
                if(pluginLockAttempted) {
                    await using var pluginLock=new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_plugin_runtime_v76'))",db) { CommandTimeout=0 };
                    await pluginLock.ExecuteScalarAsync(CancellationToken.None);
                }
            } finally {
                if(lockAttempted)await AgentManagementService.UnlockImportAsync(db,agent,locked);
            }
            Report(step);
            Console.WriteLine(new JsonObject { ["component"]="agent_ad_dc_import",["imported"]=success,
                ["elapsed_ms"]=clock.Elapsed.TotalMilliseconds,["steps_ms"]=timings }.ToJsonString());
        }
        if(diagnostic is not null && !IsConfigurationPending(reason))WriteDiagnostic(diagnostic,ct);
        return new(true,success,reason,row.Received,row.PacketId,quarantined) {
            AgentId=agent.ToString("D"),ModuleId=Text(row.Envelope["module_id"]),Diagnostic=diagnostic,TransactionCompleted=true
        };
    }
}
