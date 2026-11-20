using Npgsql;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.SnapshotPublication;

public sealed record GpoPublicationResult(bool TransportComplete, string PublicationState, string? PendingReason);

// One cycle per worker transaction; no scheduler or HTTP surface.
public static class GpoSnapshotPublisher
{
    public static async Task<GpoPublicationResult> ProcessAsync(NpgsqlConnection worker,Guid cycleId,CancellationToken ct)
    {
        await using var tx=await worker.BeginTransactionAsync(ct);
        await using(var role=new NpgsqlCommand("select current_user",worker,tx))
            if ((string?)await role.ExecuteScalarAsync(ct)!="adlog_context_worker") throw new InvalidOperationException("agent_snapshot_worker_role_required");
        SnapshotTransport? transport;
        try { transport=await SnapshotTransportReader.ReadAsync(worker,tx,cycleId,ct,Sli.Agent.Core.SnapshotPolicy.Gpo); }
        catch { await tx.RollbackAsync(ct); throw; }
        if(transport is null) { await tx.CommitAsync(ct); return new(false,"pending",null); }
        if(!transport.PublicationPending) { await tx.CommitAsync(ct); return new(true,"published",null); }
        await tx.SaveAsync("gpo_publication",ct);
        try
        {
            using var admission=Sli.Server.Agents.Control.AgentAssignmentPluginAdmission.Enter("sli.gpo",Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"),Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR"));
            var families=SnapshotFamilyDecoder.Decode(transport);
            var bundle=GpoPublicationPreparation.Prepare(transport.DomainSid,transport.Policy,families);
            var run=await GpoGovernanceStore.ImportAsync(worker,tx,bundle,ct);
            await using var update=new NpgsqlCommand("update sli_agent_snapshot_cycles set publication_state='published',gpo_source_run_id=@run,published_at=clock_timestamp() where cycle_id=@cycle",worker,tx);
            update.Parameters.AddWithValue("run",run); update.Parameters.AddWithValue("cycle",cycleId); await update.ExecuteNonQueryAsync(ct);
            await using var historySource = NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(worker.ConnectionString) { CommandTimeout = 0 }.ConnectionString);
            var history = new Sli.Server.Storage.Lifecycle.SnapshotHistory(historySource, Environment.GetEnvironmentVariable, () => historySource);
            await history.PublishAgentGpo(worker, tx, cycleId, ct);
            await tx.ReleaseAsync("gpo_publication",ct); await tx.CommitAsync(ct);
            return new(true,"published",null);
        }
        catch(Exception error) when(error is not OperationCanceledException)
        {
            await tx.RollbackAsync("gpo_publication",ct);
            string code=error is ProtocolException p ? p.Code : "agent_gpo_publication_failed";
            if(code=="agent_gpo_snapshot_superseded")
            {
                await using var update=new NpgsqlCommand("update sli_agent_snapshot_cycles set publication_state='superseded',superseded_reason=@reason,superseded_at=clock_timestamp() where cycle_id=@cycle",worker,tx);
                update.Parameters.AddWithValue("reason",code); update.Parameters.AddWithValue("cycle",cycleId); await update.ExecuteNonQueryAsync(ct);
                await tx.CommitAsync(ct); return new(true,"superseded",code);
            }
            await tx.CommitAsync(ct); return new(true,"pending",code=="agent_gpo_population_incomplete" || code=="agent_gpo_required_families_missing" || code=="agent_gpo_domain_not_bound" ? code : "agent_gpo_publication_failed");
        }
    }
}
