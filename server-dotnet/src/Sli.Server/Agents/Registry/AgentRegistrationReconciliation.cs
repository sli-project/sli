using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Control;
using Sli.Server.Infrastructure;

namespace Sli.Server.Agents.Registry;

public sealed partial class AgentEnrollmentService
{
    private static bool RecentContact(DateTime? seen,long interval,DateTime now) =>
        seen is {} at && at>=now.AddSeconds(-InstallationSetup.SetupCollectionHealth.ContactBudgetSeconds(interval));

    internal static async Task<int> ReconcileRegistrationsAsync(NpgsqlConnection db,NpgsqlTransaction tx,CancellationToken ct,
        IConfiguration? configuration = null, Action<Guid, string>? onUnbound = null)
    {
        // Registration and startup reconciliation must observe one committed registry.
        await LockRegistrationAsync(db, tx, ct);
        const string eligible="""
            status='active' or status='replaced'
                and not exists(select 1 from sli_agent_removals r where r.agent_id=sli_agents.id)
                and exists(select 1 from sli_agent_certificates c where c.agent_id=sli_agents.id and c.revoked_at is not null)
                and exists(select 1 from sli_agent_audit v where v.target=sli_agents.id::text and v.action='revoke'
                    and (v.actor='system:agent-registration-reconcile' or v.actor like 'enrollment:%'))
                and not exists(select 1 from sli_agent_audit v where v.target=sli_agents.id::text and v.action in ('disable','revoke')
                    and v.actor<>'system:agent-registration-reconcile' and v.actor not like 'enrollment:%')
            """;
        var ids=new List<Guid>();
        await using(var query=new NpgsqlCommand("select id from sli_agents where "+eligible+" order by id",db,tx))
        await using(var rows=await query.ExecuteReaderAsync(ct))
            while(await rows.ReadAsync(ct))ids.Add(rows.GetGuid(0));
        var agents=new List<(Guid Id,Guid Host,string Key,string? Reported,string Source,Version? Version,DateTime? Seen,DateTime Created,bool Conflict,DateTime? Packet,bool Live,bool DotNet,string Status,DateTime ContactAt)>();
        await using(var query=new NpgsqlCommand("""
            select a.id,a.host_id,a.key_fingerprint,a.registration_host_name,
                coalesce(b.source_name,a.registration_host_name,''),
                coalesce(a.rights_probe->>'agent_version',
                    (select version from sli_agent_update_results v where v.agent_id=a.id order by observed_at desc limit 1),
                    (select details->>'agent_version' from sli_agent_audit v where v.target=a.id::text and action='issue' order by id desc limit 1)),
                a.last_seen,a.created_at,a.rights_probe ? 'identity_conflict',
                (select max(t) from (select max(received_at) t from sli_agent_receipts where agent_id=a.id
                    union all select max(received_at) from sli_agent_stream_receipts where agent_id=a.id) p),
                -- Revocation prevents further contact; assess that registration at retirement.
                coalesce(case when a.status='replaced' then
                    (select occurred_at from sli_agent_audit v where v.target=a.id::text and v.action='disable'
                        and v.details->>'reason'='registration_replaced' order by id desc limit 1) end,clock_timestamp()),
                a.collection_policy,a.status,
                coalesce((a.rights_probe->>'runtime_handoff_supported')::boolean,false)
                    or a.rights_probe->>'agent_version' is not null
                    or exists(select 1 from sli_agent_audit v where v.target=a.id::text and v.action='issue' and v.details->>'agent_version' is not null)
            from sli_agents a left join sli_agent_module_bindings b on b.agent_id=a.id and b.module_id='sli.windows.ad-dc'
            where a.id=any(@ids) order by a.id for update of a
            """,db,tx))
        {
            query.Parameters.AddWithValue("ids",ids.ToArray());
            await using var rows=await query.ExecuteReaderAsync(ct);
            while(await rows.ReadAsync(ct))
            {
                var seen=rows.IsDBNull(6)?(DateTime?)null:rows.GetDateTime(6);
                var policy=JsonNode.Parse(rows.GetString(11))!;
                agents.Add((rows.GetGuid(0),rows.GetGuid(1),rows.GetString(2),rows.IsDBNull(3)?null:rows.GetString(3),rows.GetString(4),
                    !rows.IsDBNull(5) && Version.TryParse(rows.GetString(5),out var version)?version:null,
                    seen,rows.GetDateTime(7),rows.GetBoolean(8),rows.IsDBNull(9)?null:rows.GetDateTime(9),
                    RecentContact(seen,policy["interval_seconds"]?.GetValue<long>()??60,rows.GetDateTime(10)),rows.GetBoolean(13),rows.GetString(12),rows.GetDateTime(10)));
            }
        }
        // Keep the same lock order as import, revocation and policy updates.
        foreach(var id in ids) await AgentManagementService.LockImportAsync(db,tx,id,ct);
        var computers=new Dictionary<Guid,(long Server,string Name)>();
        var conflicts=agents.Where(a=>a.Conflict).Select(a=>a.Id).ToHashSet();
        foreach(var agent in agents)
        {
            if(await ResolveDcAsync(db,tx,agent.Source,ct,agent.Id) is not {} dc)continue;
            computers[agent.Id]=(dc.Server,dc.Name);
            if(agent.Reported is {} reported && await ResolveDcAsync(db,tx,reported,ct) is {} claimed && claimed.Server!=dc.Server)
                await Conflict(agent.Id,dc.Name,claimed.Name);
        }
        // A copied host identity or key across DCs is never grounds for replacement.
        foreach(var group in agents.GroupBy(a=>a.Host).Select(g=>g.ToArray()).Concat(agents.GroupBy(a=>a.Key).Select(g=>g.ToArray())))
        {
            var resolved=group.Where(a=>computers.ContainsKey(a.Id)).ToArray();
            foreach(var agent in resolved)
                if(resolved.FirstOrDefault(a=>computers[a.Id].Server!=computers[agent.Id].Server) is var other && other.Id!=Guid.Empty)
                    await Conflict(agent.Id,computers[agent.Id].Name,computers[other.Id].Name);
        }
        int retired=0;
        foreach(var group in agents.Where(a=>computers.ContainsKey(a.Id)).GroupBy(a=>computers[a.Id].Server))
        {
            // A previous security observation also prevents automatic consolidation.
            if(group.Any(a=>conflicts.Contains(a.Id)))continue;
            var ordered=group.OrderByDescending(a=>a.Live).ThenByDescending(a=>a.DotNet)
                .ThenByDescending(a=>a.Version??new Version(0,0,0)).ThenByDescending(a=>a.Packet).ThenByDescending(a=>a.Seen)
                .ThenByDescending(a=>a.Created).ThenBy(a=>a.Id).ToArray();
            var preferred=ordered[0];
            foreach(var old in ordered.Where(a=>a.Status=="replaced"))
            {
                bool recovery=old.Id==preferred.Id && old.Live && !group.Any(a=>a.Status=="active" && a.Created>old.ContactAt);
                await using var update=new NpgsqlCommand("update sli_agents set rights_probe=jsonb_set(rights_probe,'{certificate_reissue_required}',to_jsonb(@recovery::boolean)) where id=@id and (rights_probe->>'certificate_reissue_required')::boolean is distinct from @recovery",db,tx);
                update.Parameters.AddWithValue("id",old.Id); update.Parameters.AddWithValue("recovery",recovery);
                await update.ExecuteNonQueryAsync(ct);
            }
            var active=ordered.Where(a=>a.Status=="active").ToArray();
            if(active.Length==0)continue;
            var current=active[0];
            foreach(var old in active.Skip(1))
            {
                await RetireRegistrationAsync(db,tx,old.Id,current.Id,"system:agent-registration-reconcile",true,ct);
                retired++;
            }
        }
        foreach (var id in ids)
        {
            if (await ReconcileDcSourceAsync(db, tx, id, configuration, ct) is { } reason)
                onUnbound?.Invoke(id, reason);
            await AgentModuleAssignmentService.ReconcilePasswordDomainAsync(db,tx,id,ct);
        }
        await RetireBootstrapDomainAsync(db, tx, ct);
        return retired;

        async Task Conflict(Guid id,string computer,string other)
        {
            conflicts.Add(id);
            await using var update=new NpgsqlCommand("""
                update sli_agents set rights_probe=jsonb_set(rights_probe,'{identity_conflict}',@details::jsonb)
                where id=@id and not rights_probe ? 'identity_conflict'
                """,db,tx);
            update.Parameters.AddWithValue("id",id);
            update.Parameters.AddWithValue("details",new JsonObject { ["computer"]=computer,["other_computer"]=other,["observed_at"]=DateTimeOffset.UtcNow.ToString("O") }.ToJsonString());
            await update.ExecuteNonQueryAsync(ct);
        }
    }
}

public sealed class AgentDcSourceDiagnostics(ILogger<AgentRegistrationReconciliation> logger, TimeProvider? clock = null)
{
    private static readonly TimeSpan DiagnosticInterval = TimeSpan.FromMinutes(10);
    private readonly TimeProvider time = clock ?? TimeProvider.System;
    private readonly Dictionary<Guid, long> lastDiagnostic = new();

    internal void LogUnbound(Guid agent, string reason)
    {
        lock (lastDiagnostic)
        {
            if (lastDiagnostic.TryGetValue(agent, out long previous) && time.GetElapsedTime(previous) < DiagnosticInterval)
                return;
            lastDiagnostic[agent] = time.GetTimestamp();
        }
        logger.LogWarning("agent_dc_source_unbound agent_id={AgentId} reason={Reason}", agent, reason);
    }

    internal void RemoveExpired()
    {
        lock (lastDiagnostic)
        {
            foreach (var id in lastDiagnostic.Where(entry => time.GetElapsedTime(entry.Value) >= DiagnosticInterval).Select(entry => entry.Key).ToArray())
                lastDiagnostic.Remove(id);
        }
    }
}

// Consolidation runs once after startup. Source provisioning also retries after
// startup so later inventory changes can unblock an enrolled controller.
public sealed class AgentRegistrationReconciliation(IServiceScopeFactory scopes, ILogger<AgentRegistrationReconciliation> logger,
    IConfiguration? configuration = null, AgentDcSourceDiagnostics? diagnostics = null) : BackgroundService
{
    internal static readonly EventId ReconciliationCompleted = new(1, nameof(ReconciliationCompleted));

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Action<Guid, string>? logUnbound = diagnostics is null ? null : diagnostics.LogUnbound;
        bool reconciled = false;
        while(!stoppingToken.IsCancellationRequested)
        {
            diagnostics?.RemoveExpired();
            int? reconciledRegistrations = null;
            string failure = "agent_registration_reconciliation_failed";
            try
            {
                await using var scope=scopes.CreateAsyncScope();
                await using var db=await scope.ServiceProvider.GetRequiredService<IPostgresConnectionFactory>().OpenAsync(stoppingToken);
                if (!reconciled)
                {
                    logger.LogInformation("agent_registration_reconciliation_started");
                    await using var tx=await db.BeginTransactionAsync(stoppingToken);
                    int retired=await AgentEnrollmentService.ReconcileRegistrationsAsync(db,tx,stoppingToken,configuration,logUnbound);
                    await tx.CommitAsync(stoppingToken);
                    reconciled = true;
                    reconciledRegistrations = retired;
                }
                else
                {
                    failure = "agent_dc_source_reconciliation_failed";
                    await using var tx = await db.BeginTransactionAsync(stoppingToken);
                    await AgentEnrollmentService.ReconcileDcSourcesAsync(db, tx, configuration, stoppingToken, logUnbound);
                    await tx.CommitAsync(stoppingToken);
                }
                failure = "agent_console_token_cleanup_failed";
                await using var cleanup = new NpgsqlCommand(
                    "delete from sli_agent_console_tokens where expires_at<=statement_timestamp()", db);
                await cleanup.ExecuteNonQueryAsync(stoppingToken);
            }
            catch(OperationCanceledException) when(stoppingToken.IsCancellationRequested) { return; }
            catch { logger.LogWarning("{Failure}", failure); }
            if (reconciledRegistrations is int retiredCount)
                logger.LogInformation(ReconciliationCompleted, "agent_registration_reconciliation_completed retired={Retired}", retiredCount);
            try { await Task.Delay(reconciled ? TimeSpan.FromMinutes(1) : TimeSpan.FromSeconds(10),stoppingToken); }
            catch(OperationCanceledException) when(stoppingToken.IsCancellationRequested) { return; }
        }
    }
}
