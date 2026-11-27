using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Updates;
using Sli.Server.Hosting;

namespace Sli.Server.Agents.Control;

public sealed partial class AgentManagementService
{
    private static async Task<JsonObject[]> RowsAsync(NpgsqlConnection db, NpgsqlTransaction tx, string sql, CancellationToken ct, params NpgsqlParameter[] parameters)
    {
        await using var command = new NpgsqlCommand("select to_jsonb(r) from (" + sql + ") r", db, tx); command.Parameters.AddRange(parameters);
        var rows = new List<JsonObject>(); await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) rows.Add(AgentControlJson.Row(reader.GetString(0))); return rows.ToArray();
    }

    public async Task<JsonElement> ListAgentsAsync(NpgsqlConnection db, NpgsqlTransaction tx, string? rawId, string actor,
        CancellationToken ct, string? after = null)
    {
        string filter = rawId is not null ? "where id=@id" : """
            where (status='replaced' or not (last_seen is null and created_at <= clock_timestamp()-interval '24 hours'))
            and not exists(select 1 from sli_agent_removals r where r.agent_id=sli_agents.id)
            and (status in ('active','replaced') or not exists(select 1 from sli_agent_audit retired where retired.target=sli_agents.id::text
                and retired.action='disable' and retired.details->>'reason'='registration_replaced'))
            """;
        var parameters = new List<NpgsqlParameter> { new("shipped", ShippedAgentUpdate.Actor) };
        if (rawId is not null) parameters.Add(new NpgsqlParameter("id", AgentControlJson.Id(rawId)));
        if (rawId is null && after is not null)
        {
            parameters.Add(new NpgsqlParameter("after", AgentControlJson.Id(after)));
            filter += """
                 and exists(select 1 from sli_agents cursor_row where cursor_row.id=@after
                    and (sli_agents.created_at<cursor_row.created_at
                        or (sli_agents.created_at=cursor_row.created_at and sli_agents.id>cursor_row.id)))
                """;
        }
        var agents = await RowsAsync(db, tx, """
            select id,host_id,key_fingerprint,status,assigned_modules,last_seen,created_at,instance_name,policy_revision,machine_role,
                applied_policy_revision,rights_probe,collection_policy,applied_collection_state,windows_audit,
                coalesce(rights_probe->>'agent_version',
                    (select version from sli_agent_update_results v where v.agent_id=sli_agents.id order by observed_at desc limit 1),
                    (select details->>'agent_version' from sli_agent_audit v where v.target=sli_agents.id::text and v.action='issue' order by id desc limit 1)) as agent_version,
                case when status='active' then (
                    select jsonb_build_object('status',candidate.state,'version',candidate.version,'reason',candidate.reason)
                    from (
                        select 0 as priority,p.version,
                            case when r.status is null then 'updating' when r.status='updated' and r.version=p.version then 'updated' else 'failed' end as state,
                            case when r.status='updated' and r.version<>p.version then 'agent_update_version_mismatch' else r.reason end as reason
                        from sli_agent_update_policy a join sli_agent_update_packages p on p.sha256=a.package_sha256
                        left join lateral (
                            select r.status,r.version,r.reason from sli_agent_update_results r
                            where r.agent_id=a.agent_id and r.package_sha256=p.sha256
                            order by r.observed_at desc limit 1
                        ) r on true where a.agent_id=sli_agents.id
                        union all
                        select 1,w.version,case when m.state='pending' then 'updating' else m.state end,m.reason
                        from sli_agent_update_wave_members m join sli_agent_update_waves w on w.id=m.wave_id
                        where m.agent_id=sli_agents.id and w.created_by=@shipped
                            and w.package_sha256=(select value from platform_settings where key='agents.shipped_update')
                            and (m.state in ('updated','failed') or (
                                w.status='running' and m.state='pending' and
                                exists(select 1 from platform_settings where key='agents.automatic_update' and value='automatic')))
                            and not exists(select 1 from sli_agent_update_policy a where a.agent_id=m.agent_id)
                    ) candidate order by candidate.priority limit 1
                ) end as "update"
            from sli_agents
            """ + "\n" + filter + "\norder by created_at desc,id limit 101", ct, parameters.ToArray());
        const int pageSize = 100;
        string? nextCursor = agents.Length > pageSize ? agents[pageSize - 1]["id"]!.GetValue<string>() : null;
        if (nextCursor is not null) agents = agents[..pageSize];
        var lastRejections = new Dictionary<Guid, AgentCertificateRejections.Rejection>();
        if (agents.Length > 0 && rejections?.Snapshot() is { Count: > 0 } observed)
        {
            await using var query = new NpgsqlCommand("""
                select a.id,c.fingerprint,a.last_seen from sli_agent_certificates c
                join sli_agents a on a.id=c.agent_id
                where c.fingerprint=any(@fingerprints) and a.id=any(@ids)
                """, db, tx);
            query.Parameters.AddWithValue("fingerprints", observed.Keys.ToArray());
            query.Parameters.AddWithValue("ids", agents.Select(a => Guid.Parse(a["id"]!.GetValue<string>())).ToArray());
            await using var reader = await query.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var id = reader.GetGuid(0);
                var rejection = observed[reader.GetString(1)];
                if (!reader.IsDBNull(2) && reader.GetFieldValue<DateTimeOffset>(2) >= rejection.ObservedAt) continue;
                if (!lastRejections.TryGetValue(id, out var previous) || previous.ObservedAt < rejection.ObservedAt)
                    lastRejections[id] = rejection;
            }
        }
        var names = new Dictionary<Guid, (string? Name, string Source)>();
        if (agents.Length > 0)
        {
            await using var query = new NpgsqlCommand("""
                select a.id,a.assigned_modules,a.registration_host_name,enrolled.host_name as enrolled_name
                from sli_agents a left join lateral (
                    select coalesce(nullif(btrim(v.attributes_json->'attributes'->>'dns_host_name'),''),
                        nullif(btrim(v.attributes_json->'attributes'->>'display_name'),'')) as host_name
                    from sli_agent_audit issued
                    join sli_agent_group_approval_links c on issued.actor='enrollment:'||c.enrollment_token_id::text
                    join sli_agent_group_requests r on r.id=c.request_id
                    join ad_context_entity_versions v on v.id=r.computer_version_id
                    where issued.target=a.id::text and issued.action='issue' order by issued.id desc limit 1
                ) enrolled on true where a.id=any(@ids)
                """, db, tx);
            query.Parameters.AddWithValue("ids", agents.Select(a => Guid.Parse(a["id"]!.GetValue<string>())).ToArray());
            await using var reader = await query.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                string? name = AgentControlJson.HumanName(reader.IsDBNull(3) ? null : reader.GetString(3)); string source = name is null ? "unknown" : "ad_enrollment";
                if (name is null) { name = AgentControlJson.ReportedName(reader.IsDBNull(2) ? null : reader.GetString(2)); if (name is not null) source = "agent_reported"; }
                if (name is null)
                {
                    using var modules = JsonDocument.Parse(reader.GetString(1));
                    var candidates = modules.RootElement.EnumerateArray().Where(m => AgentControlJson.String(AgentControlJson.Get(m, "module_id")) is "sli.windows.ad-dc" or "sli.workstations")
                        .Select(m => AgentControlJson.HumanName(AgentControlJson.String(AgentControlJson.Get(AgentControlJson.Get(m, "config"), "source_name")))).Where(n => n is not null).Distinct().ToArray();
                    if (candidates.Length == 1) { name = candidates[0]; source = "module_config"; }
                }
                names[reader.GetGuid(0)] = (name, source);
            }
        }
        foreach (var agent in agents)
        {
            Guid id = Guid.Parse(agent["id"]!.GetValue<string>()); var name = names.GetValueOrDefault(id, (null, "unknown"));
            if (lastRejections.TryGetValue(id, out var rejection)) agent["certificate_rejection_reason"] = rejection.Reason;
            agent["host_name"] = name.Item1; agent["host_name_source"] = name.Item2;
            var domain = (await RowsAsync(db, tx, """
                select b.password_detection_domain_id as domain_id,d.fqdn as domain_fqdn,b.source_name
                from public.sli_agent_module_bindings b left join public.domains d on d.id=b.password_detection_domain_id
                where b.agent_id=@id and b.module_id='sli.windows.ad-dc'
                """, ct, new NpgsqlParameter("id", id))).FirstOrDefault();
            agent["password_detection_domain"] = new JsonObject { ["status"] = domain?["domain_id"] is not null ? "configured" : "unconfigured", ["domain_id"] = domain?["domain_id"]?.DeepClone(), ["domain_fqdn"] = domain?["domain_fqdn"]?.DeepClone() };
            if(domain?["source_name"]?.GetValue<string>() is {} source &&
                await Registry.AgentEnrollmentService.ResolveDcAsync(db,tx,source,ct,id) is {} dc)
            { agent["host_name"]=dc.Name; agent["server_id"]=dc.Server; }
            var probe = agent["rights_probe"]!.AsObject();
            agent["windows_product_type"] = probe["windows_product_type"]?.DeepClone();
            probe.Remove("windows_product_type");
            agent["eventlog_diagnostics"] = probe["eventlog_diagnostics"]?.DeepClone(); probe.Remove("eventlog_diagnostics");
            agent["certificate_reissue_required"] = probe["certificate_reissue_required"]?.DeepClone();
            agent["delivery_diagnostics"] = probe["delivery_diagnostics"]?.DeepClone(); probe.Remove("delivery_diagnostics");
            var removal = (await RowsAsync(db, tx, "select operation_id,command_id,state,reason,requested_at,reported_at from sli_agent_removals where agent_id=@id", ct, new NpgsqlParameter("id", id))).FirstOrDefault();
            if (removal is not null) removal["connection"] = agent["last_seen"] is null ? "never_seen" : DateTimeOffset.Parse(agent["last_seen"]!.GetValue<string>(), CultureInfo.InvariantCulture) < AgentControlJson.Now().AddMinutes(-5) ? "offline" : "online";
            agent["removal"] = removal;
            var retired = (await RowsAsync(db, tx, "select details->>'reason' as reason from sli_agent_audit where target=@id and action='disable' order by id desc limit 1", ct, new NpgsqlParameter("id", id.ToString()))).FirstOrDefault();
            agent["inventory_hidden_reason"] = removal is not null ? "administrator_removed" : agent["status"]?.GetValue<string>() is "active" or "replaced" ? null : retired?["reason"]?.GetValue<string>() == "registration_replaced" ? "registration_replaced"
                : agent["last_seen"] is null && DateTimeOffset.Parse(agent["created_at"]!.GetValue<string>(), CultureInfo.InvariantCulture) <= AgentControlJson.Now().AddHours(-24) ? "never_seen_expired" : null;
            agent["certificates"] = JsonSerializer.SerializeToNode(await RowsAsync(db, tx, "select serial,not_after,revoked_at from sli_agent_certificates where agent_id=@id order by id desc limit 100", ct, new NpgsqlParameter("id", id)));
            agent["policy_audit"] = JsonSerializer.SerializeToNode(await RowsAsync(db, tx, "select id,action,actor,occurred_at,details from sli_agent_audit where target=@id and action in ('module_assign','policy_update','policy_ack') order by id desc limit 20", ct, new NpgsqlParameter("id", id.ToString())));
        }
        foreach(var agent in agents.Where(a=>a["status"]?.GetValue<string>()=="replaced" && a["server_id"] is not null))
        {
            var current=agents.Where(a=>a["status"]?.GetValue<string>()=="active" && JsonNode.DeepEquals(a["server_id"],agent["server_id"]))
                .OrderByDescending(a=>Version.TryParse(a["agent_version"]?.GetValue<string>(),out var version) ? version : new Version(0,0,0)).FirstOrDefault();
            agent["replaced_by"]=current?["id"]?.DeepClone(); agent["replacement_version"]=current?["agent_version"]?.DeepClone();
        }
        var failed = rawId is null && after is null ? await RowsAsync(db, tx, """
            select distinct on (computer) id::text as id, reported_hostname, occurred_at, reason from (
                select a.id, a.occurred_at, a.details->>'reported_hostname' as reported_hostname,
                    a.details->>'code' as reason,
                    lower(coalesce(a.details->>'reported_hostname', a.details->>'source_address', '')) as computer
                from sli_agent_audit a
                where a.action='issue' and a.actor='enrollment' and a.details->>'outcome'='rejected'
                    and not exists(select 1 from sli_agents registered
                        where registered.created_at >= a.occurred_at
                            and lower(registered.registration_host_name)=lower(a.details->>'reported_hostname'))
                order by a.occurred_at desc, a.id desc limit 100
            ) recent order by computer, occurred_at desc, id desc
            """, ct) : [];
        await audit.AppendAsync(db, tx, "agent_list", actor, "agents", new { }, ct);
        return JsonSerializer.SerializeToElement(new { items = agents, rejected_enrollments = failed, next_cursor = nextCursor });
    }

    public async Task<JsonElement> SetMachineRoleAsync(NpgsqlConnection db, NpgsqlTransaction tx, JsonElement input, string actor, CancellationToken ct)
    {
        Guid id = AgentControlJson.Id(AgentControlJson.Get(input, "agent_id"));
        var role = AgentControlJson.Get(input, "machine_role");
        if (role.ValueKind != JsonValueKind.String || role.GetString() is not ("domain_controller" or "file_server" or "workstation"))
            throw new AgentControlException("invalid_agent_machine_role");
        string machineRole = role.GetString()!;
        await using var update = new NpgsqlCommand("""
            update sli_agents set machine_role=@role where id=@id and status='active' returning id
            """, db, tx);
        update.Parameters.AddWithValue("id", id);
        update.Parameters.AddWithValue("role", machineRole);
        if (await update.ExecuteScalarAsync(ct) is null) throw new AgentControlException("agent_not_found", 404);
        await audit.AppendAsync(db, tx, "module_assign", actor, id.ToString(), new { machine_role = machineRole }, ct);
        return JsonSerializer.SerializeToElement(new { machine_role = machineRole });
    }
}
