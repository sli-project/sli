using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Access;
using Sli.Server.Ad;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Diagnostics;
using Sli.Server.Agents.Ingress;
using Sli.Server.Domains;
using Sli.Server.Infrastructure;
using Sli.Server.Problems;
using Sli.Server.Reporting.V2;

namespace Sli.Server.Workstations;

// AD supplies the fleet. Current bindings and the canonical journal enrich it.
public sealed class WorkstationWorkspaceReader(IPostgresConnectionFactory connections,
    IAccessFactsRepository facts, EventsJournalReader journal, IReportDefinitionRegistry definitions) : IReportV2Reader
{
    internal const string Key = "workstations.overview";
    public string OwnerId => "sli.workstations";
    public bool Handles(string reportKey) => reportKey == Key;

    internal const string Population = AdAgentRegistrySql.Bindings + """
        , registered as materialized (
            select coalesce(a.source_agent_id,a.id)::text as agent_key,a.id::text as transport_agent_id,
                   coalesce(a.source_host_id,a.host_id)::text as source_instance_id,
                   a.status as agent_status,a.last_seen,a.policy_revision,a.applied_policy_revision,
                   a.registration_host_name,assignment.module,b.entity_id,
                   (a.rights_probe->>'windows_product_type'='WinNT') is true as reported_workstation,
                   coalesce(nullif(a.rights_probe->>'agent_version',''),version.version,
                            (select v.details->>'agent_version' from sli_agent_audit v
                             where v.target=a.id::text and v.action='issue' order by v.id desc limit 1)) as agent_version
            from sli_agents a
            left join unique_bindings b on b.agent_id=a.id
            left join lateral (
                select min(m::text)::jsonb as module
                from jsonb_array_elements(a.assigned_modules) m where m->>'module_id'='sli.workstations'
                having count(*)=1
            ) assignment on true
            left join lateral (
                select v.version from sli_agent_update_results v where v.agent_id=a.id and v.status='updated'
                order by v.observed_at desc,v.package_sha256 limit 1
            ) version on true
            where a.status<>'replaced' and coalesce(a.rights_probe->>'windows_product_type','WinNT')='WinNT'
                and not exists(
                select 1 from sli_agents other where other.status<>'replaced' and other.id<>a.id
                    and coalesce(other.source_agent_id,other.id)=coalesce(a.source_agent_id,a.id))
                and not exists(select 1 from sli_agent_removals r where r.agent_id=a.id and r.state='state_cleaned')
        ), agents as materialized (
            select a.*,binding.server_id,binding.domain_id,binding.computer,
                   server.hostname as host_name,server.os_name as operating_system,
                   server.os_version as operating_system_version,server.updated_at as metadata_observed_at,
                   nullif(domain.fqdn,'workstations.invalid') as domain_name,
                   coalesce(binding.computer,a.registration_host_name) as display_name,
                   case when a.module is null then 'unbound'
                        when a.module->'enabled' is distinct from 'true'::jsonb then 'disabled'
                        when binding.server_id is null then 'unbound' else 'enabled' end as collection_state
            from registered a
            left join lateral public.workstation_journal_scope412(a.transport_agent_id::uuid,null,null) binding on true
            left join servers server on server.id=binding.server_id and server.domain_id=binding.domain_id
            left join domains domain on domain.id=binding.domain_id
        ), directory as materialized (
            select 'ws:ad:'||i.ad_computer_id as station_id,i.ad_computer_id as entity_id,i.domain_id,i.ad_snapshot_metadata as metadata
            from sli_plugin_workstations.station_inventory i where i.ad_snapshot_metadata is not null
        ), matched as (
            select i.station_id,min(a.agent_key) as agent_key
            from directory i join agents a on a.entity_id=i.entity_id
            where a.domain_id is null or a.domain_id=i.domain_id
            group by i.station_id having count(*)=1
        ), bound as materialized (
            select i.station_id,i.entity_id,i.domain_id,d.fqdn as domain_name,
                   a.agent_key,a.transport_agent_id,a.source_instance_id,
                   case when lower(a.computer)=lower(i.metadata->>'dns_host_name') then a.server_id end as server_id,
                   a.module,a.agent_version,
                   a.agent_status,a.last_seen,a.policy_revision,a.applied_policy_revision,
                   case when a.collection_state='disabled' then 'disabled'
                        when lower(a.computer)=lower(i.metadata->>'dns_host_name') then 'enabled'
                        else 'unbound' end as collection_state,
                   i.metadata->>'display_name' as display_name,
                   case when lower(a.computer)=lower(i.metadata->>'dns_host_name') then a.host_name
                        else i.metadata->>'dns_host_name' end as host_name,
                   i.metadata->>'operating_system' as operating_system,i.metadata->>'operating_system_version' as operating_system_version,
                   (i.metadata->>'observed_at')::timestamptz as metadata_observed_at,
                   i.metadata->>'last_logon_utc' as last_logon_utc,i.metadata->>'ou_path' as ou_path
            from directory i join domains d on d.id=i.domain_id
            left join matched m using(station_id) left join agents a using(agent_key)
            union all
            select a.agent_key,null,a.domain_id,a.domain_name,
                   a.agent_key,a.transport_agent_id,a.source_instance_id,a.server_id,a.module,a.agent_version,
                   a.agent_status,a.last_seen,a.policy_revision,a.applied_policy_revision,a.collection_state,
                   a.display_name,a.host_name,a.operating_system,a.operating_system_version,a.metadata_observed_at,null,null
            from agents a
            where not exists(select 1 from matched m where m.agent_key=a.agent_key)
                and (a.reported_workstation or a.module is not null and not exists(
                    select 1 from sli_plugin_workstations.ad_inventory_checkpoints436 c
                    where a.domain_id is null or c.domain_id=a.domain_id))
        ), resources as (
            select a.station_id,a.agent_key,'sli.workstations'::text as plugin_id,a.source_instance_id,a.entity_id,
                   case when a.server_id is not null then 'server:'||a.server_id::text end as device_id,
                   case when a.domain_id is not null then 'ad-domain:'||a.domain_id::text end as collection_scope_id,
                   a.ou_path
            from bound a
        )
        """;

    public Task<JsonObject> QueryAsync(ReportQueryContext context, CancellationToken ct) => ReadAsync(context, null, ct);
    public Task<JsonObject> DetailAsync(ReportQueryContext context, string rowId, CancellationToken ct) => ReadAsync(context, rowId, ct);

    private async Task<JsonObject> ReadAsync(ReportQueryContext original, string? rowId, CancellationToken ct)
    {
        var subject = await facts.LoadAsync(original.Principal, ct);
        var access = new ReportEligibility().Compose(subject, new CapabilityComposer().Compose(subject));
        WorkstationPredicate scope;
        try
        {
            WorkstationReportContract.Admit(access, Key);
            scope = WorkstationAgentScope.Build(subject, access, reportKey: Key, workspace: true);
        }
        catch (WorkstationException error) { throw new ReportRequestException(error.Message, error.Status); }
        catch (AgentControlException error) { throw new ReportRequestException(error.Message, error.Status); }
        var c = original with { Access = access };
        Validate(c, rowId);
        if (Id(rowId)) rowId = Guid.Parse(rowId!).ToString("D");
        string? cursor = rowId is null && !string.IsNullOrEmpty(c.Paging.Cursor)
            ? ReportCursor.Decode(c.Paging.Cursor, Binding(c, "stations")) : null;
        if (cursor is not null && !StationId(cursor)) throw new ReportRequestException("invalid_cursor");
        var selected = Selection(c, scope, rowId);
        JsonObject result;
        JsonObject? station = null;
        try
        {
            await using var db = await connections.OpenAsync(ct);
            await using var tx = await db.BeginTransactionAsync(System.Data.IsolationLevel.RepeatableRead, ct);
            await Ws.Exec(db, "set transaction read only; set local statement_timeout='5000ms'; set local jit=off", ct);
            string basis = Population + ", selected as materialized (select a.* from bound a where " + selected.Sql + ") ";
            var total = (await Query(db, basis + "select count(*) as total,count(*) filter(where station_id<=@p0::text) as preceding from selected", selected, ct, cursor)).Single();
            var rows = await Query(db, basis + "select * from selected where @p0::text is null or station_id>@p0 order by station_id limit @p1", selected, ct, cursor, rowId is null ? c.Paging.Limit + 1 : 2);
            if (rowId is not null && rows.Count != 1) throw new ReportRequestException("workstation_not_found", 404);
            bool more = rowId is null && rows.Count > c.Paging.Limit;
            rows = rows.Take(c.Paging.Limit).Select(row => Present(row, access)).ToList();
            string? previous = null;
            if (cursor is not null)
            {
                var before = await Query(db, basis + "select station_id from selected where station_id<=@p0 order by station_id desc limit @p1", selected, ct, cursor, c.Paging.Limit + 1);
                if (before.Count > c.Paging.Limit) previous = ReportCursor.Encode(Binding(c, "stations"), Ws.Text(before[^1], "station_id")!);
            }
            result = ReportResult.Create(Key, rows.Count > 0 ? "ok" : "empty", Ws.Array(rows),
                coverage: new() { ["source"] = "ad_workstation_inventory", ["scope_unresolved"] = scope.UnresolvedScope },
                collections: new() { ["paging"] = new JsonArray(new JsonObject
                {
                    ["start"] = Ws.Number(total, "preceding") + 1,
                    ["has_previous"] = Ws.Number(total, "preceding") > 0, ["previous_cursor"] = previous
                }) });
            result["filtered_count"] = total["total"]!.DeepClone();
            result["has_more"] = more;
            result["next_cursor"] = more ? ReportCursor.Encode(Binding(c, "stations"), Ws.Text(rows[^1], "station_id")!) : null;
            result["window"] = c.Params["period"]!.DeepClone();
            result["window"]!["timezone"] = c.Paging.Timezone;
            result["window"]!["generated_at_utc"] = c.RequestTime.ToString("O", CultureInfo.InvariantCulture);
            if (rowId is null)
            {
                var domains = await Query(db, Population + "select distinct a.domain_id as value,a.domain_name as label from bound a where " + scope.Sql + " and a.domain_id is not null order by a.domain_name,a.domain_id limit 101", scope, ct);
                result["filter_options"]!["domain"] = Ws.Array(domains.Take(100));
            }
            else station = rows.Single();
            await tx.CommitAsync(ct);
        }
        catch (PostgresException error) when (error.SqlState == "57014")
        { return ReportResult.Create(Key, "error", coverage: new() { ["reason"] = "source_timeout", ["source"] = "ad_workstation_inventory" }); }
        catch (PostgresException error) when (error.SqlState is "42883" or "42P01" or "42501")
        { return ReportResult.Create(Key, "error", coverage: new() { ["reason"] = "source_unavailable", ["source"] = "ad_workstation_inventory" }); }
        catch (NpgsqlException)
        { return ReportResult.Create(Key, "error", coverage: new() { ["reason"] = "source_unavailable", ["source"] = "ad_workstation_inventory" }); }
        if (station is null) return result;
        var events = await EventsAsync(c, station, ct);
        result["detail"] = new JsonObject
        {
            ["station"] = station.DeepClone(), ["events"] = events,
            ["related"] = new JsonObject
            {
                ["journal"] = new JsonObject
                {
                    ["allowed"] = station["journal_available"]!.DeepClone(),
                    ["params"] = station["journal_available"]!.GetValue<bool>() ? JournalParameters(c, station, url: true) : null
                },
                // Finding links are emitted only per admitted journal row.
                ["problems"] = new JsonObject { ["allowed"] = CanReadProblems(access, station) }
            }
        };
        return result;
    }

    private static bool Id(string? value) => Guid.TryParseExact(value, "D", out var id) && id != Guid.Empty;
    private static bool StationId(string value) => Id(value) || value.StartsWith("ws:ad:", StringComparison.Ordinal)
        && long.TryParse(value.AsSpan(6), NumberStyles.None, CultureInfo.InvariantCulture, out long id) && id > 0;
    internal static void Validate(ReportQueryContext c, string? rowId)
    {
        if (rowId is not null && !StationId(rowId)) throw new ReportRequestException("workstation_not_found", 404);
        if (c.Params["source_instance_id"] is { } source && !Id(source.ToString()))
            throw new ReportRequestException("report_parameter_invalid:source_instance_id");
        foreach (string key in new[] { "domain", "domain_id" })
            if (c.Params[key] is { } selected && (!long.TryParse(selected.ToString(), NumberStyles.None, CultureInfo.InvariantCulture, out long value) || value <= 0))
                throw new ReportRequestException("report_parameter_invalid:" + key);
        if (c.Params["domain"] is { } domain && c.Params["domain_id"] is { } alias && !JsonNode.DeepEquals(domain, alias))
            throw new ReportRequestException("domain_scope_invalid");
        if (c.Params["event_limit"] is { } limit && (!int.TryParse(limit.ToString(), out int size) || size is < 1 or > 200))
            throw new ReportRequestException("report_limit_invalid");
        if (c.Paging.Limit is < 1 or > 200) throw new ReportRequestException("report_limit_invalid");
    }

    private static WorkstationPredicate Selection(ReportQueryContext c, WorkstationPredicate scope, string? rowId)
    {
        string predicate = scope.Sql;
        var parameters = scope.Parameters.ToList();
        string Add(object value) { string name = "selection" + parameters.Count; parameters.Add(new(name, value)); return "@" + name; }
        if ((c.Params["domain"] ?? c.Params["domain_id"]) is { } selectedDomain)
            predicate += " and a.domain_id=" + Add(long.Parse(selectedDomain.ToString(), CultureInfo.InvariantCulture));
        if (Ws.Text(c.Params, "search") is { Length: > 0 } search)
        {
            string text = Add(search.ToLowerInvariant());
            predicate += " and (strpos(lower(coalesce(a.display_name,'') collate pg_catalog.pg_unicode_fast)," + text
                + ")>0 or strpos(lower(coalesce(a.domain_name,''))," + text + ")>0)";
        }
        if (Ws.Text(c.Params, "source_instance_id") is { Length: > 0 } source) predicate += " and a.source_instance_id=" + Add(Guid.Parse(source).ToString("D"));
        if (Ws.Text(c.Params, "collection") is { Length: > 0 } collection && collection != "all") predicate += " and a.collection_state=" + Add(collection);
        if (rowId is not null)
        {
            string id = Add(rowId);
            predicate += " and (a.station_id=" + id + " or a.agent_key=" + id + ")";
        }
        return new(predicate, parameters) { UnresolvedScope = scope.UnresolvedScope };
    }

    private static async Task<List<JsonObject>> Query(NpgsqlConnection db, string sql, WorkstationPredicate scope, CancellationToken ct, params object?[] args)
    {
        await using var command = Ws.Command(db, "select to_jsonb(workstation_row)::text from (" + sql + ") workstation_row", args);
        foreach (var parameter in scope.Parameters) command.Parameters.Add(new NpgsqlParameter(parameter.ParameterName, parameter.Value));
        return await Ws.Rows(command, ct);
    }

    internal static JsonObject Present(JsonObject row, AccessDecision access)
    {
        var result = Ws.Pick(row, "station_id", "agent_key", "transport_agent_id", "source_instance_id", "display_name", "host_name", "domain_id", "domain_name", "server_id",
            "operating_system", "operating_system_version", "last_logon_utc", "agent_version", "metadata_observed_at",
            "agent_status", "last_seen", "policy_revision", "applied_policy_revision", "collection_state");
        result["profile"] = Profile(row["module"]?["config"] as JsonObject);
        result["journal_available"] = CanReadEvents(access, result);
        return result;
    }

    internal static JsonObject Profile(JsonObject? config)
    {
        var profile = new JsonObject { ["state"] = "unbound", ["event_ids"] = new JsonArray(), ["channels"] = new JsonArray() };
        if (config is null) return profile;
        profile["state"] = "unsupported";
        try
        {
            if (!WorkstationJournalAdmission.SupportsConfig(config)) return profile;
            var policy = WorkstationPolicy.Parse(config);
            bool Allows(JsonNode? filter, int id) => (filter?["allow_event_ids"] is not JsonArray allow || allow.Any(v => v?.ToString() == id.ToString(CultureInfo.InvariantCulture)))
                && (filter?["deny_event_ids"] is not JsonArray deny || !deny.Any(v => v?.ToString() == id.ToString(CultureInfo.InvariantCulture)));
            var ids = WorkstationJournalAdmission.EventIds.Where(id => Allows(config, id) && WorkstationPolicy.FamilyEvents.Any(f => f.Value.Contains(id)
                && policy.FamilyEnabled(f.Key) && Allows(config["family_filters"]?[f.Key], id))).ToArray();
            profile["state"] = "supported";
            profile["event_ids"] = new JsonArray(ids.Select(id => (JsonNode?)JsonValue.Create(id)).ToArray());
            profile["channels"] = new JsonArray(WorkstationPolicy.Channels.Where((_, index) => WorkstationPolicy.ChannelEvents[index].Intersect(ids).Any())
                .Select(channel => (JsonNode?)JsonValue.Create(channel)).ToArray());
        }
        catch (AgentException) { }
        return profile;
    }

    internal static bool CanReadEvents(AccessDecision access, JsonObject station)
    {
        if (Ws.Number(station, "server_id") <= 0 || Ws.Number(station, "domain_id") <= 0 || !Id(Ws.Text(station, "source_instance_id"))) return false;
        // One source channel can be readable even when another is denied.
        return new[] { "Security", "System", "Microsoft-Windows-Windows Defender/Operational" }.Any(channel =>
        {
            IReadOnlyList<IReadOnlyList<AccessResource>> resources = [[new("server", Ws.Number(station, "server_id")), new("domain", Ws.Number(station, "domain_id")), new("channel", Value: channel)]];
            return ResourceAccessDecisions.ReportAction(access, "events.explorer", "view", resources, new HashSet<string> { "security", "technical" }).Allowed
                && new[] { "field.security", "field.technical" }.All(capability => ResourceAccessDecisions.Capability(access.Capabilities, capability, resources).Allowed);
        });
    }

    private static bool CanReadProblems(AccessDecision access, JsonObject station)
    {
        try { return new ProblemAccess(access).Scope("security.queue").Domains() is not { } domains || domains.Contains(Ws.Number(station, "domain_id")); }
        catch (ProblemException) { return false; }
    }

    private static JsonObject JournalParameters(ReportQueryContext c, JsonObject station, bool url = false)
    {
        var parameters = new JsonObject
        {
            ["domain"] = station["domain_id"]!.DeepClone(), ["server"] = station["host_name"]!.DeepClone(),
            ["source_instance_id"] = station["source_instance_id"]!.DeepClone(), ["source_plugin"] = "sli.workstations",
            ["collapse"] = "on", ["view"] = Ws.Text(c.Params, "view") ?? "all"
        };
        if (url)
        {
            parameters["period"] = "custom"; parameters["from"] = c.Params["period"]!["from_utc"]!.DeepClone();
            parameters["to"] = c.Params["period"]!["to_utc"]!.DeepClone(); parameters["tz"] = c.Paging.Timezone;
        }
        else parameters["period"] = c.Params["period"]!.DeepClone();
        return parameters;
    }

    private async Task<JsonObject> EventsAsync(ReportQueryContext c, JsonObject station, CancellationToken ct)
    {
        if (!station["journal_available"]!.GetValue<bool>())
            return ReportResult.Create("events.journal", station["server_id"] is null ? "not_collected" : "denied",
                coverage: new() { ["reason"] = station["server_id"] is null ? "workstation_binding_unavailable" : "report_access_denied" });
        var definition = definitions.Get("events.journal") ?? throw new ReportRequestException("report_reader_unavailable", 503);
        var projection = new ReportAccess(definition, c.Access);
        int limit = c.Params["event_limit"] is null ? 50 : int.Parse(c.Params["event_limit"]!.ToString(), CultureInfo.InvariantCulture);
        var binding = Binding(c, "events", station);
        string? cursor = Ws.Text(c.Params, "event_cursor") is { Length: > 0 } token ? ReportCursor.Decode(token, binding) : null;
        var parameters = JournalParameters(c, station);
        var query = new ReportQueryContext(definition, c.Access, c.Principal, parameters,
            new(cursor, limit, c.Paging.Timezone, null, "desc", null), ReportScope.None, [Ws.Number(station, "domain_id")], "view",
            projection.FieldsAllowed, c.Access.Reports.Single(r => r.ReportKey == "events.explorer").Grants)
        {
            RequestTime = c.RequestTime, Language = c.Language, WorkstationServerId = Ws.Number(station, "server_id")
        };
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            var result = projection.Project(await journal.QueryAsync(query, deadline.Token));
            EventsJournalReader.Localize(result, DomainHttp.SelectEnglish(c.Language));
            if (Ws.Text(result, "next_cursor") is { Length: > 0 } next) result["next_cursor"] = ReportCursor.Encode(binding, next);
            return result;
        }
        catch (ReportRequestException error) when (error.Status == 403)
        { return ReportResult.Create("events.journal", "denied", coverage: new() { ["reason"] = error.Message }); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        { return ReportResult.Create("events.journal", "error", coverage: new() { ["reason"] = "source_timeout" }); }
        catch (PostgresException error) when (error.SqlState == "57014")
        { return ReportResult.Create("events.journal", "error", coverage: new() { ["reason"] = "source_timeout" }); }
        catch (NpgsqlException)
        { return ReportResult.Create("events.journal", "error", coverage: new() { ["reason"] = "source_unavailable" }); }
    }

    internal static JsonObject Binding(ReportQueryContext c, string kind, JsonObject? station = null)
    {
        var selection = new JsonObject();
        foreach (string key in kind == "events" ? new[] { "period", "view", "event_limit" } : new[] { "period", "domain", "domain_id", "search", "source_instance_id", "collection" })
            selection[key] = c.Params[key]?.DeepClone();
        return new JsonObject
        {
            ["report"] = Key, ["kind"] = kind, ["params"] = selection, ["limit"] = kind == "events" ? null : c.Paging.Limit,
            ["station_id"] = station?["station_id"]?.DeepClone(), ["source_instance_id"] = station?["source_instance_id"]?.DeepClone(),
            ["server_id"] = station?["server_id"]?.DeepClone(), ["principal"] = JsonSerializer.SerializeToNode(c.Principal),
            ["policy"] = JsonSerializer.SerializeToNode(c.Access)
        };
    }
}
