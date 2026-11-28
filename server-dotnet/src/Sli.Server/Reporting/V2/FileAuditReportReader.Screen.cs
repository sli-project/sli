using System.Globalization;
using System.Text.Json.Nodes;
using Sli.Server.Agents.FileAudit;
using Sli.Server.Problems;
using Sli.Server.Semantic;

namespace Sli.Server.Reporting.V2;

public sealed partial class FileAuditReportReader
{
    private static async Task<JsonArray> CatalogRootsAsync(ISemanticSession session, JsonArray configured, CancellationToken ct)
    {
        var agents = await session.QueryAsync("""
            select a.id::text as agent_id,c.source_id as source_instance_id,a.registration_host_name as source_name,
                a.policy_revision as audit_policy_revision,a.file_audit as audit, m.config as assigned,c.cached_shares
            from public.sli_file_audit_smb_catalog c join public.sli_agents a
                on a.id=c.agent_id and c.source_id=coalesce(a.source_host_id,a.host_id)::text
            left join lateral (
                select item->'config' as config from jsonb_array_elements(a.assigned_modules) item
                where item->>'module_id'='sli.file-audit' and item->'enabled'='true'::jsonb
                    and coalesce(item#>>'{config,source_kind}','server')='server'
                limit 1
            ) m on true
            where a.status='active' and c.supported_until>clock_timestamp() and c.cached_at is not null
                and jsonb_array_length(c.cached_shares)>0
            order by a.id limit 1001
            """, ct);
        var byAgent = configured.OfType<JsonObject>().ToLookup(row => (Text(row, "agent_id"), Text(row, "source_instance_id")));
        var matched = new HashSet<JsonObject>();
        var roots = new JsonArray();
        foreach (var server in agents.OfType<JsonObject>())
        {
            string agent = Text(server, "agent_id")!, source = Text(server, "source_instance_id")!;
            foreach (var share in Array(server["cached_shares"]).OfType<JsonObject>())
            {
                string name = Text(share, "Name")!, path = Text(share, "Path")!;
                if (FileAuditCatalog.IsAdministrativeShare(name, path)) continue;
                var previous = byAgent[(agent, source)].FirstOrDefault(root =>
                    string.Equals(Text(root, "share_name"), name, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(Text(root, "path"), path, StringComparison.OrdinalIgnoreCase));
                if (previous is not null) matched.Add(previous);
                var root = previous?.Copy() ?? new JsonObject
                {
                    ["agent_id"] = agent, ["source_instance_id"] = source, ["source_kind"] = "server",
                    ["collection_scope_id"] = FileAuditCatalog.ScopeId(source, name, path),
                    ["share_name"] = name, ["path"] = path,
                };
                root["source_name"] = SourceName(previous) ?? Text(server, "source_name");
                var scope = Text(root, "collection_scope_id")!;
                var audit = server["audit"];
                var command = audit?["request"]?["command"];
                bool selected = Array(command?["collection_scope_ids"]).Any(value => value?.ToString() == scope);
                bool assigned = Array(server["assigned"]?["roots"]).Any(value => Text(value, "collection_scope_id") == scope);
                var receipt = audit?["scopes"]?[scope];
                string? status = Text(receipt, "state");
                string? reason = Text(receipt, "reason_code");
                bool changing = selected && Text(command, "action") is "apply" or "restore";
                bool restoring = changing && Text(command, "action") == "restore";
                bool verified = Text(audit, "state") == "verified";
                var retained = audit?["permissions_retained"]?[scope];
                string auditState = "disabled";
                if (changing && !verified)
                {
                    bool error = status is "failed" or "blocked" || status == "partial" &&
                        (reason != "coverage_incomplete" || receipt?["inventory_pending"]?.GetValue<bool>() != true);
                    auditState = error ? "error" : restoring ? "restoring" : "applying";
                }
                else if (assigned && (changing && !restoring && verified || retained is not null))
                    auditState = "enabled";
                root["audit_state"] = auditState;
                root["audit_checked_at"] = (receipt?["observed_at_utc"] ?? retained?["observed_at_utc"] ?? audit?["reported_at"])?.DeepClone();
                root["audit_reason"] = reason;
                root["audit_can_restore"] = assigned || restoring;
                root["audit_policy_revision"] = server["audit_policy_revision"]?.DeepClone();
                root["catalog_configured"] = previous is not null;
                roots.Add(root);
                if (roots.Count == 1001) return roots;
            }
        }
        foreach (var root in configured.OfType<JsonObject>())
        {
            if (matched.Contains(root)) continue;
            roots.Add(root.DeepClone());
            if (roots.Count == 1001) break;
        }
        return roots;
    }

    private static string? SourceName(JsonNode? root) =>
        Text(root, "source_name") is { Length: > 0 } name && !Guid.TryParse(name, out _)
        && name != Text(root, "source_instance_id") ? name[..Math.Min(name.Length, 256)] : null;

    // Accept a configured hostname only when it binds to a single active server.
    private const string DomainRootsSql = """
        select coalesce(jsonb_agg(root),'[]'::jsonb) as roots
        from jsonb_array_elements($1::jsonb) r(root)
        cross join lateral (
            select min(s.domain_id) as domain_id from public.servers s
            where s.is_active and (lower(s.hostname)=lower(root->>'source_name') or lower(s.fqdn)=lower(root->>'source_name'))
            having count(*)=1
        ) server where server.domain_id=$2
        """;

    private static async Task ResourceAuditAsync(ISemanticSession session, ReportQueryContext context, JsonArray rows, CancellationToken ct)
    {
        if (rows.Count == 0) return;
        var receipts = await session.QueryAsync("""
            select root->>'id' as id, accepted.received_at, agent.current_version, agent.check_version,
                   agent.check_revision, agent.check_state, agent.check_receipt
            from jsonb_array_elements($1::jsonb) as r(root)
            left join lateral (
                select receipt.received_at
                from public.sli_agent_receipts receipt
                join public.sli_agent_packet_inbox inbox using(packet_id)
                where receipt.agent_id=(root->>'agent_id')::uuid and receipt.module_id='sli.file-audit'
                  and receipt.envelope->>'source_instance_id'=root->>'source_instance_id'
                  and inbox.imported_at is not null
                  and (exists(select 1 from jsonb_array_elements(inbox.event_rows) as e(observation)
                      where observation->>'collection_scope_id'=root->>'collection_scope_id'
                        and (lower(observation->>'path')=lower(root->>'path')
                            or starts_with(lower(observation->>'path'),rtrim(lower(root->>'path'),chr(92))||chr(92))))
                    or exists(select 1 from public.sli_agents a
                        cross join lateral jsonb_array_elements(a.file_audit#>'{request,config,roots}') c
                        where a.id=receipt.agent_id and a.file_audit#>>'{last_event,packet_id}'=inbox.packet_id::text
                          and a.file_audit#>>'{last_event,collection_scope_id}'=root->>'collection_scope_id'
                          and c->>'collection_scope_id'=root->>'collection_scope_id'
                          and c->>'path'=root->>'path' and c->>'share_name'=root->>'share_name'))
                order by receipt.sequence desc limit 1
            ) accepted on true
            left join lateral (
                select a.rights_probe->>'agent_version' as current_version, scope->>'agent_version' as check_version,
                    case when configured.matches and a.file_audit->'retired_apply' is null
                        and a.file_audit->>'may_own_audit' is distinct from 'true' then a.policy_revision end as check_revision,
                    case when configured.matches and selected.includes then a.file_audit->>'state' end as check_state,
                    case when configured.matches and selected.includes and scope ? 'state' then jsonb_build_object(
                        'state',scope->'state','reason_code',scope->'reason_code',
                        'observed_at',coalesce(scope->'observed_at_utc',a.file_audit->'reported_at')) end as check_receipt
                from public.sli_agents a
                cross join lateral (select a.file_audit->'scopes'->(root->>'collection_scope_id') as scope) s
                cross join lateral (select exists (
                    select 1 from jsonb_array_elements(a.file_audit#>'{request,config,roots}') c
                    where c->>'collection_scope_id'=root->>'collection_scope_id' and c->>'path'=root->>'path'
                        and c->>'share_name'=root->>'share_name') as matches) configured
                cross join lateral (select (a.file_audit#>'{request,command,collection_scope_ids}')
                    ? (root->>'collection_scope_id') as includes) selected
                where a.id=(root->>'agent_id')::uuid and a.status='active'
                  and coalesce(a.source_host_id,a.host_id)::text=root->>'source_instance_id'
                  and a.file_audit#>>'{request,command,action}'='check'
                  and coalesce(a.file_audit#>>'{request,config,source_kind}','server')='server'
                  and (configured.matches or (
                    a.file_audit#>>'{request,command,command_id}'=root#>>'{audit_receipt,command_id}'
                    and scope->>'receipt_id'=root#>>'{audit_receipt,receipt_id}'))
            ) agent on true
            """, ct, rows);
        var byId = receipts.OfType<JsonObject>().ToDictionary(row => Text(row, "id")!);
        var capabilities = context.Access.Capabilities;
        bool manageAudit = context.Action == "view" && (capabilities.IsOwner || capabilities.Decide("access.manage").Allowed);
        foreach (var row in rows.OfType<JsonObject>())
        {
            if (!byId.TryGetValue(Text(row, "id")!, out var detail)) continue;
            if (detail["received_at"] is { } stamp) row["audit_received_at"] = stamp.DeepClone();
            if (manageAudit && detail["check_revision"] is { } revision
                && FileAuditAccess.Allowed(capabilities, context.Principal.Role, context.Principal.Type, context.Principal.Id,
                    Text(row, "agent_id")!, Text(row, "source_instance_id")!, Text(row, "collection_scope_id")!))
                row["check_revision"] = revision.DeepClone();
            var current = FileAuditResult.ReportedAgentVersion(Text(detail, "current_version"));
            var checkedWith = FileAuditResult.ReportedAgentVersion(Text(detail, "check_version"));
            if (detail["check_receipt"] is JsonObject latest && Text(latest, "observed_at") is not null)
                row["check_receipt"] = latest.DeepClone();
            if (Text(detail, "check_state") == "pending")
                row["check_pending"] = true;
            var receipt = (row["check_receipt"] ?? row["audit_receipt"]) as JsonObject;
            if (!(current >= FileAuditResult.MinimumNativeCheckVersion) && FileAuditResult.NativeUnavailable(receipt))
                receipt!["check_agent_requirement"] = FileAuditResult.CheckAgentRequirement(checkedWith ?? current);
        }
    }

    private static async Task<JsonObject> ReadScreenActions(ISemanticSession session, ReportQueryContext context, string tab,
        JsonObject options, Func<JsonObject, int, Task<JsonArray>> read, CancellationToken ct)
    {
        async Task<JsonObject> Read(JsonObject paging, int size)
        {
            var response = (await read(paging, size))[0]!["data"]!.AsObject();
            var rows = Array(response["items"]);
            if (tab == "out-of-hours")
                foreach (var row in rows.OfType<JsonObject>())
                {
                    // Each outside-hours result refers to one stored action.
                    var action = Array(row["evidence"]).OfType<JsonObject>().FirstOrDefault();
                    foreach (string key in new[] { "path", "operation", "client_ip", "outcome", "access_mask", "denial_layer" })
                        if (action?[key] is { } value) row[key] = value.DeepClone();
                }
            await ResolveSubjectsAsync(session, context, rows, ct);
            return response;
        }

        string? path = Text(context.Params, "path_search"), account = Text(context.Params, "account_search");
        bool changes = Text(context.Params, "activity") == "changes";
        if (path is null && account is null && !changes) return await Read(options, context.Paging.Limit);

        // Screen searches filter retained rows across the window before applying the
        // visible cursor. The existing indexed reader pages the underlying rows.
        var scan = (JsonObject)options.DeepClone();
        scan.Remove("at"); scan.Remove("id");
        var matched = new JsonArray();
        long total = 0;
        bool hasMore = false;
        var start = Text(options, "at") is { } startText ? DateTimeOffset.Parse(startText, CultureInfo.InvariantCulture) : (DateTimeOffset?)null;
        do
        {
            var page = await Read(scan, 200);
            if (page["service_filter_version"]?.GetValue<int>() != 1) return page;
            foreach (var row in Array(page["items"]).OfType<JsonObject>())
            {
                if (changes && Text(row, "operation") is not ("write" or "rename")) continue;
                if (path is not null && !Contains(row, "path", path) && !Contains(row, "old_path", path)) continue;
                if (account is not null && !Contains(row, "subject_name", account) && !Contains(row, "subject_sid", account)) continue;
                total++;
                var at = DateTimeOffset.Parse(Text(row, "observed_at")!, CultureInfo.InvariantCulture);
                if (start.HasValue && (at > start || at == start && string.CompareOrdinal(Text(row, "id"), Text(options, "id")) >= 0)) continue;
                if (matched.Count < context.Paging.Limit) matched.Add(row.DeepClone());
                else hasMore = true;
            }
            if (!page.Flag("has_more") || page["after"] is not JsonObject next) break;
            scan["at"] = next["at"]?.DeepClone();
            scan["id"] = next["id"]?.DeepClone();
        } while (true);

        var last = matched.Count == 0 ? null : matched[^1];
        return new JsonObject
        {
            ["service_filter_version"] = 1, ["items"] = matched, ["filtered_count"] = total,
            ["has_more"] = hasMore, ["after"] = hasMore ? new JsonObject { ["at"] = last!["observed_at"]?.DeepClone(), ["id"] = last["id"]?.DeepClone() } : null
        };
    }

    private static bool Contains(JsonObject row, string field, string needle) =>
        Text(row, field)?.Contains(needle, StringComparison.OrdinalIgnoreCase) == true;

    private static async Task ResolveSubjectsAsync(ISemanticSession session, ReportQueryContext context, JsonArray rows, CancellationToken ct)
    {
        bool english = Sli.Server.Domains.DomainHttp.SelectEnglish(context.Language);
        foreach (var row in rows.OfType<JsonObject>())
        {
            string? key = Text(row, "subject_sid") switch
            {
                "S-1-5-18" => "file-audit.screen.system",
                "S-1-5-19" => "file-audit.screen.local_service",
                "S-1-5-20" => "file-audit.screen.network_service",
                _ => null
            };
            if (key is not null) row["subject_name"] = ReportResult.Message(key, english)["text"]?.DeepClone();
        }
        var candidates = new JsonArray(rows.OfType<JsonObject>().Where(row => Text(row, "subject_sid")?.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) == true)
            .Select(row => (JsonNode)new JsonObject { ["id"] = row["id"]?.DeepClone(), ["sid"] = row["subject_sid"]?.DeepClone(),
                ["observed_at"] = row["observed_at"]?.DeepClone() }).ToArray());
        if (candidates.Count == 0) return;
        var names = await session.QueryAsync($"""
            select a.id,name.account
            from jsonb_to_recordset($1::jsonb) a(id text,sid text,observed_at timestamptz)
            cross join lateral ({FileAuditAdEnrichment.AccountAtSql}) name
            where name.account is not null
            """, ct, candidates);
        var byId = names.OfType<JsonObject>().ToDictionary(row => Text(row, "id")!, row => Text(row, "account")!);
        foreach (var row in rows.OfType<JsonObject>())
            if (byId.TryGetValue(Text(row, "id")!, out var name)) row["subject_name"] = name[..Math.Min(name.Length, 256)];
    }

    private static async Task LinkActionProblemsAsync(ISemanticSession session, ReportQueryContext context, JsonArray rows,
        string tab, bool actionEpisodes, CancellationToken ct)
    {
        if (context.Action != "view" || rows.Count == 0) return;
        long[]? domains;
        try { domains = new ProblemAccess(context.Access).Scope("security.queue").Domains(); }
        catch (ProblemException) { return; }
        var keys = new JsonArray();
        foreach (var row in rows.OfType<JsonObject>())
        {
            var id = Text(row, "id");
            if (id is null) continue;
            var references = Array(row["evidence"]).OfType<JsonObject>()
                .Select(e => Text(e, "reference"))
                .Where(reference => reference?.StartsWith("event_cold_facts:", StringComparison.Ordinal) == true)
                .Select(reference => long.TryParse(reference!.AsSpan("event_cold_facts:".Length), out long value) ? value : 0)
                .Where(value => value > 0).Distinct();
            foreach (long reference in references)
                keys.Add(new JsonObject { ["row_id"] = id, ["event_id"] = reference });
            if (tab == "out-of-hours") keys.Add(new JsonObject { ["row_id"] = id, ["fingerprint"] = "file-audit:" + id });
        }
        if (keys.Count == 0 && !actionEpisodes) return;
        string episodeLinks = actionEpisodes ? "union all select row_id,finding_id from public.file_action_problems462($3::jsonb)" : "";
        object?[] arguments = actionEpisodes ? [keys, domains, rows] : [keys, domains];
        var problems = await session.QueryAsync($"""
            with keys as (select * from jsonb_to_recordset($1::jsonb) k(row_id text,event_id bigint,fingerprint text)),
            links as (
                select k.row_id,e.finding_id from keys k join public.finding_event_details337 e on e.event_db_id=k.event_id
                union all
                select k.row_id,f.id from keys k join public.findings_active f using(fingerprint)
                {episodeLinks}
            )
            select distinct on (row_id) row_id,findings.id as problem_id
            from links join public.findings_active findings on findings.id=links.finding_id
            where is_semantic_finding_published_v1(findings.id)
              and ($2::bigint[] is null or semantic_finding_in_domains_v265(findings.id,$2::bigint[]))
              and not ({ProblemRepository.Suppressed})
              and not exists(select 1 from semantic_suppressions risk where risk.finding_id=findings.id
                  and risk.kind='risk_acceptance' and risk.state='active' and risk.expires_at>statement_timestamp())
            order by row_id,case findings.severity when 'critical' then 0 when 'high' then 1 when 'medium' then 2 else 3 end,findings.id desc
            """, ct, arguments);
        var byId = problems.OfType<JsonObject>().ToDictionary(row => Text(row, "row_id")!);
        foreach (var row in rows.OfType<JsonObject>())
            if (byId.TryGetValue(Text(row, "id")!, out var problem)) row["problem_id"] = problem["problem_id"]?.DeepClone();
    }
}
