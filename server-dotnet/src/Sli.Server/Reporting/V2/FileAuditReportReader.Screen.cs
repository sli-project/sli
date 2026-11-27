using System.Globalization;
using System.Text.Json.Nodes;
using Sli.Server.Agents.FileAudit;
using Sli.Server.Problems;
using Sli.Server.Semantic;

namespace Sli.Server.Reporting.V2;

public sealed partial class FileAuditReportReader
{
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

    private static async Task ResourceAuditAsync(ISemanticSession session, JsonArray rows, CancellationToken ct)
    {
        if (rows.Count == 0) return;
        var receipts = await session.QueryAsync("""
            select root->>'id' as id, accepted.received_at, agent.current_version, agent.check_version
            from jsonb_array_elements($1::jsonb) as r(root)
            left join lateral (
                select receipt.received_at
                from public.sli_agent_receipts receipt
                join public.sli_agent_packet_inbox inbox using(packet_id)
                where receipt.agent_id=(root->>'agent_id')::uuid and receipt.module_id='sli.file-audit'
                  and receipt.envelope->>'source_instance_id'=root->>'source_instance_id'
                  and inbox.imported_at is not null
                  and exists(select 1 from jsonb_array_elements(inbox.event_rows) as e(observation)
                      where observation->>'collection_scope_id'=root->>'collection_scope_id'
                        and (lower(observation->>'path')=lower(root->>'path')
                            or starts_with(lower(observation->>'path'),rtrim(lower(root->>'path'),chr(92))||chr(92))))
                order by receipt.sequence desc limit 1
            ) accepted on true
            left join lateral (
                select a.rights_probe->>'agent_version' as current_version, scope->>'agent_version' as check_version
                from public.sli_agents a
                cross join lateral (select a.file_audit->'scopes'->(root->>'collection_scope_id') as scope) s
                where a.id=(root->>'agent_id')::uuid and a.status='active'
                  and a.file_audit#>>'{request,command,action}'='check'
                  and a.file_audit#>>'{request,command,command_id}'=root#>>'{audit_receipt,command_id}'
                  and scope->>'receipt_id'=root#>>'{audit_receipt,receipt_id}'
                  and root#>>'{audit_receipt,state}'='failed'
                  and root#>>'{audit_receipt,reason_code}'='native_unavailable'
            ) agent on true
            """, ct, rows);
        var byId = receipts.OfType<JsonObject>().ToDictionary(row => Text(row, "id")!);
        foreach (var row in rows.OfType<JsonObject>())
        {
            if (!byId.TryGetValue(Text(row, "id")!, out var detail)) continue;
            if (detail["received_at"] is { } stamp) row["audit_received_at"] = stamp.DeepClone();
            var current = FileAuditResult.ReportedAgentVersion(Text(detail, "current_version"));
            var checkedWith = FileAuditResult.ReportedAgentVersion(Text(detail, "check_version")) ?? current;
            if (current >= FileAuditResult.MinimumNativeCheckVersion || row["audit_receipt"] is not JsonObject receipt) continue;
            receipt["check_agent_requirement"] = FileAuditResult.CheckAgentRequirement(checkedWith);
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
            await ResolveSubjectsAsync(session, rows, ct);
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

    private static async Task ResolveSubjectsAsync(ISemanticSession session, JsonArray rows, CancellationToken ct)
    {
        var candidates = new JsonArray(rows.OfType<JsonObject>().Where(row => Text(row, "subject_sid")?.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) == true)
            .Select(row => (JsonNode)new JsonObject { ["id"] = row["id"]?.DeepClone(), ["sid"] = row["subject_sid"]?.DeepClone(),
                ["observed_at"] = row["observed_at"]?.DeepClone() }).ToArray());
        if (candidates.Count == 0) return;
        var names = await session.QueryAsync("""
            select a.id,name.account
            from jsonb_to_recordset($1::jsonb) a(id text,sid text,observed_at timestamptz)
            cross join lateral (
                select min(concat(coalesce(nullif(d.netbios_name,''),d.fqdn),chr(92),v.attributes_json#>>'{attributes,sam_account_name}')) as account
                from public.domains d
                join public.ad_context_entity_aliases alias on alias.domain_id=d.id and alias.alias_type='object_sid'
                  and alias.normalized_value=lower(a.sid)
                join public.ad_context_entity_versions v on v.entity_id=alias.entity_id
                join public.ad_context_runs run on run.run_id=v.source_run_id and run.status='completed'
                where lower(d.domain_sid)=lower(regexp_replace(a.sid,'-[0-9]+$',''))
                  and v.source_section='directory_accounts'
                  and v.valid_from_utc<=a.observed_at and (v.valid_to_utc is null or v.valid_to_utc>a.observed_at)
                  and nullif(v.attributes_json#>>'{attributes,sam_account_name}','') is not null
                having count(distinct concat(coalesce(nullif(d.netbios_name,''),d.fqdn),chr(92),v.attributes_json#>>'{attributes,sam_account_name}'))=1
            ) name
            """, ct, candidates);
        var byId = names.OfType<JsonObject>().ToDictionary(row => Text(row, "id")!, row => Text(row, "account")!);
        foreach (var row in rows.OfType<JsonObject>())
            if (byId.TryGetValue(Text(row, "id")!, out var name)) row["subject_name"] = name[..Math.Min(name.Length, 256)];
    }

    private static async Task LinkActionProblemsAsync(ISemanticSession session, ReportQueryContext context, JsonArray rows, string tab, CancellationToken ct)
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
        if (keys.Count == 0) return;
        var problems = await session.QueryAsync($"""
            with keys as (select * from jsonb_to_recordset($1::jsonb) k(row_id text,event_id bigint,fingerprint text)),
            links as (
                select k.row_id,e.finding_id from keys k join public.finding_event_details337 e on e.event_db_id=k.event_id
                union all
                select k.row_id,f.id from keys k join public.findings_active f using(fingerprint)
            )
            select distinct on (row_id) row_id,findings.id as problem_id
            from links join public.findings_active findings on findings.id=links.finding_id
            where is_semantic_finding_published_v1(findings.id)
              and ($2::bigint[] is null or semantic_finding_in_domains_v265(findings.id,$2::bigint[]))
              and not ({ProblemRepository.Suppressed})
              and not exists(select 1 from semantic_suppressions risk where risk.finding_id=findings.id
                  and risk.kind='risk_acceptance' and risk.state='active' and risk.expires_at>statement_timestamp())
            order by row_id,case findings.severity when 'critical' then 0 when 'high' then 1 when 'medium' then 2 else 3 end,findings.id desc
            """, ct, keys, domains);
        var byId = problems.OfType<JsonObject>().ToDictionary(row => Text(row, "row_id")!);
        foreach (var row in rows.OfType<JsonObject>())
            if (byId.TryGetValue(Text(row, "id")!, out var problem)) row["problem_id"] = problem["problem_id"]?.DeepClone();
    }
}
