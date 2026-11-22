using System.Text.Json.Nodes;
using Sli.Server.Problems;
using Sli.Server.Access;
using Sli.Server.Auth;
using static Sli.Server.Domains.HomeJson;

namespace Sli.Server.Domains;

internal sealed class HomeDecisionSummary(HomeSummaryReaders reads)
{
    internal async Task<JsonObject> Build(HomeReport? report, IReadOnlyList<DomainItem> domains, Principal principal,
        HomeSummaryQuery query, CancellationToken ct)
    {
        var filters = query.Filters("security.problems"); filters["population"] = "open";
        var payload = new JsonObject { ["contract_id"] = "sli.home-summary.v3", ["time_zone"] = query.TimeZone,
            ["state"] = "denied", ["groups"] = new JsonArray(), ["total"] = null, ["new_count"] = null,
            ["previous_login_at"] = null, ["updated_at_utc"] = null, ["remaining_groups"] = null, ["remaining_problems"] = null,
            ["href"] = HomeSummaryQuery.Href("security.problems", filters), ["warnings"] = new JsonArray() };
        if (report is null) return payload;
        var ids = report.Intersect(domains);
        if (query.Domain.HasValue && (ids is null || !ids.Contains(query.Domain.Value))) throw new HomeQueryException("domain_scope_denied", 403);
        var allDomains = query.Domain is null && report.Grant.Kind == DomainGrantKind.All;
        if (ids is null || ids.Length == 0 && !allDomains) return payload;
        // As in the queue, an all-domain grant also admits findings without a domain witness.
        long[]? populationIds = allDomains ? null : ids;
        // This warning is independent of semantic analysis availability.
        payload["agent_link_warning"] = await HomeAgentLinkWarning.Read(reads, reads.Links, report, ids,
            query.Domain is null && report.Fields(null, "technical"), query.Now, ct);
        var selected = domains.Where(d => ids.Contains(d.Id)).ToArray();
        var identity = report.Fields(populationIds, "identity_basic");
        // Cohort drilldown validates fields on the full issued scope, before selection.
        var full = report.Grant;
        var cohortsAllowed = report.Fields(full.Kind == DomainGrantKind.All ? null : full.DomainIds.Order().ToArray(), "identity_basic");
        var exact = report.Fields(populationIds, "identity_basic", "raw_evidence");
        DateTimeOffset? since = null;
        IReadOnlyList<JsonObject> rows;
        string state;
        try
        {
            if (principal.Type == "session") since = (await reads.Read(HomeSummarySql.PreviousLogin, ct, ("user", principal.Id))).FirstOrDefault().Stamp("previous_login_at");
            rows = await reads.Read(HomeDecisionSql.Groups(identity && cohortsAllowed, allDomains, excludeDeferred: true), ct, ("ids", ids), ("from", query.Period?.From),
                ("to", query.Period?.To), ("zone", query.TimeZone), ("since", since));
            var runtime = HomeSummaryReaders.Runtime((await reads.Read(HomeSummarySql.Heartbeat, ct)).FirstOrDefault(), query.Now);
            state = runtime == "stale" ? "stale" : runtime != "active" ? "partial" : rows.Count == 0 ? "empty" : "ok";
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { payload["state"] = "error"; return payload; }
        if (identity) {
            var detectionIds = rows.Where(r => ProblemPresentation.CatalogDetection(r.Text("rule_code") ?? "")).Select(r => r.Number("id")).ToArray();
            if (detectionIds.Length > 0) ProblemRepository.AttachDetectionPresentation(rows,
                await reads.Read(ProblemRepository.ShortDetectionPresentationSql, ct, ("ids", detectionIds)));
        }
        var labels = identity ? await IdentityBatch(rows,ct) : new();
        var groups = new JsonArray();
        foreach (var row in rows)
        {
            var view = HomePresentation.Finding(row, query.Language, identity, report.Fields(populationIds, "technical"));
            var cohort = identity && cohortsAllowed && row["cohort"] is JsonArray ? Sli.Agent.Protocol.CanonicalJson.Serialize(row["cohort"], ensureAscii: false) : null;
            var objects = new JsonArray();
            if (identity)
            {
                if (row["object_names"] is JsonArray names)
                {
                    foreach (var name in names.Select(n => n?.GetValue<string>()).Where(n => !string.IsNullOrWhiteSpace(n)).Distinct())
                        objects.Add(IdentityObject(name!, row, exact, labels));
                }
                else if (row["objects"] is JsonArray samples)
                    foreach (var sample in samples.OfType<JsonObject>())
                    {
                        var obj = new JsonObject();
                        foreach (var key in new[] { "name", "name_state", "domain", "identifier" })
                            if (sample.ContainsKey(key)) obj[key] = sample[key].Copy();
                        if (sample["source"] is JsonObject { Count: > 0 } source)
                        {
                            obj["snapshot_name"] = true;
                            if (exact) obj["source"] = source.DeepClone();
                        }
                        objects.Add(obj);
                    }
            }
            var link = new Dictionary<string, object?>(filters) { ["rule_code"] = row.Text("rule_code") };
            if (cohort is not null) link["cohort"] = cohort;
            var assignee = identity ? row.Text("assigned_to") : null;
            groups.Add(new JsonObject { ["key"] = cohort ?? row.Text("rule_code") + ":" + row["representative"].Number("id"), ["title"] = view["title"].Copy(),
                ["title_message"] = view["title_message"].Copy(), ["severity"] = new[] { "critical", "high", "medium", "low", "unknown" }[Math.Clamp((int)row.Number("importance"), 0, 4)],
                ["total"] = row.Number("total"), ["occurrence_count"] = row["occurrence_count"].Copy(), ["new_count"] = since.HasValue ? row["new_count"].Copy() : null,
                ["last_seen_utc"] = row["last_seen_utc"].Copy(), ["assigned_to"] = assignee,
                ["assignee_state"] = !identity ? "unknown" : string.IsNullOrEmpty(assignee) ? "unassigned" : row.Number("unassigned_count") > 0 ? "mixed" : "assigned",
                ["unassigned_count"] = identity ? row.Number("unassigned_count") : null, ["day"] = identity ? row["day"].Copy() : null,
                ["identity_state"] = identity && row["object_names"] is not null ? objects.Any(o => o.Text("name_state") == "unavailable") ? "unavailable"
                    : objects.Any(o => o.Text("name_state") is "named" or "no_match" or "ambiguous") ? "lookup_complete" : "not_requested" : null, ["objects"] = objects,
                ["object_count"] = identity ? row["object_names"] is JsonArray ? objects.Count : row.Number("object_count") : null,
                ["href"] = HomeSummaryQuery.Href(report.Key, link) });
        }
        var warnings = new JsonArray();
        foreach (var domain in selected)
        {
            var freshness = domain.Freshness;
            string? reason = freshness.SnapshotState is not ("ok" or "complete" or "available") || freshness.ObservedAtUtc is null
                ? "home.queue.warning.source_incomplete" : state is "partial" or "stale" ? "home.queue.warning.analysis_unconfirmed" : null;
            if (reason is not null) warnings.Add(Object(new { domain = domain.DisplayName, reason_code = reason, href = "/app/operations?domain=" + domain.Id }));
        }
        var uncertainEmpty = groups.Count == 0 && (state is "partial" or "stale" || warnings.Count > 0);
        var total = rows.FirstOrDefault().Number("total_problems");
        payload["state"] = uncertainEmpty ? "partial" : state;
        payload["groups"] = groups;
        payload["total"] = uncertainEmpty ? null : total;
        payload["new_count"] = uncertainEmpty || since is null ? null : rows.FirstOrDefault().Number("total_new");
        payload["previous_login_at"] = since.HasValue ? HomeSummaryQuery.Iso(since.Value) : null;
        payload["updated_at_utc"] = selected.All(d => d.Freshness.ObservedAtUtc is not null) ? selected.Select(d => d.Freshness.ObservedAtUtc).Order().FirstOrDefault() : null;
        payload["remaining_groups"] = uncertainEmpty ? null : rows.FirstOrDefault().Number("total_groups") - groups.Count;
        payload["remaining_problems"] = uncertainEmpty ? null : total - rows.Count;
        payload["warnings"] = warnings;
        return payload;
    }

    async Task<Dictionary<(long Finding, string Value), IReadOnlyList<JsonObject>?>> IdentityBatch(IReadOnlyList<JsonObject> groups, CancellationToken ct)
    {
        var keys = groups.SelectMany(g => (g["object_names"] as JsonArray ?? new()).Select(n => n?.GetValue<string>())
            .Where(n => !string.IsNullOrWhiteSpace(n) && ProblemRepository.Sid(n!) is not null)
            .Select(n => (Finding: g["representative"].Number("id"), Value: n!))).Distinct().ToArray();
        var result = new Dictionary<(long Finding, string Value), IReadOnlyList<JsonObject>?>();
        if (keys.Length == 0) return result;
        try {
            var requests = System.Text.Json.JsonSerializer.Serialize(keys.Select((k, i) => new {
                request_index = i, finding = k.Finding, sid = ProblemRepository.Sid(k.Value)!.ToLowerInvariant(),
                hostname = k.Value.StartsWith("sid:", StringComparison.OrdinalIgnoreCase) && k.Value.Split(':') is { Length: 3 } parts ? parts[1] : null
            }));
            var rows = await reads.Read(IdentitySql, ct, ("requests", requests));
            for (int i = 0; i < keys.Length; i++) result[keys[i]] = rows.Where(r => r.Number("request_index") == i).ToArray();
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { foreach (var key in keys) result[key] = null; }
        return result;
    }
    internal static JsonObject IdentityObject(string value, JsonObject group, bool exact,
        Dictionary<(long Finding, string Value), IReadOnlyList<JsonObject>?> batch)
    {
        var context = new JsonObject { ["principals"] = new JsonObject(), ["principal_states"] = new JsonObject() };
        string? sid = ProblemRepository.Sid(value);
        if (sid is not null && batch.TryGetValue((group["representative"].Number("id"), value), out var labels)) {
            string state = labels is null ? "unavailable" : !labels.Any(r => r.Boolean("witness_verified") == true) ? "unverified"
                : labels.Count(r => r["entity_id"] is not null) > 1 ? "ambiguous" : "no_match";
            if (labels is { Count: 1 } && state == "no_match" && labels[0].Text("label")?.Trim() is { Length: > 0 } name && name != "-"
                && labels[0].Stamp("observed_at_utc") is not null && !string.IsNullOrEmpty(labels[0].Text("source_run_id")) && labels[0].Number("entity_id") != 0) {
                state = "named"; var label = labels[0];
                context["principals"]![value] = new JsonObject { ["label"] = name, ["source"] = "ad_snapshot", ["sid"] = sid,
                    ["domain_id"] = label["domain_id"].Copy(), ["event_db_id"] = label["event_db_id"].Copy(), ["event_id"] = label["event_id"].Copy(),
                    ["witness_at_utc"] = label["witness_at_utc"].Copy(), ["observed_at_utc"] = label["observed_at_utc"].Copy(),
                    ["source_run_id"] = label["source_run_id"].Copy(), ["entity_id"] = label["entity_id"].Copy() };
            }
            context["principal_states"]![value] = state;
        }
        var obj = ProblemPresentation.IdentityObject(value, context, group.Text("domain_name"));
        if (obj.Text("name_state") == "named") obj["snapshot_name"] = true;
        if (!exact) obj.Remove("source");
        return obj;
    }

    internal const string IdentitySql = """
        with requests as materialized (
            select * from jsonb_to_recordset(@requests::jsonb) as r(request_index int,finding bigint,sid text,hostname text)
        ), witness as materialized (
            select e.finding_id,e.event_db_id as id,e.event_id,e.domain_id,e.time_created_utc,
                e.subject_user_sid,e.target_user_sid,e.membership_member_sid,e.hostname
            from finding_event_details337 e where e.finding_id in (select finding from requests)
        ), complete as (
            select finding_id,count(*) as total,count(distinct domain_id) as domains,
                min(domain_id) as domain_id,bool_and(domain_id is not null) as known
            from witness group by finding_id
        ), eligible as (
            select request.*,c.domain_id,e.id as event_db_id,e.event_id,e.time_created_utc,
                coalesce(finding.evidence_count=c.total and c.domains=1 and c.known and c.domain_id>0 and e.id is not null,false) as identity_verified
            from requests request join findings_active finding on finding.id=request.finding
            left join complete c on c.finding_id=request.finding
            left join lateral (select * from witness where finding_id=request.finding and time_created_utc is not null
                and (lower(subject_user_sid)=request.sid or lower(target_user_sid)=request.sid
                    or lower(membership_member_sid)=request.sid)
                and (request.hostname is null or lower(hostname)=lower(request.hostname))
                order by time_created_utc desc limit 1) e on true
        )
        select request.request_index,request.identity_verified as witness_verified,
            request.time_created_utc as witness_at_utc,candidate.* from eligible request left join lateral (
        select distinct on (version.entity_id,coalesce(nullif(btrim(version.attributes_json->'attributes'->>'display_name'),''),
            nullif(btrim(version.attributes_json->'attributes'->>'sam_account_name'),'')))
            version.entity_id,run.run_id as source_run_id,run.observed_at_utc,request.domain_id,request.event_db_id,request.event_id,
            coalesce(nullif(btrim(version.attributes_json->'attributes'->>'display_name'),''),
                nullif(btrim(version.attributes_json->'attributes'->>'sam_account_name'),'')) as label
        from ad_context_entity_aliases alias
        join ad_context_entity_versions version on version.entity_id=alias.entity_id
        join ad_context_runs run on run.run_id=version.source_run_id and run.domain_id=request.domain_id and run.status='completed'
        join ad_context_sections section on section.run_id=run.run_id and section.section_name=version.source_section and section.status='complete'
        where request.identity_verified and alias.domain_id=request.domain_id and alias.alias_type='object_sid' and alias.normalized_value=request.sid
          and lower(version.attributes_json->'identity'->>'object_sid')=request.sid
          and version.attributes_json->'identity'->>'kind' in ('ad_user','ad_group')
          and version.source_section in ('directory_accounts','directory_group_graph','privileged_membership')
          and version.valid_from_utc<=request.time_created_utc and (version.valid_to_utc is null or version.valid_to_utc>request.time_created_utc)
          and run.observed_at_utc<=request.time_created_utc
        order by version.entity_id,label,run.observed_at_utc desc limit 2
        ) candidate on true
        """;
}
