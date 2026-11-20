using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Investigations;
using Sli.Server.Semantic;

namespace Sli.Server.Problems;

public sealed partial class ProblemRepository
{
    internal static async Task AttachQueueNames(JsonArray rows,
        Func<string, long[], CancellationToken, Task<List<JsonObject>>> readSnapshots, CancellationToken ct)
    {
        // Use the same manifest selection and hash validation as the AD reports.
        long Domain(JsonObject row) {
            var domains = ProblemJson.Array(row["evidence"]).OfType<JsonObject>()
                .SelectMany(e => new[] { ProblemJson.Long(e["identity_domain_min"]), ProblemJson.Long(e["identity_domain_max"]) }).Distinct().ToArray();
            return domains.Length == 1 && domains[0] > 0 ? domains[0] : 0;
        }
        var pending = rows.OfType<JsonObject>().Where(r => ProblemJson.Array(r["entities"]).OfType<JsonObject>()
            .Any(e => Sid(ProblemJson.Text(e["display_name"])) is not null)).ToArray();
        foreach (var row in rows.OfType<JsonObject>()) row["_queue_names"] = new JsonObject();
        var domains = pending.Select(Domain).Where(d => d > 0).Distinct().ToArray();
        if (domains.Length == 0) return;
        foreach (string family in new[] { "users_v2", "computers_v6" }) {
            var sources = await readSnapshots(family, domains, ct);
            foreach (var source in sources) {
                var objects = ProblemJson.Array(source["snapshot"]?[family == "users_v2" ? "users" : "objects"]).OfType<JsonObject>()
                    .Where(o => Sid(ProblemJson.Text(o["sid"])) is not null).GroupBy(o => Sid(ProblemJson.Text(o["sid"]))!)
                    .ToDictionary(g => g.Key, g => g.ToArray(), StringComparer.OrdinalIgnoreCase);
                foreach (var row in pending.Where(r => Domain(r) == ProblemJson.Long(source["domain_id"])))
                    foreach (var entity in ProblemJson.Array(row["entities"]).OfType<JsonObject>()) {
                        string value = ProblemJson.Text(entity["display_name"]).Trim(); string? sid = Sid(value);
                        if (sid is null || !objects.TryGetValue(sid, out var matches) || matches.Length != 1) continue;
                        var obj = matches[0];
                        string? label = (family == "users_v2" ? new[] { "displayName", "name", "samAccountName" } : new[] { "name", "dnsHostName" })
                            .Select(f => ProblemJson.Text(obj[f]).Trim()).FirstOrDefault(s => s is not ("" or "-") && Sid(s) is null);
                        if (label is not null) row["_queue_names"]![value] = label;
                    }
            }
        }
    }
    internal const string ShortDetectionPresentationSql = DetectionPresentationSql;
    internal const string DetectionPresentationSql = """
        select distinct on(e.finding_id) e.finding_id,e.event_id,e.time_created_utc,e.hostname,
            e.subject_user_name,e.subject_domain_name,e.target_user_name,
            c.fields->>'MemberName' as membership_member_name,e.membership_member_sid,
            jsonb_build_object('audit_subcategory_guid',c.fields->>'SubcategoryGuid',
                'audit_category_id',c.fields->>'CategoryId') as facts_json
        from finding_event_details337 e join finding_event_copies337 c
            on (c.finding_id,c.time_created_utc,c.event_id,c.evidence_role)=(e.finding_id,e.time_created_utc,e.event_db_id,e.evidence_role)
        where e.finding_id=any(@ids) and (
            e.event_id in(4728,4732,4756,4719) and e.channel='Security' and e.identity_provider='Microsoft-Windows-Security-Auditing'
            or e.event_id=1102 and e.channel='Security' and e.identity_provider='Microsoft-Windows-Eventlog'
            or e.event_id=104 and e.channel='System' and e.identity_provider='Microsoft-Windows-Eventlog')
        order by e.finding_id,e.time_created_utc desc,e.event_db_id desc
        """;
    internal static void AttachDetectionPresentation(IEnumerable<JsonObject> rows, IEnumerable<JsonObject> observations)
    {
        foreach (var row in rows.Where(r => ProblemPresentation.CatalogDetection(ProblemJson.Text(r["rule_code"])))) {
            string rule = ProblemJson.Text(row["rule_code"]);
            var witness = observations.FirstOrDefault(e => ProblemJson.Long(e["finding_id"]) == ProblemJson.Long(row["id"]) &&
                (rule == "semantic.qw.privileged-group-addition" ? ProblemJson.Long(e["event_id"]) is 4728 or 4732 or 4756 :
                 rule == "semantic.qw.audit-disabled" ? ProblemJson.Long(e["event_id"]) == 4719 : ProblemJson.Long(e["event_id"]) is 1102 or 104));
            if (witness is null) continue;
            string? Clean(JsonNode? value) => ProblemJson.Text(value).Trim() is var text && text is not ("" or "-" or "—") ? text[..Math.Min(text.Length, 512)] : null;
            string? actor = Clean(witness["subject_user_name"]), domain = Clean(witness["subject_domain_name"]);
            var facts = row["presentation_facts"] as JsonObject ?? new();
            facts["actor"] = actor is null ? null : domain is null ? actor : domain + "\\" + actor;
            facts["computer"] = Clean(witness["hostname"]);
            facts["time"] = witness["time_created_utc"]?.DeepClone();
            if (rule == "semantic.qw.privileged-group-addition") {
                facts["member"] = Clean(witness["membership_member_name"]) ?? Clean(witness["membership_member_sid"]);
                facts["group"] = Clean(witness["target_user_name"]);
            }
            if (rule == "semantic.qw.audit-disabled") {
                var native = witness["facts_json"];
                facts["category_id"] = ProblemJson.Text(native?["audit_subcategory_guid"]).Trim('{', '}').Equals("0cce9215-69ae-11d9-bed3-505054503030", StringComparison.OrdinalIgnoreCase)
                    ? "logon" : ProblemJson.Text(native?["audit_category_id"]).TrimStart('%');
                facts["category"] = Clean(native?["audit_category_name"]);
            }
            row["presentation_facts"] = facts;
        }
    }
    internal static string? Sid(string raw)
    {
        string value = raw.Trim();
        if (value.StartsWith("sid:", StringComparison.OrdinalIgnoreCase) && value.Count(c => c == ':') == 1)
        {
            string sid = value[4..].ToUpperInvariant();
            return sid.Length <= 184 && Regex.IsMatch(sid, @"\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\z") ? sid : null;
        }
        var match = Regex.Match(value, @"\A(?:sid:[^:]+:)?(S-1-(?:[0-9]+-)+[0-9]+)\z", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value.ToUpperInvariant() : null;
    }
    private static bool Host(string value, string hostname) => !value.Trim().StartsWith("sid:", StringComparison.OrdinalIgnoreCase) ||
        (value.Split(':') is var parts && (parts.Length == 2 ? Sid(value) is not null : parts.Length == 3 && parts[1].Equals(hostname, StringComparison.OrdinalIgnoreCase)));
    internal static async Task AttachIdentities(NpgsqlTransaction tx, JsonArray rows, CancellationToken ct)
    {
        await AttachIdentities(rows, async (requests, token) => {
            await tx.SaveAsync("identity_labels", token);
            try {
                var labels = await Rows(tx, IdentityLabelsSql, new() { ["requests"] = requests.ToJsonString() }, token);
                await tx.ReleaseAsync("identity_labels", token);
                return labels;
            }
            catch (PostgresException) { await tx.RollbackAsync("identity_labels", token); throw; }
        }, ct);
    }
    internal static async Task AttachIdentities(JsonArray rows, Func<JsonArray, CancellationToken, Task<JsonArray>> readLabels,
        CancellationToken ct, IReadOnlySet<(string Stream, string Provider, long Event)>? membershipSources = null)
    {
        try { await AttachIdentityLabels(rows, readLabels, ct, membershipSources ?? SemanticNormalization.MembershipEventIdentities()); }
        finally {
            foreach (var row in rows.OfType<JsonObject>()) foreach (var item in ProblemJson.Array(row["evidence"]).OfType<JsonObject>())
                foreach (string field in new[] { "domain_id", "subject_user_sid", "subject_user_name", "subject_domain_name", "target_user_sid", "target_user_name", "target_domain_name", "ip_address", "workstation_name", "membership_member_sid", "identity_provider", "identity_domain_min", "identity_domain_max", "identity_event_count" }) item.Remove(field);
        }
    }
    private static async Task AttachIdentityLabels(JsonArray rows, Func<JsonArray, CancellationToken, Task<JsonArray>> readLabels,
        CancellationToken ct, IReadOnlySet<(string Stream, string Provider, long Event)> membershipSources)
    {
        var requests = new JsonArray(); var owners = new List<(JsonObject Context, string Value, JsonObject Provenance)>();
        foreach (var row in rows.OfType<JsonObject>())
        {
            string actor = ProblemJson.Text(row["actor"]).Trim();
            var values = new[] { actor, ProblemJson.Text(row["target"]).Trim(), ProblemJson.Text(row["presentation_facts"]?["member"]), ProblemJson.Text(row["presentation_facts"]?["group"]) }.Concat(ProblemJson.Array(row["entities"]).OfType<JsonObject>().Select(e => ProblemJson.Text(e["display_name"]).Trim())).Concat(ProblemJson.Array(row["_identity_objects"]).Select(v => ProblemJson.Text(v).Trim())).Distinct().ToArray();
            var states = new JsonObject(); foreach (string value in values.Where(v => Sid(v) is not null)) states[value] = "unverified";
            var context = new JsonObject { ["actor"] = null, ["principals"] = new JsonObject(), ["snapshot_state"] = "not_requested", ["principal_states"] = states }; row["identity_context"] = context;
            var evidence = ProblemJson.Array(row["evidence"]).OfType<JsonObject>().ToArray();
            var domains = evidence.SelectMany(e => new[] { ProblemJson.Long(e["identity_domain_min"]), ProblemJson.Long(e["identity_domain_max"]) }).Distinct().ToArray();
            if (domains.Length != 1 || domains[0] <= 0) continue;
            long domain = domains[0]; string? sid = Sid(actor);
            bool complete = ProblemJson.Long(row["evidence_count"]) == evidence.Length && evidence.All(e => ProblemJson.Long(e["identity_event_count"]) == evidence.Length);
            var candidates = evidence.Where(e => membershipSources.Contains((ProblemJson.Text(e["channel"]), ProblemJson.Text(e["identity_provider"]), ProblemJson.Long(e["event_id"]))) && ProblemJson.Text(e["subject_user_name"]).Trim() is not ("" or "-") &&
                Host(actor, ProblemJson.Text(e["hostname"])) && (actor.Length == 0 || sid is not null && Sid(ProblemJson.Text(e["subject_user_sid"])) == sid)).ToArray();
            var actors = candidates.Select(e => (Domain: ProblemJson.Text(e["subject_domain_name"]).Trim(), Name: ProblemJson.Text(e["subject_user_name"]).Trim(), Sid: Sid(ProblemJson.Text(e["subject_user_sid"])))).Distinct().ToArray();
            if (complete && candidates.Length == evidence.Length && actors.Length == 1)
            {
                var witness = candidates[0]; var identity = actors[0];
                context["actor"] = new JsonObject { ["label"] = identity.Domain is "" or "-" ? identity.Name : identity.Domain + "\\" + identity.Name,
                    ["source"] = "event", ["sid"] = identity.Sid, ["domain_id"] = domain, ["event_db_id"] = witness["event_db_id"]?.DeepClone(),
                    ["event_id"] = witness["event_id"]?.DeepClone(), ["observed_at_utc"] = witness["time_created_utc"]?.DeepClone() };
            }
            if (ProblemJson.Long(row["evidence_count"]) != ProblemJson.Long(evidence[0]["identity_event_count"])) continue;
            foreach (string value in values)
            {
                string? principal = Sid(value); if (principal is null) continue;
                var witness = evidence.Where(e => new[] { "subject_user_sid", "target_user_sid", "membership_member_sid" }.Any(f => Sid(ProblemJson.Text(e[f])) == principal) &&
                    ProblemJson.Stamp(e["time_created_utc"], out _) && Host(value, ProblemJson.Text(e["hostname"]))).OrderByDescending(e => ProblemJson.Text(e["time_created_utc"])).FirstOrDefault();
                if (witness is null) continue;
                requests.Add(new JsonObject { ["request_index"] = requests.Count, ["domain_id"] = domain, ["sid"] = principal.ToLowerInvariant(), ["at_utc"] = witness["time_created_utc"]?.DeepClone() });
                owners.Add((context, value, new() { ["source"] = "ad_snapshot", ["sid"] = principal, ["domain_id"] = domain, ["event_db_id"] = witness["event_db_id"]?.DeepClone(),
                    ["event_id"] = witness["event_id"]?.DeepClone(), ["witness_at_utc"] = witness["time_created_utc"]?.DeepClone() }));
            }
        }
        if (requests.Count == 0 || requests.Count > 5400) return;
        try
        {
            var labels = await readLabels(requests, ct);
            for (int i = 0; i < owners.Count; i++)
            {
                var (context, value, provenance) = owners[i]; var found = labels.OfType<JsonObject>().Where(l => ProblemJson.Long(l["request_index"]) == i).ToArray();
                context["snapshot_state"] = "lookup_complete"; context["principal_states"]![value] = found.Length > 1 ? "ambiguous" : "no_match";
                if (found.Length == 1 && ProblemJson.Text(found[0]["label"]).Trim() is not ("" or "-") && !string.IsNullOrEmpty(ProblemJson.Text(found[0]["source_run_id"])) &&
                    ProblemJson.Long(found[0]["entity_id"]) != 0 && ProblemJson.Stamp(found[0]["observed_at_utc"], out _))
                {
                    context["principal_states"]![value] = "named"; provenance["label"] = found[0]["label"]!.DeepClone(); provenance["observed_at_utc"] = found[0]["observed_at_utc"]!.DeepClone();
                    provenance["source_run_id"] = found[0]["source_run_id"]!.DeepClone(); provenance["entity_id"] = found[0]["entity_id"]!.DeepClone(); context["principals"]![value] = provenance;
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch
        {
            foreach (var (context, value, _) in owners) { context["snapshot_state"] = "unavailable"; context["principal_states"]![value] = "unavailable"; }
        }
    }
    internal const string IdentityLabelsSql = """
            select request.request_index,candidate.*
            from jsonb_to_recordset(@requests::jsonb) as request(request_index integer,domain_id bigint,sid text,at_utc timestamptz)
            join lateral (
              select distinct on(version.entity_id,coalesce(nullif(btrim(version.attributes_json->'attributes'->>'display_name'),''),nullif(btrim(version.attributes_json->'attributes'->>'sam_account_name'),'')))
                version.entity_id,version.source_run_id,run.observed_at_utc,
                coalesce(nullif(btrim(version.attributes_json->'attributes'->>'display_name'),''),nullif(btrim(version.attributes_json->'attributes'->>'sam_account_name'),'')) as label
              from ad_context_entity_aliases alias join ad_context_entity_versions version on version.entity_id=alias.entity_id
              join ad_context_runs run on run.run_id=version.source_run_id and run.status='completed'
              join ad_context_sections section on section.run_id=run.run_id and section.section_name=version.source_section and section.status='complete'
              where alias.domain_id=request.domain_id and run.domain_id=request.domain_id and alias.alias_type='object_sid' and alias.normalized_value=request.sid
                and lower(version.attributes_json->'identity'->>'object_sid')=request.sid and version.attributes_json->'identity'->>'kind' in ('ad_user','ad_group')
                and version.source_section in ('directory_accounts','directory_group_graph','privileged_membership') and version.valid_from_utc<=request.at_utc
                and (version.valid_to_utc is null or version.valid_to_utc>request.at_utc) and run.observed_at_utc<=request.at_utc
              order by version.entity_id,label,run.observed_at_utc desc limit 2
            ) candidate on true order by request.request_index
            
        """;

    private async Task AttachCases(NpgsqlTransaction tx, JsonArray rows, ProblemAccess access, CancellationToken ct)
    {
        foreach (var row in rows.OfType<JsonObject>()) row["linked_case"] = null;
        string? report = new[] { "investigations.workspace", "cases.workspace" }.FirstOrDefault(key => access.Decision.Reports.Any(r => r.ReportKey == key && r.Allowed && r.Grants.Any(g => g.AllowedActions.Contains("view"))));
        if (report is null || rows.Count == 0) return;
        await tx.SaveAsync("case_links", ct);
        try
        {
            var linked = await Rows(tx, """
                select link.finding_id,inv.id,inv.public_id,inv.status from investigation_finding_links link
                join investigations inv on inv.id=link.investigation_id where link.finding_id=any(@ids)
                """, new() { ["ids"] = rows.Select(r => ProblemJson.Long(r!["id"])).ToArray() }, ct);
            foreach (var item in linked.OfType<JsonObject>())
            {
                long id = ProblemJson.Long(item["id"]); var args = new Dictionary<string, object?> { ["id"] = id, ["boundary"] = Sli.Server.Storage.EventReports.EventReadService.ShortBoundary(configuration) };
                var events = await Rows(tx, "with short_events as (" + Sli.Server.Entities.EntityShortSql.Source("@boundary", daily: false) + ") " + """
                    select linked.event_db_id,s.id as server_id,s.domain_id,case when s.id is not null then e.channel end as channel from investigation_events linked
                    left join short_events e on e.id=linked.event_db_id
                    left join servers s on s.id=e.server_id and s.domain_id=e.domain_id
                    where linked.investigation_id=@id order by linked.event_db_id
                    """, args, ct);
                var domains = await Rows(tx, "select source_domain_id from investigation_evidence_refs where investigation_id=@id order by source_domain_id,reference_id", args, ct);
                var groups = new List<IReadOnlyList<AccessResource>>();
                foreach (var ev in events.OfType<JsonObject>().DistinctBy(e => ProblemJson.Long(e["event_db_id"])))
                {
                    var group = new List<AccessResource>();
                    if (ev["server_id"] is not null) group.Add(new("server", ProblemJson.Long(ev["server_id"])));
                    if (ev["domain_id"] is not null) group.Add(new("domain", ProblemJson.Long(ev["domain_id"])));
                    if (!string.IsNullOrEmpty(ProblemJson.Text(ev["channel"]))) group.Add(new("channel", Value: ProblemJson.Text(ev["channel"])));
                    groups.Add(group);
                }
                foreach (long domain in domains.OfType<JsonObject>().Select(d => ProblemJson.Long(d["source_domain_id"])).Distinct()) groups.Add([new("domain", domain)]);
                var visible = LinkedCase(item, access, groups);
                if (visible is null) continue;
                foreach (var row in rows.OfType<JsonObject>().Where(r => ProblemJson.Long(r["id"]) == ProblemJson.Long(item["finding_id"]))) row["linked_case"] = visible.DeepClone();
            }
            await tx.ReleaseAsync("case_links", ct);
        }
        catch (PostgresException) { await tx.RollbackAsync("case_links", ct); foreach (var row in rows.OfType<JsonObject>()) row["linked_case"] = null; }
    }
    internal static JsonObject? LinkedCase(JsonObject item, ProblemAccess access, IReadOnlyList<IReadOnlyList<AccessResource>> groups)
    {
        string? report = InvestigationList.ReportKey(access.Decision);
        return report is not null && InvestigationList.Allowed(access.Decision, report, groups)
            ? ProblemJson.Pick(item, "id", "public_id", "status") : null;
    }
}
