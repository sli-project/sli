using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Storage.EventReports;

namespace Sli.Server.Entities;

public sealed partial class EntityReader
{
    static readonly HashSet<string> InterpretationFields = ["security", "technical", "raw_evidence"];
    static readonly string[] RelationCapabilities = ["semantic.review", "evidence.exact", "field.security", "events.view"];
    public async Task Interpretation(JsonObject payload, JsonObject entity, EntityReadOptions options, CapabilityDecisionSet caps, AccessDecision access, CancellationToken ct)
    {
        payload["security_actions"] = new JsonArray(); payload["semantic_relations"] = new JsonArray();
        payload["security_actions_state"] = "time_bounds_required"; payload["semantic_relations_state"] = "time_bounds_required";
        if (entity["domain_id"] is null || options.From is null || options.To is null) return;
        if (options.Limit is < 1 or > 500) throw new EntityInputException("security_events_limit_invalid");
        long domain = Number(entity, "domain_id");
        IReadOnlyList<IReadOnlyList<AccessResource>> groups = [[new("domain", domain)]];
        bool report = ResourceAccessDecisions.ReportAction(access, "security.events.chains", "view", groups, InterpretationFields).Allowed;
        payload["security_actions_state"] = "not_authorized"; payload["semantic_relations_state"] = "not_authorized";
        var args = new Dictionary<string, object> { ["domain"] = (int)domain, ["id"] = checked((int)Number(entity, "id")), ["start"] = DateTimeOffset.Parse(options.From, CultureInfo.InvariantCulture).UtcDateTime, ["end"] = DateTimeOffset.Parse(options.To, CultureInfo.InvariantCulture).UtcDateTime, ["limit"] = options.Limit + 1, ["ids"] = EntitySecurityProjection.EventIds };
        args["boundary"]=Boundary;
        string entityPredicate=EntityShortSql.MatchesStored("@id","@boundary");
        if (report && ResourceAccessDecisions.Capability(caps, "events.view", groups).Allowed)
        {
            var rows = await Read(ShortInterpretationActionsSql, args, ct, 5);
            var page = rows.OfType<JsonObject>().Where(row => Number(row,"server_id")>0 && Number(row,"domain_id")==domain
                && Text(row,"channel").Length>0 && Allows(caps,"events.view",row)
                && ResourceAccessDecisions.ReportAction(access,"security.events.chains","view",[Resources(row)],InterpretationFields).Allowed)
                .Take(options.Limit).ToArray();
            await ResolveActionEntities(page, (int)domain, ct);
            await HydrateActionFields(page, ct);
            var items = new JsonArray();
            foreach (var row in page) items.Add(EntitySecurityProjection.Present(row));
            EntitySecurityProjection.ApplyHistory(items);
            payload["security_actions"] = items;
            if (items.Count > 0) payload["security_actions_state"] = "available";
            else
            {
                var coverage = await Read("with short_events as ("+EntityShortSql.Source("@boundary",daily:false)+") "+"""
                    select exists(select 1 from short_events event join servers server on server.id=event.server_id and server.domain_id=event.domain_id
                      where event.domain_id=@domain and server.role='domain_controller' and event.event_id=any(@ids) and event.channel='Security'
                        and((event.event_id=1102 and event.provider_name='Microsoft-Windows-Eventlog') or(event.event_id<>1102 and event.provider_name='Microsoft-Windows-Security-Auditing'))) as history_event_present
                    """, args, ct, 5);
                payload["security_actions_state"] = coverage.FirstOrDefault()?["history_event_present"]?.GetValue<bool>() == true ? "empty_unverified" : "not_collected";
            }
        }
        if (options.Limit > 200) throw new EntityInputException("invalid_semantic_relation_filter");
        // A server/channel grant can be evaluated only after each atom is known.
        string preflight = RelationPreflight(caps, access, domain);
        if (preflight == "deny") return;
        try
        {
            args["scan_limit"] = preflight == "allow" ? options.Limit : options.Limit * 20;
            var candidates = await Read("with short_events as ("+EntityShortSql.Source("@boundary",daily:false)+") "+$"""
                select candidate.candidate_id,candidate.window_end_utc,
                  jsonb_agg(jsonb_build_object('event_db_id',core.id,'server_id',core.server_id,'domain_id',core.domain_id,
                    'channel',core.channel) order by evidence.evidence_order) as evidence
                from (select candidate.candidate_id,candidate.window_end_utc from semantic_correlation_candidates candidate
                  where candidate.candidate_status='matched' and candidate.window_start_utc<@end::timestamptz and candidate.window_end_utc>=@start::timestamptz
                    and candidate.rule_id in('investigation.account.lockout.preceded-by-failures','investigation.account.unlock.after-lock','investigation.group.membership.removed-after-add','investigation.account.created-then-group-add','investigation.password.reset-then-logon')
                    and candidate.rule_version=(select max(rule.rule_version) from semantic_correlation_rules rule where rule.rule_id=candidate.rule_id and rule.lifecycle_status in('test','shadow','enabled'))
                    and exists(select 1 from semantic_correlation_candidate_evidence selected_evidence
                      join normalized_events selected_normalized on selected_normalized.normalized_event_id=selected_evidence.normalized_event_id
                      join short_events event on event.id=selected_normalized.source_event_id join servers server on server.id=event.server_id and server.domain_id=event.domain_id
                      where selected_evidence.candidate_id=candidate.candidate_id and event.domain_id=@domain and server.role='domain_controller'
                        and event.event_id=any(@ids) and event.channel='Security'
                        and((event.event_id=1102 and event.provider_name='Microsoft-Windows-Eventlog') or(event.event_id<>1102 and event.provider_name='Microsoft-Windows-Security-Auditing'))
                        and event.time_created_utc>=@start and event.time_created_utc<@end and {entityPredicate})
                    and not exists(select 1 from semantic_correlation_candidate_evidence foreign_evidence
                      left join normalized_events foreign_normalized on foreign_normalized.normalized_event_id=foreign_evidence.normalized_event_id
                      left join short_events foreign_core on foreign_core.id=foreign_normalized.source_event_id
                      left join servers foreign_server on foreign_server.id=foreign_core.server_id and foreign_server.domain_id=foreign_core.domain_id
                      where foreign_evidence.candidate_id=candidate.candidate_id and (foreign_core.id is null or foreign_core.domain_id<>@domain or foreign_server.id is null or foreign_core.channel is null or foreign_core.provider_name is null))
                  order by candidate.window_end_utc desc,candidate.candidate_id desc limit @scan_limit) candidate
                join semantic_correlation_candidate_evidence evidence on evidence.candidate_id=candidate.candidate_id
                join normalized_events normalized on normalized.normalized_event_id=evidence.normalized_event_id
                join short_events core on core.id=normalized.source_event_id join servers server on server.id=core.server_id and server.domain_id=core.domain_id
                group by candidate.candidate_id,candidate.window_end_utc
                order by candidate.window_end_utc desc,candidate.candidate_id desc
                """, args, ct, 5);
            bool Authorized(JsonObject relation) => relation["evidence"] is JsonArray { Count: > 0 } evidence
                && evidence.OfType<JsonObject>().Count() == evidence.Count
                && evidence.OfType<JsonObject>().All(atom => new[] { "event_db_id", "server_id", "domain_id" }.All(key => atom[key] is not null && long.TryParse(Text(atom, key), out long value) && value > 0)
                    && Text(atom, "channel").Trim().Length > 0 && RelationCapabilities.All(key => Allows(caps, key, atom))
                    && ResourceAccessDecisions.ReportAction(access, "security.events.chains", "view", [Resources(atom)], InterpretationFields).Allowed);
            var admitted = candidates.OfType<JsonObject>().Where(Authorized).Take(options.Limit).Select(r => Guid.Parse(Text(r, "candidate_id"))).ToArray();
            var hydrated = admitted.Length == 0 ? new JsonArray() : await Read("with short_events as ("+EntityShortSql.Source("@boundary",daily:false)+") "+"""
                select candidate.candidate_id,candidate.rule_id,candidate.rule_version,candidate.relation_kind,candidate.partition_key,
                  candidate.window_start_utc,candidate.window_end_utc,candidate.confidence,candidate.explanation,
                  jsonb_agg(jsonb_build_object('event_db_id',core.id,'event_id',core.event_id,'time_created_utc',core.time_created_utc,
                    'semantic_type',normalized.semantic_type,'source_host',server.hostname,'server_id',core.server_id,'domain_id',core.domain_id,
                    'channel',core.channel,'evidence_order',evidence.evidence_order) order by evidence.evidence_order) as evidence
                from semantic_correlation_candidates candidate join semantic_correlation_candidate_evidence evidence on evidence.candidate_id=candidate.candidate_id
                join normalized_events normalized on normalized.normalized_event_id=evidence.normalized_event_id
                join short_events core on core.id=normalized.source_event_id join servers server on server.id=core.server_id and server.domain_id=core.domain_id
                where candidate.candidate_id=any(@candidates)
                group by candidate.candidate_id,candidate.rule_id,candidate.rule_version,candidate.relation_kind,candidate.partition_key,candidate.window_start_utc,candidate.window_end_utc,candidate.confidence,candidate.explanation
                order by candidate.window_end_utc desc,candidate.candidate_id desc
                """, new() { ["candidates"] = admitted, ["boundary"] = Boundary }, ct, 5);
            var items = new JsonArray();
            if (hydrated.Count != admitted.Length || hydrated.OfType<JsonObject>().Any(r => !admitted.Contains(Guid.Parse(Text(r, "candidate_id"))) || !Authorized(r)))
            { payload["semantic_relations_state"] = "empty"; return; }
            foreach (var relation in hydrated.OfType<JsonObject>())
            {
                var item = (JsonObject)relation.DeepClone();
                item.Remove("partition_key");
                var basis = EntitySecurityProjection.IdentityBasis(Text(relation, "partition_key")); if (basis is not null) item["identity_basis"] = basis;
                var atoms = (JsonArray)item["evidence"]!;
                foreach (var atom in atoms.OfType<JsonObject>()) { atom.Remove("server_id"); atom.Remove("domain_id"); }
                if (new[] { "investigation.account.unlock.after-lock", "investigation.group.membership.removed-after-add", "investigation.account.created-then-group-add", "investigation.password.reset-then-logon" }.Contains(Text(item, "rule_id")) && Number(item, "rule_version") >= 2)
                {
                    for (int i = 0; i < atoms.Count; i++) atoms[i]!["evidence_role"] = i == 0 ? "anchor" : "alternative_continuation";
                    item["continuation_state"] = atoms.Count == 2 ? "unique" : "ambiguous"; item["possible_continuation_count"] = Math.Max(0, atoms.Count - 1);
                }
                items.Add(item); if (items.Count == options.Limit) break;
            }
            payload["semantic_relations_state"] = items.Count == 0 ? "empty" : "available";
            // The composition owner publishes items only for the available state.
            if (items.Count > 0) payload["semantic_relations"] = items;
        }
        catch (PostgresException error) when (error.SqlState is "42P01" or "42703") { payload["semantic_relations_state"] = "schema_unavailable"; }
    }
    internal static string RelationPreflight(CapabilityDecisionSet caps, AccessDecision access, long domain)
    {
        string Scope(System.Text.Json.JsonElement scope)
        {
            string kind = scope.Text("kind");
            if (kind == "all") return "allow";
            if (kind is "server" or "channel") return "potential";
            if (kind == "domain")
            {
                try { return scope.Get("ids").Items().Select(Sli.Server.Access.Administration.AssignmentValidation.Integer).Any(id => id == domain) ? "allow" : "deny"; }
                catch (Exception error) when (error is ArgumentException or InvalidOperationException or Sli.Server.Access.Administration.AssignmentValidationException) { return "deny"; }
            }
            return "deny";
        }
        string Combine(IEnumerable<string> states) => states.Contains("allow") ? "allow" : states.Contains("potential") ? "potential" : "deny";
        var report = access.Reports.FirstOrDefault(r => r.ReportKey == "security.events.chains" && r.Allowed);
        string reportState = report is null ? "deny" : Combine(report.Grants.Where(g => g.AllowedActions.Contains("view") && InterpretationFields.IsSubsetOf(g.FieldCategories)).Select(g => Scope(g.Scope)).ToArray());
        var states = new List<string> { reportState };
        foreach (string key in RelationCapabilities)
        {
            if (caps.IsOwner) { states.Add("allow"); continue; }
            var policies = caps.Policies.Where(p => p.CapabilityKey == key).ToArray();
            if (policies.Any(p => p.Effect == "deny" && !p.Valid)) { states.Add("deny"); continue; }
            var denies = policies.Where(p => p.Effect == "deny" && p.Valid).Select(p => Scope(p.Scope)).ToArray();
            if (denies.Contains("allow")) { states.Add("deny"); continue; }
            string allowed = caps.Capabilities.Contains(key) ? "allow" : Combine(policies.Where(p => p.Effect == "allow" && p.Valid).Select(p => Scope(p.Scope)).ToArray());
            states.Add(allowed == "allow" && denies.Contains("potential") ? "potential" : allowed);
        }
        return states.Contains("deny") ? "deny" : states.Contains("potential") ? "potential" : "allow";
    }
    async Task ResolveActionEntities(JsonObject[] rows, int domain, CancellationToken ct)
    {
        string[] fields = ["subject_user_sid", "target_user_sid", "membership_member_sid"];
        string[] ids = ["actor_entity_id", "target_entity_id", "member_entity_id"];
        var sids = rows.SelectMany(r => fields.Select(k => Text(r, k).Trim().ToLowerInvariant())).Where(v => v.Length > 0).Distinct().ToArray();
        foreach (var row in rows) foreach (string key in ids) row[key] = null;
        if (sids.Length == 0) return;
        var aliases = await Read("""
            select alias.normalized_value,alias.entity_id from ad_context_entity_aliases alias join entities_v2 alias_entity on alias_entity.id=alias.entity_id
            where alias.domain_id=@domain and alias.alias_type='object_sid' and alias.normalized_value=any(@sids)
              and alias_entity.domain_id=alias.domain_id and entity_v2_is_active(alias.entity_id)
            """, new() { ["domain"] = domain, ["sids"] = sids }, ct, 5);
        var resolved = aliases.OfType<JsonObject>().GroupBy(r => Text(r, "normalized_value").ToLowerInvariant())
            .Select(g => (Sid: g.Key, Ids: g.Select(r => Number(r, "entity_id")).Distinct().ToArray())).Where(g => g.Ids.Length == 1).ToDictionary(g => g.Sid, g => g.Ids[0]);
        foreach (var row in rows) for (int i = 0; i < fields.Length; i++) if (resolved.TryGetValue(Text(row, fields[i]).Trim().ToLowerInvariant(), out long id)) row[ids[i]] = id;
    }
    async Task HydrateActionFields(JsonObject[] rows, CancellationToken ct)
    {
        if (rows.Length == 0) return;
        var reader = services.GetService<IEventReadService>();
        if (reader is null) throw new InvalidOperationException("event_reads_not_registered");
        foreach (var batch in rows.Chunk(100))
        {
            var ids = batch.Select(r => Number(r, "event_db_id")).ToArray();
            // Bind detail hydration to the same server/domain/channel that was
            // admitted above, including when the event reader uses another session.
            foreach (var row in batch) {
                var actual = await reader.ResourcesAsync(Number(row,"event_db_id"),ct);
                var expected = Resources(row);
                if (actual.Count != expected.Count || expected.Any(resource => !actual.Contains(resource)))
                    throw new InvalidDataException("entity_action_resource_mismatch");
            }
            Dictionary<long, JsonObject> details;
            try
            {
                details = await reader.DetailsAsync(ids, false, (id, token) => Task.FromResult(ids.Contains(id)), ct);
            }
            catch (Exception error) when (!ct.IsCancellationRequested && error is IOException or InvalidOperationException or ArgumentException or EventReadConfigurationException)
            {
                string state = error is InvalidDataException ? "partial_archive_corrupt" : error is FileNotFoundException ? "partial_archive_missing" : "partial_archive_unavailable";
                foreach (var row in batch) row["archive_field_state"] = state;
                continue;
            }
            if (details.Keys.Any(id => !ids.Contains(id))) throw new InvalidDataException("unauthorized_hydration_result");
            foreach (var row in batch)
            {
                if (!details.TryGetValue(Number(row, "event_db_id"), out var detail) || detail["event_data"] is not JsonObject data)
                { row["archive_field_state"] = "partial_archive_missing"; continue; }
                var fields = new Dictionary<string, string>();
                foreach (var (source, destination) in new[] { ("CallerComputerName", "caller_computer"), ("CallerComputer", "caller_computer"), ("MemberSid", "membership_member_sid"), ("MemberName", "membership_member_name"), ("TargetSid", "target_user_sid"), ("TargetUserSid", "target_user_sid"), ("TargetUserName", "target_user_name"), ("GroupName", "target_user_name"), ("OldTargetUserName", "account_name_before"), ("NewTargetUserName", "account_name_after"), ("OldAccountName", "account_name_before"), ("NewAccountName", "account_name_after") })
                    if (data[source] is JsonValue value && value.TryGetValue<string>(out var text) && !string.IsNullOrWhiteSpace(text)) fields[destination] = text.Trim();
                foreach (var (destination, value) in fields) if (string.IsNullOrWhiteSpace(Text(row, destination))) row[destination] = value;
                if (EntitySecurityProjection.SourceChange(checked((int)Number(row, "event_id")), data) is { } change) row["source_native_change"] = change;
            }
        }
    }
}
