using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Registry;
using Sli.Server.Auth.Lifecycle.Security;

namespace Sli.Server.Semantic;

internal sealed record SemanticAction(string Kind, DateTimeOffset At, string Key, JsonObject Attributes, IReadOnlyList<SemanticEvent> Evidence)
{
    internal string Status => "observed";
    internal Guid Id => AuthAudit.Uuid5("adlog:canonical:" + Key);
    internal string Sha => SemanticJson.Hash(new JsonObject { ["action_kind"] = Kind, ["deduplication_key"] = Key, ["attributes"] = Attributes.Copy() });
}
internal static class SemanticAssembly
{
    internal static readonly HashSet<string> Authentication = ["authentication.session.created", "authentication.session.ended", "authentication.logout.requested", "authentication.session.failed", "authentication.explicit_credentials.used", "authentication.privileged_session.created", "authentication.kerberos.tgt.requested", "authentication.kerberos.service_ticket.requested", "authentication.kerberos.service_ticket.renewed", "authentication.kerberos.preauthentication.failed", "authentication.kerberos.service_ticket.failed", "authentication.credentials.validated", "remote_access.authentication.allowed", "remote_access.authentication.denied"];
    internal static IReadOnlyList<SemanticAction> Assemble(IEnumerable<SemanticEvent> events)
    {
        var grouped = new Dictionary<(string Kind, string Material), (JsonObject Material, List<SemanticEvent> Events)>();
        foreach (var ev in events)
        {
            string? kind = null; var material = new JsonObject();
            void Role(string key) => material[key] = ev.Roles[key].Copy();
            void Fact(string key) { string? value = ev.Facts.Text(key); material[key] = string.IsNullOrWhiteSpace(value) ? null : UnicodeCaseFold.Fold(value.Trim()); }
            string Bucket() => SemanticJson.Stamp(ev.At.AddMinutes(-(ev.At.Minute % 5)).AddTicks(-(ev.At.Ticks % TimeSpan.TicksPerMinute)));
            Role("source_host");
            switch (ev.Type)
            {
                case "directory.attribute.changed.fragment":
                    kind = "directory.attribute.changed"; Fact("object"); Fact("attribute"); material["actor"] = ev.Roles.Text("actor") is { } actor ? UnicodeCaseFold.Fold(actor.Trim()) : null; Fact("operation_correlation_id");
                    if (material["operation_correlation_id"] is null) { material.Remove("operation_correlation_id"); material["time_bucket"] = Bucket(); material["uncorrelated_fragment_event_id"] = ev.Source; }
                    if (material["object"] is null || material["attribute"] is null || material["actor"] is null) material["incomplete_fragment_event_id"] = ev.Source;
                    break;
                case "service.installed.fragment":
                    kind = "service.installed"; Fact("service_name"); Fact("service_file"); Fact("service_account"); material["time_bucket"] = Bucket(); material["source_event_id"] = ev.Source;
                    if (material["service_name"] is null || material["service_file"] is null) material["incomplete_fragment_event_id"] = ev.Source; break;
                case "eventlog.cleared.fragment":
                    kind = "eventlog.cleared"; Fact("cleared_log"); material["time_bucket"] = Bucket(); material["source_event_id"] = ev.Source;
                    if (material["cleared_log"] is null) material["incomplete_fragment_event_id"] = ev.Source; break;
                case "audit.policy.changed":
                    kind = ev.Type; material["actor"] = ev.Roles.Text("actor") is { } auditActor ? UnicodeCaseFold.Fold(auditActor.Trim()) : null; Fact("audit_subcategory_guid"); Fact("audit_policy_changes"); material["source_event_id"] = ev.Source;
                    if (material["actor"] is null || material["audit_subcategory_guid"] is null || material["audit_policy_changes"] is null) material["incomplete_event_id"] = ev.Source; break;
                case "group.member.added":
                    kind = ev.Type; material["actor"] = ev.Roles.Text("actor") is { } groupActor ? UnicodeCaseFold.Fold(groupActor.Trim()) : null; Fact("group"); Fact("member"); Fact("group_scope"); material["source_event_id"] = ev.Source;
                    if (material["source_host"] is null || material["group"] is null || material["member"] is null) material["incomplete_event_id"] = ev.Source; break;
                case "scheduled_task.created.fragment":
                    // Security 4698 is observed but the first assembler only accepts the task creation identity it knows.
                    kind = "scheduled_task.created"; Fact("task_name"); Fact("task_instance_id"); Fact("task_user_context"); material["source_event_id"] = ev.Source;
                    if (material["source_host"] is null || material["task_name"] is null) material["incomplete_event_id"] = ev.Source; break;
                default:
                    if (Authentication.Contains(ev.Type)) { kind = ev.Type; Role("session_principal"); material["source_event_id"] = ev.Source; }
                    break;
            }
            if (kind is null) continue;
            // Python groups and orders actions by the canonical material JSON, not its hash.
            string key = CanonicalJson.Serialize(material, ensureAscii: false); var groupKey = (kind, key);
            if (!grouped.TryGetValue(groupKey, out var group)) grouped[groupKey] = group = (material, new()); group.Events.Add(ev);
        }
        var result = new List<SemanticAction>();
        foreach (var ((kind, _), group) in grouped.OrderBy(x => x.Key.Kind, StringComparer.Ordinal).ThenBy(x => x.Key.Material, StringComparer.Ordinal))
        {
            var ordered = group.Events.OrderBy(x => x.At).ThenBy(x => x.Source).ToArray();
            var attributes = new JsonObject { ["material_identity"] = group.Material.Copy(), ["semantic_contract_version"] = 1 };
            if (Authentication.Contains(kind))
            {
                attributes["source_evidence"] = new JsonArray(ordered.Select(x => (JsonNode)new JsonObject { ["source_event_id"] = x.Source, ["semantic_sha256"] = x.Sha }).ToArray());
                attributes["observed_facts"] = new JsonArray(ordered.Select(x => x.Facts.Copy()).ToArray()); attributes["observed_roles"] = new JsonArray(ordered.Select(x => x.Roles.Copy()).ToArray()); attributes["session_independent"] = kind.StartsWith("remote_access.", StringComparison.Ordinal);
            }
            if (kind == "directory.attribute.changed")
            {
                foreach (string field in new[] { "added_values", "removed_values" }) attributes[field] = new JsonArray(ordered.SelectMany(x => x.Facts[field]?.AsArray().Select(v => v!.GetValue<string>()) ?? []).Distinct().Order(StringComparer.Ordinal).Select(x => JsonValue.Create(x)).ToArray());
                attributes["quality"] = attributes["added_values"]!.AsArray().Count > 0 && attributes["removed_values"]!.AsArray().Count > 0 ? "complete" : "partial";
                attributes["identity_quality"] = group.Material["operation_correlation_id"] is not null ? "exact_correlation_id" : "correlation_id_missing";
            }
            string key = SemanticJson.Hash(new JsonObject { ["action_kind"] = kind, ["material_identity"] = group.Material.Copy() });
            result.Add(new(kind, ordered[0].At, key, attributes, ordered));
        }
        return result;
    }
}
