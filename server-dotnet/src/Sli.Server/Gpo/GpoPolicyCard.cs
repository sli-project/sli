using System.Text;
using System.Text.Json.Nodes;
using static Sli.Server.Gpo.GpoJson;

namespace Sli.Server.Gpo;

internal static class GpoPolicyCard
{
    private static JsonObject SnapshotUnavailable() => GpoReport.Result("not_collected",
        coverage: new JsonObject { ["reason"] = "gpo_snapshot_unavailable" });

    internal static async Task<JsonObject> ExactAsync(IGpoReadStore store, IGpoSnapshotReadStore snapshots,
        GpoRequest request, CancellationToken ct)
    {
        long domain = request.DomainId!.Value;
        var selected = await snapshots.ExactSnapshotAsync(domain, request.ExactSnapshot!.Value, ct);
        if (selected?.Payload is not { } snapshot) return SnapshotUnavailable();

        return await QueryAsync(store, new JsonObject { ["domain_id"] = domain }, snapshot, request.PolicyId!, request, ct, selected);
    }

    internal static async Task<JsonObject> QueryAsync(IGpoReadStore store, JsonObject pair, JsonObject snapshot,
        string policyId, GpoRequest request, CancellationToken ct, GpoPolicySnapshot? exact = null)
    {
        var policy = snapshot.Rows("gpos").FirstOrDefault(row => row.Text("id") == policyId);
        if (policy is null) return exact is null ? GpoReport.Result("empty") : SnapshotUnavailable();

        var settings = Select("settings", "side", "setting_name", "category", "path", "value_display");
        var links = Select("links", "scope_name", "order", "enabled", "enforced");
        var permissions = Select("permissions", "trustee_name", "permission");
        var current = Observation(snapshot, policy);
        if (exact is not null) current["observed_at"] = Iso(exact.ObservedAt);
        var versions = new JsonArray(current);
        long domain = pair.Number("domain_id");
        if (domain > 0 && pair.Number("previous_domain_id") == domain && pair["previous"] is JsonObject previous
            && previous.Text("observed_at") != snapshot.Text("observed_at")
            && previous.Rows("gpos").FirstOrDefault(row => row.Text("id") == policyId) is { } oldPolicy)
            versions.Add(Observation(previous, oldPolicy));

        bool historyRequested = request.Tab == "changes";
        var data = historyRequested ? new JsonObject() :
            new JsonObject { ["settings"] = settings, ["links"] = links, ["permissions"] = permissions, ["versions"] = versions };
        var coverage = new JsonObject { ["observed_at_utc"] = snapshot["observed_at"]?.DeepClone() };
        JsonArray? items = null;
        if (exact is not null)
        {
            coverage["observed_at_utc"] = Iso(exact.ObservedAt);
            coverage["domain_id"] = domain;
            coverage["snapshot_id"] = exact.Id.ToString("D");
            var header = Project(policy, "id", "display_name", "guid", "gpo_status");
            items = new JsonArray(header);
            var sources = new JsonObject();
            foreach (string source in new[] { "report", "links", "permissions" })
                sources[source] = Bounded(policy["source_states"]?[source]?["status"] ?? snapshot["source_states"]?[source]?["status"]);
            sources["gpt"] = Bounded(policy["source_states"]?["gpt"]?["status"] ?? policy["source_states"]?["sysvol_gpt"]?["status"]);
            coverage["policy_sources"] = sources;
        }
        if (historyRequested && domain > 0)
        {
            // The history reader uses a half-open interval and PostgreSQL timestamps have microsecond precision.
            var to = exact?.ObservedAt.AddTicks(10) ?? request.To;
            var from = exact is null ? request.From : to - (request.To - request.From);
            var history = await store.PolicyHistoryAsync([domain], from, to, policyId, policy.Text("guid"), ct);
            coverage["policy_history_state"] = history["state"]?.DeepClone();
            var names = settings.OfType<JsonObject>().ToDictionary(row => row.Text("id"), row => row.Text("setting_name"));
            var targets = links.OfType<JsonObject>().ToDictionary(row => row.Text("id"), row => row.Text("scope_name"));
            data["changes"] = Array(history.Rows("items").Where(Displayable).Select(change => {
                var row = Project(change, "id", "object_id", "object_type", "kind", "field", "observed_at", "before_value", "after_value");
                string? name = change.Text("object_type") switch {
                    "gpo_setting" => names.GetValueOrDefault(change.Text("object_id")),
                    "gpo_link" => targets.GetValueOrDefault(change.Text("object_id")),
                    _ => null,
                };
                row["name"] = name;
                return row;
            }));
        }
        return GpoReport.Result("ok", items, coverage, data);

        JsonArray Select(string collection, params string[] fields) => Array(snapshot.Rows(collection)
            .Where(row => row.Text("gpo_id") == policyId)
            .Select(row => Project(row, ["id", .. fields])));
    }

    static bool Displayable(JsonObject change) => (change.Text("object_type"), change.Text("field")) switch
    {
        ("gpo_setting", "" or "setting_name" or "value_display" or "category" or "path") => true,
        ("gpo_link", "" or "order" or "enabled" or "enforced") => true,
        ("gpo", "" or "display_name" or "modification_time" or "computer.directory_version" or "computer.sysvol_version"
            or "user.directory_version" or "user.sysvol_version") => true,
        _ => false,
    };

    static JsonObject Observation(JsonObject snapshot, JsonObject policy)
    {
        var versions = GpoInventory.Versions(policy);
        versions["observed_at"] = snapshot["observed_at"]?.DeepClone();
        return versions;
    }

    static JsonObject Project(JsonObject source, params string[] fields) => new(fields
        .Where(source.ContainsKey).Select(field => KeyValuePair.Create(field, Bounded(source[field]))));

    internal static JsonNode? Bounded(JsonNode? value) => value is JsonValue scalar && scalar.TryGetValue<string>(out var text)
        ? JsonValue.Create(string.Concat(text.EnumerateRunes().Take(2048).Select(rune => rune.ToString())))
        : value is JsonValue ? value.DeepClone() : null;
}
