using System.Text;
using System.Text.Json.Nodes;
using static Sli.Server.Gpo.GpoJson;

namespace Sli.Server.Gpo;

internal static class GpoPolicyCard
{
    internal static async Task<JsonObject> QueryAsync(IGpoReadStore store, JsonObject pair, JsonObject snapshot,
        string policyId, GpoRequest request, CancellationToken ct)
    {
        var policy = snapshot.Rows("gpos").FirstOrDefault(row => row.Text("id") == policyId);
        if (policy is null) return GpoReport.Result("empty");

        var settings = Select("settings", "side", "setting_name", "category", "path", "value_display");
        var links = Select("links", "scope_name", "order", "enabled", "enforced");
        var permissions = Select("permissions", "trustee_name", "permission");
        var current = Observation(snapshot, policy);
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
        if (historyRequested && domain > 0)
        {
            var history = await store.PolicyHistoryAsync([domain], request.From, request.To, policyId, policy.Text("guid"), ct);
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
        return GpoReport.Result("ok", coverage: coverage, collections: data);

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

    static JsonNode? Bounded(JsonNode? value) => value is JsonValue scalar && scalar.TryGetValue<string>(out var text)
        ? JsonValue.Create(string.Concat(text.EnumerateRunes().Take(2048).Select(rune => rune.ToString())))
        : value is JsonValue ? value.DeepClone() : null;
}
