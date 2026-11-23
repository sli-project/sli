using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Gpo.SnapshotModel;
using static Sli.Server.Gpo.GpoJson;
using static Sli.Server.Gpo.GpoPolicyCard;

namespace Sli.Server.Gpo;

internal sealed record GpoPolicySnapshot(Guid Id, DateTimeOffset ObservedAt, JsonObject? Payload = null);

internal interface IGpoSnapshotReadStore
{
    Task<IReadOnlyList<GpoPolicySnapshot>> PolicySnapshotsAsync(long domain, string policyId,
        (Guid Before, Guid After)? comparison, CancellationToken ct);
}

internal static class GpoSnapshotComparison
{
    readonly record struct SettingKey(string Side, string Extension, string Path, string Name);

    internal static async Task<JsonObject> QueryAsync(IGpoSnapshotReadStore store, GpoRequest request, CancellationToken ct)
    {
        string policyId = request.PolicyId!;
        var selection = request.ComparePolicySnapshots;
        var snapshots = await store.PolicySnapshotsAsync(request.DomainId!.Value, policyId, selection, ct);
        if (selection is not { } pair)
        {
            var choices = Array(snapshots.Select(snapshot => new JsonObject
            {
                ["id"] = snapshot.Id.ToString("D"),
                ["observed_at"] = Iso(snapshot.ObservedAt),
            }));
            return GpoReport.Result("ok", collections: new JsonObject { ["snapshots"] = choices });
        }

        var before = snapshots.FirstOrDefault(snapshot => snapshot.Id == pair.Before)?.Payload;
        var after = snapshots.FirstOrDefault(snapshot => snapshot.Id == pair.After)?.Payload;
        if (before is null || after is null)
            return GpoReport.Result("empty", coverage: new JsonObject { ["snapshot_comparison_state"] = "unavailable" });

        return GpoReport.Result("ok", collections: new JsonObject { ["snapshot_comparison"] = Compare(before, after, policyId) });
    }

    private static JsonArray Compare(JsonObject before, JsonObject after, string policyId)
    {
        var earlier = Settings(before, policyId);
        var later = Settings(after, policyId);
        var differences = new JsonArray();
        var noValues = new Dictionary<string, JsonNode?>();
        foreach (var key in earlier.Keys.Union(later.Keys).OrderBy(key => key.Side, StringComparer.Ordinal)
                     .ThenBy(key => key.Name, StringComparer.Ordinal).ThenBy(key => key.Path, StringComparer.Ordinal)
                     .ThenBy(key => key.Extension, StringComparer.Ordinal))
        {
            var oldValues = earlier.GetValueOrDefault(key, noValues);
            var newValues = later.GetValueOrDefault(key, noValues);
            var removed = oldValues.Keys.Except(newValues.Keys).Order(StringComparer.Ordinal).ToArray();
            var added = newValues.Keys.Except(oldValues.Keys).Order(StringComparer.Ordinal).ToArray();
            if (removed.Length == 1 && added.Length == 1)
            {
                Add(key, "changed", oldValues[removed[0]], newValues[added[0]]);
                continue;
            }
            // Several values can share a path in the XML. There is no evidence for pairing an ambiguous remainder.
            foreach (string value in removed) Add(key, "removed", oldValues[value], null);
            foreach (string value in added) Add(key, "added", null, newValues[value]);
        }

        return differences;

        void Add(SettingKey key, string kind, JsonNode? oldValue, JsonNode? newValue) => differences.Add(new JsonObject
        {
            ["id"] = differences.Count + 1,
            ["side"] = key.Side,
            ["setting_name"] = Bounded(JsonValue.Create(key.Name)),
            ["path"] = Bounded(JsonValue.Create(key.Path)),
            ["kind"] = kind,
            ["before_value"] = oldValue?.DeepClone(),
            ["after_value"] = newValue?.DeepClone(),
        });
    }

    private static Dictionary<SettingKey, Dictionary<string, JsonNode?>> Settings(JsonObject snapshot, string policyId)
    {
        var settings = Array(snapshot.Rows("settings").Where(row => row.Text("gpo_id") == policyId));
        var redacted = JsonNode.Parse(GpoSnapshotDocument.Redact(JsonSerializer.SerializeToElement(settings)).GetRawText());
        // The collector's row ID includes the value. Match its structural fields before comparing visible values.
        return redacted.Rows().Where(row => row.Text("side") is "computer" or "user")
            .GroupBy(row => new SettingKey(row.Text("side"), row.Text("extension"), row.Text("path"), row.Text("setting_name")))
            .ToDictionary(group => group.Key, group => group.Select(row => Bounded(row["value_display"]))
                .Select(value => (Key: value?.ToJsonString() ?? "null", Value: value)).DistinctBy(value => value.Key)
                .ToDictionary(value => value.Key, value => value.Value));
    }
}
