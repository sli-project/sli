using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Gpo.SnapshotModel;
using static Sli.Server.Gpo.GpoJson;

namespace Sli.Server.Gpo;

internal sealed record GpoPolicySnapshot(Guid Id, DateTimeOffset ObservedAt, JsonObject? Payload = null);

internal interface IGpoSnapshotReadStore
{
    Task<GpoPolicySnapshot?> ExactSnapshotAsync(long domain, Guid snapshot, CancellationToken ct);
    IAsyncEnumerable<GpoPolicySnapshot> PolicySnapshotsAsync(long domain, string policyId,
        (Guid Before, Guid After)? comparison, CancellationToken ct);
}

internal static class GpoSnapshotComparison
{
    readonly record struct SettingKey(string Side, string Extension, string Path, string Name);
    sealed record Version(GpoPolicySnapshot Snapshot, JsonObject Numbers, Dictionary<SettingKey, Dictionary<string, JsonObject>> Settings);

    internal static async Task<JsonObject> QueryAsync(IGpoSnapshotReadStore store, GpoRequest request, CancellationToken ct)
    {
        string policyId = request.PolicyId!;
        var selection = request.ComparePolicySnapshots;
        var snapshots = store.PolicySnapshotsAsync(request.DomainId!.Value, policyId, selection, ct);
        if (selection is not { } pair)
        {
            var choices = await VersionChoicesAsync(snapshots, policyId, ct);
            return GpoReport.Result("ok", collections: new JsonObject { ["snapshots"] = choices });
        }

        JsonObject? before = null, after = null;
        await foreach (var snapshot in snapshots.WithCancellation(ct))
        {
            if (snapshot.Id == pair.Before) before = snapshot.Payload;
            if (snapshot.Id == pair.After) after = snapshot.Payload;
        }
        if (before is null || after is null)
            return GpoReport.Result("empty", coverage: new JsonObject { ["snapshot_comparison_state"] = "unavailable" });

        return GpoReport.Result("ok", collections: new JsonObject { ["snapshot_comparison"] = Compare(Settings(before, policyId), Settings(after, policyId)) });
    }

    private static async Task<JsonArray> VersionChoicesAsync(IAsyncEnumerable<GpoPolicySnapshot> snapshots, string policyId, CancellationToken ct)
    {
        var choices = new JsonArray();
        Version? current = null;
        await foreach (var snapshot in snapshots.WithCancellation(ct))
        {
            if (snapshot.Payload is not { } payload) continue;
            var policy = payload.Rows("gpos").FirstOrDefault(row => row.Text("id") == policyId);
            var next = new Version(snapshot, policy is null ? new() : GpoInventory.Versions(policy), Settings(payload, policyId));
            if (current is not null && (!JsonNode.DeepEquals(current.Numbers, next.Numbers) || !SameSettings(current.Settings, next.Settings)))
                choices.Add(Choice(current));
            // In descending order this keeps the earliest observation of the same version.
            current = next;
        }
        if (current is not null)
            choices.Add(Choice(current));
        return choices;

        static JsonObject Choice(Version version)
        {
            var row = version.Numbers;
            row["id"] = version.Snapshot.Id.ToString("D");
            row["observed_at"] = Iso(version.Snapshot.ObservedAt);
            return row;
        }
    }

    private static bool SameSettings(Dictionary<SettingKey, Dictionary<string, JsonObject>> before,
        Dictionary<SettingKey, Dictionary<string, JsonObject>> after) => before.Count == after.Count
        && before.All(entry => after.TryGetValue(entry.Key, out var values) && entry.Value.Count == values.Count
            && entry.Value.Keys.All(values.ContainsKey));

    private static JsonArray Compare(Dictionary<SettingKey, Dictionary<string, JsonObject>> earlier,
        Dictionary<SettingKey, Dictionary<string, JsonObject>> later)
    {
        var differences = new JsonArray();
        var noValues = new Dictionary<string, JsonObject>();
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
                Add("changed", oldValues[removed[0]], newValues[added[0]]);
                continue;
            }
            // Several values can share a path in the XML. There is no evidence for pairing an ambiguous remainder.
            foreach (string value in removed) Add("removed", oldValues[value], null);
            foreach (string value in added) Add("added", null, newValues[value]);
        }

        return differences;

        void Add(string kind, JsonObject? oldValue, JsonObject? newValue)
        {
            var setting = (newValue ?? oldValue)!;
            differences.Add(new JsonObject
            {
                ["id"] = differences.Count + 1,
                ["side"] = setting["side"]?.DeepClone(),
                ["category"] = setting["category"]?.DeepClone(),
                ["setting_name"] = setting["setting_name"]?.DeepClone(),
                ["path"] = setting["path"]?.DeepClone(),
                ["kind"] = kind,
                ["before_value"] = oldValue?["value_display"]?.DeepClone(),
                ["after_value"] = newValue?["value_display"]?.DeepClone(),
            });
        }
    }

    private static Dictionary<SettingKey, Dictionary<string, JsonObject>> Settings(JsonObject snapshot, string policyId)
    {
        var settings = Array(snapshot.Rows("settings").Where(row => row.Text("gpo_id") == policyId));
        var redacted = JsonNode.Parse(GpoSnapshotDocument.Redact(JsonSerializer.SerializeToElement(settings)).GetRawText());
        // The collector's row ID changes with the value or the collection format.
        return GpoSettings.RowsFor(redacted.Rows()).GroupBy(row => row.Text("category") == "Registry" && row.Text("path").Length > 0
                ? new SettingKey(row.Text("side"), "", row.Text("path").ToUpperInvariant(), "")
                : new SettingKey(row.Text("side"), row.Text("extension"), row.Text("path"), row.Text("setting_name")))
            .ToDictionary(group => group.Key, group => group.GroupBy(row => row["value_display"]?.ToJsonString() ?? "null")
                .ToDictionary(values => values.Key, values => values.First()));
    }
}
