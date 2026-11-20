using System.Text.Json.Nodes;
using Sli.Server.Ad;
using Xunit;

namespace Sli.Server.Tests.Ad;

public sealed class ComputersV6MetricsPartitionTests
{
    static readonly string[] Parts = ["ws", "srv", "unknown", "disabled", "unknown_state"];

    [Fact]
    public void V2_metrics_partition_matches_twenty_computer_reference_summary()
    {
        // The Python adapter receives this population as an already computed summary:
        // total=20, ws=10, srv=4, unknown enabled=1, disabled=4, unknown state=1.
        var rows = new List<JsonObject>();
        void Add(string type, bool? enabled, int count)
        {
            for (int i = 0; i < count; i++) rows.Add(new JsonObject
            {
                ["computer_type"] = type, ["enabled"] = enabled,
                ["reasons"] = rows.Count < 3 ? new JsonArray(new JsonObject { ["code"] = "fixture" }) : new JsonArray()
            });
        }
        Add("workstation", true, 10); Add("server", true, 4); Add("unknown", true, 1);
        Add("workstation", false, 3); Add("unknown", false, 1); Add("unknown", null, 1);

        var metrics = Metrics(rows);
        Assert.Equal(20, Value(metrics, "all")); Assert.Equal(3, Value(metrics, "attention"));
        Assert.Equal(10, Value(metrics, "ws")); Assert.Equal(4, Value(metrics, "srv"));
        Assert.Equal(1, Value(metrics, "unknown")); Assert.Equal(4, Value(metrics, "disabled"));
        Assert.Equal(1, Value(metrics, "unknown_state"));
        Assert.Equal(Value(metrics, "all"), Parts.Sum(key => Value(metrics, key)));
        AssertFilter(metrics, "unknown", """{"view":"all","type":"unknown","enabled":"enabled"}""");
        AssertFilter(metrics, "disabled", """{"view":"all","enabled":"disabled"}""");
        AssertFilter(metrics, "unknown_state", """{"view":"all","enabled":"unknown"}""");
    }

    [Theory]
    [InlineData("")]
    [InlineData("enabled")]
    [InlineData("disabled")]
    [InlineData("unknown")]
    public void Types_and_account_states_partition_before_filtering_and_paging(string enabledFilter)
    {
        var source = new JsonObject { ["domain_id"] = 1, ["fqdn"] = "example.test", ["entity_ids"] = new JsonObject() };
        var inputs = new List<(JsonObject Raw, JsonObject Row)>();
        foreach (string type in new[] { "workstation", "server", "unknown" })
        foreach (bool? enabled in new bool?[] { true, false, null })
        {
            int id = inputs.Count;
            string guid = new Guid(id + 1, 0, 0, new byte[8]).ToString();
            source["entity_ids"]![guid] = id;
            var raw = new JsonObject
            {
                ["objectGuid"] = guid, ["name"] = $"PC-{id}", ["enabled"] = enabled,
                ["classification"] = new JsonObject { ["result"] = type }
            };
            inputs.Add((raw, AdInventoryRows.Computer(raw, source, "2026-11-08T00:00:00Z", new())));
        }
        var rows = inputs.Select(i => i.Row).ToList();
        var metrics = Metrics(rows);
        Assert.Equal(9, Value(metrics, "all"));
        Assert.Equal(1, Value(metrics, "ws")); Assert.Equal(1, Value(metrics, "srv"));
        Assert.Equal(1, Value(metrics, "unknown")); Assert.Equal(3, Value(metrics, "disabled"));
        Assert.Equal(3, Value(metrics, "unknown_state"));
        Assert.Equal(9, Parts.Sum(key => Value(metrics, key)));
        Assert.Equal(3, inputs.Count(i => AdInventoryRows.Matches(Request(new JsonObject { ["view"] = "unknown_type" }), i.Raw, i.Row, false)));

        // Every metric selects exactly its counted population; no computer belongs to two parts.
        var partitioned = new List<int>();
        foreach (string key in Parts)
        {
            var request = Request(metrics[key]["filter"]!.DeepClone().AsObject());
            var selected = inputs.Where(i => AdInventoryRows.Matches(request, i.Raw, i.Row, false)).ToList();
            Assert.Equal(Value(metrics, key), selected.Count);
            partitioned.AddRange(selected.Select(i => i.Row["entity_id"]!.GetValue<int>()));
        }
        Assert.Equal(9, partitioned.Count); Assert.Equal(9, partitioned.Distinct().Count());

        var filteredRequest = Request(new JsonObject { ["view"] = "all", ["enabled"] = enabledFilter });
        var filtered = inputs.Where(i => AdInventoryRows.Matches(filteredRequest, i.Raw, i.Row, false)).Select(i => i.Row).ToList();
        var result = AdV2Store.Result("ad.computers.v6", "ok");
        result["metrics"] = AdV2Store.ComputerMetrics(rows);
        AdV2Store.Page(result, filteredRequest, filtered);
        Assert.Equal(enabledFilter.Length == 0 ? 9 : 3, result["filtered_count"]!.GetValue<int>());
        Assert.Equal(enabledFilter.Length == 0 ? 9 : 3, result["items"]!.AsArray().Count);
        if (enabledFilter.Length > 0) Assert.All(result["items"]!.AsArray(), row => Assert.Equal(enabledFilter, row!["account_state"]!.ToString()));
        Assert.True(JsonNode.DeepEquals(AdV2Store.ComputerMetrics(rows), result["metrics"]));
    }

    static AdV2Request Request(JsonObject parameters) => new("ad.computers.v6", "view", null, [1], parameters, "computers", null, false, 50, null, "UTC");
    static Dictionary<string, JsonObject> Metrics(List<JsonObject> rows) => AdV2Store.ComputerMetrics(rows).OfType<JsonObject>().ToDictionary(m => m["key"]!.ToString());
    static int Value(Dictionary<string, JsonObject> metrics, string key) => metrics[key]["value"]!.GetValue<int>();
    static void AssertFilter(Dictionary<string, JsonObject> metrics, string key, string expected) => Assert.True(JsonNode.DeepEquals(JsonNode.Parse(expected), metrics[key]["filter"]));
}
