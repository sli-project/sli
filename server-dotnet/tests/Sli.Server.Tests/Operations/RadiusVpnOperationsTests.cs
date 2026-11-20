using System.Net;
using System.Text.Json.Nodes;
using Xunit;

namespace Sli.Server.Tests.Operations;

// Public projection vectors from tests/sources/test_radius_vpn_operations.py.
public sealed class RadiusVpnOperationsTests
{
    static JsonObject Row() => new()
    {
        ["source_activation"] = "disabled",
        ["subscription_activation"] = "disabled",
        ["queued_delivery_count"] = 0,
        ["leased_delivery_count"] = 0,
        ["failed_delivery_count"] = 0,
        ["quarantined_delivery_count"] = 0,
        ["projected_session_count"] = 8,
        ["identity_unresolved_count"] = 23,
        ["timestamp_unresolved_count"] = 0,
        ["direct_capability_assignment_count"] = 0,
        ["package_capability_mapping_count"] = 0,
        ["ephemeral_login_exists"] = false,
        ["manual_worker_session_exists"] = false,
        ["continuous_runtime_enabled"] = false,
        ["autostart_enabled"] = false,
        ["resource_profile_id"] = "stage9-radius-manual-bounded-v1"
    };

    static async Task<JsonObject> PublicItem(JsonObject row)
    {
        using var app = await OperationsEndpointTests.Start();
        app.Queries.Radius = new JsonArray(row);
        using var response = await OperationsEndpointTests.Request(app, "GET", "/api/v1/operations/overview");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await OperationsEndpointTests.Body(response);
        var pilot = body["plugin_pilots"]!["vpn_radius"]!;
        Assert.Equal("sli.radius-vpn-operations.v1", (string?)pilot["contract_id"]);
        Assert.Equal("ok", (string?)pilot["status"]);
        Assert.False((bool)pilot["contains_identity_or_event_payload"]!);
        return Assert.Single(pilot["items"]!.AsArray())!.AsObject();
    }

    [Fact]
    public async Task ManualPilotKeepsSourceWorkerQueueDatasetAndAccessStatesSeparate()
    {
        var item = await PublicItem(Row());
        Assert.Equal("bundled_supervised_production", (string?)item["plugin_state"]);
        Assert.Equal("disabled", (string?)item["source_state"]);
        Assert.Equal("manual_idle", (string?)item["worker_state"]);
        Assert.Equal("drained", (string?)item["queue_state"]);
        Assert.Equal("partial", (string?)item["dataset_state"]);
        Assert.Equal("owner_only", (string?)item["access_state"]);
        var profile = item["resource_profile"]!;
        Assert.Equal("configured_manual_inactive", (string?)profile["status"]);
        Assert.False((bool)profile["ready_for_long_lived_worker"]!);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"value":1000,"unit":"records"}"""),
            profile["declared_limits"]!["records_per_run"]));
    }

    [Fact]
    public async Task PendingAndFailureStatesRemainVisible()
    {
        var pendingRow = Row(); pendingRow["queued_delivery_count"] = 2;
        var pending = await PublicItem(pendingRow);
        Assert.Equal("pending_manual", (string?)pending["queue_state"]);
        var failureRow = Row(); failureRow["failed_delivery_count"] = 1; failureRow["ephemeral_login_exists"] = true;
        var failure = await PublicItem(failureRow);
        Assert.Equal("attention", (string?)failure["queue_state"]);
        Assert.Equal("attention", (string?)failure["worker_state"]);
    }

    [Theory]
    [InlineData(0, 0, "not_collected")]
    [InlineData(0, 2, "identity_incomplete")]
    [InlineData(2, 0, "available")]
    public async Task DatasetDistinguishesAbsentIncompleteAndAvailable(int projected, int unresolved, string expected)
    {
        var row = Row(); row["projected_session_count"] = projected; row["identity_unresolved_count"] = unresolved;
        Assert.Equal(expected, (string?)(await PublicItem(row))["dataset_state"]);
    }

    [Fact]
    public async Task UnknownResourceProfileIsVisibleWithoutDefaulting()
    {
        var row = Row(); row["resource_profile_id"] = "unknown-profile";
        var item = await PublicItem(row);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"status":"not_registered","profile_id":"unknown-profile","ready_for_long_lived_worker":false}"""),
            item["resource_profile"]));
    }
}
