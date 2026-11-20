using System.Text.Json.Nodes;
using Sli.Server.Operations;
using Xunit;

namespace Sli.Server.Tests.Operations;

public sealed class OperationsCollectionProgressTests
{
    static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-05T12:00:00Z");
    static JsonObject J(string json) => JsonNode.Parse(json)!.AsObject();
    static JsonObject Collector() => J("""
        {"items":[
          {"server":"DC1","channel":"System","collection_label":"проверка сильно отстаёт","collection_severity":"high","event_observation_label":"нужна новая проверка канала","event_observation_severity":"warn"},
          {"server":"DC1","channel":"Security","collection_label":"есть задержка проверки","collection_severity":"warn","event_observation_label":"события догоняются","event_observation_severity":"warn"},
          {"server":"DC2","channel":"Security","collection_label":"проверка сильно отстаёт","collection_severity":"high","event_observation_label":"нужна новая проверка канала","event_observation_severity":"warn"}
        ]}
        """);
    static JsonObject Progress(string status = "running")
    {
        var result = J("""
            {"items":[
              {"server":"DC1","channel":"System","boundary_reached":true,"recovery_mode":false,"check_state":"current"},
              {"server":"DC1","channel":"Security","boundary_reached":false,"recovery_mode":true},
              {"server":"DC2","channel":"Security","boundary_reached":false,"recovery_mode":false}
            ]}
            """);
        result["status"] = status; result["worker_status"] = status; result["job_status"] = status;
        return result;
    }
    static string?[] Values(JsonObject collector, string key) => collector["items"]!.AsArray().Select(i => (string?)i![key]).ToArray();

    [Fact]
    public void LiveProgressReplacesStaleWordingWithoutChangingEventObservations()
    {
        var collector = Collector();
        var observations = Values(collector, "event_observation_label");
        collector = OperationsCollector.ApplyProgress(collector, Progress());
        Assert.Equal(new[] { "граница прочитана при последней успешной проверке", "канал догоняет границу", "проверяется текущая граница" }, Values(collector, "collection_label"));
        Assert.Equal(new[] { "ok", "warn", "warn" }, Values(collector, "collection_severity"));
        Assert.Equal(observations, Values(collector, "event_observation_label"));
        Assert.Equal(new[] { "warn", "warn", "warn" }, Values(collector, "event_observation_severity"));
    }

    [Fact]
    public void MergePreservesTheOriginalCollector()
    {
        var collector = Collector(); var before = collector.DeepClone();
        OperationsCollector.ApplyProgress(collector, Progress());
        Assert.True(JsonNode.DeepEquals(before, collector));
    }

    [Fact]
    public void FailedWorkerDoesNotMaskCollectorWarnings()
    {
        var collector = Collector(); var before = collector.DeepClone();
        var result = OperationsCollector.ApplyProgress(collector, Progress("failed"));
        Assert.True(JsonNode.DeepEquals(before, result));
        Assert.True(JsonNode.DeepEquals(before, collector));
    }

    [Fact]
    public void SleepingWorkerKeepsCurrentBoundarySeparateFromEventAge()
    {
        var collector = Collector();
        collector = OperationsCollector.ApplyProgress(collector, Progress("partial"));
        Assert.Equal(new[] { "граница прочитана при последней успешной проверке", "канал ожидает следующую bounded-порцию", "проверка сильно отстаёт" }, Values(collector, "collection_label"));
        Assert.Equal("нужна новая проверка канала", (string?)collector["items"]![0]!["event_observation_label"]);
        Assert.Equal("warn", (string?)collector["items"]![0]!["event_observation_severity"]);
    }

    [Fact]
    public void CompletedSecurityOutsideRecoveryIsADurableBoundary()
    {
        var collector = J("""{"items":[{"server":"DC2","channel":"Security","last_status":"completed","recovery_mode":false,"adaptive_action":"keep:completed_streak; 50000->50000; recovery=off","adaptive_limit":50000}]}""");
        var worker = J("""{"worker_name":"collection","status":"partial","details":{"last_result":{"job_id":8,"status":"partial"}}}""");
        var result = OperationsCollector.Progress(collector, worker, new(), Now);
        Assert.Equal(1, OpsJson.N(result["boundaries_reached"]));
        Assert.Equal(0, OpsJson.N(result["channels_in_recovery"]));
        Assert.True((bool)result["items"]![0]!["boundary_reached"]!);
    }

    [Theory]
    [InlineData("completed", "2020-01-01T00:00:00Z", "stale")]
    [InlineData("failed", "2020-01-01T00:00:00Z", "error")]
    [InlineData("access_denied", "2020-01-01T00:00:00Z", "error")]
    [InlineData("completed", null, "stale")]
    public void HistoricalBoundaryDoesNotConfirmCurrentHealth(string status, string? checkedAt, string state)
    {
        var collector = J("""{"items":[{"server":"fixture-node","channel":"Security","last_event_time_utc":"2019-01-01T00:00:00Z","adaptive_action":"exit_recovery:source_boundary_reached","collection_severity":"high","collection_label":"previous check is old","event_observation_label":"old event"}]}""");
        collector["items"]![0]!["last_status"] = status;
        collector["items"]![0]!["last_successful_collection_utc"] = checkedAt;
        var progress = OperationsCollector.Progress(collector, null, new(), Now);
        Assert.Equal(state == "error" ? "failed" : "stale", (string?)progress["status"]);
        Assert.True((bool)progress["items"]![0]!["boundary_reached"]!);
        Assert.Equal(state, (string?)progress["items"]![0]!["check_state"]);
        Assert.Equal(checkedAt, (string?)progress["items"]![0]!["boundary_checked_at_utc"]);
        collector = OperationsCollector.ApplyProgress(collector, progress);
        Assert.Equal("high", (string?)collector["items"]![0]!["collection_severity"]);
        Assert.Equal("old event", (string?)collector["items"]![0]!["event_observation_label"]);
    }

    static JsonObject RecentlyCheckedCollector()
    {
        var collector = J("""{"items":[{"server":"fixture-node","channel":"System","last_status":"completed","last_event_time_utc":"2019-01-01T00:00:00Z"}]}""");
        collector["items"]![0]!["last_successful_collection_utc"] = Now.ToString("O");
        return collector;
    }

    [Fact]
    public void RecentCheckWithOldEventConfirmsCurrentBoundary()
    {
        var result = OperationsCollector.Progress(RecentlyCheckedCollector(), null, new(), Now);
        Assert.Equal("completed", (string?)result["status"]);
        Assert.Equal("current", (string?)result["items"]![0]!["check_state"]);
    }

    [Fact]
    public void RuntimeBlockPreservesReasonAndConfirmedDate()
    {
        var collector = RecentlyCheckedCollector(); collector["items"]![0]!["channel"] = "Security";
        var collection = J("""{"collection_block_reason":"windows_event_log_access_denied","collection_block":{"first_seen_at":"2026-10-01T00:00:00Z"}}""");
        var result = OperationsCollector.Progress(collector, null, collection, Now);
        Assert.Equal("blocked", (string?)result["status"]);
        Assert.Equal("windows_event_log_access_denied", (string?)result["block_reason"]);
        Assert.Equal("2026-10-01T00:00:00Z", (string?)result["blocked_since_utc"]);
    }

    [Theory]
    [InlineData(null, "completed")]
    [InlineData("", "completed")]
    [InlineData("other_runtime_block", "blocked")]
    public void ExplicitOperationalBlockTakesPrecedenceOverProcessBlock(string? reason, string status)
    {
        var collection = J("""{"collection_block_reason":"windows_event_log_access_denied","collection_block":{"first_seen_at":"2026-10-01T00:00:00Z"}}""");
        collection["operational_collection_block_reason"] = reason;
        var result = OperationsCollector.Progress(RecentlyCheckedCollector(), null, collection, Now);
        Assert.Equal(status, (string?)result["status"]);
        Assert.Equal(reason, (string?)result["block_reason"]);
        Assert.Equal(status == "blocked" ? "2026-10-01T00:00:00Z" : null, (string?)result["blocked_since_utc"]);
    }
}
