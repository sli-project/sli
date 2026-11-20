using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Sli.Server.Operations;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Operations;
using static Sli.Server.Operations.OpsJson;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class StorageCapacityProfilesTests
{
    const long GiB = 1024L * 1024 * 1024;
    static readonly DateTimeOffset Now = new(2026, 9, 3, 0, 0, 0, TimeSpan.Zero);
    static JsonObject Snapshot(DateTimeOffset at, long database, long free = 200, long used = 0) => new() {
        ["captured_at"] = at.ToString("O"), ["database_bytes"] = database * GiB,
        ["disk_free_bytes"] = free * GiB, ["disk_total_bytes"] = 500 * GiB, ["disk_used_bytes"] = used * GiB,
        ["raw_bytes"] = 0, ["raw_archive_bytes"] = 0, ["backups_bytes"] = 0,
        ["logs_bytes"] = 0, ["reports_bytes"] = 0, ["artifacts_bytes"] = 0
    };
    static JsonObject Disk(long free = 90, double percent = 18) => new() {
        ["total_bytes"] = 500 * GiB, ["free_bytes"] = free * GiB,
        ["used_bytes"] = (500 - free) * GiB, ["free_percent"] = percent
    };

    [Fact]
    public void Profiles_resolve_deterministically_and_expose_explicit_overrides()
    {
        var basis = StorageCapacityProfiles.DefaultPolicy();
        var economy = StorageCapacityProfiles.Resolve("economy", basis);
        var extended = StorageCapacityProfiles.Resolve("extended", basis, new() { ["raw_retention_days"] = 5 });
        Assert.Equal("economy", S(economy["selected_profile"]));
        Assert.False(B(economy["effective_policy"]!["raw_archive_enabled"]));
        Assert.False(B(economy["effective_policy"]!["raw_archive_compress"]));
        Assert.Equal(2, N(economy["effective_policy"]!["raw_retention_days"]));
        Assert.Equal("extended", S(extended["selected_profile"]));
        Assert.Equal(5, N(extended["effective_policy"]!["raw_retention_days"]));
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["raw_retention_days"] = 5 }, extended["overrides"]));
        Assert.True(B(basis["raw_archive_enabled"])); // resolution must not mutate its inputs
        basis["post_collection_retention_days"] = 14;
        Assert.Equal(30, N(StorageCapacityProfiles.Resolve(null, basis)["effective_policy"]!["relationship_retention_days"]));
    }

    [Fact]
    public void Realistic_yaml_keeps_economy_defaults_until_explicit_override()
    {
        using var state = new StorageLifecycleTests.State();
        Directory.CreateDirectory(Path.Combine(state.Path, "config"));
        string path = Path.Combine(state.Path, "config", "adlog_config.yaml");
        File.WriteAllText(path, "retention:\n  storage_capacity_profile: economy\n  raw_retention_days: 14\n  raw_archive_enabled: true\n  raw_archive_compress: true\n  db_retention_days: 7\n  warm_retention_days: 365\n  min_free_disk_percent: 15\n  stop_collection_if_free_disk_percent_below: 10\n  stop_collection_if_free_disk_bytes_below: 10737418240\n");
        var config = new LifecycleConfiguration(state.Path, _ => null);
        var resolution = StorageCapacityProfiles.Read(config.Get);
        Assert.Equal("economy", S(resolution["selected_profile"]));
        Assert.False(B(resolution["effective_policy"]!["raw_archive_enabled"]));
        Assert.Equal(2, N(resolution["effective_policy"]!["raw_retention_days"]));
        Assert.Empty(resolution["overrides"]!.AsObject());
        File.AppendAllText(path, "  storage_capacity_profile_overrides: raw_archive_enabled\n");
        resolution = StorageCapacityProfiles.Read(new LifecycleConfiguration(state.Path, _ => null).Get);
        Assert.True(B(resolution["effective_policy"]!["raw_archive_enabled"]));
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["raw_archive_enabled"] = true }, resolution["overrides"]));
    }

    [Fact]
    public void Recommendations_require_positive_growth_and_never_change_the_selected_profile()
    {
        var policy = StorageCapacityProfiles.DefaultPolicy(); policy["warm_retention_days"] = 30;
        var insufficient = StorageCapacityProfiles.Recommend([Snapshot(Now.AddDays(-2), 100), Snapshot(Now.AddDays(-1), 90)], "extended", policy);
        Assert.Equal("economy", S(insufficient["recommended_profile"]));
        Assert.Equal("insufficient_growth_evidence", S(insufficient["reason"]));
        Assert.Equal("extended", S(insufficient["selected_profile"]));
        var valid = StorageCapacityProfiles.Recommend([Snapshot(Now.AddDays(-2), 100), Snapshot(Now.AddDays(-1), 101), Snapshot(Now, 102)], "economy", policy);
        Assert.Equal("economy", S(valid["selected_profile"]));
        Assert.False(B(valid["recommendation_changes_selection"]));
        Assert.Equal(GiB, N(valid["growth_bytes_per_day"]));
        Assert.Equal("extended", S(valid["recommended_profile"]));
        Assert.Equal("extended_capacity_sufficient", S(valid["reason"]));
    }

    [Fact]
    public void Recommendation_resets_after_shrink_and_accounts_for_the_stop_reserve()
    {
        var policy = StorageCapacityProfiles.DefaultPolicy(); policy["warm_retention_days"] = 30;
        var rows = new[] { Snapshot(Now.AddDays(-3), 100), Snapshot(Now.AddDays(-2), 150), Snapshot(Now.AddDays(-1), 90), Snapshot(Now, 92, 100) };
        var result = StorageCapacityProfiles.Recommend(rows.Reverse(), "extended", policy);
        Assert.Equal(2 * GiB, N(result["growth_bytes_per_day"]));
        Assert.Equal(1, N(result["inputs"]!["positive_intervals_after_reset"]));
        Assert.Equal(50 * GiB, N(result["reserve_bytes"]));
        Assert.Equal(60 * GiB, N(result["required_capacity_bytes"]));
        Assert.Equal("bounded_lifecycle_exceeds_usable_capacity", S(result["reason"]));
        Assert.Equal("economy", S(result["recommended_profile"]));
    }

    [Theory]
    [InlineData(50, 9, "blocked", false, "free_percent_below_stop")]
    [InlineData(5, 20, "blocked", false, "free_bytes_below_stop")]
    [InlineData(60, 12, "warn", true, "warning_only")]
    [InlineData(10, 10, "warn", true, "warning_only")]
    public void Disk_guard_uses_either_stop_threshold(long free, double percent, string status, bool allowed, string condition)
    {
        var pressure = StorageCapacityProfiles.Pressure(Disk(free, percent), StorageCapacityProfiles.DefaultPolicy());
        Assert.Equal(status, S(pressure["status"])); Assert.Equal(allowed, B(pressure["collection_allowed"]));
        Assert.Equal("free_bytes_or_percent", S(pressure["blocking_threshold"]!["mode"]));
        Assert.Equal(condition, S(pressure["blocking_threshold"]!["condition"]));
    }

    [Fact]
    public void Runtime_evidence_measures_72_hours_and_forecasts_stop_using_disk_growth()
    {
        var result = StorageCapacityProfiles.RuntimeEvidence([Snapshot(Now.AddHours(-72), 100, 120, 380), Snapshot(Now, 106, 90, 410)], Now, Disk(), StorageCapacityProfiles.DefaultPolicy());
        Assert.Equal("ok", S(result["status"])); Assert.True(B(result["read_only"]));
        Assert.Equal(90 * GiB, N(result["disk_free_bytes"])); Assert.Equal(18, result["disk_free_percent"]!.GetValue<double>());
        Assert.Equal(50 * GiB, N(result["stop_threshold"]!["effective_reserve_bytes"]));
        Assert.Equal("measured_72h", S(result["measured_growth"]!["quality"]));
        Assert.Equal(2 * GiB, N(result["measured_growth"]!["database_bytes_per_day"]));
        Assert.Equal(10 * GiB, N(result["measured_growth"]!["disk_used_bytes_per_day"]));
        Assert.Equal("ok", S(result["forecast"]!["status"]));
        Assert.Equal(4, result["forecast"]!["estimated_days_to_stop"]!.GetValue<double>());
    }

    [Theory] [InlineData(24)] [InlineData(71.99)] [InlineData(96.01)]
    public void Runtime_evidence_is_unknown_without_a_72_to_96_hour_baseline(double hours)
    {
        var result = StorageCapacityProfiles.RuntimeEvidence([Snapshot(Now.AddHours(-hours), 100), Snapshot(Now, 101)], Now, Disk(100, 20), StorageCapacityProfiles.DefaultPolicy());
        Assert.Equal("unknown", S(result["status"]));
        Assert.Equal("unknown", S(result["measured_growth"]!["quality"]));
        Assert.Equal("unknown", S(result["forecast"]!["status"]));
        Assert.Null(result["forecast"]!["estimated_days_to_stop"]);
    }

    [Fact]
    public void Runtime_evidence_reports_an_already_reached_percent_stop_even_with_50_gib_free()
    {
        var result = StorageCapacityProfiles.RuntimeEvidence([Snapshot(Now.AddHours(-72), 100, used: 440), Snapshot(Now, 101, used: 450)], Now, Disk(50, 9), StorageCapacityProfiles.DefaultPolicy());
        Assert.Equal("already_at_or_below_stop", S(result["status"]));
        Assert.Equal("free_percent_below_stop", S(result["stop_threshold"]!["condition"]));
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["status"] = "already_at_or_below_stop", ["estimated_days_to_stop"] = 0.0 }, result["forecast"]));
    }

    [Fact]
    public void Runtime_uses_closest_baseline_ignores_future_snapshots_and_reports_nonpositive_growth()
    {
        var rows = new[] { Snapshot(Now.AddHours(-96), 40), Snapshot(Now.AddHours(-72), 100), Snapshot(Now, 100), Snapshot(Now.AddHours(1), 200) };
        var result = StorageCapacityProfiles.RuntimeEvidence(rows.Reverse(), Now, Disk(), StorageCapacityProfiles.DefaultPolicy());
        Assert.Equal(3, N(result["snapshot_count"])); Assert.Equal(72, result["measured_growth"]!["elapsed_hours"]!.GetValue<double>());
        Assert.Equal(0, N(result["measured_growth"]!["database_bytes_per_day"]));
        Assert.Equal("stable_or_nonpositive_growth", S(result["forecast"]!["status"]));
        Assert.Null(result["forecast"]!["estimated_days_to_stop"]);
    }

    [Theory] [InlineData("unknown", null)] [InlineData("economy", "unknown_field")]
    public void Unknown_profiles_and_override_fields_are_rejected(string profile, string? field)
    {
        var changes = field is null ? null : new JsonObject { [field] = 1 };
        Assert.Throws<InvalidDataException>(() => StorageCapacityProfiles.Resolve(profile, StorageCapacityProfiles.DefaultPolicy(), changes));
    }

    [Fact]
    public void Persistent_raw_archive_requires_a_positive_retention_boundary()
    {
        var policy = StorageCapacityProfiles.DefaultPolicy(); policy["warm_retention_days"] = 0;
        Assert.Throws<InvalidDataException>(() => StorageCapacityProfiles.Resolve("extended", policy));
        Assert.False(B(StorageCapacityProfiles.Resolve("economy", policy)["persistent_raw_archive"]!["enabled"]));
    }

    sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }

    [Fact]
    public async Task Admin_selected_economy_profile_reaches_the_storage_health_policy()
    {
        using var app = await OperationsEndpointTests.Start(settings: new() {
            ["Sli:Operations:ADLOG_STORAGE_CAPACITY_PROFILE"] = "economy",
            ["Sli:Operations:ADLOG_RAW_ARCHIVE_ENABLED"] = "true",
            ["Sli:Operations:ADLOG_RAW_RETENTION_DAYS"] = "14"
        });
        var result = await app.Service.ReadAsync("/api/storage/health", [], TestContext.Current.CancellationToken);
        Assert.False(result["policy"]!["raw_archive_enabled"]!.GetValue<bool>());
        Assert.Equal(2, result["policy"]!["raw_retention_days"]!.GetValue<int>());
        Assert.Equal("economy", S(result["storage_lifecycle"]!["capacity_profile"]!["selected_profile"]));
        Assert.Equal("economy", S(result["storage_lifecycle"]!["capacity_recommendation"]!["selected_profile"]));
        Assert.False(B(result["storage_lifecycle"]!["capacity_recommendation"]!["recommendation_changes_selection"]));
        Assert.Equal("unknown", S(result["storage_lifecycle"]!["runtime_capacity_evidence"]!["status"]));
    }
}
