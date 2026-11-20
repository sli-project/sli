using System.Text.Json.Nodes;
using Sli.Server.Operations;
using Xunit;

namespace Sli.Server.Tests.Operations;

// Behavioral vectors from tests/reporting/test_operations_postgres_resilience.py.
public sealed class OperationsPostgresResilienceTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static DateTimeOffset Now => OperationsEndpointTests.Now;
    const string DatabaseSql = "select current_database() as database_name,pg_database_size(current_database()) as database_bytes,now() as checked_at";
    static JsonObject J(string json) => JsonNode.Parse(json)!.AsObject();
    static void EqualJson(JsonNode expected, JsonNode? actual) => Assert.True(JsonNode.DeepEquals(expected, actual), $"Expected {expected}; actual {actual}");

    sealed class Catalog : OperationsCatalog
    {
        public JsonArray Entries = [];
        public bool Fail;
        internal override JsonArray EventEntries() => Fail ? throw new InvalidOperationException("private catalogue detail") : Entries.DeepClone().AsArray();
    }

    static async Task<JsonObject> Overview(OperationsEndpointTests.App app)
    {
        using var response = await OperationsEndpointTests.Request(app, "GET", "/api/v1/operations/overview");
        Assert.Equal(200, (int)response.StatusCode);
        return await OperationsEndpointTests.Body(response);
    }

    static void Database(OperationsEndpointTests.App app, long bytes = 1_048_576) =>
        app.Queries.Results[DatabaseSql] = new JsonArray(new JsonObject { ["database_name"] = "adlog", ["database_bytes"] = bytes, ["checked_at"] = Now.ToString("O") });

    [Fact]
    public async Task OptionalTableMetricFailureKeepsDatabaseReadyAndPrivateDetailsHidden()
    {
        using var app = await OperationsEndpointTests.Start();
        Database(app); app.Queries.FailContaining = "from pg_stat_user_tables";
        var result = await app.Service.PostgresAsync(10, Ct);
        Assert.Equal("warn", (string?)result["status"]);
        Assert.True((bool)result["available"]!);
        Assert.Equal("ready", (string?)result["connectivity_status"]);
        Assert.Equal("partial", (string?)result["metrics_status"]);
        Assert.Equal("1.0 MB", (string?)result["database"]?["database_human"]);
        Assert.Empty(result["tables"]!.AsArray());
        EqualJson(JsonNode.Parse("""[{"metric":"table_statistics","error_type":"InvalidOperationException"}]""")!, result["limitations"]);
        Assert.False(result.ContainsKey("error"));
        Assert.DoesNotContain("private", result.ToJsonString());
        Assert.Single(app.Queries.Calls, c => c.Sql.Contains("from pg_stat_activity"));
    }

    [Fact]
    public async Task OverviewReadsDatabaseSizeOnceAndReusesItForStorage()
    {
        using var app = await OperationsEndpointTests.Start(); Database(app);
        var result = await Overview(app);
        Assert.Single(app.Queries.Calls, c => c.Sql.Contains("pg_database_size"));
        var tables = Assert.Single(app.Queries.Calls, c => c.Sql.Contains("from pg_stat_user_tables"));
        Assert.Equal(10, Assert.Single(tables.Parameters, p => p.Name == "limit").Value);
        Assert.Equal(1, app.Files.FootprintReads);
        EqualJson(result["postgres"]!["database"]!["database_bytes"]!, result["storage"]?["project_overview"]?["database_bytes"]);
        Assert.Equal("1.0 MB", (string?)result["storage"]?["project_overview"]?["database_human"]);
        Assert.Equal(0, app.Files.Scans); Assert.Equal(0, app.Files.Inventories);
    }

    [Fact]
    public async Task OverviewExposesPayloadFreeCatalogCompleteness()
    {
        var catalog = new Catalog { Entries = new JsonArray(J("""{"base_risk":"low","purpose_tier":"technical","noise_class":"signal","category":"other","lifecycle":{},"correlation":null,"required_fields":["event_id"]}"""), new JsonObject()) };
        using var app = await OperationsEndpointTests.Start(catalog: catalog);
        var result = await Overview(app);
        EqualJson(J("""
            {"status":"ok","basis":"distinct_catalog_entries","contains_event_payload":false,
             "entry_count":2,"fully_classified":1,"classification_ratio":0.5,"schema_v2_ready":1,
             "declared_per_field":{"base_risk":1,"purpose_tier":1,"noise_class":1,"category":1,"lifecycle":0,"correlation":0,"required_fields":1}}
            """), result["catalog_completeness"]);
    }

    [Fact]
    public async Task CatalogFailureKeepsOtherHealthAvailableAndHidesPrivateDetails()
    {
        using var app = await OperationsEndpointTests.Start(catalog: new Catalog { Fail = true });
        var result = await Overview(app);
        Assert.Equal("ok", (string?)result["postgres"]?["status"]);
        Assert.NotEmpty(result["collector_health"]!["items"]!.AsArray());
        Assert.NotNull(result["storage"]?["project_overview"]);
        EqualJson(J("""{"status":"unavailable","basis":"distinct_catalog_entries","contains_event_payload":false,"error_type":"InvalidOperationException"}"""), result["catalog_completeness"]);
        Assert.DoesNotContain("private", result.ToJsonString());
    }

    [Fact]
    public async Task RadiusFailureKeepsOtherHealthAvailableAndHidesPrivateDetails()
    {
        using var app = await OperationsEndpointTests.Start(); app.Queries.FailContaining = "radius_vpn_operations_v1";
        var result = await Overview(app);
        Assert.Equal("ok", (string?)result["postgres"]?["status"]);
        Assert.NotEmpty(result["collector_health"]!["items"]!.AsArray());
        Assert.NotNull(result["storage"]?["project_overview"]);
        EqualJson(J("""{"contract_id":"sli.radius-vpn-operations.v1","status":"unavailable","items":[],"contains_identity_or_event_payload":false,"error_type":"InvalidOperationException"}"""), result["plugin_pilots"]?["vpn_radius"]);
        Assert.DoesNotContain("private", result.ToJsonString());
    }

    static Dictionary<string, string?> CollectionSettings() => new()
    {
        ["Sli:Operations:SLI_LEGACY_COLLECTION_DISABLED"] = "0",
        ["Sli:Operations:SLI_AD_DC_AGENT_IMPORT_ENABLED"] = "0",
        ["Sli:Operations:ADLOG_DISABLE_COLLECTION"] = "1",
        ["Sli:Operations:ADLOG_ENABLE_POSTGRES_COLLECTION"] = "1"
    };

    static JsonObject Worker(string status = "running") => new()
    {
        ["worker_name"] = "collection", ["worker_id"] = "collection-example-39124", ["status"] = status,
        ["phase"] = "collection", ["heartbeat_at"] = Now.ToString("O"), ["expected_interval_seconds"] = 30,
        ["details_json"] = J("""{"active_job":{"job_id":2,"status":"running","phase":"collection"}}""")
    };

    [Theory]
    [InlineData("running", false)]
    [InlineData("failed", false)]
    [InlineData("running", true)]
    public async Task RetainedCollectorHeartbeatDoesNotClearLocalOrDurableBlock(string status, bool durableBlock)
    {
        using var app = await OperationsEndpointTests.Start(settings: CollectionSettings());
        app.Queries.Workers = new JsonArray(Worker(status));
        if (durableBlock)
            app.Queries.Results["select reason_code,retry_policy,operator_action,observed_count,first_seen_at,last_seen_at from runtime_collection_blocks where singleton_id=1 and active=true"] =
                new JsonArray(J("""{"reason_code":"windows_security_context_invalid"}"""));
        var result = await Overview(app); var collection = result["collection"]!;
        Assert.False((bool)collection["collection_enabled"]!);
        Assert.False((bool)collection["operational_collection_enabled"]!);
        string reason = durableBlock ? "windows_security_context_invalid" : "collection_disabled_by_ADLOG_DISABLE_COLLECTION";
        Assert.Equal(reason, (string?)collection["operational_collection_block_reason"]);
        Assert.Equal("server_process", (string?)collection["collection_execution_owner"]);
        Assert.False((bool)collection["local_runtime_guard_only"]!);
        Assert.DoesNotContain(result["workers"]!["items"]!.AsArray(), w => (string?)w?["worker_name"] == "collection");
        Assert.Equal("blocked", (string?)result["collection_progress"]!["status"]);
    }

    [Fact]
    public async Task OverviewReportsRetainedRecoveryAcrossTwelveChannelsWithCollectionBlocked()
    {
        using var app = await OperationsEndpointTests.Start(settings: CollectionSettings());
        app.Queries.Workers = new JsonArray(Worker());
        var states = new JsonArray(); long index = 0;
        foreach (string server in new[] { "DC1", "DC2" })
        foreach (string channel in new[] { "Security", "System", "Directory Service", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-TaskScheduler/Operational", "DNS Server" })
        {
            bool recovery = channel is "Security" or "DNS Server";
            states.Add(new JsonObject { ["server_hostname"] = server, ["channel"] = channel, ["recovery_mode"] = recovery,
                ["current_limit"] = recovery ? 50_000 : 35_200, ["last_action"] = recovery ? "keep:completed_fast_recovery" : "exit_recovery:source_boundary_reached",
                ["last_event_record_id"] = ++index, ["last_event_time_utc"] = "2026-08-26T01:00:00Z" });
        }
        app.Queries.Results[OperationsSql.CollectorState] = states;
        app.Queries.Results[OperationsSql.CollectorHistory] = [];
        var progress = (await Overview(app))["collection_progress"]!;
        Assert.Equal("blocked", (string?)progress["status"]);
        Assert.Equal(12, (int)progress["channels_total"]!);
        Assert.Equal(8, (int)progress["boundaries_reached"]!);
        Assert.Equal(4, (int)progress["channels_in_recovery"]!);
        Assert.Null(progress["worker_id"]);
        Assert.Null(progress["job_id"]);
        Assert.Equal(new[] { "DC1/DNS Server", "DC1/Security", "DC2/DNS Server", "DC2/Security" },
            progress["recovery_items"]!.AsArray().Select(i => $"{i!["server"]}/{i["channel"]}").Order(StringComparer.Ordinal).ToArray());
        Assert.All(progress["items"]!.AsArray().Where(i => !(bool)i!["recovery_mode"]!), i => Assert.True((bool)i!["boundary_reached"]!));
        Assert.All(progress["items"]!.AsArray(), i => Assert.NotNull(i!["last_event_record_id"]));
    }

    [Fact]
    public async Task SourceDetailUsesInventoryAndDoesNotInventUncollectedFields()
    {
        using var app = await OperationsEndpointTests.Start();
        app.Queries.Results[OperationsSql.Sources] = new JsonArray(J("""{"hostname":"DC2","fqdn":"dc2.example.test","role":"domain_controller","is_active":true,"domain_fqdn":"example.test","site_name":"Main","os_name":"Windows Server","os_version":"2022","ip_addresses":["192.0.2.10"]}"""));
        app.Queries.Results[OperationsSql.CollectorState] = new JsonArray(J("""{"server_hostname":"dc2","channel":"Security","last_successful_collection_utc":"2026-07-23T03:58:00Z","last_event_time_utc":"2026-07-23T03:57:00Z"}"""));
        app.Queries.Results[OperationsSql.CollectorHistory] = new JsonArray(J("""{"server":"dc2","channel":"Security","last_status":"completed"}"""));
        using var response = await OperationsEndpointTests.Request(app, "GET", "/api/v1/operations/sources/dc2");
        Assert.Equal(200, (int)response.StatusCode); var result = await OperationsEndpointTests.Body(response);
        EqualJson(J("""{"hostname":"DC2","fqdn":"dc2.example.test","role":"domain_controller","active":true,"domain_fqdn":"example.test","site":"Main","os_name":"Windows Server","os_version":"2022","ip_addresses":["192.0.2.10"],"inventory_observed_at_utc":null,"inventory_source":null,"disk_state":"not_collected","disks":[]}"""), result["source"]);
        Assert.Equal(1, (int)result["collection_freshness"]!["channels_total"]!);
        Assert.Equal("dc2", (string?)Assert.Single(result["channels"]!.AsArray())?["server"]);
        Assert.True((bool)result["read_only"]!);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public async Task SourceRejectsEmptyHostnameBeforeReadingData(string hostname)
    {
        using var app = await OperationsEndpointTests.Start();
        var error = await Assert.ThrowsAsync<OperationsInputException>(() => app.Service.SourceAsync(hostname, Ct));
        Assert.Equal("invalid_source_hostname", error.Message); Assert.Equal(0, app.Queries.Reads);
    }

    [Fact]
    public async Task FastStorageSummaryUsesExistingDatabaseSizeWithUnknownFootprint()
    {
        using var app = await OperationsEndpointTests.Start();
        app.Files.FootprintValue = J("""{"status":"unavailable","warnings":[],"totals":{},"components":[]}""");
        var result = app.Service.StorageSummary(J("""{"available":true,"database":{"database_bytes":1048576,"database_human":"1.0 MB"}}"""));
        Assert.Equal("ok", (string?)result["status"]);
        EqualJson(J("""{"database_bytes":1048576,"database_human":"1.0 MB","total_bytes":null,"total_human":null,"scope":"deduplicated_known_project_footprint","complete":false}"""), result["project_overview"]);
        Assert.True((bool)result["read_only"]!);
        Assert.Equal(1, app.Files.FootprintReads); Assert.Equal(0, app.Queries.Reads);
        Assert.Equal(0, app.Files.Scans); Assert.Equal(0, app.Files.Inventories);
    }

    [Fact]
    public async Task FastStorageSummaryPreservesPartialFootprintWithoutRescanning()
    {
        using var app = await OperationsEndpointTests.Start();
        var footprint = J("""
            {"status":"partial","warnings":["RAW spool scan is incomplete."],
             "totals":{"accounted_bytes":1234,"accounted_human":"1.2 КБ"},"components":[{"key":"project_root","bytes":1234}],
             "raw_spool":{"status":"partial","bytes":10,"batch_count":2,"oldest_batch_at_utc":"2026-08-30T10:00:00+00:00",
              "oldest_batch_age_seconds":172800,"scan":{"complete":false,"errors":1},
              "thresholds":{"bytes_warning":524288000,"bytes_critical":1073741824,"batch_count_warning":1000,"oldest_age_warning_seconds":172800}}}
            """);
        app.Files.FootprintValue = footprint;
        var result = app.Service.StorageSummary(J("""{"available":true,"database":{"database_bytes":512,"database_human":"512 Б"}}"""));
        Assert.Equal("warn", (string?)result["status"]);
        EqualJson(footprint, result["footprint"]);
        Assert.Equal(1, (int)result["footprint"]!["raw_spool"]!["scan"]!["errors"]!);
        Assert.Equal(1234, (int)result["project_overview"]!["total_bytes"]!);
        Assert.False((bool)result["project_overview"]!["complete"]!);
        Assert.Equal(1, app.Files.FootprintReads); Assert.Equal(0, app.Queries.Reads);
        Assert.Equal(0, app.Files.Scans); Assert.Equal(0, app.Files.Inventories);
    }
}
