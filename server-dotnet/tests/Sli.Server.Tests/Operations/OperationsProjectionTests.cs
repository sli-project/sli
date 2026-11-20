using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Sli.Server.Operations;
using Xunit;

namespace Sli.Server.Tests.Operations;

public sealed class OperationsProjectionTests
{
    // Frozen PostgreSQL channel/run vector from test_pg_stable_runtime_backend.py.
    sealed class StableCollectorQueries : IOperationsQueries
    {
        public Task<JsonArray> ReadAsync(string sql, CancellationToken ct, params (string Name, object? Value)[] parameters)
        {
            JsonArray rows = sql == OperationsSql.CollectorState ? JsonNode.Parse("""
                [{"server_hostname":"DC1","channel":"Security","archive_start_utc":"2026-07-09T00:00:00+00:00",
                  "last_collection_start_utc":"2026-07-10T00:00:00+00:00","last_successful_collection_utc":"2026-07-10T00:01:00+00:00",
                  "last_event_time_utc":"2026-07-10T00:00:30+00:00","last_event_record_id":123,"backfill_completed":true,
                  "updated_at":"2026-07-10T00:01:00+00:00","event_count":1,"latest_event_time_utc":"2026-07-10T00:00:30+00:00",
                  "latest_event_record_id":123,"current_limit":1000,"recovery_mode":false,"last_action":null,
                  "adaptive_last_status":null,"last_lag_minutes":null}]
                """)!.AsArray() : sql == OperationsSql.CollectorHistory ? JsonNode.Parse("""
                [{"server":"DC1","channel":"Security","timeouts_24h":0,"partial_timeouts_24h":0,"inserted":1,"skipped":0,
                  "last_partial_count":0,"last_status":"completed","query_duration_ms":100,"import_duration_ms":20,
                  "import_queue_wait_ms":0,"import_retry_count":0,"total_duration_ms":150,"events_per_second":10,
                  "last_record_id_delta":null,"lag_delta_minutes":null,"collection_mode":"current","requested_collection_mode":"current",
                  "cursor_strategy":"record_id","cursor_fallback_reason":null,"collector_backend":"python","backend_reason":null}]
                """)!.AsArray() : [];
            return Task.FromResult(rows);
        }
    }

    [Fact]
    public async Task PostgresCollectorHealthPreservesTheReportedCollectorBackend()
    {
        var config = new ConfigurationBuilder().Build();
        var service = new OperationsService(new StableCollectorQueries(), new OperationsEndpointTests.Files(config),
            new OperationsCatalog(), new OperationsJobs(), TimeProvider.System);
        var result = await service.ReadAsync("/api/collector/health", new(), TestContext.Current.CancellationToken);
        Assert.Equal("postgres", (string?)result["backend"]);
        Assert.Equal(1, OpsJson.N(result["summary"]!["channels_total"]));
        var item = Assert.Single(result["items"]!.AsArray())!;
        Assert.Equal("DC1", (string?)item["server"]);
        Assert.Equal("python", (string?)item["collector_backend"]);
        Assert.Equal("Security", (string?)item["channel"]);
        Assert.Equal(123, OpsJson.N(item["last_event_record_id"]));
        Assert.Equal("postgres", (string?)result["post_collection"]!["backend"]);
        Assert.Equal("ok", (string?)result["post_collection"]!["status"]);
    }

    [Theory]
    [InlineData("{\"contract\":\"old-contract\"}")]
    [InlineData("{broken")]
    [InlineData("{\"contract\":42}")]
    public void InvalidPurgeReceiptDegradesLikePythonInsteadOfThrowing(string receipt)
    {
        string root = Path.Combine(Path.GetTempPath(), "sli-purge-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            string directory = Path.Combine(root, "runtime", "purge-runs"); Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, "fixture.json"), receipt);
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:DataDirectory"] = root }).Build();
            var result = new OperationsFiles(config).PurgeRuns();
            Assert.Equal("unavailable", result["status"]?.ToString());
            Assert.Equal("purge_receipts_unreadable", result["reason"]?.ToString()); Assert.Empty(result["runs"]!.AsArray());
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }
    static DateTimeOffset Now => OperationsEndpointTests.Now;
    static JsonObject J(string json) => JsonNode.Parse(json)!.AsObject();
    [Theory]
    [InlineData(0, "completed", "current")]
    [InlineData(5, "completed", "current")]
    [InlineData(6, "completed", "lagging")]
    [InlineData(20, "completed", "lagging")]
    [InlineData(21, "completed", "stale")]
    [InlineData(0, "failed", "error")]
    [InlineData(0, "access_denied", "error")]
    public void CheckFreshnessUsesPollTimeInsteadOfLastEventAge(int minutes, string status, string expected)
    {
        var channel = new JsonObject { ["server"] = "DC", ["channel"] = "System", ["last_status"] = status, ["last_successful_collection_utc"] = Now.AddMinutes(-minutes).ToString("O"), ["last_event_time_utc"] = Now.AddDays(-365).ToString("O") };
        Assert.Equal(expected, (string?)OperationsCollector.Freshness(new JsonArray(channel), Now)["state"]);
    }
    [Fact]
    public void MissingPollAndMixedFailureAreNotHealthy()
    {
        Assert.Equal("stale", (string?)OperationsCollector.Freshness([], Now)["state"]);
        var channels = new JsonArray(J("""{"last_status":"failed"}"""), new JsonObject { ["last_status"] = "completed", ["last_successful_collection_utc"] = Now.ToString("O") });
        Assert.Equal("partial", (string?)OperationsCollector.Freshness(channels, Now)["state"]);
    }
    [Theory]
    [InlineData(60, "running", "active")]
    [InlineData(91, "running", "stale")]
    [InlineData(0, "blocked", "blocked")]
    [InlineData(0, "failed", "warning")]
    public async Task HeartbeatUsesTwiceTheIntervalPlus30Seconds(int age, string reported, string expected)
    {
        using var app = await OperationsEndpointTests.Start();
        app.Queries.Workers = new JsonArray(new JsonObject { ["worker_name"] = "entity_state", ["worker_id"] = "fixture", ["status"] = reported, ["expected_interval_seconds"] = 30, ["heartbeat_at"] = Now.AddSeconds(-age).ToString("O"), ["details_json"] = new JsonObject() });
        var workers = await app.Service.WorkersAsync(TestContext.Current.CancellationToken);
        var row = workers["items"]!.AsArray().First(i => (string?)i?["worker_name"] == "entity_state");
        Assert.Equal(expected, (string?)row?["state"]);
        Assert.DoesNotContain(workers["items"]!.AsArray(), i => (string?)i?["worker_name"] == "storage_v2_outbox");
    }
    [Fact]
    public void FreshLifecycleProcessDoesNotProveSuccessfulWork()
    {
        var row = new JsonObject { ["details"] = new JsonObject { ["last_cycle_status"] = "failed", ["last_cycle_completed_at"] = Now.ToString("O") } };
        OperationsService.AddLifecycleOutcome(row, true, 60, Now);
        Assert.Equal("up", (string?)row["process_status"]); Assert.Equal("degraded", (string?)row["service_outcome"]); Assert.Equal("failed", (string?)row["lifecycle_progress_status"]);
        row["details"] = new JsonObject { ["last_cycle_status"] = "success" };
        OperationsService.AddLifecycleOutcome(row, true, 60, Now); Assert.Equal("degraded", (string?)row["service_outcome"]);
    }
    [Fact]
    public void StalledWatermarkRemainsDegradedWithFreshHeartbeat()
    {
        var row = new JsonObject { ["details"] = new JsonObject { ["last_cycle_status"] = "success", ["last_successful_watermark"] = "1", ["last_cycle_completed_at"] = Now.ToString("O"), ["watermark_updated_at"] = Now.AddHours(-2).ToString("O"), ["lifecycle_phase"] = "purge" } };
        OperationsService.AddLifecycleOutcome(row, true, 60, Now); Assert.True((bool)row["progress_is_stalled"]!); Assert.Equal("degraded", (string?)row["service_outcome"]);
    }
    [Fact]
    public async Task SourceUsesDomainMatchedInventoryAndValidatedDisks()
    {
        using var app = await OperationsEndpointTests.Start();
        app.Queries.Inventory = new JsonArray(new JsonObject { ["display_key"] = "dc1", ["fqdn"] = "dc1.example.test", ["domain_fqdn"] = "example.test", ["ip_addresses"] = new JsonArray("192.0.2.1", "invalid"), ["logical_disks"] = new JsonArray("C:|10000|1000", "invalid", "D:|1|5"), ["technical_inventory_status"] = "complete", ["last_observed_at_utc"] = Now.ToString("O") });
        var source = (await app.Service.SourceAsync("dc1", TestContext.Current.CancellationToken))["source"]!;
        Assert.Equal("warning", (string?)source["disk_state"]); Assert.Single(source["disks"]!.AsArray()); Assert.Single(source["ip_addresses"]!.AsArray());
        Assert.Equal("ad_context", (string?)source["inventory_source"]);
    }
    [Fact]
    public void LifecycleGrowthAndForecastNeedTwoMeasurementsAndPositiveGrowth()
    {
        var current = new JsonObject { ["captured_at"] = Now.ToString("O"), ["database_bytes"] = 200, ["disk_total_bytes"] = 10000, ["disk_free_bytes"] = 9000 };
        Assert.Equal("baseline_only", (string?)OperationsStorage.Growth(current, null)["quality"]);
        var previous = new JsonObject { ["captured_at"] = Now.AddDays(-1).ToString("O"), ["database_bytes"] = 100 };
        var growth = OperationsStorage.Growth(current, previous); Assert.Equal("measured_24h", (string?)growth["quality"]); Assert.Equal(100, (long)growth["operational_bytes_per_day"]!);
        var files = new OperationsFiles(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>()).Build());
        var forecast = OperationsStorage.Forecast(current, 0, OperationsStorage.Thresholds(files)); Assert.Null(forecast["thresholds"]?["warn"]?["estimated_days"]);
    }
    [Fact]
    public async Task FailedStreamDiagnosticsPreserveObservedConnectionButCannotInventPacketFailure()
    {
        using var app = await OperationsEndpointTests.Start(); app.Queries.Fail = true;
        var health = await app.Service.AgentHealthAsync(TestContext.Current.CancellationToken); Assert.Equal("unavailable", (string?)health["state"]);
        var agent = new JsonObject { ["id"] = "fixture", ["host_id"] = "host", ["status"] = "active", ["last_seen"] = Now.ToString("O"), ["created_at"] = Now.AddDays(-1).ToString("O"), ["policy_revision"] = 1, ["applied_policy_revision"] = 1, ["applied_collection_state"] = "active", ["assigned_modules"] = new JsonArray(new JsonObject { ["module_id"] = "sli.windows-eventlog", ["enabled"] = true, ["config"] = new JsonObject { ["channel"] = "System" } }) };
        var view = OperationsService.AgentView(new JsonArray(agent), [], Now, false);
        Assert.Equal("unknown", (string?)view["items"]?[0]?["state"]); Assert.Equal("online", (string?)view["items"]?[0]?["connection"]);
        Assert.Null(view["items"]?[0]?["modules"]?[0]?["channels"]?[0]?["failure_reason"]);
    }
    [Fact]
    public async Task MissingFootprintAndMeasuredZeroAreDistinct()
    {
        using var app = await OperationsEndpointTests.Start();
        app.Files.FootprintValue = new JsonObject { ["status"] = "ok", ["totals"] = new JsonObject { ["accounted_bytes"] = 0, ["accounted_human"] = "0 B" }, ["warnings"] = new JsonArray(), ["components"] = new JsonArray(), ["snapshot"] = new JsonObject { ["available"] = true } };
        var summary = app.Service.StorageSummary(new JsonObject { ["available"] = true, ["database"] = new JsonObject { ["database_bytes"] = 0 } });
        Assert.Equal(0, OpsJson.N(summary["project_overview"]!["total_bytes"])); Assert.True((bool)summary["project_overview"]!["complete"]!);
    }
    [Fact]
    public void CatalogHashesUseCanonicalLineEndingsAndUnknownAdaptersNeverExecute()
    {
        var catalog = new OperationsCatalog(); Assert.True(catalog.Packs().Count >= 4);
        foreach (var pack in catalog.Packs()) Assert.Matches("^[0-9a-f]{64}$", (string)pack!["manifest_sha256"]!);
        var plan = catalog.Preflight(J("""{"hostname":"DC2","channels":["Security","security"],"adapter_id":"powershell -evil"}"""), []);
        Assert.False((bool)plan["valid"]!); Assert.Single(plan["channels"]!.AsArray()); Assert.Empty(plan["network_actions"]!.AsArray());
    }
    [Fact]
    public void ImportedSqlHasNamedParametersAndNoRawQuestionMarkPlaceholders()
    {
        foreach (string sql in new[] { OperationsSql.Streams, OperationsSql.SourceInventory, OperationsSql.CollectorHistory, OperationsSql.ChannelCycles }) Assert.DoesNotContain("?", sql);
        Assert.Contains("@requested::jsonb", OperationsSql.Streams); Assert.Contains("@hostnames", OperationsSql.SourceInventory); Assert.Contains("@cutoff", OperationsSql.CollectorHistory);
    }
    [Fact]
    public void MalformedDiagnosticsStayActiveAndLaterCollectionCanRecoverRecentError()
    {
        var error = new JsonObject { ["ts"] = Now.AddMinutes(-5).ToString("O"), ["server"] = "DC1", ["channel"] = "System", ["level"] = "ERROR" };
        var success = new JsonObject { ["ts"] = Now.AddMinutes(-1).ToString("O"), ["server"] = "DC1", ["channel"] = "System", ["status"] = "completed", ["event"] = "collection_completed" };
        var result = OperationsService.InternalErrors(error.ToJsonString() + "\nmalformed\n", success.ToJsonString(), Now);
        Assert.Equal(1, OpsJson.N(result["active_count"])); Assert.Equal(1, OpsJson.N(result["recovered_count"])); Assert.Equal(1, OpsJson.N(result["malformed_count"]));
        var old = new JsonObject { ["ts"] = Now.AddHours(-1).ToString("O"), ["level"] = "ERROR" };
        Assert.False((bool)OperationsService.InternalErrors(old.ToJsonString(), "", Now)["active"]!);
    }
    [Fact]
    public void NativeHeartbeatProvesProcessLivenessOnlyAndNeverContainsConfiguration()
    {
        var running = OperationsWorkerObservation.Payload("password_producer", "fixture", 123, Now, Now, "running", "process_alive", null);
        Assert.Equal("unknown", (string?)running["last_result"]?["service_outcome"]); Assert.Null(running["last_result"]?["process_exit_code"]);
        Assert.DoesNotContain("dsn", running.ToJsonString()); Assert.DoesNotContain("password=", running.ToJsonString());
        var failed = OperationsWorkerObservation.Payload("password_producer", "fixture", 123, Now, Now, "failed", "exited", 1);
        Assert.Equal(1, OpsJson.N(failed["last_result"]?["process_exit_code"]));
    }
    [Fact]
    public async Task NativeServicesAreObservedWithoutPrivateRunFilesAndPreserveFreshCycleEvidence()
    {
        using var app = await OperationsEndpointTests.Start();
        foreach (string name in new[] { "post_collection", "entity_state", "what_where_when_projection", "semantic", "ad_snapshot_manifest_coordinator", "plugin_radius_session_observation", "notification_delivery", "core_job_executor_light" })
            app.Files.Native[name] = OperationsWorkerObservation.Payload(name, "fixture", 123, Now.AddMinutes(-1), Now, "running", "process_alive", null);
        app.Queries.Workers = new JsonArray(new JsonObject { ["worker_name"] = "entity_state", ["worker_id"] = "cycle", ["status"] = "failed", ["expected_interval_seconds"] = 30,
            ["heartbeat_at"] = Now.AddSeconds(-1).ToString("O"), ["details_json"] = new JsonObject { ["failed"] = 1 } });
        var workers = (await app.Service.WorkersAsync(TestContext.Current.CancellationToken))["items"]!.AsArray();
        JsonNode Worker(string name) => Assert.Single(workers, w => (string?)w?["worker_name"] == name)!;
        foreach (string name in app.Files.Native.Keys.Where(n => n != "entity_state")) {
            Assert.Equal("active", (string?)Worker(name)["state"]); Assert.Equal("running", (string?)Worker(name)["status"]);
            Assert.Equal("unknown", (string?)Worker(name)["service_outcome"]);
            Assert.Equal("running", (string?)Worker(name)["details"]?["process_observation"]?["status"]);
        }
        Assert.Equal("warning", (string?)Worker("entity_state")["state"]); Assert.Equal(1, OpsJson.N(Worker("entity_state")["details"]?["failed"]));
        Assert.Equal("not_registered", (string?)Worker("radius_accounting")["state"]);
        Assert.Equal("disabled", (string?)Worker("storage_lifecycle")["state"]);
        app.Files.Native["entity_state"] = OperationsWorkerObservation.Payload("entity_state", "fixture", 123, Now.AddMinutes(-1), Now, "stopped", "exited", 0);
        workers = (await app.Service.WorkersAsync(TestContext.Current.CancellationToken))["items"]!.AsArray();
        Assert.Equal("disabled", (string?)Worker("entity_state")["state"]);
        app.Files.Native["notification_delivery"]["heartbeat_at_utc"] = Now.AddMinutes(-10).ToString("O");
        workers = (await app.Service.WorkersAsync(TestContext.Current.CancellationToken))["items"]!.AsArray();
        Assert.Equal("stale", (string?)Worker("notification_delivery")["state"]);
    }
    [Theory]
    [InlineData("collection")]
    [InlineData("agent_import")]
    [InlineData("gpo_snapshot")]
    [InlineData("password_producer")]
    [InlineData("password_risk")]
    [InlineData("smtp_delivery")]
    [InlineData("telegram_delivery")]
    public async Task RetiredRolesAreAbsentEvenWithOldDatabaseAndFileHeartbeats(string name)
    {
        using var app = await OperationsEndpointTests.Start();
        var ct = TestContext.Current.CancellationToken;
        Assert.DoesNotContain((await app.Service.WorkersAsync(ct))["items"]!.AsArray(), w => (string?)w?["worker_name"] == name);
        app.Queries.Workers = new JsonArray(new JsonObject { ["worker_name"] = name, ["status"] = "running",
            ["heartbeat_at"] = Now.AddDays(-60).ToString("O") });
        app.Files.Native[name] = OperationsWorkerObservation.Payload(name, "fixture", 123, Now.AddDays(-10), Now.AddDays(-10), "stopped", "exited", 0);
        Assert.DoesNotContain((await app.Service.WorkersAsync(ct))["items"]!.AsArray(), w => (string?)w?["worker_name"] == name);
        Assert.Single(app.Queries.Workers);
        Assert.Equal("stopped", (string?)app.Files.Native[name]["status"]);
    }
    [Theory]
    [InlineData("core_job_executor_heavy")]
    [InlineData("core_job_executor_long")]
    public async Task ExtraExecutorProfileIsHiddenWithoutRowOrFileAndShownWhenPresent(string name)
    {
        using var app = await OperationsEndpointTests.Start();
        var ct = TestContext.Current.CancellationToken;
        Assert.DoesNotContain((await app.Service.WorkersAsync(ct))["items"]!.AsArray(), w => (string?)w?["worker_name"] == name);
        app.Files.Native[name] = OperationsWorkerObservation.Payload(name, "fixture", 123, Now, Now, "running", "running", 0);
        var running = Assert.Single((await app.Service.WorkersAsync(ct))["items"]!.AsArray(), w => (string?)w?["worker_name"] == name)!;
        Assert.Equal("active", (string?)running["state"]);
        app.Files.Native[name] = OperationsWorkerObservation.Payload(name, "fixture", 123, Now, Now, "stopped", "exited", 0);
        var stopped = Assert.Single((await app.Service.WorkersAsync(ct))["items"]!.AsArray(), w => (string?)w?["worker_name"] == name)!;
        Assert.Equal("warning", (string?)stopped["state"]); Assert.Equal("stopped", (string?)stopped["status"]);
        app.Files.Native.Remove(name);
        app.Queries.Workers = new JsonArray(new JsonObject { ["worker_name"] = name, ["status"] = "stopped", ["heartbeat_at"] = Now.ToString("O") });
        Assert.Equal("warning", (string?)Assert.Single((await app.Service.WorkersAsync(ct))["items"]!.AsArray(), w => (string?)w?["worker_name"] == name)!["state"]);
    }
    [Theory]
    [InlineData("post_collection", "running", "running")]
    [InlineData("entity_state", "failed", "running")]
    [InlineData("semantic", "failed", "running")]
    [InlineData("ad_snapshot_manifest_coordinator", "idle", "running")]
    [InlineData("entity_state", "failed", "stopped")]
    [InlineData("semantic", "failed", "failed")]
    public async Task FreshProcessCannotRefreshStaleCycleEvidence(string name, string reported, string observed)
    {
        using var app = await OperationsEndpointTests.Start();
        string heartbeat = Now.AddMinutes(-10).ToString("O");
        app.Queries.Workers = new JsonArray(new JsonObject { ["worker_name"] = name, ["worker_id"] = "cycle", ["status"] = reported,
            ["phase"] = "cycle_phase", ["expected_interval_seconds"] = 30, ["heartbeat_at"] = heartbeat, ["details_json"] = new JsonObject { ["failed"] = 1 } });
        app.Files.Native[name] = OperationsWorkerObservation.Payload(name, "process", 123, Now.AddHours(-1), Now, observed, "process_alive", null);
        var workers = (await app.Service.WorkersAsync(TestContext.Current.CancellationToken))["items"]!.AsArray();
        var row = Assert.Single(workers, w => (string?)w?["worker_name"] == name)!;
        Assert.Equal("stale", (string?)row["state"]); Assert.Equal(reported, (string?)row["status"]);
        Assert.Equal("cycle", (string?)row["worker_id"]); Assert.Equal("cycle_phase", (string?)row["phase"]);
        Assert.Equal(DateTimeOffset.Parse(heartbeat), DateTimeOffset.Parse((string)row["heartbeat_at"]!));
        Assert.Equal(600, OpsJson.N(row["heartbeat_age_seconds"])); Assert.Equal(1, OpsJson.N(row["details"]?["failed"]));
        Assert.Equal(observed, (string?)row["details"]?["process_observation"]?["status"]);
        Assert.Equal("process", (string?)row["details"]?["process_observation"]?["worker_instance_id"]);
        Assert.Equal(Now.AddHours(-1), DateTimeOffset.Parse((string)row["started_at"]!));
    }
    [Fact]
    public async Task StoppedEnabledWorkerIsNotShownAsDisabled()
    {
        using var app = await OperationsEndpointTests.Start();
        app.Queries.Workers = new JsonArray(new JsonObject { ["worker_name"] = "post_collection", ["status"] = "stopped",
            ["started_at"] = Now.AddDays(-1).ToString("O"), ["heartbeat_at"] = Now.ToString("O") });
        var workers = await app.Service.WorkersAsync(TestContext.Current.CancellationToken);
        var row = Assert.Single(workers["items"]!.AsArray(), w => (string?)w?["worker_name"] == "post_collection")!;
        Assert.Equal("warning", (string?)row["state"]);
        Assert.Equal(Now.AddDays(-1), DateTimeOffset.Parse((string)row["started_at"]!));
    }
    [Fact]
    public async Task StoppedDurableWorkerIsDisabledAndKeepsItsLastLaunch()
    {
        using var app = await OperationsEndpointTests.Start();
        app.Queries.Workers = new JsonArray(new JsonObject { ["worker_name"] = "semantic", ["status"] = "stopped",
            ["started_at"] = Now.AddDays(-1).ToString("O"), ["heartbeat_at"] = Now.ToString("O") });
        var workers = await app.Service.WorkersAsync(TestContext.Current.CancellationToken);
        var row = Assert.Single(workers["items"]!.AsArray(), w => (string?)w?["worker_name"] == "semantic")!;
        Assert.Equal("disabled", (string?)row["state"]);
        Assert.Equal(Now.AddDays(-1), DateTimeOffset.Parse((string)row["started_at"]!));
    }
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ExecutorCancellationWritesStoppedOnlyWhenShutdownWasRequested(bool requested)
    {
        string root = Path.Combine(Path.GetTempPath(), "sli-executor-stop-" + Guid.NewGuid().ToString("N"));
        try
        {
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:DataDirectory"] = root }).Build();
            var files = new OperationsFiles(config);
            using var stopping = new CancellationTokenSource();
            // SIGTERM cancels this token while RunAsync is awaiting cancellable work.
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var run = OperationsWorkerObservation.RunAsync("core_job_executor_light", async () => {
                entered.SetResult();
                await Task.Delay(Timeout.Infinite, stopping.Token);
                return 0;
            }, files, requested ? stopping.Token : CancellationToken.None);
            await entered.Task.WaitAsync(TestContext.Current.CancellationToken);
            stopping.Cancel();
            if (requested) Assert.Equal(0, await run);
            else await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
            var receipt = files.NativeHeartbeat("core_job_executor_light")!;
            Assert.Equal(requested ? "stopped" : "failed", (string?)receipt["status"]);
            Assert.Equal(requested ? 0 : 1, OpsJson.N(receipt["last_result"]?["process_exit_code"]));
            Assert.Equal("exited", (string?)receipt["phase"]);
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }
    [Theory]
    [InlineData("42501", "read_failed")]
    [InlineData("42P01", "read_failed")]
    [InlineData("57014", "timeout")]
    public void StreamReadFailuresExposeOnlySafeDatabaseCodes(string sqlstate, string reason)
    {
        var failure = OperationsService.StreamFailure(new Npgsql.PostgresException("private-sql-and-AD-data", "ERROR", "ERROR", sqlstate, detail: "private-value"));
        Assert.Equal(reason, (string?)failure["reason"]); Assert.Equal(sqlstate, (string?)failure["sqlstate"]);
        Assert.DoesNotContain("private", failure.ToJsonString());
        Assert.Equal("timeout", (string?)OperationsService.StreamFailure(new Npgsql.NpgsqlException("private", new TimeoutException("private")))["reason"]);
    }
    [Fact]
    public void WorkstationChannelsFollowEnabledFamiliesInsteadOfInventingSysmon()
    {
        var config = J("""{"families":{"logons":false,"processes":false,"usb":true,"local_admins":false,"protection":false}}""");
        Assert.Equal(new[] { "Security", "Microsoft-Windows-DriverFrameworks-UserMode/Operational", "Microsoft-Windows-Kernel-PnP/Configuration" }, OperationsService.Channels("sli.workstations", config));
    }
    [Fact]
    public void DcChannelsFollowTheAgentModuleInsteadOfTheLegacyCollectorPack()
    {
        Assert.Equal(new[] { "Security", "System", "Directory Service" }, OperationsService.Channels("sli.windows.ad-dc", new()));
        Assert.Equal(new[] { "Security", "Directory Service" }, OperationsService.Channels("sli.windows.ad-dc", J("""{"channels":{"System":false,"DNS Server":true}}""")));
    }
    [Fact]
    public void AgentHealthCarriesCurrentAuditObservationForBlockedCheckActions()
    {
        var agent = J("""{"id":"00000000-0000-4000-8000-000000000001","host_id":"00000000-0000-4000-8000-000000000002","registration_host_name":"LAB-DC01","status":"active","policy_revision":3,"assigned_modules":[],"windows_audit":{"policy_revision":3,"families":{"domain_controller":{"state":"missing","required":[{"subcategory":"logon","success":true,"failure":true,"actual_success":true,"actual_failure":false,"detections":[1,2,3]}]}}}}""");
        var result = OperationsService.AgentView(new JsonArray(agent), [], Now);
        Assert.True(JsonNode.DeepEquals(agent["windows_audit"], result["items"]![0]!["windows_audit"]));
        agent["policy_revision"] = 4;
        result = OperationsService.AgentView(new JsonArray(agent.DeepClone()), [], Now);
        Assert.Null(result["items"]![0]!["windows_audit"]);
    }
    [Theory] [InlineData("?view=readiness")] [InlineData("?view=readiness&view=readiness")]
    public async Task RepeatedReadinessViewIsHandledLikeTheReference(string query)
    {
        using var app = await OperationsEndpointTests.Start(); using var response = await OperationsEndpointTests.Request(app, "GET", "/api/v1/operations/overview" + query);
        Assert.Equal(200, (int)response.StatusCode); var body = await OperationsEndpointTests.Body(response);
        Assert.Equal(query.Contains('&'), body.ContainsKey("collection"));
    }
    [Fact]
    public async Task DeepHealthUsesPersistedArchiveSettingWithoutWritingOrCreatingWatermarks()
    {
        using var app = await OperationsEndpointTests.Start(); using var response = await OperationsEndpointTests.Request(app, "GET", "/api/health/details?deep=yes"); var body = await OperationsEndpointTests.Body(response);
        Assert.Equal(200, (int)response.StatusCode); Assert.Equal("postgres", (string?)body["archive_backend"]); Assert.True(body.ContainsKey("archive_start_utc"));
        Assert.All(app.Queries.Calls, call => Assert.StartsWith("select", call.Sql.TrimStart()));
    }
    [Fact]
    public async Task DatabaseConnectFalseDoesNotOpenTheDiagnosticsConnection()
    {
        using var app = await OperationsEndpointTests.Start(); using var response = await OperationsEndpointTests.Request(app, "GET", "/api/db/status?connect=no");
        Assert.Equal(200, (int)response.StatusCode); Assert.Equal(0, app.Queries.Reads); Assert.Equal("skipped", (string?)(await OperationsEndpointTests.Body(response))["checks"]?["connection"]?["status"]);
    }
}
