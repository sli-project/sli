using System.Text.Json.Nodes;
using Sli.Server.Legacy;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Operations;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Legacy;

// Vectors from tests/core/test_nps_worker_stage.py. Only acquisition and durable
// I/O are replaced; stage admission, waiting and cycle reduction are real.
public sealed class NpsWorkerStageTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static JsonObject Result(string status, long duration = 0) => new() {
        ["status"] = status, ["phase"] = "nps", ["duration_ms"] = duration
    };
    private static NpsWorkerStage Stage(string? enabled,
        Func<NpsCollectionRequest, CancellationToken, Task<JsonObject>>? collect = null,
        Func<CancellationToken, Task>? tick = null) => new(() => enabled,
        _ => Task.FromResult<string?>("nps.example.test"),
        (_, _) => Task.FromResult<string?>("2026-09-10T00:00:00+00:00"),
        collect ?? ((_, _) => throw new InvalidOperationException("unexpected acquisition")),
        tick ?? (ct => Task.Delay(Timeout.InfiniteTimeSpan, ct)));

    [Theory]
    [InlineData(null)] [InlineData("")] [InlineData("0")] [InlineData(" 0 ")]
    public async Task DisabledByDefaultNeverReadsRouteCursorOrAcquisition(string? enabled)
    {
        var stage = new NpsWorkerStage(() => enabled,
            _ => throw new InvalidOperationException("route accessed"),
            (_, _) => throw new InvalidOperationException("database accessed"),
            (_, _) => throw new InvalidOperationException("acquisition started"));
        Assert.Equal("{\"status\":\"disabled\"}", (await stage.RunAsync(["dc.example.test"], null, Ct)).ToJsonString());
    }

    [Theory]
    [InlineData("true")] [InlineData("yes")] [InlineData("2")]
    public async Task InvalidEnableFailsClosed(string value)
    {
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Stage(value).RunAsync([], null, Ct));
        Assert.Equal("nps_eventlog_enabled_value_invalid", error.Message);
    }

    [Fact]
    public async Task CollectionUsesSeparateSecuritySourceAndHeartbeatsUntilCompletion()
    {
        var pending = new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
        var beats = new List<JsonObject>(); NpsCollectionRequest? request = null;
        var stage = Stage("1", (input, _) => { request = input; return pending.Task; }, _ => Task.CompletedTask);
        var result = await stage.RunAsync(["dc.example.test"], beat => {
            beats.Add(beat); pending.SetResult(Result("completed")); return Task.CompletedTask;
        }, Ct);
        Assert.NotNull(request);
        Assert.Equal("nps.example.test", request.Source);
        Assert.Equal("nps.example.test", request.ConnectAddress);
        Assert.Equal(new[] { "Security" }, request.Channels);
        Assert.Equal(new[] { 6272, 6273 }, request.EventIds);
        Assert.True(request.Archive); Assert.True(request.UseRecordIdCursor);
        Assert.Equal("observe", request.AdaptiveStateMode); Assert.False(request.CollectMessage);
        Assert.Equal("dpapi_current_user", request.CredentialMode);
        Assert.True(request.NoTechnicalReport);
        Assert.Equal("2026-09-10T00:00:00+00:00", request.StartTimeUtc);
        Assert.True(DateTimeOffset.Parse(request.EndTimeUtc) > DateTimeOffset.Parse(request.StartTimeUtc));
        Assert.Equal("{\"status\":\"running\",\"phase\":\"nps\",\"source\":\"nps.example.test\"}", Assert.Single(beats).ToJsonString());
        Assert.Equal("completed", result["status"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("failed")] [InlineData("skipped")] [InlineData("blocked")]
    public async Task UnsuccessfulDcNeverStartsNps(string status)
    {
        var cycle = new NpsWorkerCycle(_ => throw new InvalidOperationException("nps started"),
            (_, _) => Task.CompletedTask, (_, _, _, _, _) => throw new InvalidOperationException("block written"));
        var dc = Result(status);
        var result = await cycle.CompleteAsync(dc, "worker-1", 7, Ct);
        Assert.Equal(status, result["status"]!.GetValue<string>()); Assert.False(result.ContainsKey("nps"));
    }

    [Fact]
    public async Task NpsFailureIsSeparateFromCompletedDcAndHistorySurroundsNps()
    {
        var order = new List<string>(); var updates = new List<JsonObject>();
        var nps = Result("failed"); nps["reason"] = "nps_access_denied";
        var cycle = new NpsWorkerCycle(_ => { order.Add("nps"); return Task.FromResult(nps); },
            (row, _) => { order.Add("history"); updates.Add(row.DeepClone().AsObject()); return Task.CompletedTask; },
            (_, _, _, _, _) => throw new InvalidOperationException("unexpected block"));
        var dc = Result("completed"); dc["phase"] = "done";
        var result = await cycle.CompleteAsync(dc, "worker-1", 7, Ct);
        Assert.Equal("failed", result["status"]!.GetValue<string>());
        Assert.Equal("completed", result["dc_status"]!.GetValue<string>());
        Assert.Equal("nps_access_denied", result["nps"]!["reason"]!.GetValue<string>());
        Assert.Equal("nps", updates[^1]["phase"]!.GetValue<string>());
        Assert.Equal(new[] { "history", "nps", "history" }, order);
        Assert.Equal("completed", dc["status"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("completed", 60, "partial", 40, "partial", 100)]
    [InlineData("partial", 6, "completed", 4, "partial", 10)]
    public async Task PartialResultsPreserveDcStatusAndSumDuration(string dcStatus, long dcDuration,
        string npsStatus, long npsDuration, string expected, long duration)
    {
        JsonObject? saved = null;
        var cycle = new NpsWorkerCycle(_ => Task.FromResult(Result(npsStatus, npsDuration)),
            (row, _) => { saved = row.DeepClone().AsObject(); return Task.CompletedTask; },
            (_, _, _, _, _) => throw new InvalidOperationException("unexpected block"));
        var result = await cycle.CompleteAsync(Result(dcStatus, dcDuration), "worker-1", 7, Ct);
        Assert.Equal(expected, result["status"]!.GetValue<string>());
        Assert.Equal(dcStatus, result["dc_status"]!.GetValue<string>());
        Assert.Equal("nps", result["phase"]!.GetValue<string>());
        Assert.Equal(npsStatus, result["nps"]!["status"]!.GetValue<string>());
        Assert.Equal(duration, result["duration_ms"]!.GetValue<long>());
        Assert.Equal(expected, saved!["status"]!.GetValue<string>());
    }

    [Fact]
    public async Task TerminalNpsFailurePersistsCanonicalBlockBeforeTerminalHistory()
    {
        var nps = Result("failed", 1); nps["reason"] = "windows_event_log_authentication_failed";
        nps["blocked"] = true; nps["operator_action"] = "repair credential"; nps["source"] = "nps.example.test";
        var order = new List<string>(); JsonObject? saved = null;
        var cycle = new NpsWorkerCycle(_ => Task.FromResult(nps), (row, _) => {
            order.Add(row["status"]!.GetValue<string>()); saved = row.DeepClone().AsObject(); return Task.CompletedTask;
        }, (worker, job, source, failure, _) => {
            Assert.Equal("worker-1", worker); Assert.Equal(7, job); Assert.Equal("nps.example.test", source);
            Assert.Equal("windows_event_log_authentication_failed", failure["reason"]!.GetValue<string>());
            Assert.Equal("repair credential", failure["operator_action"]!.GetValue<string>());
            order.Add("block"); return Task.CompletedTask;
        });
        var result = await cycle.CompleteAsync(Result("completed"), "worker-1", 7, Ct);
        Assert.Equal("blocked", result["status"]!.GetValue<string>());
        Assert.Equal("completed", result["dc_status"]!.GetValue<string>());
        Assert.Equal("blocked", saved!["status"]!.GetValue<string>());
        Assert.Equal(new[] { "running", "block", "blocked" }, order);
    }

    [Fact]
    public async Task DisabledNpsKeepsOriginalDcPhaseDurationAndNoSupplementalFields()
    {
        var dc = Result("partial", 60); dc["phase"] = "done";
        var cycle = new NpsWorkerCycle(_ => Task.FromResult(new JsonObject { ["status"] = "disabled" }),
            (_, _) => Task.CompletedTask, (_, _, _, _, _) => throw new InvalidOperationException("block written"));
        Assert.True(JsonNode.DeepEquals(dc, await cycle.CompleteAsync(dc, "worker-1", 7, Ct)));
    }

    [Theory]
    [InlineData("windows_event_log_authentication_failed", "windows_event_log_authentication_failed")]
    [InlineData("WinError 1326", "windows_event_log_authentication_failed")]
    [InlineData("windows_security_context_invalid", "windows_security_context_invalid")]
    public async Task AcquisitionExceptionBlocksWithSourceAndNeverReturnsPrivateDiagnostic(string marker, string reason)
    {
        var stage = Stage("1", (_, _) => throw new InvalidOperationException(marker + " private-event-data"));
        var result = await stage.RunAsync([], null, Ct);
        Assert.Equal("failed", result["status"]!.GetValue<string>());
        Assert.True(result["blocked"]!.GetValue<bool>());
        Assert.Equal(reason, result["reason"]!.GetValue<string>());
        Assert.Equal("nps.example.test", result["source"]!.GetValue<string>());
        Assert.DoesNotContain("private-event-data", result.ToJsonString());
    }

    [Fact]
    public async Task RuntimeRejectsEvenAnEnabledRegistrationWithoutAcquisitionOrWrites()
    {
        string root = Path.Combine(Path.GetTempPath(), "sli-nps-stage-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try {
            string route = Path.Combine(root, "route.json");
            await File.WriteAllTextAsync(route, Agents.RadiusCollectionRouteTests.Route, Ct);
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
                ["Sli:ProjectRoot"] = root, ["Sli:Legacy:ADLOG_NPS_EVENTLOG_ENABLED"] = "1",
                ["Sli:Legacy:ADLOG_RADIUS_COLLECTION_ROUTES_PATH"] = route,
                ["Sli:Legacy:ADLOG_RADIUS_SOURCE_NAME"] = "nps.example.test"
            }).Build();
            var session = new Session(); var acquisition = new Acquisition();
            var runtime = new NpsWorkerRuntime(session, new(config), acquisition, new OperationsFiles(config), new(new NoConnections()));
            var dc = Result("completed", 60);
            var result = await runtime.CompleteAsync(dc,
                new(7, true, new(["dc.example.test"], 1, 90000), "external_worker"), "worker-1", Ct);
            Assert.Null(acquisition.Input);
            Assert.Equal("disabled", result["status"]!.GetValue<string>());
            Assert.Equal("module_disabled", result["reason"]!.GetValue<string>());
            Assert.True(JsonNode.DeepEquals(Result("completed", 60), dc));
            Assert.Empty(session.Order);
            Assert.Null(session.Block);
            Assert.DoesNotContain("private-event-data", result.ToJsonString());
            Assert.Equal(0, session.Commits);
        }
        finally { Directory.Delete(root, true); }
    }

    private sealed class NoConnections : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => throw new InvalidOperationException("unexpected heartbeat database access");
    }
    private sealed class Acquisition : ILegacyAcquisition
    {
        internal LegacyJobInput? Input;
        public Task<LegacyCollectionBatch> CollectAsync(LegacyJobInput input, CancellationToken ct)
        {
            Input = input;
            return Task.FromResult(new LegacyCollectionBatch("failed", [], Errors: ["windows_event_log_authentication_failed private-event-data"]));
        }
    }
    private sealed class Session : ISemanticDatabase, ISemanticSession
    {
        internal List<string> Order = [];
        internal object?[]? Block;
        internal int Commits;
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct) => Task.FromResult<ISemanticSession>(this);
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            if (sql.StartsWith("select installed,enabled")) return Task.FromResult(new JsonArray(new JsonObject { ["installed"] = true, ["enabled"] = true }));
            if (sql.Contains("from archive_settings")) {
                Assert.Equal("nps.example.test", Assert.Single(values));
                return Task.FromResult(new JsonArray(new JsonObject { ["start_time_utc"] = "2026-09-10T00:00:00+00:00" }));
            }
            if (sql.StartsWith("insert into runtime_collection_runs")) Order.Add((string)values[3]!);
            else if (sql.StartsWith("insert into runtime_collection_blocks")) { Order.Add("block"); Block = values; }
            else throw new InvalidOperationException("unexpected query");
            return Task.FromResult(new JsonArray());
        }
        public Task CommitAsync(CancellationToken ct) { Commits++; return Task.CompletedTask; }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
