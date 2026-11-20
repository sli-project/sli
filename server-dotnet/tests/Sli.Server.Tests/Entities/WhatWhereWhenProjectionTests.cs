using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Entities;
using Sli.Server.Storage.Archive;
using Xunit;

namespace Sli.Server.Tests.Entities;

public sealed class WhatWhereWhenProjectionTests
{
    static JsonObject Fixture()
    {
        using var stream = typeof(WhatWhereWhenProjectionTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Entities.what-where-when-vectors.json")!;
        return JsonNode.Parse(stream)!.AsObject();
    }
    [Fact]
    public void ClassifiesLogonsExactlyLikeFrozenPythonSourceVectors()
    {
        var fixture = Fixture(); var index = WhatWhereWhenProjection.Index(fixture["computers"]!.AsObject());
        var classification = fixture["classifications"]!.AsObject().ToDictionary(p => p.Key, p => p.Value!.GetValue<bool>());
        foreach (var item in fixture["cases"]!.AsArray().OfType<JsonObject>())
        {
            var actual = WhatWhereWhenProjection.Project(item["event"]!.AsObject(), index, classification); var expected = item["expected"]!.AsObject();
            Assert.Equal(expected["status"]!.ToString(), actual.Status); Assert.Equal(expected["reason"]?.ToString(), actual.Reason);
            if (actual.Observation is { } observed)
            {
                var source = expected["observation"]!.AsObject();
                Assert.Equal(EntityReader.Number(source, "source_event_id"), observed.EventId);
                Assert.Equal(source["source_event_hash"]!.ToString(), Convert.ToHexString(observed.Hash).ToLowerInvariant());
                Assert.Equal(source["computer_object_guid"]!.ToString(), observed.ComputerGuid); Assert.Equal(source["computer_name"]!.ToString(), observed.ComputerName);
                Assert.Equal(source["user_name"]!.ToString(), observed.UserName); Assert.Equal(DateTimeOffset.Parse(source["observed_at_utc"]!.ToString(), CultureInfo.InvariantCulture), observed.Observed);
            }
        }
    }
    [Theory]
    [InlineData("alice", null, null, false)] [InlineData("svc.backup", null, null, true)] [InlineData("alice", "CN=alice,OU=ServiceAcc,DC=test", null, true)]
    [InlineData("alice", null, "Service account", true)] [InlineData("svcalice", null, null, false)]
    public void PreservesSourceServiceAccountHeuristic(string sam, string? dn, string? display, bool expected)
    { Assert.Equal(expected, WhatWhereWhenProjection.ServiceAccount(new() { ["samAccountName"] = sam, ["distinguishedName"] = dn, ["displayName"] = display })); }
    [Fact]
    public void LocalHourIsNovosibirskAndCollisionPreservingIndexCannotGuessAnIdentity()
    {
        Assert.Equal(new DateTime(2026, 1, 1, 7, 0, 0), WhatWhereWhenProjection.Hour(DateTimeOffset.Parse("2026-01-01T00:59:00Z", CultureInfo.InvariantCulture)));
        var fixture = Fixture(); var computers = fixture["computers"]!.AsObject();
        var copy = computers["objects"]![0]!.DeepClone(); copy["objectGuid"] = "55555555-5555-5555-5555-555555555555"; computers["objects"]!.AsArray().Add(copy);
        var decision = WhatWhereWhenProjection.Project(fixture["cases"]![0]!["event"]!.AsObject(), WhatWhereWhenProjection.Index(computers), new Dictionary<string, bool> { ["ivanov"] = false });
        Assert.Equal("ambiguous", decision.Status); Assert.Equal("computer_identity_not_unique", decision.Reason);
    }
    [Fact]
    public void ValidatesSnapshotAndItsExactSourceCanonicalHash()
    {
        var fixture = Fixture(); var snapshot = fixture["valid_snapshot"]!.AsObject();
        Assert.Same(snapshot, WhatWhereWhenSnapshots.Validate(snapshot));
        WhatWhereWhenCycle.VerifyHash(snapshot, fixture["snapshot_sha256"]!.ToString(), "bad_hash");
        snapshot["objects"]![0]!["name"] = "tampered";
        Assert.Equal("bad_hash", Assert.Throws<InvalidDataException>(() => WhatWhereWhenCycle.VerifyHash(snapshot, fixture["snapshot_sha256"]!.ToString(), "bad_hash")).Message);
    }
    [Theory]
    [InlineData("schema")] [InlineData("count")] [InlineData("identity")] [InlineData("duplicate")] [InlineData("demo")] [InlineData("dc_events")]
    [InlineData("missing_source")] [InlineData("not_collected_observation")] [InlineData("source_error")] [InlineData("missing_field")]
    public void RejectsInvalidSourceSnapshotBeforeItCanBecomeAuthority(string mutation)
    {
        var snapshot = Fixture()["valid_snapshot"]!.AsObject(); var item = snapshot["objects"]![0]!.AsObject();
        switch (mutation)
        {
            case "schema": snapshot["schema_version"] = "1"; break;
            case "count": snapshot["metadata"]!["object_count"] = 2; break;
            case "identity": item["id"] = "55555555-5555-5555-5555-555555555555"; break;
            case "duplicate": snapshot["objects"]!.AsArray().Add(item.DeepClone()); snapshot["metadata"]!["object_count"] = 2; break;
            case "demo": snapshot["metadata"]!["label"] = "demo"; break;
            case "dc_events": item["sources"]!["dc_events"]!["status"] = "observed"; break;
            case "missing_source": item["sources"]!.AsObject().Remove("ad"); break;
            case "not_collected_observation": item["sources"]!["dns"]!["observed_at"] = "2026-01-01T00:00:00Z"; break;
            case "source_error": item["sources"]!["dns"]!["status"] = "failed"; item["sources"]!["dns"]!["observed_at"] = "2026-01-01T00:00:00Z"; break;
            case "missing_field": item.Remove("enabled"); break;
        }
        Assert.Throws<InvalidDataException>(() => WhatWhereWhenSnapshots.Validate(snapshot));
    }
    sealed class Transaction : IWhatWhereWhenTransaction
    {
        public bool Locked = true, Configured = true, BadHash, Collapse, Conflict;
        public bool Completed { get; set; }
        public JsonArray Hot = new(), Reconciliation = new();
        public readonly List<(string Sql, Dictionary<string, object> Args)> Reads = [], Writes = [];
        public Task<JsonArray> Query(string sql, Dictionary<string, object> args, CancellationToken ct)
        {
            Reads.Add((sql, args));
            var fixture = Fixture(); JsonArray rows;
            if (sql.Contains("platform_settings", StringComparison.Ordinal)) rows = Configured ? new(new JsonObject { ["value"] = "example.test" }) : new();
            else if (sql.Contains("from domains d", StringComparison.Ordinal)) rows = Configured ? new(new JsonObject { ["id"] = 1, ["display_name"] = "example.test", ["is_archived"] = false }) : new();
            else if (sql.Contains("pg_try_advisory_xact_lock", StringComparison.Ordinal)) rows = new(new JsonObject { ["acquired"] = Locked });
            else if (sql.Contains("select id from domains", StringComparison.Ordinal)) rows = JsonNode.Parse("[{\"id\":1}]")!.AsArray();
            else if (sql.Contains("projection_state where", StringComparison.Ordinal)) rows = new(new JsonObject { ["high_water_event_id"] = 0, ["initial_cutoff_utc"] = "2025-01-01T00:00:00Z", ["backfill_completed"] = Completed });
            else if (sql.Contains("computers_v6_source_snapshots", StringComparison.Ordinal)) rows = new(new JsonObject { ["source_snapshot_id"] = 20, ["domain_id"] = 1, ["snapshot_uuid"] = "44444444-4444-4444-4444-444444444444", ["collection_status"] = "complete", ["base_inventory_status"] = "observed", ["object_count"] = 1, ["payload_json"] = fixture["valid_snapshot"]!.DeepClone(), ["payload_sha256"] = BadHash ? new string('0', 64) : fixture["snapshot_sha256"]!.ToString() });
            else if (sql.Contains("users_report_v2_snapshots", StringComparison.Ordinal))
            {
                var payload = JsonNode.Parse("{\"users\":[{\"samAccountName\":\"Ivanov\"}]}")!;
                rows = new(new JsonObject { ["snapshot_id"] = 30, ["payload_json"] = payload, ["payload_sha256"] = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalJson.Serialize(payload, false)))) });
            }
            else if (sql.Contains("not exists(select 1 from what_where_when_observations", StringComparison.Ordinal)) rows = (JsonArray)Reconciliation.DeepClone();
            else if (sql.Contains("from event_rows event", StringComparison.Ordinal)) rows = (JsonArray)Hot.DeepClone();
            else if (sql.Contains("where source_event_id=@id", StringComparison.Ordinal)) rows = Conflict ? JsonNode.Parse("[{\"source_event_id\":10,\"source_event_hash\":\"00\",\"computer_object_guid\":\"bad\"}]")!.AsArray() : new();
            else if (sql.Contains("insert into what_where_when_observations", StringComparison.Ordinal)) { Writes.Add((sql, args)); rows = Collapse ? new() : new(new JsonObject { ["source_event_id"] = Convert.ToInt64(args["id"]) }); }
            else throw new InvalidOperationException(sql);
            return Task.FromResult(rows);
        }
        public Task<int> Execute(string sql, Dictionary<string, object> args, CancellationToken ct) { Writes.Add((sql, args)); return Task.FromResult(1); }
    }
    static JsonObject Event(int id = 10) { var item = Fixture()["cases"]![0]!["event"]!.DeepClone().AsObject(); item["source_event_id"] = id; return item; }
    [Fact]
    public async Task CycleProjectsBoundedHotPageAndPersistsCursorWithRetention()
    {
        var tx = new Transaction { Hot = new(Event()) };
        var result = await WhatWhereWhenCycle.Run(tx, 2, 3, TestContext.Current.CancellationToken);
        Assert.Equal("ok", result["status"]!.ToString()); Assert.Equal(1, result["inserted"]!.GetValue<int>()); Assert.Equal(10, result["high_water"]!.GetValue<long>()); Assert.True(result["backfill_completed"]!.GetValue<bool>());
        var insert = Assert.Single(tx.Writes, w => w.Sql.Contains("insert into what_where_when_observations", StringComparison.Ordinal));
        Assert.Equal("example\\ivanov", insert.Args["key"]); Assert.Equal(new DateTime(2026, 1, 1, 7, 0, 0), insert.Args["hour"]);
        var retention = Assert.Single(tx.Writes, w => w.Sql.Contains("with doomed", StringComparison.Ordinal)); Assert.Equal(3, retention.Args["limit"]);
        var update = tx.Writes.Last(); Assert.Contains("update what_where_when_projection_state", update.Sql); Assert.Equal(10L, update.Args["high"]); Assert.Equal(true, update.Args["complete"]);
        var hot = Assert.Single(tx.Reads, w => w.Sql.Contains("event.time_created_utc>=@cutoff", StringComparison.Ordinal)); Assert.Equal(3, hot.Args["limit"]);
    }
    [Fact]
    public async Task PageLookaheadDoesNotSkipUnprocessedEvents()
    {
        var tx = new Transaction { Hot = new(Event(10),Event(11),Event(12)) };
        var result = await WhatWhereWhenCycle.Run(tx, 2, 3, TestContext.Current.CancellationToken);
        Assert.Equal(2, result["inserted"]!.GetValue<int>());
        Assert.Equal(11, result["high_water"]!.GetValue<long>());
        Assert.False(result["backfill_completed"]!.GetValue<bool>());
    }
    [Fact]
    public async Task ReconciliationCannotAdvanceHighWaterAndHourlyCollisionIsCollapsed()
    {
        var tx = new Transaction { Reconciliation = new(Event(100)), Collapse = true };
        var result = await WhatWhereWhenCycle.Run(tx, 2, 3, TestContext.Current.CancellationToken);
        Assert.Equal(0, result["high_water"]!.GetValue<long>()); Assert.Equal(1, result["collapsed"]!.GetValue<int>());
    }
    [Theory] [InlineData(false, true, "report_domain_not_configured")] [InlineData(true, false, "lock_busy")]
    public async Task NoDomainOrBusyLockStopsWithoutAnyMutation(bool configured, bool locked, string reason)
    {
        var tx = new Transaction { Configured = configured, Locked = locked };
        var result = await WhatWhereWhenCycle.Run(tx, 2, 3, TestContext.Current.CancellationToken);
        Assert.Equal(reason, result["reason"]!.ToString()); Assert.Empty(tx.Writes); Assert.DoesNotContain(tx.Reads, r => r.Sql.Contains("snapshot", StringComparison.Ordinal));
    }
    [Theory] [InlineData(true, false)] [InlineData(false, true)]
    public async Task BadSourceOrIdentityConflictNeverAdvancesCursor(bool hash, bool conflict)
    {
        var tx = new Transaction { BadHash = hash, Conflict = conflict, Hot = new(Event()) };
        await Assert.ThrowsAsync<InvalidDataException>(() => WhatWhereWhenCycle.Run(tx, 2, 3, TestContext.Current.CancellationToken));
        Assert.DoesNotContain(tx.Writes, w => w.Sql.Contains("update what_where_when_projection_state", StringComparison.Ordinal));
    }
    [Fact]
    public async Task CommandClampsBoundsAndPassesOnceToRunner()
    {
        WhatWhereWhenOptions? received = null; var stdout = new StringWriter(); var stderr = new StringWriter();
        int code = await WhatWhereWhenCommand.RunCore(["--once", "--batch-limit", "999999", "--retention-limit", "0"], (options, output, ct) => { received = options; return Task.FromResult(0); }, stdout, stderr, TestContext.Current.CancellationToken);
        Assert.Equal(0, code); Assert.NotNull(received); Assert.True(received.Once); Assert.Equal(10000, received.Batch); Assert.Equal(1, received.Retention);
        Assert.Equal("", stderr.ToString());
    }
}
