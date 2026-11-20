using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Reporting.V2;
using Sli.Server.Semantic;
using Sli.Server.Tests.Problems;
using Xunit;

namespace Sli.Server.Tests.Reporting;

// Vectors from tests/reporting/test_file_acl_evidence_v2.py.
public sealed class FileAclEvidenceV2Tests
{
    private const string Watermark = "2026-01-02T00:00:00+00:00";
    private static readonly string[] Fields = ["security", "raw_evidence", "identity_basic", "technical"];
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static JsonObject Resource() => new()
    {
        ["installation_id"] = "00000000-0000-4000-8000-000000000099",
        ["plugin_id"] = "sli.file-audit", ["agent_id"] = "00000000-0000-4000-8000-000000000001",
        ["source_instance_id"] = "synthetic-source", ["collection_scope_id"] = "synthetic-root"
    };
    private static JsonObject Native(int id) => new()
    {
        ["storage_kind"] = "file_audit_snapshot", ["evidence_key"] = new string((char)('0' + id), 64),
        ["evidence_role"] = "semantic_scenario", ["time_created_utc"] = "2026-01-01T00:00:00Z", ["availability"] = "available", ["historical"] = true,
        ["observed_at_utc"] = "2026-01-01T00:00:00+00:00", ["resource"] = null,
        ["coverage"] = new JsonObject { ["state"] = "complete", ["unread_objects"] = 0, ["has_more"] = false },
        ["grants"] = new JsonArray(), ["grants_has_more"] = false, ["limitations"] = new JsonArray()
    };
    private static ReportQueryContext Context(string action = "view", string[]? capabilities = null, bool fields = true, int limit = 20)
    {
        var grant = new AtomicReportGrant(ReportFixture.J("""{"kind":"all"}"""), Fields.ToHashSet(), new HashSet<string> { "view", "export" }, 1, 1);
        var caps = new CapabilityDecisionSet(false, (capabilities ?? ["file-audit.view"]).ToHashSet(), new HashSet<string>(), [], new Dictionary<string, JsonElement>());
        var access = new AccessDecision("viewer", caps, [new("security.queue", true, [grant])]);
        return new(new ReportDefinitionRegistry().Get("security.problems")!, access, new Principal("session", 1, "viewer"),
            new JsonObject(), new(null, limit, "UTC", null, "asc", null), new ReportScope("all", []), [7], action, _ => fields, [grant]);
    }

    // Replace only query results, as the Python reference does. Authorization,
    // keyset merging, cursor validation and report rendering are production code.
    private sealed class Database(int coreCount = 0, int nativeCount = 1) : ISemanticDatabase, ISemanticSession
    {
        internal readonly List<(string Sql, object?[] Values)> Calls = [];
        internal int Opens, Commits, Disposals;
        internal bool DenyNative;
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct)
        {
            Assert.False(write); Opens++; return Task.FromResult<ISemanticSession>(this);
        }
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            Calls.Add((sql, values));
            JsonArray rows;
            if (sql.Contains("clock_timestamp")) rows = [new JsonObject { ["watermark"] = Watermark }];
            else if (sql.Contains("read_file_acl_finding_resources"))
            {
                Assert.Equal(7L, values[0]); Assert.Equal(new long[] { 7 }, Assert.IsType<long[]>(values[1]));
                rows = [new JsonObject { ["resources"] = new JsonArray(Resource()) }];
            }
            else if (sql.Contains("count(*)")) rows = [new JsonObject { ["total"] = (long)coreCount }];
            else if (sql.Contains("from finding_event_details337 e"))
            {
                long after = Assert.IsType<long>(values[1]); int limit = Assert.IsType<int>(values[2]);
                rows = new JsonArray(Enumerable.Range(1, coreCount).Where(id => id > after).Take(limit).Select(id => (JsonNode)new JsonObject
                {
                    ["evidence_id"] = (long)id, ["event_db_id"] = (long)id, ["evidence_role"] = "semantic_scenario", ["time_created_utc"] = "2026-01-01T00:00:00Z"
                }).ToArray());
            }
            else
            {
                Assert.Contains("read_file_acl_finding_evidence(", sql); Assert.False(DenyNative, "Unauthorized native payload/count lookup");
                Assert.Equal(7L, values[0]); Assert.True(JsonNode.DeepEquals(new JsonArray(Resource()), Assert.IsType<JsonArray>(values[1])));
                Assert.Equal(Watermark, values[4]); Assert.Equal(new long[] { 7 }, Assert.IsType<long[]>(values[5]));
                string? after = values[2] as string; int limit = Assert.IsType<int>(values[3]);
                var remaining = Enumerable.Range(1, nativeCount).Select(Native)
                    .Where(row => after is null || string.CompareOrdinal(row["evidence_key"]!.ToString(), after) > 0).ToArray();
                var items = new JsonArray();
                foreach (var row in remaining.Take(limit)) { row["_native_key"] = row["evidence_key"]!.DeepClone(); items.Add(row); }
                rows = [new JsonObject { ["evidence"] = new JsonObject { ["items"] = items, ["total"] = nativeCount, ["has_more"] = remaining.Length > limit } }];
            }
            return Task.FromResult(rows);
        }
        public Task CommitAsync(CancellationToken ct) { Commits++; return Task.CompletedTask; }
        public ValueTask DisposeAsync() { Disposals++; return ValueTask.CompletedTask; }
    }

    [Fact]
    public async Task NativeSnapshotIsNotAMissingEventAndUsesRegisteredDetail()
    {
        var db = new Database(); var context = Context();
        var reader = new SecurityProblemsReader(new ProblemEndpointTests.Repository(), new SecurityProblemEvidence(db));
        var body = await reader.DetailAsync(context, "7", Ct);
        Assert.Equal("ok", body["state"]!.ToString());
        Assert.Equal(0, body["coverage"]!["evidence_missing_sources"]!.GetValue<int>());
        Assert.Equal(1, body["coverage"]!["evidence_native_snapshots"]!.GetValue<int>());
        Assert.True(body["coverage"]!["evidence_historical"]!.GetValue<bool>());
        Assert.Equal("problems.acl-evidence", context.Definition.Declaration["detail"]!["row_component"]!.ToString());
        var row = Assert.Single(body["items"]!.AsArray())!.AsObject();
        Assert.True(JsonNode.DeepEquals(Native(1), row)); Assert.False(row.ContainsKey("event_db_id"));
        Assert.Equal(1, db.Commits); Assert.Equal(1, db.Disposals);
    }

    [Theory]
    [InlineData("domains")]
    [InlineData("action")]
    public async Task SnapshotCursorIsBoundToSelectedDomainsAndAction(string changed)
    {
        var db = new Database(nativeCount: 2); var context = Context(limit: 1);
        var reader = new SecurityProblemsReader(new ProblemEndpointTests.Repository(), new SecurityProblemEvidence(db));
        var body = await reader.DetailAsync(context, "7", Ct);
        string cursor = body["next_cursor"]!.GetValue<string>();
        var next = context with { Paging = context.Paging with { Cursor = cursor } };
        var continuation = await reader.DetailAsync(next, "7", Ct);
        Assert.Equal(new string('2', 64), Assert.Single(continuation["items"]!.AsArray())!["evidence_key"]!.ToString());
        Assert.False(continuation["has_more"]!.GetValue<bool>()); Assert.Null(continuation["next_cursor"]);
        var altered = changed == "domains" ? next with { DomainIds = [8] } : next with { Action = "export" };
        var error = await Assert.ThrowsAsync<ReportRequestException>(() => reader.DetailAsync(altered, "7", Ct));
        Assert.Equal("invalid_cursor", error.Message); Assert.Equal(2, db.Opens);
        Assert.Single(db.Calls, c => c.Sql.Contains("clock_timestamp"));
    }

    [Theory]
    [InlineData("view", false, true)]
    [InlineData("export", true, true)]
    [InlineData("view", true, false)]
    public async Task IndependentNativeScopeOrFieldsDenialHidesPayloadAndCounts(string action, bool viewCapability, bool fields)
    {
        var db = new Database { DenyNative = true };
        var context = Context(action, viewCapability ? ["file-audit.view"] : [], fields);
        var page = await new SecurityProblemEvidence(db).PageAsync(context, 7, null, Ct);
        Assert.Empty(page["items"]!.AsArray()); Assert.Equal(0L, page["total"]!.GetValue<long>());
        Assert.False(page["has_more"]!.GetValue<bool>()); Assert.Null(page["next_position"]);
        Assert.DoesNotContain(db.Calls, c => c.Sql.Contains("read_file_acl_finding_evidence("));
        Assert.Equal(fields ? 1 : 0, db.Calls.Count(c => c.Sql.Contains("read_file_acl_finding_resources")));
        Assert.Equal(1, db.Commits); Assert.Equal(1, db.Disposals);
    }

    [Fact]
    public async Task MixedTypedKeysetKeepsAllEventsAndNativeRowsWithoutFakeIds()
    {
        var db = new Database(coreCount: 2, nativeCount: 3); var context = Context(limit: 2);
        var evidence = new SecurityProblemEvidence(db); var combined = new List<JsonObject>();
        JsonObject? cursor = null;
        for (int index = 0; index < 3; index++)
        {
            var page = await evidence.PageAsync(context, 7, cursor, Ct);
            Assert.Equal(5L, page["total"]!.GetValue<long>()); Assert.Equal(Watermark, page["watermark"]!.ToString());
            combined.AddRange(page["items"]!.AsArray().OfType<JsonObject>());
            Assert.Equal(index < 2, page["has_more"]!.GetValue<bool>());
            if (index < 2)
            {
                var position = page["next_position"]!.AsObject();
                Assert.Equal(index == 0 ? "core_event" : "file_audit_snapshot", position["storage_kind"]!.ToString());
                if(index==0) Assert.Equal(2,JsonNode.Parse(position["native_key"]!.ToString())![0]!.GetValue<long>());
                else Assert.Equal(new string('2',64),position["native_key"]!.ToString());
                cursor = new() { ["version"] = 2, ["position"] = position.DeepClone(), ["watermark"] = Watermark };
            }
            else Assert.Null(page["next_position"]);
        }
        Assert.Equal(new long[] { 1, 2 }, combined.Where(r => r["storage_kind"]!.ToString() == "core_event").Select(r => r["event_db_id"]!.GetValue<long>()));
        var snapshots = combined.Where(r => r["storage_kind"]!.ToString() == "file_audit_snapshot").ToArray();
        Assert.Equal(Enumerable.Range(1, 3).Select(i => new string((char)('0' + i), 64)), snapshots.Select(r => r["evidence_key"]!.ToString()));
        Assert.All(snapshots, row => { Assert.False(row.ContainsKey("event_db_id")); Assert.False(row.ContainsKey("_native_key")); });
        Assert.Equal(3, db.Commits); Assert.Equal(3, db.Disposals);
        Assert.Single(db.Calls, c => c.Sql.Contains("clock_timestamp"));
        Assert.Equal(2, db.Calls.Count(c => c.Sql.Contains("from finding_event_details337 e")));
    }
}
