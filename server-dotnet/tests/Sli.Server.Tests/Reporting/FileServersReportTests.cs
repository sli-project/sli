using System.Net;
using System.Text.Json.Nodes;
using Sli.Server.Reporting.V2;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class FileServersReportTests
{
    private static JsonObject Raw(string id = "41600000-0000-4000-8000-000000000004", int revision = 2) => new()
    {
        ["root"] = FileAuditReportTests.Root(),
        ["policy"] = new JsonObject { ["policy_revision"] = revision.ToString(), ["roots"] = new JsonArray(FileAuditReportTests.Root()) },
        ["snapshot"] = new JsonObject { ["id"] = id, ["observed_at"] = revision == 2 ? "2026-11-20T12:00:00Z" : "2026-11-20T11:00:00Z",
            ["policy_revision"] = revision.ToString(), ["completeness"] = "partial", ["page_number"] = 1, ["has_more"] = false },
        ["object_state"] = "observed",
        ["object"] = new JsonObject { ["path"] = @"C:\share", ["object_type"] = "directory", ["object_id"] = "volume:42",
            ["owner_sid"] = "S-1-5-21-1-2-3-1001", ["dacl"] = "D:(D;;FW;;;WD)(A;CIIO;FR;;;BA)(A;ID;0x021f01ff;;;S-1-5-21-1-2-3-9999)", ["sacl"] = "S:" },
        ["share"] = new JsonObject { ["name"] = "share", ["path"] = @"C:\share", ["complete"] = true, ["dacl"] = "D:(A;;FR;;;AU)" },
        ["snapshots"] = new JsonArray(new JsonObject { ["id"] = id }),
        ["objects"] = new JsonArray(new JsonObject { ["id"] = "object", ["path"] = @"C:\share", ["snapshot_id"] = id }),
        ["snapshots_has_more"] = false, ["objects_has_more"] = false
    };

    [Fact]
    public void Long_acl_preserves_order_duplicates_masks_and_unsupported_condition()
    {
        string entries = string.Concat(Enumerable.Range(0, 126).Select(n => $"(A;CIIO;0x021f01ff;;;S-1-5-21-1-2-3-{1000 + n})"));
        var parsed = FileAuditReportReader.DescribeAcl("D:" + entries, "D");
        Assert.Equal("complete", parsed["state"]!.ToString());
        Assert.Equal(126, parsed["aces"]!.AsArray().Count);
        Assert.Equal(126, parsed["aces"]![125]!["ordinal"]!.GetValue<int>());
        Assert.True(parsed["aces"]![0]!["inherit_only"]!.GetValue<bool>());
        Assert.Equal(0x021f01ffU, parsed["aces"]![0]!["mask"]!.GetValue<uint>());
        const string conditional = "(XA;CI;FR;;;S-1-1-0;((@User.Department == \"Finance\") || (@User.Level > 1)))";
        var unsupported = FileAuditReportReader.DescribeAcl("D:" + conditional + "(D;;FW;;;WD)", "D");
        Assert.Equal("unsupported", unsupported["state"]!.ToString());
        Assert.Equal(conditional, unsupported["aces"]![0]!["raw"]!.ToString());
        Assert.Equal("unknown", unsupported["aces"]![0]!["type"]!.ToString());
        Assert.Equal("deny", unsupported["aces"]![1]!["type"]!.ToString());
        Assert.Equal("missing", FileAuditReportReader.DescribeAcl(null, "D")["state"]!.ToString());
        Assert.Equal("complete", FileAuditReportReader.DescribeAcl("D:", "D")["state"]!.ToString());
        Assert.Equal("partial", FileAuditReportReader.DescribeAcl("D:(A;;FR;;;WD)", "D", false)["state"]!.ToString());
    }

    [Fact]
    public void Comparison_uses_object_identity_and_preserves_missing_layers()
    {
        var current = Raw(); var before = Raw("41600000-0000-4000-8000-000000000003", 1);
        before["object"]!.AsObject().Remove("sacl");
        var result = FileAuditReportReader.CompareSnapshots(current, before, true);
        Assert.Equal("available", result["state"]!.ToString());
        Assert.Equal("file_id", result["identity_basis"]!.ToString());
        Assert.Equal("missing", result["before"]!["object"]!["sacl"]!["state"]!.ToString());
        Assert.Equal("complete", result["before"]!["object"]!["dacl"]!["state"]!.ToString());
        before["object"]!["object_id"] = "volume:replaced";
        Assert.Equal("object_replaced", FileAuditReportReader.CompareSnapshots(current, before, true)["reason"]!.ToString());
        before["object"]!.AsObject().Remove("object_id");
        Assert.Equal("path", FileAuditReportReader.CompareSnapshots(current, before, true)["identity_basis"]!.ToString());
        before["policy"]!["roots"]![0]!["path"] = @"C:\other";
        Assert.Equal("policy_incompatible", FileAuditReportReader.CompareSnapshots(current, before, true)["reason"]!.ToString());
        before["object"] = null;
        Assert.Equal("object_unavailable", FileAuditReportReader.CompareSnapshots(current, before, true)["reason"]!.ToString());
        Assert.Equal("snapshot_unavailable", FileAuditReportReader.CompareSnapshots(current, null, true)["reason"]!.ToString());
    }

    private sealed class InventoryDatabase : ISemanticDatabase, ISemanticSession
    {
        public JsonArray Roots = [FileAuditReportTests.Root()];
        public JsonObject Current = Raw();
        public JsonObject Prior = Raw("41600000-0000-4000-8000-000000000003", 1);
        public int SnapshotReads, Commits;
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct)
        { Assert.False(write); return Task.FromResult<ISemanticSession>(this); }
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            if (sql.Contains("report_roots")) return Task.FromResult(new JsonArray(new JsonObject { ["roots"] = Roots.DeepClone() }));
            SnapshotReads++;
            Assert.Equal(FileAuditReportReader.ShareKey(FileAuditReportTests.Root()), FileAuditReportReader.ShareKey((JsonNode)values[0]!));
            Assert.Equal(@"C:\share", values[3]);
            return Task.FromResult(new JsonArray(new JsonObject
            {
                ["snapshot"] = values[1]!.ToString() == Current["snapshot"]!["id"]!.ToString() ? Current.DeepClone() : Prior.DeepClone()
            }));
        }
        public Task CommitAsync(CancellationToken ct) { Commits++; return Task.CompletedTask; }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private static string DetailUrl(string? share = null, string? path = null) =>
        "/api/v2/reports/file-audit.permissions/rows/41600000-0000-4000-8000-000000000004/detail?source_kind=server&share="
        + Uri.EscapeDataString(share ?? FileAuditReportReader.ShareKey(FileAuditReportTests.Root()))
        + "&path=" + Uri.EscapeDataString(path ?? @"C:\share");

    [Fact]
    public async Task Detail_returns_only_the_authorized_object_and_keeps_snapshot_page_completeness()
    {
        var db = new InventoryDatabase();
        await using var host = await ReportFixture.Start(FileAuditReportTests.Facts("permissions"),
            new ReportDefinitionRegistry().Get("file-audit.permissions"), nativeReader: new FileAuditReportReader(db));
        using var response = await host.Client.GetAsync(DetailUrl() + "&compare_snapshot_id=41600000-0000-4000-8000-000000000003",
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await ReportFixture.Body(response);
        Assert.Equal("complete", body["detail"]!["object"]!["dacl"]!["state"]!.ToString());
        Assert.Equal("complete", body["detail"]!["share"]!["dacl"]!["state"]!.ToString());
        Assert.Equal("partial", body["detail"]!["snapshot"]!["completeness"]!.ToString());
        Assert.Equal("not_proven", body["coverage"]!["completeness"]!.ToString());
        Assert.Equal("available", body["detail"]!["comparison"]!["state"]!.ToString());
        Assert.Single(body["collections"]!["objects"]!.AsArray());
        Assert.Single(body["collections"]!["snapshots"]!.AsArray());
        Assert.False(body["detail"]!.AsObject().ContainsKey("policy"));
        Assert.Equal(2, db.SnapshotReads); Assert.Equal(1, db.Commits);
    }

    [Theory]
    [InlineData("source")]
    [InlineData("path")]
    [InlineData("scope")]
    [InlineData("grant")]
    public async Task Detail_rechecks_root_path_and_report_grant_before_snapshot_read(string denied)
    {
        var db = new InventoryDatabase();
        var facts = FileAuditReportTests.Facts("permissions", allowed: denied != "grant",
            scope: denied == "scope" ? """{"mode":"restricted","clauses":[{"collection_scope_ids":["other"]}]}""" : """{"kind":"all"}""");
        await using var host = await ReportFixture.Start(facts, new ReportDefinitionRegistry().Get("file-audit.permissions"),
            nativeReader: new FileAuditReportReader(db));
        var root = FileAuditReportTests.Root();
        if (denied == "source") root["source_instance_id"] = "other";
        using var response = await host.Client.GetAsync(DetailUrl(FileAuditReportReader.ShareKey(root),
            denied == "path" ? @"C:\share-old\secret" : null), TestContext.Current.CancellationToken);
        Assert.Equal(denied == "grant" ? HttpStatusCode.Forbidden : HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(0, db.SnapshotReads); Assert.Equal(0, db.Commits);
    }

    [Fact]
    public async Task Two_hundred_and_exact_source_filters_reach_the_reader()
    {
        var db = new FileAuditReportTests.Database { Roots = [FileAuditReportTests.Root(), FileAuditReportTests.Root("other")] };
        await using var host = await ReportFixture.Start(FileAuditReportTests.Facts("overview"),
            new ReportDefinitionRegistry().Get("file-audit.overview"), nativeReader: new FileAuditReportReader(db));
        using var response = await host.Client.GetAsync("/api/v2/reports/file-audit.overview/data?limit=200&source_instance_id=synthetic&device_id=11111111-1111-1111-1111-111111111111",
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(200, db.Last![9]);
        Assert.Single((JsonArray)db.Last[0]!);
        var body = await ReportFixture.Body(response);
        Assert.DoesNotContain("\"other\"", body.ToJsonString());
        Assert.Equal(10000, body["window"]!["export_row_limit"]!.GetValue<int>());
        Assert.Equal("server_permissions_only", body["coverage"]!["supported_collection_mode"]!.ToString());
    }
}
