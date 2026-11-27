using Microsoft.Extensions.DependencyInjection;
using Sli.Server.Access;
using Sli.Server.Reporting.V2;
using Npgsql;
using Xunit;
using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Sli.Server.Infrastructure;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;

namespace Sli.Server.Tests.Reporting;

public sealed class FileAuditReportTests
{
    [Theory] [InlineData("data")] [InlineData("export.csv")]
    public async Task Old_period_restores_archived_agent_evidence_for_data_and_export(string action)
    {
        var ct = TestContext.Current.CancellationToken;
        using var handler = new FileAuditRetentionTests.HistoryHttp(); using var http = new HttpClient(handler);
        var payload = FileAuditRetentionTests.Payload(); var observation = payload["observation"]!;
        var history = new FileAuditHistory(new LifecycleClickHouse(http,new Uri("http://192.0.2.1/")));
        await history.PreserveAsync(payload,ct);
        var root = Root(); root["collection_scope_id"] = "scope:one";
        var item = root.Copy(); item["id"] = new string('b',64); item["action_id"] = new string('b',64);
        item["evidence"] = new JsonArray(new JsonObject { ["reference"] = FileAuditHistory.ReferencePrefix+observation["evidence_key"], ["role"] = "primary" });
        var db = new Database { Roots = new JsonArray(root), Page = new JsonObject { ["service_filter_version"] = 1, ["items"] = new JsonArray(item), ["filtered_count"] = 1, ["has_more"] = false } };
        await using var h = await ReportFixture.Start(Facts("actions"),new ReportDefinitionRegistry().Get("file-audit.actions"),nativeReader:new FileAuditReportReader(db,() => history));
        using var response = await h.Client.GetAsync("/api/v2/reports/file-audit.actions/"+action+"?period=custom&from=2026-10-07T00:00:00Z&to=2026-10-08T00:00:00Z",ct);
        Assert.Equal(HttpStatusCode.OK,response.StatusCode); Assert.Equal(1,db.Commits);
        if (action == "data") {
            var evidence = (await ReportFixture.Body(response))["items"]![0]!["evidence"]![0]!;
            Assert.Equal(observation["core_evidence_ref"]!.ToString(),evidence["reference"]!.ToString());
            Assert.Equal(observation["payload_sha256"]!.ToString(),evidence["payload_sha256"]!.ToString());
            Assert.Equal(observation["normalized"]!["path"]!.ToString(),evidence["path"]!.ToString());
            Assert.Equal(observation["event_id"]!.ToString(),evidence["event_id"]!.ToString());
        } else Assert.Equal("1",response.Headers.GetValues("X-Sli-Export-Rows").Single());
    }
    [Theory] [InlineData("missing")] [InlineData("corrupt")] [InlineData("scope")] [InlineData("link")] [InlineData("unavailable")]
    public async Task Archived_evidence_never_becomes_empty_success_or_crosses_scope(string failure)
    {
        var ct = TestContext.Current.CancellationToken;
        using var handler = new FileAuditRetentionTests.HistoryHttp(); using var http = new HttpClient(handler);
        var payload = FileAuditRetentionTests.Payload(); var observation = payload["observation"]!;
        if (failure == "scope") { observation["collection_scope_id"] = "other"; observation["normalized"]!["scopes"] = new JsonArray(); }
        if (failure == "link") payload["links"]![0]!["action_id"] = new string('c',64);
        if (failure != "missing") handler.Records.Add(FileAuditHistory.Record(payload));
        if (failure == "corrupt") handler.Records[0]["payload_sha256"] = new string('0',64);
        if (failure == "unavailable") handler.Failure = "unavailable";
        var root = Root(); root["collection_scope_id"] = "scope:one";
        var item = root.Copy(); item["id"] = new string('b',64); item["evidence"] = new JsonArray(new JsonObject { ["reference"] = FileAuditHistory.ReferencePrefix+observation["evidence_key"], ["role"] = "primary" });
        var db = new Database { Roots = new JsonArray(root), Page = new JsonObject { ["service_filter_version"] = 1, ["items"] = new JsonArray(item), ["has_more"] = false } };
        await using var h = await ReportFixture.Start(Facts("actions"),new ReportDefinitionRegistry().Get("file-audit.actions"),nativeReader:new FileAuditReportReader(db,() => new FileAuditHistory(new LifecycleClickHouse(http,new Uri("http://192.0.2.1/")))));
        using var response = await h.Client.GetAsync("/api/v2/reports/file-audit.actions/data",ct);
        var body = await ReportFixture.Body(response); Assert.Equal("error",body["state"]!.ToString());
        Assert.Equal("file_audit_history_unavailable",body["coverage"]!["reason"]!.ToString()); Assert.Equal(0,db.Commits);
    }
    internal static readonly string[] Tabs = ["overview", "actions", "mass-operations", "permission-changes", "access-denials", "out-of-hours", "permissions", "audit-state"];
    private sealed class PostgresConnections(SqlPostgresFixture fixture) : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => fixture.Pg.OpenAsync(ct, "adlog_user");
    }

    internal static async Task CheckActivity(SqlPostgresFixture fixture, DateTimeOffset observed, CancellationToken ct)
    {
        var from = observed.AddMinutes(-1).UtcDateTime.ToString("O",CultureInfo.InvariantCulture);
        var to = observed.AddMinutes(1).UtcDateTime.ToString("O",CultureInfo.InvariantCulture);
        var filter = $"period=custom&from={Uri.EscapeDataString(from)}&to={Uri.EscapeDataString(to)}&source_kind=server";
        var reader = new FileAuditReportReader(new SemanticDatabase(new PostgresConnections(fixture)));
        foreach (string tab in new[] { "actions", "overview" })
        {
            string key = "file-audit." + tab;
            await using var host = await ReportFixture.Start(Facts(tab),new ReportDefinitionRegistry().Get(key),nativeReader:reader);
            using var response = await host.Client.GetAsync($"/api/v2/reports/{key}/data?{filter}",ct);
            Assert.Equal(HttpStatusCode.OK,response.StatusCode);
            var body = await ReportFixture.Body(response);
            Assert.Equal("server_file_activity",body["coverage"]!["supported_collection_mode"]!.GetValue<string>());
            if (tab == "actions")
                Assert.Equal(113,body["filtered_count"]!.GetValue<int>());
            else
            {
                var resource = Assert.Single(body["items"]!.AsArray())!;
                Assert.NotNull(resource["audit_received_at"]);
            }
        }
    }

    internal static async Task CheckNativePermissionChanges(SqlPostgresFixture fixture, NpgsqlConnection owner,
        Guid agentId, string sourceId, string rootPath, JsonObject nativeEvent, CancellationToken ct)
    {
        const string legacyId = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        await PostCollectionPostgres.Sql(owner, """
            insert into sli_plugin_file_audit.actions(action_id,contract_version,agent_id,source_instance_id,collection_scope_id,
                observed_at,subject_sid,path,operation,outcome,projection_version)
            select repeat('b',64),1,(f.method#>>'{$origin,agent_id}')::uuid,f.method#>>'{$origin,source_instance_id}',
                f.method#>>'{$origin,collection_scope_id}',f.time_created_utc-interval '1 second',f.actor,
                'C:\Files\legacy.txt','permissions','success',1
            from event_cold_facts f where f.event_kind=4670;

            insert into sli_plugin_file_audit.policy_revisions(agent_id,source_instance_id,revision,authored_at,actor_kind,actor_id,policy,policy_sha256)
            select p.agent_id,p.source_instance_id,100,now(),p.actor_kind,p.actor_id,updated.policy,
                encode(sha256(convert_to(updated.policy::text,'UTF8')),'hex')
            from sli_plugin_file_audit.policy_revisions p
            cross join lateral (select jsonb_set(p.policy,'{roots}',p.policy->'roots' ||
                jsonb_build_array(jsonb_set(p.policy#>'{roots,0}','{collection_scope_id}','"scope:other"'))) as policy) updated
            where p.revision=2;
            """,ct);
        var stamp = DateTimeOffset.Parse(nativeEvent["time_created"]!.GetValue<string>(), CultureInfo.InvariantCulture);
        string scope = nativeEvent["collection_scope_id"]!.GetValue<string>();
        var shareKey = FileAuditReportReader.ShareKey(new JsonObject
        {
            ["agent_id"] = agentId.ToString("D"),
            ["source_instance_id"] = sourceId,
            ["collection_scope_id"] = scope
        });
        var window = $"period=custom&from={stamp.AddDays(-1):yyyy-MM-dd}T00:00:00Z&to={stamp.AddDays(1):yyyy-MM-dd}T00:00:00Z";
        var filter = $"source_kind=server&share={Uri.EscapeDataString(shareKey)}&path={Uri.EscapeDataString(rootPath)}&include_nested=true&operation=permissions";
        var reader = new FileAuditReportReader(new SemanticDatabase(new PostgresConnections(fixture)));
        foreach (string tab in new[] { "permission-changes", "actions" })
        {
            var key = "file-audit." + tab;
            var definition = new ReportDefinitionRegistry().Get(key);
            var query = $"/api/v2/reports/{key}/data?{window}&{filter}&limit=1";
            const string allowed = """{"mode":"restricted","clauses":[{"collection_scope_ids":["scope:files"]}]}""";
            await using var host = await ReportFixture.Start(Facts(tab, scope: allowed), definition, nativeReader: reader);
            using var first = await host.Client.GetAsync(query, ct);
            Assert.Equal(HttpStatusCode.OK,first.StatusCode);
            var page = await ReportFixture.Body(first);
            Assert.Equal(2, page["filtered_count"]!.GetValue<int>());
            var row = Assert.Single(page["items"]!.AsArray());
            Assert.NotEqual(legacyId, row!["id"]!.ToString());
            Assert.Equal("permissions",row["operation"]!.ToString());
            Assert.Equal("success",row["outcome"]!.ToString());
            Assert.Equal(agentId.ToString("D"), row["agent_id"]!.GetValue<string>());
            Assert.Equal(sourceId, row["source_instance_id"]!.GetValue<string>());
            Assert.Equal(scope, row["collection_scope_id"]!.GetValue<string>());
            Assert.Equal(nativeEvent["path"]!.GetValue<string>(), row["path"]!.GetValue<string>());
            Assert.Equal(stamp, DateTimeOffset.Parse(row["observed_at"]!.GetValue<string>(), CultureInfo.InvariantCulture));
            var evidence = Assert.Single(row["evidence"]!.AsArray())!;
            Assert.Equal(4670, evidence["event_id"]!.GetValue<int>());
            Assert.Equal(nativeEvent["record_id"]!.ToString(), evidence["record_id"]!.ToString());
            string cursor = page["next_cursor"]!.GetValue<string>();
            using var next = await host.Client.GetAsync(query + "&cursor=" + Uri.EscapeDataString(cursor), ct);
            Assert.Equal(HttpStatusCode.OK,next.StatusCode);
            var last = await ReportFixture.Body(next);
            Assert.Equal(legacyId,Assert.Single(last["items"]!.AsArray())!["id"]!.ToString());
            Assert.False(last["has_more"]!.GetValue<bool>());
        }
        const string other = """{"mode":"restricted","clauses":[{"collection_scope_ids":["scope:other"]}]}""";
        var permissions = new ReportDefinitionRegistry().Get("file-audit.permission-changes");
        await using var denied = await ReportFixture.Start(Facts("permission-changes", scope: other), permissions,nativeReader:reader);
        using var response = await denied.Client.GetAsync($"/api/v2/reports/file-audit.permission-changes/data?{window}&{filter}", ct);
        Assert.Equal(HttpStatusCode.OK,response.StatusCode);
        var result = await ReportFixture.Body(response);
        Assert.Equal(0,result["filtered_count"]!.GetValue<int>());
        Assert.Empty(result["items"]!.AsArray());
        Assert.DoesNotContain("scope:files",result.ToJsonString());
    }

    public static IEnumerable<object[]> Routes() => Tabs.SelectMany(t => new[] { "data", "export.csv", "rows/row-1/detail" }.Select(a => new object[] { t, a }));
    internal static JsonObject Root(string source = "synthetic") => new() { ["agent_id"] = "11111111-1111-1111-1111-111111111111", ["source_instance_id"] = source, ["collection_scope_id"] = "root", ["source_name"] = "server.example.test", ["share_name"] = "share", ["path"] = @"C:\share" };
    internal static AccessFacts Facts(string tab, bool allowed = true, bool export = true, string scope = "{\"kind\":\"all\"}")
    {
        string key = "file-audit." + tab;
        JsonElement J(object value) => JsonSerializer.SerializeToElement(value);
        return new(false, "viewer", [], [], new[] { "file-audit.view", "file-audit.export", "reports.export", "field.identity_basic", "field.privilege", "field.security", "field.technical" }.Where(c => export || c != "file-audit.export").Select(c => J(new { capability_key = c, effect = "allow", scope_json = new { kind = "all" } })).ToArray(), [], [],
            allowed ? [J(new { report_key = key, effect = "allow", allowed_actions = new[] { "view", "export" }, field_categories = new[] { "identity_basic", "privilege", "security", "technical" }, scope_json = JsonDocument.Parse(scope).RootElement })] : [],
            [J(new { report_key = key, version = 1, dataset_version = 1, actions_json = new[] { "view", "export" }, fields_json = new[] { "identity_basic", "privilege", "security", "technical" }.Select(c => new { category = c }).ToArray(), definition_json = new { actions = new[] { "view", "export" } } })]);
    }
    internal sealed class Database : ISemanticDatabase, ISemanticSession
    {
        public JsonArray Roots = [Root()]; public int Opens, Pages, Decisions, Commits;
        public object?[]? Last; public Exception? Failure; public JsonObject? Page;
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct) { Assert.False(write); Opens++; return Task.FromResult<ISemanticSession>(this); }
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            if (Failure is not null) throw Failure;
            if (sql.Contains("report_roots")) return Task.FromResult(new JsonArray(new JsonObject { ["roots"] = Roots.DeepClone() }));
            if (sql.Contains("read_file_ransom_details")) { Decisions++; return Task.FromResult(new JsonArray(new JsonObject { ["decisions"] = new JsonObject() })); }
            if (sql.Contains("as r(root)") || sql.Contains("ad_context_entity_aliases")) return Task.FromResult(new JsonArray());
            Assert.Contains("report_rows($1::jsonb", sql); Pages++; Last = values;
            var row = Root(); row["id"] = "row-1"; row["subject_sid"] = "S-1-5-21-100000001-200000002-300000003-1001"; row["rule_code"] = "file-audit.mass-write";
            row["details"] = new JsonObject { ["distinct_files"] = 100, ["window_seconds"] = 300, ["operation"] = "write" }; row["evidence"] = new JsonArray(new JsonObject { ["path"] = @"C:\share\file", ["payload_sha256"] = new string('a',64) });
            return Task.FromResult(new JsonArray(new JsonObject { ["data"] = Page?.DeepClone() ?? new JsonObject { ["service_filter_version"] = 1, ["items"] = new JsonArray(row), ["filtered_count"] = 1, ["has_more"] = false, ["summary"] = new JsonObject { ["write"] = 1 } } }));
        }
        public Task CommitAsync(CancellationToken ct) { Commits++; return Task.CompletedTask; }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    [Theory] [MemberData(nameof(Routes))]
    public async Task Every_file_report_route_obeys_reference_contract(string tab, string action)
    {
        var db = new Database(); var definition = new ReportDefinitionRegistry().Get("file-audit." + tab)!;
        await using var host = await ReportFixture.Start(Facts(tab), definition, nativeReader: new FileAuditReportReader(db));
        using var response = await host.Client.GetAsync($"/api/v2/reports/file-audit.{tab}/{action}", TestContext.Current.CancellationToken);
        if (action.StartsWith("rows/")) { Assert.Equal(HttpStatusCode.NotFound, response.StatusCode); Assert.Equal(tab == "permissions" ? "file_audit_snapshot_not_found" : "report_detail_not_available", (await ReportFixture.Body(response))["error"]!.GetValue<string>()); Assert.Equal(0, db.Opens); return; }
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Equal(1, db.Pages); Assert.Equal(1, db.Commits);
        if (action == "data")
        {
            var body = await ReportFixture.Body(response); Assert.Equal("partial", body["state"]!.GetValue<string>()); Assert.Single(body["items"]!.AsArray());
            Assert.Equal(1, body["filtered_count"]!.GetValue<int>()); Assert.Equal("server.example.test · share", body["items"]![0]!["share_label"]!.GetValue<string>());
            if (tab == "mass-operations") { Assert.Equal("denied", body["items"]![0]!["ransom"]!["state"]!.GetValue<string>()); Assert.Equal(0, db.Decisions); }
        }
        else { Assert.Contains("text/csv", response.Content.Headers.ContentType!.ToString()); Assert.Equal("1", response.Headers.GetValues("X-Sli-Export-Rows").Single()); }
    }
    [Theory] [MemberData(nameof(Routes))]
    public async Task Every_route_denies_without_report_assignment(string tab, string action)
    {
        var db = new Database(); await using var h = await ReportFixture.Start(Facts(tab, false), new ReportDefinitionRegistry().Get("file-audit." + tab), nativeReader: new FileAuditReportReader(db));
        using var r = await h.Client.GetAsync($"/api/v2/reports/file-audit.{tab}/{action}", TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode); Assert.Equal(0, db.Opens);
    }
    [Theory] [MemberData(nameof(Routes))]
    public async Task Every_route_rejects_bad_input_or_unavailable_inline_detail(string tab, string action)
    {
        var db = new Database(); await using var h = await ReportFixture.Start(Facts(tab), new ReportDefinitionRegistry().Get("file-audit." + tab), nativeReader: new FileAuditReportReader(db));
        using var r = await h.Client.GetAsync($"/api/v2/reports/file-audit.{tab}/{action}?limit=201", TestContext.Current.CancellationToken);
        Assert.Equal(action.StartsWith("rows/") && tab != "permissions" ? HttpStatusCode.NotFound : HttpStatusCode.BadRequest, r.StatusCode); Assert.Equal(0, db.Opens);
    }
    [Fact] public async Task Resource_denies_and_source_filters_run_before_database_paging()
    {
        var facts = Facts("actions", scope: "{\"mode\":\"restricted\",\"clauses\":[{\"source_instance_ids\":[\"synthetic\"]}]}");
        var db = new Database { Roots = [Root(), Root("other")] };
        await using var h = await ReportFixture.Start(facts, new ReportDefinitionRegistry().Get("file-audit.actions"), nativeReader: new FileAuditReportReader(db));
        using var r = await h.Client.GetAsync("/api/v2/reports/file-audit.actions/data?show_service=true&include_nested=false&path=%27%3BDROP&operation=write", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode); Assert.Single((JsonArray)db.Last![0]!); Assert.Equal("';DROP", db.Last[4]); Assert.Equal(false, db.Last[5]); Assert.Equal("write", db.Last[7]); Assert.True(((JsonObject)db.Last[8]!)["show_service"]!.GetValue<bool>());
    }
    [Fact] public async Task Export_requires_independent_file_capability()
    {
        var db = new Database(); await using var h = await ReportFixture.Start(Facts("actions", export: false), new ReportDefinitionRegistry().Get("file-audit.actions"), nativeReader: new FileAuditReportReader(db));
        using var r = await h.Client.GetAsync("/api/v2/reports/file-audit.actions/export.csv", TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode); Assert.Equal(0, db.Opens);
    }
    [Fact] public async Task Missing_migration_and_timeout_remain_source_errors()
    {
        var db = new Database { Failure = new Npgsql.PostgresException("private", "ERROR", "ERROR", "57014") };
        await using var h = await ReportFixture.Start(Facts("actions"), new ReportDefinitionRegistry().Get("file-audit.actions"), nativeReader: new FileAuditReportReader(db));
        using var r = await h.Client.GetAsync("/api/v2/reports/file-audit.actions/data", TestContext.Current.CancellationToken); var body = await ReportFixture.Body(r); Assert.Equal("error", body["state"]!.GetValue<string>()); Assert.Equal("source_timeout", body["coverage"]!["reason"]!.GetValue<string>()); Assert.DoesNotContain("private", body.ToJsonString());
        db.Failure = null; db.Page = new JsonObject { ["items"] = new JsonArray(), ["has_more"] = false };
        using var second = await h.Client.GetAsync("/api/v2/reports/file-audit.actions/data", TestContext.Current.CancellationToken); Assert.Equal("source_unreadable", (await ReportFixture.Body(second))["coverage"]!["reason"]!.GetValue<string>());
    }
    [Fact] public async Task Invalid_capability_scope_deny_remains_fail_closed_like_python()
    {
        var facts = Facts("actions"); var deny = JsonSerializer.SerializeToElement(new { capability_key = "file-audit.view", effect = "deny", scope_json = new { mode = "restricted", clauses = new[] { new { source_instance_ids = new[] { "synthetic" } } } } }); facts = facts with { DirectCapabilities = facts.DirectCapabilities.Append(deny).ToArray() };
        var db = new Database { Roots = [Root(),Root("other")] }; await using var h = await ReportFixture.Start(facts,new ReportDefinitionRegistry().Get("file-audit.actions"),nativeReader:new FileAuditReportReader(db));
        using var r = await h.Client.GetAsync("/api/v2/reports/file-audit.actions/data",TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.Forbidden,r.StatusCode); Assert.Equal(0,db.Opens);
    }
    [Fact] public async Task No_roots_is_not_collected_and_cannot_export()
    {
        var db = new Database { Roots = [] }; await using var h = await ReportFixture.Start(Facts("actions"),new ReportDefinitionRegistry().Get("file-audit.actions"),nativeReader:new FileAuditReportReader(db));
        using var r = await h.Client.GetAsync("/api/v2/reports/file-audit.actions/data",TestContext.Current.CancellationToken); var body = await ReportFixture.Body(r);
        Assert.Equal("not_collected",body["state"]!.GetValue<string>()); Assert.Null(body["filtered_count"]); Assert.Equal(0,db.Pages);
        using var export = await h.Client.GetAsync("/api/v2/reports/file-audit.actions/export.csv",TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.BadRequest,export.StatusCode); Assert.Equal("report_export_unavailable",(await ReportFixture.Body(export))["error"]!.GetValue<string>());
    }
    [Fact] public async Task Native_cursor_is_bound_by_engine_and_passed_without_display_flags()
    {
        var db = new Database { Page = JsonNode.Parse("""{"service_filter_version":1,"items":[],"filtered_count":2,"has_more":true,"after":{"at":"2026-01-01T00:00:00Z","id":"row-1"}}""")!.AsObject() };
        await using var h = await ReportFixture.Start(Facts("actions"),new ReportDefinitionRegistry().Get("file-audit.actions"),nativeReader:new FileAuditReportReader(db));
        string path = "/api/v2/reports/file-audit.actions/data?period=custom&from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z";
        using var r = await h.Client.GetAsync(path,TestContext.Current.CancellationToken); string cursor = (await ReportFixture.Body(r))["next_cursor"]!.GetValue<string>(); Assert.DoesNotContain("row-1",cursor);
        using var next = await h.Client.GetAsync(path + "&cursor=" + Uri.EscapeDataString(cursor),TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.OK,next.StatusCode); Assert.Equal("row-1",((JsonObject)db.Last![8]!)["id"]!.GetValue<string>());
        using var altered = await h.Client.GetAsync(path + "&operation=write&cursor=" + Uri.EscapeDataString(cursor),TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.BadRequest,altered.StatusCode); Assert.Equal(2,db.Pages);
    }
    [Fact] public void Permission_group_inventory_preserves_unknown_masks_and_employee_filter()
    {
        var root = Root(); root["share_label"] = "synthetic"; root["share_dacl"] = "D:(A;;FR;;;WD)"; root["root_dacl"] = "D:(A;;FW;;;WD)"; root["share_complete"] = false;
        var groups = FileAuditReportReader.Groups(new JsonArray(root),"S-1-1-0"); Assert.Single(groups); Assert.Null(groups[0]!["smb_mask"]); Assert.Equal(0x120116u,groups[0]!["ntfs_mask"]!.GetValue<uint>());
    }
    [Fact]
    public void Engine_registers_native_file_audit_reader()
    {
        var services = new ServiceCollection(); services.AddLogging(); services.AddReportV2Engine();
        Assert.Contains(services, s => s.ServiceType == typeof(IReportV2Reader) && s.ImplementationType?.Name == "FileAuditReportReader");
    }
}
