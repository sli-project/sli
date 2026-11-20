using System.Net;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Vectors from tests/semantic/test_semantic_relation_reporting.py.
public sealed class SemanticRelationReportingTests
{
    private const string Rule = "investigation.account.unlock.after-lock";
    private const string Sid = "S-1-5-21-100000001-200000002-300000003-1001";
    private const string Bounds = "domain_id=7&time_from=2026-09-01T09:00:00Z&time_to=2026-09-01T11:00:00Z&timezone=UTC";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static string Id(int n) => new Guid(n, 0, 0, new byte[8]).ToString();
    private static JsonElement Scope(string kind = "all", int id = 7) => JsonSerializer.SerializeToElement(new { kind, ids = new[] { id } });
    private static AtomicReportGrant Grant(string kind = "all", int id = 7, string[]? fields = null, string action = "view") =>
        new(Scope(kind, id), (fields ?? ["security", "technical", "raw_evidence"]).ToHashSet(), new HashSet<string> { action }, 1, 1);
    private static AccessDecision Access(string? scoped = null, params AtomicReportGrant[] grants) => new("operator",
        new(false, (scoped is null ? SemanticRelations.RequiredCapabilities : SemanticRelations.RequiredCapabilities.Where(x => x != "semantic.review")).ToHashSet(),
            new HashSet<string>(), scoped is null ? [] : [new CapabilityPolicy("semantic.review", "allow", true, false, Scope(scoped, scoped == "server" ? 30 : 7))], new Dictionary<string, JsonElement>()),
        [new(SemanticRelations.Report, true, grants.Length == 0 ? [Grant()] : grants)]);
    private static JsonObject Row(int id, int domain = 7, int order = 0) => new()
    {
        ["candidate_id"] = Id(id), ["window_start_utc"] = "2026-09-01T09:55:00Z", ["window_end_utc"] = "2026-09-01T10:00:00Z",
        ["server_id"] = 30, ["domain_id"] = domain, ["channel"] = "Security", ["event_db_id"] = 100 + order,
        ["event_id"] = 4740, ["time_created_utc"] = "2026-09-01T10:00:00Z", ["semantic_type"] = "account.lockout",
        ["source_host"] = "dc01.example.test", ["evidence_order"] = order, ["rule_id"] = Rule, ["rule_version"] = 2,
        ["relation_kind"] = "authentication.lockout_preceded_by_failures", ["confidence"] = "medium", ["explanation"] = "Observed exact source events; no causal claim."
    };
    private static JsonArray Rows(params JsonObject[] rows) => new(rows.Cast<JsonNode>().ToArray());
    private sealed class Database : ISemanticDatabase
    {
        public Func<string, object?[], JsonArray> Query = (sql, _) => sql.StartsWith("with current_supported")
            ? Rows(new JsonObject { ["rule_id"] = Rule, ["rule_version"] = 2, ["lifecycle_status"] = "shadow" }) : new();
        public readonly List<(int Session, string Sql, object?[] Values)> Calls = [];
        public int Opened, Disposed;
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct)
        { Assert.False(write); return Task.FromResult<ISemanticSession>(new Session(this, ++Opened)); }
        private sealed class Session(Database db, int id) : ISemanticSession
        {
            private bool failed;
            public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
            {
                ct.ThrowIfCancellationRequested();
                if (failed) throw new InvalidOperationException("transaction aborted");
                db.Calls.Add((id, sql, values));
                try { return Task.FromResult(db.Query(sql, values)); } catch { failed = true; throw; }
            }
            public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("read only");
            public ValueTask DisposeAsync() { db.Disposed++; return ValueTask.CompletedTask; }
        }
        public void Seed(JsonArray preflight, JsonArray? hydrated = null)
        {
            var original = Query;
            Query = (sql, values) => sql.Contains("candidate_page as(select candidate.candidate_id",StringComparison.Ordinal) ? (JsonArray)preflight.DeepClone()
                : sql.Contains("select candidate.candidate_id,candidate.rule_id",StringComparison.Ordinal) ? (JsonArray)(hydrated ?? preflight).DeepClone() : original(sql, values);
        }
    }
    private static Task<JsonObject> Read(Database db, AccessDecision? access = null, string extra = "") => new SemanticRelations(db).ReadAsync(new(Bounds + extra), access ?? Access(), Ct);
    private static void Empty(JsonObject payload)
    {
        Assert.Equal("empty", payload.Text("state")); Assert.Empty(payload["items"]!.AsArray()); Assert.False(payload.Flag("has_more"));
        Assert.Null(payload["next_cursor"]); Assert.Null(payload["coverage"]!["matched_relation_count"]); Assert.Empty(payload["coverage"]!["observed_rules"]!.AsArray());
    }

    [Fact] public async Task Every_exact_atom_must_be_allowed_before_hydration()
    {
        var db = new Database(); db.Seed(Rows(Row(1), Row(2), Row(2, 8, 1)), Rows(Row(1)));
        var result = await Read(db, Access("domain"));
        Assert.Equal(Id(1), Assert.Single(result["items"]!.AsArray()).Text("candidate_id")); Assert.DoesNotContain(Id(2), result.ToJsonString());
        Assert.Equal(new[] { Guid.Parse(Id(1)) }, (Guid[])Assert.Single(db.Calls, c => c.Sql.Contains("select candidate.candidate_id,candidate.rule_id",StringComparison.Ordinal)).Values[0]!);
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Late_denial_or_partial_hydration_erases_all_page_signals(bool partial)
    {
        var db = new Database(); db.Seed(Rows(Row(1), Row(2)), partial ? Rows(Row(1)) : Rows(Row(1), Row(2), Row(2, 8, 1)));
        var result = await Read(db, Access("domain"), "&limit=2"); Empty(result); Assert.DoesNotContain(Id(1), result.ToJsonString());
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Missing_fields_and_split_grants_deny_before_any_database_read(bool split)
    {
        var db = new Database();
        var grants = split ? new[] { Grant("domain", 7, ["security", "technical"]), Grant("domain", 7, ["raw_evidence"], "export"), Grant("domain", 8) }
            : new[] { Grant(fields: ["security", "technical"]) };
        var result = await Read(db, Access(null, grants));
        Assert.Equal("not_authorized", result.Text("state")); Assert.Empty(result["items"]!.AsArray()); Assert.False(result.Flag("has_more")); Assert.Null(result["next_cursor"]); Assert.Equal(0, db.Opened);
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Server_scoped_grants_admit_complete_evidence_and_empty_scope_is_not_denial(bool empty)
    {
        var db = new Database(); if (!empty) db.Seed(Rows(Row(1)));
        var result = await Read(db, Access("server", Grant("server", 30)));
        if (empty) Empty(result); else Assert.Equal("available", result.Text("state"));
    }
    [Fact] public async Task Complete_grant_exposes_coverage_from_inventory_and_observed_rows_separately()
    {
        var db = new Database(); var row = Row(1); row["rule_id"] = "lockout-preceded-by-failures"; row["rule_version"] = 1; db.Seed(Rows(row));
        var result = await Read(db); var coverage = result["coverage"]!;
        Assert.Equal("available", result.Text("state")); Assert.Equal("available", coverage.Text("supported_rules_state"));
        Assert.Equal(Rule, Assert.Single(coverage["supported_rules"]!.AsArray()).Text("rule_id"));
        Assert.Equal("lockout-preceded-by-failures", Assert.Single(coverage["observed_rules"]!.AsArray()).Text("rule_id"));
        Assert.Equal(new[] { "bounded_retained_page", "no_completeness_proof" }, coverage["limitation_codes"]!.AsArray().Select(x => x!.GetValue<string>()));
        Assert.True(coverage["limitations"]!.AsArray().Count >= 2);
    }
    [Theory] [InlineData("account_sid", "exact_domain_account_sid")] [InlineData("account_member_sid", "exact_domain_account_member_sid")] [InlineData("member_sid", "exact_domain_member_group_sid")]
    public async Task Public_identity_is_typed_and_resource_tuple_is_private(string name, string kind)
    {
        var row = Row(1); row["partition_key"] = "domain:7|" + name + ":" + Sid + (name == "member_sid" ? "|group_sid:S-1-5-21-100000001-200000002-300000003-512" : "");
        var db = new Database(); db.Seed(Rows(row)); var result = await Read(db); var item = Assert.Single(result["items"]!.AsArray())!;
        Assert.Equal(kind, item["identity_basis"].Text("kind")); Assert.Equal(7, item["identity_basis"].Number("domain_id")); Assert.Equal(Sid, item["identity_basis"].Text(name));
        if (name == "member_sid") Assert.Equal("S-1-5-21-100000001-200000002-300000003-512", item["identity_basis"].Text("group_sid"));
        Assert.Null(item["partition_key"]); var atom = Assert.Single(item["evidence"]!.AsArray())!; Assert.Null(atom["domain_id"]); Assert.Null(atom["server_id"]); Assert.Equal(100, atom.Number("event_db_id"));
        string sql = Assert.Single(db.Calls, c => c.Sql.Contains("select candidate.candidate_id,candidate.rule_id",StringComparison.Ordinal)).Sql; Assert.Contains("normalized.semantic_type", sql); Assert.DoesNotContain("facts_json", sql);
    }
    [Theory] [InlineData("untyped:secret-internal-value")] [InlineData("domain:7|account_sid:not-a-sid")] [InlineData("domain:7|account_sid:S-1-5-21-not-numeric")]
    public async Task Unknown_or_malformed_partitions_never_claim_exact_identity(string partition)
    {
        var row = Row(1); row["partition_key"] = partition; var db = new Database(); db.Seed(Rows(row));
        var item = Assert.Single((await Read(db))["items"]!.AsArray())!; Assert.Null(item["partition_key"]); Assert.Null(item["identity_basis"]);
    }
    [Fact] public async Task All_alternative_continuations_are_ordered_without_unique_claim()
    {
        var db = new Database(); db.Seed(Rows(Row(1)), Rows(Row(1, order: 2), Row(1), Row(1, order: 1)));
        var item = Assert.Single((await Read(db))["items"]!.AsArray())!;
        Assert.Equal("ambiguous", item.Text("continuation_state")); Assert.Equal(2, item.Number("possible_continuation_count"));
        Assert.Equal(new[] { "anchor", "alternative_continuation", "alternative_continuation" }, item["evidence"]!.AsArray().Select(x => x.Text("evidence_role")));
        Assert.Equal(new long[] { 100, 101, 102 }, item["evidence"]!.AsArray().Select(x => x.Number("event_db_id")));
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Empty_and_hidden_candidates_are_indistinguishable(bool hidden)
    {
        var db = new Database(); if (hidden) db.Seed(Rows(Row(2, 8)));
        var result = await Read(db, Access("server", Grant("domain", 7))); Empty(result);
        Assert.DoesNotContain(Id(2), result.ToJsonString()); Assert.DoesNotContain(db.Calls, c => c.Sql.Contains("select candidate.candidate_id,candidate.rule_id",StringComparison.Ordinal));
    }
    [Fact] public async Task Domain_wide_reader_queries_one_raw_page_and_cursor_resumes_after_last_visible()
    {
        var db = new Database(); db.Seed(Rows(Row(1), Row(2), Row(3)), Rows(Row(1), Row(2)));
        var first = await Read(db, extra: "&limit=2"); Assert.True(first.Flag("has_more"));
        Assert.Single(db.Calls, c => c.Sql.Contains("candidate_page as(select candidate.candidate_id",StringComparison.Ordinal));
        db.Seed(new()); await Read(db, extra: "&limit=2&cursor=" + first.Text("next_cursor"));
        var call = db.Calls.Last(c => c.Sql.Contains("candidate_page as(select candidate.candidate_id",StringComparison.Ordinal)); Assert.Contains(Guid.Parse(Id(2)), call.Values);
    }
    [Fact] public async Task Resource_reader_scans_hidden_pages_until_visible_result_without_arbitrary_page_cap()
    {
        var db = new Database(); var original = db.Query; int pages = 0;
        db.Query = (sql, values) => sql.Contains("candidate_page as(select candidate.candidate_id",StringComparison.Ordinal)
            ? ++pages <= 25 ? Rows(Row(pages * 2, 8), Row(pages * 2 + 1, 8)) : Rows(Row(101))
            : sql.Contains("select candidate.candidate_id,candidate.rule_id",StringComparison.Ordinal) ? Rows(Row(101)) : original(sql, values);
        var result = await Read(db, Access("server", Grant("domain", 7)), "&limit=1");
        Assert.Equal(26, pages); Assert.Equal(Id(101), Assert.Single(result["items"]!.AsArray()).Text("candidate_id")); Assert.False(result.Flag("has_more"));
        Assert.DoesNotContain(Id(50), result.ToJsonString());
    }
    [Fact] public async Task Resource_reader_scans_past_hidden_candidate_without_false_pagination_signal()
    {
        var db = new Database(); var original = db.Query; int pages = 0;
        db.Query = (sql, values) => sql.Contains("candidate_page as(select candidate.candidate_id",StringComparison.Ordinal) ? ++pages == 1 ? Rows(Row(1), Row(2, 8), Row(3, 8)) : Rows(Row(4))
            : sql.Contains("select candidate.candidate_id,candidate.rule_id",StringComparison.Ordinal) ? Rows(Row(1), Row(4)) : original(sql, values);
        var result = await Read(db, Access("server", Grant("domain", 7)), "&limit=2");
        Assert.Equal(new[] { Id(1), Id(4) }, result["items"]!.AsArray().Select(x => x.Text("candidate_id"))); Assert.Equal(2, pages);
        Assert.False(result.Flag("has_more")); Assert.Null(result["next_cursor"]); Assert.DoesNotContain(Id(2), result.ToJsonString());
        Assert.Contains(Guid.Parse(Id(2)), db.Calls.Last(c => c.Sql.Contains("candidate_page as(select candidate.candidate_id",StringComparison.Ordinal)).Values);
    }
    [Theory] [InlineData("42P01")] [InlineData("42501")] [InlineData("runtime")]
    public async Task Inventory_failure_preserves_rows_without_unbound_cursor_or_error_text(string failure)
    {
        var db = new Database(); db.Seed(Rows(Row(1), Row(2)), Rows(Row(1)));
        var original = db.Query; db.Query = (sql, values) => sql.StartsWith("with current_supported")
            ? throw (failure == "runtime" ? new InvalidOperationException("private inventory failure") : new PostgresException("private inventory failure", "ERROR", "ERROR", failure)) : original(sql, values);
        var result = await Read(db, extra: "&limit=1");
        Assert.Equal("available", result.Text("state")); Assert.Single(result["items"]!.AsArray()); Assert.Null(result["result_revision"]);
        Assert.False(result.Flag("has_more")); Assert.Null(result["next_cursor"]); Assert.Equal("check_unavailable", result["coverage"].Text("supported_rules_state"));
        Assert.Empty(result["coverage"]!["supported_rules"]!.AsArray()); Assert.Contains(result["coverage"]!["limitations"]!.AsArray(), x => x!.GetValue<string>().Contains("версии правил"));
        Assert.DoesNotContain("private inventory failure", result.ToJsonString()); Assert.Equal(db.Opened, db.Disposed);
        Assert.NotEqual(db.Calls.First().Session, db.Calls.First(c => c.Sql.Contains("candidate_page as(select candidate.candidate_id",StringComparison.Ordinal)).Session);
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Failed_relation_read_disposes_snapshot_and_schema_absence_has_explicit_state(bool schema)
    {
        var db = new Database(); var original = db.Query;
        db.Query = (sql, values) => sql.Contains("candidate_page as(select candidate.candidate_id",StringComparison.Ordinal) ? throw (schema ? new PostgresException("missing", "ERROR", "ERROR", "42P01") : new InvalidOperationException("read failed")) : original(sql, values);
        if (schema) { var result = await Read(db); Assert.Equal("schema_unavailable", result.Text("state")); Assert.Equal("check_unavailable", result["coverage"].Text("supported_rules_state")); }
        else await Assert.ThrowsAsync<InvalidOperationException>(() => Read(db));
        Assert.Equal(db.Opened, db.Disposed);
    }
    [Fact] public async Task Cursor_is_opaque_bound_to_filters_and_keeps_initial_rule_snapshot()
    {
        var db = new Database(); db.Seed(Rows(Row(1), Row(2)), Rows(Row(1)));
        const string filters = "&limit=1&event_db_id=100&entity_id=42&rule_version=2&relation_kind=authentication.lockout_preceded_by_failures";
        var first = await Read(db, extra: filters); string cursor = first.Text("next_cursor")!;
        Assert.StartsWith("v2.", cursor); Assert.DoesNotContain(Id(1), cursor); Assert.DoesNotContain(Rule, cursor);
        db.Seed(new()); await Read(db, extra: filters + "&cursor=" + cursor);
        Assert.Single(db.Calls, c => c.Sql.StartsWith("with current_supported"));
        var call = db.Calls.Last(c => c.Sql.Contains("candidate_page as(select candidate.candidate_id",StringComparison.Ordinal)); Assert.Contains(Rule, call.Values); Assert.Contains(2, call.Values);
        var second = await Read(db, extra: filters + "&cursor=" + cursor); Assert.Equal(first.Text("result_revision"), second.Text("result_revision"));
        foreach (string invalid in new[] { filters.Replace("event_db_id=100", "event_db_id=101") + "&cursor=" + cursor, filters + "&cursor=" + cursor[..^1] + (cursor[^1] == 'A' ? "B" : "A") })
        { var error = await Assert.ThrowsAsync<SemanticInputException>(() => Read(db, extra: invalid)); Assert.Equal("invalid_cursor", error.Message); }
    }
    [Theory] [InlineData("&unknown=x")] [InlineData("&domain_id=8")]
    public async Task Unknown_and_duplicate_relation_query_input_is_rejected_before_storage(string extra)
    {
        var db = new Database(); var error = await Assert.ThrowsAsync<SemanticInputException>(() => Read(db, extra: extra));
        Assert.Equal("invalid_semantic_relation_filter", error.Message); Assert.Equal(0, db.Opened);
    }
    [Theory] [InlineData("&unknown=x")] [InlineData("&domain_id=8")]
    public async Task Http_route_rejects_unknown_or_duplicate_input_before_storage(string extra)
    {
        var db = new Database(); using var host = await SemanticEndpointTests.Host(db); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v1/semantic/relations?" + Bounds + extra, Ct);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_semantic_relation_filter", JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct)).Text("error")); Assert.Equal(0, db.Opened);
    }
    [Fact] public async Task Http_route_uses_resource_aware_denial_and_forwards_report_filters()
    {
        var db = new Database(); using var deniedHost = await SemanticEndpointTests.Host(db, owner: false); using var deniedClient = deniedHost.GetTestClient();
        using var denied = await deniedClient.GetAsync("/api/v1/semantic/relations?" + Bounds, Ct);
        Assert.Equal(HttpStatusCode.OK, denied.StatusCode); Assert.Equal("not_authorized", JsonNode.Parse(await denied.Content.ReadAsStringAsync(Ct)).Text("state")); Assert.Equal(0, db.Opened);
        using var host = await SemanticEndpointTests.Host(db); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v1/semantic/relations?" + Bounds + "&category=group_membership&event_id=4728&outcome=unknown&actor=operator&target=member&group=admins&source=dc01&q=operator&limit=10", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); var result = JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!;
        var expected = JsonNode.Parse("""{"category":"group_membership","event_id":4728,"outcome":"unknown","actor":"operator","target_account":"member","group":"admins","source_host":"dc01","q":"operator"}""");
        Assert.True(JsonNode.DeepEquals(expected, result["filters"])); Assert.Equal(10, result["limits"].Number("row_limit"));
    }
    [Fact] public async Task Inventory_cancellation_propagates_and_disposes_its_read_session()
    {
        var db = new Database { Query = (_, _) => throw new OperationCanceledException() };
        await Assert.ThrowsAsync<OperationCanceledException>(() => Read(db)); Assert.Equal(1, db.Opened); Assert.Equal(1, db.Disposed);
    }
    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }
    [Fact] public async Task Expired_server_cursor_is_rejected_before_storage()
    {
        var db = new Database(); db.Seed(Rows(Row(1), Row(2)), Rows(Row(1)));
        var clock = new Clock(); var reader = new SemanticRelations(db, clock);
        var first = await reader.ReadAsync(new(Bounds + "&limit=1"), Access(), Ct);
        int opened = db.Opened; clock.Now = clock.Now.AddHours(1).AddSeconds(1);
        var error = await Assert.ThrowsAsync<SemanticInputException>(() => reader.ReadAsync(new(Bounds + "&limit=1&cursor=" + first.Text("next_cursor")), Access(), Ct));
        Assert.Equal("invalid_cursor", error.Message); Assert.Equal(opened, db.Opened);
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Combined_report_filters_are_parameterized_on_one_atom_with_exact_time_and_entity_contract(bool shortReads)
    {
        var db = new Database();
        const string query = "domain_id=7&time_from=2026-09-01T09:00:00.123456Z&time_to=2026-09-01T11:00:00.654321Z&timezone=UTC&category=group_membership&event_id=4728&outcome=unknown&actor=operator&target=member&group=admins&source=dc01.example.test&q=operator&entity_id=42&event_db_id=100";
        var config=new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string,string?> { ["Sli:Storage:ShortEventReads"]=shortReads.ToString() }).Build();
        var result = await new SemanticRelations(db,configuration:config).ReadAsync(new(query), Access(), Ct);
        Assert.Equal("2026-09-01T09:00:00.123456Z", result["time_bounds"].Text("from_utc")); Assert.Equal("2026-09-01T11:00:00.654321Z", result["time_bounds"].Text("to_utc_exclusive"));
        Assert.Equal("member", result["filters"].Text("target_account")); Assert.Equal("dc01.example.test", result["filters"].Text("source_host"));
        var call = Assert.Single(db.Calls, c => c.Sql.Contains("candidate_page as(select candidate.candidate_id",StringComparison.Ordinal)); string sql = call.Sql;
        Assert.Contains("candidate.candidate_status='matched'", sql); Assert.Contains("ev.domain_id<>", sql);
        string selected = sql[sql.IndexOf("where se.candidate_id=candidate.candidate_id", StringComparison.Ordinal)..];
        foreach (string predicate in new[] { "ev.event_id=any(", "ev.subject_user_sid", "facts.membership_member_sid", "srv.hostname", "ev.id=" }) Assert.Contains(predicate, selected);
        foreach (string value in new[] { "operator", "member", "admins", "dc01.example.test" }) { Assert.Contains(value, call.Values); Assert.DoesNotContain("'" + value + "'", sql); }
        Assert.DoesNotContain("newer", sql);
        var inventory = Assert.Single(db.Calls, c => c.Sql.StartsWith("with current_supported")).Sql;
        Assert.Contains("row_number() over(partition by rule_id order by rule_version desc)", inventory); Assert.Contains("version_rank=1", inventory); Assert.Contains("lifecycle_status in('shadow','enabled')", inventory);
    }
}
