using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Domains;
using Sli.Server.Infrastructure;
using Sli.Server.Problems;
using Sli.Server.Reporting.V2;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Problems;
using Xunit;

namespace Sli.Server.Tests.Reporting;

// Behavioral vectors from tests/reporting/test_security_problems_v2.py.
public sealed partial class SecurityProblemsV2Tests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static JsonObject O(string json) => JsonNode.Parse(json)!.AsObject();
    static ReportDefinition Definition => new ReportDefinitionRegistry().Get("security.problems")!;
    static ProblemAccess Access => ProblemLifecycleTests.Access("security.queue");
    static ReportQueryContext Context(JsonObject? parameters = null, int limit = 50) => new(Definition, Access.Decision,
        new("session", 7, "admin"), parameters ?? new(), new(null, limit, "UTC", null, "desc", null), ReportScope.All,
        null, "view", _ => true, Access.Decision.Reports[0].Grants);
    static long[] Ids(JsonObject page) => page["items"]!.AsArray().Select(r => r!["id"]!.GetValue<long>()).ToArray();

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void QueueDefaultColumnsHaveLocalizedLabelsAndKeepOptionalFields(bool english)
    {
        var declaration = ReportPresentation.Apply(Definition.Declaration, english);
        var columns = declaration["columns"]!.AsArray().OfType<JsonObject>().ToArray();
        var visible = columns.Where(c => (bool?)c["hidden_by_default"] != true).ToArray();
        Assert.Equal(new[] { "severity", "title", "entities", "actor", "last_seen_utc", "occurrence_count", "status" },
            visible.Select(c => c["key"]!.ToString()));
        Assert.Equal(english ? new[] { "Severity", "Problem", "Object", "Who", "Last event", "Times", "State" }
            : new[] { "Важность", "Проблема", "Объект", "Кто", "Последнее событие", "Раз", "Состояние" },
            visible.Select(c => c["label"]!.ToString()));
        Assert.Equal(english ? "Snooze" : "Отложить", columns.Single(c => c["key"]!.ToString() == "risk_acceptance")["label"]!.ToString());
        foreach (string key in new[] { "risk_acceptance", "what", "why", "next", "id" })
            Assert.True((bool?)columns.Single(c => c["key"]!.ToString() == key)["hidden_by_default"]);
        var actor = ProblemPresentation.Finding(O("""{"id":7,"actor":""}"""), Access, english ? "en" : "ru");
        Assert.Null(actor["actor_text"]);
    }
    static void Same(JsonNode? expected, JsonNode? actual) => Assert.True(JsonNode.DeepEquals(expected, actual), $"Expected {expected}; actual {actual}");
    static void Message(JsonObject row, string field, string code, string locale)
    {
        var expected = ProblemPresentation.Message(code, locale);
        Assert.NotEqual(code, expected["text"]!.ToString());
        Assert.Equal(code, row["presentation_messages"]![field]!["code"]!.ToString()); Same(expected["text"], row[field]);
    }

    [Theory]
    [InlineData("ru", "account-watch", "watch", "account_watch_activity")]
    [InlineData("en", "account-watch", "watch", "account_watch_activity")]
    [InlineData("ru", "account-decoy", "decoy", "account_decoy_used")]
    [InlineData("en", "account-decoy", "decoy", "account_decoy_used")]
    [InlineData("ru", "file-decoy", "file_decoy", "file_decoy_touched")]
    [InlineData("en", "file-decoy", "file_decoy", "file_decoy_touched")]
    public void RegisteredWordingNeverUsesPrivateReasonOrPath(string locale, string rule, string prefix, string code)
    {
        var source = new JsonObject { ["id"] = 42, ["rule_code"] = "semantic.qw." + rule, ["severity"] = "high",
            ["title"] = "Source title", ["summary"] = "synthetic-private-value" };
        string original = source.ToJsonString();
        var row = ProblemPresentation.Finding(source, Access, locale);
        Assert.Equal(code, row["presentation_code"]!.ToString());
        foreach (var (field, suffix) in new[] { ("title_text", "title"), ("what_happened", "what"), ("why_text", "why"), ("next_text", "next") })
            Message(row, field, "security.problems.presentation." + prefix + "_" + suffix, locale);
        Assert.DoesNotContain("synthetic-private-value", row["presentation_messages"]!.ToJsonString());
        Assert.Equal(original, source.ToJsonString());
    }

    [Fact]
    public void AuditActorAndUnknownRuleUseRuleCatalogAndNoInventedActor()
    {
        var audit = ProblemPresentation.Finding(O("""{"id":3,"rule_code":"semantic.security.audit_controls_changed","title":"Saved English title","actor":"sid:DC1:S-1-5-18"}"""), Access, "ru");
        Assert.Equal("Изменена политика аудита Windows", audit["title_text"]!.ToString());
        Assert.Equal("Системная учётная запись DC1", audit["actor_text"]!.ToString());
        var raw = O("""{"id":4,"rule_code":"future.rule","title":"Stored title","summary":"Stored observation","actor":"source-actor"}""");
        var row = ProblemPresentation.Finding(raw, Access, "en");
        Assert.Equal("future.rule", row["title_text"]!.ToString());
        Assert.Equal("source-actor", row["actor_text"]!.ToString());
        Assert.DoesNotContain("Stored", row.ToJsonString());
        var fallback = ProblemPresentation.Finding(O("""{"id":4,"rule_code":"future.rule","actor":""}"""), Access, "en");
        Assert.Equal("future.rule", fallback["title_text"]!.ToString()); Assert.Null(fallback["actor_text"]);
        Assert.Null(fallback["wording_limitation"]);
    }

    [Theory]
    [InlineData("machine_account")][InlineData("system_account")][InlineData("known_gpo_refresh")][InlineData("interactive_admin")][InlineData("unknown")]
    public void ReviewUsesThePublishedBucketAndSuppressesNonAuditChanges(string bucket)
    {
        var raw = new JsonObject { ["id"] = 1, ["review_hint"] = new JsonObject { ["bucket"] = bucket } };
        var row = ProblemPresentation.Finding(raw, Access, "ru");
        Message(row, "review_hint_text", "reports.v2.security.problems.presentation." + bucket, "ru");
        Assert.Equal(bucket, row["review_hint"]!["bucket"]!.ToString());
        raw["review_hint"]!["has_audit_change"] = false;
        row = ProblemPresentation.Finding(raw, Access, "ru"); Assert.Null(row["review_hint_text"]);
        Assert.False(row["presentation_messages"]!.AsObject().ContainsKey("review_hint_text"));
    }

    [Theory][InlineData("account")][InlineData("file")]
    public void ProjectionExposesOnlyTheEventTimeDecoyReference(string rule)
    {
        var raw = O("""{"id":42,"status":"new","severity":"high","decoy_id":"00000000-0000-4000-8000-000000000003","decoy_revision":1,"private_label_payload":"synthetic-private-value"}""");
        raw["rule_code"] = $"semantic.qw.{rule}-decoy";
        var row = ProblemPresentation.Finding(raw, Access, "ru");
        Same(raw["decoy_id"], row["decoy_id"]); Same(raw["decoy_revision"], row["decoy_revision"]); Assert.False(row.ContainsKey("private_label_payload"));
        foreach (string field in new[] { "decoy_id", "decoy_revision" }) Assert.Equal("technical", Assert.Single(Definition.Declaration["row_categories"]![field]!.AsArray())!.ToString());
        row = ProblemPresentation.Finding(raw, ProblemLifecycleTests.Access("security.queue", fields: ["security"]), "ru");
        Assert.False(row.ContainsKey("decoy_id")); Assert.False(row.ContainsKey("decoy_revision"));
    }

    [Theory][InlineData("ru")][InlineData("en")]
    public async Task NativeQueueLocalizesVisibleFactsAndLeavesDetailFieldsForTheDrawer(string locale)
    {
        var raw = O("""{"id":9,"rule_code":"semantic.security.audit_controls_changed","title":"Audit policy was changed","status":"repeated","severity":"critical","actor":"sid:fixture-host:S-1-5-18","review_hint":{"bucket":"machine_account"},"entities":[{"display_name":"42","entity_role":"source_host"},{"display_name":"source-observation"}],"linked_case":{"id":7,"status":"review"}}""");
        var repo = new Repository { Result = new() { ["state"] = "available", ["items"] = new JsonArray(raw.DeepClone()), ["semantic_runtime"] = new JsonObject { ["findings_state"] = "inactive" } } };
        await using var host = await ReportFixture.Start(ProblemEndpointTests.Facts(), Definition, nativeReader: new SecurityProblemsReader(repo, new Evidence()));
        host.Client.DefaultRequestHeaders.AcceptLanguage.ParseAdd(locale);
        using var response = await host.Client.GetAsync("/api/v2/reports/security.problems/data", Ct); Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await ReportFixture.Body(response); var row = body["items"]![0]!.AsObject();
        foreach (string field in new[] { "id", "status", "severity" }) Same(raw[field], row[field]);
        Assert.Equal(locale == "ru" ? "Изменена политика аудита Windows" : "Windows audit policy changed", row["title_text"]!.ToString());
        Assert.Equal(locale == "ru" ? "Системная учётная запись FIXTURE-HOST" : "System account FIXTURE-HOST", row["actor_text"]!.ToString());
        Assert.Equal("source-observation", row["entity_text"]!.ToString());
        foreach (string field in new[] { "evidence", "entities", "linked_case", "identity_context", "presentation_messages", "what_happened" })
            Assert.False(row.ContainsKey(field));
        Message(body["limitations"]![0]!.AsObject(), "text", "reports.v2.security.problems.limitations.zero_is_not_safe", locale);
        Message(body["metrics"]![0]!.AsObject(), "label", "reports.v2.security.problems.metrics.open.label", locale);
        Same(raw, repo.Result["items"]![0]);
    }

    [Theory][InlineData("ru")][InlineData("en")]
    public async Task DeclarationLocalizesOnlyRegisteredMetadataAndPreservesFilterValues(string locale)
    {
        var definition = Definition; string original = definition.Declaration.ToJsonString();
        await using var host = await ReportFixture.Start(ProblemEndpointTests.Facts(), definition, nativeReader: new SecurityProblemsReader(new Repository(), new Evidence()));
        host.Client.DefaultRequestHeaders.AcceptLanguage.ParseAdd(locale);
        using var response = await host.Client.GetAsync("/api/v2/reports/security.problems", Ct); Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await ReportFixture.Body(response); const string prefix = "reports.v2.security.problems.";
        Message(body, "title", prefix + "title", locale);
        foreach (var column in body["columns"]!.AsArray().OfType<JsonObject>()) {
            Message(column, "label", prefix + "columns." + column["key"] + ".label", locale);
            foreach (var (value, message) in column["labels_messages"] as JsonObject ?? []) Same(message!["text"], column["labels"]![value]);
        }
        var parameters = body["params"]!.AsArray().OfType<JsonObject>().ToDictionary(p => p["key"]!.ToString());
        foreach (var param in parameters.Values) {
            string key = param["key"]!.ToString();
            if (key == "queue_tab") {
                Assert.True(param["hidden"]!.GetValue<bool>());
                continue;
            }
            Message(param, "label", prefix + "params." + key + ".label", locale);
            var before = definition.Params.Single(p => p["key"]!.ToString() == key);
            Assert.Equal((before["options"] as JsonArray ?? []).Select(o => o!["value"]!.ToString()), (param["options"] as JsonArray ?? []).Select(o => o!["value"]!.ToString()));
            foreach (var option in (param["options"] as JsonArray ?? []).OfType<JsonObject>()) Message(option, "label", prefix + "params." + key + ".options." + option["value"], locale);
        }
        foreach (string key in new[] { "id", "domain", "time_from", "time_to", "entity_id", "rule_code", "created_from", "created_to" }) Assert.True(parameters[key]["hidden"]!.GetValue<bool>());
        Assert.Equal("int", parameters["id"]["kind"]!.ToString()); Assert.Equal("int", parameters["entity_id"]["kind"]!.ToString());
        Assert.Equal("open", parameters["population"]["default"]!.ToString());
        Assert.Equal(new[] { "open", "attention", "all" }, parameters["population"]["options"]!.AsArray().Select(o => o!["value"]!.ToString()));
        Assert.Equal(new[] { "accepted", "all" }, parameters["risk"]["options"]!.AsArray().Select(o => o!["value"]!.ToString()));
        Assert.Equal(new[] { "new", "repeated", "confirmed", "active", "review", "false_positive", "closed" }, parameters["status"]["options"]!.AsArray().Select(o => o!["value"]!.ToString()));
        Assert.Equal(new[] { "critical", "high", "medium", "low" }, parameters["severity"]["options"]!.AsArray().Select(o => o!["value"]!.ToString()));
        foreach (var preset in body["presets"]!.AsArray().OfType<JsonObject>()) Message(preset, "label", prefix + "presets." + preset["params"]!.ToJsonString(), locale);
        Same(new JsonArray(definition.Declaration["presets"]!.AsArray().Select(p => p!["params"]!.DeepClone()).ToArray()), new JsonArray(body["presets"]!.AsArray().Select(p => p!["params"]!.DeepClone()).ToArray()));
        Assert.Equal("security.queue", definition.AccessKey); Assert.Equal("problems.lifecycle", body["detail"]!["actions"]!.ToString()); Assert.Equal("sub", body["detail"]!["kind"]!.ToString());
        Assert.Equal("problems.risk-badge", definition.Columns.Single(c => c["key"]!.ToString() == "risk_acceptance")["component"]!.ToString());
        Message(body["detail"]!["row_links"]![0]!.AsObject(), "label", prefix + "detail.row_links./app/events/{event_db_id}", locale);
        foreach (string field in new[] { "question", "denominator", "freshness_expectation" }) Message(body["intent"]!.AsObject(), field, prefix + "intent." + field, locale);
        foreach (var (key, value) in definition.Declaration["intent"]!.AsObject().Where(p => p.Key is not ("question" or "denominator" or "freshness_expectation"))) Same(value, body["intent"]![key]);
        Assert.Equal(original, definition.Declaration.ToJsonString());
    }

    [Fact]
    public async Task WorkplaceDeclarationAndClosedDataUseTheSameReportAccess()
    {
        var repository = new Repository { Result = O("""
            {"state":"available","items":[{"id":7,"status":"closed","rule_code":"semantic.qw.audit-disabled","severity":"high",
              "last_seen_utc":"2026-11-22T01:00:00Z","closed_at":"2026-11-22T02:00:00Z",
              "presentation_facts":{"actor":"example.test\\operator","computer":"dc01.example.test"}}],
             "summary":[{"status":"new","count":4},{"status":"closed","count":1}]}
            """) };
        await using var host = await ReportFixture.Start(ProblemEndpointTests.Facts(), Definition, nativeReader: new SecurityProblemsReader(repository, new Evidence()));
        using var declaration = await host.Client.GetAsync("/api/v2/reports/security.problems", Ct);
        Assert.Equal(HttpStatusCode.OK, declaration.StatusCode);
        Assert.Contains((await ReportFixture.Body(declaration))["views"]!.AsArray(),
            view => view?["component"]?.ToString() == "problems.workplace");
        using var response = await host.Client.GetAsync("/api/v2/reports/security.problems/data?queue_tab=closed&severity=high", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var page = await ReportFixture.Body(response);
        Assert.Equal(4, page["queue_counts"]!["open"]!.GetValue<long>());
        Assert.Equal(1, page["queue_counts"]!["closed"]!.GetValue<long>());
        Assert.Equal("dc01.example.test", page["items"]![0]!["object"]!.ToString());
        Assert.Equal("closed", Assert.Single(repository.Calls).WorkplaceTab);
    }

    [Fact]
    public async Task FiltersAuthorizationMetricsAndFreshnessReachTheNativeReader()
    {
        var repo = new Repository { Result = O("""{"state":"available","items":[{"id":7,"status":"new","title":"X","evidence":[{"event_db_id":1}],"entities":[{"display_name":"42","entity_role":"source_host"}],"last_seen_utc":"2026-09-01T00:00:00Z","published_at_utc":"2026-10-07T00:00:00Z","updated_at":"2026-10-07T11:00:00Z"}],"summary":[{"status":"new","count":2},{"status":"active","count":1},{"status":"closed","count":5},{"status":"new","count":3,"risk_accepted":true},{"status":"repeated","count":1,"risk_accepted":false}],"semantic_runtime":{"findings_state":"inactive","heartbeat_at":"2026-10-07T12:00:00Z"}}""") };
        repo.Result["lifecycle"] = O("""{"allowed_transitions":{"new":["active","false_positive"]}}""");
        var c = Context(O("""{"status":"new","q":"audit","entity_id":"7","id":123,"risk":"accepted","rule_code":"semantic.synthetic","created_from":"2026-10-01T00:00:00Z","created_to":"2026-10-07T00:00:00Z","show_suppressed":"true","population":"attention"}""")) with { DomainIds = [7] };
        var body = await new SecurityProblemsReader(repo, new Evidence()).QueryAsync(c, Ct); var q = Assert.Single(repo.Calls);
        Assert.Equal("new", q.Status); Assert.Equal("audit", q.Search); Assert.Equal(7, q.EntityId); Assert.Equal(123, q.FindingId);
        Assert.Equal("accepted", q.Risk); Assert.Equal("semantic.synthetic", q.RuleCode); Assert.Equal("attention", q.Population); Assert.True(q.Suppressed);
        Assert.Equal(c.Params["created_from"]!.ToString(), q.CreatedFrom); Assert.Equal(c.Params["created_to"]!.ToString(), q.CreatedTo); Assert.Equal([7L], q.Domains!);
        Assert.Same(c.Access, repo.Authorization!.Decision);
        var metrics = body["metrics"]!.AsArray().ToDictionary(m => m!["key"]!.ToString(), m => m!["value"]!.GetValue<long>());
        Assert.Equal(4, metrics["open"]); Assert.Equal(3, metrics["attention"]); Assert.Equal(1, metrics["progress"]); Assert.Equal(5, metrics["closed"]);
        Same(O("""{"population":"attention"}"""), body["metrics"]![1]!["filter"]);
        var row = body["items"]![0]!; Assert.Equal(new[] { "new", "active", "false_positive" }, row["allowed_statuses"]!.AsArray().Select(s => s!.ToString()));
        Assert.Equal(1, row["evidence_total"]!.GetValue<int>()); Assert.Null(row["entity_text"]);
        Assert.Equal("2026-09-01T00:00:00Z", body["coverage"]!["event_at_utc"]!.ToString()); Assert.Equal("2026-10-07T00:00:00Z", body["coverage"]!["published_at_utc"]!.ToString());
        Assert.Equal("2026-10-07T12:00:00Z", body["coverage"]!["worker_checked_at_utc"]!.ToString());
        Assert.Null(body["coverage"]!["snapshot_at_utc"]); Assert.Null(body["coverage"]!["observed_at_utc"]);
        Assert.Contains(body["limitations"]!.AsArray(), l => l!["code"]!.ToString() == "zero_is_not_safe");
    }

    [Theory]
    [InlineData("{\"time_from\":\"not-an-instant\"}")]
    [InlineData("{\"time_from\":\"2026-10-01T00:00:00Z\"}")]
    [InlineData("{\"time_from\":\"2026-10-02T00:00:00Z\",\"time_to\":\"2026-10-01T00:00:00Z\"}")]
    public async Task InvalidWindowNeverReadsStorage(string parameters)
    {
        var repo = new Repository(); await Assert.ThrowsAsync<ReportRequestException>(() => new SecurityProblemsReader(repo, new Evidence()).QueryAsync(Context(O(parameters)), Ct)); Assert.Empty(repo.Calls);
    }

    [Fact]
    public async Task AttentionPopulationAndExactIdCountNewConfirmedAndRepeated()
    {
        var repo = new Repository { Result = O("""{"state":"available","items":[],"summary":[{"status":"new","count":2},{"status":"confirmed","count":3},{"status":"repeated","count":4},{"status":"active","count":5}],"semantic_runtime":{"findings_state":"active"}}""") };
        var body = await new SecurityProblemsReader(repo, new Evidence()).QueryAsync(Context(O("""{"population":"attention","id":123}""")), Ct);
        var query = Assert.Single(repo.Calls); Assert.Equal("attention", query.Population); Assert.Equal(123, query.FindingId);
        Assert.Equal(9, body["metrics"]![1]!["value"]!.GetValue<long>());
    }

    [Fact]
    public async Task CohortQueueCursorKeepsOriginalIdsExactTotalAndContext()
    {
        const string cohort = "[\"membership\",\"synthetic\",7,11,\"S-1-5-21-100000001-200000002-300000003-1101\",\"S-1-5-21-100000001-200000002-300000003-512\",\"2026-10-01\"]";
        var repo = new Repository { Result = O("""{"state":"available","items":[{"id":9},{"id":8}],"has_more":true,"summary":[{"count":188,"status":"new"}]}""") };
        var c = Context(new() { ["cohort"] = cohort, ["population"] = "attention", ["rule_code"] = "synthetic" }); var reader = new SecurityProblemsReader(repo, new Evidence());
        var page = await reader.QueryAsync(c, Ct); Assert.Equal([9L, 8L], Ids(page)); Assert.Equal(188, page["filtered_count"]!.GetValue<long>());
        var next = c with { Paging = c.Paging with { Cursor = page["next_cursor"]!.ToString() } };
        await reader.QueryAsync(next, Ct); Assert.Equal(8, repo.Calls[^1].BeforeId); Assert.Equal("UTC", repo.Calls[^1].Timezone); Assert.Equal(cohort, repo.Calls[^1].Cohort); Assert.False(repo.Calls[^1].GroupQueue);
        foreach (var changed in new[] { next with { Paging = next.Paging with { Timezone = "Europe/Berlin" } }, next with { DomainIds = [8] }, next with { Params = O("""{"population":"all"}""") } })
            Assert.Equal("invalid_cursor", (await Assert.ThrowsAsync<ReportRequestException>(() => reader.QueryAsync(changed, Ct))).Message);
        Assert.Equal(2, repo.Calls.Count);
    }

    [Fact]
    public async Task DetailRechecksPopulationCompactlyAndRejectsUnpublishedFindingBeforeEvidence()
    {
        var c = Context(O("""{"cohort":"[\"finding\",7]","population":"attention","status":"new","severity":"high","q":"audit","entity_id":9,"risk":"all","rule_code":"semantic.synthetic","created_from":"2026-10-01T00:00:00Z","created_to":"2026-10-07T00:00:00Z","time_from":"2026-10-01T00:00:00Z","time_to":"2026-10-02T00:00:00Z","show_suppressed":"true"}""")) with { DomainIds = [7] };
        var repo = new Repository { Result = O("""{"items":[]}""") }; var evidence = new Evidence(); var reader = new SecurityProblemsReader(repo, evidence);
        var error = await Assert.ThrowsAsync<ReportRequestException>(() => reader.DetailAsync(c, "7", Ct)); Assert.Equal("report_row_not_found", error.Message); Assert.Equal(404, error.Status); Assert.Equal(0, evidence.Calls);
        var q = Assert.Single(repo.Calls); Assert.True(q.Compact); Assert.Equal(1, q.Limit); Assert.Equal(7, q.FindingId); Assert.Equal("[\"finding\",7]", q.Cohort); Assert.Equal("UTC", q.Timezone);
        Assert.Equal("attention", q.Population); Assert.Equal([7L], q.Domains!); Assert.Equal("new", q.Status); Assert.Equal("high", q.Severity); Assert.Equal("audit", q.Search); Assert.Equal(9, q.EntityId);
        Assert.Equal("all", q.Risk); Assert.Equal("semantic.synthetic", q.RuleCode); Assert.True(q.Suppressed);
        Assert.Equal(c.Params["time_from"]!.ToString(), q.From); Assert.Equal(c.Params["time_to"]!.ToString(), q.To);
        Assert.Equal(c.Params["created_from"]!.ToString(), q.CreatedFrom); Assert.Equal(c.Params["created_to"]!.ToString(), q.CreatedTo);
        Assert.Same(c.Access, repo.Authorization!.Decision);
    }

    [Theory][InlineData("8", "new")][InlineData("7", "active")]
    public async Task EvidenceCursorCannotMoveToAnotherFindingOrFilter(string id, string status)
    {
        var repo = new Repository { Result = O("""{"items":[{"id":7},{"id":8}]}""") }; var evidence = new Evidence { Result = O("""{"items":[{"evidence_id":1,"event_db_id":1}],"has_more":true,"total":2,"watermark":"2026-10-01T00:00:00Z","next_position":{"storage_kind":"core_event","native_key":"00000000000000000001"}}""") };
        var reader = new SecurityProblemsReader(repo, evidence); var c = Context(O("""{"status":"new"}"""));
        var first = await reader.DetailAsync(c, "7", Ct);
        var changed = c with { Params = new() { ["status"] = status }, Paging = c.Paging with { Cursor = first["next_cursor"]!.ToString() } };
        Assert.Equal("invalid_cursor", (await Assert.ThrowsAsync<ReportRequestException>(() => reader.DetailAsync(changed, id, Ct))).Message); Assert.Equal(1, evidence.Calls);
    }

    [Fact]
    public async Task MissingSourceKeepsLinkAndUnknownCountAndEmitsAnotherPage()
    {
        var repo = new Repository(); var evidence = new Evidence { Result = O("""{"items":[{"evidence_id":1,"event_db_id":null}],"has_more":true,"total":null,"total_lower_bound":10001}""") };
        var body = await new SecurityProblemsReader(repo, evidence).DetailAsync(Context(), "7", Ct);
        Assert.Equal("partial", body["state"]!.ToString()); Assert.Null(body["filtered_count"]); Assert.Equal(10001, body["coverage"]!["evidence_total_lower_bound"]!.GetValue<int>());
        Assert.Equal(1, body["coverage"]!["evidence_missing_sources"]!.GetValue<int>()); Assert.True(body["has_more"]!.GetValue<bool>()); Assert.NotNull(body["next_cursor"]);
    }

    [Theory][InlineData(false)][InlineData(true)]
    public void LifecycleOptionsComeFromTheReadModelAndKeepTheCurrentStatusOnce(bool declared)
    {
        var raw = O("""{"state":"available","items":[{"id":7,"status":"new"}]}""");
        if (declared) raw["lifecycle"] = O("""{"allowed_transitions":{"new":["new","active","active","false_positive"]}}""");
        var row = SecurityProblemsReader.Render(Context(), raw)["items"]![0]!;
        Assert.Equal(declared ? new[] { "new", "active", "false_positive" } : ["new"], row["allowed_statuses"]!.AsArray().Select(s => s!.ToString()));
    }

    sealed class Repository : IProblemRepository
    {
        internal JsonObject Result = O("""{"state":"available","items":[{"id":7}],"summary":[],"semantic_runtime":{"findings_state":"active"}}""");
        internal List<FindingQuery> Calls = []; internal ProblemAccess? Authorization;
        public Task<JsonObject> FindingsAsync(FindingQuery q, ProblemAccess access, CancellationToken ct) { Calls.Add(q); Authorization = access; return Task.FromResult(Result.DeepClone().AsObject()); }
        public Task<JsonObject> StatusAsync(long id, FindingStatusInput input, string actor, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> RiskAsync(long id, RiskInput input, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> ResponsiblesAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> RiskAuditAsync(long id, long? before, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> WatchListAsync(RegistryQuery query, ProblemAccess access, Principal p, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> WatchSaveAsync(string? id, WatchInput input, ProblemAccess access, Principal p, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> DecoyListAsync(RegistryQuery query, ProblemAccess access, Principal p, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> DecoySaveAsync(string? id, DecoyInput input, ProblemAccess access, Principal p, CancellationToken ct) => throw new NotSupportedException();
    }
    sealed class Evidence : ISecurityProblemEvidence
    {
        internal int Calls; internal JsonObject Result = O("""{"items":[],"total":0,"has_more":false}""");
        public Task<JsonObject> PageAsync(ReportQueryContext c, long finding, JsonObject? cursor, CancellationToken ct) { Calls++; return Task.FromResult(Result.DeepClone().AsObject()); }
    }
}
