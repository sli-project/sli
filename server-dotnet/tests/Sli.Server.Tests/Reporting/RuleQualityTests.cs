using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;
using Sli.Server.Problems;
using Sli.Server.Reporting.V2;
using Sli.Server.Semantic;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Reporting;

// Parity vectors from tests/reporting/test_rule_quality.py; synthetic data only.
public sealed class RuleQualityTests
{
    const string Key = "security.rule-quality";
    static readonly DateTimeOffset Start = DateTimeOffset.Parse("2026-10-01T00:00:00Z", CultureInfo.InvariantCulture);
    static readonly DateTimeOffset End = Start.AddDays(7);
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static ReportDefinition Definition(string key = Key) => new ReportDefinitionRegistry().Get(key)!;
    static string Stamp(DateTimeOffset value) => value.ToString("O", CultureInfo.InvariantCulture);
    static JsonObject Change(int id, string status, int hours, string? old = "new") => new()
    { ["id"] = id, ["new_status"] = status, ["old_status"] = old, ["changed_at"] = Stamp(Start.AddHours(hours)) };
    static JsonObject Finding(string rule = "semantic.synthetic", params JsonObject[] history) => new()
    {
        ["id"] = 1, ["rule_code"] = rule, ["created_at"] = Stamp(Start), ["repeat_count"] = 0,
        ["history"] = new JsonArray(history.Select(h => (JsonNode?)h).ToArray()), ["complete_evidence"] = true, ["suppressed"] = false
    };
    static JsonObject Policy(string id, string rule, string? kind = null, bool enabled = false, bool managed = false, int version = 1) => new()
    { ["policy_id"] = id, ["policy_version"] = version, ["rule_code"] = rule, ["result_class"] = kind, ["enabled"] = enabled, ["managed"] = managed, ["title"] = "must not escape" };
    static IQueryCollection Query(params (string Key, string Value)[] values) => new QueryCollection(values.ToDictionary(p => p.Key, p => new StringValues(p.Value)));
    static AccessFacts Facts(bool review = true, bool assigned = true, bool security = true, string scope = "{\"kind\":\"all\"}")
    {
        JsonElement J(object value) => JsonSerializer.SerializeToElement(value);
        return new(false, "viewer", [], [],
            (review ? new[] { "field.security", "semantic.review" } : ["field.security"]).Select(c => J(new { capability_key = c, effect = "allow", scope_json = new { kind = "all" } })).ToArray(), [], [],
            assigned ? [J(new { report_key = "security.queue", effect = "allow", allowed_actions = new[] { "view" }, field_categories = security ? new[] { "security" } : [], scope_json = ReportFixture.J(scope) })] : [],
            [J(new { report_key = "security.queue", version = 1, dataset_version = 1, definition_json = new { actions = new[] { "view" } }, actions_json = new[] { "view" }, fields_json = new[] { new { category = "security" } } })]);
    }
    static ReportQueryContext Context(AccessFacts? facts = null, ReportScope? scope = null, string? cursor = null, string? sort = null, string direction = "asc", int limit = 50, DateTimeOffset? now = null)
    {
        facts ??= Facts();
        var access = new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts));
        var projection = new ReportAccess(Definition(), access);
        var (parameters, paging) = ReportParameters.Parse(Definition(), now is null
            ? Query(("period", "custom"), ("from", Stamp(Start)), ("to", Stamp(End))) : Query(("period", "7d")), now);
        return new(Definition(), access, new Principal("session", 7, "viewer"), parameters,
            paging with { Cursor = cursor, Sort = sort, Direction = direction, Limit = limit }, scope ?? projection.Scope, null, "view", projection.FieldsAllowed, access.Reports.Single().Grants);
    }
    sealed class Database : ISemanticDatabase, ISemanticSession
    {
        public JsonArray Findings = [], Policies = [];
        public readonly List<(string Sql, object?[] Values)> Queries = [];
        public Exception? Failure;
        public int Opens, Disposes;
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct)
        { Assert.False(write); Opens++; return Task.FromResult<ISemanticSession>(this); }
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            Queries.Add((sql, values));
            if (Failure is not null) throw Failure;
            Assert.True(sql == RuleQualityReader.CohortSql || sql == RuleQualityReader.PoliciesSql);
            return Task.FromResult((JsonArray)(sql == RuleQualityReader.CohortSql ? Findings : Policies).DeepClone());
        }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("Read-only reports do not commit changes");
        public ValueTask DisposeAsync() { Disposes++; return ValueTask.CompletedTask; }
    }
    static JsonObject[] Rows(JsonObject result) => result["items"]!.AsArray().OfType<JsonObject>().ToArray();
    static string[] Notes(JsonObject result) => result["limitations"]!.AsArray().Select(n => n!["code"]!.ToString()).ToArray();
    static void Number(JsonObject row, string key, double expected) => Assert.Equal(expected, double.Parse(row[key]!.ToString(), CultureInfo.InvariantCulture));

    [Fact]
    public void LifecycleHasOneVoteLatestClassificationClosureReopenAndMedianWithoutMutation()
    {
        var suppressed = Finding(history: [Change(1, "false_positive", 2), Change(2, "false_positive", 3, "false_positive"), Change(3, "closed", 4, "false_positive")]); suppressed["suppressed"] = true;
        var repeated = Finding(history: [Change(1, "confirmed", 6), Change(2, "false_positive", 10, "confirmed")]); repeated["repeat_count"] = 2;
        var incomplete = Finding(history: [Change(1, "new", 0, null)]); incomplete["complete_evidence"] = false;
        JsonArray source = [suppressed, repeated,
            Finding(history: [Change(1, "false_positive", 8), Change(2, "active", 9, "false_positive"), Change(3, "confirmed", 12, "active")]),
            Finding(history: [Change(1, "accepted_risk", 10)]), incomplete];
        var original = source.DeepClone();
        var row = Assert.Single(RuleQualityReader.Metrics(source.OfType<JsonObject>(), End));
        foreach (var (key, value) in new (string, double)[] { ("findings_produced", 5), ("false_positive", 2), ("confirmed", 1), ("closed", 1), ("accepted_risk", 1), ("suppressed", 1), ("false_positive_rate", 66.67), ("classified", 3), ("median_decision_seconds", 7 * 3600), ("decided", 4), ("repeat_rate", 20), ("complete_evidence_share", 80) }) Number(row, key, value);
        Assert.True(JsonNode.DeepEquals(original, source));
    }

    [Fact]
    public void WindowEndIsExclusiveAndUnclassifiedAndUnsupportedMetricsStayNull()
    {
        var rows = RuleQualityReader.Metrics([
            Finding(history: [Change(1, "new", 0, null), Change(2, "false_positive", 7 * 24)]),
            Finding("semantic.other", Change(1, "closed", 4))], End, acceptedRisk: false);
        Assert.All(rows, r => { Assert.Null(r["false_positive_rate"]); Assert.Null(r["accepted_risk"]); });
        Assert.Null(rows[1]["median_decision_seconds"]); Number(rows[0], "median_decision_seconds", 4 * 3600);
    }

    [Fact]
    public void HistoryTiesUseIdAndRepeatedTransitionAndMissingHistoryAreCounted()
    {
        var row = Assert.Single(RuleQualityReader.Metrics([
            Finding(history: [Change(2, "false_positive", 1, "confirmed"), Change(1, "confirmed", 1), Change(3, "repeated", 2, "false_positive")]),
            Finding()], End, acceptedRisk: false));
        Number(row, "false_positive", 1); Number(row, "confirmed", 0); Number(row, "missing_history", 1); Number(row, "repeat_rate", 50);
    }

    [Fact]
    public async Task ReaderIsReadOnlyScopesBeforePagingAndKeepsSuppressionAndPolicyContext()
    {
        var finding = Finding(history: [Change(1, "new", 0, null)]); finding["suppressed"] = true;
        var db = new Database { Findings = [finding], Policies = [Policy("synthetic-policy", "semantic.synthetic", managed: true)] };
        var body = await new RuleQualityReader(db).QueryAsync(Context(Facts(scope: "{\"kind\":\"domain\",\"ids\":[7]}")), Ct);
        Assert.Equal(1, db.Opens); Assert.Equal(1, db.Disposes); Assert.Equal(2, db.Queries.Count);
        var parameters=db.Queries[0].Values;
        Assert.Equal(Start,parameters[0]); Assert.Equal(End,parameters[1]); Assert.Equal(new long[]{7},Assert.IsType<long[]>(parameters[2]));
        var row = Assert.Single(Rows(body)); Number(row, "suppressed", 1);
        Assert.Equal("synthetic-policy:1", Assert.Single(row["managed_policies"]!.AsArray())!.ToString()); Assert.Empty(row["admitted_policies"]!.AsArray());
    }

    [Theory]
    [InlineData(false, false)] [InlineData(true, false)] [InlineData(false, true)]
    public async Task UnprovenCoverageMissingHistoryAndTruncationRemainPartial(bool truncated, bool missing)
    {
        var db = new Database();
        int count = truncated ? 10001 : 1;
        for (int i = 0; i < count; i++) db.Findings.Add(missing ? Finding() : Finding(history: [Change(1, "new", 0, null)]));
        var body = await new RuleQualityReader(db).QueryAsync(Context(), Ct);
        Assert.Equal("partial", body["state"]!.ToString()); Assert.Equal("not_proven", body["coverage"]!["completeness"]!.ToString());
        Assert.Equal(truncated, body["coverage"]!["truncated"]!.GetValue<bool>());
        Number(Assert.Single(Rows(body)), "findings_produced", truncated ? 10000 : 1);
        Assert.Equal(truncated, Notes(body).Contains("truncated")); Assert.Equal(missing, Notes(body).Contains("history_missing"));
        Assert.False(body["coverage"]!["accepted_risk_supported"]!.GetValue<bool>()); Assert.Contains("accepted_risk_unavailable", Notes(body));
    }

    [Fact]
    public async Task UnprovenEmptyCohortAndSanitizedSourceErrorAreDistinct()
    {
        var db = new Database(); var reader = new RuleQualityReader(db);
        var empty = await reader.QueryAsync(Context(), Ct);
        Assert.Equal("partial", empty["state"]!.ToString()); Assert.Empty(Rows(empty)); Assert.Equal("not_proven", empty["coverage"]!["completeness"]!.ToString());
        db.Failure = new InvalidOperationException("synthetic-error");
        var error = await reader.QueryAsync(Context(), Ct);
        Assert.Equal("error", error["state"]!.ToString()); Assert.Null(error["filtered_count"]);
        Assert.Equal("source_or_storage_error", error["state_details"]!["reason"]!.ToString()); Assert.Equal(new[] { "unavailable" }, Notes(error));
        Assert.DoesNotContain("synthetic-error", error.ToJsonString()); Assert.Equal(2, db.Disposes);
    }

    [Theory]
    [InlineData(false, true, true, "{\"kind\":\"all\"}")]
    [InlineData(true, false, true, "{\"kind\":\"all\"}")]
    [InlineData(true, true, false, "{\"kind\":\"all\"}")]
    [InlineData(true, true, true, "{\"kind\":\"domain\",\"ids\":[]}")]
    [InlineData(true, true, true, "{\"mode\":\"restricted\",\"clauses\":[{\"entity_ids\":[7]}]}")]
    public async Task DeclarationAndDataDenyIneligibleReadersBeforeOpeningStorage(bool review, bool assigned, bool security, string scope)
    {
        var db = new Database();
        await using var host = await ReportFixture.Start(Facts(review, assigned, security, scope), Definition(), nativeReader: new RuleQualityReader(db));
        foreach (string suffix in new[] { "", "/data" })
        {
            using var response = await host.Client.GetAsync("/api/v2/reports/" + Key + suffix, Ct);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }
        Assert.Equal(0, db.Opens);
    }

    [Theory] [InlineData("{\"kind\":\"all\"}")] [InlineData("{\"kind\":\"domain\",\"ids\":[7]}")]
    public async Task AnalystDeclarationAcceptsGlobalAndDomainGrants(string scope)
    {
        var db = new Database(); var context = Context(Facts(scope: scope));
        if (scope.Contains("domain", StringComparison.Ordinal)) Assert.Equal(new long[] { 7 }, context.Scope.DomainIds()); else Assert.Equal("all", context.Scope.Mode);
        await using var host = await ReportFixture.Start(Facts(scope: scope), Definition(), nativeReader: new RuleQualityReader(db));
        using var response = await host.Client.GetAsync("/api/v2/reports/" + Key, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Equal(Key, (await ReportFixture.Body(response))["key"]!.ToString()); Assert.Equal(0, db.Opens);
    }

    [Fact]
    public void OwnerGrantHasGlobalScopeWithoutExplicitAssignment()
    {
        var facts = Facts(assigned: false);
        var context = Context(facts with { IsOwner = true, AllCapabilities = facts.DirectCapabilities });
        Assert.Equal("all", context.Scope.Mode); Assert.Null(context.Scope.DomainIds());
    }

    [Fact]
    public void CatalogRuleIsExecutableOnlyWithReviewCapabilityAndSecurityGrant()
    {
        var rule = Assert.Single(new ReportRuleCatalog(new PluginGenerationReader(null)).Capture().Rules, r => r.RegistryKey == Key);
        Assert.Equal("security.queue", rule.ReportKey); Assert.Equal("sli.core", rule.OwnerId);
        Assert.Equal(new[] { "semantic.review" }, rule.RequiredCapabilities); Assert.Equal(new[] { "security" }, rule.RequiredFields);
        foreach (bool review in new[] { false, true })
        {
            var facts = Facts(review: review);
            var access = new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts));
            Assert.Equal(review ? DomainGrantKind.All : DomainGrantKind.None, new ReportScopeResolver().PermittedDomains(access, [rule]).Kind);
        }
    }

    [Fact]
    public async Task UnsupportedReaderScopeFailsClosedBeforeOpeningStorage()
    {
        var db = new Database();
        var scope = new ReportScope("restricted", [new JsonObject { ["entity_ids"] = new JsonArray(7) }]);
        var error = await Assert.ThrowsAsync<ReportRequestException>(() => new RuleQualityReader(db).QueryAsync(Context(scope: scope), Ct));
        Assert.Equal(403, error.Status); Assert.Equal("report_scope_not_executable", error.Message); Assert.Equal(0, db.Opens);
    }

    [Fact]
    public async Task DefaultSortCursorPinsRollingWindowAndRejectsChangedSort()
    {
        var db = new Database { Findings = [Finding("semantic.low", Change(1, "confirmed", 2)), Finding("semantic.high", Change(1, "false_positive", 3)), Finding("semantic.unknown", Change(1, "new", 0, null))] };
        var reader = new RuleQualityReader(db);
        var first = await reader.QueryAsync(Context(limit: 1, now: End), Ct);
        Assert.Equal("sli.report-result.v2", first["contract_id"]!.ToString()); Assert.Equal("partial", first["state"]!.ToString()); Assert.True(first["has_more"]!.GetValue<bool>());
        Assert.Equal("semantic.high", Assert.Single(Rows(first))["rule_code"]!.ToString());
        string cursor = first["next_cursor"]!.ToString();
        var second = await reader.QueryAsync(Context(limit: 1, now: End.AddMinutes(1), cursor: cursor), Ct);
        Assert.Equal("semantic.low", Assert.Single(Rows(second))["rule_code"]!.ToString());
        Assert.All(db.Queries.Where(q => q.Sql == RuleQualityReader.CohortSql), q => { Assert.Equal(Start, q.Values[0]); Assert.Equal(End, q.Values[1]); });
        var third = await reader.QueryAsync(Context(limit: 1, now: End.AddMinutes(2), cursor: second["next_cursor"]!.ToString()), Ct);
        Assert.Equal("semantic.unknown", Assert.Single(Rows(third))["rule_code"]!.ToString()); Assert.False(third["has_more"]!.GetValue<bool>()); Assert.Null(third["next_cursor"]);
        var error = await Assert.ThrowsAsync<ReportRequestException>(() => reader.QueryAsync(Context(limit: 1, now: End, cursor: cursor, sort: "false_positive_rate", direction: "asc"), Ct));
        Assert.Equal("invalid_cursor", error.Message); Assert.Equal(3, db.Opens);
    }

    [Fact]
    public async Task ApiPaginationRechecksAccessBeforeLoadingNextPage()
    {
        var db = new Database { Findings = [Finding("semantic.low", Change(1, "confirmed", 2)), Finding("semantic.high", Change(1, "false_positive", 3))] };
        await using var host = await ReportFixture.Start(Facts(), Definition(), nativeReader: new RuleQualityReader(db));
        const string path = "/api/v2/reports/security.rule-quality/data?period=7d&limit=1";
        using var firstResponse = await host.Client.GetAsync(path, Ct); Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);
        var first = await ReportFixture.Body(firstResponse); string cursor = first["next_cursor"]!.ToString();
        Assert.Equal("semantic.high", Assert.Single(Rows(first))["rule_code"]!.ToString());
        using var nextResponse = await host.Client.GetAsync(path + "&cursor=" + Uri.EscapeDataString(cursor), Ct); Assert.Equal(HttpStatusCode.OK, nextResponse.StatusCode);
        Assert.Equal("semantic.low", Assert.Single(Rows(await ReportFixture.Body(nextResponse)))["rule_code"]!.ToString());
        var windows = db.Queries.Where(q => q.Sql == RuleQualityReader.CohortSql).ToArray(); Assert.Equal(windows[0].Values, windows[1].Values);
        host.Facts.Value = Facts(review: false);
        using var denied = await host.Client.GetAsync(path + "&cursor=" + Uri.EscapeDataString(cursor), Ct);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode); Assert.Equal(2, db.Opens);
    }

    static readonly string[] TechnicalKeys = ["rule_code", "policies", "admitted_policies", "managed_policies", "closed", "accepted_risk", "suppressed", "classified", "median_decision_seconds", "decided", "repeat_rate"];
    [Theory]
    [InlineData("semantic.qw.file-ransom", "Признаки шифровальщика: массовые изменения файлов", "Ransomware indicators: mass file changes")]
    [InlineData("semantic.security.audit_controls_changed", "Изменения контроля аудита", "Audit control changes")]
    [InlineData("semantic.security.privileged_group_member_added", "Добавление участника в привилегированную группу", "Member added to a privileged group")]
    [InlineData("semantic.security.scheduled_task_created", "Создание задачи планировщика", "Scheduled task creation")]
    public async Task LocalizedRuleNamesAndInlineDetailsPreserveMetricsAndIdentity(string rule, string ru, string en)
    {
        var db = new Database { Findings = [Finding(rule, Change(1, "confirmed", 2)), Finding("semantic.synthetic-one"), Finding("semantic.synthetic-two")],
            Policies = [Policy("synthetic-policy", rule, managed: true, version: 7), Policy("synthetic-policy", "semantic.synthetic-one", managed: true, version: 7), Policy("synthetic-policy", "semantic.synthetic-two", managed: true, version: 7)] };
        var source = db.Findings.DeepClone(); var policies = db.Policies.DeepClone();
        var metrics = RuleQualityReader.Metrics(db.Findings.OfType<JsonObject>(), End, acceptedRisk: false);
        var body = await new RuleQualityReader(db).QueryAsync(Context(), Ct);
        foreach (var row in Rows(body))
        {
            string code = row["rule_code"]!.ToString(); bool known = code == rule;
            Assert.Equal(known ? ru : "Название правила недоступно", row["rule_name"]!.ToString());
            var message = row["presentation_messages"]!["rule_name"]!;
            Assert.Equal(row["rule_name"]!.ToString(), message["text"]!.ToString());
            Assert.Equal(known ? en : "Rule name unavailable", ReportResult.Message(message["code"]!.ToString(), english: true)["text"]!.ToString());
            var details = Assert.Single(row["technical_details"]!.AsArray())!.AsObject(); Assert.Equal(TechnicalKeys.Order(), details.Select(p => p.Key).Order());
            foreach (string key in TechnicalKeys) Assert.True(JsonNode.DeepEquals(row[key], details[key]), key);
            Assert.Equal("synthetic-policy:7", Assert.Single(row["policies"]!.AsArray())!.ToString());
            Assert.Equal("synthetic-policy:7", Assert.Single(row["managed_policies"]!.AsArray())!.ToString()); Assert.Empty(row["admitted_policies"]!.AsArray());
            foreach (var (key, value) in metrics.Single(r => r["rule_code"]!.ToString() == code)) Assert.True(JsonNode.DeepEquals(value, row[key]), key);
            Assert.Equal(Start, DateTimeOffset.Parse(row["cohort_from"]!.ToString(), CultureInfo.InvariantCulture)); Assert.Equal(End, DateTimeOffset.Parse(row["cohort_to"]!.ToString(), CultureInfo.InvariantCulture));
            if (!known) Assert.Null(row["false_positive_rate"]);
        }
        Assert.True(JsonNode.DeepEquals(source, db.Findings)); Assert.True(JsonNode.DeepEquals(policies, db.Policies));
        var definition = Definition(); Assert.Equal("rule_code", definition.Declaration["row_key"]!.ToString()); Assert.Equal("rule_name", definition.Columns[0]["key"]!.ToString());
        Assert.DoesNotContain(definition.Columns, c => new[] { "rule_code", "policies", "admitted_policies", "managed_policies" }.Contains(c["key"]!.ToString()));
        Assert.Equal("technical_details", definition.Detail!["inline"]!.ToString()); Assert.False(definition.HasDetail);
        Assert.Equal(TechnicalKeys.Order(), definition.Detail["columns"]!.AsArray().Select(c => c!["key"]!.ToString()).Order());
        Assert.Contains("rule_code={rule_code}&created_from={cohort_from}&created_to={cohort_to}&show_suppressed=true", definition.Columns[0]["link"]!.ToString());
    }

    [Theory]
    [InlineData("security_incident", "Name unavailable · incident detection")]
    [InlineData("security_exposure", "Name unavailable · security exposure")]
    [InlineData("control_gap", "Name unavailable · control gap")]
    public async Task AllowlistedPolicyMetadataProducesLocalizedFallbackWithoutPolicyTitle(string kind, string label)
    {
        var db = new Database { Findings = [Finding()], Policies = [Policy("synthetic-policy", "semantic.synthetic", kind)] };
        var row = Assert.Single(Rows(await new RuleQualityReader(db).QueryAsync(Context(), Ct)));
        Assert.Equal(kind, row["rule_result_class"]!.ToString());
        string code = row["presentation_messages"]!["rule_name"]!["code"]!.ToString();
        Assert.Equal(label, ReportResult.Message(code, english: true)["text"]!.ToString());
        Assert.Equal("semantic.synthetic", row["technical_details"]![0]!["rule_code"]!.ToString()); Assert.DoesNotContain("must not escape", row.ToJsonString());
    }

    [Fact]
    public async Task MetadataUsesOnlyUnambiguousAllowlistedPolicyClass()
    {
        var db = new Database { Findings = [Finding("semantic.single"), Finding("semantic.conflict"), Finding("semantic.invalid")], Policies = [
            Policy("0", "semantic.single", "security_incident"), Policy("1", "semantic.single", "security_incident"),
            Policy("2", "semantic.conflict", "control_gap"), Policy("3", "semantic.conflict", "security_incident"), Policy("4", "semantic.invalid", "private value")] };
        var result = await new RuleQualityReader(db).QueryAsync(Context(), Ct); var rows = Rows(result).ToDictionary(r => r["rule_code"]!.ToString());
        Assert.Equal("security_incident", rows["semantic.single"]["rule_result_class"]!.ToString()); Assert.Null(rows["semantic.conflict"]["rule_result_class"]); Assert.Null(rows["semantic.invalid"]["rule_result_class"]);
        Assert.DoesNotContain("must not escape", result.ToJsonString()); Assert.DoesNotContain("private value", result.ToJsonString()); Assert.Contains("definition_json->>'result_class'", db.Queries[1].Sql);
    }

    [Fact]
    public void CohortLinkParsesToExactRuleAndExclusiveCreationWindowIncludingSuppressedFindings()
    {
        var context = Context();
        var (parameters, paging) = ReportParameters.Parse(Definition("security.problems"), Query(("rule_code", "semantic.synthetic"), ("created_from", Stamp(Start)), ("created_to", Stamp(End)), ("show_suppressed", "true")));
        var input = SecurityProblemsReader.Input(context with { Definition = Definition("security.problems"), Params = parameters, Paging = paging });
        Assert.Equal("semantic.synthetic", input.RuleCode); Assert.Equal(Stamp(Start), input.CreatedFrom); Assert.Equal(Stamp(End), input.CreatedTo); Assert.True(input.Suppressed);
        parameters["created_from"] = "2026-10-01T00:00:00";
        Assert.Equal("report_period_invalid", Assert.Throws<ReportRequestException>(() => SecurityProblemsReader.Input(context with { Definition = Definition("security.problems"), Params = parameters, Paging = paging })).Message);
    }

    sealed class Connections(PostCollectionPostgres pg) : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => pg.OpenAsync(ct);
    }

    [Fact]
    public async Task Evidence_copies_preserve_domain_scope_and_completeness_without_source_events()
    {
        await using var pg=new PostCollectionPostgres(canonicalSchema:true);await pg.StartAsync(Ct);
        await using var db=await pg.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db,"""
            create table findings_active(id bigint,rule_code text,created_at timestamptz,repeat_count integer,evidence_count bigint,published boolean);
            create table finding_status_history(id bigint,finding_id bigint,old_status text,new_status text,changed_at timestamptz);
            create table finding_event_details337(finding_id bigint,event_id int,time_created_utc timestamptz,event_record_id bigint,channel text,domain_id bigint);
            create function is_semantic_finding_published_v1(bigint) returns boolean language sql as $$select published from findings_active where id=$1$$;
            create function semantic_finding_suppressed_v160(bigint,text) returns boolean language sql as $$select false$$;
            insert into findings_active select n,'semantic.synthetic','2026-10-01T00:00:00Z',0,1,true from generate_series(1,5) n;
            update findings_active set evidence_count=2 where id=2;
            update findings_active set published=false where id=5;
            insert into finding_event_details337 values
                (1,4719,'2026-10-01T00:00:00Z',1,'Security',7),
                (2,4719,'2026-10-01T00:00:00Z',2,'Security',7),
                (2,4719,'2026-10-01T00:00:00Z',3,'Security',8),
                (4,4719,'2026-10-01T00:00:00Z',4,null,7),
                (5,4719,'2026-10-01T00:00:00Z',5,'Security',7);
            """,Ct);
        var scoped=await Sli.Server.Ad.AdJson.ReadAsync(db,RuleQualityReader.CohortSql,Ct,Start,End,new long[]{7});
        Assert.Equal(new long[]{1,4},scoped.Select(r=>r["id"]!.GetValue<long>()));
        Assert.True(scoped[0]["complete_evidence"]!.GetValue<bool>());Assert.False(scoped[1]["complete_evidence"]!.GetValue<bool>());
        var all=await Sli.Server.Ad.AdJson.ReadAsync(db,RuleQualityReader.CohortSql,Ct,Start,End,null);
        Assert.Equal(new long[]{1,2,3,4},all.Select(r=>r["id"]!.GetValue<long>()));
        Assert.False(all.Single(r=>r["id"]!.GetValue<long>()==3)["complete_evidence"]!.GetValue<bool>());
    }

    [Fact]
    public async Task QueueRowsAndSummaryApplyExactRuleAndExclusiveCreationWindowAndKeepSuppressed()
    {
        // An owned disposable cluster: no installed runtime or inherited connection string.
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using (var db = await pg.OpenAsync(Ct))
            await PostCollectionPostgres.Sql(db, """
                create table findings_active(id bigint,rule_code text,created_at timestamptz,repeat_count integer,
                    severity text,status text,last_seen_utc text,updated_at timestamptz);
                create table auth_users(id bigint,username text);
                create table semantic_suppressions(id bigint,finding_id bigint,kind text,responsible_user_id bigint,
                    state text,expires_at timestamptz,semantic_type text not null);
                create table semantic_control_audit(id bigint,action text,actor text,occurred_at timestamptz,details jsonb);
                create table runtime_worker_heartbeats(worker_name text,status text,phase text,heartbeat_at timestamptz,expected_interval_seconds integer,details_json jsonb);
                create table findings_refresh_state(pipeline_name text,last_status text,last_error text);
                create function is_semantic_finding_published_v1(bigint) returns boolean language sql as 'select true';
                create function semantic_finding_in_domains_v265(bigint,bigint[]) returns boolean language sql as 'select true';
                create function semantic_finding_suppressed_v160(bigint,text) returns boolean language sql as 'select $1=1';
                create function semantic_finding_review_v160(bigint) returns jsonb language sql as 'select null::jsonb';
                create function finding_decoy_context(bigint) returns jsonb language sql as 'select null::jsonb';
                insert into semantic_suppressions(id,kind,state,expires_at,semantic_type)
                    values(1,'suppression','active',now()+interval '1 day','semantic.synthetic');
                insert into findings_active(id,rule_code,created_at,repeat_count,severity,status,last_seen_utc,updated_at) values
                    (1,'semantic.synthetic','2026-10-01T00:00:00Z',0,'high','new','2026-10-01T00:00:00Z','2026-10-01T00:00:00Z'),
                    (2,'semantic.synthetic-other','2026-10-02T00:00:00Z',0,'high','new','2026-10-02T00:00:00Z','2026-10-02T00:00:00Z'),
                    (3,'semantic.synthetic','2026-10-08T00:00:00Z',0,'high','new','2026-10-08T00:00:00Z','2026-10-08T00:00:00Z'),
                    (4,'semantic.synthetic','2026-09-30T23:59:59Z',0,'high','new','2026-09-30T23:59:59Z','2026-09-30T23:59:59Z'),
                    (5,'semantic.synthetic','2026-10-07T00:00:00Z',0,'high','new','2026-10-07T00:00:00Z','2026-10-07T00:00:00Z');
                """, Ct);
        var context = Context();
        var (parameters, paging) = ReportParameters.Parse(Definition("security.problems"), Query(("rule_code", "semantic.synthetic"), ("created_from", Stamp(Start)), ("created_to", Stamp(End)), ("show_suppressed", "true")));
        var input = SecurityProblemsReader.Input(context with { Definition = Definition("security.problems"), Params = parameters, Paging = paging });
        var repository = new ProblemRepository(new Connections(pg), TimeProvider.System);
        var access = new ProblemAccess(context.Access);
        var result = await repository.FindingsAsync(input with { Compact = true, GroupQueue = false, Limit = 1 }, access, Ct);
        Assert.Equal("5", Assert.Single(Rows(result))["id"]!.ToString()); Assert.True(result["has_more"]!.GetValue<bool>());
        Assert.Equal("2", Assert.Single(result["summary"]!.AsArray())!["count"]!.ToString());
        result = await repository.FindingsAsync(input with { Compact = true, GroupQueue = false, Limit = 10 }, access, Ct);
        Assert.Equal(new[] { "5", "1" }, Rows(result).Select(r => r["id"]!.ToString())); Assert.True(Rows(result).Single(r => r["id"]!.ToString() == "1")["suppressed"]!.GetValue<bool>());
        result = await repository.FindingsAsync(input with { Compact = true, GroupQueue = false, Suppressed = false, Limit = 10 }, access, Ct);
        Assert.Equal("5", Assert.Single(Rows(result))["id"]!.ToString()); Assert.Equal("1", Assert.Single(result["summary"]!.AsArray())!["count"]!.ToString());
        Assert.DoesNotContain("ERROR:", await pg.DiagnosticsAsync(Ct));
    }
}
