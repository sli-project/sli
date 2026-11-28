using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Domains;
using Sli.Server.Agents.Registry;
using Sli.Server.Problems;
using Xunit;
using AdV2Request = Sli.Server.Ad.AdV2Request;
using IAdV2Store = Sli.Server.Ad.IAdV2Store;
using IGpoReadStore = Sli.Server.Gpo.IGpoReadStore;

namespace Sli.Server.Tests.Domains;

public sealed partial class HomeSummaryEndpointTests
{
    [Fact]
    public async Task Weak_spots_cap_results_and_represent_each_allowed_check_screen()
    {
        var ad = new WeakSpotAdStore();
        var gpo = new WeakSpotGpoStore();
        var reports = new[] { Report("ad.infrastructure"), Report("ad.users.v2"), Report("ad.computers.v6"), Report("ad.gpo.v2") };
        var context = new DefaultHttpContext();
        context.Request.QueryString = new QueryString("?contract=v5&domain_id=7");
        var query = HomeSummaryQuery.Parse(context.Request.Query, Now);
        async Task<JsonObject> Read(params HomeReport[] allowed)
        {
            var service = new HomeSummaryService(new Reports(allowed), new Domains(true), new HomeSummaryReaders(new Rows(false)), gpo, ad: ad);
            return (await service.BuildAsync(new("session", 1, "viewer"), query, TestContext.Current.CancellationToken))["weak_spots"]!.AsObject();
        }

        var total = await Read(reports);
        var items = total["items"]!.AsArray();
        Assert.Equal(10, items.Count);
        Assert.Empty(total["failed"]!.AsArray());
        var controls = Assert.Single(items, item => item.Text("report") == "ad.infrastructure");
        Assert.Equal(2, controls.Number("count"));
        Assert.Contains("qualification=failed", controls.Text("href"));
        Assert.Contains(items, item => item.Text("report") == "ad.users.v2" && item.Text("href")!.Contains("account_rows=yes"));
        Assert.Contains(items, item => item.Text("id") == "ad.computers.v6:laps" && item.Text("href")!.Contains("tab=checks"));
        Assert.Contains(items, item => item.Text("report") == "ad.gpo.v2" && item.Text("href")!.Contains("view=attention"));
        Assert.DoesNotContain(items, item => item.Text("id") == "ad.computers.v6:new_computer");
        Assert.All(items, item => Assert.Contains("domain=7", item.Text("href")));

        ad.Requests.Clear();
        var restricted = await Read(reports[0], Report("ad.users.v2", ["identity_basic", "security", "technical"]), reports[2]);
        Assert.DoesNotContain(ad.Requests, request => request.Key == "ad.users.v2");
        Assert.DoesNotContain(restricted["items"]!.AsArray(), item => item.Text("report") is "ad.users.v2" or "ad.gpo.v2");
    }

    private sealed class WeakSpotAdStore : IAdV2Store
    {
        public List<AdV2Request> Requests { get; } = [];
        public Task<IReadOnlyList<JsonObject>> DomainsAsync(DomainGrant grant, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> ReadAsync(AdV2Request request, Func<IEnumerable<string>, bool> fields, CancellationToken ct)
        {
            Requests.Add(request);
            Assert.Equal(new long[] { 7 }, request.Domains);
            if (request.Key == "ad.users.v2")
            {
                Assert.Equal("yes", (string?)request.Params["account_rows"]);
                var checks = Enumerable.Range(1, 12).Select(number => new { value = "user_" + number, count = number });
                return Task.FromResult(HomeJson.Object(new { state = "ok", filter_options = new { check = checks } }));
            }
            object items = request.Key switch
            {
                "ad.infrastructure" => new[] { 1, 1, 2 }.Select(id => new { control_id = "dc.dns", qualification = "failed", entity_id = id, label = "DNS" }),
                _ => new[] { new { key = "laps", title = "Expired LAPS", total = 4 },
                    new { key = "new_computer", title = "New computers", total = 25 }, new { key = "rbcd", title = "Delegation", total = 0 } }
            };
            return Task.FromResult(HomeJson.Object(new { state = "ok", items }));
        }
    }

    private sealed class WeakSpotGpoStore : IGpoReadStore
    {
        public Task<JsonObject> PairAsync(long[]? domains, CancellationToken ct)
        {
            Assert.Equal(new long[] { 7 }, domains);
            return Task.FromResult(JsonNode.Parse("""
                {"current":{"gpos":[{"computer":{"directory_version":12,"sysvol_version":11},
                  "source_states":{"report":{"status":"observed"},"sysvol_gpt":{"status":"observed"}}}]}}
                """)!.AsObject());
        }
        public Task<JsonObject> HistoryAsync(long[]? domains, DateTimeOffset from, DateTimeOffset to, string query, CancellationToken ct) =>
            Task.FromResult(new JsonObject { ["items"] = new JsonArray() });
        public Task<JsonObject> GraphAsync(JsonObject snapshot, long[]? domains, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> PolicyHistoryAsync(long[] domains, DateTimeOffset from, DateTimeOffset to, string policyId, string guid, CancellationToken ct) =>
            throw new NotSupportedException();
    }

    [Theory]
    [InlineData("problems")]
    [InlineData("controllers")]
    [InlineData("changes")]
    [InlineData("activity")]
    public async Task Period_home_isolates_a_failed_read_and_recovers_on_the_next_request(string block)
    {
        var owner = Report("events.journal").Capabilities! with { IsOwner = true };
        HomeReport[] reports = [Report("security.problems"), Report("ad.infrastructure"), Report("events.journal") with { Capabilities = owner }];
        var rows = new Rows(populated: false) { FailPeriodRead = sql => block switch {
            "problems" => sql.Contains("as new_count"),
            "controllers" => sql == HomePeriodSql.Controllers,
            "changes" => sql == HomePeriodSql.PasswordPolicyChanges,
            _ => sql.Contains("@read_from", StringComparison.Ordinal)
        } };
        var (status, body) = await Request("?contract=v4&domain_id=7", rows, true, reports);
        Assert.Equal(200, status);
        Assert.True(body.ContainsKey(block));
        Assert.Null(body[block]);
        foreach (var other in new[] { "problems", "controllers", "changes", "activity" }.Where(key => key != block))
            Assert.IsType<JsonObject>(body[other]);

        rows.FailPeriodRead = null;
        var (retryStatus, retryBody) = await Request("?contract=v4&domain_id=7", rows, true, reports);
        Assert.Equal(200, retryStatus);
        Assert.IsType<JsonObject>(retryBody[block]);
    }

    [Theory]
    [InlineData("timeout")]
    [InlineData("postgres")]
    [InlineData("driver")]
    public async Task Report_read_timeout_is_structured_and_the_next_request_can_read(string failure)
    {
        var domains = new Domains(false) { Error = failure switch
        {
            "postgres" => new Npgsql.PostgresException("private-database-value", "ERROR", "ERROR", "57014"),
            "driver" => new Npgsql.NpgsqlException("private-database-value", new TimeoutException("private-read")),
            _ => new TimeoutException("private-database-value")
        } };
        var config = new ConfigurationBuilder().Build();
        using var services = new ServiceCollection().AddLogging().AddSingleton(new TransportGate(config))
            .AddSingleton<IPrincipalAuthenticator>(new Authentication()).AddSingleton<IDomainAccessService>(new Access(true))
            .AddSingleton<IHomeSummaryAccess>(new Reports()).AddSingleton<IDomainRepository>(domains)
            .AddSingleton<IHomeSummaryRepository>(new Rows()).AddSingleton<HomeSummaryReaders>().AddSingleton<HomeSummaryService>()
            .BuildServiceProvider();
        async Task<(int Status, JsonObject Body)> Read()
        {
            var context = new DefaultHttpContext { RequestServices = services };
            context.Request.Path = "/api/v1/home/summary";
            context.Response.Body = new MemoryStream();
            await HomeSummaryEndpoints.HandleAsync(context);
            return (context.Response.StatusCode, JsonNode.Parse(((MemoryStream)context.Response.Body).ToArray())!.AsObject());
        }
        var (status, body) = await Read();
        Assert.Equal(503, status); Assert.Equal(2, body.Count);
        Assert.Equal("report_read_timeout", body["error"]!.GetValue<string>());
        Assert.Equal("unavailable", body["state"]!.GetValue<string>());
        domains.Error = null;
        Assert.Equal(200, (await Read()).Status);
    }

    [Fact]
    public async Task Aborted_request_ignores_postgres_query_cancellation()
    {
        var config = new ConfigurationBuilder().Build();
        var domains = new Domains(false) { Error = new Npgsql.PostgresException("query canceled", "ERROR", "ERROR", "57014") };
        using var services = new ServiceCollection().AddLogging().AddSingleton(new TransportGate(config))
            .AddSingleton<IPrincipalAuthenticator>(new Authentication()).AddSingleton<IDomainAccessService>(new Access(true))
            .AddSingleton<IHomeSummaryAccess>(new Reports()).AddSingleton<IDomainRepository>(domains)
            .AddSingleton<IHomeSummaryRepository>(new Rows()).AddSingleton<HomeSummaryReaders>().AddSingleton<HomeSummaryService>()
            .BuildServiceProvider();
        using var abort = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        abort.Cancel();
        var context = new DefaultHttpContext { RequestServices = services, RequestAborted = abort.Token };
        context.Request.Path = "/api/v1/home/summary";
        context.Response.Body = new MemoryStream();

        await HomeSummaryEndpoints.HandleAsync(context);

        Assert.Equal(0, context.Response.Body.Length);
        Assert.Equal(200, context.Response.StatusCode);
    }

    [Fact]
    public async Task Unavailable_vpn_package_removes_home_contribution_without_cache_reset()
    {
        using var files = new Sli.Server.Tests.Access.ReportCatalogLifecycleTests.CatalogFiles();
        var baseline = files.Catalog.Capture();
        async Task<JsonObject> Home(Sli.Server.Access.ReportCatalogSnapshot snapshot)
        {
            var reports = snapshot.Rules.Where(r => r.RegistryKey is "ad.infrastructure" or "vpn.connections")
                .Select(r => Report(r.RegistryKey)).ToArray();
            var (status, body) = await Request("?contract=v2&domain_id=7", new Rows(), true, reports);
            Assert.Equal(200, status); return body;
        }
        Assert.Contains((await Home(baseline))["kpis"]!.AsArray(), k => (string?)k?["key"] == "vpn_closed");
        files.Fence("sli.remote-access");
        var unavailable = files.Catalog.Capture();
        Assert.DoesNotContain(unavailable.Rules, r => r.RegistryKey == "vpn.connections");
        Assert.DoesNotContain(files.Catalog.Recheck(baseline).Rules, r => r.RegistryKey == "vpn.connections");
        Assert.DoesNotContain((await Home(unavailable))["kpis"]!.AsArray(), k => (string?)k?["key"] == "vpn_closed");
    }

    [Fact]
    public async Task Vpn_capability_denial_never_reads_retained_session_views()
    {
        var rows = new Rows();
        var report = Report("vpn.connections") with { Capabilities = new(false, new HashSet<string>(), new HashSet<string>(), [], new Dictionary<string, JsonElement>()) };
        var (status, body) = await Request("?contract=v2&domain_id=7", rows, true, Report("ad.infrastructure"), report);
        Assert.Equal(200, status);
        var vpn = body["kpis"]!.AsArray().Single(k => (string?)k?["key"] == "vpn_closed");
        Assert.Equal("denied", (string?)vpn?["state"]); Assert.Null(vpn?["value"]);
        Assert.DoesNotContain(rows.Calls, c => c.Sql.Contains("radius_vpn_session_"));
    }

    [Fact] public async Task V1_progress_and_closed_use_published_scoped_status_counts()
    {
        var rows = new Rows { ProblemCounts = new[] { ("new", 2), ("active", 3), ("review", 4), ("closed", 5), ("false_positive", 6) }
            .Select(p => new JsonObject { ["status"] = p.Item1, ["count"] = p.Item2 }).ToArray() };
        var (status, body) = await Request("?contract=v1", rows);
        Assert.Equal(200, status);
        var metrics = body["metrics"]!.AsArray().Single(m => (string?)m!["report_key"] == "security.problems")!["items"]!.AsArray();
        long Value(string key) => metrics.Single(m => (string?)m!["key"] == key)!["value"]!.GetValue<long>();
        Assert.Equal(2, Value("attention")); Assert.Equal(9, Value("open")); Assert.Equal(7, Value("progress")); Assert.Equal(11, Value("closed"));
        var countQuery = rows.Calls.Single(c => c.Sql.Contains("findings.severity") && c.Sql.Contains("group by"));
        Assert.Contains("@all_statuses", countQuery.Sql); Assert.Equal(true, countQuery.Parameters["all_statuses"]);
        Assert.Contains("semantic_finding_in_domains_v265", countQuery.Sql); Assert.Contains("is_semantic_finding_published_v1", countQuery.Sql);
    }
    private sealed class Authentication : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct) =>
            ValueTask.FromResult(AuthenticationResult.Success(new("session", 1, "viewer")));
    }

    private sealed class Access(bool allowed) : IDomainAccessService
    {
        public Task<DomainAccessDecision> EvaluateAsync(Principal principal, CancellationToken ct) =>
            Task.FromResult(new DomainAccessDecision(allowed, "insufficient_capability", DomainGrant.All));
    }

    [Theory]
    [InlineData("v1", false, 403, "workspace_view_required")]
    [InlineData("v2", false, 403, "workspace_view_required")]
    [InlineData("v3", false, 403, "workspace_view_required")]
    public async Task RequiresWorkspaceAccess(string contract, bool allowed, int status, string error)
    {
        var config = new ConfigurationBuilder().Build();
        using var services = new ServiceCollection().AddLogging().AddSingleton(new TransportGate(config))
            .AddSingleton<IPrincipalAuthenticator>(new Authentication()).AddSingleton<IDomainAccessService>(new Access(allowed))
            .BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Path = "/api/v1/home/summary";
        context.Request.QueryString = new QueryString("?contract=" + contract);
        context.Response.Body = new MemoryStream();
        await HomeSummaryEndpoints.HandleAsync(context);
        Assert.Equal(status, context.Response.StatusCode);
        Assert.Contains(error, Encoding.UTF8.GetString(((MemoryStream)context.Response.Body).ToArray()));
    }

    private static readonly DateTimeOffset Now = new(2026, 11, 25, 12, 0, 0, TimeSpan.Zero);

    private sealed class Clock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static string Stamp(DateTimeOffset at) => at.ToString("O");
    private sealed class Domains(bool populated, bool archived = false) : IDomainRepository
    {
        public Exception? Error;
        public Task<IReadOnlyList<DomainItem>> ReadAsync(DomainGrant grant, CancellationToken ct) =>
            Error is { } error ? Task.FromException<IReadOnlyList<DomainItem>>(error) : Task.FromResult<IReadOnlyList<DomainItem>>(populated && grant.Kind != DomainGrantKind.None
                && (grant.Kind == DomainGrantKind.All || grant.DomainIds.Contains(7))
                ? [new DomainItem(7, "synthetic.example", archived, new DomainFreshness(Stamp(Now), Stamp(Now), "complete", Stamp(Now), Stamp(Now), Stamp(Now), Stamp(Now)))] : []);
    }

    private sealed class Reports(params HomeReport[] reports) : IHomeSummaryAccess
    {
        public Task<IReadOnlyList<HomeReport>> LoadAsync(Principal principal, CancellationToken ct) => Task.FromResult<IReadOnlyList<HomeReport>>(reports);
    }
    private static HomeReport Report(string key, string[]? fields = null, long[]? ids = null)
    {
        string accessKey = key switch { "security.problems" => "security.queue", "ad.infrastructure" => "ad.state", "vpn.connections" => "vpn.audit", _ => key };
        string[] required = key == "security.problems" ? ["security"] : key == "vpn.connections" ? [] : ["identity_basic", "security", "technical"];
        var grant = new AtomicReportGrant(JsonSerializer.SerializeToElement(new { kind = "domain", ids = ids ?? [7] }),
            (fields ?? ["security", "identity_basic", "technical", "privilege"]).ToHashSet(), new HashSet<string> { "view" }, 1, 1);
        return new HomeReport(new(key, accessKey, key == "vpn.connections" ? "delegated" : "domain", required.ToHashSet(), new HashSet<string>(), null, false),
            new(accessKey, true, [grant]), JsonSerializer.SerializeToElement(new { name = key }),
            JsonSerializer.SerializeToElement(new { pinned = true, updated_at = "2026-11-01" }))
        { Capabilities = new(false, new HashSet<string> { "vpn.sessions.view" }, new HashSet<string>(), [], new Dictionary<string, JsonElement>()) };
    }

    private sealed class Rows(bool populated = true) : IHomeSummaryRepository
    {
        public List<(string Sql, IReadOnlyDictionary<string, object?> Parameters)> Calls { get; } = [];
        public bool Fail { get; set; }
        public Func<string, bool>? FailPeriodRead { get; set; }
        public bool Active { get; set; } = true;
        public bool HasGroups { get; set; } = true;
        public JsonObject[]? ProblemCounts { get; set; }
        public JsonObject? ProblemRow { get; set; }
        public bool SidGroups { get; set; }
        public JsonObject? ComputerSnapshot { get; set; }
        public JsonObject[] LinkAgents { get; set; } = [];
        public bool LinkFail { get; set; }
        public AgentLinkHistory Links { get; } = new();
        public long VpnPreviousCount { get; set; } = 5;
        public Task<IReadOnlyList<JsonObject>> ReadAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct)
        {
            if (FailPeriodRead?.Invoke(sql) == true)
                return Task.FromException<IReadOnlyList<JsonObject>>(new TimeoutException("synthetic read failure"));
            Calls.Add((sql, parameters));
            if (Fail) throw new InvalidOperationException("private-database-identity");
            JsonObject Row(object value) => JsonSerializer.SerializeToNode(value)!.AsObject();
            IReadOnlyList<JsonObject> result = [];
            if (!populated)
            {
                if (sql.Contains("required_sections")) result = ((string)parameters["sections"]!).Split(',').Select(section => Row(new {
                    domain_id = 7, domain_name = "synthetic.example", section_name = section, run_status = (string?)null, section_status = (string?)null, observed_at_utc = (string?)null })).ToArray();
                return Task.FromResult(result);
            }
            if (sql.Contains("from sli_agents a"))
            {
                if (LinkFail) throw new InvalidOperationException("private-agent-database-error");
                result = LinkAgents;
            }
            else if (sql.Contains("previous_login_at")) result = [Row(new { previous_login_at = Stamp(Now.AddDays(-2)) })];
            else if (sql.Contains("runtime_worker_heartbeats")) result = Active ? [Row(new { status = "running", heartbeat_at = Stamp(Now), expected_interval_seconds = 30,
                details_json = new { runtime_mode = "findings-v1", manual_runtime = false } })] : [];
            else if (sql.Contains("population as materialized")) result = !HasGroups || !populated ? [] : [Row(new {
                rule_code = "synthetic-rule", title = "Synthetic problem", importance = 1, total = 11, new_count = 3,
                last_seen_utc = Stamp(Now), assigned_to = "synthetic-owner", unassigned_count = 2,
                total_problems = 20, total_new = 4, total_groups = 20, cohort = new object[] { "finding", 41 },
                object_names = SidGroups ? new[] { "S-1-5-21-100000001-200000002-300000003-1001", "S-1-5-21-100000001-200000002-300000003-1002" } : new[] { "synthetic-target" }, domain_name = "synthetic.example", representative = new { id = 41 }, day = (string?)null })];
            else if (sql.Contains("as label")) result = parameters.ContainsKey("requests")
                ? [Row(new { request_index=0, label="fixture-one", witness_verified=true, entity_id=14, source_run_id="synthetic-run", observed_at_utc=Stamp(Now) }),Row(new { request_index=1,label="fixture-two", witness_verified=true, entity_id=15, source_run_id="synthetic-run", observed_at_utc=Stamp(Now) })]
                : [Row(new { label="fixture-one" })];
            else if (sql.Contains("read_password_detection_coverage")) result = [Row(new { coverage = new { availability = "observed", has_more = false,
                rows = new[] { new { policy_state = "enabled", frozen_episode_count = "0", status = "healthy" } } } })];
            else if (sql.Contains("findings.severity") && sql.Contains("group by")) result = ProblemCounts ?? [Row(new { severity = "high", status = "new", count = 11 })];
            else if (sql.Contains("select findings.id")) result = [ProblemRow ?? Row(new { id = 41, rule_code = "synthetic-rule", title = "Synthetic problem", summary = "Observed synthetic activity",
                why_it_matters = "Synthetic reason", recommended_action = "Review synthetic object", severity = "high", status = "new", repeat_count = 2,
                last_seen_utc = Stamp(Now), published_at_utc = Stamp(Now), target = "synthetic-target", assigned_to = "synthetic-owner" })];
            else if (sql.Contains("required_sections")) result = ((string)parameters["sections"]!).Split(',').Select(section => Row(new {
                domain_id = 7, domain_name = "synthetic.example", section_name = section, run_status = "completed", section_status = "complete", observed_at_utc = Stamp(Now) })).ToArray();
            else if (sql.Contains("from entities_v2_active"))
            {
                if ((string)parameters["sections"]! == "directory_accounts") result = [Row(new { entity_id = 11, domain_id = 7, entity_type = "ad_computer", display_name = "synthetic-pc",
                    source_section = "directory_accounts", observed_at_utc = Stamp(Now), attributes = new { identity = new { object_guid = "00000000-0000-4000-8000-000000000001" }, attributes = new { enabled = true, operating_system = "Windows 10 Pro", operating_system_version = "10.0 (19045)",
                        last_logon_utc = Stamp(Now.AddDays(-120)) } } })];
                else result = [Row(new { entity_id = 12, domain_id = 7, domain_name = "synthetic.example", entity_type = "domain", display_name = "synthetic.example",
                    source_section = "domain_posture", observed_at_utc = Stamp(Now), attributes = new { attributes = new { ldap_signing_requirement = "not_required", ldap_channel_binding_requirement = "always", machine_account_quota = 10 } } })];
            }
            else if (sql.Contains("from computers_v6_source_snapshots")) result = ComputerSnapshot is null ? [] : [ComputerSnapshot.DeepClone().AsObject()];
            else if (sql.Contains("from ad_context_relation_versions")) result = [Row(new { current_count = 3, previous_count = 2 })];
            else if (sql.Contains("min(run.observed_at_utc) as history_from")) result = [Row(new { domain_id = 7, history_from = Stamp(Now.AddDays(-20)), observed_at_utc = Stamp(Now) })];
            else if (sql.Contains("read_plugin_states_v1")) result = [Row(new { enabled = true })];
            else if (sql.Contains("radius_vpn_session_coverage_v1")) result = [Row(new { total_delivery_count = 10, projected_session_count = 10,
                history_available_from_utc = Stamp(Now.AddDays(-10)), history_available_to_utc = Stamp(Now) })];
            else if (sql.Contains("radius_vpn_session_rows_v1")) result = [Row(new { current_count = 7, previous_count = VpnPreviousCount })];
            return Task.FromResult(result);
        }
    }

    [Fact]
    public async Task SecurityOnlyCompactQueueKeepsDomainTimeAndFieldPolicyWithoutReadingCases()
    {
        var rows = new Rows { ProblemRow = JsonNode.Parse("""
            {"id":7,"rule_code":"semantic.qw.password-brute-force","title":"Synthetic summary","summary":"Synthetic observation","severity":"high","status":"new",
             "actor":"identity-marker","target":"identity-marker","assigned_to":"identity-marker",
             "source":"technical-marker","status_reason":"exact-marker","unknown_future_field":"future-marker",
             "presentation_facts":{"account":"identity-marker","source":"technical-marker","count":12,"time":"2026-10-01T12:00:00Z"},
             "evidence":[{"event_db_id":900001,"note":"exact-marker"}],"linked_case":{"id":44,"public_id":"case-marker"}}
            """)!.AsObject() };
        var (status, body) = await Request("?contract=v2&domain_id=7&period=custom&from=2026-10-01T00:00:00Z&to=2026-10-02T00:00:00Z",
            rows, true, Report("security.problems", ["security"]));
        Assert.Equal(200, status); Assert.DoesNotContain("Synthetic summary", body.ToJsonString());
        foreach (string marker in new[] { "identity-marker", "exact-marker", "technical-marker", "future-marker", "case-marker", "900001" }) Assert.DoesNotContain(marker, body.ToJsonString());
        Assert.DoesNotContain("linked_case", body.ToJsonString());
        var problem = Assert.Single(body["action_queue"]!["items"]!.AsArray(), item => (string?)item?["id"] == "problem:7")!;
        Assert.Equal("password_brute", (string?)problem["presentation_code"]);
        Assert.Equal("Подбор пароля к учётной записи", (string?)problem["title"]);
        Assert.Contains("12", (string?)problem["what"]);
        var read = rows.Calls.First(c => c.Sql.Contains("select findings.id"));
        Assert.Equal(new long[] { 7 }, read.Parameters["ids"]);
        Assert.Equal(DateTimeOffset.Parse("2026-10-01T00:00:00Z"), read.Parameters["from"]);
        Assert.Equal(DateTimeOffset.Parse("2026-10-02T00:00:00Z"), read.Parameters["to"]);
        Assert.Contains("('new','confirmed','repeated')", read.Sql);
        // Password wording reads aggregate event facts; cases and status history are still not loaded.
        Assert.DoesNotContain(rows.Calls, c => c.Sql.Contains("investigation") || c.Sql.Contains("finding_status_history"));
    }

    [Theory]
    [InlineData("v4", true)]
    [InlineData("v5", true)]
    [InlineData("v5", false)]
    public async Task HomeWithoutDomainsMeasuresAnEmptyQueueWithGlobalAccess(string contract, bool globalAccess)
    {
        var queue = Report("security.problems");
        if (globalAccess)
        {
            var grant = queue.Decision.Grants[0] with { Scope = JsonSerializer.SerializeToElement(new { kind = "all" }) };
            queue = queue with { Decision = queue.Decision with { Grants = [grant] } };
        }
        var rows = new Rows(populated: false);
        var (status, body) = await Request("?contract=" + contract, rows, false, queue);
        Assert.Equal(200, status);
        Assert.Null(body["domain_id"]);
        Assert.Empty(body["domains"]!.AsArray());
        var problems = Assert.IsType<JsonObject>(body["problems"]);
        int? expectedCount = globalAccess ? 0 : null;
        Assert.Equal(expectedCount, (int?)problems["open_count"]);
        Assert.Equal(expectedCount, (int?)problems["hygiene"]);
        Assert.Equal(expectedCount, (int?)problems["other"]);
        Assert.Empty(problems["items"]!.AsArray());
        Assert.Empty(rows.Calls);
    }

    private static async Task<(int Status, JsonObject Body)> Request(string query, Rows rows, bool populated = true, params HomeReport[] reports) =>
        await RequestWithArchive(query, rows, populated, false, reports);

    private static async Task<(int Status, JsonObject Body)> RequestWithArchive(string query, Rows rows, bool populated, bool archived, params HomeReport[] reports)
    {
        var config = new ConfigurationBuilder().Build();
        using var services = new ServiceCollection().AddLogging().AddSingleton(new TransportGate(config))
            .AddSingleton<IPrincipalAuthenticator>(new Authentication()).AddSingleton<IDomainAccessService>(new Access(true))
            .AddSingleton<IHomeSummaryAccess>(new Reports(reports.Length > 0 ? reports : [Report("security.problems"), Report("ad.infrastructure"), Report("ad.computers.v6"), Report("vpn.connections")]))
            .AddSingleton<IDomainRepository>(new Domains(populated, archived)).AddSingleton<IHomeSummaryRepository>(rows)
            .AddSingleton<TimeProvider>(new Clock())
            .AddSingleton(rows.Links).AddSingleton<HomeSummaryReaders>().AddSingleton<HomeSummaryService>().BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Path = "/api/v1/home/summary"; context.Request.QueryString = new QueryString(query); context.Response.Body = new MemoryStream();
        await HomeSummaryEndpoints.HandleAsync(context);
        return (context.Response.StatusCode, JsonNode.Parse(((MemoryStream)context.Response.Body).ToArray())!.AsObject());
    }

    [Theory]
    [InlineData("v1")]
    [InlineData("v2")]
    [InlineData("v3")]
    public async Task ArchivedDomainDoesNotHideSecurityFindingsInSharedHomeResolver(string contract)
    {
        var rows = new Rows();
        var (status, body) = await RequestWithArchive("?contract=" + contract, rows, true, true, Report("security.problems"));
        Assert.Equal(200, status);
        Assert.NotEqual("denied", (string?)body["state"]);
        var findingReads = rows.Calls.Where(c => c.Sql.Contains("findings", StringComparison.Ordinal) && c.Parameters.ContainsKey("ids")).ToArray();
        Assert.NotEmpty(findingReads);
        Assert.All(findingReads, c => Assert.Equal(new long[] { 7 }, Assert.IsType<long[]>(c.Parameters["ids"])));
        if (contract == "v3") Assert.NotEmpty(body["groups"]!.AsArray());
        else
        {
            var selected = Assert.Single(body["domains"]!.AsArray())!;
            Assert.Equal(7, (long)selected["id"]!);
            Assert.True((bool)selected["is_archived"]!);
        }
    }

    [Theory]
    [InlineData(-1, "missing", "home.comparison.missing", null)]
    [InlineData(0, "comparable", "home.comparison.absolute", 7d)]
    [InlineData(5, "comparable", "home.comparison.percent", 2d)]
    public async Task V2_vpn_comparison_uses_valid_baselines(long previous, string state, string code, double? change)
    {
        var (status, body) = await Request("?contract=v2&scope=domain&domain=7", new Rows { VpnPreviousCount = previous });
        Assert.Equal(200, status);
        var comparison = body["kpis"]!.AsArray().Single(k => (string?)k!["key"] == "vpn_closed")!["comparison"]!;
        Assert.Equal(state, (string?)comparison["state"]);
        Assert.Equal(code, (string?)comparison["message_code"]);
        Assert.Equal(change, (double?)comparison["absolute_change"]);
        Assert.Equal(previous > 0 ? 40d : (double?)null, (double?)comparison["percent_change"]);
        Assert.Equal("neutral", (string?)comparison["tone"]);
    }

    [Fact] public async Task V3_resolves_retained_sid_labels_in_one_batch_like_reference()
    {
        var rows=new Rows { SidGroups=true };
        var (status,body)=await Request("?contract=v3&domain_id=7",rows);
        Assert.Equal(200,status);
        Assert.Equal(2,body["groups"]![0]!["objects"]!.AsArray().Count);
        Assert.All(body["groups"]![0]!["objects"]!.AsArray(),o=>Assert.Equal("named",(string?)o!["name_state"]));
        Assert.Single(rows.Calls,c=>c.Sql.Contains("as label"));
    }

    [Fact]
    public void RepeatedContactGapsRemainVisibleAfterRecoveryAndExpireAfterOneHour()
    {
        var history = new AgentLinkHistory(); var id = Guid.NewGuid();
        var start = Now.AddMinutes(-30);
        history.Contact(id, null, start, 60, true);
        // Each gap misses one signal after a grace of three usual intervals.
        for (int i = 1; i <= 3; i++) history.Contact(id, start.AddMinutes((i - 1) * 4), start.AddMinutes(i * 4), 60, true);
        history.Contact(id, start.AddMinutes(12), Now, 60, true);
        Assert.Equal(Now, history.Check(id, Now, 60, Now.AddHours(-1), Now));
        for (int i = 1; i <= 61; i++) history.Contact(id, Now.AddMinutes(i - 1), Now.AddMinutes(i), 60, true);
        var later = Now.AddMinutes(61);
        Assert.Null(history.Check(id, later, 60, later.AddHours(-1), later));
    }

    [Fact]
    public void RecoveredShortGapsAccumulateWithoutDependingOnLatestContactAge()
    {
        var history = new AgentLinkHistory(); var id = Guid.NewGuid();
        var start = Now.AddMinutes(-12);
        for (int i = 1; i <= 3; i++) history.Contact(id, start.AddMinutes((i - 1) * 4), start.AddMinutes(i * 4), 60, true);
        Assert.Equal(Now, history.Check(id, Now, 60, Now.AddHours(-1), Now));
        Assert.Null(history.Check(Guid.NewGuid(), Now, 60, Now.AddHours(-1), Now));
    }

    [Theory]
    [InlineData(60, 180, false)]
    [InlineData(60, 240, false)]
    [InlineData(60, 360, true)]
    [InlineData(600, 360, false)]
    [InlineData(600, 3600, true)]
    public void MissingContactsUseUsualCadenceIncludingAfterServerRestart(long interval, int age, bool warning)
    {
        var history = new AgentLinkHistory();
        Assert.Equal(warning, history.Check(Guid.NewGuid(), Now.AddSeconds(-age), interval, Now.AddHours(-1), Now) is not null);
    }

    [Fact]
    public void RegularContactsJitterAndPolicyChangesDoNotAccumulateFalseGaps()
    {
        var history = new AgentLinkHistory(); var id = Guid.NewGuid();
        for (int i = 20; i >= 0; i--) history.Contact(id, Now.AddMinutes(-i - 1), Now.AddMinutes(-i), 60, true);
        Assert.Null(history.Check(id, Now, 60, Now.AddHours(-1), Now));
        history.Contact(id, Now, Now.AddMinutes(4), 60, true);
        history.Contact(id, Now.AddMinutes(4), Now.AddMinutes(8), 60, true);
        history.Contact(id, Now.AddMinutes(8), Now.AddMinutes(12), 60, false);
        history.Contact(id, Now.AddMinutes(12), Now.AddMinutes(16), 60, true);
        Assert.Null(history.Check(id, Now.AddMinutes(16), 60, Now.AddMinutes(-44), Now.AddMinutes(16)));
        history.Contact(id, Now.AddMinutes(16), Now.AddMinutes(22), 60, true);
        history.Contact(id, Now.AddMinutes(22), Now.AddMinutes(23), 600, true);
        Assert.Null(history.Check(id, Now.AddMinutes(23), 600, Now.AddMinutes(-37), Now.AddMinutes(23)));
    }

    [Fact]
    public async Task AgentLinkWarningIsScopedCountsAgentsOnceAndDoesNotLeakIdentities()
    {
        JsonObject Agent(int minutes) => new() { ["id"] = Guid.NewGuid().ToString(), ["last_seen"] = Stamp(Now.AddMinutes(-minutes)),
            ["created_at"] = Stamp(Now.AddDays(-1)), ["collection_policy"] = new JsonObject { ["interval_seconds"] = 60 } };
        var rows = new Rows { LinkAgents = [Agent(12), Agent(7), Agent(1)] };
        var (status, body) = await Request("?contract=v3&domain_id=7", rows);
        Assert.Equal(200, status);
        var warning = body["agent_link_warning"]!;
        Assert.Equal(2, (int?)warning["agent_count"]);
        Assert.Equal("home.queue.warning.agent_link_unstable", (string?)warning["reason_code"]);
        Assert.NotNull(warning["observed_at_utc"]); Assert.NotNull(warning["window_from_utc"]); Assert.NotNull(warning["window_to_utc"]);
        Assert.DoesNotContain((string)rows.LinkAgents[0]["id"]!, warning.ToJsonString());
        var call = rows.Calls.Single(c => c.Sql.Contains("from sli_agents a"));
        Assert.Equal(new long[] { 7 }, (long[])call.Parameters["ids"]!);
        Assert.Equal(false, call.Parameters["all_agents"]);
        Assert.Contains("d.id=any(@ids)", call.Sql); Assert.Contains("a.status='active'", call.Sql);
        Assert.Contains("applied_collection_state='active'", call.Sql);
        Assert.Contains("a.policy_revision=a.applied_policy_revision", call.Sql);
        Assert.Contains("t.domain_id=d.id", call.Sql);
    }

    [Fact]
    public async Task RecoveredAgentStillWarnsOnHomeWhenLastSeenIsCurrent()
    {
        var id = Guid.NewGuid(); var rows = new Rows { LinkAgents = [new JsonObject {
            ["id"] = id.ToString(), ["last_seen"] = Stamp(Now), ["created_at"] = Stamp(Now.AddDays(-1)),
            ["collection_policy"] = new JsonObject { ["interval_seconds"] = 60 } }] };
        for (int i = 3; i > 0; i--) rows.Links.Contact(id, Now.AddMinutes(-i * 4), Now.AddMinutes(-(i - 1) * 4), 60, true);
        var (_, body) = await Request("?contract=v3&domain_id=7", rows);
        Assert.Equal(1, (int?)body["agent_link_warning"]?["agent_count"]);
    }

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(true, false, true)]
    [InlineData(true, true, false)]
    public async Task UnboundAgentsRequireGlobalTechnicalGrantAndNoSelectedDomain(bool technicalAll, bool selected, bool expected)
    {
        var report = Report("security.problems");
        var scoped = report.Decision.Grants[0];
        var global = scoped with { Scope = JsonSerializer.SerializeToElement(new { kind = "all" }),
            FieldCategories = (technicalAll ? new[] { "security", "technical" } : new[] { "security" }).ToHashSet() };
        report = report with { Decision = report.Decision with { Grants = [global, scoped] } };
        var rows = new Rows();
        await Request("?contract=v3" + (selected ? "&domain_id=7" : ""), rows, true, report);
        Assert.Equal(expected, rows.Calls.Single(c => c.Sql.Contains("from sli_agents a")).Parameters["all_agents"]);
    }

    [Fact]
    public async Task AgentLinkReadFailureIsHonestAndIndependentOfQueueAvailability()
    {
        var (status, body) = await Request("?contract=v3", new Rows { LinkFail = true });
        Assert.Equal(200, status); Assert.Equal("ok", (string?)body["state"]);
        Assert.Equal("home.queue.warning.agent_link_unknown", (string?)body["agent_link_warning"]?["reason_code"]);
        Assert.DoesNotContain("private-agent-database-error", body.ToJsonString());
        var rows = new Rows();
        (_, body) = await Request("?contract=v3", rows, true, Report("security.problems", ["security"]));
        Assert.Null(body["agent_link_warning"]); Assert.DoesNotContain(rows.Calls, c => c.Sql.Contains("from sli_agents a"));
    }
    [Fact]
    public async Task PopulatedV2ProjectsMetricsAttentionFreshnessContributionsAndDomainSummary()
    {
        var rows = new Rows();
        var (status, body) = await Request("?contract=v2&domain_id=7", rows);
        Assert.Equal(200, status); Assert.Equal("sli.home-summary.v2", (string?)body["contract_id"]);
        Assert.Equal(11, (int?)body["problems_found"]?["count"]);
        Assert.Equal(4, body["kpis"]!.AsArray().Count); Assert.Equal(5, body["readers"]!.AsArray().Count);
        var kpis = body["kpis"]!.AsArray();
        Assert.Equal(1, (int?)kpis.Single(k => (string?)k?["key"] == "ad_failed")?["value"]);
        Assert.Equal(3, (int?)kpis.Single(k => (string?)k?["key"] == "privileged_changes")?["value"]);
        var vpn = kpis.Single(k => (string?)k?["key"] == "vpn_closed");
        Assert.Equal(7, (int?)vpn?["value"]); Assert.Equal("comparable", (string?)vpn?["comparison"]?["state"]);
        var computer = body["metrics"]!.AsArray().Single(m => (string?)m?["report_key"] == "ad.computers.v6");
        Assert.Equal(1, (int?)computer?["items"]?.AsArray().Single(m => (string?)m?["key"] == "total")?["value"]);
        Assert.Equal(1, (int?)computer?["items"]?.AsArray().Single(m => (string?)m?["key"] == "attention")?["value"]);
        Assert.Equal("problem:41", (string?)body["action_queue"]?["items"]?[0]?["id"]);
        Assert.Contains("domain=7", (string?)body["action_queue"]?["items"]?[0]?["href"]);
        Assert.Equal(11, (int?)body["domains"]?[0]?["summary"]?["problems_found"]?["count"]);
        Assert.All(rows.Calls.Where(c => c.Parameters.ContainsKey("ids")), c => Assert.Equal(new long[] { 7 }, (long[])c.Parameters["ids"]!));
        var sql = rows.Calls.First(c => c.Sql.Contains("select findings.id")).Sql;
        Assert.Contains("is_semantic_finding_published_v1", sql);
        Assert.Contains($"and not ({ProblemRepository.Suppressed})", sql);
        Assert.Contains("then semantic_finding_suppressed_v160(findings.id,findings.rule_code)", sql);
        Assert.Contains("not coalesce(risk.state='active'", sql); Assert.Contains("semantic_finding_in_domains_v265", sql);
    }

    [Fact]
    public async Task PopulatedV3UsesExactQueueGroupsCountsAndRemainders()
    {
        var rows = new Rows(); var (status, body) = await Request("?contract=v3&domain_id=7", rows);
        Assert.Equal(200, status); Assert.Equal("sli.home-summary.v3", (string?)body["contract_id"]);
        Assert.Equal("ok", (string?)body["state"]); Assert.Equal(20, (int?)body["total"]);
        Assert.Equal(4, (int?)body["new_count"]);
        var groups = body["groups"]!.AsArray();
        int remaining = body["total"]!.GetValue<int>() - groups.Count;
        Assert.Equal(remaining, body["remaining_groups"]!.GetValue<int>());
        Assert.Equal(remaining, body["remaining_problems"]!.GetValue<int>());
        var group = Assert.Single(groups);
        Assert.Equal(11, group!["total"]!.GetValue<int>());
        Assert.Equal("mixed", (string?)group["assignee_state"]);
        Assert.Equal("synthetic-target", (string?)group?["objects"]?[0]?["name"]);
        Assert.Contains("cohort=", (string?)group?["href"]); Assert.Empty(body["warnings"]!.AsArray());
        Assert.Null(body["kpis"]); Assert.DoesNotContain(rows.Calls, c => c.Sql.Contains("from entities_v2_active"));
    }

    [Theory]
    [InlineData("v2")]
    [InlineData("v3")]
    public async Task EmptyInstallationReturnsHonestContractWithoutReadingWholePopulation(string contract)
    {
        var rows = new Rows(false); var (status, body) = await Request("?contract=" + contract, rows, false);
        Assert.Equal(200, status); Assert.Equal("sli.home-summary." + contract, (string?)body["contract_id"]);
        Assert.Empty(rows.Calls);
        if (contract == "v2") { Assert.Empty(body["domains"]!.AsArray()); Assert.Equal("no_domains", (string?)body["domain_scope"]?["state"]); Assert.Null(body["problems_found"]?["count"]); }
        else { Assert.Empty(body["groups"]!.AsArray()); Assert.Null(body["total"]); Assert.Equal("denied", (string?)body["state"]); }
    }

    [Fact]
    public async Task MissingIdentityIsRedactedAndNeverUsedToGenerateCohortLink()
    {
        var rows = new Rows(); var report = Report("security.problems", ["security"]);
        var (status, body) = await Request("?contract=v3", rows, true, report);
        Assert.Equal(200, status); var group = body["groups"]![0];
        Assert.Empty(group!["objects"]!.AsArray()); Assert.Null(group["assigned_to"]); Assert.Equal("unknown", (string?)group["assignee_state"]);
        Assert.Null(group["object_count"]); Assert.DoesNotContain("cohort=", (string?)group["href"]);
        Assert.DoesNotContain("synthetic-target", body.ToJsonString()); Assert.DoesNotContain("synthetic-owner", body.ToJsonString());
        Assert.Equal(20, (int?)body["total"]);
    }

    [Theory]
    [InlineData("v2")]
    [InlineData("v3")]
    public async Task RegisteredDomainWithoutCollectedDataDoesNotClaimHealthyOrSafeZero(string contract)
    {
        var rows = new Rows(false); var (status, body) = await Request("?contract=" + contract + "&domain_id=7", rows);
        Assert.Equal(200, status);
        if (contract == "v3") { Assert.Equal("partial", (string?)body["state"]); Assert.Null(body["total"]); Assert.Null(body["new_count"]); }
        else
        {
            Assert.Equal("partial", (string?)body["problems_found"]?["state"]);
            Assert.NotEqual("ok", (string?)body["observation_health"]?["state"]);
            Assert.Contains(body["action_queue"]!["items"]!.AsArray(), i => (string?)i?["message_code"] == "home.attention.analysis_unconfirmed");
            Assert.Null(body["kpis"]!.AsArray().Single(k => (string?)k?["key"] == "privileged_changes")?["value"]);
        }
    }

    [Fact]
    public async Task SelectedDomainDoesNotEmitCohortThatFullScopeFieldGateWouldReject()
    {
        var report = Report("security.problems");
        var securityOnly = Report("security.problems", ["security"], [8]);
        report = report with { Decision = report.Decision with { Grants = report.Decision.Grants.Concat(securityOnly.Decision.Grants).ToArray() } };
        var rows = new Rows(); var (status, body) = await Request("?contract=v3&domain_id=7", rows, true, report);
        Assert.Equal(200, status); Assert.DoesNotContain("cohort=", (string?)body["groups"]?[0]?["href"]);
        Assert.Equal(20, (int?)body["total"]);
        Assert.Equal("synthetic-target", (string?)body["groups"]?[0]?["objects"]?[0]?["name"]);
    }

    [Fact]
    public async Task UnsupportedEntityScopeAndMissingQueueGrantDoNotReadOrBecomeDomainAuthority()
    {
        var report = Report("security.problems");
        var grant = report.Decision.Grants[0] with { Scope = JsonSerializer.SerializeToElement(new { mode = "restricted", clauses = new[] { new { entity_ids = new[] { 11 } } } }) };
        report = report with { Decision = report.Decision with { Grants = [grant] } };
        var rows = new Rows(); var (status, body) = await Request("?contract=v3&domain_id=7", rows, true, report);
        Assert.Equal(200, status); Assert.Equal("denied", (string?)body["state"]); Assert.Empty(rows.Calls);
        (status, body) = await Request("?contract=v3&domain_id=7", rows, true, Report("ad.infrastructure"));
        Assert.Equal(200, status); Assert.Equal("denied", (string?)body["state"]); Assert.Empty(rows.Calls);
    }

    [Theory]
    [InlineData("valid", 1)]
    [InlineData("bad_hash", 0)]
    [InlineData("bad_source_state", 0)]
    [InlineData("bad_schema", 0)]
    public async Task ComputerMetricsUseOnlyValidatedRetainedSnapshots(string mutation, int expectedServers)
    {
        using var stream = typeof(HomeSummaryEndpointTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Domains.home-computer-source.json")!;
        var payload = (await JsonNode.ParseAsync(stream, cancellationToken: TestContext.Current.CancellationToken))!.AsObject();
        var completed = Stamp(Now.AddMinutes(1));
        payload["metadata"]!["started_at"] = Stamp(Now); payload["metadata"]!["completed_at"] = completed;
        if (mutation == "bad_source_state") payload["objects"]![0]!["sources"]!["ad"]!["status"] = "unproven";
        if (mutation == "bad_schema") payload["schema_version"] = "99.0";
        var bytes = Encoding.UTF8.GetBytes(Sli.Agent.Protocol.CanonicalJson.Serialize(payload, ensureAscii: false));
        var rows = new Rows { ComputerSnapshot = new JsonObject { ["domain_id"] = 7, ["snapshot_uuid"] = payload["metadata"]!["snapshot_id"]!.DeepClone(),
            ["source_completed_at_utc"] = completed, ["collection_status"] = "complete", ["base_inventory_status"] = "observed", ["object_count"] = 1,
            ["payload_json"] = payload, ["payload_sha256"] = mutation == "bad_hash" ? new string('0', 64) : Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes)) } };
        var (status, body) = await Request("?contract=v2", rows);
        Assert.Equal(200, status);
        var computer = body["metrics"]!.AsArray().Single(m => (string?)m?["report_key"] == "ad.computers.v6");
        Assert.Equal(expectedServers, (int?)computer?["items"]?.AsArray().Single(m => (string?)m?["key"] == "srv")?["value"]);
        var sourceRead = Assert.Single(rows.Calls, c => c.Sql.Contains("from computers_v6_source_snapshots"));
        Assert.Contains("order by source_completed_at_utc desc,source_snapshot_id desc limit 1", sourceRead.Sql);
        Assert.Equal(new long[] { 7 }, Assert.IsType<long[]>(sourceRead.Parameters["ids"]));
    }

    [Fact]
    public async Task PartialEmptyQueueIsUnknownWhileConfirmedEmptyIsZero()
    {
        var rows = new Rows { HasGroups = false };
        var (_, confirmed) = await Request("?contract=v3", rows); Assert.Equal(0, (int?)confirmed["total"]); Assert.Equal("empty", (string?)confirmed["state"]);
        rows.Active = false;
        var (_, uncertain) = await Request("?contract=v3", rows); Assert.Null(uncertain["total"]); Assert.Equal("partial", (string?)uncertain["state"]);
        Assert.Single(uncertain["warnings"]!.AsArray());
    }

    [Theory]
    [InlineData("?contract=v9", "home_contract_invalid")]
    [InlineData("?contract=v2&x=1", "home_parameter_unknown")]
    [InlineData("?contract=v2&tz=Bad/Zone", "home_timezone_invalid")]
    [InlineData("?contract=v2&scope=domain", "home_scope_invalid")]
    [InlineData("?contract=v2&domain_id=0", "domain_scope_invalid")]
    [InlineData("?contract=v2&domain_id=7&scope=domain", "domain_scope_invalid")]
    [InlineData("?contract=v2&tz=UTC&tz=UTC", "home_parameter_invalid")]
    [InlineData("?contract=v2&period=custom&from=2026-10-10&to=2026-10-01", "report_period_invalid")]
    public async Task InvalidQueryDoesNotRead(string query, string code)
    {
        var rows = new Rows(); var (status, body) = await Request(query, rows);
        Assert.Equal(400, status); Assert.Equal("home_parameters_invalid", (string?)body["error"]); Assert.Empty(rows.Calls);
        var context = new DefaultHttpContext(); context.Request.QueryString = new QueryString(query);
        Assert.Equal(code, Assert.Throws<HomeQueryException>(() => HomeSummaryQuery.Parse(context.Request.Query, Now)).Message);
    }

    [Theory]
    [InlineData("v2")]
    [InlineData("v3")]
    public async Task DeniedDomainNeverReads(string contract)
    {
        var rows = new Rows(); var (status, body) = await Request("?contract=" + contract + "&domain_id=8", rows);
        Assert.Equal(403, status); Assert.Equal("domain_scope_denied", (string?)body["error"]); Assert.Empty(rows.Calls);
    }

    [Theory]
    [InlineData("v2")]
    [InlineData("v3")]
    public async Task ReaderFailureReturnsUnknownWithoutDisclosingDatabaseException(string contract)
    {
        var rows = new Rows { Fail = true }; var (status, body) = await Request("?contract=" + contract, rows);
        Assert.Equal(200, status); Assert.DoesNotContain("private-database-identity", body.ToJsonString());
        if (contract == "v3") { Assert.Equal("error", (string?)body["state"]); Assert.Null(body["total"]); }
        else { Assert.Equal("error", (string?)body["problems_found"]?["state"]); Assert.Null(body["problems_found"]?["count"]); }
    }

    [Fact]
    public void CalendarCustomPeriodAndCompletedDaysKeepTimezoneAndExclusiveEnd()
    {
        var context = new DefaultHttpContext(); context.Request.QueryString = new QueryString("?contract=v2&period=custom&from=2026-10-01&to=2026-10-01&tz=Asia/Bangkok");
        var query = HomeSummaryQuery.Parse(context.Request.Query, Now);
        Assert.Equal(DateTimeOffset.Parse("2026-09-30T17:00:00Z"), query.Period!.From);
        Assert.Equal(DateTimeOffset.Parse("2026-10-01T17:00:00Z"), query.Period.To);
        Assert.Equal(query.Current.From, query.Previous.To);
        context.Request.QueryString = new QueryString("?contract=v2&tz=America/New_York");
        query = HomeSummaryQuery.Parse(context.Request.Query, DateTimeOffset.Parse("2026-11-02T12:00:00Z"));
        Assert.Equal(TimeSpan.FromHours(25), query.Current.To - query.Current.From);
        Assert.Equal(TimeSpan.FromHours(24), query.Previous.To - query.Previous.From);
    }
}
