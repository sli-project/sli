using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Sli.Server.Access;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Vpn;

// Parity vectors from tests/reporting/test_vpn_default_domain.py.
public sealed class VpnDefaultDomainTests
{
    const string Report = "vpn.connections";
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static JsonObject Json(object value) => VpnRouteTests.Json(value);

    sealed class Store : IVpnStore, IVpnReadSession
    {
        readonly VpnRouteTests.Store fallback = new();
        public List<JsonObject> Domains =
        [
            Json(new { id = 1, fqdn = "archive.example.test", is_archived = true, observed_at_utc = DateTimeOffset.UtcNow.AddHours(-1) }),
            Json(new { id = 2, fqdn = "live.example.test", is_archived = false, observed_at_utc = DateTimeOffset.UtcNow.AddDays(-1) })
        ];
        public long[] SourceOptions = [1, 2];
        public string Preferred = "archive.example.test";
        public Exception? MetadataFailure;
        public readonly List<long[]> MetadataReads = [];
        public readonly List<(string Sql, object?[] Values)> Calls = [];
        public Task<IVpnReadSession> OpenAsync(CancellationToken ct) => Task.FromResult<IVpnReadSession>(this);
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public Task<List<JsonObject>> ReadAsync(string sql, object?[] values, CancellationToken ct)
        {
            Calls.Add((sql, values));
            if (sql == "select id,fqdn from domains order by id limit 10001")
                return Task.FromResult(Domains.Where(r => SourceOptions.Contains(r["id"]!.GetValue<int>())).Select(r => (JsonObject)r.DeepClone()).ToList());
            if (sql.StartsWith("select value from platform_settings", StringComparison.Ordinal))
                return Task.FromResult(new List<JsonObject> { Json(new { value = Preferred }) });
            if (sql.Contains("select d.id,d.fqdn,d.is_archived", StringComparison.Ordinal))
            {
                var ids = Assert.IsType<long[]>(Assert.Single(values));
                MetadataReads.Add(ids);
                if (MetadataFailure is not null) throw MetadataFailure;
                return Task.FromResult(Domains.Where(r => ids.Contains(r["id"]!.GetValue<int>())).Select(r => (JsonObject)r.DeepClone()).ToList());
            }
            return fallback.ReadAsync(sql, values, ct);
        }
    }

    // The beta HTTP route denies the retired module before any storage read.
    // Exercise the retained recommendation and reader contracts directly.
    static async Task<(long? Id, string State, List<JsonObject> Options)> Recommendation(Store store, AccessFacts? facts = null)
    {
        var access = new VpnAccess(facts ?? VpnRouteTests.MakeFacts());
        var options = await VpnReports.DomainOptions(store, access, Ct);
        var (id, state) = await VpnReports.DefaultDomain(store, access, options, Ct);
        return (id, state, options);
    }

    static Task<JsonObject> Data(Store store, string query) =>
        VpnReports.Read(store, new VpnAccess(VpnRouteTests.MakeFacts()), Report,
            new QueryCollection(QueryHelpers.ParseQuery(query)), "view", Ct);

    [Fact]
    public async Task Declaration_prefers_live_observed_domain_without_removing_archive_option()
    {
        var recommendation = await Recommendation(new Store());
        Assert.Equal(2L, recommendation.Id);
        Assert.Equal("available", recommendation.State);
        Assert.Equal(new[] { "1", "2" }, recommendation.Options.Select(r => r["value"]!.ToString()));
    }

    [Fact]
    public async Task Default_does_not_escape_source_options()
    {
        var recommendation = await Recommendation(new Store { SourceOptions = [1] });
        Assert.Null(recommendation.Id);
        Assert.Equal("unknown", recommendation.State);
    }

    [Theory]
    [InlineData("archive_only")]
    [InlineData("unknown")]
    [InlineData("future")]
    public async Task No_fallback_to_archive_or_unobserved_domain(string kind)
    {
        var store = new Store();
        if (kind == "archive_only") store.Domains.RemoveAt(1);
        else store.Domains[1]["observed_at_utc"] = kind == "unknown" ? null : JsonValue.Create(DateTimeOffset.UtcNow.AddDays(1));
        var recommendation = await Recommendation(store);
        Assert.Null(recommendation.Id);
        Assert.Equal("unknown", recommendation.State);
        var error = await Assert.ThrowsAsync<VpnInputException>(() => Data(store, "period=7d"));
        Assert.Equal("report_parameter_required:domain", error.Message);
        Assert.DoesNotContain(store.Calls, c => c.Sql == VpnSql.Coverage || c.Sql == VpnSql.ConnectionSessions);
    }

    [Fact]
    public async Task Direct_missing_domain_uses_same_default_and_preserves_period()
    {
        var store = new Store();
        var recommendation = await Recommendation(store);
        var response = await Data(store, "period=7d");
        Assert.Equal(recommendation.Id, response["window"]!["source_domain_id"]!.GetValue<long>());
        var call = Assert.Single(store.Calls, c => c.Sql == VpnSql.ConnectionSessions);
        Assert.Equal(2L, call.Values[0]);
        Assert.Equal(TimeSpan.FromDays(7), Assert.IsType<DateTimeOffset>(call.Values[1]) - Assert.IsType<DateTimeOffset>(call.Values[2]));
    }

    [Fact]
    public async Task Explicit_archive_preserves_custom_period_without_default_lookup()
    {
        var store = new Store { MetadataFailure = new InvalidOperationException("explicit selection needs no default") };
        await Data(store, "domain=1&period=custom&from=2026-01-01&to=2026-01-07");
        Assert.Empty(store.MetadataReads);
        Assert.DoesNotContain(store.Calls, c => c.Sql.StartsWith("select value from platform_settings", StringComparison.Ordinal));
        var call = Assert.Single(store.Calls, c => c.Sql == VpnSql.ConnectionSessions);
        Assert.Equal(1L, call.Values[0]);
        Assert.Equal(DateTimeOffset.Parse("2026-01-01T00:00:00Z"), call.Values[2]);
        Assert.Equal(DateTimeOffset.Parse("2026-01-08T00:00:00Z"), call.Values[1]);
    }

    [Theory]
    [InlineData("metadata")]
    [InlineData("postgres")]
    [InlineData("timeout")]
    public async Task Metadata_failure_has_no_invented_default(string kind)
    {
        var store = new Store { MetadataFailure = kind switch
        {
            "postgres" => new Npgsql.NpgsqlException("synthetic metadata unavailable"),
            "timeout" => new TimeoutException("synthetic metadata unavailable"),
            _ => new InvalidOperationException("synthetic metadata unavailable")
        } };
        var recommendation = await Recommendation(store);
        Assert.Null(recommendation.Id);
        Assert.Equal("unavailable", recommendation.State);
        var error = await Assert.ThrowsAsync<VpnInputException>(() => Data(store, "period=7d"));
        Assert.Equal("report_parameter_required:domain", error.Message);
        Assert.DoesNotContain(store.Calls, c => c.Sql == VpnSql.Coverage || c.Sql == VpnSql.ConnectionSessions);
    }

    [Fact]
    public async Task Recommendation_is_limited_to_report_authorized_domains()
    {
        var facts = VpnRouteTests.MakeFacts(false) with
        {
            DirectCapabilities = [JsonSerializer.SerializeToElement(new { capability_key = "events.view", effect = "allow", scope_json = new { kind = "all" } })],
            ReportAssignments = [JsonSerializer.SerializeToElement(new { report_key = "vpn.audit", effect = "allow", allowed_actions = new[] { "view" }, field_categories = Array.Empty<string>(), scope_json = new { kind = "domain", ids = new[] { 1 } } })]
        };
        var store = new Store();
        var recommendation = await Recommendation(store, facts);
        Assert.Equal(new long[] { 1 }, Assert.Single(store.MetadataReads));
        Assert.Null(recommendation.Id);
        Assert.Equal("unknown", recommendation.State);
    }

    [Fact]
    public async Task Saved_live_preference_does_not_require_new_observation()
    {
        var store = new Store { Preferred = "live.example.test" };
        store.Domains[1]["observed_at_utc"] = null;
        var recommendation = await Recommendation(store);
        Assert.Equal(2L, recommendation.Id);
        Assert.Equal("available", recommendation.State);
    }

    [Theory]
    [InlineData("domain_id=1&period=7d", 1)]
    [InlineData("domain=1&domain_id=1&period=7d", 1)]
    [InlineData("domain=1&domain_id=2", 0)]
    [InlineData("scope=all&period=7d", 0)]
    public async Task Direct_route_preserves_alias_or_rejects_conflicting_or_all_scope(string query, int expected)
    {
        var store = new Store();
        if (expected > 0)
        {
            await Data(store, query);
            Assert.Equal((long)expected, Assert.Single(store.Calls, c => c.Sql == VpnSql.ConnectionSessions).Values[0]);
            Assert.Empty(store.MetadataReads);
        }
        else
        {
            var error = await Assert.ThrowsAsync<VpnInputException>(() => Data(store, query));
            Assert.Equal(query.StartsWith("scope", StringComparison.Ordinal) ? "report_parameter_required:domain" : "domain_scope_invalid", error.Message);
            Assert.DoesNotContain(store.Calls, c => c.Sql == VpnSql.Coverage || c.Sql == VpnSql.ConnectionSessions);
        }
    }
}
