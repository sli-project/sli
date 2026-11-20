using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Ad;
using Sli.Server.Auth;
using Sli.Server.Domains;
using Sli.Server.Reporting.V2;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Reporting;

// Parity vectors from tests/reporting/test_security_event_domain_options.py.
public sealed class SecurityEventDomainOptionsTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static ReportDefinition Definition => new ReportDefinitionRegistry().Get("security.events.chains")!;

    static AccessDecision Access(string? missing = null, bool all = false, params long[] ids)
    {
        var scope = all ? JsonSerializer.SerializeToElement(new { kind = "all" })
            : JsonSerializer.SerializeToElement(new { kind = "domain", ids = ids.Length > 0 ? ids : [7L] });
        var grant = new AtomicReportGrant(scope,
            missing == "field" ? new HashSet<string> { "technical" }
                : new HashSet<string> { "identity_basic", "security", "technical", "raw_evidence" },
            new HashSet<string> { "view", "export" }, 1, 1);
        return new("viewer", new(false,
            missing == "capability" ? new HashSet<string>() : new HashSet<string> { "events.view" },
            new HashSet<string>(), [], new Dictionary<string, JsonElement>()),
            missing == "report" ? [] : [new("security.events.chains", true, [grant])]);
    }

    static ReportQueryContext Context(AccessDecision access, long? domain) => new(
        Definition, access, new Principal("session", 1, "viewer"),
        new JsonObject {
            ["domain"] = domain is {} id ? JsonValue.Create(id) : null,
            ["period"] = new JsonObject { ["from_utc"] = "2026-09-01T10:00:00Z", ["to_utc"] = "2026-09-01T11:00:00Z" }
        }, new(null, 100, "UTC", null, "asc", null), ReportScope.None, null, "view", _ => true, []);

    sealed class Store : IAdReportStore
    {
        public long[] DomainIds = [7, 8, 9];
        public readonly List<long> DiscoveryCursors = [];
        public readonly List<AdReportRequest> Reads = [];
        public int Probes;
        public bool Observed;
        public Exception? DiscoveryFailure, ReadFailure;

        public Task<IReadOnlyList<long>> DomainsAsync(long after, CancellationToken ct)
        {
            DiscoveryCursors.Add(after);
            if (DiscoveryFailure is {} error) throw error;
            return Task.FromResult<IReadOnlyList<long>>(DomainIds.Where(id => id > after).Take(256).ToArray());
        }
        public Task<bool> HasSourceAsync(string kind, long domain, CancellationToken ct)
        {
            Probes++;
            return domain == 7 ? Task.FromResult(true) : throw new TimeoutException("synthetic private archive probe detail");
        }
        public Task<JsonObject> ReadAsync(AdReportRequest request, bool sensitive, CancellationToken ct)
        {
            Reads.Add(request);
            if (ReadFailure is {} error) throw error;
            JsonObject[] events = Observed && request.Domain == 7
                ? [new() { ["event_db_id"] = 1L, ["event_id"] = 4624L, ["domain_id"] = 7L, ["time_created_utc"] = "2026-09-01T10:05:00Z" }]
                : [];
            return Task.FromResult(AdSecurity.Compose(request, events, true, false, new()));
        }
    }

    internal sealed class Names : IReportDomains, ISemanticDatabase, ISemanticSession
    {
        public readonly List<long[]> Reads = [];
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct) { Assert.False(write); return Task.FromResult<ISemanticSession>(this); }
        public async Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            var items = await ReadAsync(Assert.IsType<long[]>(Assert.Single(values)), ct);
            return new JsonArray(items.Select(item => (JsonNode)new JsonObject { ["id"] = item.Id, ["fqdn"] = item.DisplayName }).ToArray());
        }
        public Task CommitAsync(CancellationToken ct) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public Task<IReadOnlyList<DomainItem>> ReadAsync(long[]? ids, CancellationToken ct)
        {
            Assert.NotNull(ids);
            Reads.Add(ids);
            return Task.FromResult<IReadOnlyList<DomainItem>>(ids.Select(id => new DomainItem(
                id, $"domain{id}.example.test", false, new(null, null, null, null, null, null, null))).ToArray());
        }
    }

    static SecurityEventsReader Reader(Store store, Names names) => new(store, names, null!, null!);

    [Fact]
    public async Task Options_keep_all_authorized_domains_without_probing_event_history()
    {
        var store = new Store(); var names = new Names();
        var options = await Reader(store, names).OptionsAsync(Definition, Access(ids: [7, 8]), Ct);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""
            {"domain":[{"value":"7","label":"domain7.example.test"},{"value":"8","label":"domain8.example.test"}]}
            """), options));
        Assert.Equal(new long[] { 7, 8 }, Assert.Single(names.Reads));
        Assert.Empty(store.Reads); Assert.Equal(0, store.Probes);
    }

    [Theory]
    [InlineData("capability")]
    [InlineData("field")]
    [InlineData("report")]
    public async Task Options_require_full_read_authorization(string missing)
    {
        var store = new Store(); var names = new Names();
        var options = await Reader(store, names).OptionsAsync(Definition, Access(missing), Ct);
        Assert.Empty(options["domain"]!.AsArray());
        Assert.Empty(names.Reads); Assert.Empty(store.Reads); Assert.Equal(0, store.Probes);
    }

    [Theory]
    [InlineData(7L, false)]
    [InlineData(7L, true)]
    [InlineData(null, false)]
    [InlineData(null, true)]
    public async Task Page_and_coverage_are_independent_of_option_source_probes(long? domain, bool observed)
    {
        var store = new Store { Observed = observed }; var names = new Names();
        var payload = await Reader(store, names).QueryAsync(Context(Access(ids: [7, 8]), domain), Ct);
        Assert.Equal(domain is {} id ? new[] { id } : new long[] { 7, 8 }, store.Reads.Select(r => r.Domain));
        Assert.All(store.Reads, request => {
            Assert.Equal("security", request.Kind);
            Assert.Equal(DateTimeOffset.Parse("2026-09-01T10:00:00Z"), request.Period!.Start);
            Assert.Equal(DateTimeOffset.Parse("2026-09-01T11:00:00Z"), request.Period.End);
        });
        Assert.Equal(observed && domain is not null ? "ok" : "partial", (string?)payload["state"]);
        Assert.Equal("not_proven", (string?)payload["coverage"]?["source_completeness"]);
        Assert.Equal(observed ? new long[] { 1 } : [], payload["items"]!.AsArray().Select(row => row!["event_db_id"]!.GetValue<long>()));
        Assert.Equal(new long[] { 7, 8 }, Assert.Single(names.Reads));
        Assert.Equal(0, store.Probes);
    }

    [Fact]
    public async Task Failed_scope_discovery_is_not_silently_hidden()
    {
        var failure = new TimeoutException("synthetic metadata failure");
        var store = new Store { DiscoveryFailure = failure }; var names = new Names();
        Assert.Same(failure, await Assert.ThrowsAsync<TimeoutException>(() => Reader(store, names).OptionsAsync(Definition, Access(), Ct)));
        Assert.Empty(names.Reads); Assert.Empty(store.Reads); Assert.Equal(0, store.Probes);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(101)]
    [InlineData(10_000)]
    [InlineData(10_001)]
    public async Task Metadata_enumeration_never_silently_truncates(int count)
    {
        var store = new Store { DomainIds = Enumerable.Range(1, count).Select(id => (long)id).ToArray() };
        var names = new Names(); var reader = Reader(store, names);
        var options = await reader.OptionsAsync(Definition, Access(all: true), Ct);
        Assert.Equal(Enumerable.Range(1, count).Select(id => id.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            options["domain"]!.AsArray().Select(option => (string?)option!["value"]));
        Assert.Equal(Enumerable.Range(0, Math.Max(1, (count + 255) / 256)).Select(batch => batch * 256L), store.DiscoveryCursors);
        Assert.Empty(store.Reads); Assert.Equal(0, store.Probes);
    }

    [Fact]
    public async Task Explicit_unauthorized_domain_does_not_fall_back_and_negative_domain_is_invalid()
    {
        var store = new Store(); var names = new Names(); var reader = Reader(store, names);
        var denied = await reader.QueryAsync(Context(Access(), 9), Ct);
        Assert.Equal("denied", (string?)denied["state"]);
        var error = await Assert.ThrowsAsync<ReportRequestException>(() => reader.QueryAsync(Context(Access(), -1), Ct));
        Assert.Equal("security_events_domain_invalid", error.Message);
        Assert.Empty(store.Reads); Assert.Equal(0, store.Probes);
    }

    [Fact]
    public async Task Selected_scope_read_failure_is_not_converted_to_success()
    {
        var failure = new TimeoutException("synthetic selected source failure");
        var store = new Store { ReadFailure = failure };
        Assert.Same(failure, await Assert.ThrowsAsync<TimeoutException>(() => Reader(store, new Names()).QueryAsync(Context(Access(), 7), Ct)));
        Assert.Equal(7, Assert.Single(store.Reads).Domain); Assert.Equal(0, store.Probes);
    }
}
