using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Entities;
using Xunit;

namespace Sli.Server.Tests.Entities;

// Behavioral vectors from tests/access/test_object_provenance_v4.py.
public sealed class ObjectProvenanceV4Tests
{
    const string ContextAt = "2026-07-26T11:08:44+07:00";
    const string StorageAt = "2026-07-26T11:00:00+07:00";
    static JsonArray Rows(string json) => JsonNode.Parse(json)!.AsArray();
    static JsonElement J(string json) => JsonDocument.Parse(json).RootElement.Clone();
    static AccessFacts Facts(string? denied = null, int server = 9, bool scopedOnly = false)
    {
        string[] capabilities = ["objects.view", "field.identity_basic", "field.technical", "field.security", "evidence.exact"];
        var grants = capabilities.Where(c => !scopedOnly || c != "objects.view").Select(c => J(JsonSerializer.Serialize(new
        { capability_key = c, effect = "allow", scope_json = new { kind = "all" } }))).ToList();
        if (denied is not null || scopedOnly) grants.Add(J(JsonSerializer.Serialize(new
        { capability_key = denied ?? "objects.view", effect = scopedOnly ? "allow" : "deny", scope_json = new { kind = "server", ids = new[] { server } } })));
        return new(false, "viewer", [], [], grants, [], [], [], []);
    }
    sealed class Store : IEntityReadStore
    {
        public int Id = 7;
        public string Type = "ad_user", DisplayName = "Allowed entity";
        public int? Server = 7;
        public string? StorageObservedAt;
        public bool Events, RejectHydration;
        public string? DeniedField;
        public readonly List<string> Reads = [];
        public Task<JsonArray> ReadAsync(string sql, IReadOnlyDictionary<string, object> args, int seconds, CancellationToken ct)
        {
            Reads.Add(sql);
            Assert.Equal(Id, Convert.ToInt32(args["id"]));
            if (sql.Contains("resolve_entity_identity_v2(@id)", StringComparison.Ordinal))
                return Task.FromResult(new JsonArray(new JsonObject { ["id"] = Id, ["entity_type"] = Type, ["domain_id"] = 1, ["server_id"] = Server }));
            Assert.False(RejectHydration, "Hidden entity must not be hydrated");
            JsonArray result;
            if (sql.Contains("state.status as latest_state_status", StringComparison.Ordinal))
                result = new(new JsonObject { ["id"] = Id, ["entity_type"] = Type, ["display_name"] = DisplayName, ["natural_key"] = "example.test\\account" });
            else if (sql.Contains("from entity_state_current", StringComparison.Ordinal)) result = new();
            else if (sql.Contains("from ad_context_entity_versions", StringComparison.Ordinal))
                result = new(new JsonObject { ["context_kind"] = "entity", ["source_section"] = "gpo_governance", ["observed_at_utc"] = ContextAt, ["attributes_json"] = new JsonObject() });
            else if (sql.Contains("select e.id as event_db_id,s.id as server_id", StringComparison.Ordinal))
                result = Events ? Rows("""[{"event_db_id":12,"server_id":9,"domain_id":2,"channel":"Security"}]""") : new();
            else if (sql.Contains("link.natural_key=any(keys.natural_keys)", StringComparison.Ordinal))
            {
                Assert.Equal(new long[] { 12 }, (long[])args["event_ids"]);
                Assert.Empty((string[])args["summary_keys"]);
                string columns = sql.Split("select distinct ", StringSplitOptions.None)[^1]
                    .Split(" from short_events e", StringSplitOptions.None)[0];
                if (DeniedField == "field.technical")
                {
                    Assert.DoesNotContain("e.provider_name", columns);
                    Assert.DoesNotContain("link.link_role", columns);
                    Assert.DoesNotContain("SubjectUserName", columns);
                    Assert.DoesNotContain("TargetUserName", columns);
                    Assert.Contains("e.event_id", columns);
                    result = Rows("""[{"event_db_id":12,"event_id":4624,"time_utc":"2026-09-10T01:00:00Z","server":"foreign.example.test","channel":"Security"}]""");
                }
                else
                {
                    Assert.Equal("field.security", DeniedField);
                    Assert.DoesNotContain("e.event_id", columns);
                    Assert.DoesNotContain("as time_utc", columns);
                    Assert.DoesNotContain("SubjectUserName", columns);
                    Assert.DoesNotContain("TargetUserName", columns);
                    Assert.Contains("e.provider_name", columns);
                    result = Rows("""[{"event_db_id":12,"server":"foreign.example.test","channel":"Security","provider_name":"Microsoft-Windows-Security-Auditing","link_role":"subject","confidence":1.0}]""");
                }
            }
            else if (sql.Contains("storage_v2_observed_at_utc", StringComparison.Ordinal))
                result = new(new JsonObject { ["domain_id"] = 1, ["server_id"] = Server, ["storage_v2_observed_at_utc"] = StorageObservedAt });
            else if (sql.Contains("object_identity_links", StringComparison.Ordinal)) result = new();
            else if (sql.Contains("findings_active", StringComparison.Ordinal))
            {
                // A foreign finding has the same (possibly empty) display name,
                // but belongs to entity 99. Only entity identity may select it.
                Assert.Contains("where link.entity_id=@id", sql);
                Assert.DoesNotContain("link.display_name", sql);
                result = new();
            }
            else throw new InvalidOperationException("Unexpected entity SQL: " + sql);
            return Task.FromResult(result);
        }
    }
    sealed class Auth : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct) =>
            ValueTask.FromResult(AuthenticationResult.Success(new("session", 1, "viewer")));
    }
    sealed class FactsReader(AccessFacts facts) : IAccessFactsRepository
    { public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct) => Task.FromResult(facts); }
    static string RepositoryRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (Directory.Exists(Path.Combine(dir.FullName, "config", "plugin_packages", "v3"))) return dir.FullName;
        throw new InvalidOperationException("Repository root missing");
    }
    static async Task<IHost> Host(Store store, AccessFacts? facts = null)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "true" }).Build();
        return await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().UseContentRoot(RepositoryRoot()).ConfigureServices(services =>
        {
            services.AddRouting(); services.AddLogging(); services.AddSingleton<IConfiguration>(config);
            services.AddSingleton(new AuthRequestPolicy(config)); services.AddSingleton(new TransportGate(config));
            services.AddSingleton<IPrincipalAuthenticator>(new Auth()); services.AddSingleton<IAccessFactsRepository>(new FactsReader(facts ?? Facts()));
            services.AddSingleton<IEntityReadStore>(store); services.AddEntityReads();
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => e.MapEntityReads()); })).StartAsync(TestContext.Current.CancellationToken);
    }
    static async Task<JsonObject> Object(IHost host, Store store)
    {
        using var client = host.GetTestClient();
        using var response = await client.GetAsync($"https://localhost/api/v1/objects/{store.Type}/{store.Id}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
    }
    [Fact]
    public async Task SharedEntityIdWinsBeforeAnyAliasLookup()
    {
        var store = new Store { Id = 41 }; using var host = await Host(store);
        var context = await host.Services.GetRequiredService<EntityDirectoryReader>().ReadAsync(41, TestContext.Current.CancellationToken);
        Assert.Equal("shared_entity_id", context["resolution"]!.ToString());
        Assert.Equal(41, context["ad_context_entity_id"]!.GetValue<int>());
        Assert.Equal(41, context["entity_id"]!.GetValue<int>());
        Assert.Equal(1, context["returned_count"]!.GetValue<int>());
        Assert.True(context["bounded"]!.GetValue<bool>());
        Assert.Equal("gpo_governance", Assert.Single(context["items"]!.AsArray())!["source_section"]!.ToString());
        Assert.Single(store.Reads); // Any alias fallback fails in the strict store.
    }
    [Fact]
    public async Task AdOnlyGpoDoesNotClaimStorageV2Observation()
    {
        var store = new Store { Id = 41, Type = "gpo", Server = null }; using var host = await Host(store);
        var body = await Object(host, store);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""[{"source":"AD Context","observed_at_utc":"2026-07-26T11:08:44+07:00","freshness":"observed"}]"""), body["provenance"]));
    }
    [Fact]
    public async Task DualSourceEntityReportsBothObservedSourcesInOrder()
    {
        var store = new Store { Id = 42, Server = 2, StorageObservedAt = StorageAt }; using var host = await Host(store);
        var body = await Object(host, store);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""[{"source":"Storage V2","observed_at_utc":"2026-07-26T11:00:00+07:00","freshness":"observed"},{"source":"AD Context","observed_at_utc":"2026-07-26T11:08:44+07:00","freshness":"observed"}]"""), body["provenance"]));
    }
    [Theory]
    [InlineData("ad_user")]
    [InlineData("computer")]
    public async Task ScopeDenialPrecedesDetailHydrationAndTypeMismatch(string requestedType)
    {
        var store = new Store { RejectHydration = true }; using var host = await Host(store, Facts("objects.view", 7)); using var client = host.GetTestClient();
        using var response = await client.GetAsync($"https://localhost/api/v1/objects/{requestedType}/7", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("object_not_found", JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!["error"]!.ToString());
        Assert.Single(store.Reads);
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ResourceGrantIsEvaluatedForTheObjectInsteadOfRejectedGlobally(bool scopedOnly)
    {
        var store = new Store(); using var host = await Host(store, scopedOnly ? Facts(server: 7, scopedOnly: true) : Facts("objects.view", 9));
        var body = await Object(host, store);
        Assert.Equal("7", body["object"]!["object_id"]!.ToString());
    }
    [Theory]
    [InlineData("field.technical", """[{"event_db_id":12,"event_id":4624,"time_utc":"2026-09-10T01:00:00Z","server":"foreign.example.test","channel":"Security","label":"Успешный вход"}]""")]
    [InlineData("field.security", """[{"event_db_id":12,"server":"foreign.example.test","channel":"Security","provider_name":"Microsoft-Windows-Security-Auditing","link_role":"subject","confidence":1.0}]""")]
    public async Task EachEventUsesItsOwnFieldPermissionsBeforeHydration(string denied, string expected)
    {
        var store = new Store { Events = true, DeniedField = denied }; using var host = await Host(store, Facts(denied));
        var body = await Object(host, store);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(expected), body["events"]), $"Actual events: {body["events"]}");
        Assert.Single(store.Reads, sql => sql.Contains("link.natural_key=any(keys.natural_keys)", StringComparison.Ordinal));
    }
    [Theory]
    [InlineData("Shared display name")]
    [InlineData("")]
    public async Task FindingsUseEntityIdentityInsteadOfCollidingDisplayName(string displayName)
    {
        var store = new Store { DisplayName = displayName }; using var host = await Host(store);
        var body = await Object(host, store);
        Assert.Empty(body["findings"]!.AsArray());
        Assert.Single(store.Reads, sql => sql.Contains("findings_active", StringComparison.Ordinal));
    }
}
