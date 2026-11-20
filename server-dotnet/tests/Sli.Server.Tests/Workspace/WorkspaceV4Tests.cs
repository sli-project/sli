using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Reporting;
using Sli.Server.Workspace;
using Xunit;

namespace Sli.Server.Tests.Workspace;

public sealed class WorkspaceV4Tests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    public static TheoryData<string> Scenarios => new(Vectors.Select(v => v["name"]!.ToString()));
    static readonly JsonObject[] Vectors = Load();
    static JsonObject[] Load()
    {
        using var stream = typeof(WorkspaceV4Tests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Workspace.workspace-source.json")!;
        return JsonNode.Parse(stream)!.AsArray().OfType<JsonObject>().ToArray();
    }
    sealed class Facts(JsonObject vector) : IAccessFactsRepository
    {
        public int Reads;
        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct)
        {
            Reads++;
            var input = vector["facts"]!.AsObject();
            JsonElement[] Rows(string key) => input[key]!.AsArray().Select(v => JsonSerializer.SerializeToElement(v)).ToArray();
            return Task.FromResult(new AccessFacts(input["is_owner"]![0]!["is_owner"]!.GetValue<bool>(), principal.Role,
                Rows("role_packages").Concat(Rows("subject_packages")).Concat(Rows("owner_packages")).ToArray(),
                Rows("package_capabilities"), Rows("direct_capabilities"), Rows("all_capabilities"), Rows("package_reports"),
                Rows("report_assignments"), Rows("definitions")) { Groups = Rows("groups"), Preferences = Rows("preferences") });
        }
    }
    sealed class Rows(JsonObject vector) : IWorkspaceRows
    {
        public int Reads;
        public Task<IReadOnlyList<JsonElement>> ReadAsync(string sql, CancellationToken ct, params NpgsqlParameter[] parameters)
        {
            Reads++;
            Assert.Contains("entities_v2_active", sql);
            Assert.Contains("entity.domain_id,entity.server_id", sql);
            Assert.Contains("order by entity.last_seen_utc desc nulls last,entity.id desc limit 8", sql);
            if (vector["read_error"] is {} code) throw new PostgresException("synthetic database failure", "ERROR", "ERROR", code.ToString());
            return Task.FromResult<IReadOnlyList<JsonElement>>(vector["rows"]!.AsArray().Select(v => JsonSerializer.SerializeToElement(v)).ToArray());
        }
    }
    sealed class Reports(JsonObject vector) : IReportDatabase, IReportSession
    {
        public List<string> Executed = [];
        public Task<IReportSession> OpenAsync(bool write, CancellationToken ct) { Assert.False(write); return Task.FromResult<IReportSession>(this); }
        public Task<IReadOnlyList<JsonObject>> QueryAsync(string sql, IReadOnlyList<object?> values, CancellationToken ct)
        {
            if (sql.StartsWith("select r.definition_json"))
            {
                string key = (string)values[0]!; Executed.Add(key);
                if (vector["report_error"]!.GetValue<bool>()) throw new InvalidOperationException("synthetic report failure");
                return Task.FromResult<IReadOnlyList<JsonObject>>([vector["facts"]!["definitions"]!.AsArray().Single(r => r!["report_key"]!.ToString() == key)!.DeepClone().AsObject()]);
            }
            Assert.Contains("entities_v2_active", sql);
            Assert.Contains(2, values); // ReportRunner receives limit=1 and reads one extra row.
            return Task.FromResult<IReadOnlyList<JsonObject>>(vector["name"]!.ToString() == "empty_report" ? [] : [new() { ["id"] = 7 }]);
        }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("GET must not commit writes");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    sealed class Authentication(bool loggedIn, string role) : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct) => ValueTask.FromResult(loggedIn
            ? AuthenticationResult.Success(new("session", 7, role, Username: "fixture"))
            : AuthenticationResult.Denied(401, "authentication_required"));
    }
    static async Task<IHost> Start(Facts facts, Rows rows, Reports reports, bool loggedIn = true, string role = "viewer", bool local = false)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["Sli:AuthRequired"] = local ? "0" : "1", ["Sli:AllowUnauthenticated"] = "1" }).Build();
        return await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s =>
        {
            s.AddRouting(); s.AddLogging(); s.AddSingleton<IConfiguration>(config);
            s.AddSingleton(new AuthRequestPolicy(config)); s.AddSingleton(new TransportGate(config));
            s.AddSingleton<IPrincipalAuthenticator>(new Authentication(loggedIn, role)); s.AddSingleton<IAccessFactsRepository>(facts);
            s.AddSingleton<IWorkspaceCompatibilityReader>(new WorkspaceCompatibilityReader(rows, config, new ReportRunner(reports), null!, null!));
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => e.MapWorkspaceCompatibility()); })).StartAsync(Ct);
    }
    [Theory, MemberData(nameof(Scenarios))]
    public async Task Http_body_status_and_reads_match_frozen_Python_route(string name)
    {
        var vector = Vectors.Single(v => v["name"]!.ToString() == name);
        var facts = new Facts(vector); var rows = new Rows(vector); var reports = new Reports(vector);
        using var host = await Start(facts, rows, reports, local: vector["local"]?.GetValue<bool>() == true); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v1/workspace?limit=bad&limit=ignored&force=true", Ct);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!;
        Assert.Equal(vector["status"]!.GetValue<int>(), (int)response.StatusCode);
        if (response.StatusCode == System.Net.HttpStatusCode.InternalServerError)
        {
            Assert.Equal("internal_server_error", body["error"]!.ToString());
            Assert.DoesNotContain("synthetic database failure", body.ToJsonString());
        }
        else Assert.True(JsonNode.DeepEquals(vector["expected"], body), name + ": " + body.ToJsonString());
        Assert.Equal(vector["expected_reads"]!.GetValue<int>(), rows.Reads);
        Assert.Equal(vector["expected_reports"]!.AsArray().Select(v => v!.ToString()).Order(), reports.Executed.Order());
    }
    [Theory]
    [InlineData(false, "viewer", 401, "authentication_required")]
    [InlineData(true, "invalid", 403, "insufficient_permissions")]
    public async Task Authentication_and_role_denials_precede_all_reads(bool loggedIn, string role, int status, string error)
    {
        var vector = Vectors[0]; var facts = new Facts(vector); var rows = new Rows(vector); var reports = new Reports(vector);
        using var host = await Start(facts, rows, reports, loggedIn, role); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v1/workspace", Ct);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!;
        Assert.Equal(status, (int)response.StatusCode); Assert.Equal(error, body["error"]!.ToString());
        Assert.Equal(0, facts.Reads); Assert.Equal(0, rows.Reads); Assert.Empty(reports.Executed);
    }
}
