using System.Net;
using System.Security.Cryptography;
using System.Text;
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
using Sli.Server.InstallationSetup;
using Xunit;

namespace Sli.Server.Tests.InstallationSetup;

internal sealed class InstallationFixture : IAsyncDisposable
{
    public readonly string Root = Path.Combine(Path.GetTempPath(), "sli-installation-" + Guid.NewGuid().ToString("N"));
    public readonly ScriptDatabase Database = new();
    public Principal Principal = new("session", 1, "admin", "alice");
    public bool Owner = true, Deny, Authenticated = true;
    public readonly Dictionary<string, string?> Configuration = new() { ["Sli:AuthRequired"] = "true" };
    public IHost Host = null!;
    public HttpClient Client = null!;
    public string Hash { get; private set; } = "";
    public readonly byte[] Asset = Encoding.UTF8.GetBytes("export const title = 'synthetic';\n");
    public InstallationFixture()
    {
        Directory.CreateDirectory(Root);
        Configuration["Sli:ConfigRoot"] = Path.Combine(Root, "config"); Directory.CreateDirectory(Configuration["Sli:ConfigRoot"]!);
        Configuration["Sli:PluginUiDirectory"] = Path.Combine(Root, "ui");
        WriteUi();
    }
    public void WriteUi(string[]? required = null)
    {
        string directory = Path.Combine(Root, "ui", "sli.ad"); Directory.CreateDirectory(directory);
        Hash = Convert.ToHexStringLower(SHA256.HashData(Asset)); File.WriteAllBytes(Path.Combine(directory, "entry.js"), Asset);
        File.WriteAllText(Path.Combine(directory, "descriptor.json"), JsonSerializer.Serialize(new { plugin_id = "sli.ad", ui_api = "sli.plugin-ui.v1", version = "1.0.0",
            routes = new[] { "/extensions/sli.ad/settings" }, entry = new { path = "entry.js", sha256 = Hash }, required_capabilities = required ?? new[] { "access.manage" } }));
    }
    sealed class Authentication(InstallationFixture f) : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c, CancellationToken ct) => ValueTask.FromResult(f.Authenticated
            ? AuthenticationResult.Success(f.Principal) : AuthenticationResult.Denied(401, "authentication_required"));
    }
    sealed class Facts(InstallationFixture f) : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal p, CancellationToken ct)
        {
            string[] capabilities = ["access.manage", "operations.view", "workspace.view", "plugins.manage"];
            var policies = f.Deny ? Array.Empty<JsonElement>() : capabilities.Select(c => JsonSerializer.SerializeToElement(new { capability_key = c, effect = "allow", scope_json = new { kind = "all" } })).ToArray();
            return Task.FromResult(new AccessFacts(f.Owner && !f.Deny, p.Role, [], [], policies, [], [], [], []));
        }
    }
    public async Task StartAsync()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(Configuration).Build();
        Host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services => {
            services.AddRouting(); services.AddLogging(); services.AddSingleton<IConfiguration>(config);
            services.AddSingleton(new TransportGate(config)); services.AddSingleton(new AuthRequestPolicy(config));
            services.AddSingleton<IPrincipalAuthenticator>(new Authentication(this)); services.AddSingleton<IAccessFactsRepository>(new Facts(this));
            services.AddSingleton<IInstallationDatabase>(Database); services.AddInstallation();
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => { e.MapInstallation(); e.MapFallback(c => { c.Response.StatusCode = 501; return Task.CompletedTask; }); }); }))
            .StartAsync(TestContext.Current.CancellationToken);
        Client = Host.GetTestClient(); Client.BaseAddress = new Uri("https://localhost");
    }
    public async Task<(int Status, JsonNode Body)> SendAsync(string method, string path, string? body = null)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), path.Replace("HASH", Hash, StringComparison.Ordinal));
        if (body is not null) request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        using var response = await Client.SendAsync(request, TestContext.Current.CancellationToken);
        string text = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return ((int)response.StatusCode, response.Content.Headers.ContentType?.MediaType == "application/javascript" ? JsonValue.Create(text)! : JsonNode.Parse(text)!);
    }
    public ValueTask DisposeAsync()
    {
        Client?.Dispose(); Host?.Dispose();
        // Root is a fresh test-owned directory; remove links themselves, never targets.
        if (Directory.Exists(Root)) Directory.Delete(Root, true);
        return ValueTask.CompletedTask;
    }
}

internal sealed class ScriptDatabase : IInstallationDatabase, IInstallationSession
{
    public readonly List<(string Sql, object?[] Args, bool Write)> Calls = [];
    public readonly Dictionary<string, string> Settings = new();
    public Func<string, object?[], JsonArray?>? Override;
    public int Commits, Rollbacks;
    bool write;
    public Task<T> ReadAsync<T>(Func<IInstallationSession, Task<T>> read, CancellationToken ct) => read(this);
    public async Task<T> WriteAsync<T>(Func<IInstallationSession, Task<T>> action, CancellationToken ct)
    {
        var before = Settings.ToDictionary(p => p.Key, p => p.Value); write = true;
        try { T result = await action(this); Commits++; return result; }
        catch { Settings.Clear(); foreach (var p in before) Settings.Add(p.Key, p.Value); Rollbacks++; throw; }
        finally { write = false; }
    }
    public static JsonArray Rows(string json) => JsonNode.Parse(json)!.AsArray();
    public static JsonObject State() => JsonNode.Parse("""
        {"plugin_id":"sli.ad","package_version":"1.0.0","installed":true,"configured":true,"enabled":true,"receiving_data":false,
         "component_runtime":"stopped","queue_state":"drained","revision":2,"last_data_at_utc":null}
        """)!.AsObject();
    public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] args)
    {
        Calls.Add((sql, args, write));
        JsonArray? custom = Override?.Invoke(sql, args); if (custom is not null) return Task.FromResult(custom);
        JsonArray result;
        if (sql.Contains("select value,updated_by", StringComparison.Ordinal) || sql.StartsWith("select value from platform_settings", StringComparison.Ordinal))
            result = Settings.TryGetValue((string)args[0]!, out string? value) ? new(new JsonObject { ["value"] = value, ["updated_by"] = "alice", ["updated_at"] = "2026-01-01 00:00:00+00" }) : new();
        else if (sql.Contains("insert into platform_settings", StringComparison.Ordinal)) { Settings[(string)args[0]!] = (string)args[1]!; result = new(); }
        else if (sql.Contains("from domains d join forests", StringComparison.Ordinal)) result = Rows("""[{"fqdn":"example.test","netbios_name":"EXAMPLE","is_archived":false,"forest":"example.test","observed_at_utc":null,"server_count":0}]""");
        else if (sql.Contains("from domain_controller_targets t", StringComparison.Ordinal)) result = Rows("""[{"hostname":"dc","connect_address":"dc.example.test","domain":"example.test","enabled":true,"source":"db","dns_readback":false}]""");
        else if (sql.Contains("select netbios_name,is_archived", StringComparison.Ordinal) || sql.StartsWith("select is_archived", StringComparison.Ordinal) && sql.Contains("for update", StringComparison.Ordinal))
            result = args[0]?.ToString() == "new.test" ? new() : Rows("""[{"netbios_name":"EXAMPLE","is_archived":false}]""");
        else if (sql.Contains("from domains where upper(netbios", StringComparison.Ordinal)) result = new();
        else if (sql.StartsWith("insert into forests", StringComparison.Ordinal) || sql.StartsWith("select id from domains", StringComparison.Ordinal)) result = Rows("[{\"id\":1}]");
        else if (sql.StartsWith("select is_archived", StringComparison.Ordinal)) result = Rows("[{\"is_archived\":false}]");
        else if (sql.StartsWith("select hostname,enabled", StringComparison.Ordinal)) result = Rows("[{\"hostname\":\"dc\",\"enabled\":true}]");
        else if (sql.Contains("read_plugin_states_v1", StringComparison.Ordinal) || sql.Contains("set_plugin_enabled_v1", StringComparison.Ordinal)) result = new(State());
        else if (sql.Contains("insert into access_audit_v4", StringComparison.Ordinal)) result = Rows("[{\"id\":1,\"created_at\":\"2026-01-01T00:00:00Z\"}]");
        else result = new();
        return Task.FromResult(result);
    }
}
