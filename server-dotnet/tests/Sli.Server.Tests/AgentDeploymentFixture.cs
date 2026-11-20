using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Agents.Deployment;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Infrastructure;
using Xunit;

namespace Sli.Server.Tests;

// Synthetic repository boundary: the actual endpoint, ACL, validators, crypto,
// snapshot/hash and state machine run unchanged. No stand or AD connections.
internal sealed class AgentDeploymentFixture : IAsyncDisposable
{
    internal const string Credentials = "/api/v1/ad-operation-credentials";
    internal const string Gpo = "/api/v1/agent-deployment/gpo/";
    internal const string Directory = "/api/v1/admin/agent-deployment-directory";
    internal static readonly Guid Installation = Guid.Parse("11111111-1111-4111-8111-111111111111");
    internal readonly State Data = new();
    internal readonly Key Secrets = new();
    private readonly ServiceProvider provider;
    internal AgentDeploymentFixture()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["Sli:AuthRequired"] = "1", ["Sli:TrustedProxies"] = "", ["Sli:AuthAllowInsecureHttp"] = "1", ["Sli:OwnerSetup"] = "0" }).Build();
        var services = new ServiceCollection();
        services.AddLogging(); services.AddSingleton<IConfiguration>(config);
        services.AddSingleton(new TransportGate(config)); services.AddSingleton(new AuthRequestPolicy(config));
        services.AddSingleton<IPrincipalAuthenticator>(new Auth());
        services.AddSingleton<IAccessFactsRepository>(new Facts(Data));
        services.AddSingleton<IAdCredentialSecrets>(Secrets);
        services.AddScoped<IAgentDeploymentDatabase>(_ => new Database(Data));
        services.AddAgentDeployment();
        provider = services.BuildServiceProvider();
    }
    internal async Task<(int Status, JsonObject Body)> Send(string path, JsonObject? body = null, string actor = "session", bool owner = true, string scheme = "https", string? query = null, string? origin = null, string? raw = null)
    {
        await using var scope = provider.CreateAsyncScope();
        var c = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        c.Request.Method = body is null && path == Credentials ? "GET" : "POST";
        c.Request.Path = path; c.Request.Scheme = scheme; c.Request.Host = new HostString("localhost");
        c.Features.Get<IHttpRequestFeature>()!.RawTarget = path + query;
        if (query is not null) c.Request.QueryString = new QueryString(query);
        if (origin is not null) c.Request.Headers.Origin = origin;
        c.Request.Headers["X-Test-Actor"] = actor; c.Request.Headers["X-Test-Owner"] = owner ? "1" : "0";
        c.Request.Headers["X-Forwarded-Proto"] = "https";
        byte[] bytes = Encoding.UTF8.GetBytes(raw ?? body?.ToJsonString() ?? "");
        c.Request.Body = new MemoryStream(bytes); c.Request.ContentLength = bytes.Length; c.Request.ContentType = "application/json";
        c.Response.Body = new MemoryStream();
        await AgentDeploymentEndpoints.Handle(c, path);
        Assert.Equal("no-store", c.Response.Headers.CacheControl);
        c.Response.Body.Position = 0;
        var result = (await JsonNode.ParseAsync(c.Response.Body, cancellationToken: TestContext.Current.CancellationToken))!.AsObject();
        Assert.NotEqual(501, c.Response.StatusCode);
        return (c.Response.StatusCode, result);
    }
    internal async Task<JsonObject> Create()
    {
        var (status, body) = await Send(Credentials, new() { ["domain_id"] = 1, ["label"] = " synthetic ", ["username"] = "operator", ["password"] = "synthetic password" });
        Assert.Equal(200, status); return body;
    }
    internal static JsonObject Revision(JsonObject credential) => new() { ["credential_id"] = credential["credential_id"]!.DeepClone(), ["credential_revision"] = credential["credential_revision"]!.DeepClone() };
    internal static JsonObject Selection() => new() { ["domain_id"] = 1, ["ou_entity_ids"] = new JsonArray(10) };
    internal async Task<JsonObject> Preview(JsonObject credential)
    {
        var selection = Selection(); foreach (var (key, value) in Revision(credential)) selection[key] = value?.DeepClone();
        var (status, body) = await Send(Gpo + "preview", selection); Assert.Equal(200, status); return body;
    }
    internal static JsonObject Finish(JsonObject plan, JsonObject? credential = null)
    {
        var body = new JsonObject { ["plan_id"] = plan["plan_id"]!.DeepClone(), ["plan_sha256"] = plan["plan_sha256"]!.DeepClone() };
        if (credential is not null) { body["acknowledged"] = true; foreach (var (key, value) in Revision(credential)) body[key] = value?.DeepClone(); }
        return body;
    }
    public ValueTask DisposeAsync() => provider.DisposeAsync();
    internal sealed class Key : IAdCredentialSecrets
    {
        internal string? Error;
        internal byte[] Bytes = Enumerable.Range(0, 32).Select(x => (byte)x).ToArray();
        public byte[] ReadKey() => Error is null ? Bytes.ToArray() : throw new Sli.Server.Agents.Control.AgentControlException(Error, 409);
    }
    private sealed class Auth : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct)
        {
            string actor = context.Request.Headers["X-Test-Actor"].ToString();
            return ValueTask.FromResult(actor == "anonymous" ? AuthenticationResult.Denied(401, "authentication_required")
                : AuthenticationResult.Success(new Principal(actor, actor == "other" ? 2 : 1, actor == "badrole" ? "invalid" : "viewer", context.Request.Headers["X-Test-Owner"])));
        }
    }
    private sealed class Facts(State state) : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct)
            => Task.FromResult(new AccessFacts(principal.Username == "1", "viewer", [], [], state.AccessManager
                ? [System.Text.Json.JsonSerializer.SerializeToElement(new { capability_key = "access.manage", effect = "allow" })] : [], [], [], [], []));
    }
    internal sealed class State
    {
        internal State()
        {
            for (int i = 0; i < Directory.Count; i++) Directory[i] = JsonNode.Parse(Directory[i].ToJsonString())!.AsObject();
        }
        internal bool Granted = true, DeploymentGranted = true, RecipientReady = true, FailAudit, FailCommit, ExpireOnUpdate, AccessManager;
        internal long ScopeRevision = 1, RecipientRevision = 1;
        internal long[] AdOus = [10], GrantOus = [10];
        internal JsonObject Package = new();
        internal readonly Dictionary<string, JsonObject> Credentials = new(), Plans = new();
        internal readonly List<JsonObject> Audits = [];
        internal JsonObject? Last;
        internal int Commits, Opens, Rollbacks;
        internal readonly List<string> Sql = [];
        internal readonly List<JsonObject> Directory = [
            new() { ["entity_id"] = 10, ["version_id"] = 100, ["source_section"] = "domain_posture", ["record"] = new JsonObject { ["identity"] = new JsonObject { ["kind"] = "security_principal" }, ["attributes"] = new JsonObject { ["infrastructure_role"] = "organizational_unit", ["distinguished_name"] = "OU=Test,DC=example,DC=test" } } },
            new() { ["entity_id"] = 20, ["version_id"] = 200, ["source_section"] = "directory_accounts", ["record"] = new JsonObject { ["identity"] = new JsonObject { ["kind"] = "ad_computer", ["object_guid"] = "22222222-2222-4222-8222-222222222222", ["object_sid"] = "S-1-5-21-1-2-3-1000" }, ["attributes"] = new JsonObject { ["enabled"] = true, ["distinguished_name"] = "CN=Synthetic,OU=Test,DC=example,DC=test", ["display_name"] = "Synthetic", ["user_account_control"] = 4096 } } }
        ];
    }
    private sealed class Database(State state) : IAgentDeploymentDatabase
    {
        private bool committed, opened;
        private Dictionary<string, JsonObject>? beforeCredentials, beforePlans;
        private JsonObject? beforeLast;
        private int beforeAudit;
        private static JsonObject Copy(JsonObject value) => JsonNode.Parse(value.ToJsonString())!.AsObject();
        public Task OpenAsync(CancellationToken ct)
        {
            opened = true; state.Opens++; beforeAudit = state.Audits.Count;
            beforeCredentials = state.Credentials.ToDictionary(x => x.Key, x => Copy(x.Value)); beforePlans = state.Plans.ToDictionary(x => x.Key, x => Copy(x.Value)); beforeLast = state.Last is null ? null : Copy(state.Last);
            return Task.CompletedTask;
        }
        public Task CommitAsync(CancellationToken ct)
        {
            if (state.FailCommit) throw new InvalidOperationException("synthetic commit failure");
            committed = true; state.Commits++; return Task.CompletedTask;
        }
        public ValueTask DisposeAsync()
        {
            if (opened && !committed)
            {
                state.Rollbacks++;
                state.Credentials.Clear(); foreach (var (k, v) in beforeCredentials!) state.Credentials[k] = v;
                state.Plans.Clear(); foreach (var (k, v) in beforePlans!) state.Plans[k] = v;
                state.Audits.RemoveRange(beforeAudit, state.Audits.Count - beforeAudit); state.Last = beforeLast;
            }
            return ValueTask.CompletedTask;
        }
        public Task<List<JsonObject>> Rows(string sql, CancellationToken ct, params (string, object?)[] args)
        {
            state.Sql.Add(sql); var p = args.ToDictionary(x => x.Item1, x => x.Item2);
            string Id(string key = "id") => p[key]!.ToString()!;
            long Long(string key) => Convert.ToInt64(p[key]);
            List<JsonObject> result;
            if (sql.Contains("sli_ad_operations_scopes")) result = [new() { ["scopes"] = state.Granted && Id("actor") == "session:1" ? new JsonArray(new JsonObject { ["domain_id"] = 1, ["ou_entity_ids"] = JsonSerializerNode(state.AdOus) }) : new JsonArray() }];
            else if (sql.Contains("sli_agent_gpo_plan_scope")) result = [new() { ["scope"] = state.DeploymentGranted && Id("actor") == "session:1" ? new JsonObject { ["revision"] = state.ScopeRevision, ["ou_entity_ids"] = new JsonArray(10), ["grant_ou_entity_ids"] = JsonSerializerNode(state.GrantOus), ["grant_permissions"] = new JsonArray("apply", "preview"), ["evidence_sha256"] = new string('a', 64), ["package"] = state.Package.DeepClone() } : null }];
            else if (sql.Contains("sli_gpo_plan_recipient")) result = [new() { ["recipient"] = state.RecipientReady ? new JsonObject { ["agent_id"] = "33333333-3333-4333-8333-333333333333", ["certificate_sha256"] = new string('b', 64), ["assignment_revision"] = state.RecipientRevision } : null }];
            else if (sql.Contains("sli_ad_credential_installation")) result = [new() { ["installation_id"] = Installation.ToString() }];
            else if (sql.StartsWith("insert into sli_ad_operation_credentials"))
            {
                var row = new JsonObject { ["credential_id"] = Id(), ["installation_id"] = Id("installation"), ["domain_id"] = Long("domain"), ["ou_entity_ids"] = JsonSerializerNode(p["ous"]!), ["label"] = Id("label"), ["username"] = Id("username"), ["credential_revision"] = 1,
                    ["envelope"] = JsonNode.Parse(Id("envelope")), ["created_by"] = Id("actor"), ["updated_by"] = Id("actor"), ["created_at"] = "2026-11-05T01:02:03+00:00", ["updated_at"] = "2026-11-05T01:02:03+00:00", ["check_status"] = "not_checked", ["checked_at"] = null };
                state.Credentials[Id()] = row; result = [row];
            }
            else if (sql.StartsWith("update sli_ad_operation_credentials"))
            {
                var row = state.Credentials[Id()]; row["envelope"] = JsonNode.Parse(Id("envelope")); row["credential_revision"] = Long("revision"); row["updated_by"] = Id("actor"); row["check_status"] = "not_checked"; row["checked_at"] = null; result = [row];
            }
            else if (sql.Contains("from sli_ad_operation_credentials"))
                result = p.ContainsKey("id") ? state.Credentials.TryGetValue(Id(), out var credential) ? [credential] : [] : state.Credentials.Values.ToList();
            else if (sql.Contains("from sli_gpo_plan_last_credentials")) result = state.Last is null ? [] : [state.Last];
            else if (sql.Contains("from sli_agent_gpo_plans")) result = state.Plans.TryGetValue(Id(), out var plan) ? [plan] : [];
            else if (sql.StartsWith("update sli_agent_gpo_plans"))
            {
                var row = state.Plans[Id()];
                if (state.ExpireOnUpdate || row["status"]!.GetValue<string>() != "preview" || DateTimeOffset.Parse(row["expires_at"]!.GetValue<string>()) <= DateTimeOffset.UtcNow) result = [];
                else { row["status"] = Id("status"); row["finished_at"] = DateTimeOffset.UtcNow.ToString("O"); result = [new() { ["id"] = Id() }]; }
            }
            else if (sql.Contains("select attributes_json from ad_context_entity_versions")) result = state.Directory.Where(x => x["version_id"]!.GetValue<long>() == Long("version")).Select(x => new JsonObject { ["attributes_json"] = x["record"]!.DeepClone() }).ToList();
            else if (sql.Contains("ad_context_entity_versions"))
                result = state.Directory.Where(x => !p.ContainsKey("id") || x["entity_id"]!.GetValue<long>() == Long("id"))
                    .Where(x => !p.ContainsKey("section") || x["source_section"]!.GetValue<string>() == Id("section"))
                    .Where(x => !sql.Contains("v.source_section='directory_accounts'") || x["source_section"]!.GetValue<string>() == "directory_accounts")
                    .Where(x => !p.ContainsKey("ous") || ((long[])p["ous"]!).Contains(x["entity_id"]!.GetValue<long>())).ToList();
            else if (sql.Contains("from domains")) result = sql.Contains("fqdn as name") ? [new() { ["id"] = 1, ["name"] = "example.test" }] : [new() { ["id"] = 1, ["fqdn"] = "example.test" }];
            else throw new InvalidOperationException("Unrecognized synthetic query: " + sql);
            return Task.FromResult(result.Select(Copy).ToList());
        }
        public Task<int> Execute(string sql, CancellationToken ct, params (string, object?)[] args)
        {
            state.Sql.Add(sql); var p = args.ToDictionary(x => x.Item1, x => x.Item2);
            string Id(string key) => p[key]!.ToString()!;
            if (sql.Contains("insert into sli_ad_credential_audit") || sql.Contains("insert into sli_agent_gpo_plan_audit"))
            {
                if (state.FailAudit) throw new InvalidOperationException("synthetic audit failure");
                var row = new JsonObject(); foreach (var (key, value) in p) row[key] = System.Text.Json.JsonSerializer.SerializeToNode(value); state.Audits.Add(row);
            }
            else if (sql.StartsWith("delete from sli_ad_operation_credentials")) state.Credentials.Remove(Id("id"));
            else if (sql.StartsWith("insert into sli_agent_gpo_plans")) state.Plans[Id("id")] = new JsonObject { ["id"] = Id("id"), ["actor"] = Id("actor"), ["domain_id"] = Convert.ToInt64(p["domain"]), ["selection"] = JsonNode.Parse(Id("selection")), ["snapshot"] = JsonNode.Parse(Id("snapshot")), ["plan_sha256"] = Id("digest"), ["status"] = "preview", ["expires_at"] = ((DateTimeOffset)p["expires"]!).ToString("O") };
            else if (sql.StartsWith("insert into sli_gpo_plan_last_credentials")) state.Last = new() { ["credential_id"] = Id("credential"), ["credential_revision"] = Convert.ToInt64(p["revision"]) };
            else throw new InvalidOperationException("Unrecognized synthetic mutation: " + sql);
            return Task.FromResult(1);
        }
        private static JsonNode JsonSerializerNode(object value) => System.Text.Json.JsonSerializer.SerializeToNode(value)!;
    }
}
