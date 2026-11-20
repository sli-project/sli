using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Domains;
using Sli.Server.Infrastructure;
using Xunit;

namespace Sli.Server.Tests.Domains;

public sealed class DomainContractTests
{
    private static JsonElement Vectors()
    {
        using var stream = typeof(DomainContractTests).Assembly.GetManifestResourceStream(
            "Sli.Server.Tests.Domains.domain-contract-vectors.json")!;
        using var document = JsonDocument.Parse(stream);
        return document.RootElement.Clone();
    }

    [Fact]
    public async Task ResponseDtoAndWriterMatchExecutedPythonSelectionIncludingNullEmptyAndBigint()
    {
        foreach (var vector in Vectors().GetProperty("responses").EnumerateArray())
        {
            string? Text(JsonElement row, string key) => row.GetProperty(key).GetString();
            var items = vector.GetProperty("rows").EnumerateArray().Select(row => new DomainItem(
                row.GetProperty("id").GetInt64(), Text(row, "display_name")!, row.GetProperty("is_archived").GetBoolean(),
                new DomainFreshness(Text(row, "snapshot_at_utc"), Text(row, "published_at_utc"),
                    Text(row, "snapshot_state"), Text(row, "observed_at_utc"), Text(row, "default_observed_at_utc"),
                    Text(row, "event_at_utc"), Text(row, "last_successful_collection_utc")))).ToArray();
            var context = new DefaultHttpContext();
            context.Response.Body = new MemoryStream();
            await DomainHttp.WriteAsync(context, new DomainResponse(items), 200, TestContext.Current.CancellationToken);
            var bytes = ((MemoryStream)context.Response.Body).ToArray();
            Assert.True(JsonNode.DeepEquals(JsonNode.Parse(vector.GetProperty("expected").GetRawText()),
                JsonNode.Parse(bytes)), vector.GetProperty("name").GetString());
            Assert.Equal("application/json; charset=utf-8", context.Response.ContentType);
            Assert.Equal(bytes.Length, context.Response.ContentLength);
        }
    }

    [Fact]
    public async Task QueryVectorsRejectUnsupportedParametersThroughHttpWithoutDatabaseAccess()
    {
        using var factory = Factory("allowed");
        using var client = factory.CreateClient();
        foreach (var vector in Vectors().GetProperty("queries").EnumerateArray())
        {
            string query = vector.GetProperty("raw").GetString()!;
            bool rejected = vector.GetProperty("rejected").GetBoolean();
            Assert.Equal(rejected, DomainQuery.HasParameters(query));
            using var response = await client.GetAsync("/api/v1/domains" + query, TestContext.Current.CancellationToken);
            Assert.Equal(rejected ? HttpStatusCode.BadRequest : HttpStatusCode.OK, response.StatusCode);
            var actual = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            Assert.True(JsonNode.DeepEquals(JsonNode.Parse(rejected
                ? """{"error":"domain_parameters_invalid"}""" : """{"items":[]}"""), actual), query);
        }
    }

    [Theory]
    [InlineData("unauthenticated", 401, "authentication_required")]
    [InlineData("role", 403, "insufficient_permissions")]
    [InlineData("capability", 403, "workspace_view_required")]
    [InlineData("scope", 400, "domain_parameters_invalid")]
    [InlineData("timeout", 503, "report_read_timeout")]
    [InlineData("unexpected", 500, "internal_server_error")]
    public async Task ActualRouteErrorsHaveConcreteBodiesAndGatePrecedence(string mode, int status, string code)
    {
        using var factory = Factory(mode);
        using var client = factory.CreateClient();
        // Authentication and role gates precede query validation. With a valid query,
        // capability and repository failures must still produce concrete safe errors.
        using var response = await client.GetAsync("/api/v1/domains" + (mode is "unauthenticated" or "role" or "scope" ? "?domain_id=1" : ""), TestContext.Current.CancellationToken);
        Assert.Equal(status, (int)response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var root = body.RootElement;
        Assert.Equal(code, root.GetProperty("error").GetString());
        string[] fields = mode switch
        {
            "unauthenticated" => ["error", "message"],
            "capability" => ["error"],
            "timeout" => ["error", "state"],
            "unexpected" => ["error", "internal_error_id"],
            _ => ["error"]
        };
        Assert.Equal(fields.Order(), root.EnumerateObject().Select(p => p.Name).Order());
        if (mode == "timeout") Assert.Equal("unavailable", root.GetProperty("state").GetString());
        if (mode == "unexpected") Assert.True(Guid.TryParse(root.GetProperty("internal_error_id").GetString(), out _));
        if (mode == "unauthenticated")
        {
            var message = root.GetProperty("message");
            Assert.Equal("login.error.authenticationRequired", message.GetProperty("code").GetString());
            Assert.Empty(message.GetProperty("params").EnumerateObject());
            Assert.Equal("Необходимо войти в систему.", message.GetProperty("text").GetString());
        }
    }

    private static WebApplicationFactory<Program> Factory(string mode) => new WebApplicationFactory<Program>().WithWebHostBuilder(Sli.Server.Tests.Domains.SafeTestEnvironment.ConfigureApiHost)
        .WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.RemoveAll<IPrincipalAuthenticator>();
            services.AddSingleton<IPrincipalAuthenticator>(new Auth(mode));
            services.RemoveAll<IDomainAccessService>();
            services.AddSingleton<IDomainAccessService>(new Access(mode));
            services.RemoveAll<IPostgresConnectionFactory>();
            services.AddSingleton<IPostgresConnectionFactory, NoDatabase>();
            services.AddTransient<IStartupFilter, RawTargetFilter>();
        }));

    private sealed class Auth(string mode) : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct) =>
            ValueTask.FromResult(mode == "unauthenticated" ? AuthenticationResult.Denied(401, "authentication_required")
                : AuthenticationResult.Success(new("session", 1, mode == "role" ? "unknown" : "viewer")));
    }

    private sealed class Access(string mode) : IDomainAccessService
    {
        public Task<DomainAccessDecision> EvaluateAsync(Principal principal, CancellationToken ct)
        {
            if (mode == "scope") throw new DomainScopeCompositionException();
            if (mode == "timeout") throw new PostgresException("synthetic", "ERROR", "ERROR", "57014");
            if (mode == "unexpected") throw new InvalidOperationException("synthetic");
            return Task.FromResult(new DomainAccessDecision(mode != "capability", "explicit_deny", DomainGrant.None));
        }
    }

    private sealed class NoDatabase : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) =>
            throw new InvalidOperationException("This isolated contract test must never access PostgreSQL.");
    }

    private sealed class RawTargetFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, runNext) =>
            {
                context.Features.Get<IHttpRequestFeature>()!.RawTarget = context.Request.Path + context.Request.QueryString;
                await runNext(context);
            });
            next(app);
        };
    }
}
