using Sli.Server.Auth;
using Sli.Server.Auth.ReportKeys;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Auth;

public sealed class ExactEventAuthorizationTests
{
    [Fact]
    public void NullEventDomainFailsClosed()
    {
        Assert.False(ExactEventAuthorization.TryDomain(DBNull.Value, out _));
        Assert.False(ExactEventAuthorization.TryDomain(null, out _));
    }
    private sealed class Connections(SyntheticDatabase database) : IPostgresConnectionFactory
    { public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => database.OpenConnectionAsync(ct); }

    [Fact]
    public async Task OrdinaryPrincipalPassesReportSpecificGuard()
    {
        var guard = new ExactEventAuthorization(null!);
        var result = await guard.CheckAsync(new Principal("session", 1, "viewer"), "/api/v1/events/0", TestContext.Current.CancellationToken);
        Assert.Null(result);
    }

    [Theory]
    [InlineData("/api/v1/events/0")]
    [InlineData("/api/v1/events/01")]
    [InlineData("/api/v1/events/-1")]
    [InlineData("/api/v1/events/9223372036854775808")]
    [InlineData("/api/v1/events/1x")]
    public async Task ReportPrincipalRejectsInvalidEventIdBeforeDatabaseAccess(string path)
    {
        var guard = new ExactEventAuthorization(null!);
        var failure = await guard.CheckAsync(new Principal("api_key", 1, "viewer", ReportSubjectId: 2), path, TestContext.Current.CancellationToken);
        Assert.NotNull(failure); Assert.Equal(404, failure.StatusCode); Assert.Equal("event_not_found", failure.Code);
    }

    [Fact]
    public void MatchingGenericDomainClauseSurvivesOtherValidClauses()
    {
        var scope = JsonSerializer.SerializeToElement(new { mode = "restricted", clauses = new object[] {
            new { plugin_ids = new[] { "sli.file-audit" } },
            new { collection_scope_ids = new[] { "ad-domain:7" } }
        }});
        Assert.True(ExactEventScope.AllowsDomain(scope, 7));
        Assert.False(ExactEventScope.AllowsDomain(scope, 8));
    }

    [Fact]
    public async Task AuthenticatedReportKeyRequiresAtomicCurrentEventGrant()
    {
        var ct = TestContext.Current.CancellationToken;
        var binding = OwnedDatabaseBinding.FromEnvironment();
        Assert.Equal("7f76e02a-754d-435b-84d5-f16b96203c38", binding.RunId.ToString("D"));
        await using var database = await SyntheticDatabase.BorrowAsync(binding, ct);
        var connections = new Connections(database);
        await using var db = await database.OpenConnectionAsync(ct);
        string marker = "netevent_" + Guid.NewGuid().ToString("N");
        var tokens = new CredentialTokens();
        string token = "adl_" + tokens.NewSessionToken();
        using var eventFixture = JsonDocument.Parse(await File.ReadAllBytesAsync(Environment.GetEnvironmentVariable("SLI_REPORT_EVENT_FIXTURE")!, ct));
        long first = eventFixture.RootElement.GetProperty("first").GetInt64();
        long foreign = eventFixture.RootElement.GetProperty("foreign").GetInt64();
        long user = 0, key = 0;
        string? ownerSessionHash = null;
        Exception? primaryFailure = null;
        try
        {
            await using (var q = new NpgsqlCommand("insert into auth_users(username,password_hash,role,is_service) values(@name,'synthetic-no-password','viewer',true) returning id", db))
            { q.Parameters.AddWithValue("name", marker); user = Convert.ToInt64(await q.ExecuteScalarAsync(ct)); }
            await using (var q = new NpgsqlCommand("insert into auth_api_keys(key_prefix,key_hash,label,role,report_subject_id) values(@prefix,@hash,@label,'viewer',@user) returning id", db))
            { q.Parameters.AddWithValue("prefix", token[..12]); q.Parameters.AddWithValue("hash", tokens.Digest(token)); q.Parameters.AddWithValue("label", marker); q.Parameters.AddWithValue("user", user); key = Convert.ToInt64(await q.ExecuteScalarAsync(ct)); }
            await using (var q = new NpgsqlCommand("insert into access_capability_assignments(subject_type,subject_id,capability_id,effect,scope_json,business_reason) select 'user',@user,id,'allow','{\"kind\":\"all\"}'::jsonb,@reason from access_capabilities where capability_key=any(@caps)", db))
            { q.Parameters.AddWithValue("user", user); q.Parameters.AddWithValue("reason", marker); q.Parameters.AddWithValue("caps", new[] { "events.view", "field.raw_evidence", "field.technical", "field.security", "evidence.exact" }); Assert.Equal(5, await q.ExecuteNonQueryAsync(ct)); }
            await using (var q = new NpgsqlCommand("insert into access_report_assignments(subject_type,subject_id,report_key,effect,scope_json,field_categories,allowed_actions,source_type,business_reason) values('user',@user,'events.explorer','allow','{\"kind\":\"domain\",\"ids\":[99101]}'::jsonb,@fields,@actions,'temporary',@reason)", db))
            { q.Parameters.AddWithValue("user", user); q.Parameters.AddWithValue("fields", new[] { "raw_evidence", "technical", "security" }); q.Parameters.AddWithValue("actions", new[] { "view" }); q.Parameters.AddWithValue("reason", marker); await q.ExecuteNonQueryAsync(ct); }
            var context = new DefaultHttpContext(); context.Request.Method = "GET"; context.Request.Path = "/api/v1/events/" + first; context.Request.Headers.Authorization = "Bearer " + token;
            var authenticated = await new PrincipalAuthenticator(connections).AuthenticateAsync(context, ct);
            Assert.NotNull(authenticated.Principal); Assert.True(authenticated.Principal.RestrictedReportKey);
            var guard = new ExactEventAuthorization(connections);
            Assert.Null(await guard.CheckAsync(authenticated.Principal, "/api/v1/events/" + first, ct));
            Assert.Equal("event_not_found", (await guard.CheckAsync(authenticated.Principal, "/api/v1/events/" + foreign, ct))?.Code);
            Assert.Equal("event_not_found", (await guard.CheckAsync(authenticated.Principal, "/api/v1/events/9223372036854775807", ct))?.Code);
            long owner;
            await using (var q = new NpgsqlCommand("select o.user_id from access_platform_owners o join auth_users u on u.id=o.user_id where u.role='admin' and u.is_active order by o.user_id limit 1", db))
                owner = Convert.ToInt64(await q.ExecuteScalarAsync(ct));
            Assert.True(owner > 0);
            string session = await new SessionLifecycle(connections, tokens, TimeProvider.System).IssueAsync(new("session", owner, "admin"), false, ct);
            ownerSessionHash = tokens.Digest(session);
            var ownerRequest = new DefaultHttpContext(); ownerRequest.Request.Method = "GET"; ownerRequest.Request.Path = "/api/v1/events/1";
            ownerRequest.Request.Headers.Cookie = "adlog_session=" + session;
            var ownerAuth = await new PrincipalAuthenticator(connections).AuthenticateAsync(ownerRequest, ct);
            Assert.NotNull(ownerAuth.Principal);
            Assert.True((await new Sli.Server.Access.AccessFactsRepository(connections).LoadAsync(ownerAuth.Principal, ct)).IsOwner);
            var services = new ServiceCollection();
            services.AddSingleton<IPostgresConnectionFactory>(connections); services.AddSingleton(new TransportGate(new ConfigurationBuilder().Build()));
            services.AddReportKeyServices(); services.AddReportKeyRequestGate();
            using (var provider = services.BuildServiceProvider())
            {
                int reached = 0;
                var app = new ApplicationBuilder(provider).UseReportKeyRequestGate();
                app.Run(context => { reached++; context.Response.StatusCode = 204; return Task.CompletedTask; });
                var pipeline = app.Build();
                async Task<(int Status, string Code)> Request(string path)
                {
                    using var scope = provider.CreateScope(); var request = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
                    request.Response.Body = new MemoryStream(); request.Request.Method = "GET"; request.Request.Path = path;
                    request.Request.Headers.Authorization = "Bearer " + token; request.Request.Headers.Cookie = "adlog_session=" + session;
                    await pipeline(request); request.Response.Body.Position = 0;
                    if (request.Response.StatusCode == 204) return (204, "");
                    using var body = await JsonDocument.ParseAsync(request.Response.Body, cancellationToken: ct);
                    return (request.Response.StatusCode, body.RootElement.GetProperty("error").GetString()!);
                }
                Assert.Equal((204, ""), await Request("/api/v1/events/" + first));
                Assert.Equal((404, "event_not_found"), await Request("/api/v1/events/" + foreign));
                Assert.Equal((404, "event_not_found"), await Request("/api/v1/events/9223372036854775807"));
                Assert.Equal((403, "report_key_route_denied"), await Request("/api/auth/me"));
                Assert.Equal(1, reached);
            }
            async Task UpdateGrant(string sql, string[] values)
            {
                await using var q = new NpgsqlCommand(sql + " where subject_type='user' and subject_id=@user and business_reason=@reason", db);
                q.Parameters.AddWithValue("user", user); q.Parameters.AddWithValue("reason", marker); q.Parameters.AddWithValue("values", values);
                Assert.Equal(1, await q.ExecuteNonQueryAsync(ct));
            }
            var allFields = new[] { "raw_evidence", "technical", "security" };
            foreach (string missing in allFields)
            {
                await UpdateGrant("update access_report_assignments set field_categories=@values", allFields.Where(f => f != missing).ToArray());
                Assert.Equal("event_not_found", (await guard.CheckAsync(authenticated.Principal, "/api/v1/events/" + first, ct))?.Code);
            }
            await UpdateGrant("update access_report_assignments set field_categories=@values", new[] { "technical", "security" });
            await using (var split = new NpgsqlCommand("insert into access_report_assignments(subject_type,subject_id,report_key,effect,scope_json,field_categories,allowed_actions,source_type,business_reason) values('user',@user,'events.explorer','allow','{\"kind\":\"domain\",\"ids\":[99101]}'::jsonb,array['raw_evidence'],array['view'],'temporary',@reason)", db))
            { split.Parameters.AddWithValue("user", user); split.Parameters.AddWithValue("reason", marker); await split.ExecuteNonQueryAsync(ct); }
            Assert.Equal("event_not_found", (await guard.CheckAsync(authenticated.Principal, "/api/v1/events/" + first, ct))?.Code);
            await using (var split = new NpgsqlCommand("delete from access_report_assignments where subject_type='user' and subject_id=@user and business_reason=@reason and field_categories=array['raw_evidence']", db))
            { split.Parameters.AddWithValue("user", user); split.Parameters.AddWithValue("reason", marker); Assert.Equal(1, await split.ExecuteNonQueryAsync(ct)); }
            await UpdateGrant("update access_report_assignments set field_categories=@values", allFields);
            await UpdateGrant("update access_report_assignments set allowed_actions=@values", new[] { "export" });
            Assert.Equal("event_not_found", (await guard.CheckAsync(authenticated.Principal, "/api/v1/events/" + first, ct))?.Code);
            await UpdateGrant("update access_report_assignments set allowed_actions=@values", new[] { "view" });
            await using (var q = new NpgsqlCommand("update access_report_assignments set valid_until=now()-interval '1 second' where subject_type='user' and subject_id=@user and business_reason=@reason", db))
            { q.Parameters.AddWithValue("user", user); q.Parameters.AddWithValue("reason", marker); Assert.Equal(1, await q.ExecuteNonQueryAsync(ct)); }
            Assert.Equal("event_not_found", (await guard.CheckAsync(authenticated.Principal, "/api/v1/events/" + first, ct))?.Code);
            await using (var q = new NpgsqlCommand("update access_report_assignments set valid_until=null,effect='deny' where subject_type='user' and subject_id=@user and business_reason=@reason", db))
            { q.Parameters.AddWithValue("user", user); q.Parameters.AddWithValue("reason", marker); Assert.Equal(1, await q.ExecuteNonQueryAsync(ct)); }
            Assert.Equal("event_not_found", (await guard.CheckAsync(authenticated.Principal, "/api/v1/events/" + first, ct))?.Code);
        }
        catch (Exception error) { primaryFailure = error; throw; }
        finally
        {
            var failures = new List<string>();
            foreach (var step in new[] {
                ("sessions", "delete from auth_sessions where token_hash=@session"),
                ("grants", "delete from access_report_assignments where subject_type='user' and subject_id=@user and business_reason=@name"),
                ("capabilities", "delete from access_capability_assignments where subject_type='user' and subject_id=@user and business_reason=@name"),
                ("key", "delete from auth_api_keys where id=@key and label=@name"),
                ("subject", "delete from auth_users where id=@user and username=@name") })
            {
                try
                {
                    await using var cleanup = new NpgsqlCommand(step.Item2, db);
                    cleanup.Parameters.AddWithValue("name", marker); cleanup.Parameters.AddWithValue("user", user); cleanup.Parameters.AddWithValue("key", key);
                    cleanup.Parameters.AddWithValue("session", NpgsqlTypes.NpgsqlDbType.Text, (object?)ownerSessionHash ?? DBNull.Value);
                    await cleanup.ExecuteNonQueryAsync(CancellationToken.None);
                }
                catch (Exception) { failures.Add(step.Item1); }
            }
            if (failures.Count > 0)
            {
                string message = "owned_fixture_cleanup_failed:" + string.Join(',', failures);
                if (primaryFailure is null) throw new InvalidOperationException(message);
                primaryFailure.Data["cleanup"] = message;
            }
        }
    }
}
