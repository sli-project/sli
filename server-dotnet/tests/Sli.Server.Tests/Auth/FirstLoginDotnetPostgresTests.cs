using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text.Json;
using System.Text;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Npgsql;
using Sli.Server.Tests.Domains;
using Xunit;

namespace Sli.Server.Tests.Auth;

public sealed class FirstLoginDotnetPostgresTests
{
    private const string Login = "/api/auth/login";
    private const string Change = "/api/auth/change-initial-password";
    private const string InitialPassword = "admin";
    private const string NewPassword = "synthetic-first-login-replacement-91!";
    private const string NextPassword = "synthetic-second-login-replacement-82!";

    [Fact]
    public async Task Setup_password_allows_only_change_and_logout_and_root_reset_requires_a_new_change()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await StartAsync(fixture, ct);
        Assert.Equal("admin", await SetupAsync(fixture, "prepare", ct));

        var logs = new ConcurrentQueue<string>();
        using var host = OpenHost(fixture, logs);
        using var browser = OpenClient(host);
        using var other = OpenClient(host);
        using (var anonymous = await ChangeAsync(browser, NewPassword, NewPassword, ct))
            Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        SetCookie(browser, await SignInAsync(browser, InitialPassword, true, ct));
        SetCookie(other, await SignInAsync(other, InitialPassword, true, ct));

        foreach (string endpoint in new[] { "/api/auth/me", "/api/health", "/api/auth/users", "/api/v1/access/me", "/api/unknown" })
        {
            using var denied = await browser.GetAsync(endpoint, ct);
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            Assert.Equal("password_change_required", await ErrorAsync(denied, ct));
        }
        using (var foreignLogout = new HttpRequestMessage(HttpMethod.Post, "/api/auth/logout") { Content = JsonBody(new { }) })
        {
            foreignLogout.Headers.Add("Origin", "https://foreign.example.test");
            using var denied = await other.SendAsync(foreignLogout, ct);
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            Assert.Equal("cross_origin_request_rejected", await ErrorAsync(denied, ct));
        }
        using (var logout = await other.PostAsync("/api/auth/logout", JsonBody(new { }), ct))
        {
            Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
            Assert.Equal("adlog_session=", ReadCookie(logout));
            Assert.Contains("Max-Age=0", Assert.Single(logout.Headers.GetValues("Set-Cookie")));
        }
        using (var replay = await ChangeAsync(other, NextPassword, NextPassword, ct))
            Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        SetCookie(other, null);
        SetCookie(other, await SignInAsync(other, InitialPassword, true, ct));
        using (var app = await browser.GetAsync("/app", ct))
        {
            Assert.Equal(HttpStatusCode.Redirect, app.StatusCode);
            Assert.StartsWith("/login/change-password", app.Headers.Location!.OriginalString);
        }
        using (var page = await browser.GetAsync("/login/change-password", ct))
        {
            Assert.Equal(HttpStatusCode.OK, page.StatusCode);
            Assert.Equal("text/html", page.Content.Headers.ContentType!.MediaType);
        }
        using (var origin = await ChangeAsync(browser, NewPassword, NewPassword, ct, origin: "https://foreign.example.test"))
            Assert.Equal(HttpStatusCode.Forbidden, origin.StatusCode);
        using (var insecure = await ChangeAsync(browser, NewPassword, NewPassword, ct, insecure: true))
            Assert.Equal(HttpStatusCode.Forbidden, insecure.StatusCode);
        foreach (string invalid in new[] { InitialPassword, "short", "synthetic\0password", new string('a', 4097), string.Concat(Enumerable.Repeat("🔐", 11)) })
        {
            using var rejected = await ChangeAsync(browser, invalid, invalid, ct);
            Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        }
        using (var mismatch = await ChangeAsync(browser, NewPassword, NextPassword, ct))
            Assert.Equal(HttpStatusCode.BadRequest, mismatch.StatusCode);
        using (var changed = await ChangeAsync(browser, NewPassword, NewPassword, ct))
        {
            Assert.Equal(HttpStatusCode.OK, changed.StatusCode);
            SetCookie(browser, ReadCookie(changed));
        }
        Assert.Null(await SetupAsync(fixture, "status", ct));
        await AssertOwnerAsync(browser, ct);
        using (var removed = await browser.GetAsync("/api/auth/bootstrap", ct))
            Assert.Equal(HttpStatusCode.NotFound, removed.StatusCode);
        using (var removed = await browser.PostAsync("/api/auth/bootstrap", JsonBody(new { }), ct))
            Assert.Equal(HttpStatusCode.NotFound, removed.StatusCode);
        using (var replay = await ChangeAsync(other, NextPassword, NextPassword, ct))
            Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        SetCookie(other, null);
        using (var stale = await LoginAsync(other, InitialPassword, ct))
            Assert.Equal(HttpStatusCode.Unauthorized, stale.StatusCode);
        await SignInAsync(other, NewPassword, false, ct);

        Assert.Equal("admin", await SetupAsync(fixture, "reset", ct));
        using (var stale = await browser.GetAsync("/api/auth/me", ct))
            Assert.Equal(HttpStatusCode.Unauthorized, stale.StatusCode);
        using (var stale = await LoginAsync(other, NewPassword, ct))
            Assert.Equal(HttpStatusCode.Unauthorized, stale.StatusCode);
        SetCookie(browser, await SignInAsync(other, InitialPassword, true, ct));
        using (var changed = await ChangeAsync(browser, NextPassword, NextPassword, ct))
        {
            Assert.Equal(HttpStatusCode.OK, changed.StatusCode);
            SetCookie(browser, ReadCookie(changed));
        }
        await AssertOwnerAsync(browser, ct);
        Assert.NotEmpty(logs);
        string diagnostics = string.Join('\n', logs) + await fixture.Pg.DiagnosticsAsync(ct);
        foreach (string credential in new[] { NewPassword, NextPassword })
            Assert.DoesNotContain(credential, diagnostics);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Guessing_blocks_correct_initial_password_on_the_standard_login_route()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await StartAsync(fixture, ct);
        Assert.Equal("admin", await SetupAsync(fixture, "prepare", ct));
        using var host = OpenHost(fixture, new());
        using var browser = OpenClient(host);
        for (int i = 0; i < 5; i++)
        {
            using var wrong = await LoginAsync(browser, "synthetic-wrong-password", ct);
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
            Assert.False(wrong.Headers.Contains("Set-Cookie"));
        }
        using var blocked = await LoginAsync(browser, InitialPassword, ct, "ADMIN");
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
        Assert.Equal("login_temporarily_locked", await ErrorAsync(blocked, ct));
        Assert.NotNull(blocked.Headers.RetryAfter);
        Assert.False(blocked.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task Insecure_first_login_does_not_persist_a_session_when_http_is_allowed()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await StartAsync(fixture, ct);
        Assert.Equal("admin", await SetupAsync(fixture, "prepare", ct));
        using var host = OpenHost(fixture, new(), allowHttp: true);
        using var browser = OpenClient(host);
        browser.BaseAddress = new Uri("http://localhost");
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString);
        await db.OpenAsync(ct);
        await using var count = new NpgsqlCommand("select count(*) from auth_sessions", db);
        var before = await count.ExecuteScalarAsync(ct);
        using var insecure = await LoginAsync(browser, InitialPassword, ct);
        Assert.Equal(HttpStatusCode.Forbidden, insecure.StatusCode);
        Assert.Equal("secure_transport_required", await ErrorAsync(insecure, ct));
        Assert.False(insecure.Headers.Contains("Set-Cookie"));
        Assert.Equal(before, await count.ExecuteScalarAsync(ct));
    }

    [Fact]
    public async Task Reset_preserves_the_username_of_an_existing_owner()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await StartAsync(fixture, ct);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString);
        await db.OpenAsync(ct);
        await using var markUsed = new NpgsqlCommand("update auth_users set last_login_at=now() where username='platform-owner'", db);
        await markUsed.ExecuteNonQueryAsync(ct);
        Assert.Null(await SetupAsync(fixture, "prepare", ct));
        Assert.Equal("platform-owner", await SetupAsync(fixture, "reset", ct));
        using var host = OpenHost(fixture, new());
        using var browser = OpenClient(host);
        using var login = await LoginAsync(browser, InitialPassword, ct, "platform-owner");
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        using var body = JsonDocument.Parse(await login.Content.ReadAsStringAsync(ct));
        Assert.True(body.RootElement.GetProperty("password_change_required").GetBoolean());
    }

    private static async Task StartAsync(SqlPostgresFixture fixture, CancellationToken ct)
    {
        await fixture.StartAsync(ct);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString);
        await db.OpenAsync(ct);
        await using var insert = new NpgsqlCommand("""
            insert into access_platform_owners(user_id,owner_key,business_reason)
            select id,'primary','Synthetic first login' from auth_users where username='platform-owner'
            on conflict(owner_key) do nothing
            """, db);
        await insert.ExecuteNonQueryAsync(ct);
    }

    private static WebApplicationFactory<Program> OpenHost(SqlPostgresFixture fixture, ConcurrentQueue<string> logs, bool allowHttp = false)
    {
        string root = Repository();
        return new WebApplicationFactory<Program>()
            .WithWebHostBuilder(SafeTestEnvironment.ConfigureApiHost)
            .WithWebHostBuilder(builder => builder
                .ConfigureLogging(logging => logging.ClearProviders().SetMinimumLevel(LogLevel.Trace).AddProvider(new CaptureProvider(logs)))
                .ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user"),
                    ["Sli:AgentMtlsCaFile"] = "", ["Sli:TrustedProxies"] = "",
                    ["Sli:AuthRequired"] = "1", ["Sli:AuthCookieSecure"] = "1", ["Sli:AuthAllowInsecureHttp"] = allowHttp ? "1" : "0",
                    ["Sli:WebRoot"] = Path.Combine(root, "web/app"),
                    ["Sli:ProjectRoot"] = root,
                    ["Sli:DataDirectory"] = Path.Combine(fixture.Pg.Root, "app-data"),
                    ["Sli:LogDirectory"] = Path.Combine(fixture.Pg.Root, "app-logs"),
                    ["ADLOG_MAX_LOGIN_FAILURES"] = "30"
                })));
    }

    private static HttpClient OpenClient(WebApplicationFactory<Program> host) =>
        new(host.Server.CreateHandler(context =>
            context.Features.Get<IHttpRequestFeature>()!.RawTarget = context.Request.Path + context.Request.QueryString))
        { BaseAddress = new Uri("https://localhost") };

    private static void SetCookie(HttpClient client, string? cookie)
    {
        client.DefaultRequestHeaders.Remove("Cookie");
        if (cookie is not null) client.DefaultRequestHeaders.Add("Cookie", cookie);
    }

    private static string ReadCookie(HttpResponseMessage response)
    {
        string cookie = Assert.Single(response.Headers.GetValues("Set-Cookie"));
        Assert.Contains("HttpOnly", cookie);
        Assert.Contains("Secure", cookie);
        Assert.Contains("SameSite=Strict", cookie);
        return cookie.Split(';')[0];
    }

    private static async Task AssertOwnerAsync(HttpClient client, CancellationToken ct)
    {
        using var response = await client.GetAsync("/api/auth/me", ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var principal = body.RootElement.GetProperty("principal");
        Assert.Equal("admin", principal.GetProperty("username").GetString());
        Assert.Equal("admin", principal.GetProperty("role").GetString());
    }

    private static async Task<string> SignInAsync(HttpClient client, string password, bool restricted, CancellationToken ct)
    {
        using var response = await LoginAsync(client, password, ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        string json = await response.Content.ReadAsStringAsync(ct);
        Assert.DoesNotContain(password, json);
        using var body = JsonDocument.Parse(json);
        Assert.Equal(restricted, body.RootElement.TryGetProperty("password_change_required", out var value) && value.GetBoolean());
        if (restricted) Assert.False(body.RootElement.TryGetProperty("principal", out _));
        return ReadCookie(response);
    }

    private static Task<HttpResponseMessage> LoginAsync(HttpClient client, string password, CancellationToken ct, string username = "admin") =>
        client.PostAsync(Login, JsonBody(new { username, password, remember = true }), ct);

    private static StringContent JsonBody(object body) =>
        new(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");

    private static async Task<string?> ErrorAsync(HttpResponseMessage response, CancellationToken ct)
    {
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        return body.RootElement.GetProperty("error").GetString();
    }

    private static async Task<HttpResponseMessage> ChangeAsync(HttpClient client, string password, string repeat, CancellationToken ct,
        string? origin = null, bool insecure = false)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, insecure ? "http://localhost" + Change : Change)
        {
            Content = JsonBody(new { password, repeat })
        };
        if (origin is not null) request.Headers.TryAddWithoutValidation("Origin", origin);
        return await client.SendAsync(request, ct);
    }

    private static string Repository([System.Runtime.CompilerServices.CallerFilePath] string path = "") =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(path)!, "../../../.."));

    private static async Task<string?> SetupAsync(SqlPostgresFixture fixture, string mode, CancellationToken ct)
    {
        const string script = """
            import contextlib, json, os, sys
            from pathlib import Path
            from unittest.mock import patch
            import psycopg
            from deploy.linux import native_setup as setup

            request = json.load(sys.stdin)
            real_connect = psycopg.connect
            with contextlib.ExitStack() as stack:
                for context in [
                    patch.object(setup.install, 'trusted', return_value=b'synthetic-db-password'),
                    patch.object(setup.install, 'site_configuration', return_value={'owner_setup': True}),
                    patch.object(setup.install, 'inventory', return_value=(Path.cwd(), {'python': sys.executable}, None)),
                    patch.object(setup.install, 'trusted_path'),
                    patch.object(os, 'geteuid', return_value=0, create=True),
                    patch.object(psycopg, 'connect', lambda **kwargs: real_connect(**request['postgres'])),
                ]:
                    stack.enter_context(context)
                mode = request['mode']
                if mode == 'prepare':
                    assert setup.main(['--initial-admin', 'prepare', 'synthetic-release']) == 0
                    mode = 'status'
                assert setup.main(['--initial-admin', mode, 'synthetic-release']) == 0
            """;
        var dsn = new NpgsqlConnectionStringBuilder(fixture.Pg.ConnectionString);
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("SLI_TEST_PYTHON") ??
            (OperatingSystem.IsWindows() ? "python" : "python3"))
        {
            WorkingDirectory = Repository(), UseShellExecute = false, CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden, RedirectStandardInput = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        SafeTestEnvironment.Apply(start);
        start.ArgumentList.Add("-B");
        start.ArgumentList.Add("-c");
        start.ArgumentList.Add(script);
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync(ct);
        var stderr = process.StandardError.ReadToEndAsync(ct);
        try
        {
            await process.StandardInput.WriteAsync(JsonSerializer.Serialize(new
            {
                mode,
                postgres = new { host = dsn.Host, port = dsn.Port, dbname = dsn.Database, user = dsn.Username }
            }));
            process.StandardInput.Close();
            await process.WaitForExitAsync(ct);
            Assert.True(process.ExitCode == 0, "Synthetic setup helper failed: " + await stderr);
            string result = (await stdout).Trim();
            if (result.Length == 0) return null;
            return JsonSerializer.Deserialize<string>(result);
        }
        finally
        {
            if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); }
        }
    }

    private sealed class CaptureProvider(ConcurrentQueue<string> logs) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new CaptureLogger(logs);
        public void Dispose() { }

        private sealed class CaptureLogger(ConcurrentQueue<string> events) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel level) => true;
            public void Log<TState>(LogLevel level, EventId id, TState state, Exception? error,
                Func<TState, Exception?, string> formatter) => events.Enqueue(formatter(state, error) + error);
        }
    }
}
