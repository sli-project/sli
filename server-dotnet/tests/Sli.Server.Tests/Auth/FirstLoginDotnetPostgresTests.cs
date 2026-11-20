using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
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
    [Fact]
    public async Task Installer_code_opens_owner_session_and_built_app_once_without_disclosing_credentials()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString);
        await admin.OpenAsync(ct);
        await using (var owner = new NpgsqlCommand("""
            insert into access_platform_owners(user_id,owner_key,business_reason)
            select id,'primary','Synthetic first login' from auth_users where username='platform-owner'
            on conflict(owner_key) do nothing
            """, admin)) await owner.ExecuteNonQueryAsync(ct);

        // Execute the installer's real rotation/issuance path, including its
        // argon2-cffi hash and committed PostgreSQL update. Only the privileged
        // host filesystem/connection boundaries are redirected to this fixture.
        var codes = await IssueInstallerCodesAsync(fixture, ct);
        string code = codes.Current, foreignCode = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        Assert.NotEqual(code, codes.Previous);
        const string password = "Synthetic-first-owner-password-180!";
        var logs = new ConcurrentQueue<string>();
        string root = Repository();
        using (var host = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(SafeTestEnvironment.ConfigureApiHost)
            .WithWebHostBuilder(builder => builder
                .ConfigureLogging(logging => logging.ClearProviders().SetMinimumLevel(LogLevel.Trace).AddProvider(new CapturedLogs(logs)))
                .ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user"),
                    ["Sli:AgentMtlsCaFile"] = "", ["Sli:TrustedProxies"] = "",
                    ["Sli:AuthRequired"] = "1", ["Sli:AllowUnauthenticated"] = "0",
                    ["Sli:AuthCookieSecure"] = "1", ["Sli:AuthAllowInsecureHttp"] = "0",
                    ["SLI_OWNER_SETUP"] = "1", ["Sli:OwnerSetup"] = "1",
                    ["Sli:WebRoot"] = Path.Combine(root, "web/app"),
                    ["Sli:ReactRoot"] = Path.Combine(root, "web/app/react"),
                    ["Sli:ProjectRoot"] = root,
                    ["Sli:DataDirectory"] = Path.Combine(fixture.Pg.Root, "app-data"),
                    ["Sli:LogDirectory"] = Path.Combine(fixture.Pg.Root, "app-logs"),
                    ["ADLOG_MAX_LOGIN_FAILURES"] = "30"
                }))))
        {
            // Run the product Program and its middleware/routes. TestServer
            // supplies only HTTPS transport; authentication and SQL stay real.
            using var client = new HttpClient(host.Server.CreateHandler(context =>
                context.Features.Get<IHttpRequestFeature>()!.RawTarget = context.Request.Path + context.Request.QueryString))
                { BaseAddress = new Uri("https://localhost") };
            using (var anonymous = await client.GetAsync("/api/auth/me", ct))
                Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
            using (var page = await client.GetAsync("/api/auth/bootstrap", ct))
            {
                Assert.Equal(HttpStatusCode.OK, page.StatusCode);
                Assert.Equal("text/html", page.Content.Headers.ContentType!.MediaType);
                string html = await page.Content.ReadAsStringAsync(ct);
                Assert.Contains("<form>", html);
                Assert.DoesNotContain(code, html);
            }
            using (var ordinaryLogin = await PostJsonAsync(client, "/api/auth/login", new { username = "platform-owner", password = code }, ct))
                Assert.Equal(HttpStatusCode.Unauthorized, ordinaryLogin.StatusCode);

            async Task<string> Denied(string submitted)
            {
                using var response = await PostJsonAsync(client, "/api/auth/bootstrap", new { code = submitted, password }, ct);
                Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
                Assert.False(response.Headers.Contains("Set-Cookie"));
                return await response.Content.ReadAsStringAsync(ct);
            }
            string foreignDenial = await Denied(foreignCode);
            Assert.Equal(foreignDenial, await Denied(codes.Previous));
            await using (var expire = new NpgsqlCommand("update auth_users set updated_at=clock_timestamp()-interval '25 hours' where username='platform-owner'", admin))
                Assert.Equal(1, await expire.ExecuteNonQueryAsync(ct));
            string expiredDenial = await Denied(code);
            Assert.Equal(foreignDenial, expiredDenial);
            await using (var pending = new NpgsqlCommand("select last_login_at is null from auth_users where username='platform-owner'", admin))
                Assert.Equal(true, await pending.ExecuteScalarAsync(ct));
            await using (var reissue = new NpgsqlCommand("update auth_users set updated_at=clock_timestamp() where username='platform-owner'", admin))
                Assert.Equal(1, await reissue.ExecuteNonQueryAsync(ct));

            using var success = await PostJsonAsync(client, "/api/auth/bootstrap", new { code, password }, ct);
            Assert.Equal(HttpStatusCode.OK, success.StatusCode);
            string cookie = Assert.Single(success.Headers.GetValues("Set-Cookie"));
            Assert.Contains("HttpOnly", cookie);
            Assert.Contains("Secure", cookie);
            Assert.Contains("SameSite=Strict", cookie);
            cookie = cookie.Split(';')[0];
            client.DefaultRequestHeaders.Add("Cookie", cookie);
            using (var me = await client.GetAsync("/api/auth/me", ct))
            {
                Assert.Equal(HttpStatusCode.OK, me.StatusCode);
                using var body = JsonDocument.Parse(await me.Content.ReadAsStringAsync(ct));
                Assert.True(body.RootElement.GetProperty("authenticated").GetBoolean());
                var principal = body.RootElement.GetProperty("principal");
                Assert.Equal("session", principal.GetProperty("type").GetString());
                Assert.Equal("platform-owner", principal.GetProperty("username").GetString());
                Assert.Equal("admin", principal.GetProperty("role").GetString());
            }
            string token = cookie[(cookie.IndexOf('=') + 1)..];
            await using (var persisted = new NpgsqlCommand("""
                select count(*) from auth_sessions s join auth_users u on u.id=s.user_id
                join access_platform_owners o on o.user_id=u.id
                where s.token_hash=@hash and s.revoked_at is null and s.expires_at>clock_timestamp()
                  and u.username='platform-owner' and u.last_login_at is not null and o.owner_key='primary'
                """, admin))
            {
                persisted.Parameters.AddWithValue("hash", Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token))));
                Assert.Equal(1L, await persisted.ExecuteScalarAsync(ct));
            }
            string index = await File.ReadAllTextAsync(Path.Combine(root, "web/app/react/index.html"), ct);
            // HTML gains a random CSP nonce; all other bytes must be the shipped
            // frontend build, and its actual JS must also be served by Program.
            foreach (string path in new[] { "/", "/app", "/app/" })
            {
                using var page = await client.GetAsync(path, ct);
                Assert.Equal(HttpStatusCode.OK, page.StatusCode);
                Assert.Equal("text/html", page.Content.Headers.ContentType!.MediaType);
                Assert.Equal(index, Regex.Replace(await page.Content.ReadAsStringAsync(ct), " nonce=\"[A-Za-z0-9_-]+\"", ""));
            }
            string asset = Regex.Match(index, "src=\"(/app/assets/[^\"]+\\.js)\"").Groups[1].Value;
            Assert.NotEmpty(asset);
            using (var script = await client.GetAsync(asset, ct))
            {
                Assert.Equal(HttpStatusCode.OK, script.StatusCode);
                Assert.Equal(await File.ReadAllBytesAsync(Path.Combine(root, "web/app/react", asset[5..]), ct),
                    await script.Content.ReadAsByteArrayAsync(ct));
            }
            client.DefaultRequestHeaders.Remove("Cookie");
            Assert.Equal(foreignDenial, await Denied(code));
            using (var closed = await client.GetAsync("/api/auth/bootstrap", ct))
                Assert.Equal(HttpStatusCode.NotFound, closed.StatusCode);
            using (var ordinaryLogin = await PostJsonAsync(client, "/api/auth/login", new { username = "platform-owner", password }, ct))
                Assert.Equal(HttpStatusCode.OK, ordinaryLogin.StatusCode);
        }
        string diagnostics = string.Join('\n', logs) + await fixture.Pg.DiagnosticsAsync(ct);
        await using (var audit = new NpgsqlCommand("select coalesce(jsonb_agg(to_jsonb(a))::text,'[]') from auth_audit a", admin))
            diagnostics += (string?)await audit.ExecuteScalarAsync(ct);
        Assert.DoesNotContain(code, diagnostics);
        Assert.DoesNotContain(foreignCode, diagnostics);
        Assert.DoesNotContain(codes.Previous, diagnostics);
        Assert.DoesNotContain(password, diagnostics);
        Assert.NotEmpty(logs);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    private static async Task<HttpResponseMessage> PostJsonAsync(HttpClient client, string path, object payload, CancellationToken ct)
    {
        using var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        return await client.PostAsync(path, content, ct);
    }

    private static async Task<(string Previous, string Current)> IssueInstallerCodesAsync(SqlPostgresFixture fixture, CancellationToken ct)
    {
        const string script = """
            import json, sys
            from pathlib import Path
            from unittest.mock import patch
            import psycopg
            from deploy.linux import native_setup as setup
            request = json.load(sys.stdin)
            directory = Path(request['directory']).resolve()
            directory.mkdir()
            secret = directory / 'platform_owner_password'
            secret.write_text('synthetic-unissued-code', encoding='utf-8')
            (directory / 'postgres_password').write_text('synthetic-only', encoding='utf-8')
            connect = psycopg.connect
            def trusted(path):
                assert path.parent.resolve() == directory
                return path.read_bytes()
            def atomic(path, value):
                assert path.parent.resolve() == directory
                path.write_text(json.dumps(value), encoding='utf-8')
            with patch.object(setup.install, 'SECRETS', directory), patch.object(setup.install, 'STATE', directory), \
                 patch.object(setup.install, 'trusted', trusted), patch.object(setup.install, 'atomic', atomic), \
                 patch.object(psycopg, 'connect', lambda **kwargs: connect(**request['postgres'])):
                previous = setup.owner_code(new=True)
                current = setup.owner_code(new=True)
                assert secret.read_text(encoding='utf-8').strip() == current
                assert setup.owner_code() == 'pending'
                assert setup.owner_code(check_only=True) == 'unclaimed'
            print(json.dumps(dict(previous=previous, current=current)))
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
        start.ArgumentList.Add("-B"); start.ArgumentList.Add("-c"); start.ArgumentList.Add(script);
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync(ct);
        var stderr = process.StandardError.ReadToEndAsync(ct);
        try
        {
            await process.StandardInput.WriteAsync(JsonSerializer.Serialize(new
            {
                directory = Path.Combine(fixture.Pg.Root, "installer"),
                postgres = new { host = dsn.Host, port = dsn.Port, dbname = dsn.Database, user = dsn.Username }
            }));
            process.StandardInput.Close();
            await process.WaitForExitAsync(ct);
            string error = await stderr;
            Assert.True(process.ExitCode == 0, error.Contains("ModuleNotFoundError")
                ? "Python for the installer test lacks a required module (argon2-cffi or psycopg); set SLI_TEST_PYTHON to an interpreter that has them. " + error
                : "Synthetic installer failed: " + error);
            using var result = JsonDocument.Parse(await stdout);
            return (result.RootElement.GetProperty("previous").GetString()!, result.RootElement.GetProperty("current").GetString()!);
        }
        finally
        {
            if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); }
        }
    }

    private static string Repository([System.Runtime.CompilerServices.CallerFilePath] string path = "") =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(path)!, "../../../.."));

    private sealed class CapturedLogs(ConcurrentQueue<string> events) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new Capture(events);
        public void Dispose() { }
        private sealed class Capture(ConcurrentQueue<string> events) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel level) => true;
            public void Log<TState>(LogLevel level, EventId id, TState state, Exception? error, Func<TState, Exception?, string> formatter)
                => events.Enqueue(formatter(state, error) + error?.ToString());
        }
    }
}
