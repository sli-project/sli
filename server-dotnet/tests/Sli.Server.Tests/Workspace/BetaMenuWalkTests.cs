using System.Diagnostics;
using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sli.Server.Notifications;
using Sli.Server.Tests.Ad;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Domains;
using Sli.Server.Tests.Notifications;
using Sli.Server.Tests.Storage;
using Sli.Server.Tests.Vpn;
using Xunit;

namespace Sli.Server.Tests.Workspace;

[Collection("Semantic producer environment")]
public sealed class BetaMenuWalkTests
{
    [Fact]
    public async Task Owner_can_open_every_beta_menu_destination()
    {
        Assert.SkipWhen(Environment.GetEnvironmentVariable("SLI_MENU_WALK_RESULTS") is null,
            "Run npm run beta:menu-walk -- --results <directory>");
        var ct = TestContext.Current.CancellationToken;
        string root = PostCollectionPostgres.Repository();
        string results = Path.GetFullPath(Environment.GetEnvironmentVariable("SLI_MENU_WALK_RESULTS")!);
        Directory.CreateDirectory(results);
        Console.WriteLine("menu-walk: creating owned PostgreSQL cluster and applying schema");
        using var heartbeat = new Timer(_ => Console.WriteLine("menu-walk: preparing owned database / .NET host"), null, 10_000, 10_000);
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        var directory = await NewLogonPairsNativeFixture.SeedAsync(fixture.Pg, DateTimeOffset.UtcNow, 3, ct);
        await using (var db = await fixture.Pg.OpenAsync(ct))
        {
            var events = await ShortEventAdmissionPostgresTests.SeedAsync(db, ct);
            await ShortEventAdmissionPostgresTests.WriteAsync(fixture, events, ct);
            await NewLogonPairsNativeFixture.ExecuteAsync(db, """
                insert into findings(fingerprint,rule_code,title,target,actor,first_seen_utc,last_seen_utc,severity,status)
                select 'menu-walk-'||n,'semantic.qw.agent-tamper','Изменена служба агента',
                    'dc-1.example.test','synthetic-user-'||n,now()::text,now()::text,'high','new'
                from generate_series(0,2) n
                """, ct);
        }
        string token = await fixture.SeedOwnerAsync(ct);
        using var accounting = await VpnAccountingPostgresFixture.RegisterAsync(fixture, ct);
        // Real setup domain logic on an empty test filesystem. Only the
        // privileged socket transport is replaced, as in its endpoint tests.
        // No provider response is consumed and no credentials are configured.
        var setupFiles = new NotificationMemoryFiles();
        var setupBot = new NotificationBotStub { Error = "telegram_setup_network" };
        var setup = new NotificationSetupStub(new NotificationSetupService(setupFiles, setupBot, "https://example.test"));
        using var host = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(SafeTestEnvironment.ConfigureApiHost)
            .WithWebHostBuilder(builder => builder
                .ConfigureLogging(logging => logging.ClearProviders())
                .ConfigureServices(services => services.AddSingleton<INotificationSetupClient>(setup))
                .ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user"),
                    ["Sli:AgentMtlsCaFile"] = "", ["Sli:TrustedProxies"] = "",
                    ["Sli:AuthRequired"] = "1", ["Sli:AllowUnauthenticated"] = "0",
                    ["Sli:AuthAllowInsecureHttp"] = "1", ["Sli:AuthCookieSecure"] = "0",
                    ["Sli:OwnerSetup"] = "0", ["Sli:ProjectRoot"] = root,
                    ["Sli:WebRoot"] = Path.Combine(root, "web/app"),
                    ["Sli:ReactRoot"] = Path.Combine(root, "artifacts/frontend/react-build"),
                    ["Sli:DataDirectory"] = Path.Combine(fixture.Pg.Root, "app-data"),
                    ["Sli:LogDirectory"] = Path.Combine(fixture.Pg.Root, "app-logs")
                })));
        host.UseKestrel(options => options.Listen(IPAddress.Loopback, 0));
        using var client = host.CreateClient();
        heartbeat.Change(Timeout.Infinite, Timeout.Infinite);
        Assert.True(client.BaseAddress!.IsLoopback);
        // Validate the same real API the browser uses, before entering the menu walk.
        client.DefaultRequestHeaders.Add("Cookie", "adlog_session=" + token);
        const string vpnDeclaration = "/api/v2/reports/vpn.connections";
        using var disabled = await client.GetAsync(vpnDeclaration, ct);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, disabled.StatusCode);
        using var disabledBody = JsonDocument.Parse(await disabled.Content.ReadAsStringAsync(ct));
        Assert.Equal("module_disabled", disabledBody.RootElement.GetProperty("error").GetString());
        Assert.False(disabledBody.RootElement.TryGetProperty("plugin", out _));

        await VpnAccountingPostgresFixture.SetEnabledAsync(fixture, true, ct);
        using var definition = await client.GetAsync(vpnDeclaration, ct);
        Assert.Equal(HttpStatusCode.OK, definition.StatusCode);
        using var declaration = JsonDocument.Parse(await definition.Content.ReadAsStringAsync(ct));
        var plugin = declaration.RootElement.GetProperty("plugin");
        Assert.Equal("sli.remote-access", plugin.GetProperty("plugin_id").GetString());
        Assert.Equal("enabled", plugin.GetProperty("state").GetString());
        Assert.False(plugin.GetProperty("read_only").GetBoolean());
        Assert.True(declaration.RootElement.GetProperty("access").GetProperty("allowed").GetBoolean());
        Assert.Contains(declaration.RootElement.GetProperty("filter_options").GetProperty("domain").EnumerateArray(),
            item => item.GetProperty("value").GetString() == directory.DomainId.ToString(System.Globalization.CultureInfo.InvariantCulture));
        using var data = await client.GetAsync($"/api/v2/reports/vpn.connections/data?domain={directory.DomainId}&period=7d", ct);
        Assert.Equal(HttpStatusCode.OK, data.StatusCode);
        using var accountingResult = JsonDocument.Parse(await data.Content.ReadAsStringAsync(ct));
        Assert.Equal("domain_history", accountingResult.RootElement.GetProperty("coverage").GetProperty("accounting_scope").GetString());
        var start = new ProcessStartInfo("node")
        {
            WorkingDirectory = root, UseShellExecute = false, CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        start.ArgumentList.Add("frontend/tests/menu-walk/walk.mjs");
        // Session travels through stdin only: no argv, environment, traces or saved browser state.
        using var browser = Process.Start(start) ?? throw new InvalidOperationException("Cannot start menu walk");
        async Task RelayProgressAsync()
        {
            while (await browser.StandardOutput.ReadLineAsync(ct) is { } line) Console.WriteLine(line);
        }
        var output = RelayProgressAsync();
        var error = browser.StandardError.ReadToEndAsync(ct);
        try
        {
            await browser.StandardInput.WriteLineAsync(JsonSerializer.Serialize(new { url = client.BaseAddress.AbsoluteUri, token, results }));
            browser.StandardInput.Close();
            await browser.WaitForExitAsync(ct);
            await output;
            Assert.Empty(setupBot.Calls);
            Assert.Empty(setupFiles.Writes);
            Assert.True(browser.ExitCode == 0, "Menu walk failed; see " + Path.Combine(results, "menu-walk.md") + "\n" + await error);
        }
        finally { if (!browser.HasExited) browser.Kill(entireProcessTree: true); }
    }
}
