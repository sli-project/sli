using System.Net;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Sli.Server.Compatibility;
using Sli.Server.Tests.Operations;
using Sli.Server.Workspace;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class UiNavigationRolesTests
{
    static readonly IConfiguration Configuration = new ConfigurationBuilder().Build();
    static JsonObject Navigation() => LegacyWorkspaceModels.Navigation(Configuration);
    static JsonArray Views() => JsonNode.Parse(WorkspaceJson.ReadResource("role-view-templates.json"))!.AsArray();
    static string UnusedReportsDirectory => Path.Combine(Path.GetTempPath(), "sli-ui-navigation-" + Guid.NewGuid().ToString("N"));
    static string[] Strings(JsonNode? values) => values!.AsArray().Select(v => v!.ToString()).ToArray();

    [Fact]
    public void CatalogHasAllRolesAndKnownRoutes()
    {
        var data = Navigation();
        Assert.Equal("ok", data["status"]!.ToString());
        string version = data["release_metadata"]!["project_version"]!.ToString();
        Assert.StartsWith("2026.", version);
        Assert.Equal(new[] { "it", "security", "technical" }, data["roles"]!.AsArray().Select(r => r!["id"]!.ToString()).Order(StringComparer.Ordinal));
        var items = data["items"]!.AsArray();
        Assert.Contains(items, item => item!["url"]!.ToString() == "/reports/ui-navigation.html");
        Assert.Contains(items, item => item!["url"]!.ToString() == "/reports/autocollection.html" && Strings(item["roles"]).Contains("it"));
        Assert.Contains(items, item => item!["url"]!.ToString() == "/reports/storage-health.html" && Strings(item["roles"]).SequenceEqual(["it"]));
        Assert.Contains(items, item => item!["url"]!.ToString() == "/reports/db-status.html" && Strings(item["roles"]).Contains("technical"));
        Assert.DoesNotContain(items, item => item!["url"]!.ToString().Contains("db-migration", StringComparison.Ordinal));
        Assert.All(items, item => {
            Assert.True(item!["url"]!.ToString().StartsWith('/') || item["url"]!.ToString().StartsWith('#'));
            Assert.NotEmpty(item["roles"]!.AsArray());
        });
        foreach (var role in data["roles"]!.AsArray())
            Assert.Equal(items.Where(i => Strings(i!["roles"]).Contains(role!["id"]!.ToString())).Select(i => i!["id"]!.ToString()),
                role!["items"]!.AsArray().Select(i => i!["id"]!.ToString()));
    }

    [Fact]
    public void DynamicReportsIncludeNavigationRolesWithoutStoredReports()
    {
        var reports = DashboardSnapshotReader.Reports(UnusedReportsDirectory).ToDictionary(r => r!["name"]!.ToString(), r => r!);
        var navigation = reports["ui-navigation.html"];
        Assert.Equal("ui_navigation", navigation["kind"]!.ToString());
        Assert.Equal(new[] { "it", "security", "technical" }, Strings(navigation["roles"]).Order(StringComparer.Ordinal));
        Assert.Equal(new[] { "it" }, Strings(reports["storage-health.html"]["roles"]));
        Assert.Contains("it", Strings(reports["autocollection.html"]["roles"]));
    }

    [Fact]
    public async Task HtmlRendererRendersRoleMatrix()
    {
        var context = new DefaultHttpContext();
        await using var output = new MemoryStream(); context.Response.Body = output;
        await LegacyRender.HtmlAsync(context, "/reports/ui-navigation.html", Navigation(), TestContext.Current.CancellationToken);
        string html = System.Text.Encoding.UTF8.GetString(output.ToArray());
        Assert.Equal("text/html; charset=utf-8", context.Response.ContentType);
        Assert.Contains("Карта навигации ИБ / ИТ / Технический", html);
        Assert.Contains("/reports/ui-navigation.html", html);
        Assert.Contains("/reports/autocollection.html", html);
        Assert.Contains("ui_nav_check.py", html);
        Assert.Contains("<th>Роли</th>", html);
    }

    [Fact]
    public void NavigationCheckValidatesCatalogWithoutWarnings()
    {
        var result = LegacyWorkspaceModels.NavigationCheck(Configuration, UnusedReportsDirectory);
        Assert.Equal("ok", result["status"]!.ToString());
        Assert.True(result["ui_navigation_items"]!.GetValue<int>() >= 10);
        Assert.Contains("ui-navigation.html", Strings(result["reports"]));
        Assert.Empty(result["warnings"]!.AsArray());
        Assert.Equal("UI_NAV_CHECK", result["package_type"]!.ToString());
    }

    [Theory]
    [InlineData("report", "Missing required dynamic reports: ui-navigation.html")]
    [InlineData("view", "Role view metadata is incomplete")]
    [InlineData("role", "UI navigation role coverage is incomplete")]
    [InlineData("route", "UI navigation has unresolved routes: /reports/missing.html")]
    public void NavigationCheckReportsBrokenCatalogInsteadOfReturningSuccess(string change, string warning)
    {
        var navigation = Navigation(); var reports = DashboardSnapshotReader.Reports(UnusedReportsDirectory); var views = Views();
        if (change == "report") reports.Remove(reports.Single(r => r!["name"]!.ToString() == "ui-navigation.html"));
        if (change == "view") views.RemoveAt(0);
        if (change == "role") navigation["roles"]!.AsArray().RemoveAt(0);
        if (change == "route") navigation["items"]![0]!["url"] = "/reports/missing.html";
        var result = LegacyWorkspaceModels.CheckNavigation(navigation, reports, views);
        Assert.Equal("warn", result["status"]!.ToString());
        Assert.Contains(warning, Strings(result["warnings"]));
    }

    [Fact]
    public void HtmlRendererEscapesCatalogTextAndLinkAttributes()
    {
        var data = Navigation();
        const string untrusted = "<script>fixture</script>\"&";
        data["principle"] = untrusted;
        var group = data["groups"]![0]!;
        group["title"] = untrusted;
        var item = group["items"]![0]!;
        foreach (string key in new[] { "title", "id", "description", "url" }) item[key] = untrusted;
        item["role_titles"] = new JsonArray(untrusted);
        var html = LegacyWorkspaceModels.RenderNavigation(data);
        Assert.DoesNotContain(untrusted, html);
        Assert.DoesNotContain("<script>", html);
        Assert.Contains("href=\"" + WebUtility.HtmlEncode(untrusted) + "\"", html);
        Assert.Contains("<span class=\"role\">" + WebUtility.HtmlEncode(untrusted), html);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task DiagnosticsUsesStructuralCheckAndRetainsSpaAssetValidation(bool hasSpa)
    {
        var directory = Directory.CreateTempSubdirectory("sli-ui-navigation-");
        try
        {
            if (hasSpa)
            {
                string web = Path.Combine(directory.FullName, "web", "app"); Directory.CreateDirectory(web);
                File.WriteAllText(Path.Combine(web, "index.html"), "<!doctype html><script src=\"/fixture.js\"></script>");
                File.WriteAllText(Path.Combine(web, "fixture.js"), "// test fixture");
            }
            using var app = await OperationsEndpointTests.Start(settings: new() {
                ["Sli:ProjectRoot"] = directory.FullName, ["Sli:DataDirectory"] = directory.FullName });
            var result = await app.Service.ReadAsync("/api/diagnostics/overview", new() { ["run_checks"] = ["1"] }, TestContext.Current.CancellationToken);
            var check = result["parsed_checks"]!["ui_nav_check"]!;
            Assert.Equal("UI_NAV_CHECK", check["package_type"]!.ToString());
            Assert.True(check["ui_navigation_items"]!.GetValue<int>() >= 10);
            Assert.Contains("ui-navigation.html", Strings(check["reports"]));
            Assert.Equal(hasSpa ? "ok" : "warn", check["status"]!.ToString());
            if (hasSpa) Assert.Empty(check["warnings"]!.AsArray());
            else Assert.Contains("spa_index_missing", Strings(check["warnings"]));
        }
        finally { directory.Delete(true); }
    }
}
