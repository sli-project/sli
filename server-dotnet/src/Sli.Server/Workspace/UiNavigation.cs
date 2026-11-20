using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;

namespace Sli.Server.Workspace;

internal static partial class LegacyWorkspaceModels
{
    static readonly string[] RequiredNavigationReports = ["collector-health.html", "autocollection.html", "system-health.html",
        "db-status.html", "findings.html", "investigation.html", "role-overview.html", "ui-navigation.html",
        "security-events-monitor.html", "ai-redaction-preview.html", "ai-prompt-preview.html", "ai-reports.html"];
    static readonly string[] RequiredNavigationRoles = ["security", "it", "technical"];

    internal static JsonObject NavigationCheck(IConfiguration configuration, string reportsDirectory)
    {
        var timer = Stopwatch.StartNew();
        var navigation = Navigation(configuration);
        var reports = DashboardSnapshotReader.Reports(reportsDirectory);
        var views = JsonNode.Parse(WorkspaceJson.ReadResource("role-view-templates.json"))!.AsArray();
        var result = CheckNavigation(navigation, reports, views);
        result["duration_ms"] = timer.ElapsedMilliseconds;
        result["release_metadata"] = navigation["release_metadata"]!.DeepClone();
        return result;
    }

    internal static JsonObject CheckNavigation(JsonObject navigation, JsonArray reports, JsonArray views)
    {
        static string Text(JsonNode? node) => node?.ToString() ?? "";
        var names = reports.Select(r => Text(r?["name"])).ToHashSet(StringComparer.Ordinal);
        var urls = reports.Select(r => Text(r?["url"])).ToHashSet(StringComparer.Ordinal);
        var roles = views.Select(r => Text(r?["id"])).ToArray();
        var navRoles = navigation["roles"]!.AsArray().Select(r => Text(r?["id"])).ToHashSet(StringComparer.Ordinal);
        var warnings = new JsonArray();
        var missing = RequiredNavigationReports.Except(names).Order(StringComparer.Ordinal).ToArray();
        if (missing.Length > 0) warnings.Add("Missing required dynamic reports: " + string.Join(", ", missing));
        if (RequiredNavigationRoles.Except(roles).Any()) warnings.Add("Role view metadata is incomplete");
        if (RequiredNavigationRoles.Except(navRoles).Any()) warnings.Add("UI navigation role coverage is incomplete");
        string[] detailRoutes = ["/reports/search.html", "/reports/event-details.html", "/reports/entity-details.html", "/reports/account-timeline.html"];
        var items = navigation["items"]!.AsArray();
        var broken = items.Select(i => Text(i?["url"])).Where(url => url != "/" && !url.StartsWith("/#", StringComparison.Ordinal)
            && !urls.Contains(url.Split('?')[0]) && !detailRoutes.Any(prefix => url.Split('?')[0].StartsWith(prefix, StringComparison.Ordinal)))
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        if (broken.Length > 0) warnings.Add("UI navigation has unresolved routes: " + string.Join(", ", broken));
        static JsonArray Strings(IEnumerable<string> values) => new(values.Select(s => (JsonNode)JsonValue.Create(s)!).ToArray());
        return new() { ["package_type"] = "UI_NAV_CHECK", ["status"] = warnings.Count > 0 ? "warn" : "ok",
            ["role_views"] = Strings(roles), ["ui_navigation_items"] = items.Count, ["reports"] = Strings(names.Order(StringComparer.Ordinal)),
            ["required_reports"] = Strings(RequiredNavigationReports.Order(StringComparer.Ordinal)), ["warnings"] = warnings };
    }

    internal static string RenderNavigation(JsonObject data)
    {
        static string E(JsonNode? value) => WebUtility.HtmlEncode(value?.ToString() ?? "");
        static string Link(JsonNode item) => "<a class=\"button\" href=\"" + E(item["url"]) + "\">" + E(item["title"]) + "</a>";
        var html = new StringBuilder("<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Карта навигации</title></head><body><main><h1>Карта навигации ИБ / ИТ / Технический</h1>");
        html.Append("<p>").Append(E(data["principle"])).Append("</p><p>Версия: ").Append(E(data["release_metadata"]?["project_version"]))
            .Append("</p><p>Элементов: ").Append(data["items"]!.AsArray().Count).Append("</p><section><h2>Быстрые ролевые входы</h2>");
        foreach (var role in data["roles"]!.AsArray())
        {
            html.Append("<article><h3>").Append(E(role!["title"])).Append("</h3><p>").Append(role["items"]!.AsArray().Count).Append(" точек входа</p>");
            foreach (var item in role["items"]!.AsArray().Take(6)) html.Append(Link(item!));
            html.Append("</article>");
        }
        html.Append("</section>");
        foreach (var group in data["groups"]!.AsArray())
        {
            html.Append("<section><h2>").Append(E(group!["title"])).Append("</h2><table><thead><tr><th>Пункт</th><th>Роли</th><th>Назначение</th><th>Переход</th></tr></thead><tbody>");
            foreach (var item in group["items"]!.AsArray())
            {
                html.Append("<tr><td><strong>").Append(E(item!["title"])).Append("</strong><br>").Append(E(item["id"])).Append("</td><td>");
                foreach (var title in item["role_titles"]!.AsArray()) html.Append("<span class=\"role\">").Append(E(title)).Append("</span> ");
                html.Append("</td><td>").Append(E(item["description"])).Append("</td><td>").Append(Link(item)).Append("</td></tr>");
            }
            html.Append("</tbody></table></section>");
        }
        return html.Append("<section><h2>Проверка на “мертвые” кнопки</h2><p>Каталог проверяет <code>ui_nav_check.py</code>.</p></section></main></body></html>").ToString();
    }
}
