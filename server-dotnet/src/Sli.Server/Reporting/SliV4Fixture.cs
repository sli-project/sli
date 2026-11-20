using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Auth.Lifecycle;

namespace Sli.Server.Reporting;

// Frozen prototype fixture, separate from real principals and access facts.
public static class SliV4Fixture
{
    private sealed record Package(string Label, string[] Capabilities, string[] Fields, string[] Scopes, string[] Reports);
    private sealed record DirectReport(string Report, string ValidUntil, string Source);
    private sealed record Actor(string[] Packages, DirectReport[] DirectReports);

    private static readonly Dictionary<string, Package> Packages = new(StringComparer.Ordinal)
    {
        ["sec-operators"] = new("ИБ · операторы",
            ["entity.view", "entity.basic", "problem.view", "problem.act", "case.create", "finding.summary"],
            ["identity.basic"], ["host5.example.invalid"], ["security-queue"]),
        ["sec-analysts"] = new("ИБ · аналитики",
            ["entity.view", "entity.basic", "entity.groups", "entity.privileges", "entity.activity", "entity.states", "entity.technical", "event.view", "evidence.view", "evidence.raw", "finding.view", "case.view", "case.manage", "case.create"],
            ["identity.basic", "technical.raw"], ["host5.example.invalid"], ["security-events", "investigations"]),
        ["ad-auditors"] = new("AD · аудит и сопровождение",
            ["entity.view", "entity.basic", "entity.groups", "entity.privileges", "entity.states", "task.create", "report.export"],
            ["identity.basic", "pii.contact", "pii.hr", "ad.attributes"], ["host5.example.invalid", "OU=Users_KHV"], ["ad-summary", "gpo-review"]),
        ["project-ops"] = new("Проект · эксплуатация",
            ["project.ops.view", "project.events.view", "report.export"],
            ["platform.technical"], ["platform"], ["project-readiness", "technical-events"]),
        ["access-admins"] = new("Администраторы доступа",
            ["access.manage", "access.audit", "report.publish", "report.design"],
            ["access.metadata"], ["all-subjects"], [])
    };
    private static readonly Dictionary<string, Actor> Actors = new(StringComparer.Ordinal)
    {
        ["alex"] = new(["sec-operators", "ad-auditors"], [new("privileged-accounts", "2026-12-31", "Распоряжение ИБ-128")]),
        ["marina"] = new(["sec-operators"], []),
        ["dmitry"] = new(["sec-analysts", "ad-auditors"], [new("privileged-accounts", "2026-09-30", "Проект аттестации PAM-26")]),
        ["admin"] = new(["project-ops", "access-admins"], [])
    };

    public static JsonObject Evaluate(JsonElement payload, DateOnly? today = null)
    {
        string actor = AuthJsonBody.CredentialString(payload, "actor");
        string fixture = AuthJsonBody.CredentialString(payload, "fixture");
        if (fixture != "sli-universal-prototype-v4" || !Actors.TryGetValue(actor, out var definition))
            throw new ArgumentException("invalid_sli_v4_fixture_actor");

        var capabilities = new SortedSet<string>(StringComparer.Ordinal);
        var fields = new SortedSet<string>(StringComparer.Ordinal);
        var scopes = new SortedSet<string>(StringComparer.Ordinal);
        var grants = new List<JsonObject>();
        var packages = new JsonArray();
        foreach (string key in definition.Packages)
        {
            var package = Packages[key];
            packages.Add(new JsonObject { ["key"] = key, ["name"] = package.Label });
            capabilities.UnionWith(package.Capabilities);
            fields.UnionWith(package.Fields);
            scopes.UnionWith(package.Scopes);
            grants.AddRange(package.Reports.Select(report => new JsonObject
            {
                ["report"] = report, ["source_type"] = "group", ["source"] = package.Label, ["valid_until"] = null
            }));
        }
        foreach (var direct in definition.DirectReports)
        {
            if (DateOnly.ParseExact(direct.ValidUntil, "yyyy-MM-dd", CultureInfo.InvariantCulture) >= (today ?? DateOnly.FromDateTime(DateTime.Today)))
                grants.Add(new JsonObject { ["report"] = direct.Report, ["source_type"] = "direct", ["source"] = direct.Source, ["valid_until"] = direct.ValidUntil });
        }
        string[] reports = grants.Select(g => g["report"]!.GetValue<string>()).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        var decisions = new JsonArray();
        foreach (string report in reports)
            decisions.Add(new JsonObject
            {
                ["report"] = report, ["allowed"] = true, ["scope"] = Strings(scopes), ["fields"] = Strings(fields),
                ["actions"] = Strings(capabilities.Contains("report.export") ? ["view", "export"] : ["view"]),
                ["trace"] = new JsonArray(grants.Where(g => g["report"]!.GetValue<string>() == report).Select(g => g.DeepClone()).ToArray())
            });
        return new JsonObject
        {
            ["actor"] = actor, ["fixture"] = fixture, ["packages"] = packages,
            ["capabilities"] = Strings(capabilities), ["fields"] = Strings(fields), ["scopes"] = Strings(scopes),
            ["reports"] = Strings(reports), ["report_decisions"] = decisions,
            ["direct_reports"] = Strings(definition.DirectReports.Select(d => d.Report)),
            ["explicit_denies"] = new JsonArray(), ["server_evaluated"] = true
        };
    }

    private static JsonArray Strings(IEnumerable<string> values) => new(values.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray());
}
