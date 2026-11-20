using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Domains;
using Sli.Server.Problems;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Detections;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Problems;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class DetectionsCommonTests(ITestOutputHelper output)
{
    [Fact]
    public void FindingRuleCatalogHasRussianAndEnglishWording()
    {
        var scope = new PasswordScope("00000000-0000-0000-0000-000000000001", "sli.windows.ad-dc", "synthetic", "generation", "");
        var rules = DefaultDetectionDefinitions.Read().Select(p => p.Key)
            .Concat(IdentityAttacks.Rules.Keys).Concat(AttackPrecursors.Rules)
            .Concat(new[] { new PasswordRule(scope).Id, new PasswordRule(scope, "spray").Id }).ToHashSet();
        string seed = File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(), "deploy/linux/default_semantic_policy.sql"));
        foreach (Match match in Regex.Matches(seed, @"\$policy\$(.*?)\$policy\$", RegexOptions.Singleline))
            rules.Add(JsonNode.Parse(match.Groups[1].Value)!["scenario_kind"]!.GetValue<string>());
        var missing = new List<string>();
        foreach (string rule in rules.Order()) foreach (string language in new[] { "ru", "en" }) foreach (string suffix in new[] { "title", "what", "next" }) {
            if (!ProblemPresentation.HasRuleMessage("semantic." + rule, suffix, language)) missing.Add(rule + ":" + language + ":" + suffix);
            else {
                var row = ProblemPresentation.Finding(new() { ["rule_code"] = "semantic." + rule,
                    ["last_seen_utc"] = "2026-11-13T08:00:00Z", ["presentation_facts"] = new JsonObject {
                        ["actor"] = "example.test\\operator", ["member"] = "member", ["group"] = "Domain Admins",
                        ["computer"] = "dc.example.test", ["category_id"] = "logon", ["account"] = "synthetic-user",
                        ["source"] = "192.0.2.8", ["count"] = 10, ["minutes"] = 1, ["time"] = "2026-11-13T08:00:00Z" } }, ProblemLifecycleTests.Access("security.queue"), language);
                string field = suffix switch { "title" => "title_text", "what" => "what_happened", _ => "next_text" };
                Assert.False(string.IsNullOrWhiteSpace(row[field]?.ToString()), rule + ":" + language + ":" + suffix);
            }
        }
        // File audit and NPS are excluded from beta-1; expose their gaps without developing those rules.
        var outsideBeta = missing.Where(item => item.StartsWith("qw.file-", StringComparison.Ordinal) || item.StartsWith("qw.nps-", StringComparison.Ordinal)).ToArray();
        output.WriteLine("Outside beta-1, missing wording: " + string.Join(", ", outsideBeta));
        Assert.True(missing.Except(outsideBeta).Count() == 0, "Missing beta-1 rule wording: " + string.Join(", ", missing.Except(outsideBeta)));
    }

    [Theory]
    [InlineData("ru", "Агент SLI остановлен или отключён")]
    [InlineData("en", "The SLI agent was stopped or disabled")]
    public void StoredEnglishTitleIsReplacedInQueueAndHome(string language, string title)
    {
        var finding = new JsonObject { ["id"] = 1, ["rule_code"] = "semantic.qw.agent-tamper",
            ["title"] = "SLI agent service tampering", ["target"] = "dc.example.test" };
        var queue = ProblemPresentation.Finding(finding, ProblemLifecycleTests.Access("security.queue"), language);
        Assert.Equal(title, queue["title_text"]!.ToString());
        Assert.Equal(title, queue["title"]!.ToString());
        Assert.Equal(title, HomePresentation.Finding(finding, language)["title"]!.ToString());
    }

    [Theory]
    [InlineData("ru")]
    [InlineData("en")]
    public void MissingValuesDoNotLeavePlaceholdersOrInventAnActor(string language)
    {
        var finding = new JsonObject { ["id"] = 1, ["rule_code"] = "semantic.qw.agent-tamper" };
        var row = ProblemPresentation.Finding(finding, ProblemLifecycleTests.Access("security.queue"), language);
        Assert.Null(row["actor_text"]);
        Assert.DoesNotContain("{host}", row["what_happened"]!.ToString());
        Assert.DoesNotContain("Инициатор не определён", row.ToJsonString());
        var message = ProblemPresentation.Message("security.problems.presentation.asrep_observed", language,
            new() { ["source"] = "192.0.2.8" });
        Assert.DoesNotContain("{account}", message["text"]!.ToString());
        Assert.Equal("The service stopped;", ProblemPresentation.Render("The service stopped; changed by {actor}.", new()));
    }

    [Fact]
    public void KnownFactsReachWordingAndRespectFieldAccess()
    {
        var finding = new JsonObject { ["rule_code"] = "semantic.qw.audit-disabled", ["actor"] = "EXAMPLE\\operator",
            ["target"] = "synthetic-account", ["computer"] = "dc.example.test", ["source"] = "192.0.2.8",
            ["occurrence_count"] = 3, ["last_seen_utc"] = "2026-11-13T08:00:00Z",
            ["presentation_facts"] = new JsonObject { ["actor"] = "EXAMPLE\\operator", ["category_id"] = "logon" } };
        var row = ProblemPresentation.Finding(finding, ProblemLifecycleTests.Access("security.queue"), "en");
        Assert.Equal("EXAMPLE\\operator turned off auditing of Logon on dc.example.test at 2026-11-13T08:00:00Z.", row["what_happened"]!.ToString());
        row = ProblemPresentation.Finding(finding, ProblemLifecycleTests.Access("security.queue", fields: ["security"]), "en");
        foreach (string fact in new[] { "operator", "synthetic-account", "dc.example.test", "192.0.2.8" }) Assert.DoesNotContain(fact, row.ToJsonString());
        finding["presentation_facts"] = new JsonObject { ["source"] = "198.51.100.8" };
        finding.Remove("source");
        Assert.DoesNotContain("198.51.100.8", HomePresentation.Finding(finding, "en", technical: false).ToJsonString());
    }

    [Fact]
    public void UnknownRuleNeverReturnsSavedWording()
    {
        var row = ProblemPresentation.Finding(new() { ["rule_code"] = "synthetic.future", ["title"] = "Stored title",
            ["summary"] = "Stored summary" }, ProblemLifecycleTests.Access("security.queue"), "ru");
        Assert.Equal("synthetic.future", row["title_text"]!.ToString());
        Assert.Equal("synthetic.future", row["title"]!.ToString());
        Assert.DoesNotContain("Stored", row.ToJsonString());
    }
}
