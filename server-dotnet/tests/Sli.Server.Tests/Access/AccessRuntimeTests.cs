using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Access;

public sealed class AccessRuntimeTests
{
    [Fact]
    public void PerReportCombinedDomainBoundUsesDeduplicatedUnionAndPreservesIndependentReports()
    {
        var capabilities = new CapabilityDecisionSet(false, new HashSet<string>(), new HashSet<string>(), [], new Dictionary<string, JsonElement>());
        ReportRule Rule(string key) => new(key, key, "domain", new HashSet<string>(), new HashSet<string>(), null, false);
        AtomicReportGrant Grant(IEnumerable<int> ids) => new(JsonSerializer.SerializeToElement(new { kind = "domain", ids }),
            new HashSet<string>(), new HashSet<string> { "view" }, 1, 1);
        DomainGrant Resolve(params ReportDecision[] reports) => new ReportScopeResolver().PermittedDomains(
            new("viewer", capabilities, reports), reports.Select(r => Rule(r.ReportKey)).ToArray());

        Assert.Equal(100, Resolve(new ReportDecision("first", true, [Grant(Enumerable.Range(1, 60)), Grant(Enumerable.Range(61, 40))])).DomainIds.Count);
        Assert.Throws<DomainScopeCompositionException>(() => Resolve(
            new ReportDecision("first", true, [Grant(Enumerable.Range(1, 60)), Grant(Enumerable.Range(61, 41))])));
        Assert.Equal(100, Resolve(new ReportDecision("first", true, [Grant(Enumerable.Range(1, 60)), Grant(Enumerable.Range(50, 51))])).DomainIds.Count);
        Assert.Equal(101, Resolve(new ReportDecision("first", true, [Grant(Enumerable.Range(1, 60))]),
            new ReportDecision("second", true, [Grant(Enumerable.Range(61, 41))])).DomainIds.Count);
        var restrictedSource = new AtomicReportGrant(JsonSerializer.Deserialize<JsonElement>(
            """{"mode":"restricted","clauses":[{"source_instance_ids":["source-1"]}]}"""), new HashSet<string>(), new HashSet<string> { "view" }, 1, 1);
        // Python validates the merged pure-domain clause before its strict domain adapter.
        Assert.Throws<DomainScopeCompositionException>(() => Resolve(new ReportDecision("first", true,
            [restrictedSource, Grant(Enumerable.Range(1, 60)), Grant(Enumerable.Range(61, 41))])));
        var all = new AtomicReportGrant(JsonSerializer.Deserialize<JsonElement>("""{"kind":"all"}"""),
            new HashSet<string>(), new HashSet<string> { "view" }, 1, 1);
        Assert.Equal(DomainGrantKind.All, Resolve(new ReportDecision("first", true,
            [Grant(Enumerable.Range(1, 60)), Grant(Enumerable.Range(61, 41)), all])).Kind);
    }

    [Fact]
    public void CapabilityDenyPrecedenceAndViewerStarterRestriction()
    {
        JsonElement Json(string value) => JsonSerializer.Deserialize<JsonElement>(value);
        AccessFacts Facts(string policy, bool owner = false) => new(owner, "viewer",
            [Json("""{"package_key":"starter","effect":"allow","source_kind":"role"}""")],
            [Json("""{"capability_key":"workspace.view","package_key":"starter"}"""), Json("""{"capability_key":"field.technical","package_key":"starter"}""")],
            [Json(policy)], [Json("""{"capability_key":"workspace.view"}""")], [], [], []);
        foreach (var (scope, effect, reason) in new[] {
            ("""{"kind":"domain","ids":[7]}""", "deny", "resource_context_required"),
            ("""{"kind":"domain","ids":[]}""", "deny", "invalid_scope_policy"),
            ("""{"kind":"all"}""", "deny", "explicit_deny"),
            ("""{"kind":"all"}""", "allow", "global_allow") })
        {
            var facts = Facts("{\"capability_key\":\"workspace.view\",\"effect\":\"" + effect + "\",\"scope_json\":" + scope + "}");
            var composer = new CapabilityComposer();
            var result = composer.Compose(facts);
            Assert.Equal(reason, result.Decide("workspace.view").Reason);
            Assert.Equal(reason == "global_allow", result.Decide("workspace.view").Allowed);
            Assert.Equal("insufficient_capability", result.Decide("field.technical").Reason);
            Assert.Equal("platform_owner", composer.Compose(facts with { IsOwner = true }).Decide("workspace.view").Reason);
        }
    }

    [Fact]
    public void DomainAdapterRejectsMixedScopeAndNeverCombinesAtomicFieldGrants()
    {
        var capabilities = new CapabilityDecisionSet(false, new HashSet<string>(), new HashSet<string>(), [], new Dictionary<string, JsonElement>());
        var rule = new ReportRule("test.report", "test.report", "domain", new HashSet<string> { "identity_basic", "security" }, new HashSet<string>(), null, false);
        AtomicReportGrant Grant(string scope, params string[] fields) => new(JsonSerializer.Deserialize<JsonElement>(scope), fields.ToHashSet(), new HashSet<string> { "view" }, 1, 1);
        DomainGrant Resolve(params AtomicReportGrant[] grants) => new ReportScopeResolver().PermittedDomains(
            new("viewer", capabilities, [new("test.report", true, grants)]), [rule]);
        Assert.Equal(DomainGrantKind.None, Resolve(
            Grant("""{"kind":"domain","ids":[7]}""", "identity_basic"),
            Grant("""{"kind":"domain","ids":[8]}""", "security")).Kind);
        Assert.Equal(DomainGrantKind.None, Resolve(Grant("""{"mode":"restricted","clauses":[{"collection_scope_ids":["ad-domain:7"]},{"source_instance_ids":["source-1"]}]}""", "identity_basic", "security")).Kind);
        Assert.Equal(DomainGrantKind.None, Resolve(Grant("""{"mode":"restricted","clauses":[{"collection_scope_ids":["ad-domain:7"],"plugin_ids":["ad"]}]}""", "identity_basic", "security")).Kind);
        Assert.Equal(new long[] { 7, 8 }, Resolve(Grant("""{"kind":"domain","ids":[8,7,7]}""", "identity_basic", "security")).DomainIds.Order());
        Assert.Equal(DomainGrantKind.All, Resolve(Grant("""{"kind":"all"}""", "identity_basic", "security")).Kind);
        Assert.Equal(DomainGrantKind.None, Resolve(Grant("""{"kind":"all","ids":[7]}""", "identity_basic", "security")).Kind);
    }

    [Fact]
    public void IndependentPythonFactsMatchCapabilitiesAtomicGrantsAndDomainUnion()
    {
        string directory = Environment.GetEnvironmentVariable("SLI_ACCESS_EXPORTS")
            ?? throw new InvalidOperationException("Explicit independent source-export directory is required.");
        var catalog = new ReportRuleCatalog();
        Assert.Equal(27, catalog.Rules.Count);
        Assert.Equal(6, catalog.Rules.Count(r => r.Scope == "domain"));
        foreach (var name in new[] { "owner-final", "scoped-final", "empty-final", "disjoint-final", "mixed-final" })
        {
            using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(directory, name + ".json")));
            var source = document.RootElement;
            foreach (var expectedRule in source.GetProperty("registered_reports").EnumerateArray())
            {
                var actualRule = Assert.Single(catalog.Rules, r => r.RegistryKey == expectedRule.GetProperty("key").GetString());
                var accessRule = expectedRule.GetProperty("access");
                Assert.Equal(accessRule.GetProperty("report_key").GetString(), actualRule.ReportKey);
                Assert.Equal(accessRule.GetProperty("scope").GetString(), actualRule.Scope);
                Assert.Equal(accessRule.GetProperty("required_fields").EnumerateArray().Select(s => s.GetString()).Order(), actualRule.RequiredFields.Order());
                Assert.Equal(accessRule.GetProperty("required_capabilities").EnumerateArray().Select(s => s.GetString()).Order(), actualRule.RequiredCapabilities.Order());
                Assert.Equal(accessRule.TryGetProperty("required_role", out var requiredRole) ? requiredRole.GetString() : null, actualRule.RequiredRole);
                Assert.Equal(accessRule.TryGetProperty("global_scope_only", out var globalOnly) && globalOnly.GetBoolean(), actualRule.GlobalScopeOnly);
            }
            var facts = source.GetProperty("facts");
            JsonElement[] Rows(string key) => facts.GetProperty(key).EnumerateArray().Select(i => i.Clone()).ToArray();
            var subject = source.GetProperty("composed_access").GetProperty("subject");
            var loaded = new AccessFacts(Rows("is_owner").Any(i => i.GetProperty("is_owner").GetBoolean()),
                subject.GetProperty("coarse_role").GetString()!, Rows("role_packages").Concat(Rows("subject_packages")).Concat(Rows("owner_packages")).ToArray(),
                Rows("package_capabilities"), Rows("direct_capabilities"), Rows("all_capabilities"),
                Rows("package_reports"), Rows("report_assignments"), Rows("definitions"));
            var capabilities = new CapabilityComposer().Compose(loaded);
            foreach (var expected in source.GetProperty("capability_decisions").EnumerateArray())
            {
                var actual = capabilities.Decide(expected.GetProperty("capability").GetString()!);
                Assert.Equal(expected.GetProperty("allowed").GetBoolean(), actual.Allowed);
                Assert.Equal(expected.GetProperty("reason").GetString(), actual.Reason);
            }
            var composed = new ReportEligibility().Compose(loaded, capabilities);
            foreach (var expected in source.GetProperty("composed_access").GetProperty("reports").EnumerateArray())
            {
                var actual = Assert.Single(composed.Reports, r => r.ReportKey == expected.GetProperty("report_key").GetString());
                Assert.Equal(expected.GetProperty("allowed").GetBoolean(), actual.Allowed);
                if (!actual.Allowed) continue;
                var grants = expected.GetProperty("grants").EnumerateArray().ToArray();
                Assert.Equal(grants.Length, actual.Grants.Count);
                for (int i = 0; i < grants.Length; i++)
                {
                    Assert.Equal(grants[i].GetProperty("field_categories").EnumerateArray().Select(s => s.GetString()).Order(), actual.Grants[i].FieldCategories.Order());
                    Assert.Equal(grants[i].GetProperty("allowed_actions").EnumerateArray().Select(s => s.GetString()).Order(), actual.Grants[i].AllowedActions.Order());
                    Assert.True(JsonElement.DeepEquals(grants[i].GetProperty("scope"), actual.Grants[i].Scope));
                    Assert.Equal(grants[i].GetProperty("validated_report_version").GetInt64(), actual.Grants[i].ReportVersion);
                    Assert.Equal(grants[i].GetProperty("validated_dataset_version").GetInt64(), actual.Grants[i].DatasetVersion);
                }
            }
            var grant = new ReportScopeResolver().PermittedDomains(composed, catalog.Rules);
            var ids = source.GetProperty("permitted_domain_ids");
            if (ids.ValueKind == JsonValueKind.Null) Assert.Equal(DomainGrantKind.All, grant.Kind);
            else Assert.Equal(ids.EnumerateArray().Select(i => i.GetInt64()).Order(), grant.DomainIds.Order());
        }
    }

    [Fact]
    public async Task RealPostgresServiceReadsAuthorityFactsWithoutFixtureDecisions()
    {
        var ct = TestContext.Current.CancellationToken;
        var binding = OwnedDatabaseBinding.FromEnvironment();
        await using var admitted = await SyntheticDatabase.BorrowAsync(binding, ct);
        Assert.Equal(300, (await admitted.ReadBaselineAsync(ct)).SchemaVersion);
        var configBytes = await File.ReadAllBytesAsync(Path.Combine(binding.Root, binding.RunId.ToString("D"), binding.Side, "dotnet-test-config.json"), ct);
        Assert.Equal(Environment.GetEnvironmentVariable("SLI_AUTH_CONFIG_SHA256"), Convert.ToHexStringLower(SHA256.HashData(configBytes)));
        var config = new ConfigurationBuilder().AddJsonStream(new MemoryStream(configBytes)).Build();
        var factory = new PostgresConnectionFactory(config);
        var service = new DomainAccessService(factory);
        foreach (var (id, expectedKind, expectedIds) in new[] {
            (101L, DomainGrantKind.All, Array.Empty<long>()), (105L, DomainGrantKind.Scoped, new long[] { 101 }),
            (107L, DomainGrantKind.None, Array.Empty<long>()), (108L, DomainGrantKind.Scoped, new long[] { 102 }),
            (109L, DomainGrantKind.None, Array.Empty<long>()) })
        {
            await admitted.AssertProofAsync(binding.ProofSha256, ct);
            var result = await service.EvaluateAsync(new Principal("session", id, id == 101 ? "admin" : "viewer"), ct);
            Assert.True(result.CapabilityAllowed);
            Assert.Equal(expectedKind, result.Grant.Kind);
            Assert.Equal(expectedIds, result.Grant.DomainIds.Order());
        }
        await admitted.AssertProofAsync(binding.ProofSha256, ct);
        // The viewer starter package grants a global user report in this seed.
        // This is role authority, not inherited owner/user assignments.
        var keyPrincipal = new Principal("api_key", 301, "viewer");
        var keyFacts = await new AccessFactsRepository(factory).LoadAsync(keyPrincipal, ct);
        Assert.False(keyFacts.IsOwner);
        Assert.Empty(keyFacts.DirectCapabilities);
        Assert.Empty(keyFacts.ReportAssignments);
        Assert.DoesNotContain(keyFacts.Packages, p => p.GetProperty("source_kind").GetString() != "role");
        var apiKey = await service.EvaluateAsync(keyPrincipal, ct);
        Assert.True(apiKey.CapabilityAllowed);
        Assert.Equal(DomainGrantKind.All, apiKey.Grant.Kind);
        Assert.Equal("global_allow", apiKey.CapabilityReason);
    }
}

