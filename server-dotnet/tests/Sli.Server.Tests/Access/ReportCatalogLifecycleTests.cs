using System.Text.Json;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;
using Npgsql;
using Xunit;

namespace Sli.Server.Tests.Access;

public sealed class ReportCatalogLifecycleTests
{
    [Fact]
    public void SourceFormatDrainUnknownGenerationAndRollbackRebuildOnlyGuardedContributions()
    {
        using var files = new CatalogFiles();
        var catalog = files.Catalog;
        var baseline = catalog.Capture();
        Assert.Equal(27, baseline.Rules.Count);
        Assert.Equal(6, baseline.Rules.Count(r => r.Scope == "domain"));
        Assert.Equal(5, baseline.Rules.Count(r => r.OwnerId == "sli.ad"));
        files.Fence("sli.ad");
        var drained = catalog.Capture();
        Assert.Equal("plugin_update_draining", drained.UnavailableOwners["sli.ad"]);
        Assert.Equal(22, drained.Rules.Count);
        Assert.Equal(11, drained.Rules.Count(r => !r.GuardedContribution));
        Assert.Equal("plugin_update_draining", catalog.Recheck(baseline).UnavailableOwners["sli.ad"]);

        files.Activate("sli.ad", new string('a', 64));
        files.Unfence("sli.ad");
        var unsupported = catalog.Capture();
        Assert.Equal("plugin_generation_unsupported", unsupported.UnavailableOwners["sli.ad"]);
        Assert.DoesNotContain(unsupported.Rules, r => r.OwnerId == "sli.ad");
        Assert.Equal("plugin_version_changed", catalog.Recheck(baseline).UnavailableOwners["sli.ad"]);
        files.Rollback("sli.ad");
        Assert.Equal(27, catalog.Capture().Rules.Count);
        // A snapshot captured while denied must never become an allow after SQL completes.
        Assert.DoesNotContain(catalog.Recheck(unsupported).Rules, r => r.OwnerId == "sli.ad");
        Assert.Equal(27, baseline.Rules.Count); // Capture itself was not mutated.
        var immutableFields = Assert.IsAssignableFrom<ISet<string>>(baseline.Rules[0].RequiredFields);
        Assert.Throws<NotSupportedException>(() => immutableFields.Add("unreviewed_field"));
        files.Fence("sli.workstations");
        Assert.Equal(27, catalog.Capture().Rules.Count); // registry.py100–105 source exception.
    }

    [Fact]
    public async Task ActualComposerAndResolverBindCaptureAcrossTheFactsReadWithoutScopeOrVersionFallback()
    {
        using var files = new CatalogFiles();
        var facts = ScopedFacts();
        var source = new ControlledFacts(facts);
        var service = new DomainAccessService(new NeverOpenedConnections(), files.Catalog, source);
        var principal = new Principal("session", 123, "viewer");
        var baseline = await service.EvaluateAsync(principal, TestContext.Current.CancellationToken);
        Assert.True(baseline.CapabilityAllowed);
        Assert.Equal(new long[] { 7 }, baseline.Grant.DomainIds.Order());
        var composed = new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts));
        var grant = Assert.Single(Assert.Single(composed.Reports).Grants);
        Assert.Equal(11, grant.ReportVersion);
        Assert.Equal(4, grant.DatasetVersion);

        source.DuringRead = () => files.Activate("sli.ad", new string('b', 64));
        var changed = await service.EvaluateAsync(principal, TestContext.Current.CancellationToken);
        Assert.True(changed.CapabilityAllowed); // workspace authority was not rewritten.
        Assert.Equal(DomainGrantKind.None, changed.Grant.Kind);
        source.DuringRead = null;
        Assert.Equal(DomainGrantKind.None, (await service.EvaluateAsync(principal, TestContext.Current.CancellationToken)).Grant.Kind);
        files.Rollback("sli.ad");
        Assert.Equal(new long[] { 7 }, (await service.EvaluateAsync(principal, TestContext.Current.CancellationToken)).Grant.DomainIds.Order());
        source.DuringRead = () => files.Fence("sli.ad");
        Assert.Equal(DomainGrantKind.None, (await service.EvaluateAsync(principal, TestContext.Current.CancellationToken)).Grant.Kind);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("true")]
    [InlineData("12")]
    [InlineData("{}")]
    [InlineData("{\"generation\":\"../outside\"}")]
    [InlineData("{\"generation\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}")]
    [InlineData("{")]
    public void MalformedPointersFailClosedOnlyForTheirOwner(string payload)
    {
        using var files = new CatalogFiles();
        files.Pointer("sli.ad", payload);
        var snapshot = files.Catalog.Capture();
        Assert.DoesNotContain(snapshot.Rules, r => r.OwnerId == "sli.ad");
        Assert.Equal(22, snapshot.Rules.Count);
        Assert.Equal(11, snapshot.Rules.Count(r => !r.GuardedContribution));
    }

    [Fact]
    public void GenericScopeUsesTheSameSnapshotAndBaselineRequiresNoRuntimeDirectory()
    {
        var bundled = new ReportRuleCatalog(new PluginGenerationReader(null)).Capture();
        Assert.Equal(27, bundled.Rules.Count);
        Assert.Equal(27, new ReportRuleCatalog(new PluginGenerationReader("\u001c \u001f")).Capture().Rules.Count);
        using var files = new CatalogFiles();
        var before = files.Catalog.Capture();
        Assert.True(before.SupportsGenericScope("file-audit.overview"));
        Assert.True(before.SupportsGenericScope("notifications.channels"));
        Assert.False(before.SupportsGenericScope("unknown.report"));
        files.Fence("sli.file-audit");
        var after = files.Catalog.Recheck(before);
        Assert.False(after.SupportsGenericScope("file-audit.overview"));
        Assert.True(after.SupportsGenericScope("notifications.channels"));
        Assert.True(before.SupportsGenericScope("file-audit.overview"));
    }

    private sealed class ControlledFacts(AccessFacts facts) : IAccessFactsRepository
    {
        public Action? DuringRead { get; set; }
        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct)
        { DuringRead?.Invoke(); return Task.FromResult(facts); }
    }

    private sealed class NeverOpenedConnections : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => throw new InvalidOperationException("This isolated composer test supplies explicit facts; the separate SQL test uses real PostgreSQL.");
    }

    private static JsonElement Json(string value) => JsonSerializer.Deserialize<JsonElement>(value);
    private static AccessFacts ScopedFacts() => new(false, "viewer", [], [],
        new[] { "workspace.view", "field.identity_basic", "field.security", "field.technical" }
            .Select(key => JsonSerializer.SerializeToElement(new { capability_key = key, effect = "allow", scope_json = new { kind = "all" } })).ToArray(),
        [], [],
        [Json("""{"report_key":"ad.state","effect":"allow","scope_json":{"kind":"domain","ids":[7]},"field_categories":["identity_basic","security","technical"],"allowed_actions":["view"]}""")],
        [Json("""{"report_key":"ad.state","version":11,"dataset_version":4,"definition_json":{"field_categories":["identity_basic","security","technical"],"actions":["view"]},"fields_json":[{"category":"identity_basic"},{"category":"security"},{"category":"technical"}],"actions_json":["view"]}""")]);

    internal sealed class CatalogFiles : IDisposable
    {
        public string Root { get; } = Path.Combine(Path.GetTempPath(), "sli-owned-catalog-" + Guid.NewGuid().ToString("N"));
        public ReportRuleCatalog Catalog { get; }
        public CatalogFiles() { Directory.CreateDirectory(Root); Catalog = new(new PluginGenerationReader(Root)); }
        private string Plugin(string owner) { var path = Path.Combine(Root, owner); Directory.CreateDirectory(path); return path; }
        public void Fence(string owner) => File.WriteAllText(Path.Combine(Plugin(owner), "draining.json"), "{\"operation\":\"synthetic-owned\"}");
        public void Unfence(string owner) => File.Delete(Path.Combine(Plugin(owner), "draining.json"));
        public void Pointer(string owner, string payload)
        {
            var directory = Plugin(owner);
            var temporary = Path.Combine(directory, ".update-owned");
            File.WriteAllText(temporary, payload);
            File.Move(temporary, Path.Combine(directory, "active.json"), true);
        }
        public void Activate(string owner, string generation)
        {
            Directory.CreateDirectory(Path.Combine(Plugin(owner), "versions", generation));
            Pointer(owner, JsonSerializer.Serialize(new { generation }));
        }
        public void Rollback(string owner) => File.Delete(Path.Combine(Plugin(owner), "active.json"));
        public void Dispose()
        {
            var full = Path.GetFullPath(Root);
            if (!Path.GetFileName(full).StartsWith("sli-owned-catalog-", StringComparison.Ordinal)
                || Path.GetDirectoryName(full) != Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar))
                throw new InvalidOperationException("Unexpected owned catalog path.");
            Directory.Delete(full, true);
        }
    }
}
