using Sli.Server.Agents.Radius;
using Xunit;

namespace Sli.Server.Tests.Agents;

// Vectors from tests/sources/test_radius_accounting_identity.py.
public sealed class RadiusAccountingIdentityTests
{
    private const string Domain = "example.test";
    private const string Observation = "example.test/Users/Example User";
    private const string Cn = "cn=example user,cn=users,dc=example,dc=test";
    private const string Ou = "cn=example user,ou=users,dc=example,dc=test";

    [Fact]
    public void SlashDnCandidatesCoverCnAndOu()
    {
        var derived = RadiusIdentity.DeriveSlashDnCandidates(Observation);

        Assert.NotNull(derived);
        Assert.Equal(Domain, derived.Value.Domain);
        Assert.Equal(new[] { Cn, Ou }, derived.Value.Candidates.Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task ResolverReturnsOnlyOneUniqueStructuralEntity()
    {
        var aliases = new Dictionary<(string, string), string> { [(Domain, Cn)] = "entity:101" };
        Task<string?> Lookup(string domain, string dn) => Task.FromResult(aliases.GetValueOrDefault((domain, dn.ToLowerInvariant())));

        Assert.Equal("entity:101", await RadiusIdentity.ResolveAsync(Observation, Domain, Lookup));

        // Both structural aliases may name the same entity; uniqueness is by entity.
        aliases[(Domain, Ou)] = "entity:101";
        Assert.Equal("entity:101", await RadiusIdentity.ResolveAsync(Observation, Domain, Lookup));
    }

    [Fact]
    public async Task ResolverFailsClosedOnAmbiguityOrForeignDomain()
    {
        var aliases = new Dictionary<(string, string), string>
        {
            [(Domain, Cn)] = "entity:101",
            [(Domain, Ou)] = "entity:202"
        };
        var calls = new List<(string, string)>();
        Task<string?> Lookup(string domain, string dn)
        {
            calls.Add((domain, dn));
            return Task.FromResult(aliases.GetValueOrDefault((domain, dn.ToLowerInvariant())));
        }

        Assert.Null(await RadiusIdentity.ResolveAsync(Observation, Domain, Lookup));
        Assert.Equal(new[] { (Domain, Observation), (Domain, Cn), (Domain, Ou) }, calls);

        calls.Clear();
        const string foreign = "other.example.test/Users/Example User";
        Assert.Null(await RadiusIdentity.ResolveAsync(foreign, Domain, Lookup));
        Assert.Equal(new[] { (Domain, foreign) }, calls);
    }

    [Fact]
    public async Task ResolverPreservesExistingExactDnLookup()
    {
        var calls = new List<(string, string)>();
        Task<string?> Lookup(string domain, string dn)
        {
            calls.Add((domain, dn));
            return Task.FromResult<string?>(dn.StartsWith("cn=", StringComparison.Ordinal) ? "entity:101" : null);
        }

        Assert.Equal("entity:101", await RadiusIdentity.ResolveAsync(Cn, Domain, Lookup));
        Assert.Equal(new[] { (Domain, Cn) }, calls);
    }

    [Theory]
    [InlineData("example.test")]
    [InlineData("other.example.test")]
    public async Task ExcessivePathDepthRaisesBeforeDomainComparison(string domain)
    {
        var observation = domain + "/" + string.Join('/', Enumerable.Repeat("Users", 9));
        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            RadiusIdentity.ResolveAsync(observation, Domain, (_, _) => Task.FromResult<string?>(null)));

        Assert.Equal("radius_identity_path_depth_exceeded", error.Message);
    }
}
