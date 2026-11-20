using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticIdentityTests
{
    private const string Sid = "S-1-5-21-100000001-200000002-300000003-400";

    [Fact]
    public void Canonical_account_partition_preserves_exact_identity()
    {
        // Parity with tests/semantic/test_semantic_identity.py, using synthetic SIDs.
        var actual = SemanticRelations.IdentityBasis("domain:7|account_sid:" + Sid);

        var expected = new JsonObject
        {
            ["kind"] = "exact_domain_account_sid",
            ["domain_id"] = 7,
            ["account_sid"] = Sid
        };
        Assert.True(JsonNode.DeepEquals(expected, actual));
    }

    [Theory]
    [InlineData("domain:7|account_sid:" + Sid + "|junk:x")]
    [InlineData("domain:7|account_sid:" + Sid + "|account_sid:S-1-5-21-100000001-200000002-300000003-401")]
    [InlineData("domain:7|account_sid:S-1-5-21-100000001-200000002-300000003-40\u0664")]
    [InlineData("domain:+1|account_sid:" + Sid)]
    [InlineData("domain:01|account_sid:" + Sid)]
    [InlineData("domain: 1|account_sid:" + Sid)]
    [InlineData("domain:\u0661|account_sid:" + Sid)]
    [InlineData("domain:0|account_sid:" + Sid)]
    public void Noncanonical_partition_does_not_claim_exact_identity(string partition)
    {
        Assert.Null(SemanticRelations.IdentityBasis(partition));
    }
}
