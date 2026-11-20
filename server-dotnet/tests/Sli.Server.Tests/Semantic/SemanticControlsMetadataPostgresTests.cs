using System.Globalization;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticControlsMetadataPostgresTests
{
    [Fact]
    public async Task Policy_metadata_uses_version_registration_not_lifecycle_update()
    {
        // Parity: tests/semantic/test_semantic_controls_metadata_postgres_integration.py.
        // Like the reference, this checks the real governance query as an administrator,
        // rather than runtime-role privileges. The fixture owns a fresh migrated cluster.
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        string policyId = "000-t058-" + Guid.NewGuid();
        var created = new DateTimeOffset(2026, 1, 2, 3, 4, 0, TimeSpan.Zero);
        var updated = new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero);
        await using (var db = new NpgsqlConnection(fixture.Pg.ConnectionString))
        {
            await db.OpenAsync(ct);
            await using var seed = new NpgsqlCommand("""
                insert into semantic_risk_policies
                    (policy_id,policy_version,source_kind,lifecycle_status,definition_json,
                     definition_sha256,created_at,updated_at)
                values (@id,1,'control_health','draft',@definition::jsonb,@hash,@created,@updated)
                """, db);
            seed.Parameters.AddWithValue("id", policyId);
            seed.Parameters.AddWithValue("definition", """{"title":"Synthetic audit rule"}""");
            seed.Parameters.AddWithValue("hash", new byte[32]);
            seed.Parameters.AddWithValue("created", created);
            seed.Parameters.AddWithValue("updated", updated);
            await seed.ExecuteNonQueryAsync(ct);
        }

        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Sli"] = fixture.Pg.ConnectionString
        }).Build();
        var governance = new SemanticGovernance(new SemanticDatabase(new PostgresConnectionFactory(configuration)));
        var result = await governance.ListAsync(ct);
        var policies = Assert.IsType<JsonArray>(result["policies"]);
        var policy = Assert.IsType<JsonObject>(Assert.Single(policies, p => p?["policy_id"]?.GetValue<string>() == policyId));

        Assert.Equal("Synthetic audit rule", policy["title"]!.GetValue<string>());
        Assert.Equal(created, DateTimeOffset.Parse(policy["version_created_at"]!.GetValue<string>(), CultureInfo.InvariantCulture));
        Assert.Equal(1, policy["policy_version"]!.GetValue<int>());
        Assert.False(policy.ContainsKey("definition_json"));
        Assert.False(policy.ContainsKey("definition_sha256"));
        Assert.False(policy.ContainsKey("updated_at"));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
