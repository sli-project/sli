using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Registry;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed partial class AdDcImportPerformanceTests
{
    [Fact]
    public async Task Capacity_upgrade_preserves_explicit_limits_history_and_later_edits_on_rollback()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        int previous = MigrationDirectory.Read().Where(m => m.Version < 373).Max(m => m.Version);
        await fixture.StartAsync(ct, throughVersion: previous);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert = new CertificateRequest("CN=synthetic", key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        await SeedAsync(admin, fixture.Pg.Root, cert, ct);
        async Task<Guid> Copy(int rate = 120, bool dc = true, bool template = false) {
            var id = Guid.NewGuid();
            await using var command = new NpgsqlCommand("""
                insert into sli_agents(id,host_id,key_fingerprint,assigned_modules,collection_policy,policy_revision)
                select @id,@id,@key,case when @dc then assigned_modules else '[]'::jsonb end,
                    jsonb_set(collection_policy,'{rate_limit_per_minute}',to_jsonb(@rate::int)),policy_revision
                from sli_agents where id=@original;
                """, admin);
            command.Parameters.AddWithValue("id", id); command.Parameters.AddWithValue("key", id.ToString("N") + id.ToString("N"));
            command.Parameters.AddWithValue("dc", dc); command.Parameters.AddWithValue("rate", rate); command.Parameters.AddWithValue("original", Agent);
            await command.ExecuteNonQueryAsync(ct);
            if (template) {
                await using var attach = new NpgsqlCommand("""
                    insert into sli_agent_policy_templates(id,version,assigned_modules,collection_policy,policy_sha256)
                    select @id,1,assigned_modules,collection_policy,repeat('a',64) from sli_agents where id=@id;
                    update sli_agents set template_id=@id,template_version=1,template_sha256=repeat('a',64) where id=@id;
                    """, admin);
                attach.Parameters.AddWithValue("id", id); await attach.ExecuteNonQueryAsync(ct);
            }
            return id;
        }
        async Task Update(Guid id, int rate) {
            await using var tx = await admin.BeginTransactionAsync(ct);
            await using var query = new NpgsqlCommand("select policy_revision from sli_agents where id=@id", admin, tx);
            query.Parameters.AddWithValue("id", id); long revision = (long)(await query.ExecuteScalarAsync(ct))!;
            await new AgentPolicyService(new AgentControlAudit()).UpdateControlAsync(admin, tx,
                JsonSerializer.SerializeToElement(new { agent_id = id, expected_revision = revision, collection_policy = new { rate_limit_per_minute = rate } }), "session:1", ct);
            await tx.CommitAsync(ct);
        }
        async Task AssertRate(Guid id, int rate, long revision) {
            await using var query = new NpgsqlCommand("select (collection_policy->>'rate_limit_per_minute')::int,policy_revision from sli_agents where id=@id", admin);
            query.Parameters.AddWithValue("id", id); await using var result = await query.ExecuteReaderAsync(ct);
            Assert.True(await result.ReadAsync(ct)); Assert.Equal(rate, result.GetInt32(0)); Assert.Equal(revision, result.GetInt64(1));
        }
        var unchanged = await Copy(); var custom = await Copy(50); var explicitDefault = await Copy();
        var templated = await Copy(template: true); var other = await Copy(dc: false);
        await Update(explicitDefault, 120);
        string path = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/373_dc_pipeline_capacity.sql");
        await fixture.Pg.ApplyFileAsync(path, null, ct);
        await AssertRate(Agent, AdDcConfig.DefaultRateLimitPerMinute, 2);
        await AssertRate(unchanged, AdDcConfig.DefaultRateLimitPerMinute, 2);
        await AssertRate(custom, 50, 1); await AssertRate(explicitDefault, 120, 2);
        await AssertRate(templated, 120, 1); await AssertRate(other, 120, 1);
        await Update(Agent, 300);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(path, ".rollback.sql"), null, ct);
        await AssertRate(Agent, 300, 3); await AssertRate(unchanged, 120, 3);
        await using (var history = new NpgsqlCommand("select (collection_policy->>'rate_limit_per_minute')::int from sli_agent_policy_history where agent_id=@id order by revision", admin)) {
            history.Parameters.AddWithValue("id", unchanged); await using var rows = await history.ExecuteReaderAsync(ct);
            foreach (int rate in new[] { 120, AdDcConfig.DefaultRateLimitPerMinute, 120 }) {
                Assert.True(await rows.ReadAsync(ct)); Assert.Equal(rate, rows.GetInt32(0));
            }
            Assert.False(await rows.ReadAsync(ct));
        }
        await fixture.Pg.ApplyFileAsync(path, null, ct);
        await AssertRate(unchanged, AdDcConfig.DefaultRateLimitPerMinute, 4);
        await AssertRate(Agent, 300, 3);
        await AssertNewDcRateAsync(admin, ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    private static async Task AssertNewDcRateAsync(NpgsqlConnection db, CancellationToken ct)
    {
        using var certificates = new Certificates();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var host = Guid.NewGuid(); var tokenId = Guid.NewGuid();
        var csr = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256);
        string raw = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        await using var tx = await db.BeginTransactionAsync(ct);
        await using (var seed = new NpgsqlCommand("""
            insert into servers(domain_id,hostname,fqdn,role) select id,'new-dc.example.test','new-dc.example.test','domain_controller' from domains where fqdn='example.test';
            insert into sli_agent_enrollment_tokens(id,token_hash,host_id,key_fingerprint,created_at,expires_at)
            values(@token,@hash,@host,@key,clock_timestamp(),clock_timestamp()+interval '15 minutes');
            """, db, tx)) {
            seed.Parameters.AddWithValue("token", tokenId); seed.Parameters.AddWithValue("hash", Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(raw))));
            seed.Parameters.AddWithValue("host", host); seed.Parameters.AddWithValue("key", Convert.ToHexStringLower(SHA256.HashData(csr.PublicKey.ExportSubjectPublicKeyInfo())));
            await seed.ExecuteNonQueryAsync(ct);
        }
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:CollectionProfile"] = "beta" }).Build();
        var service = new AgentEnrollmentService(certificates.Ca, new AgentIdentityService(certificates.Ca), config);
        var enrolled = await service.EnrollAsync(db, tx, new JsonObject { ["token"] = raw, ["csr_pem"] = csr.CreateSigningRequestPem(),
            ["machine_role"] = "domain_controller", ["reported_hostname"] = "new-dc.example.test" }, ct);
        await using var query = new NpgsqlCommand("select collection_policy::text from sli_agents where id=@id", db, tx);
        query.Parameters.AddWithValue("id", Guid.Parse(enrolled["agent_id"]!.GetValue<string>()));
        var policy = CollectionControl.Parse(JsonNode.Parse((string)(await query.ExecuteScalarAsync(ct))!)!);
        Assert.Equal(AdDcConfig.DefaultRateLimitPerMinute, policy.RateLimitPerMinute);
        await tx.CommitAsync(ct);
    }
}
