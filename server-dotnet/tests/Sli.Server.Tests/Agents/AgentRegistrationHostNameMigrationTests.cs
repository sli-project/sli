using Npgsql;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentRegistrationHostNameMigrationTests
{
    [Fact]
    public async Task Upgrade_accepts_unicode_names_and_rollback_preserves_registrations()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 441);
        await using var db = await fixture.Pg.OpenAsync(ct);
        string migration = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/442_agent_unicode_host_names.sql");
        string rollback = Path.ChangeExtension(migration, ".rollback.sql");

        async Task Insert(string name)
        {
            Guid id = Guid.NewGuid();
            await using var command = new NpgsqlCommand("""
                insert into public.sli_agents(id,host_id,key_fingerprint,registration_host_name)
                values(@id,@id,repeat('a',64),@name)
                """, db);
            command.Parameters.AddWithValue("id", id);
            command.Parameters.AddWithValue("name", name);
            await command.ExecuteNonQueryAsync(ct);
        }

        async Task Reject(string name)
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() => Insert(name));
            Assert.Equal(PostgresErrorCodes.CheckViolation, error.SqlState);
            Assert.Equal("sli_agents_registration_host_name_check", error.ConstraintName);
        }

        await Insert("legacy.example.test");
        await Reject("test-\u041f\u041a");
        await fixture.Pg.ApplyFileAsync(migration, null, ct);

        foreach (string name in new[] { "test-\u041f\u041a", "PC_01", "\U00010400-\u0662.\u2160-\u00b2", new string('\u042f', 63) })
            await Insert(name);
        foreach (string name in new[] { ".", "pc..test", ".pc", "pc.", "pc a", "pc\n", "pc\u200b", "pc\u093e", new string('\u042f', 64),
            string.Join('.', Enumerable.Repeat(new string('a', 63), 4)) })
            await Reject(name);

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Pg.ApplyFileAsync(rollback, null, ct));
        Assert.Contains("non-ASCII agent registration host names exist", failure.Message);
        await using (var count = new NpgsqlCommand("select count(*) from public.sli_agents", db))
            Assert.Equal(5L, await count.ExecuteScalarAsync(ct));
        await Insert("test-\u0411");

        await using (var remove = new NpgsqlCommand("delete from public.sli_agents where registration_host_name <> 'legacy.example.test'", db))
            Assert.Equal(5, await remove.ExecuteNonQueryAsync(ct));
        await fixture.Pg.ApplyFileAsync(rollback, null, ct);
        await Reject("test-\u041f\u041a");
        await Reject("PC_01");
        await using var remaining = new NpgsqlCommand("select registration_host_name from public.sli_agents", db);
        Assert.Equal("legacy.example.test", await remaining.ExecuteScalarAsync(ct));
    }
}
