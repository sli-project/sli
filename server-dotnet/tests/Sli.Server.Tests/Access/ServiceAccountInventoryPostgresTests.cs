using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Access.Administration;
using Sli.Server.Auth.Administration;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Infrastructure;
using Xunit;

namespace Sli.Server.Tests.Access;

// Vectors from tests/access/test_service_account_inventory_postgres.py, on the
// migrated production schema and through both production inventory readers.
public sealed class ServiceAccountInventoryPostgresTests
{
    [Fact]
    public async Task BothInventoriesClassifyByKeyRelationshipAfterRevocationAndExpiryWithoutWriting()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        string suffix = Guid.NewGuid().ToString("N");
        var expected = new Dictionary<long, bool>();
        foreach (var (name, active, service) in new[] {
            ("person", true, false), ("report-key-person", false, false),
            ("renamed-reader", true, true), ("revoked-reader", false, true), ("expired-reader", true, true) })
        {
            await using var user = new NpgsqlCommand("""
                insert into auth_users(username,password_hash,role,is_active)
                values(@name,'synthetic-unusable','viewer',@active) returning id
                """, db);
            user.Parameters.AddWithValue("name", name + "-" + suffix); user.Parameters.AddWithValue("active", active);
            long id = Convert.ToInt64(await user.ExecuteScalarAsync(ct)); expected.Add(id, service);
            if (!service) continue;
            for (int number = 0; number < (name == "renamed-reader" ? 2 : 1); number++)
                await InsertKeyAsync(db, $"synthetic-{suffix}-{name}-{number}", id, active,
                    revoked: name == "revoked-reader", expired: name == "expired-reader", ct);
        }
        // A key without a report subject must not classify a person as service.
        await InsertKeyAsync(db, "synthetic-" + suffix + "-ordinary", null, true, false, false, ct);
        string before = await SnapshotAsync(db, ct);
        var connections = Connections(fixture);
        var users = new UserAdministrationService(connections, new PasswordCodec(), new AuthAudit(connections));
        var subjects = new AccessReadService(connections);
        foreach (var rows in new[] {
            (await users.ListAsync(ct)).ToArray(),
            JsonSerializer.SerializeToElement(await subjects.GetSubjectsAsync("all", ct)).GetProperty("users").EnumerateArray().ToArray() })
        {
            var observed = rows.Where(row => expected.ContainsKey(row.GetProperty("id").GetInt64())).ToArray();
            Assert.Equal(expected.Count, observed.Length);
            foreach (var (id, service) in expected)
            {
                var row = Assert.Single(observed, row => row.GetProperty("id").GetInt64() == id);
                Assert.Equal(service ? JsonValueKind.True : JsonValueKind.False, row.GetProperty("is_service").ValueKind);
            }
            Assert.All(rows, row => {
                Assert.False(row.TryGetProperty("password_hash", out _));
                Assert.False(row.TryGetProperty("key_hash", out _));
            });
            Assert.Equal(before, await SnapshotAsync(db, ct));
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task SubjectTypeFilterPrecedesCapWith501OppositeAccounts(bool majorityService, bool markerOnly)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        string suffix = Guid.NewGuid().ToString("N");
        var majorityIds = new List<long>();
        await using (var users = new NpgsqlCommand("""
            insert into auth_users(username,password_hash,role)
            select @prefix || n::text,'synthetic-unusable','viewer' from generate_series(1,501) n returning id
            """, db))
        {
            users.Parameters.AddWithValue("prefix", "aaaa-t007-" + suffix + "-");
            await using var rows = await users.ExecuteReaderAsync(ct);
            while (await rows.ReadAsync(ct)) majorityIds.Add(rows.GetInt64(0));
        }
        long minorityId;
        await using (var user = new NpgsqlCommand("""
            insert into auth_users(username,password_hash,role)
            values(@name,'synthetic-unusable','viewer') returning id
            """, db))
        {
            user.Parameters.AddWithValue("name", "zzzz-t007-" + suffix);
            minorityId = Convert.ToInt64(await user.ExecuteScalarAsync(ct));
        }
        long[] serviceIds = majorityService ? majorityIds.ToArray() : [minorityId];
        if (markerOnly)
        {
            await using var mark = new NpgsqlCommand("update auth_users set is_service=true where id=any(@ids)", db);
            mark.Parameters.AddWithValue("ids", serviceIds);
            Assert.Equal(serviceIds.Length, await mark.ExecuteNonQueryAsync(ct));
        }
        else
            foreach (long id in serviceIds)
                await InsertKeyAsync(db, $"t007-{suffix}-{id}", id, false, true, false, ct);

        var reader = new AccessReadService(Connections(fixture));
        async Task<JsonElement[]> ReadAsync(string kind) => JsonSerializer.SerializeToElement(
            await reader.GetSubjectsAsync(kind, ct)).GetProperty("users").EnumerateArray().ToArray();
        var unfiltered = await ReadAsync("all");
        Assert.Equal(500, unfiltered.Length);
        Assert.DoesNotContain(unfiltered, row => row.GetProperty("id").GetInt64() == minorityId);
        foreach (var (kind, service) in new[] { ("people", false), ("service", true) })
        {
            var filtered = await ReadAsync(kind);
            Assert.InRange(filtered.Length, 1, 500);
            Assert.All(filtered, row => Assert.Equal(service, row.GetProperty("is_service").GetBoolean()));
            if (service != majorityService)
                Assert.Contains(filtered, row => row.GetProperty("id").GetInt64() == minorityId);
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    private static PostgresConnectionFactory Connections(SqlPostgresFixture fixture) => new(
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user") }).Build());

    private static async Task InsertKeyAsync(NpgsqlConnection db, string label, long? subject,
        bool active, bool revoked, bool expired, CancellationToken ct)
    {
        await using var key = new NpgsqlCommand("""
            insert into auth_api_keys(key_prefix,key_hash,label,role,is_active,report_subject_id,revoked_at,expires_at)
            values(@label,@hash,@label,'viewer',@active,@subject,
                case when @revoked then now() else null end,
                now() + case when @expired then interval '-1 day' else interval '1 day' end)
            """, db);
        key.Parameters.AddWithValue("label", label);
        key.Parameters.AddWithValue("hash", Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(label))));
        key.Parameters.AddWithValue("active", active);
        key.Parameters.AddWithValue("subject", NpgsqlDbType.Bigint, subject.HasValue ? subject.Value : DBNull.Value);
        key.Parameters.AddWithValue("revoked", revoked); key.Parameters.AddWithValue("expired", expired);
        Assert.Equal(1, await key.ExecuteNonQueryAsync(ct));
    }

    private static async Task<string> SnapshotAsync(NpgsqlConnection db, CancellationToken ct)
    {
        await using var snapshot = new NpgsqlCommand("""
            select jsonb_build_object(
                'users',(select jsonb_agg(to_jsonb(u) order by id) from auth_users u),
                'keys',(select jsonb_agg(to_jsonb(k) order by id) from auth_api_keys k))::text
            """, db);
        return (string)(await snapshot.ExecuteScalarAsync(ct))!;
    }
}
