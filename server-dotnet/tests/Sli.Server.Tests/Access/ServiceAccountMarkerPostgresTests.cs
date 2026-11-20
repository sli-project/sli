using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Access.Administration;
using Sli.Server.Auth.Administration;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Access;

// Parity with tests/access/test_service_account_marker_postgres.py.
public sealed class ServiceAccountMarkerPostgresTests
{
    // Break caught: inferring service origin from a name, failed/foreign audit,
    // losing explicit provenance, changing account data or widening table grants.
    [Fact]
    public async Task MigrationRecoversOnlyProvenOriginsAndSurvivesEvidenceDeletion()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString);
        await db.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, """
            alter table auth_users drop column is_service;
            delete from schema_migrations where version=280;
            """, ct);
        var cases = new Dictionary<string, bool> {
            ["live"] = true, ["issued"] = true, ["partial"] = true,
            ["failed"] = false, ["wrong-subject"] = false, ["wrong-actor"] = false,
            ["wrong-target"] = false, ["prefix-only"] = false
        };
        var ids = new Dictionary<string, long>();
        foreach (string name in cases.Keys)
        {
            await using var insert = new NpgsqlCommand("""
                insert into auth_users(username,password_hash,role,is_active)
                values(@name,'synthetic','viewer',false) returning id
                """, db);
            insert.Parameters.AddWithValue("name", "report-key-synthetic-" + name);
            ids[name] = Convert.ToInt64(await insert.ExecuteScalarAsync(ct));
        }
        await using (var key = new NpgsqlCommand("""
            insert into auth_api_keys(key_prefix,key_hash,label,role,report_subject_id)
            values('synthetic-live','synthetic-hash','synthetic','viewer',@id)
            """, db))
        {
            key.Parameters.AddWithValue("id", ids["live"]);
            Assert.Equal(1, await key.ExecuteNonQueryAsync(ct));
        }
        foreach (string name in new[] { "issued", "partial", "failed", "wrong-subject", "wrong-actor", "wrong-target" })
        {
            await using var audit = new NpgsqlCommand("""
                insert into access_audit_v4(actor_type,action,subject_type,subject_id,target_type,target_key,outcome)
                values(@actor,@action,@subject,@id,@target,'1',@outcome)
                """, db);
            audit.Parameters.AddWithValue("actor", name == "wrong-actor" ? "session" : "local_operator");
            audit.Parameters.AddWithValue("action", name == "partial" ? "report_key_capabilities_created" : "report_api_key_issued");
            audit.Parameters.AddWithValue("subject", name == "wrong-subject" ? "group" : "user");
            audit.Parameters.AddWithValue("id", ids[name]);
            audit.Parameters.AddWithValue("target", name is "partial" or "wrong-target" ? "ad_domain" : "api_key");
            audit.Parameters.AddWithValue("outcome", name == "failed" ? "error" : "ok");
            Assert.Equal(1, await audit.ExecuteNonQueryAsync(ct));
        }
        const string accountSnapshot = "select coalesce(jsonb_agg(r order by id),'[]'::jsonb)::text from (select id,role,is_active,password_hash from auth_users) r";
        string before = await ScalarAsync(db, accountSnapshot, ct);
        string aclBefore = await ScalarAsync(db, AclSnapshot, ct);
        await fixture.Pg.ApplyFileAsync(Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/280_service_account_origin.sql"), null, ct);
        var observed = await MarkersAsync(db, ct);
        foreach (var (name, expected) in cases) Assert.Equal(expected, observed[ids[name]]);
        Assert.Equal(before, await ScalarAsync(db, accountSnapshot, ct));
        Assert.Equal(aclBefore, await ScalarAsync(db, AclSnapshot, ct));
        await using (var delete = new NpgsqlCommand("""
            delete from auth_api_keys where report_subject_id=any(@ids);
            delete from access_audit_v4 where subject_id=any(@ids);
            """, db))
        {
            delete.Parameters.AddWithValue("ids", ids.Values.ToArray());
            Assert.Equal(7, await delete.ExecuteNonQueryAsync(ct));
        }
        Assert.Equal(observed.OrderBy(p => p.Key), (await MarkersAsync(db, ct)).OrderBy(p => p.Key));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    // Break caught: CreateAsync failing to persist the marker, listings relying
    // only on live keys, prefix-based classification, leaking hashes or new grants.
    [Fact]
    public async Task RuntimeRoleCreatesAndListsServiceAfterKeyDeletionWithoutNewGrants()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        var connections = new PostgresConnectionFactory(new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user") }).Build());
        var users = new UserAdministrationService(connections, new PasswordCodec(), new AuthAudit(connections));
        var access = new AccessReadService(connections);
        await using var db = await connections.OpenAsync(ct);
        Assert.Equal("adlog_user", await ScalarAsync(db, "select current_user::text", ct));
        string aclBefore = await ScalarAsync(db, AclSnapshot, ct);
        const string password = "Synthetic-marker-password";
        var actor = new UserAdministrationActor("session", null, "192.0.2.80");
        var person = await users.CreateAsync(new("report-key-synthetic-person", password, "viewer"), actor, ct);
        var service = await users.CreateAsync(new("renamed-synthetic-service", password, "viewer", IsService: true), actor, ct);
        long personId = person.GetProperty("id").GetInt64(), serviceId = service.GetProperty("id").GetInt64();
        var expected = new Dictionary<long, bool> { [personId] = false, [serviceId] = true };
        foreach (var (id, marker) in expected) Assert.Equal(marker, (await MarkersAsync(db, ct))[id]);
        await using (var key = new NpgsqlCommand("""
            insert into auth_api_keys(key_prefix,key_hash,label,role,report_subject_id)
            values('synthetic-deleted',@hash,'synthetic','viewer',@id) returning id
            """, db))
        {
            key.Parameters.AddWithValue("hash", Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("synthetic-deleted"))));
            key.Parameters.AddWithValue("id", serviceId);
            long keyId = Convert.ToInt64(await key.ExecuteScalarAsync(ct));
            await using var delete = new NpgsqlCommand("delete from auth_api_keys where id=@id", db);
            delete.Parameters.AddWithValue("id", keyId);
            Assert.Equal(1, await delete.ExecuteNonQueryAsync(ct));
        }
        var subjects = JsonSerializer.SerializeToElement(await access.GetSubjectsAsync("all", ct));
        foreach (var rows in new[] { (await users.ListAsync(ct)).ToArray(), subjects.GetProperty("users").EnumerateArray().ToArray() })
        {
            foreach (var (id, marker) in expected)
                Assert.Equal(marker, Assert.Single(rows, row => row.GetProperty("id").GetInt64() == id).GetProperty("is_service").GetBoolean());
            Assert.All(rows, AssertSafe);
        }
        foreach (var (kind, marker, id) in new[] { ("people", false, personId), ("service", true, serviceId) })
        {
            var rows = JsonSerializer.SerializeToElement(await access.GetSubjectsAsync(kind, ct)).GetProperty("users").EnumerateArray().ToArray();
            Assert.All(rows, row => { Assert.Equal(marker, row.GetProperty("is_service").GetBoolean()); AssertSafe(row); });
            Assert.Equal(new[] { id }, rows.Select(row => row.GetProperty("id").GetInt64()).Where(expected.ContainsKey));
        }
        Assert.Equal(aclBefore, await ScalarAsync(db, AclSnapshot, ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    private const string AclSnapshot = """
        select jsonb_agg(r order by relname)::text from (
            select relname,relowner,relacl from pg_class
            where oid in ('auth_users'::regclass,'auth_api_keys'::regclass,'access_audit_v4'::regclass)
        ) r
        """;

    private static void AssertSafe(JsonElement row)
    {
        Assert.False(row.TryGetProperty("password_hash", out _));
        Assert.False(row.TryGetProperty("key_hash", out _));
    }

    private static async Task<string> ScalarAsync(NpgsqlConnection db, string sql, CancellationToken ct)
    {
        await using var query = new NpgsqlCommand(sql, db);
        return (string)(await query.ExecuteScalarAsync(ct))!;
    }

    private static async Task<Dictionary<long, bool>> MarkersAsync(NpgsqlConnection db, CancellationToken ct)
    {
        await using var query = new NpgsqlCommand("select id,is_service from auth_users", db);
        await using var rows = await query.ExecuteReaderAsync(ct);
        var result = new Dictionary<long, bool>();
        while (await rows.ReadAsync(ct)) result.Add(rows.GetInt64(0), rows.GetBoolean(1));
        return result;
    }
}
