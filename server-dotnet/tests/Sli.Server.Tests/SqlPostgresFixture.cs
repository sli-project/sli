using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests;

// Same clean-install path as ReadSqlPostgresTests. No substitute tables or grants.
internal sealed class SqlPostgresFixture(bool nativeJobAddress = false, string nativeJobHost = "127.0.0.2", int maxConnections = 100) : IAsyncDisposable
{
    internal readonly PostCollectionPostgres Pg = nativeJobAddress
        ? new(canonicalSchema: true, host: nativeJobHost, fixedPort: 5432, database: "sli", maxConnections: maxConnections)
        : new(canonicalSchema: true, maxConnections: maxConnections);
    internal static string Repository([System.Runtime.CompilerServices.CallerFilePath] string path = "") =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(path)!, "../../.."));
    internal string Dsn(string role) => new NpgsqlConnectionStringBuilder(Pg.ConnectionString) { Username = role }.ConnectionString;
    internal async Task<string[]> RollbackAfterAsync(int version, CancellationToken ct)
    {
        // A migration test can reapply only its own version after an earlier
        // rollback. Later files on disk are not necessarily installed again.
        var installed = new HashSet<int>();
        await using (var db = new NpgsqlConnection(Pg.ConnectionString)) {
            await db.OpenAsync(ct);
            await using var command = new NpgsqlCommand("select version from schema_migrations where version>@version", db);
            command.Parameters.AddWithValue("version", version);
            await using var rows = await command.ExecuteReaderAsync(ct);
            while (await rows.ReadAsync(ct)) installed.Add(rows.GetInt32(0));
        }
        var files = MigrationDirectory.Read(version + 1)
            .Where(item => installed.Contains(item.Version))
            .OrderByDescending(item => item.Version).Select(item => item.Path).ToArray();
        foreach (string file in files) await Pg.ApplyFileAsync(Path.ChangeExtension(file, ".rollback.sql"), null, ct);
        return files;
    }
    internal async Task StartAsync(CancellationToken ct, int? throughVersion = null)
    {
        await Pg.StartAsync(ct);
        await using var db = new NpgsqlConnection(Pg.ConnectionString); await db.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, "create role adlog_user login nosuperuser nocreatedb nocreaterole noinherit nobypassrls noreplication", ct);
        string root = Repository(), baseline = Path.Combine(root, "config/postgres_baseline");
        var manifest = JsonNode.Parse(File.ReadAllText(Path.Combine(baseline, "manifest.json")))!;
        int version = manifest["baseline_version"]!.GetValue<int>();
        foreach (var file in manifest["files"]!.AsObject()) Assert.Equal(file.Value!.GetValue<string>(), Hash(Path.Combine(baseline, file.Key)));
        var migrations = MigrationDirectory.Read().Where(m => throughVersion is null || m.Version <= throughVersion).ToArray();
        Assert.Equal(migrations.Count(m => m.Version <= version), manifest["migrations"]!.AsObject().Count);
        foreach (var migration in migrations.Where(m => m.Version <= version)) Assert.Equal(manifest["migrations"]![migration.Version.ToString()]!.GetValue<string>(), Hash(migration.Path));
        await Pg.ApplyFileAsync(Path.Combine(baseline, "roles.sql"), null, ct);
        string rendered = Path.Combine(Pg.Root, "baseline.sql");
        await File.WriteAllTextAsync(rendered, File.ReadAllText(Path.Combine(baseline, "baseline.sql")).Replace(manifest["domain_placeholder"]!.GetValue<string>(), "example.test"), ct);
        await Pg.ApplyFileAsync(rendered, null, ct);
        await PostCollectionPostgres.Sql(db, "insert into auth_users(username,password_hash,role) values('platform-owner','synthetic-unusable-hash','admin')", ct);
        foreach (var migration in migrations.Where(m => m.Version > version)) await Pg.ApplyFileAsync(migration.Path, null, ct);
        var installed = new List<int>();
        await using (var ledger = new NpgsqlCommand("select version from schema_migrations where version>=9 order by version", db))
        await using (var rows = await ledger.ExecuteReaderAsync(ct)) while (await rows.ReadAsync(ct)) installed.Add(rows.GetInt32(0));
        Assert.Equal(migrations.Select(m => m.Version), installed);
        // deploy/linux/migrate.py configure_worker_logins: NOINHERIT + one role,
        // requiring the worker to SET ROLE itself, exactly as native runtime.
        // CONNECT belongs to the login: SET ROLE is only possible after connecting.
        string database = new NpgsqlCommandBuilder().QuoteIdentifier(db.Database);
        (string Login, string Role, int Introduced)[] workerRoles =
        [
            ("sli_storage_login", "adlog_storage_worker", version),
            ("sli_context_login", "adlog_context_worker", version),
            ("sli_semantic_login", "adlog_semantic_worker", version),
            ("sli_notification_login", "adlog_notification_worker", 261),
            ("sli_storage_lifecycle_login", "adlog_storage_lifecycle_worker", 319),
            ("sli_storage_lifecycle_delete_login", "adlog_storage_lifecycle_delete", 319),
        ];
        // Historical tests install only a predecessor. Future roles must come
        // from their real migration; current-schema grants still fail if missing.
        foreach (var (login, role, _) in workerRoles.Where(worker => installed[^1] >= worker.Introduced))
            await PostCollectionPostgres.Sql(db, $"create role {login} login nosuperuser nocreatedb nocreaterole noinherit nobypassrls noreplication; grant {role} to {login}; grant connect on database {database} to {login}", ct);
    }
    internal async Task<string> SeedOwnerAsync(CancellationToken ct)
    {
        string token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        await using var db = new NpgsqlConnection(Pg.ConnectionString); await db.OpenAsync(ct);
        await using var seed = new NpgsqlCommand("""
            insert into auth_sessions(user_id,token_hash,expires_at) select id,@hash,now()+interval '1 hour' from auth_users where username='platform-owner';
            insert into access_platform_owners(user_id,owner_key,business_reason) select id,'primary','synthetic SQL test' from auth_users where username='platform-owner' on conflict do nothing;
            """, db);
        seed.Parameters.AddWithValue("hash", Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)))) ; await seed.ExecuteNonQueryAsync(ct);
        return token;
    }
    // allowLockTimeout: a bounded wait for a lock that ran out is a normal outcome for the backfill, not a failure.
    internal async Task AssertNoSqlErrorsAsync(CancellationToken ct, bool allowLockTimeout = false)
    {
        string log = await Pg.DiagnosticsAsync(ct);
        // A background autovacuum yielding to DDL is normal server behavior, not a statement failure.
        string ignored = allowLockTimeout ? "|canceling statement due to lock timeout|тайм-аута блокировки" : "";
        var error = Regex.Match(log, @"(?m)^(?!.*(?:canceling autovacuum task|отмена задачи автоочистки" + ignored + @")).*(?:ERROR:|FATAL:|ОШИБКА:|ВАЖНО:).*$");
        Assert.False(error.Success, error.Value);
    }
    private static string Hash(string path) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(File.ReadAllText(path).Replace("\r\n", "\n"))));
    public ValueTask DisposeAsync() => Pg.DisposeAsync();
}
