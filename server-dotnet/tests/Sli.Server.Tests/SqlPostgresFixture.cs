using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Tests.Agents;
using Xunit;

[assembly: AssemblyFixture<Sli.Server.Tests.SqlPostgresTemplate>]

namespace Sli.Server.Tests;

// Keep cluster-wide state (roles, connection limits and server logs) isolated.
// Each test gets a private copy of this stopped cluster and clones its database.
public sealed class SqlPostgresTemplate : IAsyncDisposable
{
    private static readonly Lazy<Task<SqlPostgresFixture>> Template = new(CreateAsync);

    internal static async Task<string> DataDirectoryAsync(CancellationToken ct) =>
        (await Template.Value.WaitAsync(ct)).Pg.DataDirectory;

    private static async Task<SqlPostgresFixture> CreateAsync()
    {
        var fixture = new SqlPostgresFixture();
        try {
            await fixture.InstallAsync(CancellationToken.None, throughVersion: null);
            await fixture.Pg.FreezeTemplateAsync(CancellationToken.None);
            return fixture;
        } catch {
            await fixture.DisposeAsync();
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (!Template.IsValueCreated) return;
        SqlPostgresFixture fixture;
        try { fixture = await Template.Value; }
        catch { return; } // Failed setup already attempted cleanup and failed the test.
        await fixture.DisposeAsync();
    }
}

// Same clean-install path as ReadSqlPostgresTests. No substitute tables or grants.
internal sealed class SqlPostgresFixture(bool nativeJobAddress = false, string nativeJobHost = "127.0.0.2", int maxConnections = 100, bool trackCommitTimestamps = false) : IAsyncDisposable
{
    internal readonly PostCollectionPostgres Pg = nativeJobAddress
        ? new(canonicalSchema: true, host: nativeJobHost, fixedPort: 5432, database: "sli", maxConnections: maxConnections, trackCommitTimestamps: trackCommitTimestamps)
        : new(canonicalSchema: true, maxConnections: maxConnections, trackCommitTimestamps: trackCommitTimestamps);
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
        if (throughVersion is not null) {
            await InstallAsync(ct, throughVersion);
            return;
        }
        await Pg.StartAsync(ct, await SqlPostgresTemplate.DataDirectoryAsync(ct));
        await using var db = new NpgsqlConnection(Pg.ConnectionString); await db.OpenAsync(ct);
        // PostgreSQL clones objects and their grants, but not the database ACL.
        await GrantWorkerConnectAsync(db, int.MaxValue, ct);
    }

    internal async Task InstallAsync(CancellationToken ct, int? throughVersion)
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
        // Historical tests install only a predecessor. Future roles must come
        // from their real migration; current-schema grants still fail if missing.
        foreach (var (login, role, _) in WorkerRoles.Where(worker => installed[^1] >= worker.Introduced))
            await PostCollectionPostgres.Sql(db, $"create role {login} login nosuperuser nocreatedb nocreaterole noinherit nobypassrls noreplication; grant {role} to {login}", ct);
        await GrantWorkerConnectAsync(db, installed[^1], ct);
    }

    private static readonly (string Login, string Role, int Introduced)[] WorkerRoles =
    [
        ("sli_storage_login", "adlog_storage_worker", 0),
        ("sli_context_login", "adlog_context_worker", 0),
        ("sli_semantic_login", "adlog_semantic_worker", 0),
        ("sli_notification_login", "adlog_notification_worker", 261),
        ("sli_storage_lifecycle_login", "adlog_storage_lifecycle_worker", 319),
        ("sli_storage_lifecycle_delete_login", "adlog_storage_lifecycle_delete", 319),
    ];

    private static Task GrantWorkerConnectAsync(NpgsqlConnection db, int version, CancellationToken ct)
    {
        string database = new NpgsqlCommandBuilder().QuoteIdentifier(db.Database);
        string logins = string.Join(", ", WorkerRoles.Where(worker => version >= worker.Introduced).Select(worker => worker.Login));
        return PostCollectionPostgres.Sql(db, $"grant connect on database {database} to {logins}", ct);
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
