using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Consumer;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class StorageV2WorkerConnectionTests
{
    [Fact]
    public async Task Worker_pool_admits_physical_login_and_resets_role_before_reuse()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(ct);
        await using var admin = await pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(admin, """
            create role adlog_storage_worker nologin nosuperuser nocreatedb nocreaterole noinherit nobypassrls noreplication;
            create role sli_storage_login login nosuperuser nocreatedb nocreaterole noinherit nobypassrls noreplication;
            grant adlog_storage_worker to sli_storage_login;
            alter role sli_storage_login set log_statement='all';
            """, ct);
        await using var runtime = CreateRuntime(pg);
        int physicalPid;
        await using (var db = await runtime.Worker.OpenConnectionAsync(ct))
        {
            physicalPid = db.ProcessID;
            Assert.Equal("adlog_storage_worker", await Scalar(db, "select current_user", ct));
            Assert.Equal("sli_storage_login", await Scalar(db, "select session_user", ct));
            Assert.Equal(false, await Scalar(db, "select rolsuper from pg_roles where rolname=current_user", ct));
            Assert.Equal(false, await Scalar(db, "select has_schema_privilege(current_user,'public','CREATE')", ct));
            await using var state = new NpgsqlCommand("select state='idle' and xact_start is null from pg_stat_activity where pid=@pid", admin);
            state.Parameters.AddWithValue("pid", physicalPid);
            Assert.Equal(true, await state.ExecuteScalarAsync(ct));
            await using (var tx = await db.BeginTransactionAsync(ct)) await tx.RollbackAsync(ct);
            Assert.Equal("adlog_storage_worker", await Scalar(db, "select current_user", ct));
        }

        await using (var reused = await runtime.Worker.OpenConnectionAsync(ct))
        {
            Assert.Equal(physicalPid, reused.ProcessID);
            Assert.Equal("sli_storage_login", await Scalar(reused, "select current_user", ct));
            Assert.Equal(false, await Scalar(reused, "select has_schema_privilege(current_user,'public','CREATE')", ct));
        }

        var now = DateTime.UtcNow;
        var record = new DirectRuntimeRecord("v2", "storage-v2-transition-controller/v1", new string('a', 64),
            pg.Root, new JsonObject(), "synthetic-fixture", now, now.AddMinutes(1), null, "");
        var authorization = DirectRuntimeAuthorization.Validate(
            record with { AuthorizationDigest = DirectRuntimeAuthorization.Digest(record) }, now);
        Assert.Empty(await DirectDictionaries.ResolveAsync(authorization, runtime.Worker, [], ct));

        await using (var reused = await runtime.Worker.OpenConnectionAsync(ct))
        {
            Assert.Equal(physicalPid, reused.ProcessID);
            Assert.Equal("sli_storage_login", await Scalar(reused, "select current_user", ct));
        }

        string log = await pg.DiagnosticsAsync(ct);
        int activate = log.IndexOf("set role adlog_storage_worker", StringComparison.Ordinal);
        Assert.True(activate >= 0, "Worker must explicitly activate its role");
        int verify = log.IndexOf("select current_user as role", activate, StringComparison.Ordinal);
        Assert.True(verify > activate, "Worker must verify the activated role");
        Assert.True(log.IndexOf("COMMIT", verify, StringComparison.Ordinal) > verify, "Worker must commit role activation before returning");
        Assert.Contains("set local role adlog_storage_worker", log);
    }

    [Fact]
    public async Task Login_without_worker_membership_is_rejected_and_connection_is_closed()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(ct);
        await using var admin = await pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(admin, """
            create role adlog_storage_worker nologin;
            create role sli_storage_login login nosuperuser nocreatedb nocreaterole noinherit nobypassrls noreplication;
            """, ct);
        await using var runtime = CreateRuntime(pg);
        var error = await Assert.ThrowsAsync<PostgresException>(async () =>
        {
            await using var db = await runtime.Worker.OpenConnectionAsync(ct);
        });
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
        Assert.Equal(0L, await Scalar(admin, "select count(*) from pg_stat_activity where usename='sli_storage_login'", ct));
    }

    private static DirectAdDcRuntime CreateRuntime(PostCollectionPostgres pg)
    {
        var dsn = new NpgsqlConnectionStringBuilder(pg.ConnectionString) { Username = "sli_storage_login" }.ConnectionString;
        return DirectAdDcRuntime.TryCreate(key => key == "ADLOG_STORAGE_V2_WORKER_DSN" ? dsn : null,
            _ => throw new InvalidOperationException("No secret files in this fixture"), Path.GetFullPath("synthetic-catalog.json"))!;
    }

    private static async Task<object?> Scalar(NpgsqlConnection db, string sql, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand(sql, db);
        return await cmd.ExecuteScalarAsync(ct);
    }
}
