using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Legacy;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Legacy;

// SQL vectors from tests/sources/test_post_collection_lease_postgres.py.
// Each test uses a disposable PostgreSQL cluster with the installed schema and runtime role.
public sealed class PostCollectionLeasePostgresTests
{
    private const string Job = "lease-test";
    internal static async Task AuthorizeAsync(PostCollectionPostgres pg, CancellationToken ct)
    {
        await using var db = await pg.OpenAsync(ct);
        await using (var exists = new NpgsqlCommand("select to_regclass('public.storage_v2_runtime_authorizations') is not null", db))
            if (await exists.ExecuteScalarAsync(ct) is not true)
            {
                string sql = await File.ReadAllTextAsync(Path.Combine(PostCollectionPostgres.Repository(),
                    "config/postgres_migrations/091_storage_v2_runtime_authorization.sql"), ct);
                string table = System.Text.RegularExpressions.Regex.Match(sql,
                    @"create table storage_v2_runtime_authorizations \([\s\S]*?\r?\n\);").Value;
                Assert.NotEmpty(table);
                await PostCollectionPostgres.Sql(db, table, ct);
            }
        var now = new DateTime(DateTime.UtcNow.Ticks / 10 * 10, DateTimeKind.Utc);
        var record = new DirectRuntimeRecord("v2", "storage-v2-fresh-bootstrap/v1", new string('a', 64),
            Path.Combine(pg.Root, "archive"), new JsonObject { ["kind"] = "fresh-event-store", ["version"] = 1 },
            "fixture-owner", now, now.AddDays(1), null, "");
        await using var seed = new NpgsqlCommand("""
            insert into storage_v2_runtime_authorizations(route,authority,preflight_digest,authorization_digest,
                archive_root,evidence,authorized_by,authorized_at,expires_at)
            values(@route,@authority,@preflight,@digest,@root,@evidence::jsonb,@owner,@issued,@expires)
            """, db);
        seed.Parameters.AddWithValue("route", record.Route); seed.Parameters.AddWithValue("authority", record.Authority);
        seed.Parameters.AddWithValue("preflight", record.PreflightDigest); seed.Parameters.AddWithValue("digest", DirectRuntimeAuthorization.Digest(record));
        seed.Parameters.AddWithValue("root", record.ArchiveRoot); seed.Parameters.AddWithValue("evidence", record.Evidence.ToJsonString());
        seed.Parameters.AddWithValue("owner", record.AuthorizedBy); seed.Parameters.AddWithValue("issued", record.AuthorizedAt);
        seed.Parameters.AddWithValue("expires", record.ExpiresAt);
        await seed.ExecuteNonQueryAsync(ct);
    }
    private sealed class Factory(SqlPostgresFixture fixture) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        {
            var db = new NpgsqlConnection(fixture.Dsn("adlog_user"));
            await db.OpenAsync(ct);
            return db;
        }
    }

    private static Task QueueAsync(LegacyPostStore store, CancellationToken ct) => store.QueueAsync(Job, 1, [], ct);
    private static async Task<LegacyPostClaim> ClaimAsync(LegacyPostStore store, string worker, CancellationToken ct) =>
        Assert.Single(await store.ClaimAsync(worker, 1, ct));
    private static Task ExpireAsync(NpgsqlConnection db, CancellationToken ct) => PostCollectionPostgres.Sql(db,
        "update post_collection_jobs set worker_lease_until=now()-interval '1 second' where durable_job_id='lease-test'", ct);

    private static async Task<JsonObject> ReadAsync(NpgsqlConnection db, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("select row_to_json(p)::text from post_collection_jobs p where durable_job_id=@id", db);
        command.Parameters.AddWithValue("id", Job);
        return JsonNode.Parse((string)(await command.ExecuteScalarAsync(ct))!)!.AsObject();
    }

    private static async Task AssertCannotMutateAsync(LegacyPostStore store, LegacyPostClaim claim,
        NpgsqlConnection db, CancellationToken ct)
    {
        var before = await ReadAsync(db, ct);
        Func<Task>[] mutations = [
            () => store.HeartbeatAsync(claim, "findings_running", ct),
            () => store.FindingsAsync(claim, new JsonObject(), null, ct),
            () => store.FinishAsync(claim, null, null, ct),
            () => store.FinishAsync(claim, null, "synthetic_failure", ct)
        ];
        foreach (var mutate in mutations)
        {
            var error = await Assert.ThrowsAsync<LegacyLeaseLost>(mutate);
            Assert.Equal("post_collection_lease_lost", error.Message);
            Assert.True(JsonNode.DeepEquals(before, await ReadAsync(db, ct)), "Rejected mutation changed the durable job");
        }
    }

    [Theory]
    [InlineData("worker-b")]
    [InlineData("worker-a")]
    public async Task StaleAttemptCannotMutateNewClaimEvenWhenWorkerNameIsReused(string nextWorker)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct); await AuthorizeAsync(fixture.Pg, ct);
        await using var db = await new Factory(fixture).OpenAsync(ct);
        var store = new LegacyPostStore(new Factory(fixture));
        await QueueAsync(store, ct);
        var a = await ClaimAsync(store, "worker-a", ct);
        await ExpireAsync(db, ct);
        await store.RecoverAsync(ct);
        var recovered = await ReadAsync(db, ct);
        Assert.Equal("queued", (string?)recovered["status"]);
        Assert.Null(recovered["worker_id"]);
        Assert.Null(recovered["worker_lease_until"]);
        var b = await ClaimAsync(store, nextWorker, ct);
        Assert.Equal(a.Attempt + 1, b.Attempt);
        await AssertCannotMutateAsync(store, a, db, ct);
        await store.HeartbeatAsync(b, "findings_running", ct);
        await store.FindingsAsync(b, new JsonObject(), null, ct);
        await store.FinishAsync(b, null, null, ct);
        Assert.Equal("completed", (string?)(await ReadAsync(db, ct))["status"]);
        await AssertCannotMutateAsync(store, b, db, ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task ExpiredOwnerCannotResurrectLeaseBeforeRecovery()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct); await AuthorizeAsync(fixture.Pg, ct);
        await using var db = await new Factory(fixture).OpenAsync(ct);
        var store = new LegacyPostStore(new Factory(fixture));
        await QueueAsync(store, ct);
        var claim = await ClaimAsync(store, "worker-a", ct);
        await ExpireAsync(db, ct);
        await AssertCannotMutateAsync(store, claim, db, ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task RecoveryPreservesLiveFinalAttemptThenExhaustsAfterExpiry()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct); await AuthorizeAsync(fixture.Pg, ct);
        await using var db = await new Factory(fixture).OpenAsync(ct);
        var store = new LegacyPostStore(new Factory(fixture));
        await QueueAsync(store, ct);
        await PostCollectionPostgres.Sql(db, "update post_collection_jobs set max_attempts=1 where durable_job_id='lease-test'", ct);
        var claim = await ClaimAsync(store, "worker-a", ct);
        var before = await ReadAsync(db, ct);
        Assert.Equal(1, claim.Attempt);
        Assert.Equal(claim.Attempt, (int)before["max_attempts"]!);
        await store.RecoverAsync(ct);
        Assert.Equal("running", (string?)(await ReadAsync(db, ct))["status"]);
        Assert.True(JsonNode.DeepEquals(before, await ReadAsync(db, ct)));
        await ExpireAsync(db, ct);
        await store.RecoverAsync(ct);
        var exhausted = await ReadAsync(db, ct);
        Assert.Equal("failed", (string?)exhausted["status"]);
        Assert.Equal("post_collection_attempts_exhausted", (string?)exhausted["error_message"]);
        Assert.Empty(await store.ClaimAsync("worker-b", 1, ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Theory]
    [InlineData("queued")]
    [InlineData("running")]
    public async Task RecoveryExhaustsUnleasedFinalAttempt(string status)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct); await AuthorizeAsync(fixture.Pg, ct);
        await using var db = await new Factory(fixture).OpenAsync(ct);
        var store = new LegacyPostStore(new Factory(fixture));
        await QueueAsync(store, ct);
        await using (var seed = new NpgsqlCommand("update post_collection_jobs set status=@status,attempt_count=max_attempts,worker_lease_until=null where durable_job_id=@id", db))
        {
            seed.Parameters.AddWithValue("status", status); seed.Parameters.AddWithValue("id", Job);
            await seed.ExecuteNonQueryAsync(ct);
        }
        await store.RecoverAsync(ct);
        var exhausted = await ReadAsync(db, ct);
        Assert.Equal("failed", (string?)exhausted["status"]);
        Assert.Equal("post_collection_attempts_exhausted", (string?)exhausted["error_message"]);
        Assert.Empty(await store.ClaimAsync("worker-b", 1, ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Theory]
    [InlineData("owner")]
    [InlineData("generation")]
    [InlineData("expired")]
    [InlineData("terminal")]
    public async Task PublicationGuardRejectsLostClaim(string loss)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct); await AuthorizeAsync(fixture.Pg, ct);
        await using var db = await new Factory(fixture).OpenAsync(ct);
        var store = new LegacyPostStore(new Factory(fixture));
        await QueueAsync(store, ct);
        var claim = await ClaimAsync(store, "worker-a", ct);
        switch (loss)
        {
            case "owner": claim = claim with { Worker = "worker-b" }; break;
            case "generation": claim = claim with { Attempt = claim.Attempt + 1 }; break;
            case "expired": await ExpireAsync(db, ct); break;
            case "terminal": await store.FinishAsync(claim, null, null, ct); break;
        }
        var before = await ReadAsync(db, ct);
        bool published = false;
        await Assert.ThrowsAsync<LegacyLeaseLost>(() => store.FenceAsync(claim, () => { published = true; return Task.CompletedTask; }, ct));
        Assert.False(published);
        Assert.True(JsonNode.DeepEquals(before, await ReadAsync(db, ct)));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task PublicationGuardHoldsRowLockUntilPromotionFinishes()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct); await AuthorizeAsync(fixture.Pg, ct);
        await using var db = await new Factory(fixture).OpenAsync(ct);
        var store = new LegacyPostStore(new Factory(fixture));
        await QueueAsync(store, ct);
        var claim = await ClaimAsync(store, "worker-a", ct);
        // NOWAIT proves contention without depending on elapsed time or a lock timeout.
        const string changeOwner = """
            with locked as (select id from post_collection_jobs where durable_job_id='lease-test' for update nowait)
            update post_collection_jobs p set worker_id='worker-b' from locked where p.id=locked.id
            """;
        await store.FenceAsync(claim, async () =>
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() => PostCollectionPostgres.Sql(db, changeOwner, ct));
            Assert.Equal(PostgresErrorCodes.LockNotAvailable, error.SqlState);
            Assert.Equal("worker-a", (string?)(await ReadAsync(db, ct))["worker_id"]);
        }, ct);
        await PostCollectionPostgres.Sql(db, changeOwner, ct);
        Assert.Equal("worker-b", (string?)(await ReadAsync(db, ct))["worker_id"]);
        // This vector deliberately generates PostgreSQL 55P03; do not assert an error-free server log.
    }
}
