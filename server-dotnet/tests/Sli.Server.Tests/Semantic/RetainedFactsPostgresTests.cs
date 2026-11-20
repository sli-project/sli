using System.Text.Json.Nodes;
using Npgsql;
using Microsoft.Extensions.Configuration;
using Sli.Server.Semantic;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Semantic;

[Collection("Semantic producer environment")]
public sealed class RetainedFactsPostgresTests
{
    private static readonly string Hash = string.Concat(Enumerable.Repeat("63", 32));
    private static readonly string OtherHash = string.Concat(Enumerable.Repeat("64", 32));
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    // Test the shipped controller rather than the removed duplicate archive poller.
    private sealed class Database(string dsn, string? role) : ISemanticDatabase
    {
        public async Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct)
        {
            var db = new NpgsqlConnection(dsn); await db.OpenAsync(ct);
            var tx = await db.BeginTransactionAsync(ct);
            var session = new SemanticSession(db, tx, ownsConnection: true);
            if (!write) await session.ExecuteAsync("set transaction read only", ct);
            if (role is not null) await session.QueryAsync("select set_config('role',$1,true)", ct, role);
            return session;
        }
    }
    private static RetainedFactsControl Control(NpgsqlConnection db, string path = "unused", string fingerprint = "test-rules", string? role = null) =>
        new(new Database(db.ConnectionString, role), path, fingerprint, () => { });
    private sealed record Snapshot(JsonObject Identity, long HighWatermark);
    private static async Task<Snapshot> SnapshotAsync(NpgsqlConnection db, CancellationToken ct)
    {
        var plan = await Control(db).PlanAsync(ct);
        return new(plan["database_identity"]!.AsObject(), plan.Number("observed_high_watermark_event_id"));
    }
    private static Task<JsonObject> CheckQueueAsync(NpgsqlConnection db, IReadOnlyCollection<long> ids, CancellationToken ct) =>
        Control(db).QueueStatusAsync(ids.Distinct().ToArray(), ct);
    private static async Task<JsonObject> PollAsync(NpgsqlConnection db, string path, string fingerprint, CancellationToken ct)
    {
        // Poll owns a controller transaction and a separate publication connection.
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string,string?> { ["ConnectionStrings:Sli"] = db.ConnectionString }).Build();
        await new RetainedFactsControl(new SemanticDatabase(new Sli.Server.Infrastructure.PostgresConnectionFactory(config)), path, fingerprint).PollAsync(ct);
        return RetainedFactsControl.Read(path)!;
    }

    // Same deliberately narrow PostgreSQL types as the Python vectors. Each
    // test owns a fresh cluster; neither inherited DSNs nor stand data are used.
    private sealed class Fixture : IAsyncDisposable
    {
        internal readonly PostCollectionPostgres Pg = new(canonicalSchema: true);
        internal NpgsqlConnection Db = null!;
        internal async Task Start()
        {
            await Pg.StartAsync(Ct); Db = await Pg.OpenAsync(Ct);
            await RetainedShortPostgresSource.Create(Db, Ct);
            await Sql("""
                create table public.semantic_processing_outbox(source_event_id integer not null,job_kind text not null,
                  semantic_contract_version integer not null,processor_id text not null,processor_version text not null,
                  source_identity_json jsonb not null,status text not null);
                create table public.normalized_events(source_event_id integer not null,semantic_contract_version integer not null,
                  normalizer_id text not null,normalizer_version text not null,processing_status text not null,source_event_sha256 bytea not null);
                """);
            await RetainedShortPostgresSource.Insert(Db, 7, Hash, Ct);
        }
        internal async Task Sql(string sql, params object?[] values)
        {
            await using var command = new NpgsqlCommand(sql, Db) { CommandTimeout = 0 };
            SemanticSession.Parameters(command, values); await command.ExecuteNonQueryAsync(Ct);
        }
        internal Task Job(string status, string? field = null, object? stale = null, JsonObject? identity = null)
        {
            object Value(string key, object value) => field == key ? stale! : value;
            return Sql("insert into public.semantic_processing_outbox values($1,$2,$3,$4,$5,$6,$7)",
                Value("source_event_id", 7), Value("job_kind", "normalize_event"), Value("semantic_contract_version", 1),
                Value("processor_id", "semantic-shadow"), Value("processor_version", SemanticEvent.Version),
                identity ?? new JsonObject { ["id"] = 7, ["normalized_hash"] = Hash }, status);
        }
        internal Task Normalized(string? field = null, object? stale = null)
        {
            object Value(string key, object value) => field == key ? stale! : value;
            return Sql("insert into public.normalized_events values($1,$2,$3,$4,$5,$6)",
                Value("source_event_id", 7), Value("semantic_contract_version", 1), Value("normalizer_id", SemanticEvent.Normalizer),
                Value("normalizer_version", SemanticEvent.Version), Value("processing_status", "normalized"),
                Value("source_event_sha256", Convert.FromHexString(Hash)));
        }
        internal Task<JsonObject> Check(params long[] ids) => CheckQueueAsync(Db, ids.Length == 0 ? [7] : ids, Ct);
        public async ValueTask DisposeAsync() { if (Db is not null) await Db.DisposeAsync(); await Pg.DisposeAsync(); }
    }

    private static void Only(JsonObject states, string state, long count = 1)
    {
        Assert.Equal(new[] { "completed", "failed", "incomplete", "leased", "not_enqueued", "quarantined", "queued" }, states.Select(p => p.Key).Order());
        foreach (string key in states.Select(p => p.Key)) Assert.Equal(key == state ? count : 0, states.Number(key));
    }

    [Fact]
    public async Task Actual_database_identity_and_frozen_watermark()
    {
        await using var f = new Fixture(); await f.Start();
        var snapshot = await SnapshotAsync(f.Db, Ct);
        Assert.Equal(7, snapshot.HighWatermark);
        await using var tx = await f.Db.BeginTransactionAsync(Ct);
        var expected = (await new SemanticSession(f.Db, tx).QueryAsync("""
            select system_identifier::text as system_identifier,current_database() as database,session_user as role,
              inet_server_addr()::text as host,inet_server_port()::text as port,
              (select oid::text from pg_database where datname=current_database()) as database_oid from pg_control_system()
            """, Ct)).Single();
        Assert.True(JsonNode.DeepEquals(expected, snapshot.Identity));
        Assert.Equal(6, snapshot.Identity.Count);
        Assert.All(snapshot.Identity, field => Assert.False(string.IsNullOrEmpty(field.Value?.GetValue<string>())));
        await tx.CommitAsync(Ct);
        await RetainedShortPostgresSource.Insert(f.Db, 8, Hash, Ct);
        Assert.Equal(7, snapshot.HighWatermark);
        Assert.Equal(8, (await SnapshotAsync(f.Db, Ct)).HighWatermark);
    }

    [Fact]
    public async Task Denied_identity_stops_poll_before_selection_publication_or_checkpoint()
    {
        using var admission = new SemanticProducerPostgresTests.Admission(SemanticRuntimeSettings.FactsMode);
        await using var f = new Fixture(); await f.Start();
        string path = Path.Combine(f.Pg.Root, "checkpoint.json");
        await f.Sql("""
            create role sli_test_identity nologin nosuperuser nocreatedb nocreaterole noinherit;
            revoke execute on function pg_catalog.pg_control_system() from public,sli_test_identity;
            """);
        // No table privileges: attempting selection or publication first would
        // produce the wrong error. SET ROLE also proves PUBLIC is insufficient.
        await using var denied = await f.Pg.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(denied, "set role sli_test_identity", Ct);
        await using (var check = new NpgsqlCommand("select has_function_privilege(current_user,'pg_catalog.pg_control_system()','EXECUTE')", denied))
            Assert.Equal(false, await check.ExecuteScalarAsync(Ct));
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Control(denied, path, role: "sli_test_identity").PollAsync(Ct));
        Assert.Contains("read-only EXECUTE on pg_control_system", error.Message);
        Assert.False(File.Exists(path));
        Assert.Empty(Directory.GetFiles(f.Pg.Root, "checkpoint.json*"));
        Only(await f.Check(), "not_enqueued");
        // The poll's session lock was released on failure.
        await using var unlocked = new NpgsqlCommand("select pg_try_advisory_lock(hashtext('semantic_retained_v2_facts_controller'))", f.Db);
        Assert.Equal(true, await unlocked.ExecuteScalarAsync(Ct));
    }

    [Theory]
    [InlineData("completed", "queued", "semantic_contract_version")]
    [InlineData("completed", "queued", "processor_id")]
    [InlineData("completed", "queued", "processor_version")]
    [InlineData("failed", "completed", "semantic_contract_version")]
    [InlineData("failed", "completed", "processor_id")]
    [InlineData("failed", "completed", "processor_version")]
    public async Task Current_queue_contract_ignores_stale_rows(string old, string current, string field)
    {
        await using var f = new Fixture(); await f.Start();
        await f.Job(old, field, field == "semantic_contract_version" ? 2 : "fixture-other");
        await f.Job(current); await f.Normalized();
        Only(await f.Check(), current);
    }

    [Theory]
    [InlineData("semantic_contract_version")]
    [InlineData("normalizer_id")]
    [InlineData("normalizer_version")]
    [InlineData("processing_status")]
    [InlineData("source_event_sha256")]
    [InlineData("source_event_id")]
    public async Task Normalization_requires_every_current_predicate(string field)
    {
        await using var f = new Fixture(); await f.Start();
        object stale = field switch { "semantic_contract_version" => 2, "source_event_id" => 8,
            "source_event_sha256" => Convert.FromHexString(OtherHash), "processing_status" => "failed", _ => "fixture-other" };
        await f.Job("completed"); await f.Normalized(field, stale);
        Only(await f.Check(), "incomplete");
        await f.Normalized(); Only(await f.Check(), "completed");
    }

    [Theory]
    [InlineData("id")]
    [InlineData("normalized_hash")]
    [InlineData("missing")]
    public async Task Source_identity_mismatch_is_incomplete(string field)
    {
        await using var f = new Fixture(); await f.Start();
        var identity = field == "missing" ? new JsonObject() : new JsonObject { ["id"] = field == "id" ? 8 : 7,
            ["normalized_hash"] = field == "normalized_hash" ? OtherHash : Hash };
        await f.Job("completed", identity: identity); await f.Normalized();
        Only(await f.Check(), "incomplete");
    }

    [Fact]
    public async Task Duplicate_current_coverage_is_rejected()
    {
        await using var f = new Fixture(); await f.Start();
        await f.Job("queued"); await f.Job("completed"); await f.Normalized();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => f.Check());
        Assert.Contains("ambiguous", error.Message);
    }

    [Fact]
    public async Task Absent_current_jobs_preserve_no_admitted_contract()
    {
        await using var f = new Fixture(); await f.Start();
        await f.Job("completed", "processor_version", "fixture-old"); await f.Normalized();
        Only(await f.Check(), "not_enqueued");
        await f.Job("completed", "job_kind", "investigation_context");
        Only(await f.Check(), "not_enqueued");
    }

    [Theory]
    [InlineData("queued")]
    [InlineData("failed")]
    [InlineData("leased")]
    [InlineData("quarantined")]
    public async Task Noncompleted_states_need_identity_but_not_normalization(string status)
    {
        await using var f = new Fixture(); await f.Start(); await f.Job(status);
        Only(await f.Check(), status);
        await f.Sql("update public.semantic_processing_outbox set source_identity_json='{}'");
        Only(await f.Check(), "incomplete");
    }

    [Theory]
    [InlineData("incomplete")]
    [InlineData("unknown")]
    public async Task Invalid_persisted_status_is_rejected(string status)
    {
        await using var f = new Fixture(); await f.Start(); await f.Job(status);
        await Assert.ThrowsAsync<InvalidOperationException>(() => f.Check());
    }

    [Fact]
    public async Task Empty_unique_and_missing_source_boundaries()
    {
        await using var f = new Fixture(); await f.Start();
        Only(await CheckQueueAsync(f.Db, [], Ct), "not_enqueued", 0);
        await f.Job("completed"); Only(await f.Check(7, 7), "incomplete");
        await f.Normalized(); Only(await f.Check(7, 7), "completed");
        await f.Sql("delete from public.event_cold_facts"); Only(await f.Check(), "incomplete");
        Assert.Equal(0, (await SnapshotAsync(f.Db, Ct)).HighWatermark);
    }

    [Fact]
    public async Task Poll_publishes_real_jobs_and_resume_keeps_frozen_range_and_identity()
    {
        using var admission = new SemanticProducerPostgresTests.Admission(SemanticRuntimeSettings.FactsMode);
        await using var f = new SqlPostgresFixture(); await f.StartAsync(Ct);
        await using var db = await f.Pg.OpenAsync(Ct);
        await SemanticRuntimePostgresTests.SeedShortAsync(f, db, 0, Ct);
        await PostCollectionPostgres.Sql(db, "delete from semantic_processing_outbox", Ct);
        string path = Path.Combine(f.Pg.Root, "checkpoint.json");
        var first = await PollAsync(db, path, "test-rules", Ct);
        Assert.Equal(900003, first.Number("frozen_high_watermark_event_id"));
        Assert.Equal(900003, first.Number("last_committed_event_id"));
        Assert.Equal("complete", first.Text("status"));
        Assert.True(JsonNode.DeepEquals(first, JsonNode.Parse(await File.ReadAllTextAsync(path, Ct))));
        var jobs = await CheckQueueAsync(db, [900001, 900003], Ct);
        Only(jobs, "queued", 2);
        await SemanticRuntimePostgresTests.SeedShortAsync(f, db, 1, Ct);
        await PostCollectionPostgres.Sql(db, "delete from semantic_processing_outbox where source_event_id>900003", Ct);
        var resumed = await PollAsync(db, path, "test-rules", Ct);
        Assert.Equal(900003, resumed.Number("frozen_high_watermark_event_id"));
        Assert.Equal(900003, resumed.Number("last_committed_event_id"));
        Only(await CheckQueueAsync(db, [900011, 900012, 900013], Ct), "not_enqueued", 3);
        string before = await File.ReadAllTextAsync(path, Ct);
        await Assert.ThrowsAsync<InvalidOperationException>(() => PollAsync(db, path, "changed-rules", Ct));
        Assert.Equal(before, await File.ReadAllTextAsync(path, Ct));
        resumed["database_identity"]!["database_oid"] = "0";
        await File.WriteAllTextAsync(path, resumed.ToJsonString(), Ct);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => PollAsync(db, path, "test-rules", Ct));
        Assert.Contains("database identity mismatch", error.Message);
        await f.AssertNoSqlErrorsAsync(Ct);
    }
}
