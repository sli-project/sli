using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Workstations;
using Xunit;

namespace Sli.Server.Tests.Workstations;

public sealed partial class WorkstationInventoryJobPostgresTests
{
    static string Migration(string suffix) => Path.Combine(Sli.Server.Tests.Agents.PostCollectionPostgres.Repository(), "config/postgres_migrations", suffix);
    static async Task Script(NpgsqlConnection db, string path)
    {
        string sql = (await File.ReadAllTextAsync(path, Ct)).Replace("\r\n", "\n");
        try { await Exec(db, sql); }
        catch { await Exec(db, "rollback"); throw; }
    }

    // Migration 287 has an independent rollback contract. Build its actual predecessor
    // lineage without trying to reverse unrelated releases in the current test database.
    [Fact]
    public async Task Rollback_refuses_active_job_then_reapplies_without_inventory_data_loss()
    {
        await using var schema = new SqlPostgresFixture();
        await schema.StartAsync(Ct, throughVersion: 287);
        await using var db = await schema.Pg.OpenAsync(Ct);
        await Directory(db); var job = await Job(db);
        Assert.Contains("rollback prerequisites failed", (await Assert.ThrowsAsync<PostgresException>(() => Script(db, Migration("287_workstation_inventory_job.rollback.sql")))).MessageText);
        Assert.Equal("committed", await Publish(db, job, await Stage(db, job)));
        var before = await InventoryRows(db);
        await Script(db, Migration("287_workstation_inventory_job.rollback.sql"));
        Assert.Null(await Scalar(db, "select to_regprocedure('public.read_workstation_inventory_input_v1(uuid,uuid,bigint)')::text"));
        Assert.Null(await Scalar(db, "select to_regclass('sli_plugin_workstations.inventory_checkpoints')::text"));
        EqualRows(before, await InventoryRows(db));
        await Script(db, Migration("287_workstation_inventory_job.sql")); await Run(db, 11); EqualRows(before, await InventoryRows(db));
        await As(db, "sli_job_publisher_light", async () => Assert.Equal("42501", (await Assert.ThrowsAsync<PostgresException>(() => Scalar(db, "select count(*) from sli_plugin_workstations.inventory_checkpoints"))).SqlState));
    }

    [Fact]
    public async Task Pending_queue_rebuilds_after_rollback_while_ids_history_and_core_receipts_survive()
    {
        await using var schema = new SqlPostgresFixture();
        await schema.StartAsync(Ct, throughVersion: 287);
        await using var db = await schema.Pg.OpenAsync(Ct);
        var (own, _, job, before, history) = await PendingConflict(db);
        var result = await Stage(db, job); Assert.Equal("committed", await Publish(db, job, result));
        var receipt = JsonNode.Parse((string)(await Scalar(db, "select result_payload::text from sli_jobs.jobs where job_id=@p0", Guid.Parse(job.Text("job_id")!)))!);
        await Script(db, Migration("287_workstation_inventory_job.rollback.sql"));
        Assert.Null(await Scalar(db, "select to_regclass('sli_plugin_workstations.inventory_deferred')::text"));
        EqualRows(before, await InventoryRows(db)); await AssertHistory(db, history);
        Equal(receipt, JsonNode.Parse((string)(await Scalar(db, "select result_payload::text from sli_jobs.jobs where job_id=@p0", Guid.Parse(job.Text("job_id")!)))!));
        await Script(db, Migration("287_workstation_inventory_job.sql"));
        Assert.Equal(0L, await Scalar(db, "select count(*) from sli_plugin_workstations.inventory_deferred"));
        var rebuilt = await Run(db, 11);
        Equal(JsonNode.Parse($$"""[{"station_id":"ws:ad:{{own}}","reason":"identity_owner_conflict"}]"""), rebuilt["inventory_deferred"]);
        Assert.Equal("pending", await Scalar(db, "select state from sli_plugin_workstations.inventory_deferred")); Assert.Equal(1L, await Scalar(db, "select attempts from sli_plugin_workstations.inventory_deferred"));
        EqualRows(before, await InventoryRows(db)); await AssertHistory(db, history);
    }

    [Fact]
    public async Task Reused_owner_with_unexpected_login_membership_is_denied_without_partial_grants()
    {
        await using var schema = new SqlPostgresFixture();
        await schema.StartAsync(Ct, throughVersion: 287);
        await using var db = await schema.Pg.OpenAsync(Ct);
        await Script(db, Migration("287_workstation_inventory_job.rollback.sql"));
        await Exec(db, "create role sli_workstation_inventory_owner nologin noinherit nosuperuser nocreatedb nocreaterole nobypassrls noreplication");
        string guest = "synthetic_inventory_guest_" + Guid.NewGuid().ToString("N");
        await Exec(db, "create role " + guest + " login noinherit nosuperuser nocreatedb nocreaterole nobypassrls noreplication");
        try
        {
            await Exec(db, "grant sli_workstation_inventory_owner to " + guest);
            Assert.Contains("workstation_inventory_owner_invalid", (await Assert.ThrowsAsync<PostgresException>(() => Script(db, Migration("287_workstation_inventory_job.sql")))).MessageText);
            Assert.Null(await Scalar(db, "select to_regprocedure('public.read_workstation_inventory_input_v1(uuid,uuid,bigint)')::text"));
            Assert.Equal(false, await Scalar(db, "select has_column_privilege(@p0,'public.sli_agents','assigned_modules','SELECT')", guest));
        }
        finally { await Exec(db, "revoke sli_workstation_inventory_owner from " + guest); await Exec(db, "drop role " + guest); }
    }
}
