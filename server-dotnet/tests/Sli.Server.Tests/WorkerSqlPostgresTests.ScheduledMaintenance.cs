using System.Diagnostics;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Legacy;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests;

public sealed partial class WorkerSqlPostgresTests
{
    [Fact]
    public async Task Native_report_producer_role_is_restricted_and_not_started_in_beta()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        string root = SqlPostgresFixture.Repository(), credentials = Path.Combine(fixture.Pg.Root, "producer-credentials");
        Directory.CreateDirectory(credentials);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, "create database sli", ct);
        // Exercise the installation provisioner itself, not test-only grants or an admin producer.
        var provision = ProcessInfo(Environment.GetEnvironmentVariable("SLI_TEST_PYTHON") ?? (OperatingSystem.IsWindows()
            ? "python" : "python3"), root);
        provision.ArgumentList.Add("-B"); provision.ArgumentList.Add("-c");
        provision.ArgumentList.Add("import os,psycopg; from deploy.linux import migrate; " +
            "c=psycopg.connect(os.environ['TEST_PROVISION_DSN'],autocommit=True); migrate.configure_worker_logins(c); migrate.configure_worker_logins(c)");
        var provisionTarget = new NpgsqlConnectionStringBuilder(fixture.Pg.ConnectionString);
        provision.Environment["TEST_PROVISION_DSN"] = $"host={provisionTarget.Host} port={provisionTarget.Port} dbname={provisionTarget.Database} user={provisionTarget.Username}";
        foreach (string setting in new[] { "SLI_NOTIFICATION_DB_PASSWORD", "SLI_REPORT_PRODUCER_PG_PASSWORD", "ADLOG_SEMANTIC_WORKER_PASSWORD", "ADLOG_STORAGE_V2_WORKER_PASSWORD", "ADLOG_AD_CONTEXT_WORKER_PASSWORD" }) {
            string file = Path.Combine(credentials, setting); await File.WriteAllTextAsync(file, "synthetic-test-password\n", ct);
            provision.Environment[setting + "_FILE"] = file;
        }
        var provisioned = await RunProcess(provision, ct); Assert.True(provisioned.Exit == 0, provisioned.Error);
        await using (var rights = new NpgsqlCommand("""
            select not (rolsuper or rolcreatedb or rolcreaterole or rolreplication or rolbypassrls or rolinherit),
              (select count(*) from pg_auth_members where member=r.oid)=1,
              pg_has_role(oid,'adlog_report_producer','MEMBER'),
              exists(select 1 from report_producer_principals p where p.principal_oid=r.oid and p.principal_name=r.rolname)
            from pg_roles r where rolname='sli_report_producer_login'
            """, db)) {
            await using var row = await rights.ExecuteReaderAsync(ct); Assert.True(await row.ReadAsync(ct));
            for (int i = 0; i < 4; i++) Assert.True(row.GetBoolean(i));
        }
        var render = ProcessInfo(provision.FileName, root); render.ArgumentList.Add("-B"); render.ArgumentList.Add("-c");
        render.ArgumentList.Add("from deploy.linux import native_runtime as n; import json; n.clickhouse.configured_mode=lambda:'native'; print(json.dumps(n.dotnet_units('synthetic',dict(profiles=['light'],radius_pilot=False,bind='192.0.2.1',health_url='https://192.0.2.1:8443/api/health/ready'))))");
        var rendered = await RunProcess(render, ct); Assert.Equal(0, rendered.Exit);
        Assert.False(JsonNode.Parse(rendered.Out)!.AsObject().ContainsKey("sli-dotnet-report-producer.service"));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Legacy_cleanup_keeps_active_recent_null_and_boundary_rows_and_beta_worker_leaves_history()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db = new NpgsqlConnection(fixture.Dsn("adlog_user")); await db.OpenAsync(ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        // now() is fixed by the transaction, so the strict boundary is deterministic.
        await PostCollectionPostgres.Sql(db, """
            insert into post_collection_jobs(durable_job_id,source_job_id,status,phase,finished_at,queued_at,updated_at)
            select state||'-'||age,1,state,state,case when age=0 then null else now()-age*interval '1 day' end,now()-interval '60 days',now()
            from unnest(array['completed','failed','running','queued']) state cross join unnest(array[0,7,8,60]) age;
            """, ct);
        Assert.Equal(4, await LegacyPostStore.CleanupAsync(db, 7, ct));
        await using (var count = new NpgsqlCommand("select count(*) from post_collection_jobs", db)) Assert.Equal(12L, await count.ExecuteScalarAsync(ct));
        await using (var active = new NpgsqlCommand("select count(*) from post_collection_jobs where status in ('queued','running')", db)) Assert.Equal(8L, await active.ExecuteScalarAsync(ct));
        Assert.Equal(2, await LegacyPostStore.CleanupAsync(db, 0, ct)); // Python clamps configured zero to one day.
        await tx.RollbackAsync(ct);
        // The installed core worker has no legacy job cleanup callback.
        await PostCollectionPostgres.Sql(db, """
            insert into post_collection_jobs(durable_job_id,source_job_id,status,phase,finished_at,queued_at,updated_at)
            values('old-completed',1,'completed','completed',now()-interval '8 days',now(),now()),
              ('old-failed',1,'failed','failed',now()-interval '8 days',now(),now()),
              ('recent-completed',1,'completed','completed',now()-interval '6 days',now(),now()),
              ('active',1,'running','running',now()-interval '60 days',now(),now());
            """, ct);
        var start = ProcessInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet", SqlPostgresFixture.Repository());
        start.ArgumentList.Add(typeof(Program).Assembly.Location); start.ArgumentList.Add("post-collection-worker"); start.ArgumentList.Add("--once");
        start.Environment["ConnectionStrings__Sli"] = fixture.Dsn("adlog_user");
        start.Environment["SLI_LEGACY_COLLECTION_DISABLED"] = "1";
        start.Environment["ADLOG_POST_COLLECTION_RETENTION_DAYS"] = "7";
        start.Environment["ADLOG_DATA_DIR"] = fixture.Pg.Root;
        var result = await RunProcess(start, ct); Assert.True(result.Exit == 0, result.Out + result.Error);
        await using (var remaining = new NpgsqlCommand("select array_agg(durable_job_id order by durable_job_id) from post_collection_jobs", db))
            Assert.Equal(new[] { "active", "old-completed", "old-failed", "recent-completed" }, (string[])(await remaining.ExecuteScalarAsync(ct))!);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
