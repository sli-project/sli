using Npgsql;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Server.Agents.SnapshotPublication;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class GpoPublicationFixtureTests
{
    [Fact]
    public async Task Gpo_snapshot_commits_postgres_history_and_replays_without_ClickHouse()
    {
        var ct = TestContext.Current.CancellationToken;
        string? runtime = Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"), locks = Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR");
        try {
            Environment.SetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR", ""); Environment.SetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR", "");
            await using var pg = new PostCollectionPostgres(); await pg.StartAsync(ct);
            await using var admin = await pg.OpenAsync(ct);
            var vector = JsonNode.Parse(File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(),
                "server-dotnet/tests/Sli.Server.Tests/Agents/gpo-publication-source-vector.json")))!.AsObject();
            var config = vector["config"]!.AsObject(); Guid cycle = Guid.NewGuid();
            await using (var domain = new NpgsqlCommand("update domains set domain_sid=@sid,fqdn=@dns where id=7",admin)) {
                domain.Parameters.AddWithValue("sid",config["domain_sid"]!.GetValue<string>());
                domain.Parameters.AddWithValue("dns",config["domain_dns"]!.GetValue<string>()); await domain.ExecuteNonQueryAsync(ct);
            }
            await PostCollectionDatabaseTests.SeedAsync(admin,Guid.NewGuid(),cycle,SnapshotPolicy.Gpo,config,
                vector["families"]!.AsObject().ToDictionary(p=>p.Key,p=>p.Value!.AsObject()),"2026-10-08T11:00:00+00:00",ct);
            await using var worker = await pg.OpenAsync(ct,"adlog_context_worker");
            var result = await GpoSnapshotPublisher.ProcessAsync(worker,cycle,ct);
            Assert.True(result.PublicationState == "published",result.PendingReason + await pg.DiagnosticsAsync(ct));
            // A completed cycle is no longer queued for publication; replay keeps its stored history.
            Assert.False((await GpoSnapshotPublisher.ProcessAsync(worker,cycle,ct)).TransportComplete);
            await using var history = new NpgsqlCommand("""
                select (select count(*) from ad_snapshot_change_history where manifest_id=@cycle and family='gpo_v2' and record_kind='changes_header'),
                       (select count(*) from ad_snapshot_history_confirmations where manifest_id=@cycle and family='gpo_v2')
                """,admin);
            history.Parameters.AddWithValue("cycle",cycle);
            await using var rows = await history.ExecuteReaderAsync(ct); Assert.True(await rows.ReadAsync(ct));
            Assert.Equal(1L,rows.GetInt64(0)); Assert.Equal(1L,rows.GetInt64(1));
        } finally { Environment.SetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR",runtime); Environment.SetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR",locks); }
    }

    [Fact]
    public async Task Source_worker_login_connects_without_public_access_and_keeps_only_its_role()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString);
        await admin.OpenAsync(ct);
        string database = new NpgsqlCommandBuilder().QuoteIdentifier(admin.Database);
        await PostCollectionPostgres.Sql(admin, $"revoke connect on database {database} from public", ct);

        await using var worker = new NpgsqlConnection(fixture.Dsn("sli_context_login"));
        await worker.OpenAsync(ct);
        await using (var check = new NpgsqlCommand("""
            select session_user,current_user,
                   has_database_privilege(current_user,current_database(),'CONNECT'),
                   has_database_privilege(current_user,current_database(),'CREATE'),
                   has_table_privilege(current_user,'gpo_report_v2_source_snapshots','SELECT'),
                   rolsuper or rolcreatedb or rolcreaterole or rolinherit or rolreplication or rolbypassrls
            from pg_roles where rolname=current_user
            """, worker))
        await using (var rows = await check.ExecuteReaderAsync(ct)) {
            Assert.True(await rows.ReadAsync(ct));
            Assert.Equal("sli_context_login", rows.GetString(0));
            Assert.Equal("sli_context_login", rows.GetString(1));
            Assert.True(rows.GetBoolean(2));
            for (int i = 3; i <= 5; i++) Assert.False(rows.GetBoolean(i));
        }
        await using (var memberships = new NpgsqlCommand("""
            select r.rolname,m.admin_option,m.inherit_option,m.set_option
            from pg_auth_members m join pg_roles r on r.oid=m.roleid
            where m.member='sli_context_login'::regrole
            """, admin))
        await using (var rows = await memberships.ExecuteReaderAsync(ct)) {
            Assert.True(await rows.ReadAsync(ct));
            Assert.Equal("adlog_context_worker", rows.GetString(0));
            Assert.False(rows.GetBoolean(1));
            Assert.False(rows.GetBoolean(2));
            Assert.True(rows.GetBoolean(3));
            Assert.False(await rows.ReadAsync(ct));
        }
        await using (var grants = new NpgsqlCommand("""
            select exists (
                select 1 from pg_class c cross join lateral aclexplode(c.relacl) a
                where a.grantee='sli_context_login'::regrole
                union all
                select 1 from pg_namespace n cross join lateral aclexplode(n.nspacl) a
                where a.grantee='sli_context_login'::regrole
                union all
                select 1 from pg_proc p cross join lateral aclexplode(p.proacl) a
                where a.grantee='sli_context_login'::regrole
            )
            """, admin)) Assert.Equal(false, await grants.ExecuteScalarAsync(ct));

        await PostCollectionPostgres.Sql(worker, "set role adlog_context_worker", ct);
        await using (var check = new NpgsqlCommand("select session_user,current_user,(select count(*) from gpo_report_v2_source_snapshots)", worker))
        await using (var rows = await check.ExecuteReaderAsync(ct)) {
            Assert.True(await rows.ReadAsync(ct));
            Assert.Equal("sli_context_login", rows.GetString(0));
            Assert.Equal("adlog_context_worker", rows.GetString(1));
            Assert.Equal(0L, rows.GetInt64(2));
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
