using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Vpn;

// Vectors from tests/sources/test_plugin_runtime_admission_handler_integration.py.
public sealed class PluginRuntimeAdmissionHandlerTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed class Database(string dsn, bool broker = false) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        {
            var db = new NpgsqlConnection(broker ? new NpgsqlConnectionStringBuilder(dsn) { Username = "fixture_broker" }.ConnectionString : dsn);
            try {
                await db.OpenAsync(ct);
                if (broker) {
                    await using var owner = new NpgsqlConnection(dsn); await owner.OpenAsync(ct);
                    await PostCollectionPostgres.Sql(owner, "revoke connect on database postgres from fixture_broker", ct);
                }
                return db;
            }
            catch { await db.DisposeAsync(); throw; }
        }
    }

    [Theory]
    [InlineData("open", "enabled_manual", "running")]
    [InlineData("drain_only", "disabled", "draining")]
    public async Task ConsumerObtainsPermissionBeforeClaimAndReportsEmptyCycle(string mode, string activation, string state)
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(Ct);
        await using var db = new NpgsqlConnection(pg.ConnectionString); await db.OpenAsync(Ct);
        await AdmissionSchema(db);
        await using (var configure = new NpgsqlCommand("update plugin_installations_v1 set desired_activation=$1,component_runtime=$2", db)) {
            configure.Parameters.AddWithValue(activation); configure.Parameters.AddWithValue(state);
            await configure.ExecuteNonQueryAsync(Ct);
        }
        await using (var configure = new NpgsqlCommand("update plugin_component_admission_v1 set admission_mode=$1 where component_id='radius-session-observation'", db)) {
            configure.Parameters.AddWithValue(mode); await configure.ExecuteNonQueryAsync(Ct);
        }

        var result = await RadiusObservationHost.RunConsumerCycleAsync(db, Ct);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"status":"completed","claimed":0,"processed":0,"outcomes":{}}"""), result));
        await using var lease = new NpgsqlCommand("select component_id,lease_kind,holder_key,release_outcome from plugin_component_leases_v1", db);
        await using var row = await lease.ExecuteReaderAsync(Ct);
        Assert.True(await row.ReadAsync(Ct));
        Assert.Equal("radius-session-observation", row.GetString(0)); Assert.Equal("delivery_claim", row.GetString(1));
        Assert.StartsWith("radius-session-observation:", row.GetString(2)); Assert.Equal("completed", row.GetString(3));
        Assert.False(await row.ReadAsync(Ct));
    }

    [Fact]
    public async Task ClosedConsumerDoesNotReadOrChangeDeliveries()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = new NpgsqlConnection(pg.ConnectionString); await db.OpenAsync(Ct);
        await AdmissionSchema(db);
        var error = await Assert.ThrowsAsync<PostgresException>(() => RadiusObservationHost.RunConsumerCycleAsync(db, Ct));
        Assert.Equal("plugin consumer admission is closed", error.MessageText);
        await using var check = new NpgsqlCommand("select (select count(*) from plugin_component_leases_v1)=0 and (select count(*) from acquisition_delivery_outbox where delivery_state='queued' and attempt_count=0)=1", db);
        Assert.Equal(true, await check.ExecuteScalarAsync(Ct));
    }

    [Fact]
    public async Task ConsumerLoginRollsBackRoleCreationWhenConnectGrantFails()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = new NpgsqlConnection(pg.ConnectionString); await db.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db, """
            create role adlog_radius_session_consumer;
            create role fixture_broker login createrole noinherit;
            grant adlog_radius_session_consumer to fixture_broker with admin option;
            revoke connect on database postgres from public;
            grant connect on database postgres to fixture_broker;
            """, Ct);
        bool ran = false;
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => RadiusObservationHost.WithConsumerLogin(new Database(pg.ConnectionString, broker: true), _ => {
            ran = true; return Task.CompletedTask;
        }, Ct));
        Assert.Equal("consumer_database_connect_grant_failed", error.Message); Assert.False(ran);
        await using var check = new NpgsqlCommand("select count(*) from pg_roles where rolname like 'adlog_radius_consumer_%'", db);
        Assert.Equal(0L, await check.ExecuteScalarAsync(Ct));
    }

    [Fact]
    public async Task ConsumerLoginRevokesDirectConnectAndDropsRoleAfterWorkerFailure()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = new NpgsqlConnection(pg.ConnectionString); await db.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db, "create role adlog_radius_session_consumer; revoke connect on database postgres from public", Ct);
        string? role = null;
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => RadiusObservationHost.WithConsumerLogin(new Database(pg.ConnectionString), async dsn => {
            role = new NpgsqlConnectionStringBuilder(dsn).Username;
            await using var child = new NpgsqlConnection(dsn); await child.OpenAsync(Ct);
            await using var direct = new NpgsqlCommand("select exists(select 1 from pg_database d,aclexplode(d.datacl) a where d.datname=current_database() and a.grantee=(select oid from pg_roles where rolname=current_user) and a.privilege_type='CONNECT')", child);
            Assert.Equal(true, await direct.ExecuteScalarAsync(Ct));
            throw new InvalidOperationException("injected_worker_failure");
        }, Ct));
        Assert.Equal("injected_worker_failure", error.Message); Assert.NotNull(role);
        await using var check = new NpgsqlCommand("select not exists(select 1 from pg_roles where rolname=$1) and not exists(select 1 from pg_database d,aclexplode(d.datacl) a where d.datname=current_database() and a.grantee<>0 and a.privilege_type='CONNECT' and a.grantee<>d.datdba)", db);
        check.Parameters.AddWithValue(role); Assert.Equal(true, await check.ExecuteScalarAsync(Ct));
    }

    [Fact]
    public async Task ConsumerCleanupWaitsForItsExitingSessionAndPreservesTheWorkerFailure()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = new NpgsqlConnection(pg.ConnectionString); await db.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db, "create role adlog_radius_session_consumer; revoke connect on database postgres from public", Ct);
        var opened = new TaskCompletionSource<NpgsqlConnection>(TaskCreationOptions.RunContinuationsAsynchronously);
        var failed = new InvalidOperationException("injected_worker_failure");
        var cleanup = Record.ExceptionAsync(() => RadiusObservationHost.WithConsumerLogin(new Database(pg.ConnectionString), async dsn => {
            var child = new NpgsqlConnection(dsn);
            try { await child.OpenAsync(Ct); }
            catch { await child.DisposeAsync(); throw; }
            opened.SetResult(child);
            throw failed;
        }, Ct)).AsTask();
        string? role;
        await using (var child = await opened.Task.WaitAsync(TimeSpan.FromSeconds(5), Ct))
        {
            role = child.UserName;
            // Hold the fixture's child connection briefly after the callback fails,
            // as if PostgreSQL had not yet processed the child's disconnect.
            await Task.WhenAny(cleanup, Task.Delay(TimeSpan.FromMilliseconds(200), Ct));
        }
        Assert.Same(failed, await cleanup);
        Assert.NotNull(role);
        await using var check = new NpgsqlCommand("""
            select not exists(select 1 from pg_roles where rolname=$1)
                and not exists(select 1 from pg_database d,aclexplode(d.datacl) a
                    where d.datname=current_database() and a.grantee<>0 and a.privilege_type='CONNECT' and a.grantee<>d.datdba)
            """, db);
        check.Parameters.AddWithValue(role);
        Assert.Equal(true, await check.ExecuteScalarAsync(Ct));
    }

    private static async Task AdmissionSchema(NpgsqlConnection db)
    {
        await PostCollectionPostgres.Sql(db, """
            create role adlog_storage_owner; create role adlog_user;
            create role adlog_radius_accounting_worker; create role adlog_radius_session_consumer;
            create role adlog_plugin_lifecycle_owner;
            create table schema_migrations(version integer primary key,name text);
            insert into schema_migrations values(74,'plugin_bundled_install_executor');
            create table plugin_installations_v1(plugin_id text primary key,package_lifecycle text,desired_activation text,component_runtime text);
            insert into plugin_installations_v1 values('sli.remote-access','registered','disabled','stopped');
            alter table plugin_installations_v1 owner to adlog_plugin_lifecycle_owner;
            """, Ct);
        await PostCollectionPostgres.Sql(db, await File.ReadAllTextAsync(Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/075_plugin_component_admission.sql"), Ct), Ct);
        await PostCollectionPostgres.Sql(db, """
            create table acquisition_delivery_outbox(
                delivery_id bigint primary key,subscription_id text,attempt_count integer,available_at timestamptz,
                created_at timestamptz,delivery_state text,lease_until timestamptz,lease_token uuid,
                heartbeat_at timestamptz,last_error_code text,updated_at timestamptz);
            insert into acquisition_delivery_outbox values(1,'vpn-radius-session-observations-radius01-v1',0,now(),now(),'queued',null,null,null,null,now());
            alter table acquisition_delivery_outbox enable row level security;
            create function fixture_admission_before_read() returns boolean language plpgsql security definer as $$
            begin
                if not exists(select 1 from plugin_component_leases_v1 where component_id='radius-session-observation' and released_at_utc is null) then
                    raise exception 'delivery_read_before_admission';
                end if;
                return false;
            end $$;
            create policy fixture_empty_claim on acquisition_delivery_outbox using(fixture_admission_before_read());
            grant select,update on acquisition_delivery_outbox to adlog_radius_session_consumer;
            """, Ct);
    }
}
