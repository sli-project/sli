using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Agents.Radius;
using Xunit;

namespace Sli.Server.Tests.Agents;

// Vectors from tests/sources/test_radius_accounting_manual_control.py.
public sealed class RadiusManualControlTests : IAsyncLifetime
{
    private const string Source = "radius01.example.test";
    private readonly PostCollectionPostgres pg = new(canonicalSchema: true);
    private CancellationToken Ct => TestContext.Current.CancellationToken;

    public async ValueTask InitializeAsync()
    {
        await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct);
        await Sql(db, """
            create role adlog_storage_owner noinherit nologin;
            create role adlog_radius_accounting_worker noinherit nologin;
            create table schema_migrations(version integer primary key,name text);
            insert into schema_migrations values(58,'radius_accounting_transaction_foundation'),(59,'radius_identity_spine_resolver');
            grant usage,create on schema public to adlog_storage_owner;
            set role adlog_storage_owner;
            """);
        // Use the actual table constraints, not a substitute schema for the control plane.
        string migration = await File.ReadAllTextAsync(Path.Combine(PostCollectionPostgres.Repository(),
            "config/postgres_migrations/058_radius_accounting_transaction_foundation.sql"), Ct);
        foreach (string name in new[] { "acquisition_source_instances", "acquisition_stream_cursors", "acquisition_consumer_subscriptions" }) {
            var match = Regex.Match(migration, @"create table if not exists " + name + @"\s*\([\s\S]*?\r?\n\);");
            Assert.True(match.Success);
            await Sql(db, match.Value);
        }
        await Sql(db, """
            reset role;
            insert into acquisition_source_instances(source_instance_id,organization_scope,source_kind,endpoint_identity,adapter_binding,display_name,configuration_sha256)
              values('radius01.example.test','example.test','radius','radius01.example.test','radius','Synthetic RADIUS',repeat('a',64));
            insert into acquisition_stream_cursors(source_instance_id,stream_id,transport_binding,cursor_epoch,file_generation,byte_offset,revision)
              values('radius01.example.test','radius-accounting','unc-logfiles-in','00000000-0000-4000-8000-000000000001','in-20260730',0,7);
            insert into acquisition_consumer_subscriptions(subscription_id,source_instance_id,stream_id,transport_binding,consumer_id,consumer_component_id,
              consumer_component_version,routing_contract_id,consumer_contract_version,replay_policy,resource_profile_id,selector_json,selector_sha256,authority_mode,partition_key)
              values('vpn-radius-session-observations-radius01-v1','radius01.example.test','radius-accounting','unc-logfiles-in','vpn','radius-session-observation',
                '1','synthetic-routing','1','no_replay','synthetic-profile','{}',repeat('b',64),'authoritative','synthetic-partition');
            """);
    }

    public ValueTask DisposeAsync() => pg.DisposeAsync();
    private Task Sql(NpgsqlConnection db, string sql) => PostCollectionPostgres.Sql(db, sql, Ct);
    private async Task<object?> Scalar(NpgsqlConnection db, string sql)
    {
        await using var cmd = new NpgsqlCommand(sql, db);
        return await cmd.ExecuteScalarAsync(Ct);
    }
    private static Task<RadiusManualState> State(NpgsqlConnection db, CancellationToken ct)
        => RadiusManualControl.InspectAsync(db, Source, RadiusManualControl.SubscriptionId, ct);
    private async Task AssertNoLogin(NpgsqlConnection db)
        => Assert.Equal(0L, await Scalar(db, "select count(*) from pg_roles where rolname like 'adlog_radius_manual_%'"));

    [Fact]
    public async Task Readiness_is_fail_closed_for_both_activations_and_migrations()
    {
        await using var db = await pg.OpenAsync(Ct);
        Assert.Equal(new("disabled", "disabled", 7, true, true), await State(db, Ct));
        foreach (string column in new[] { "source", "subscription" }) {
            var state = new RadiusManualState(column == "source" ? "manual_enabled" : "disabled", column == "subscription" ? "manual_enabled" : "disabled", 7, true, true);
            Assert.Equal("manual_activation_not_disabled", Assert.Throws<RadiusManualControlException>(() => RadiusManualControl.RequireReadyDisabled(state)).Message);
        }
        foreach (int version in new[] { 58, 59 }) {
            await Sql(db, $"delete from schema_migrations where version={version}");
            var error = await Assert.ThrowsAsync<RadiusManualControlException>(() => RadiusManualControl.RunOnceAsync(db, Source, RadiusManualControl.SubscriptionId, (_, _) => Task.FromResult(1), Ct));
            Assert.Equal("manual_required_migration_missing", error.Message);
            await AssertNoLogin(db);
            await Sql(db, $"insert into schema_migrations values({version},'{(version == 58 ? "radius_accounting_transaction_foundation" : "radius_identity_spine_resolver")}')");
        }
        var missing = await Assert.ThrowsAsync<RadiusManualControlException>(() => RadiusManualControl.InspectAsync(db, "unknown.example.test", RadiusManualControl.SubscriptionId, Ct));
        Assert.Equal("manual_registration_not_found", missing.Message);
    }

    [Fact]
    public async Task Ephemeral_login_has_only_explicit_worker_membership_and_direct_database_connect()
    {
        await using var db = await pg.OpenAsync(Ct);
        var login = await RadiusManualControl.CreateLoginAsync(db, Ct);
        Assert.Matches(@"\Aadlog_radius_manual_[a-f0-9]{16}\z", login.Role);
        try {
            await using var cmd = new NpgsqlCommand("""
                select rolcanlogin and not rolinherit and not rolsuper and not rolcreatedb and not rolcreaterole and not rolbypassrls and not rolreplication,
                  pg_has_role(oid,'adlog_radius_accounting_worker','MEMBER'),
                  exists(select 1 from pg_database d cross join lateral aclexplode(d.datacl) a
                    where d.datname=current_database() and a.grantee=r.oid and a.privilege_type='CONNECT'),
                  (select count(*) from pg_auth_members where member=r.oid)
                from pg_roles r where rolname=$1
                """, db);
            cmd.Parameters.AddWithValue(login.Role);
            await using (var reader = await cmd.ExecuteReaderAsync(Ct)) {
                Assert.True(await reader.ReadAsync(Ct));
                Assert.True(reader.GetBoolean(0)); Assert.True(reader.GetBoolean(1)); Assert.True(reader.GetBoolean(2)); Assert.Equal(1L, reader.GetInt64(3));
            }
            var settings = new NpgsqlConnectionStringBuilder(pg.ConnectionString) { Username = login.Role, Password = login.Password, Pooling = false };
            await using var worker = new NpgsqlConnection(settings.ConnectionString);
            await worker.OpenAsync(Ct);
            Assert.Equal(login.Role, await Scalar(worker, "select current_user::text"));
            await Sql(worker, "set role adlog_radius_accounting_worker");
            Assert.Equal("adlog_radius_accounting_worker", await Scalar(worker, "select current_user::text"));
            Assert.False((bool)(await Scalar(worker, "select has_table_privilege(current_user,'acquisition_source_instances','UPDATE')"))!);
        }
        finally { await RadiusManualControl.DropLoginAsync(db, login.Role, Ct); }
        await AssertNoLogin(db);
        Assert.Equal(0L, await Scalar(db, "select count(*) from pg_database d cross join lateral aclexplode(d.datacl) a where d.datname=current_database() and a.grantee not in (select oid from pg_roles) and a.grantee<>0"));
        var invalid = await Assert.ThrowsAsync<RadiusManualControlException>(() => RadiusManualControl.DropLoginAsync(db, "adlog_storage_owner", Ct));
        Assert.Equal("manual_login_role_name_invalid", invalid.Message);
    }

    [Theory]
    [InlineData("success")]
    [InlineData("worker_failure")]
    [InlineData("cancelled")]
    public async Task Scope_runs_once_and_disables_both_rows_and_drops_login(string outcome)
    {
        await using var db = await pg.OpenAsync(Ct);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        int calls = 0;
        async Task<int> Operation(RadiusManualLease lease, CancellationToken ct)
        {
            calls++;
            Assert.Equal(Source, lease.SourceInstanceId); Assert.Equal(RadiusManualControl.SubscriptionId, lease.SubscriptionId);
            Assert.Equal(new("manual_enabled", "manual_enabled", 7, true, true), await State(db, ct));
            Assert.DoesNotContain(lease.Password, lease.ToString()!);
            if (outcome == "worker_failure") throw new InvalidOperationException("injected_worker_failure");
            if (outcome == "cancelled") { stop.Cancel(); ct.ThrowIfCancellationRequested(); }
            return 42;
        }
        var run = RadiusManualControl.RunOnceAsync(db, Source, RadiusManualControl.SubscriptionId, Operation, stop.Token);
        if (outcome == "success") Assert.Equal(42, await run);
        else if (outcome == "worker_failure") Assert.Equal("injected_worker_failure", (await Assert.ThrowsAsync<InvalidOperationException>(() => run)).Message);
        else await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
        Assert.Equal(1, calls);
        Assert.Equal(new("disabled", "disabled", 7, true, true), await State(db, Ct));
        await AssertNoLogin(db);
    }

    [Theory]
    [InlineData("manual_enabled", "manual_source_activation_failed")]
    [InlineData("disabled", "manual_cleanup_failed")]
    public async Task Activation_or_cleanup_failure_still_drops_login(string failingTarget, string expected)
    {
        await using var db = await pg.OpenAsync(Ct);
        await Sql(db, $$"""
            create function synthetic_activation_failure() returns trigger language plpgsql as $$
            begin if new.desired_activation='{{failingTarget}}' then return null; end if; return new; end $$;
            create trigger synthetic_failure before update on acquisition_source_instances for each row execute function synthetic_activation_failure();
            """);
        int calls = 0;
        var error = await Assert.ThrowsAsync<RadiusManualControlException>(() => RadiusManualControl.RunOnceAsync(db, Source, RadiusManualControl.SubscriptionId,
            (_, _) => { calls++; return Task.FromResult(42); }, Ct));
        Assert.Equal(expected, error.Message);
        Assert.Equal(failingTarget == "manual_enabled" ? 0 : 1, calls);
        await AssertNoLogin(db);
        var state = await State(db, Ct);
        Assert.Equal(failingTarget == "manual_enabled" ? "disabled" : "manual_enabled", state.SourceActivation);
        Assert.Equal(state.SourceActivation, state.SubscriptionActivation);
    }

    [Fact]
    public async Task Database_connect_acl_lock_serializes_two_real_transactions()
    {
        await using var first = await pg.OpenAsync(Ct);
        await using var second = await pg.OpenAsync(Ct);
        await using var observer = await pg.OpenAsync(Ct);
        await using var tx1 = await first.BeginTransactionAsync(Ct);
        await using var tx2 = await second.BeginTransactionAsync(Ct);
        await RadiusManualControl.LockDatabaseConnectAclAsync(first, Ct);
        var waiter = RadiusManualControl.LockDatabaseConnectAclAsync(second, Ct);
        try {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            deadline.CancelAfter(TimeSpan.FromSeconds(10)); // Test watchdog only.
            await using var cmd = new NpgsqlCommand("select exists(select 1 from pg_locks where pid=$1 and locktype='advisory' and not granted)", observer);
            cmd.Parameters.AddWithValue(second.ProcessID);
            while (await cmd.ExecuteScalarAsync(deadline.Token) is not true) await Task.Delay(10, deadline.Token);
            Assert.False(waiter.IsCompleted);
        }
        finally { await tx1.CommitAsync(Ct); }
        await waiter.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        await tx2.CommitAsync(Ct);
    }
}
