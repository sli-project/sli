using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Radius;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Semantic;
using Xunit;

namespace Sli.Server.Tests.Vpn;

internal static class VpnAccountingPostgresFixture
{
    internal static async Task<IDisposable> RegisterAsync(SqlPostgresFixture fixture, CancellationToken ct)
    {
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString);
        await admin.OpenAsync(ct);

        await PostCollectionPostgres.Sql(admin, """
            create role sli_radius_accounting_login login noinherit;
            grant adlog_nps_agent_import_worker to sli_radius_accounting_login with inherit false, set true;
            grant connect on database postgres to sli_radius_accounting_login;
            update plugin_installations_v1 set package_lifecycle='registered' where plugin_id='sli.remote-access';
            insert into acquisition_source_instances(source_instance_id,organization_scope,source_kind,endpoint_identity,
                adapter_binding,display_name,desired_activation,configuration_sha256)
            values('radius-instance','example.test','windows.nps.radius','fqdn:nps.example.test|ipv4:192.0.2.12',
                'radius-accounting-database-compatible-v1','Fixture','manual_enabled',repeat('a',64));
            insert into acquisition_stream_cursors(source_instance_id,stream_id,transport_binding,cursor_epoch,file_generation,byte_offset,revision)
            values('radius-instance','radius-accounting','windows-rpc-smb-readonly-tail-v1',gen_random_uuid(),'fixture-generation',0,7);
            insert into acquisition_consumer_subscriptions(subscription_id,source_instance_id,stream_id,transport_binding,
                consumer_id,consumer_component_id,consumer_component_version,routing_contract_id,consumer_contract_version,
                replay_policy,resource_profile_id,selector_json,selector_sha256,authority_mode,desired_activation,partition_key)
            values('vpn-radius-session-observations-nps-v1','radius-instance','radius-accounting','windows-rpc-smb-readonly-tail-v1',
                'sli.windows.vpn-radius','radius-session-observation','1.0.0','sli.radius-accounting-runtime.v1','1','bounded_replay',
                'fixture','{}',repeat('b',64),'authoritative','manual_enabled','fixture');
            """, ct);

        var env = new SemanticProducerPostgresTests.Admission(mode: null);
        try
        {
            env.Set(RadiusAccountingMode.EnabledSetting, "1");
            env.Set("CREDENTIALS_DIRECTORY", fixture.Pg.Root);
            env.Set(RadiusAccountingMode.ConfigRootSetting, Directory.GetParent(MigrationDirectory.Read(406).Single(migration => migration.Version == 406).Path)!.Parent!.FullName);
            var route = JsonNode.Parse(RadiusCollectionRouteTests.Route)!.AsObject();
            route["owner_confirmed_ip"] = "192.0.2.12";
            await File.WriteAllTextAsync(Path.Combine(fixture.Pg.Root, RadiusAccountingMode.RouteCredential), route.ToJsonString(), ct);
            return env;
        }
        catch
        {
            env.Dispose();
            throw;
        }
    }

    internal static async Task SetEnabledAsync(SqlPostgresFixture fixture, bool enabled, CancellationToken ct)
    {
        await using var api = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await api.OpenAsync(ct);
        await using var command = new NpgsqlCommand("""
            select enabled from set_plugin_enabled_v1('sli.remote-access',@enabled,
                (select revision from read_plugin_states_v1() where plugin_id='sli.remote-access'),'session',1,true)
            """, api);
        command.Parameters.AddWithValue("enabled", enabled);
        Assert.Equal(enabled, await command.ExecuteScalarAsync(ct));
    }
}
