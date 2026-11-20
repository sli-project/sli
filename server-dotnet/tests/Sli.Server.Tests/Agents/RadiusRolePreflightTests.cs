using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class RadiusRolePreflightTests
{
    [Fact]
    public async Task OwnedReadOnlyRolePrivilegesAreRecorded()
    {
        var ct=TestContext.Current.CancellationToken;await using var fixture=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);await using var db=await fixture.OpenConnectionAsync(ct);
        await using var cmd=new NpgsqlCommand("""
            select jsonb_build_object(
                'current_user',current_user,
                'nps_inherit',(select rolinherit from pg_roles where rolname='adlog_nps_agent_import_worker'),
                'nps_agent_update_table',has_table_privilege('adlog_nps_agent_import_worker','public.sli_agents','UPDATE'),
                'nps_agent_update_any_column',has_any_column_privilege('adlog_nps_agent_import_worker','public.sli_agents','UPDATE'),
                'nps_inbox_update_any_column',has_any_column_privilege('adlog_nps_agent_import_worker','public.sli_agent_packet_inbox','UPDATE'),
                'nps_can_set_radius',pg_has_role('adlog_nps_agent_import_worker','adlog_radius_accounting_worker','MEMBER'),
                'nps_user_member',pg_has_role('adlog_nps_agent_import_worker','adlog_user','USAGE'),
                'membership',(select coalesce(jsonb_agg(jsonb_build_object('role',r.rolname,'inherit',r.rolinherit) order by r.rolname),'[]'::jsonb)
                   from pg_roles r where pg_has_role('adlog_nps_agent_import_worker',r.oid,'USAGE'))
            )::text
            """,db);
        var json=(string)(await cmd.ExecuteScalarAsync(ct))!;Assert.Equal("adlog_user",JsonNode.Parse(json)!["current_user"]!.GetValue<string>());
        string output=Environment.GetEnvironmentVariable("SLI_RADIUS_ROLE_PROOF") ?? throw new InvalidOperationException("explicit owned output required");
        await File.WriteAllTextAsync(output,json,ct);
    }
}
