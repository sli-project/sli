using Npgsql;
using Sli.Server.Agents.Ingress;
using Sli.Server.Agents.Radius;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class RadiusBacklogPostgresTests
{
    [Fact]
    public async Task AccountingPauseRetainsAcceptedBacklogAndNeverReopensHistoricalTombstones()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres();
        await pg.StartAsync(ct);
        await using var admin = await pg.OpenAsync(ct);
        await using var api = await pg.OpenAsync(ct,"adlog_user");
        var accepted = Guid.NewGuid();
        var historical = Guid.NewGuid();
        var ordinary = Guid.NewGuid();
        // Model the mailbox state left by a previously accepted accounting packet.
        // The shipped migration still keeps first-time accounting admission off.
        await using (var seed = new NpgsqlCommand("""
            insert into sli_agent_packet_inbox(packet_id,received_at,envelope,packet,event_rows,module_disabled_at)
            values
                (@historical,now()-interval '2 seconds',
                 jsonb_build_object('module_id','sli.radius-accounting'),'{}','[]',now()),
                (@accepted,now()-interval '1 second',
                 jsonb_build_object('module_id','sli.radius-accounting'),'{}','[]',null),
                (@ordinary,now(),jsonb_build_object('module_id','sli.workstations'),'{}','[]',null)
            """,admin))
        {
            seed.Parameters.AddWithValue("accepted",accepted);
            seed.Parameters.AddWithValue("historical",historical);
            seed.Parameters.AddWithValue("ordinary",ordinary);
            await seed.ExecuteNonQueryAsync(ct);
        }
        async Task Poll()
        {
            await using var tx = await api.BeginTransactionAsync(ct);
            await AgentPolicyAssignments.MarkDisabledAsync(api,tx,10,ct);
            await tx.CommitAsync(ct);
        }
        async Task<bool> Marked(Guid packet)
        {
            await using var query = new NpgsqlCommand("""
                select module_disabled_at is not null from sli_agent_packet_inbox
                where packet_id=@packet and imported_at is null
                """,admin);
            query.Parameters.AddWithValue("packet",packet);
            return Assert.IsType<bool>(await query.ExecuteScalarAsync(ct));
        }
        await Poll(); // Shipped global accounting gate is off.
        Assert.False(await Marked(accepted));
        Assert.True(await Marked(historical));
        Assert.True(await Marked(ordinary));

        // Simulate re-opening the gate in the disposable database only.
        await PostCollectionPostgres.Sql(admin, """
            create or replace function public.agent_module_enabled_v380(p_module text)
            returns boolean language sql stable security definer set search_path=pg_catalog,pg_temp
            as $$ select p_module='sli.radius-accounting' $$;
            """,ct);
        await Poll();
        Assert.False(await Marked(accepted));
        Assert.True(await Marked(historical));

        var consumer = new RadiusInboxConsumer();
        var result = await consumer.RunUnderProcessLockAsync(pg.ConnectionString,
            new RadiusImportBinding(pg.Root,"fixture-only"),1,ct);
        Assert.Equal(1,result.Scanned);
        Assert.Equal(0,result.Imported);
        Assert.Equal(accepted.ToString("D"),consumer.Cursor?["packet_id"]?.GetValue<string>());
        Assert.True(await Marked(historical));
    }
}
