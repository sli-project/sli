using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Entities;
using Sli.Server.Entities.State;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class EntityNewLayerPostgresTests
{
    [Fact]
    public async Task Projection_reads_new_events_once_and_claim_requires_admitted_source_without_legacy_tables()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var accepted=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,[accepted[0],accepted[1]],ct);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,[accepted[2] with { PacketId=null }],ct);
        await EntityShortReadsPostgresTests.Write(fixture,[
            EntityShortReadsPostgresTests.Row(910001,domain:2),
            EntityShortReadsPostgresTests.Row(910002,at:DateTime.UtcNow.AddDays(-20)),
            EntityShortReadsPostgresTests.Row(910003,4740,DateTime.UtcNow.AddDays(-20))],ct);
        await PostCollectionPostgres.Sql(owner,"""
            insert into storage_v2_entity_type(value) values('ad_user') on conflict do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
                select 10001,id,'sid:S-1-5-21-100000001-200000002-300000003-1001','synthetic',1,sha256('entity'::bytea)
                from storage_v2_entity_type where value='ad_user';
            insert into entity_state_projection_jobs(job_id,source_event_db_id,candidate_states)
                select gen_random_uuid(),id,'[{"entity_id":10001}]' from (values(900001),(900003),(999999)) ids(id);
            """,ct);
        await using(var retired=new NpgsqlCommand("""
            select count(*) from unnest(array['public.events_v2_core','public.event_facts_v2',
              'public.event_entity_link_blocks_v2','public.raw_log_files']) relation where to_regclass(relation) is not null
            """,owner))
            Assert.Equal(0L,await retired.ExecuteScalarAsync(ct));
        await using(var app=await fixture.Pg.OpenAsync(ct,"adlog_user"))
        await using(var tx=await app.BeginTransactionAsync(ct)) {
            var reader=new WhatWhereWhenDatabase(app,tx);
            var rows=await reader.Query(WhatWhereWhenCycle.HotSql+"where event.domain_id=@domain order by event.id",
                new() { ["boundary"]=DateTime.UtcNow.Date.AddDays(-14),["domain"]=1 },ct);
            Assert.Equal(new long[]{900001,900002,900003,910003},rows.Select(r=>EntityReader.Number(r!.AsObject(),"source_event_id")));
            var logon=Assert.Single(rows.OfType<JsonObject>(),r=>EntityReader.Number(r,"event_id")==4624);
            Assert.Equal("synthetic-user",logon["target_user_name"]!.ToString());
            Assert.Equal("example.test",logon["target_domain_name"]!.ToString());
            Assert.Equal("192.0.2.1",logon["ip_address"]!.ToString());
            Assert.Equal("3",logon["logon_type"]!.ToString());
            Assert.Equal(64,logon["source_event_hash"]!.ToString().Length);
        }
        await using(var worker=new NpgsqlConnection(fixture.Dsn("sli_storage_login"))) {
            await worker.OpenAsync(ct);
            var projector=new EntityStateProjector();
            var job=await projector.ClaimAsync(worker,ct);
            Assert.NotNull(job); Assert.Equal(900001,job.EventId);
            Assert.Null(await projector.ClaimAsync(worker,ct));
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
