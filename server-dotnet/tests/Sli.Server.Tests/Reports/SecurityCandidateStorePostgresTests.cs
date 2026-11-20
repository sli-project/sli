using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Reports.SecurityCandidates;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Reports;

public sealed class SecurityCandidateStorePostgresTests
{
    [Fact]
    public async Task Candidates_use_short_rows_with_legacy_reads_disabled_or_requested()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var db=await fixture.Pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db,"""
            insert into servers(id,domain_id,hostname,fqdn,role) select 1,id,'dc.example.test','dc.example.test','domain_controller' from domains where fqdn='example.test';
            insert into storage_v2_entity_type(value) values('ad_user') on conflict do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
                select 70001,t.id,'sid:S-1-5-21-100000001-200000002-300000003-1002','Synthetic',d.id,sha256('synthetic'::bytea)
                from storage_v2_entity_type t cross join domains d where t.value='ad_user' and d.fqdn='example.test';
            """,ct);
        await using(var retired=new NpgsqlCommand("""
            select count(*) from unnest(array['public.events_v2_core','public.event_facts_v2','public.event_entity_link_blocks_v2']) relation
            where to_regclass(relation) is not null
            """,db)) Assert.Equal(0L,await retired.ExecuteScalarAsync(ct));
        long domain;
        await using(var command=new NpgsqlCommand("select domain_id from servers where id=1",db)) domain=Convert.ToInt64(await command.ExecuteScalarAsync(ct));
        var at=DateTimeOffset.UtcNow.AddMinutes(-10);
        var included=EventShortReadPostgresTests.Event(2147483648,4728,at,domain,sid:true,
            fields:new Dictionary<string,string> { ["MemberSid"]="S-1-5-21-100000001-200000002-300000003-1002" }).Short;
        var unrelated=EventShortReadPostgresTests.Event(2147483649,4728,at.AddMinutes(1),domain).Short;
        await using(var tx=await db.BeginTransactionAsync(ct)) { await ShortEventWriter.WriteAsync(db,tx,[included,unrelated],ct);await tx.CommitAsync(ct); }
        foreach(string setting in new[]{"true","false"}) {
            var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
                ["ConnectionStrings:Sli"]=fixture.Dsn("adlog_user"),["Sli:Storage:ShortEventReads"]=setting
            }).Build();
            var store=new SecurityCandidateStore(new PostgresConnectionFactory(config),config);
            Assert.Equal(new long[]{2147483648},await store.CandidatesAsync(70001,domain,at.AddMinutes(-1),at.AddMinutes(2),10,ct));
            Assert.Empty(await store.CandidatesAsync(70001,domain+1,at.AddMinutes(-1),at.AddMinutes(2),10,ct));
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
