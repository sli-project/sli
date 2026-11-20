using Npgsql;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class ShortEventReplayPostgresTests
{
    [Fact]
    public async Task Base_at_362_accepts_365_and_replay_attests_legacy_rows_without_counting_them_twice()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct,throughVersion:362);
        await using var owner=new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows.Select(r=>r with { PacketId=null }).ToArray(),ct);
        await using(var missing=new NpgsqlCommand("select bool_and(source_sha256 is null) from event_hot",owner))
            Assert.Equal(true,await missing.ExecuteScalarAsync(ct));
        string path=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/365_short_event_replay_admission.sql");
        await fixture.Pg.ApplyFileAsync(path,null,ct);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await Task.WhenAll(Enumerable.Range(0,3).Select(_=>ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct)));
        await using(var proof=new NpgsqlCommand("""
            select count(*),bool_and(h.source_sha256=a.normalized_hash and h.event_record_id=a.event_record_id
                and h.method#>>'{$origin,agent_id}'=@agent
                and not (h.method ?| array['$packet_id','$packet_ordinal']))
            from event_hot h join storage_v2_event_identity_allocations a on a.id=h.event_id;
            select bool_and(source_sha256 is not null) from event_cold_facts;
            select (select count(*) from event_cold_facts)+(select sum(event_count)::bigint from event_cold_daily);
            """,owner)) {
            proof.Parameters.AddWithValue("agent",ShortEventAdmissionPostgresTests.Agent.ToString());
            await using var result=await proof.ExecuteReaderAsync(ct); Assert.True(await result.ReadAsync(ct));
            Assert.Equal(rows.Length,result.GetInt64(0)); Assert.True(result.GetBoolean(1));
            Assert.True(await result.NextResultAsync(ct)); Assert.True(await result.ReadAsync(ct)); Assert.True(result.GetBoolean(0));
            Assert.True(await result.NextResultAsync(ct)); Assert.True(await result.ReadAsync(ct)); Assert.Equal(rows.Length,result.GetInt64(0));
        }
        // Rollback keeps imported data and quarantined refusals; reapply validates them.
        await PostCollectionPostgres.Sql(owner,"insert into sli_agent_packet_quarantine(packet_id,reason_code,event_ordinal) select packet_id,'short_event_attestation_failed',0 from sli_agent_packet_inbox",ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(path,".rollback.sql"),null,ct);
        await fixture.Pg.ApplyFileAsync(path,null,ct);
        await using(var retained=new NpgsqlCommand("select count(*) from sli_agent_packet_quarantine where reason_code='short_event_attestation_failed'",owner))
            Assert.Equal(1L,await retained.ExecuteScalarAsync(ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Theory]
    [InlineData("pending")]
    [InlineData("wrong-envelope")]
    [InlineData("wrong-ordinal")]
    [InlineData("wrong-fields")]
    [InlineData("wrong-native")]
    [InlineData("wrong-native-time")]
    [InlineData("wrong-time")]
    public async Task Replay_cannot_promote_legacy_rows_without_matching_admission_and_contents(string condition)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner=new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,nativeTimestamp:"2026-11-17T00:01:12.518787500Z");
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows.Select(r=>r with { PacketId=null }).ToArray(),ct);
        if(condition=="pending") await PostCollectionPostgres.Sql(owner,"update sli_agent_packet_inbox set imported_at=null",ct);
        if(condition=="wrong-envelope") await PostCollectionPostgres.Sql(owner,"update sli_agent_packet_inbox set envelope=envelope||'{\"generation\":\"forged\"}'",ct);
        if(condition=="wrong-native") await PostCollectionPostgres.Sql(owner,"update sli_agent_packet_inbox set event_rows=jsonb_set(event_rows,'{0,xml}','\"forged\"')",ct);
        if(condition=="wrong-native-time") await PostCollectionPostgres.Sql(owner,"update sli_agent_packet_inbox set event_rows=jsonb_set(event_rows,'{0,time_created}','\"2026-11-01T00:00:01Z\"')",ct);
        if(condition=="wrong-time") rows[0]=rows[0] with { Time=rows[0].Time.AddMicroseconds(1) };
        if(condition=="wrong-ordinal") rows[0]=rows[0] with { PacketOrdinal=99 };
        if(condition=="wrong-fields") rows[0]=rows[0] with { Actor="forged" };
        var error=await Assert.ThrowsAsync<InvalidOperationException>(()=>ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct));
        Assert.Equal("short_event_attestation_failed",error.Message);
        await using(var proof=new NpgsqlCommand("select count(*),bool_and(source_sha256 is null and method->'$origin' is null and actor is distinct from 'forged') from event_hot",owner)) {
            await using var result=await proof.ExecuteReaderAsync(ct); Assert.True(await result.ReadAsync(ct));
            Assert.Equal(rows.Length,result.GetInt64(0)); Assert.True(result.GetBoolean(1));
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
