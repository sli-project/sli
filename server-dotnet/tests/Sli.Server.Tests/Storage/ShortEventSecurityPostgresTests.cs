using Npgsql;
using Sli.Server.Tests.Agents;
using Sli.Server.Storage.Direct;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class ShortEventSecurityPostgresTests
{
    [Fact]
    public async Task Previous_database_accepts_379_and_retries_Security_without_losing_quarantine_history()
    {
        var ct=TestContext.Current.CancellationToken;
        int previous=MigrationDirectory.Read().Where(m=>m.Version<379).Max(m=>m.Version);
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct,throughVersion:previous);
        await using var owner=new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        const string stamp="2026-11-01T00:00:00.0001255Z";
        await using(var time=new NpgsqlCommand("select @stamp::timestamptz<>@normalized",owner)) {
            time.Parameters.AddWithValue("stamp",stamp); time.Parameters.AddWithValue("normalized",DirectEventTime.Utc(stamp));
            Assert.Equal(true,await time.ExecuteScalarAsync(ct));
        }
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,eventKinds:[4625,4776,4768,4769],nativeTimestamp:stamp);
        Assert.Equal("short_event_attestation_failed",(await Assert.ThrowsAsync<InvalidOperationException>(
            ()=>ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct))).Message);
        await PostCollectionPostgres.Sql(owner,"""
            update sli_agent_packet_inbox set imported_at=null;
            insert into sli_agent_packet_quarantine(packet_id,reason_code,event_ordinal,recheck_reason_code,rechecked_at)
                select packet_id,'short_event_attestation_failed',2,'agent_projection_failed',now() from sli_agent_packet_inbox;
            """,ct);
        string migration=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/379_security_packet_attestation.sql");
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        await using(var retry=new NpgsqlCommand("""
            select not exists(select 1 from sli_agent_packet_quarantine)
                and exists(select 1 from sli_agent_packet_inbox where imported_at is null and event_rows is not null)
                and exists(select 1 from sli_agent_audit where action='packet_attestation_retry379'
                    and details#>>'{quarantine,reason_code}'='short_event_attestation_failed'
                    and details#>>'{quarantine,event_ordinal}'='2'
                    and details#>>'{quarantine,recheck_reason_code}'='agent_projection_failed');
            """,owner)) Assert.Equal(true,await retry.ExecuteScalarAsync(ct));
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration,".rollback.sql"),null,ct);
        await using(var restored=new NpgsqlCommand("select event_ordinal=2 and recheck_reason_code='agent_projection_failed' and rechecked_at is not null from sli_agent_packet_quarantine",owner))
            Assert.Equal(true,await restored.ExecuteScalarAsync(ct));
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        await PostCollectionPostgres.Sql(owner,"update sli_agent_packet_inbox set imported_at=now()",ct);
        // Even an allocation forged to match a shifted short row cannot replace
        // the native event's time. The attestation must validate both bindings.
        await PostCollectionPostgres.Sql(owner,"update storage_v2_event_identity_allocations set time_created_utc=time_created_utc+interval '1 microsecond'",ct);
        Assert.Equal("short_event_attestation_failed",(await Assert.ThrowsAsync<InvalidOperationException>(
            ()=>ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows.Select(r=>r with { Time=r.Time.AddMicroseconds(1) }).ToArray(),ct))).Message);
        await PostCollectionPostgres.Sql(owner,"update storage_v2_event_identity_allocations set time_created_utc=time_created_utc-interval '1 microsecond'",ct);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await using var proof=new NpgsqlCommand("select count(*),bool_and(source_sha256 is not null) from event_hot",owner);
        await using(var reader=await proof.ExecuteReaderAsync(ct)) {
            Assert.True(await reader.ReadAsync(ct)); Assert.Equal(rows.Length,reader.GetInt64(0)); Assert.True(reader.GetBoolean(1));
        }
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration,".rollback.sql"),null,ct);
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        await using(var retained=new NpgsqlCommand("select not exists(select 1 from sli_agent_packet_quarantine) and (select count(*) from event_hot)=4",owner))
            Assert.Equal(true,await retained.ExecuteScalarAsync(ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
