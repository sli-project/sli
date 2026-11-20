using Npgsql;
using Sli.Server.Tests.Agents;
using Sli.Server.Storage.Direct;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class ShortEventTimePostgresTests
{
    [Fact]
    public async Task Attestation_matches_importer_for_the_entire_decimal_tail_without_a_tolerance()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner=new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        var cases=DirectEventTimeTests.MicrosecondRoundingCases().ToArray();
        var stamps=cases.Select(c=>(string)c[0]).ToArray();
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,
            eventKinds:Enumerable.Repeat(4625,stamps.Length).ToArray(),nativeTimestamps:stamps);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await using var proof=new NpgsqlCommand("select time_created_utc,source_sha256 is not null from event_hot order by event_record_id",owner);
        await using(var reader=await proof.ExecuteReaderAsync(ct)) {
            foreach(var sample in cases) {
                Assert.True(await reader.ReadAsync(ct));
                Assert.Equal(DirectEventTime.Utc((string)sample[0]),reader.GetDateTime(0));
                Assert.Equal((string)sample[1],DirectEventTime.IsoUtc(reader.GetDateTime(0).ToString("O")));
                Assert.True(reader.GetBoolean(1));
            }
            Assert.False(await reader.ReadAsync(ct));
        }
        // Even a matching forged allocation does not admit a one-microsecond shift.
        await PostCollectionPostgres.Sql(owner,
            "update storage_v2_event_identity_allocations set time_created_utc=time_created_utc+interval '1 microsecond'",ct);
        Assert.Equal("short_event_attestation_failed",(await Assert.ThrowsAsync<InvalidOperationException>(()=>
            ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows.Select(r=>r with { Time=r.Time.AddMicroseconds(1) }).ToArray(),ct))).Message);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Database_at_380_retries_only_eligible_packets_and_rollback_preserves_imports_and_refusals()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct,throughVersion:380);
        await using var owner=new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,eventKinds:[4625],nativeTimestamp:"2026-11-17T00:01:12.518787500Z");
        Assert.Equal("short_event_attestation_failed",(await Assert.ThrowsAsync<InvalidOperationException>(()=>
            ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct))).Message);
        await PostCollectionPostgres.Sql(owner,"update sli_agent_packet_inbox set imported_at=null",ct);
        int sequence=1;
        var cases=new List<(Guid Packet,bool Retry)> { (ShortEventAdmissionPostgresTests.Packet,true) };
        foreach(var (channel,module,reason,imported,disabled,retry) in new[] {
            ("System","sli.windows.ad-dc","short_event_attestation_failed",false,false,true),
            ("Directory Service","sli.windows.ad-dc","short_event_attestation_failed",false,false,true),
            ("Security","sli.windows.ad-dc-history","short_event_attestation_failed",false,false,true),
            ("System","sli.windows.ad-dc-history","short_event_attestation_failed",false,false,true),
            ("Directory Service","sli.windows.ad-dc-history","short_event_attestation_failed",false,false,true),
            ("Security","sli.windows.ad-dc","source_event_allocation_hash_mismatch",false,false,false),
            ("Security","sli.windows.ad-dc","short_event_attestation_failed",true,false,false),
            ("Security","sli.windows.ad-dc","short_event_attestation_failed",false,true,false),
            ("Microsoft-Windows-PowerShell/Operational","sli.windows.ad-dc","short_event_attestation_failed",false,false,false),
            ("Security","sli.workstations","short_event_attestation_failed",false,false,false)
        }) {
            Guid packet=Guid.NewGuid(); cases.Add((packet,retry));
            await using var clone=new NpgsqlCommand("""
                insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                    select agent_id,@module,@sequence,@packet,envelope_sha256,
                        envelope||jsonb_build_object('module_id',@module),receipt from sli_agent_receipts where packet_id=@original;
                insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at,module_disabled_at)
                    select @packet,r.envelope,jsonb_set(i.packet,'{header,channel}',to_jsonb(@channel::text)),i.event_rows,
                        case when @imported then now() end,case when @disabled then now() end
                    from sli_agent_packet_inbox i join sli_agent_receipts r on r.packet_id=@packet where i.packet_id=@original;
                insert into sli_agent_packet_quarantine(packet_id,reason_code,event_ordinal,recheck_reason_code,rechecked_at)
                    values(@packet,@reason,2,'agent_projection_failed',now());
                """,owner);
            clone.Parameters.AddWithValue("original",ShortEventAdmissionPostgresTests.Packet);
            clone.Parameters.AddWithValue("packet",packet); clone.Parameters.AddWithValue("sequence",(long)++sequence);
            clone.Parameters.AddWithValue("module",module); clone.Parameters.AddWithValue("channel",channel);
            clone.Parameters.AddWithValue("imported",imported); clone.Parameters.AddWithValue("disabled",disabled);
            clone.Parameters.AddWithValue("reason",reason); await clone.ExecuteNonQueryAsync(ct);
        }
        await PostCollectionPostgres.Sql(owner,"""
            insert into sli_agent_packet_quarantine(packet_id,reason_code,event_ordinal,recheck_reason_code,rechecked_at)
                select packet_id,'short_event_attestation_failed',2,'agent_projection_failed',now()
                from sli_agent_packet_inbox where packet_id='00000000-0000-4000-8000-000000003490';
            create temporary table synthetic_before381 as select packet_id,to_jsonb(q) refusal from sli_agent_packet_quarantine q;
            create temporary table synthetic_inbox381 as select packet_id,to_jsonb(i) body from sli_agent_packet_inbox i;
            """,ct);
        string migration=MigrationDirectory.Read().Single(m=>m.Version==381).Path;
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        foreach(var (packet,retry) in cases) {
            await using var proof=new NpgsqlCommand("""
                select (q.packet_id is null)=@retry
                    and case when @retry then a.details->'quarantine'=b.refusal else to_jsonb(q)=b.refusal end
                    and to_jsonb(i)=s.body
                from synthetic_before381 b join sli_agent_packet_inbox i using(packet_id)
                join synthetic_inbox381 s using(packet_id)
                left join sli_agent_packet_quarantine q using(packet_id)
                left join sli_agent_audit a on a.target=b.packet_id::text and a.action='packet_attestation_retry381'
                where b.packet_id=@packet;
                """,owner);
            proof.Parameters.AddWithValue("packet",packet); proof.Parameters.AddWithValue("retry",retry);
            Assert.Equal(true,await proof.ExecuteScalarAsync(ct));
        }
        // Finish one retry before rollback; all other refusals must return intact.
        await using(var imported=new NpgsqlCommand("update sli_agent_packet_inbox set imported_at=now() where packet_id=@packet",owner)) {
            imported.Parameters.AddWithValue("packet",ShortEventAdmissionPostgresTests.Packet); await imported.ExecuteNonQueryAsync(ct);
        }
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration,".rollback.sql"),null,ct);
        await using(var restored=new NpgsqlCommand("""
            select not exists(select 1 from synthetic_before381 b left join sli_agent_packet_quarantine q using(packet_id)
                where b.packet_id<>@packet and to_jsonb(q) is distinct from b.refusal)
                and not exists(select 1 from sli_agent_packet_quarantine where packet_id=@packet)
                and (select count(*)=1 and bool_and(source_sha256 is not null) from event_hot);
            """,owner)) {
            restored.Parameters.AddWithValue("packet",ShortEventAdmissionPostgresTests.Packet); Assert.Equal(true,await restored.ExecuteScalarAsync(ct));
        }
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
