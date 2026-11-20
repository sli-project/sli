using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.Ingress;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Semantic;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed partial class AdDcImportPerformanceTests
{
    [Theory]
    [InlineData("Security")]
    [InlineData("System")]
    [InlineData("Directory Service")]
    public async Task Dc_packet_with_Windows_precision_is_automatically_retried(string channel)
    {
        const int version=381;
        var ct=TestContext.Current.CancellationToken;
        using var environment=new SemanticProducerPostgresTests.Admission(mode:null);
        int previous=MigrationDirectory.Read().Where(m=>m.Version<version).Max(m=>m.Version);
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct,throughVersion:previous);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert=new CertificateRequest("CN=synthetic",key,HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(1));
        await SeedAsync(admin,fixture.Pg.Root,cert,ct);
        // Exercise the hostname fallback too: no enrollment audit with server_id.
        await PostCollectionPostgres.Sql(admin,"update servers set hostname='dc-fixture' where fqdn='dc-fixture.example.test'",ct);
        var sample=Sample(1,4);
        int[] kinds=channel=="Security" ? [4625,4776,4768,4769] : Enumerable.Repeat(channel=="System" ? 7045 : 2887,4).ToArray();
        string provider=channel switch { "System"=>"Service Control Manager","Directory Service"=>"Microsoft-Windows-ActiveDirectory_DomainService",_=>"Microsoft-Windows-Security-Auditing" };
        string[] fractions=["518787500","1234564999","1234565001","999999500"];
        for(int i=0;i<kinds.Length;i++) {
            string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='{provider}'/><EventID>{kinds[i]}</EventID><EventRecordID>{i+1}</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00.{fractions[i]}Z'/><Channel>{channel}</Channel><Computer>{Source}</Computer></System><EventData><Data Name='TargetUserName'>synthetic-user</Data><Data Name='TargetDomainName'>example.test</Data><Data Name='IpAddress'>192.0.2.17</Data><Data Name='Status'>0xc000006a</Data></EventData></Event>";
            sample.Payload["records"]![i]!["payload"]=EventXml.Parse(xml,Source,"fixture-endpoint",channel);
        }
        var envelope=Envelope.Parse(sample.Envelope) with { PayloadSha256=Packets.Digest(sample.Payload), PayloadBytes=CanonicalJson.Length(sample.Payload) };
        if(channel!="Security") {
            int index=channel=="System" ? 1 : 2;
            sample.Payload["context"]!["ad_dc"]!["channels"]=new JsonObject { ["Security"]=true,["System"]=true,["Directory Service"]=true };
            sample.Payload["header"]!["channel"]=channel;
            var after=JsonNode.Parse(envelope.CursorAfter.Token)!;
            var progress=after["channels"]!["Security"]!.DeepClone();
            progress["bookmark"]=progress["bookmark"]!.GetValue<string>().Replace("Security",channel);
            after["channels"]!.AsObject().Remove("Security"); after["channels"]![channel]=progress; after["next"]=(index+1)%3;
            envelope=envelope with {
                CursorBefore=new("bookmark",CanonicalJson.Serialize(new JsonObject { ["next"]=index,["channels"]=new JsonObject() })),
                CursorAfter=new("bookmark",CanonicalJson.Serialize(after)),
                PayloadSha256=Packets.Digest(sample.Payload),PayloadBytes=CanonicalJson.Length(sample.Payload)
            };
        }
        sample=new(envelope.ToJson(),sample.Payload,AgentAdDcValidator.Validate(envelope,sample.Payload,null,Source));
        await ReceiptAsync(admin,sample,ct);
        await using var worker=NpgsqlDataSource.Create(fixture.Dsn("sli_storage_login"));
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user")); await app.OpenAsync(ct);
        string catalog=Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json");
        var consumer=new AgentWorkstationInboxConsumer(new ImportConnection(),new DirectAdDcRuntime(worker,catalog));
        var refused=await consumer.RunOnceAsync(app,1,ct);
        Assert.Equal(1,refused.Quarantined); Assert.Equal(0,refused.Imported);
        await using(var failed=new NpgsqlCommand("""
            select (select reason_code from sli_agent_packet_quarantine)='short_event_attestation_failed'
                and (select imported_at is null from sli_agent_packet_inbox)
                and not exists(select 1 from event_hot);
            """,admin)) Assert.Equal(true,await failed.ExecuteScalarAsync(ct));
        // Other permanent refusals must stay quarantined.
        var other=Sample(20); await ReceiptAsync(admin,other,ct);
        await using(var quarantine=new NpgsqlCommand("insert into sli_agent_packet_quarantine(packet_id,reason_code,event_ordinal) values(@packet,'source_event_allocation_hash_mismatch',0)",admin)) {
            quarantine.Parameters.AddWithValue("packet",Guid.Parse(other.Envelope["packet_id"]!.GetValue<string>()));
            await quarantine.ExecuteNonQueryAsync(ct);
        }
        string migration=MigrationDirectory.Read().Single(m=>m.Version==version).Path;
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        var retried=await consumer.RunOnceAsync(app,1,ct);
        // A running poller first closes its previous fairness round, then
        // revisits earlier packets on the following scheduled poll.
        if(retried.Scanned==0) retried=await consumer.RunOnceAsync(app,1,ct);
        Assert.Equal(1,retried.Imported); Assert.Equal(0,retried.Quarantined); Assert.Empty(retried.PendingReasons);
        // Ordinary replay preserves identities and daily totals.
        await using(var tx=await app.BeginTransactionAsync(ct)) {
            await ImportAsync(app,tx,worker,sample,catalog,ct); await tx.CommitAsync(ct);
        }
        await using(var proof=new NpgsqlCommand("""
            select count(*),bool_and(h.source_sha256=a.normalized_hash and h.event_record_id=a.event_record_id
                and h.method->>'$channel'=@channel and h.method#>>'{$origin,agent_id}'=@agent)
            from event_hot h join storage_v2_event_identity_allocations a on a.id=h.event_id;
            select (select count(*) from event_cold_facts)+coalesce((select sum(event_count)::bigint from event_cold_daily),0);
            select count(*)=1 and bool_and(reason_code='source_event_allocation_hash_mismatch') from sli_agent_packet_quarantine;
            select count(*)=1 from sli_agent_packet_inbox where imported_at is not null;
            select count(*)=1 from sli_agent_audit where action=@action
                and details#>>'{quarantine,reason_code}'='short_event_attestation_failed';
            """,admin)) {
            proof.Parameters.AddWithValue("agent",Agent.ToString());
            proof.Parameters.AddWithValue("channel",channel); proof.Parameters.AddWithValue("action","packet_attestation_retry"+version);
            await using var reader=await proof.ExecuteReaderAsync(ct);
            Assert.True(await reader.ReadAsync(ct)); Assert.Equal(kinds.Length,reader.GetInt64(0)); Assert.True(reader.GetBoolean(1));
            Assert.True(await reader.NextResultAsync(ct)); Assert.True(await reader.ReadAsync(ct)); Assert.Equal(kinds.Length,reader.GetInt64(0));
            for(int i=0;i<3;i++) { Assert.True(await reader.NextResultAsync(ct)); Assert.True(await reader.ReadAsync(ct)); Assert.True(reader.GetBoolean(0)); }
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
