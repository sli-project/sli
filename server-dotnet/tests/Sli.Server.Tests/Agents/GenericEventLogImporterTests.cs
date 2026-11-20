using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using AgentIdentity = Sli.Server.Agents.AgentIdentity;
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.Ingress;
using Sli.Server.Entities;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class GenericEventLogImporterTests
{
    private const string Module="sli.windows-eventlog", Source="eventlog-fixture.example.test";
    private static readonly Guid Agent=Guid.NewGuid(), Host=Guid.NewGuid();

    private static JsonObject Payload(string channel,int eventId,long record=1,string? provider=null)
    {
        provider??=channel=="Security"?"Microsoft-Windows-Security-Auditing":"Service Control Manager";
        string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='{provider}'/><EventID>{eventId}</EventID><EventRecordID>{record}</EventRecordID><TimeCreated SystemTime='2026-11-08T00:00:00.0001255Z'/><Channel>{channel}</Channel><Computer>{Source}</Computer></System><EventData><Data Name='SubjectUserName'>synthetic-user</Data></EventData></Event>";
        return CollectionPacket.Make(Source,channel,"synthetic-generation",new JsonObject { ["after_record_id"]=null,["last_record_id"]=record },
            [new PacketRecord("event_xml",record,EventXml.Parse(xml,Source,Source,channel))],"not_proven",null,DateTimeOffset.UtcNow);
    }

    private static SignedPacket Sign(ECDsa key,JsonObject payload,long sequence,Guid? agent=null) => Packets.Make(new EcdsaPacketSigner(key),(agent??Agent).ToString("D"),sequence,
        new Sample(Module,Host.ToString("D"),payload["header"]!["channel"]!.GetValue<string>(),"synthetic-generation",new Cursor("record_id",""),
            new Cursor("record_id",payload["header"]!["cursor"]!["last_record_id"]?.ToString()??""),payload),DateTimeOffset.UtcNow);

    [Fact]
    public async Task Signed_receipts_publish_native_events_with_identity_provenance_and_replay()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:387);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString);await admin.OpenAsync(ct);
        string migration=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/388_password_live_first.sql");
        await using(var metadata=new NpgsqlCommand("""
            select jsonb_agg(jsonb_build_array(p.oid,p.proowner,p.proacl,pg_get_functiondef(p.oid)) order by p.oid)::text
            from pg_proc p where p.oid in ('public.attest_short_event337()'::regprocedure,'public.short_detection_sources337()'::regprocedure)
            """,admin)) {
            string before=Assert.IsType<string>(await metadata.ExecuteScalarAsync(ct));
            await fixture.Pg.ApplyFileAsync(migration,null,ct);
            string applied=Assert.IsType<string>(await metadata.ExecuteScalarAsync(ct));
            Assert.NotEqual(before,applied);
            Assert.Single(await fixture.RollbackAfterAsync(387,ct));
            Assert.Equal(before,await metadata.ExecuteScalarAsync(ct));
            await fixture.Pg.ApplyFileAsync(migration,null,ct);
            Assert.Equal(applied,await metadata.ExecuteScalarAsync(ct));
        }
        await using(var privileges=new NpgsqlCommand("""
            select has_function_privilege('adlog_user','public.write_generic_short_events388(jsonb)','execute')
               and not has_function_privilege('adlog_semantic_worker','public.write_generic_short_events388(jsonb)','execute')
               and not has_function_privilege('adlog_user','public.generic_short_event_proof388(uuid,integer,bigint,timestamptz,integer,bigint,jsonb)','execute')
            """,admin))
            Assert.Equal(true,await privileges.ExecuteScalarAsync(ct));
        await SeedAsync(admin,fixture.Pg.Root,ct);
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user"));await app.OpenAsync(ct);
        string catalog=Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json");
        await using var runtime=DirectAdDcRuntime.TryCreate(k=>k=="ADLOG_STORAGE_V2_WORKER_DSN"?fixture.Dsn("sli_storage_login"):null,_=>[],catalog);
        Assert.NotNull(runtime);
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert=new CertificateRequest("CN=synthetic",key,HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(1));
        var service=new AgentPacketService(TimeProvider.System,new AgentInboxLimits(4096,268435456,32768,2147483648,65536,4294967296,17179869184),
            new AgentIngressDiagnostics(fixture.Pg.Root,NullLogger<AgentIngressDiagnostics>.Instance,TimeProvider.System));
        async Task<long> AllocationCount()
        {
            await using var count=new NpgsqlCommand("select count(*) from storage_v2_event_identity_allocations",admin);
            return Assert.IsType<long>(await count.ExecuteScalarAsync(ct));
        }
        long sequence=0;
        Guid firstSecurityPacket=Guid.Empty;
        foreach(var (channel,kind) in new[]{("Security",4625),("System",7045),("Application",65000)}) {
            // Each generic module has one channel for its complete receipt stream.
            Guid streamAgent=channel=="Security"?Agent:Guid.NewGuid();
            if(streamAgent!=Agent)await SeedAgentAsync(admin,streamAgent,channel,ct);
            sequence++;var signed=Sign(key,Payload(channel,kind),1,streamAgent);
            if(channel=="Security")firstSecurityPacket=Guid.Parse(signed.Envelope.PacketId);
            await using(var tx=await app.BeginTransactionAsync(ct)) {
                var identity=await LockAgentAsync(app,tx,streamAgent,ct);
                var receipt=await service.ReceiveAsync(app,tx,identity,cert,signed.ToJson(),ct);
                Assert.True(receipt["status"]!.GetValue<string>()=="committed",receipt["error_code"]?.ToString());await tx.CommitAsync(ct);
            }
            // Receipt alone is not an import. The worker must publish first.
            Assert.Equal(sequence-1,await AllocationCount());
            // A newer policy revision must not strand an acknowledged packet.
            await PostCollectionPostgres.Sql(admin,"update sli_agent_module_bindings set policy_revision='2'",ct);
            await using(var tx=await app.BeginTransactionAsync(ct)) {
                var unavailable=await AgentWorkstationInboxConsumer.ProcessNextAsync(app,tx,null,ct);
                Assert.False(unavailable.Imported);Assert.Equal("agent_storage_unavailable",unavailable.PendingReason);await tx.RollbackAsync(ct);
            }
            for(int replay=0;replay<2;replay++) {
                await using var tx=await app.BeginTransactionAsync(ct);
                var step=await AgentWorkstationInboxConsumer.ProcessNextAsync(app,tx,null,ct,runtime);
                Assert.True(step.Imported,step.PendingReason);
                Assert.Equal(Guid.Parse(signed.Envelope.PacketId),step.PacketId);
                if(replay==0)await tx.RollbackAsync(ct);else await tx.CommitAsync(ct);
            }
            await using(var verify=new NpgsqlCommand("""
                select a.id,a.event_record_id,ch.value,rep.representation->>'provider_name',
                    rep.representation->>'computer_name',rep.representation->>'xml',
                    octet_length(a.normalized_hash),octet_length(rep.representation_sha256),i.imported_at is not null,
                    h.event_kind,h.event_record_id,h.method#>>'{$origin,plugin_id}',h.method#>>'{$origin,agent_id}',
                    h.source_sha256 is null,exists(select 1 from semantic_event_source355 s where s.id=a.id),a.time_created_utc
                from sli_agent_packet_inbox i join sli_agent_receipts r using(packet_id)
                join storage_v2_channel ch on ch.value=@channel
                join storage_v2_event_identity_allocations a on a.channel_id=ch.id and a.event_record_id=1
                join event_source_representations_v2 rep on rep.event_id=a.id and rep.normalized_hash=a.normalized_hash
                join servers on servers.id=a.server_id and servers.hostname=@source
                left join event_hot h on h.event_id=a.id and h.time_created_utc=a.time_created_utc
                where i.packet_id=@packet and r.module_id=@module and r.envelope=i.envelope
                """,admin)) {
                verify.Parameters.AddWithValue("packet",Guid.Parse(signed.Envelope.PacketId));
                verify.Parameters.AddWithValue("channel",channel);
                verify.Parameters.AddWithValue("source",Source);
                verify.Parameters.AddWithValue("module",Module);
                await using var r=await verify.ExecuteReaderAsync(ct);
                Assert.True(await r.ReadAsync(ct));
                Assert.True(r.GetInt64(0)>0);
                Assert.Equal(1L,r.GetInt64(1));Assert.Equal(channel,r.GetString(2));
                Assert.Equal(channel=="Security"?"Microsoft-Windows-Security-Auditing":"Service Control Manager",r.GetString(3));
                Assert.Equal(Source,r.GetString(4));
                Assert.Equal(signed.Payload["records"]![0]!["payload"]!["xml"]!.GetValue<string>(),r.GetString(5));
                Assert.Equal(32,r.GetInt32(6));Assert.Equal(32,r.GetInt32(7));Assert.True(r.GetBoolean(8));
                if(channel=="Application") Assert.True(r.IsDBNull(9));
                else {
                    Assert.Equal(kind,r.GetInt32(9));Assert.Equal(1L,r.GetInt64(10));
                    Assert.Equal(Module,r.GetString(11));Assert.Equal(streamAgent.ToString(),r.GetString(12));
                    Assert.True(r.GetBoolean(13));
                }
                Assert.False(r.GetBoolean(14));
                Assert.Equal(new DateTime(2026,11,8,0,0,0,DateTimeKind.Utc).AddTicks(1260),r.GetDateTime(15));
                Assert.False(await r.ReadAsync(ct));
            }
            await PostCollectionPostgres.Sql(admin,"update sli_agent_module_bindings set policy_revision='1'",ct);
        }
        // Use the original agent for the remaining synthetic receipt mutations.
        await using(var binding=new NpgsqlCommand("update sli_agent_module_bindings set channel='Application' where agent_id=@agent",admin)) {
            binding.Parameters.AddWithValue("agent",Agent);await binding.ExecuteNonQueryAsync(ct);
        }
        sequence=1;
        // Replay a separately acknowledged packet with the same native identity.
        var duplicate=Sign(key,Payload("Application",65000),++sequence);
        await InsertAsync(admin,duplicate,ct);
        await using(var tx=await app.BeginTransactionAsync(ct)) {
            Assert.True((await AgentWorkstationInboxConsumer.ProcessNextAsync(app,tx,null,ct,runtime)).Imported);await tx.CommitAsync(ct);
        }
        Assert.Equal(3L,await AllocationCount());
        await using(var count=new NpgsqlCommand("""
            select (select count(*) from event_hot),(select count(*) from event_cold_facts),
                   (select sum(event_count)::bigint from event_cold_daily)
            """,admin)) {
            await using var r=await count.ExecuteReaderAsync(ct);Assert.True(await r.ReadAsync(ct));
            // 4625 rolls into daily counts, 7045 keeps a fact, and the unknown event retains native identity.
            Assert.Equal(2,r.GetInt64(0));Assert.Equal(1,r.GetInt64(1));Assert.Equal(1,r.GetInt64(2));
        }

        var empty=Sign(key,CollectionPacket.Make(Source,"Application","synthetic-generation",
            new JsonObject { ["after_record_id"]=null,["last_record_id"]=null },[],"not_proven",null,DateTimeOffset.UtcNow),++sequence);
        await InsertAsync(admin,empty,ct);
        await using(var tx=await app.BeginTransactionAsync(ct)) {
            Assert.True((await AgentWorkstationInboxConsumer.ProcessNextAsync(app,tx,null,ct,runtime)).Imported);await tx.CommitAsync(ct);
        }

        await using(var binding=new NpgsqlCommand("update sli_agent_module_bindings set channel='Security' where agent_id=@agent and module_id=@module",admin)) {
            binding.Parameters.AddWithValue("agent",Agent);binding.Parameters.AddWithValue("module",Module);await binding.ExecuteNonQueryAsync(ct);
        }
        // Every refused packet stays pending, without publishing any new event.
        var pending=Sign(key,Payload("Security",4625,2),++sequence);await InsertAsync(admin,pending,ct);
        // Only the synthetic owner can corrupt admitted evidence for refusal tests.
        async Task AdminRefuses(string expected,string mutation) {
            await using var tx=await admin.BeginTransactionAsync(ct);await PostCollectionPostgres.Sql(admin,mutation,ct);
            var step=await AgentWorkstationInboxConsumer.ProcessNextAsync(admin,tx,null,ct,runtime);
            Assert.False(step.Imported);Assert.Equal(expected,step.PendingReason);
            await using var check=new NpgsqlCommand("select imported_at is null from sli_agent_packet_inbox where packet_id=@id",admin,tx);
            check.Parameters.AddWithValue("id",Guid.Parse(pending.Envelope.PacketId));Assert.Equal(true,await check.ExecuteScalarAsync(ct));await tx.RollbackAsync(ct);
        }
        await using(var tx=await admin.BeginTransactionAsync(ct)) {
            await PostCollectionPostgres.Sql(admin,"update sli_agents set status='disabled'",ct);
            var step=await AgentWorkstationInboxConsumer.ProcessNextAsync(admin,tx,null,ct,runtime);
            Assert.False(step.Scanned);
            Assert.Equal(3L,await AllocationCount());
            await tx.RollbackAsync(ct);
        }
        await AdminRefuses("agent_module_not_assigned","update sli_agents set assigned_modules='[]'");
        await AdminRefuses("agent_eventlog_source_not_bound","update sli_agent_module_bindings set source_instance_id='other'");
        await AdminRefuses("agent_eventlog_source_not_bound","update sli_agent_module_bindings set channel='Application'");
        await AdminRefuses("agent_packet_attestation_invalid","update sli_agent_receipts set envelope_sha256=repeat('b',64)");
        await AdminRefuses("agent_packet_attestation_invalid","update sli_agent_packet_inbox set event_rows=jsonb_set(event_rows,'{0,event_id}','65002') where imported_at is null");
        await AdminRefuses("agent_eventlog_source_not_configured","update servers set is_active=false");
        await AdminRefuses("agent_storage_unavailable","delete from storage_v2_runtime_authorizations");
        await AdminRefuses("storage_v2_projection_schema_missing","delete from schema_migrations where version=19");
        await AdminRefuses("agent_packet_attestation_invalid","update sli_agent_packet_inbox set packet=jsonb_set(packet,'{records,0,payload,xml}','\"<Event/>\"') where imported_at is null");
        await AdminRefuses("agent_packet_attestation_invalid","update sli_agent_packet_inbox set envelope=jsonb_set(envelope,'{payload_sha256}',to_jsonb(repeat('c',64))) where imported_at is null");
        Assert.Equal(3L,await AllocationCount());

        await using(var tx=await app.BeginTransactionAsync(ct)) {
            Assert.True((await AgentWorkstationInboxConsumer.ProcessNextAsync(app,tx,null,ct,runtime)).Imported);await tx.CommitAsync(ct);
        }
        var conflictPayload=Payload("Security",4625,2);var original=conflictPayload["records"]![0]!["payload"]!.AsObject();
        conflictPayload["records"]![0]!["payload"]=EventXml.Parse(original["xml"]!.GetValue<string>().Replace("synthetic-user","different-user",StringComparison.Ordinal),Source,Source,"Security");
        var conflict=Sign(key,conflictPayload,++sequence);await InsertAsync(admin,conflict,ct);
        await using(var tx=await app.BeginTransactionAsync(ct)) {
            var step=await AgentWorkstationInboxConsumer.ProcessNextAsync(app,tx,null,ct,runtime);
            Assert.False(step.Imported);Assert.True(step.Quarantined);Assert.Equal("published_source_event_hash_mismatch",step.PendingReason);await tx.CommitAsync(ct);
        }
        var malformedPayload=Payload("Security",4625,3);malformedPayload["records"]![0]!["payload"]!["event_id"]=4624;
        var malformed=Sign(key,malformedPayload,++sequence);await InsertAsync(admin,malformed,ct);
        await using(var tx=await app.BeginTransactionAsync(ct)) {
            var step=await AgentWorkstationInboxConsumer.ProcessNextAsync(app,tx,null,ct,runtime);
            Assert.Equal(Guid.Parse(malformed.Envelope.PacketId),step.PacketId);Assert.False(step.Imported);Assert.False(step.Quarantined);Assert.Equal("agent_projection_failed",step.PendingReason);await tx.CommitAsync(ct);
        }
        await using(var verify=new NpgsqlCommand("""
            select (select count(*) from storage_v2_event_identity_allocations),
                   (select count(*) from storage_v2_event_identity_allocations where event_record_id=3),
                   (select imported_at is null from sli_agent_packet_inbox where packet_id=@id),
                   (select count(*) from sli_agent_packet_quarantine where packet_id=@conflict)
            """,admin)) {
            verify.Parameters.AddWithValue("id",Guid.Parse(malformed.Envelope.PacketId));
            verify.Parameters.AddWithValue("conflict",Guid.Parse(conflict.Envelope.PacketId));await using var r=await verify.ExecuteReaderAsync(ct);
            Assert.True(await r.ReadAsync(ct));Assert.Equal(4,r.GetInt64(0));Assert.Equal(0,r.GetInt64(1));Assert.True(r.GetBoolean(2));Assert.Equal(1,r.GetInt64(3));
        }
        await CheckSharedAdSourceAsync(fixture,admin,app,runtime,firstSecurityPacket,ct);
        await CheckConcurrentSharedAdSourceAsync(fixture,admin,app,runtime,Sign(key,Payload("Security",4625,4),sequence+1),ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
        var refused=await Assert.ThrowsAsync<InvalidOperationException>(()=>fixture.RollbackAfterAsync(387,ct));
        Assert.Contains("generic_short_events388_rollback_has_history",refused.Message);
        await using var retained=new NpgsqlCommand("""
            select exists(select 1 from schema_migrations where version=388 and name='password_live_first')
               and exists(select 1 from event_cold_facts where event_kind=7045 and event_record_id=1
                   and method#>>'{$origin,plugin_id}'='sli.windows-eventlog')
            """,admin);
        Assert.Equal(true,await retained.ExecuteScalarAsync(ct));
    }

    private static async Task CheckSharedAdSourceAsync(SqlPostgresFixture fixture,NpgsqlConnection admin,
        NpgsqlConnection app,DirectAdDcRuntime runtime,Guid firstSecurityPacket,CancellationToken ct)
    {
        await using(var binding=new NpgsqlCommand("""
            insert into sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy)
                select id,2,assigned_modules||jsonb_build_array(jsonb_build_object('module_id','sli.windows.ad-dc','enabled',true,
                    'config',jsonb_build_object('source_name',@source,'connect_address',@source,'policy_revision','2',
                    'channels','{"Directory Service":false,"Security":true,"System":false}'::jsonb,
                    'channel_generations',jsonb_build_object('Security',@host),'allow_event_ids',null,
                    'batch_size',128,'initial_read_hours','all'))),collection_policy
                from sli_agents where id=@agent;
            update sli_agents a set assigned_modules=p.assigned_modules,policy_revision=p.revision
                from sli_agent_policy_history p where a.id=@agent and p.agent_id=a.id and p.revision=2;
            """,admin)) {
            binding.Parameters.AddWithValue("agent",Agent);
            binding.Parameters.AddWithValue("host",Host.ToString());
            binding.Parameters.AddWithValue("source",Source);
            await binding.ExecuteNonQueryAsync(ct);
        }
        await using var semantic=new NpgsqlConnection(fixture.Dsn("sli_semantic_login"));await semantic.OpenAsync(ct);
        await PostCollectionPostgres.Sql(semantic,"set role adlog_semantic_worker",ct);
        await using var sources=new NpgsqlCommand("select count(*) from public.t109_detection_sources()",semantic);
        Assert.Equal(0L,await sources.ExecuteScalarAsync(ct));

        long id,server,domain;
        await using(var publication=new NpgsqlCommand("""
            select m.event_id,(m.method->>'$server_id')::bigint,m.domain_id
            from event_hot m where m.event_kind=4625 and m.event_record_id=1 and m.method#>>'{$origin,plugin_id}'=@module
            """,app)) {
            publication.Parameters.AddWithValue("module",Module);
            await using var r=await publication.ExecuteReaderAsync(ct);
            Assert.True(await r.ReadAsync(ct));
            id=r.GetInt64(0);server=r.GetInt64(1);domain=r.GetInt64(2);
            Assert.False(await r.ReadAsync(ct));
        }
        string journalSql=EntityShortSql.Source("@boundary",daily:false);
        await using(var journal=new NpgsqlCommand(
            $"select event_id from ({journalSql}) visible where visible.id=@id and visible.domain_id=@domain",app)) {
            journal.Parameters.AddWithValue("boundary",new DateTime(2026,11,8,0,0,0,DateTimeKind.Utc));
            journal.Parameters.AddWithValue("id",id);journal.Parameters.AddWithValue("domain",domain);
            Assert.Equal(4625,await journal.ExecuteScalarAsync(ct));
        }
        await using var admitted=new NpgsqlCommand("select count(*) from public.semantic_event_source355 where id=@id",semantic);
        admitted.Parameters.AddWithValue("id",id);
        Assert.Equal(0L,await admitted.ExecuteScalarAsync(ct));

        // The AD writer receives an independently admitted copy of the same
        // native row. Both streams share the same physical event identity.
        var native=Payload("Security",4625)["records"]![0]!["payload"]!.AsObject();
        Guid packet=await SeedAdReceiptAsync(admin,native,1,ct);
        var row=ShortEventRow.Create(id,domain,native,Direct4624Projection.Create(native),server)!;
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,[row with { PacketId=packet,PacketOrdinal=0 }],ct);
        Assert.Equal(1L,await admitted.ExecuteScalarAsync(ct));
        Assert.Equal(1L,await sources.ExecuteScalarAsync(ct));
        await using(var replay=new NpgsqlCommand("update sli_agent_packet_inbox set imported_at=null where packet_id=@packet",admin)) {
            replay.Parameters.AddWithValue("packet",firstSecurityPacket);
            Assert.Equal(1,await replay.ExecuteNonQueryAsync(ct));
        }
        await using(var tx=await app.BeginTransactionAsync(ct)) {
            var step=await AgentWorkstationInboxConsumer.ProcessNextAsync(app,tx,null,ct,runtime);
            Assert.True(step.Imported,step.PendingReason);
            Assert.Equal(firstSecurityPacket,step.PacketId);
            await tx.CommitAsync(ct);
        }
        Assert.Equal(1L,await admitted.ExecuteScalarAsync(ct));
        Assert.Equal(1L,await sources.ExecuteScalarAsync(ct));
        await using var aggregate=new NpgsqlCommand("select count(*)=1 and sum(event_count)=2 from event_cold_daily where event_kind=4625",app);
        Assert.Equal(true,await aggregate.ExecuteScalarAsync(ct));
    }

    private static async Task CheckConcurrentSharedAdSourceAsync(SqlPostgresFixture fixture,NpgsqlConnection admin,
        NpgsqlConnection app,DirectAdDcRuntime runtime,SignedPacket signed,CancellationToken ct)
    {
        await InsertAsync(admin,signed,ct);
        var native=signed.Payload["records"]![0]!["payload"]!.AsObject();
        var rows=EventLogValidator.Validate(signed.Envelope,signed.Payload,Source);
        await using var generic=await app.BeginTransactionAsync(ct);
        await DirectWindowsEventLogPacket.ImportAsync(app,generic,runtime.Worker,Guid.Parse(signed.Envelope.PacketId),
            signed.Envelope.ToJson(),signed.Payload,rows,runtime.CatalogPath,ct);

        long id,server,domain;
        await using(var allocation=new NpgsqlCommand("""
            select a.id,a.server_id,s.domain_id from storage_v2_event_identity_allocations a
            join servers s on s.id=a.server_id where s.hostname=@source and a.event_record_id=4
            """,admin)) {
            allocation.Parameters.AddWithValue("source",Source);
            await using var r=await allocation.ExecuteReaderAsync(ct);
            Assert.True(await r.ReadAsync(ct));
            id=r.GetInt64(0);server=r.GetInt64(1);domain=r.GetInt64(2);
            Assert.False(await r.ReadAsync(ct));
        }
        Guid packet=await SeedAdReceiptAsync(admin,native,2,ct);
        var row=ShortEventRow.Create(id,domain,native,Direct4624Projection.Create(native),server)!;
        await using var worker=new NpgsqlConnection(fixture.Dsn("sli_storage_login"));await worker.OpenAsync(ct);
        await using var ad=await worker.BeginTransactionAsync(ct);
        await PostCollectionPostgres.Sql(worker,"set local role adlog_storage_worker",ct);
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(12));
        var awaitingAd=ShortEventWriter.WriteAsync(worker,ad,[row with { PacketId=packet,PacketOrdinal=0 }],deadline.Token);
        try {
            await using var wait=new NpgsqlCommand("""
                select exists(select 1 from pg_stat_activity where pid=@pid and wait_event_type='Lock')
                """,admin);
            wait.Parameters.AddWithValue("pid",worker.ProcessID);
            while(!awaitingAd.IsCompleted && await wait.ExecuteScalarAsync(deadline.Token) is false)
                await Task.Delay(25,deadline.Token);
            Assert.False(awaitingAd.IsCompleted);
            await generic.CommitAsync(deadline.Token);
        } finally {
            await generic.DisposeAsync();
            await awaitingAd;
        }
        await ad.CommitAsync(ct);
        await using var proof=new NpgsqlCommand("""
            select exists(select 1 from semantic_event_source355 where id=@id)
                and (select count(*)=1 and sum(event_count)=3 from event_cold_daily where event_kind=4625)
            """,admin);
        proof.Parameters.AddWithValue("id",id);
        Assert.Equal(true,await proof.ExecuteScalarAsync(ct));
    }

    private static async Task<Guid> SeedAdReceiptAsync(NpgsqlConnection admin,JsonObject native,long sequence,CancellationToken ct)
    {
        Guid packet=Guid.NewGuid();
        var envelope=new JsonObject { ["agent_id"]=Agent.ToString(),["module_id"]="sli.windows.ad-dc",
            ["source_instance_id"]=Host.ToString(),["generation"]=Host.ToString() };
        await using(var receipt=new NpgsqlCommand("""
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                values(@agent,'sli.windows.ad-dc',@sequence,@packet,@hash,@envelope,'{"status":"committed"}');
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
                values(@packet,@envelope,jsonb_build_object('contract','sli.collection-packet.v1',
                    'header',jsonb_build_object('channel','Security','source',@source)),@rows,now());
            """,admin)) {
            receipt.Parameters.AddWithValue("sequence",sequence);
            receipt.Parameters.AddWithValue("agent",Agent);receipt.Parameters.AddWithValue("packet",packet);
            receipt.Parameters.AddWithValue("hash",Packets.Digest(envelope));receipt.Parameters.AddWithValue("source",Source);
            receipt.Parameters.AddWithValue("envelope",NpgsqlDbType.Jsonb,envelope.ToJsonString());
            receipt.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,new JsonArray(native.DeepClone()).ToJsonString());
            await receipt.ExecuteNonQueryAsync(ct);
        }
        return packet;
    }

    private static async Task InsertAsync(NpgsqlConnection db,SignedPacket signed,CancellationToken ct)
    {
        var envelope=signed.Envelope.ToJson();var payload=signed.ToJson()["payload"]!.AsObject();
        await using var insert=new NpgsqlCommand("""
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            values(@agent,@module,@sequence,@packet,@hash,@envelope,'{"status":"committed"}');
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows) values(@packet,@envelope,@payload,@rows)
            """,db);
        insert.Parameters.AddWithValue("agent",Guid.Parse(signed.Envelope.AgentId));insert.Parameters.AddWithValue("module",Module);insert.Parameters.AddWithValue("sequence",signed.Envelope.Sequence);
        insert.Parameters.AddWithValue("packet",Guid.Parse(signed.Envelope.PacketId));insert.Parameters.AddWithValue("hash",Packets.Digest(envelope));
        insert.Parameters.AddWithValue("envelope",NpgsqlDbType.Jsonb,envelope.ToJsonString());insert.Parameters.AddWithValue("payload",NpgsqlDbType.Jsonb,payload.ToJsonString());
        insert.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,EventLogValidator.Validate(signed.Envelope,payload,Source).ToJsonString());await insert.ExecuteNonQueryAsync(ct);
    }

    private static async Task SeedAsync(NpgsqlConnection db,string archive,CancellationToken ct)
    {
        await using(var seed=new NpgsqlCommand("""
            insert into servers(domain_id,hostname,fqdn,role) select id,@source,@source,'domain_controller' from domains where fqdn='example.test';
            insert into log_sources(name) values('Security'),('System'),('Application') on conflict do nothing;
            """,db)) {
            seed.Parameters.AddWithValue("source",Source);await seed.ExecuteNonQueryAsync(ct);
        }
        await SeedAgentAsync(db,Agent,"Security",ct);
        var record=new DirectRuntimeRecord("v2","storage-v2-fresh-bootstrap/v1",new string('a',64),archive,
            new JsonObject{["kind"]="fresh-event-store",["version"]=1},"synthetic",DateTime.UtcNow.AddMinutes(-1),DateTime.UtcNow.AddHours(1),null,"");
        await using var authorization=new NpgsqlCommand("""
            insert into storage_v2_runtime_authorizations(route,authority,preflight_digest,authorization_digest,archive_root,evidence,authorized_by,authorized_at,expires_at)
            values('v2',@authority,@preflight,@digest,@archive,@evidence,'synthetic',@at,@expires)
            """,db);
        authorization.Parameters.AddWithValue("authority",record.Authority);authorization.Parameters.AddWithValue("preflight",record.PreflightDigest);
        authorization.Parameters.AddWithValue("digest",DirectRuntimeAuthorization.Digest(record));authorization.Parameters.AddWithValue("archive",archive);
        authorization.Parameters.AddWithValue("evidence",NpgsqlDbType.Jsonb,record.Evidence.ToJsonString());authorization.Parameters.AddWithValue("at",record.AuthorizedAt);authorization.Parameters.AddWithValue("expires",record.ExpiresAt);
        await authorization.ExecuteNonQueryAsync(ct);
    }

    private static async Task SeedAgentAsync(NpgsqlConnection db,Guid agent,string channel,CancellationToken ct)
    {
        await using var seed=new NpgsqlCommand("""
            insert into sli_agents(id,host_id,key_fingerprint,assigned_modules,policy_revision)
            values(@agent,@host,repeat('a',64),'[{"module_id":"sli.windows-eventlog","enabled":true}]',1);
            insert into sli_agent_module_bindings(agent_id,module_id,source_instance_id,source_name,channel,module_version,policy_revision)
            values(@agent,'sli.windows-eventlog',@instance,@source,@channel,'1.0.0','1');
            """,db);
        seed.Parameters.AddWithValue("source",Source);seed.Parameters.AddWithValue("agent",agent);seed.Parameters.AddWithValue("host",agent==Agent?Host:Guid.NewGuid());
        seed.Parameters.AddWithValue("instance",Host.ToString("D"));seed.Parameters.AddWithValue("channel",channel);await seed.ExecuteNonQueryAsync(ct);
    }

    private static async Task<AgentIdentity> LockAgentAsync(NpgsqlConnection db,NpgsqlTransaction tx,Guid agent,CancellationToken ct)
    {
        await using var command=new NpgsqlCommand("select id,host_id,key_fingerprint,status from sli_agents where id=@agent for no key update",db,tx);
        command.Parameters.AddWithValue("agent",agent);await using var reader=await command.ExecuteReaderAsync(ct);Assert.True(await reader.ReadAsync(ct));
        return new(reader.GetGuid(0),reader.GetGuid(1),reader.GetString(2),reader.GetString(3));
    }
}
