using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Sli.Server.Agents.Radius;
using Sli.Server.Tests.Semantic;
using Xunit;

namespace Sli.Server.Tests.Agents;

[Collection("Semantic producer environment")]
public sealed class NativeAccountingAdmissionPostgresTests
{
    private sealed class Clock(DateTimeOffset now) : TimeProvider
    { public override DateTimeOffset GetUtcNow() => now; }

    [Fact]
    public async Task NativeAccountingClosesByDefaultAndCommitsOneScopedReceiptAndImport()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();
        await fixture.InstallAsync(ct,throughVersion:406);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString);
        await admin.OpenAsync(ct);
        const string login="sli_radius_accounting_login";
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
            """,ct);
        using var env=new SemanticProducerPostgresTests.Admission(mode:null);
        env.Set("SLI_PLUGIN_RUNTIME_DIR",null);
        env.Set("SLI_PLUGIN_LOCK_DIR",null);
        env.Set("SLI_DEPLOYMENT_MODE","native");
        env.Set("SLI_NPS_AGENT_IMPORT_ENABLED","0");
        env.Set(RadiusAccountingMode.EnabledSetting,"0");
        env.Set("CREDENTIALS_DIRECTORY",fixture.Pg.Root);
        env.Set(RadiusAccountingMode.ConfigRootSetting,Directory.GetParent(MigrationDirectory.Read(406).Single(migration => migration.Version==406).Path)!.Parent!.FullName);
        env.Set("SLI_NPS_AGENT_WORKER_DSN",fixture.Dsn(login));
        env.Set("ADLOG_DATA_DIR",fixture.Pg.Root);
        var route=JsonNode.Parse(RadiusCollectionRouteTests.Route)!.AsObject();
        route["owner_confirmed_ip"]="192.0.2.12";
        await File.WriteAllTextAsync(Path.Combine(fixture.Pg.Root,RadiusAccountingMode.RouteCredential),route.ToJsonString(),ct);
        const string source="radius-instance", subscription="vpn-radius-session-observations-nps-v1";
        var cursor=new RadiusCursor(source,"radius-accounting","windows-rpc-smb-readonly-tail-v1","fixture-generation",0,null);
        var now=new DateTimeOffset(2026,10,5,12,0,0,TimeSpan.Zero);
        var fields=Enumerable.Repeat("",66).ToArray();
        fields[0]="nps.example.test"; fields[1]="IAS"; fields[2]="10/05/2026"; fields[3]="12:00:00";
        fields[4]="4"; fields[11]="fixture-gateway"; fields[31]="1"; fields[35]="fixture-session";
        string line=string.Join(',',fields);
        var next=cursor with { ByteOffset=256,LastRecordSha256=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(line))) };
        var payload=CollectionPacket.Make(cursor.SourceId,cursor.StreamId,cursor.FileGeneration,
            new JsonObject { ["before"]=cursor.ToJson(),["start_offset"]=0,["end_offset"]=256 },
            [new("accounting_line",null,JsonValue.Create(line)!)],"complete",
            new JsonObject { ["source_timezone_id"]="N. Central Asia Standard Time",["source_utc_offset_minutes"]=420 },now);
        payload["continuity"]!["previous_generation_eof"]=false;
        var policy=NpsPolicy.Parse(NpsPolicy.Accounting,new() {
            ["source_instance_id"]=source,["initial_cursor"]=cursor.ToJson(),["subscription_id"]=subscription,
            ["accounting_directory"]=fixture.Pg.Root,["source_timezone_id"]="N. Central Asia Standard Time",["source_utc_offset_minutes"]=420
        });
        var assignments=new JsonArray(new JsonObject { ["module_id"]=NpsPolicy.Accounting,["enabled"]=true,["config"]=policy.Value });
        var agent=Guid.NewGuid(); var host=Guid.NewGuid();
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string fingerprint=Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
        using var cert=new CertificateRequest("CN=fixture.invalid",key,HashAlgorithmName.SHA256)
            .CreateSelfSigned(now.AddDays(-1),now.AddDays(1));
        await using (var seed=new NpgsqlCommand("""
            insert into sli_agents(id,host_id,key_fingerprint,assigned_modules) values(@agent,@host,@fp,@assignment)
            """,admin))
        {
            seed.Parameters.AddWithValue("agent",agent); seed.Parameters.AddWithValue("host",host);
            seed.Parameters.AddWithValue("fp",fingerprint);
            seed.Parameters.AddWithValue("assignment",NpgsqlDbType.Jsonb,assignments.ToJsonString());
            await seed.ExecuteNonQueryAsync(ct);
        }
        var packet=Packets.Make(new EcdsaPacketSigner(key),agent.ToString("D"),1,
            new Sample(NpsPolicy.Accounting,source,cursor.StreamId,host.ToString("D"),Cursor.Start("file_offset"),
                new Cursor("file_offset",CanonicalJson.Serialize(next.ToJson())),payload,LostCount:0),now);
        string signed=packet.ToCanonical();
        var clock=new Clock(now);
        var service=new AgentPacketService(clock,AgentInboxLimits.FromEnvironment(_=>null) with { FreeDiskBytes=()=>long.MaxValue },
            new AgentIngressDiagnostics(fixture.Pg.Root,NullLogger<AgentIngressDiagnostics>.Instance,clock));
        await using var api=new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await api.OpenAsync(ct);
        async Task<JsonObject> Receive(string? wire=null)
        {
            await using var tx=await api.BeginTransactionAsync(ct);
            await using var held=new NpgsqlCommand("select id from sli_agents where id=@id for no key update",api,tx);
            held.Parameters.AddWithValue("id",agent); Assert.Equal(agent,await held.ExecuteScalarAsync(ct));
            var receipt=await service.ReceiveAsync(api,tx,new Sli.Server.Agents.AgentIdentity(agent,host,fingerprint,"active"),
                cert,JsonNode.Parse(wire ?? signed)!,ct);
            await tx.CommitAsync(ct);
            return receipt;
        }
        Assert.Equal("agent_radius_accounting_paused",(await Receive())["error_code"]?.GetValue<string>());
        Assert.False(RadiusWorkerConfiguration.FromEnvironment().Enabled);
        env.Set(RadiusAccountingMode.EnabledSetting,"1");
        Assert.Equal(0,await RadiusWorkerCommand.RunAsync(["--check-native-accounting"],ct));
        Assert.Equal("agent_radius_accounting_paused",(await Receive())["error_code"]?.GetValue<string>());
        await PostCollectionPostgres.Sql(api, """
            select enabled from set_plugin_enabled_v1('sli.remote-access',true,
                (select revision from read_plugin_states_v1() where plugin_id='sli.remote-access'),'session',1,true)
            """,ct);
        var receipt=await Receive();
        Assert.True(receipt["status"]?.GetValue<string>()=="committed",receipt["error_code"]?.GetValue<string>());
        Assert.Equal("duplicate",(await Receive())["status"]?.GetValue<string>());
        var secondPayload = (JsonObject)payload.DeepClone();
        var secondBounds = secondPayload["header"]!["cursor"]!.AsObject();
        secondBounds["before"] = next.ToJson();
        secondBounds["start_offset"] = 256;
        secondBounds["end_offset"] = 512;
        var secondCursor = next with { ByteOffset=512 };
        var second = Packets.Make(new EcdsaPacketSigner(key),agent.ToString("D"),2,
            new Sample(NpsPolicy.Accounting,source,cursor.StreamId,host.ToString("D"),packet.Envelope.CursorAfter,
                new Cursor("file_offset",CanonicalJson.Serialize(secondCursor.ToJson())),secondPayload,LostCount:0),now);
        string secondWire=second.ToCanonical();

        async Task SetPlugin(bool enabled)
        {
            await using var toggle=new NpgsqlCommand("""
                select enabled from set_plugin_enabled_v1('sli.remote-access',@enabled,
                    (select revision from read_plugin_states_v1() where plugin_id='sli.remote-access'),'session',1,true)
                """,api);
            toggle.Parameters.AddWithValue("enabled",enabled);
            Assert.Equal(enabled,await toggle.ExecuteScalarAsync(ct));
        }
        await SetPlugin(false);
        var lostAcknowledgement=await Receive();
        Assert.Equal("duplicate",Receipt.Status(lostAcknowledgement));
        Assert.True(Receipt.IsDeliveryProof(packet.Envelope,lostAcknowledgement));
        var paused=await Receive(secondWire);
        Assert.Equal("retry_later",Receipt.Status(paused));
        Assert.Equal("agent_radius_accounting_paused",Receipt.ErrorCode(paused));
        Assert.False(Receipt.IsModuleDisabled(second.Envelope,paused));
        Assert.False(Receipt.IsDeliveryProof(second.Envelope,paused));
        await PostCollectionPostgres.Sql(admin, """
            with plugin as (select revision from read_plugin_states_v1() where plugin_id='sli.remote-access'),
            plan as (select revision,encode(sha256(convert_to('sli.remote-access:disable:'||revision,'UTF8')),'hex') digest from plugin)
            select component_runtime from plan cross join lateral execute_plugin_runtime_transition_v1(
                gen_random_uuid(),'disable',plan.revision,plan.digest,
                format('PLUGIN-DISABLE-SLI-REMOTE-ACCESS-R%s-%s',plan.revision,upper(substr(plan.digest,1,12))),
                'session','1')
            """,ct);
        await SetPlugin(true);

        var worker=RadiusWorkerConfiguration.FromEnvironment();
        var consumer=new RadiusInboxConsumer();
        await PostCollectionPostgres.Sql(admin,"select pg_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))",ct);
        async Task StillPending()
        {
            var held=await consumer.RunUnderProcessLockAsync(worker.WorkerDsn!,worker.Binding!,1,ct);
            Assert.Equal(1,held.Scanned);
            Assert.Equal(0,held.Imported);
            Assert.Equal(1,held.PendingReasons["agent_source_binding_changed"]);
            await using var state=new NpgsqlCommand("""
                select (select revision=7 and byte_offset=0 from acquisition_stream_cursors
                          where source_instance_id='radius-instance')
                       and (select count(*)=1 from sli_agent_packet_inbox
                          where imported_at is null and module_disabled_at is null)
                       and not exists(select 1 from core_evidence_manifests)
                       and not exists(select 1 from radius_accounting_session_observations)
                       and not exists(select 1 from acquisition_delivery_outbox)
                """,admin);
            Assert.Equal(true,await state.ExecuteScalarAsync(ct));
            Assert.Equal(0,(await consumer.RunUnderProcessLockAsync(worker.WorkerDsn!,worker.Binding!,1,ct)).Scanned);
        }
        await PostCollectionPostgres.Sql(admin, """
            update acquisition_source_instances set endpoint_identity='fqdn:nps.example.test|ipv4:192.0.2.13'
            where source_instance_id='radius-instance'
            """,ct);
        await StillPending();
        await PostCollectionPostgres.Sql(admin, """
            update acquisition_source_instances set endpoint_identity='fqdn:nps.example.test|ipv4:192.0.2.12'
            where source_instance_id='radius-instance'
            """,ct);
        var admissionMigration=Assert.Single(await fixture.RollbackAfterAsync(405,ct));
        await StillPending();
        await fixture.Pg.ApplyFileAsync(admissionMigration,null,ct);
        var imported=await consumer.RunUnderProcessLockAsync(worker.WorkerDsn!,worker.Binding!,1,ct);
        Assert.Empty(imported.PendingReasons);
        Assert.Equal(1,imported.Imported);
        Assert.Equal(0,(await consumer.RunUnderProcessLockAsync(worker.WorkerDsn!,worker.Binding!,1,ct)).Scanned);
        await using var result=new NpgsqlCommand("""
            select revision,byte_offset,(select count(*) from core_evidence_manifests),
              (select count(*) from radius_accounting_session_observations),
              (select count(*) from acquisition_delivery_outbox)
            from acquisition_stream_cursors where source_instance_id='radius-instance'
            """,admin);
        await using var rows=await result.ExecuteReaderAsync(ct);
        Assert.True(await rows.ReadAsync(ct));
        Assert.Equal(8L,rows.GetInt64(0)); Assert.Equal(256L,rows.GetInt64(1));
        for (int i=2;i<5;i++) Assert.Equal(1L,rows.GetInt64(i));
        await rows.DisposeAsync();
        Assert.Single(await fixture.RollbackAfterAsync(405,ct));
        Assert.True(Receipt.IsDeliveryProof(packet.Envelope,await Receive()));
        Assert.Equal("agent_radius_accounting_paused",Receipt.ErrorCode(await Receive(secondWire)));
        await fixture.Pg.ApplyFileAsync(admissionMigration,null,ct);
        Assert.True(Receipt.IsDeliveryProof(second.Envelope,await Receive(secondWire)));
        Assert.Equal(1L,await new NpgsqlCommand("select count(*) from radius_accounting_session_observations",admin).ExecuteScalarAsync(ct));
    }
}
