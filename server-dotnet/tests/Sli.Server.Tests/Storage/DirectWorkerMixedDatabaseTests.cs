using System.Text.Json.Nodes;
using System.Runtime.CompilerServices;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Sli.Server.Storage.Direct;
using Sli.Server.Agents.Consumer;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

[Collection("Semantic producer environment")]
public class DirectWorkerMixedDatabaseTests
{
    private static readonly Guid Agent = Guid.Parse("85eea031-26b1-47a6-97b7-05c14593796c");
    private static readonly Guid Host = Guid.Parse("925a2af5-6c59-4169-a53e-c9c7d965c686");
    private static readonly Guid Packet = Guid.Parse("ba9b4f67-6a9c-400c-9e21-c3036e5b47d7");
    internal const string Name = "dc-sv2-603d08a32d69";
    private static string Vector([CallerFilePath] string path="")
    {
        for(var dir=new FileInfo(path).Directory;dir is not null;dir=dir.Parent) {
            var file=Path.Combine(dir.FullName,"agent-dotnet","tests","vectors","ad-dc-scenarios.json");
            if(File.Exists(file)) return file;
        }
        throw new FileNotFoundException();
    }
    internal static (JsonObject Envelope,JsonObject Packet,JsonArray Rows) Sample()
    {
        var scenario=JsonNode.Parse(File.ReadAllBytes(Vector()))!.AsArray().OfType<JsonObject>().Single(x=>x["name"]!.GetValue<string>()=="security-initial-window-all");
        var step=scenario["steps"]![0]!; var expected=step["expected"]!; string old=scenario["host_id"]!.GetValue<string>();
        var payload=JsonNode.Parse(expected["payload_canonical"]!.GetValue<string>().Replace(old,Host.ToString("D"),StringComparison.Ordinal).Replace("fixture-dc",Name,StringComparison.Ordinal))!.AsObject();
        string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>1</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00.1234575Z'/><Channel>Security</Channel><Computer>{Name}</Computer></System><EventData><Data Name='LogonType'>3</Data></EventData></Event>";
        payload["records"]![0]!["payload"]=EventXml.Parse(xml,Name,"fixture-endpoint","Security");
        var before=JsonNode.Parse(expected["cursor_before"]!.ToJsonString().Replace(old,Host.ToString("D"),StringComparison.Ordinal));
        var after=JsonNode.Parse(expected["cursor_after"]!.ToJsonString().Replace(old,Host.ToString("D"),StringComparison.Ordinal));
        var env=new Envelope(Packet.ToString("D"),Agent.ToString("D"),Host.ToString("D"),"sli.windows.ad-dc","1.0.0","1","ad-dc",Host.ToString("D"),1,
            Cursor.FromJson(before),Cursor.FromJson(after),CollectionPacket.Contract,Packets.Digest(payload),1,CanonicalJson.Length(payload),
            step["now"]!.GetValue<string>(),"not_proven",0,0);
        var rows=AgentAdDcValidator.Validate(env,payload,null,Name);
        return (env.ToJson(),payload,rows);
    }
    [Fact]
    public async Task Mixed_batch_atomic_publication_replay_and_tampering_pending()
    {
        using var environment=new Sli.Server.Tests.Semantic.SemanticProducerPostgresTests.Admission(mode:null);
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var monitor=new NpgsqlConnection(fixture.Pg.ConnectionString);
        await monitor.OpenAsync(ct);await SeedAsync(monitor,fixture.Pg.Root,ct);
        await using var db=new NpgsqlConnection(fixture.Dsn("adlog_user"));await db.OpenAsync(ct);
        Guid supported=Guid.Parse("d30a8249-464c-4c53-9732-d653fbe134ec"), unsupported=Guid.Parse("2b719fee-903b-4cb3-9ef4-2a4a4edee662");
        (DateTime Received,Guid Packet) after=(DateTime.UnixEpoch,Guid.Empty);
        var sample=Sample();
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            for(int i=0;i<2;i++) {
                var payload=(JsonObject)sample.Packet.DeepClone();
                string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}'/><EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><EventRecordID>6</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00.1234575Z'/><Execution ProcessID='4' ThreadID='8'/><Channel>Security</Channel><Computer>{Name}</Computer></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-100000001-200000002-300000003-1101</Data><Data Name='SubjectUserName'>operator</Data><Data Name='SubjectDomainName'>EXAMPLE</Data><Data Name='SubjectLogonId'>0x123</Data><Data Name='TargetUserSid'>S-1-5-21-100000001-200000002-300000003-1102</Data><Data Name='TargetUserName'>alice</Data><Data Name='TargetDomainName'>EXAMPLE</Data><Data Name='TargetLogonId'>0x456</Data><Data Name='LogonType'>3</Data><Data Name='IpAddress'>192.0.2.55</Data><Data Name='WorkstationName'>ws01</Data><Data Name='ProcessName'>C:\\Windows\\System32\\lsass.exe</Data><Data Name='ProcessId'>0x2a</Data><Data Name='LogonProcessName'>User32</Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='IpPort'>49152</Data><Data Name='ElevatedToken'>%%1842</Data><Data Name='ImpersonationLevel'>%%1833</Data></EventData></Event>";
                xml=xml.Replace("</EventData>","<Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='NetworkAccountName'>-</Data><Data Name='NetworkAccountDomain'>-</Data></EventData>");
                payload["records"]![0]!["payload"]=EventXml.Parse(xml,Name,"fixture-endpoint","Security");
                var second=xml.Replace("<EventID>4624</EventID>","<EventID>4625</EventID>")
                    .Replace("<EventRecordID>6</EventRecordID>","<EventRecordID>7</EventRecordID>")
                    .Replace("00:00:00.1234575Z","00:00:01.0000005Z");
                foreach(var field in new[]{"SubjectUserSid","SubjectUserName","SubjectDomainName","SubjectLogonId"}) {
                    var start=second.IndexOf("<Data Name='"+field+"'>",StringComparison.Ordinal);
                    var end=second.IndexOf("</Data>",start,StringComparison.Ordinal)+"</Data>".Length;
                    second=second.Remove(start,end-start);
                }
                var third=second.Replace("<EventID>4625</EventID>","<EventID>4634</EventID>").Replace("<EventRecordID>7</EventRecordID>","<EventRecordID>8</EventRecordID>");
                second=second.Replace("</EventData>","<Data Name='Status'>0xc000006d</Data><Data Name='SubStatus'>0xc000006a</Data><Data Name='FailureReason'>%%2313</Data></EventData>");

                payload["records"]!.AsArray().Add(new JsonObject { ["format"]="event_xml",["record_id"]=7,["payload"]=EventXml.Parse(second,Name,"fixture-endpoint","Security") });
                payload["records"]!.AsArray().Add(new JsonObject { ["format"]="event_xml",["record_id"]=8,["payload"]=EventXml.Parse(third,Name,"fixture-endpoint","Security") });
                payload["records"]![0]!["record_id"]=6;payload["header"]!["cursor"]!["last_record_id"]=8;
                payload["header"]!["record_id_range"]!["first"]=6;payload["header"]!["record_id_range"]!["last"]=8;
                var envelope=(JsonObject)sample.Envelope.DeepClone();Guid id=i==0?supported:unsupported;
                envelope["packet_id"]=id.ToString("D");envelope["sequence"]=i+14;
                var state=JsonNode.Parse(envelope["cursor_after"]!["token"]!.GetValue<string>())!.AsObject();
                state["channels"]!["Security"]!["record_id"]=8;
                state["channels"]!["Security"]!["bookmark"]=state["channels"]!["Security"]!["bookmark"]!.GetValue<string>().Replace("RecordId='1'","RecordId='8'",StringComparison.Ordinal);
                envelope["cursor_after"]!["token"]=CanonicalJson.Serialize(state);
                envelope["record_count"]=3;envelope["payload_sha256"]=Packets.Digest(payload);envelope["payload_bytes"]=CanonicalJson.Length(payload);
                var rows=AgentAdDcValidator.Validate(Envelope.Parse(envelope),payload,null,Name);
                if(i==1)rows[2]!["event_id"]=6274; // Corrupt inbox rows after signed packet admission.
                await using var insert=new NpgsqlCommand("""
                    insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                    values(@agent,'sli.windows.ad-dc',@sequence,@packet,@hash,@envelope,'{"status":"committed"}'::jsonb);
                    insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at) values(@packet,@envelope,@payload,@rows,@received)
                    """,db,tx);
                insert.Parameters.AddWithValue("agent",Agent);insert.Parameters.AddWithValue("sequence",(long)i+14);insert.Parameters.AddWithValue("packet",id);
                insert.Parameters.AddWithValue("hash",Packets.Digest(envelope));insert.Parameters.AddWithValue("envelope",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(envelope));
                insert.Parameters.AddWithValue("payload",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(payload));insert.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(rows));
                insert.Parameters.AddWithValue("received",DateTime.UnixEpoch.AddSeconds(i+1));
                await insert.ExecuteNonQueryAsync(ct);
            }
            await tx.CommitAsync(ct);
        }
        string catalog=Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json");
        var env=new Dictionary<string,string?> { ["ADLOG_STORAGE_V2_WORKER_DSN"]=fixture.Dsn("sli_storage_login") };
        await using var runtime=DirectAdDcRuntime.TryCreate(k=>env.GetValueOrDefault(k),_=>[],catalog);Assert.NotNull(runtime);
        await using var contender=new NpgsqlConnection(fixture.Dsn("adlog_user"));await contender.OpenAsync(ct);
        await using(var hold=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))",db))Assert.Equal(true,await hold.ExecuteScalarAsync(ct));
        await using(var blocked=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))",contender))Assert.Equal(false,await blocked.ExecuteScalarAsync(ct));
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            var first=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,after,ct,runtime);
            Assert.True(first.Imported,first.PendingReason);Assert.Equal(supported,first.PacketId);await tx.RollbackAsync(ct);
            await using var stillHeld=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))",contender);Assert.Equal(false,await stillHeld.ExecuteScalarAsync(ct));
        }
        await using(var rolledBack=new NpgsqlCommand("""
            select not exists(select 1 from event_hot), not exists(select 1 from event_cold_daily),
                   not exists(select 1 from sli_agent_packet_inbox where imported_at is not null)
            """,db))
        await using(var rollbackState=await rolledBack.ExecuteReaderAsync(ct)) {
            Assert.True(await rollbackState.ReadAsync(ct));
            Assert.True(rollbackState.GetBoolean(0));Assert.True(rollbackState.GetBoolean(1));Assert.True(rollbackState.GetBoolean(2));
        }
        (DateTime Received,Guid Packet) next;
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            var replay=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,after,ct,runtime);
            Assert.True(replay.Imported,replay.PendingReason);Assert.Equal(supported,replay.PacketId);next=(replay.Received,replay.PacketId);await tx.CommitAsync(ct);
        }
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            var pending=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,next,ct,runtime);
            Assert.True(pending.Scanned);Assert.False(pending.Imported);Assert.Equal(unsupported,pending.PacketId);await tx.CommitAsync(ct);
        }
        // Observe the private reservation ledger from the owned test connection.
        await using var verify=new NpgsqlCommand("""
            select a.event_record_id,(native.doc->>'event_id')::integer,a.time_created_utc,
                   h.fields->>'ProcessName',h.outcome->>'SubStatus',
                   array(select l.link_role||'='||l.natural_key
                         from short_event_entity_links339(h.event_kind,h.actor,h.target,h.source,h.computer,h.method,h.fields) l
                         order by l.link_role,l.natural_key),
                   (select count(*) from entity_state_projection_jobs j where j.source_event_db_id=a.id),
                   i.imported_at is not null, r.representation->>'xml'=native.doc->>'xml', h.event_kind,
                   h.source_sha256=a.normalized_hash and h.event_record_id=a.event_record_id
                       and h.method#>>'{$origin,plugin_id}'='sli.windows.ad-dc'
                       and h.method#>>'{$origin,source_instance_id}'=i.envelope->>'source_instance_id'
            from sli_agent_packet_inbox i
            cross join lateral jsonb_array_elements(i.event_rows) native(doc)
            join servers s on s.hostname=@source
            join storage_v2_channel ch on ch.value=i.collection_channel
            join storage_v2_event_identity_allocations a on a.server_id=s.id and a.channel_id=ch.id
                and a.event_record_id=(native.doc->>'record_id')::bigint
                and a.time_created_utc=(native.doc->>'time_created')::timestamptz
            join event_source_representations_v2 r on r.event_id=a.id and r.normalized_hash=a.normalized_hash
            left join event_hot h on h.event_id=a.id and h.time_created_utc=a.time_created_utc
            where i.packet_id=@packet order by a.event_record_id
            """,monitor);
        verify.Parameters.AddWithValue("packet",supported);
        verify.Parameters.AddWithValue("source",Name);
        await using(var result=await verify.ExecuteReaderAsync(ct)) {
            Assert.True(await result.ReadAsync(ct));Assert.Equal(6,result.GetInt64(0));Assert.Equal(4624,result.GetInt32(1));
            Assert.Equal(new DateTime(2026,10,7,0,0,0,DateTimeKind.Utc).AddTicks(1234580),result.GetDateTime(2));
            Assert.Equal(@"C:\Windows\System32\lsass.exe",result.GetString(3));
            Assert.Equal(new[] { "actor=sid:s-1-5-21-100000001-200000002-300000003-1101",
                "context=log:security", "context=provider:microsoft-windows-security-auditing", $"recorder=server:{Name}",
                "source=ip:192.0.2.55", "source=workstation:ws01", "target=sid:s-1-5-21-100000001-200000002-300000003-1102" },
                result.GetFieldValue<string[]>(5));
            Assert.Equal(0,result.GetInt64(6));Assert.True(result.GetBoolean(7));Assert.True(result.GetBoolean(8));
            Assert.Equal(4624,result.GetInt32(9));Assert.True(result.GetBoolean(10));
            Assert.True(await result.ReadAsync(ct));Assert.Equal(7,result.GetInt64(0));Assert.Equal(4625,result.GetInt32(1));Assert.Equal(new DateTime(2026,10,7,0,0,1,DateTimeKind.Utc),result.GetDateTime(2));
            Assert.Equal("0xc000006a",result.GetString(4));
            Assert.Equal(new[] { "context=log:security", "context=provider:microsoft-windows-security-auditing", $"recorder=server:{Name}",
                "source=ip:192.0.2.55", "source=workstation:ws01", "target=sid:s-1-5-21-100000001-200000002-300000003-1102" },
                result.GetFieldValue<string[]>(5));
            Assert.Equal(0,result.GetInt64(6));Assert.True(result.GetBoolean(7));Assert.True(result.GetBoolean(8));
            Assert.Equal(4625,result.GetInt32(9));Assert.True(result.GetBoolean(10));
            // The current storage catalog leaves 4634 out of retained events.
            // Its admitted source still participates in the batch's replay identity.
            Assert.True(await result.ReadAsync(ct));Assert.Equal(8,result.GetInt64(0));Assert.Equal(4634,result.GetInt32(1));
            Assert.Equal(0,result.GetInt64(6));Assert.True(result.GetBoolean(7));Assert.True(result.GetBoolean(8));
            Assert.True(result.IsDBNull(9));Assert.False(await result.ReadAsync(ct));
        }
        await using(var pendingCheck=new NpgsqlCommand("""
            select imported_at is null,(select count(*) from event_hot),
                   (select coalesce(sum(event_count),0)::bigint from event_cold_daily)
            from sli_agent_packet_inbox where packet_id=@id
            """,db)) {
            pendingCheck.Parameters.AddWithValue("id",unsupported);
            await using var rr=await pendingCheck.ExecuteReaderAsync(ct);
            Assert.True(await rr.ReadAsync(ct));Assert.True(rr.GetBoolean(0));
            Assert.Equal(2,rr.GetInt64(1));Assert.Equal(2,rr.GetInt64(2));
        }
        await using(var reservations=new NpgsqlCommand("select count(*) from storage_v2_event_identity_allocations",monitor))
            Assert.Equal(3L,(long)(await reservations.ExecuteScalarAsync(ct))!);
        await using(var release=new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_post_collection_process'))",db))Assert.Equal(true,await release.ExecuteScalarAsync(ct));
        await using(var available=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))",contender))Assert.Equal(true,await available.ExecuteScalarAsync(ct));
        await using(var release=new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_post_collection_process'))",contender))Assert.Equal(true,await release.ExecuteScalarAsync(ct));
    }

    internal static async Task SeedAsync(NpgsqlConnection db,string archive,CancellationToken ct)
    {
        await using(var seed=new NpgsqlCommand("""
            insert into servers(domain_id,hostname,fqdn,role) select id,@source,@source,'domain_controller' from domains where fqdn='example.test';
            insert into log_sources(name) values('Security') on conflict do nothing;
            update plugin_installations_v1 set desired_activation='enabled_manual' where plugin_id='sli.ad';
            insert into sli_agents(id,host_id,key_fingerprint,assigned_modules,policy_revision) values(@agent,@host,@fp,@modules,1);
            insert into sli_agent_module_bindings(agent_id,module_id,source_instance_id,source_name,channel,module_version,policy_revision)
            values(@agent,'sli.windows.ad-dc',@instance,@source,'ad-dc','1.0.0','1');
            """,db)) {
            seed.Parameters.AddWithValue("source",Name);seed.Parameters.AddWithValue("agent",Agent);seed.Parameters.AddWithValue("host",Host);
            seed.Parameters.AddWithValue("instance",Host.ToString());seed.Parameters.AddWithValue("fp",new string('a',64));
            var config=AgentAdDcValidator.NormalizePolicy(new JsonObject{["source_name"]=Name,["connect_address"]=Name},false);
            seed.Parameters.AddWithValue("modules",NpgsqlDbType.Jsonb,new JsonArray(new JsonObject{["module_id"]=AgentAdDcValidator.Live,["enabled"]=true,["config"]=config}).ToJsonString());
            await seed.ExecuteNonQueryAsync(ct);
        }
        var record=new DirectRuntimeRecord("v2","storage-v2-fresh-bootstrap/v1",new string('a',64),archive,
            new JsonObject{["kind"]="fresh-event-store",["version"]=1},"synthetic",DateTime.UtcNow.AddMinutes(-1),DateTime.UtcNow.AddHours(1),null,"");
        await using var authorization=new NpgsqlCommand("""
            insert into storage_v2_runtime_authorizations(route,authority,preflight_digest,authorization_digest,archive_root,evidence,authorized_by,authorized_at,expires_at)
            values('v2',@authority,@preflight,@digest,@archive,@evidence,'synthetic',@at,@expires)
            """,db);
        authorization.Parameters.AddWithValue("authority",record.Authority);authorization.Parameters.AddWithValue("preflight",record.PreflightDigest);
        authorization.Parameters.AddWithValue("digest",DirectRuntimeAuthorization.Digest(record));authorization.Parameters.AddWithValue("archive",archive);
        authorization.Parameters.AddWithValue("evidence",NpgsqlDbType.Jsonb,record.Evidence.ToJsonString());
        authorization.Parameters.AddWithValue("at",record.AuthorizedAt);authorization.Parameters.AddWithValue("expires",record.ExpiresAt);
        await authorization.ExecuteNonQueryAsync(ct);
    }
}
