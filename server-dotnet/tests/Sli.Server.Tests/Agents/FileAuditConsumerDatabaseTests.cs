using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Server.Agents;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.FileAudit;
using Sli.Server.Agents.Ingress;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Tests.Reporting;
using Xunit;
using EventXml = Sli.Agent.Core.EventXml;
using FileAuditPolicy = Sli.Agent.Core.FileAuditPolicy;

namespace Sli.Server.Tests.Agents;

public class FileAuditConsumerDatabaseTests
{
    private sealed class Clock(DateTimeOffset now):TimeProvider { public override DateTimeOffset GetUtcNow()=>now; }
    private static readonly Guid Agent=Guid.Parse("00000000-0000-4000-8000-000000000227");
    // Enable the future 7a branch only inside a disposable, owned cluster.
    private static Task Enable(NpgsqlConnection db,CancellationToken ct)=>PostCollectionPostgres.Sql(db,"""
        create or replace function public.agent_module_enabled_v380(p_module text) returns boolean
        language sql stable security definer set search_path=pg_catalog,pg_temp as $$
          select p_module not in ('sli.workstations','sli.vpn-nps','sli.radius-accounting')
        $$;
        """,ct);
    private static async Task Register(NpgsqlConnection db,CancellationToken ct,string? scopeRoot=null)
    {
        var (_,_,policy)=AgentFileAuditValidatorTests.ActionPacket();
        if(scopeRoot is not null)policy.Roots[0]!["path"]=scopeRoot;
        await using var seed=new NpgsqlCommand("""
            insert into servers(id,domain_id,hostname,fqdn,role) values(900227,1,'files','files.example.test','file_server');
            insert into sli_agents(id,host_id,key_fingerprint,registration_host_name,assigned_modules)
              values(@agent,@host,repeat('a',64),'files.example.test',@assignments);
            """,db);
        seed.Parameters.AddWithValue("agent",Agent);seed.Parameters.AddWithValue("host",AgentFileAuditValidatorTests.ActionHost);
        seed.Parameters.AddWithValue("assignments",NpgsqlDbType.Jsonb,new JsonArray(new JsonObject {
            ["module_id"]="sli.file-audit",["enabled"]=true,["config"]=policy.Value.DeepClone() }).ToJsonString());
        await seed.ExecuteNonQueryAsync(ct);
    }
    private static async Task<(Guid Id,JsonObject Envelope,JsonObject Body,JsonArray Rows)> Seed(NpgsqlConnection db,CancellationToken ct,
        string operation,int kind,int sequence=1,Action<JsonObject>? change=null)
    {
        var (e,body,_)=AgentFileAuditValidatorTests.ActionPacket(operation,kind);
        change?.Invoke(body);
        e=e with { AgentId=Agent.ToString(),Sequence=sequence,PayloadSha256=Packets.Digest(body),PayloadBytes=CanonicalJson.Length(body),
            RecordCount=body["records"]!.AsArray().Count };
        var envelope=e.ToJson();var rows=new JsonArray(body["records"]!.AsArray().Select(r=>r!["payload"]!.DeepClone()).ToArray());
        var id=Guid.Parse(e.PacketId);
        await using var seed=new NpgsqlCommand("""
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
              values(@agent,'sli.file-audit',@sequence,@packet,@hash,@envelope,@receipt);
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows) values(@packet,@envelope,@body,@rows);
            """,db);
        seed.Parameters.AddWithValue("agent",Agent);seed.Parameters.AddWithValue("sequence",sequence);seed.Parameters.AddWithValue("packet",id);
        seed.Parameters.AddWithValue("hash",Packets.Digest(envelope));seed.Parameters.AddWithValue("envelope",NpgsqlDbType.Jsonb,envelope.ToJsonString());
        seed.Parameters.AddWithValue("receipt",NpgsqlDbType.Jsonb,AgentReceipt.Make(e,"committed",null,DateTimeOffset.Parse(e.ObservedAtUtc)).ToJsonString());
        seed.Parameters.AddWithValue("body",NpgsqlDbType.Jsonb,body.ToJsonString());seed.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,rows.ToJsonString());
        await seed.ExecuteNonQueryAsync(ct);return(id,envelope,body,rows);
    }
    private static async Task<long> Number(NpgsqlConnection db,string sql,CancellationToken ct)
    { await using var cmd=new NpgsqlCommand(sql,db);return Convert.ToInt64(await cmd.ExecuteScalarAsync(ct)); }
    private static async Task Write(NpgsqlConnection db,Guid packet,JsonArray rows,CancellationToken ct)
    {
        await using var cmd=new NpgsqlCommand("select write_file_actions389(@packet,@rows)",db);
        cmd.Parameters.AddWithValue("packet",packet);cmd.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,rows.ToJsonString());
        await cmd.ExecuteNonQueryAsync(ct);
    }

    [Fact]
    public async Task First_check_result_is_accepted_without_authorizing_file_events()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 410);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await Register(owner, ct);
        await PostCollectionPostgres.Sql(owner, "update sli_agents set policy_revision=3,assigned_modules='[]'", ct);

        var (envelope, packet, policy) = AgentFileAuditValidatorTests.ActionPacket("permissions", 4670);
        var now = Iso8601.ParseUtc(envelope.ObservedAtUtc);
        const string commandId = "first-file-check";
        var identity = new AgentIdentity(Agent, AgentFileAuditValidatorTests.ActionHost, new string('a', 64), "active");
        var principal = new Principal("session", 1, "admin");
        var access = new CapabilityDecisionSet(true, new HashSet<string>(), new HashSet<string>(), [],
            new Dictionary<string, System.Text.Json.JsonElement>());
        var control = new FileAuditControlService(new AgentControlAudit());
        var ingest = new FileAuditIngestService(null!);
        await using var app = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await app.OpenAsync(ct);

        await using (var tx = await app.BeginTransactionAsync(ct))
        {
            var queued = await control.Enqueue(app, tx, new JsonObject {
                ["agent_id"] = Agent.ToString(), ["expected_revision"] = 3, ["config"] = policy.Value.DeepClone(),
                ["command"] = new JsonObject {
                    ["contract_id"] = "sli.file-audit.audit-command.v1", ["command_id"] = commandId,
                    ["action"] = "check", ["policy_revision"] = "4", ["collection_scope_ids"] = new JsonArray("scope:files")
                }
            }, principal, access, ct);
            Assert.Equal("pending", queued.GetProperty("state").GetString());
            await tx.CommitAsync(ct);
        }

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert = new CertificateRequest("CN=example.test", key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
        packet["context"]!["policy_revision"] = "4";
        var signed = Packets.Make(new EcdsaPacketSigner(key), Agent.ToString(), 1,
            new Sample("sli.file-audit", envelope.SourceInstanceId, "Security", envelope.Generation,
                envelope.CursorBefore, envelope.CursorAfter, packet, PolicyRevision: "4",
                ContinuityState: "not_proven", FilteredCount: 0, LostCount: 0), now);
        var clock = new Clock(now);
        var events = new AgentPacketService(clock,
            new AgentInboxLimits(4096,268435456,32768,2147483648,65536,4294967296,17179869184),
            new AgentIngressDiagnostics(fixture.Pg.Root, NullLogger<AgentIngressDiagnostics>.Instance, clock));
        var report = ReportForRoot(policy, "directory", now, commandId, "4", "check");

        await using (var tx = await app.BeginTransactionAsync(ct))
        {
            Assert.False(await AgentPolicyAssignments.FilePermissionsAllowedAsync(app, tx, Agent, "4", false, ct));
            var accepted = await ingest.Ingest(app, tx, identity, report, ct, () => new MemoryStream());
            Assert.Equal("accepted", accepted["status"]!.ToString());
            var replay = await ingest.Ingest(app, tx, identity, report, ct, () => new MemoryStream());
            Assert.Equal("accepted", replay["status"]!.ToString());

            var forged = (JsonObject)report.DeepClone();
            forged["command_id"] = "different-check";
            var error = await Assert.ThrowsAsync<AgentControlException>(() =>
                ingest.Ingest(app, tx, identity, forged, ct, () => new MemoryStream()));
            Assert.Equal("file_audit_result_invalid", error.Message);
            forged["command_id"] = commandId;
            forged["scopes"]![0]!["collection_scope_id"] = "scope:unrequested";
            error = await Assert.ThrowsAsync<AgentControlException>(() =>
                ingest.Ingest(app, tx, identity, forged, ct, () => new MemoryStream()));
            Assert.Equal("file_audit_result_invalid", error.Message);
            var rejected = await events.ReceiveAsync(app, tx, identity, cert, signed.ToJson(), ct);
            Assert.Equal("module_disabled", rejected["error_code"]!.ToString());
            Assert.False(await AgentPolicyAssignments.FilePermissionsAllowedAsync(app, tx, Agent, "4", true, ct));

            var status = await control.Status(app, tx, Agent.ToString(), principal, access, ct);
            Assert.Equal("verified", status.GetProperty("state").GetString());
            Assert.False(status.GetProperty("may_own_audit").GetBoolean());
            await tx.CommitAsync(ct);
        }
        Assert.Equal(1, await Number(owner, "select count(*) from sli_plugin_file_audit.audit_receipts where action='check'", ct));
        Assert.Equal(1, await Number(owner, "select count(*) from sli_plugin_file_audit.access_snapshots", ct));
        Assert.Equal(0, await Number(owner, "select count(*) from sli_agent_packet_inbox", ct));

        // A native inspection failure can return a scope result for every selected root.
        var anotherRoot = policy.Roots[0]!.DeepClone();
        anotherRoot["collection_scope_id"] = "scope:another";
        anotherRoot["path"] = @"C:\Another";
        anotherRoot["share_name"] = "Another";
        policy.Roots.Add(anotherRoot);
        await using (var tx = await app.BeginTransactionAsync(ct))
        {
            const string secondCommand = "multi-scope-check";
            await control.Enqueue(app, tx, new JsonObject {
                ["agent_id"] = Agent.ToString(), ["expected_revision"] = 4, ["config"] = policy.Value.DeepClone(),
                ["command"] = new JsonObject {
                    ["contract_id"] = "sli.file-audit.audit-command.v1", ["command_id"] = secondCommand,
                    ["action"] = "check", ["policy_revision"] = "5",
                    ["collection_scope_ids"] = new JsonArray("scope:files", "scope:another")
                }
            }, principal, access, ct);
            var failed = (JsonObject)report.DeepClone();
            failed["command_id"] = secondCommand;
            failed["policy_revision"] = "5";
            failed["snapshots"] = new JsonArray();
            failed["scopes"] = new JsonArray(new[] { "scope:files", "scope:another" }.Select(scope =>
                (JsonNode?)new JsonObject {
                    ["collection_scope_id"] = scope, ["state"] = "failed", ["reason_code"] = "native_unavailable",
                    ["required_masks"] = new JsonObject(), ["actual_masks"] = new JsonObject()
                }).ToArray());
            var stale = await Assert.ThrowsAsync<AgentControlException>(() =>
                ingest.Ingest(app, tx, identity, report, ct, () => new MemoryStream()));
            Assert.Equal("module_disabled", stale.Message);

            var firstScope = (JsonObject)failed.DeepClone();
            firstScope["scopes"]!.AsArray().RemoveAt(1);
            var firstObserved = Iso8601.Format(now.AddSeconds(1));
            firstScope["observed_at_utc"] = firstObserved;
            Assert.Equal("accepted", (await ingest.Ingest(app, tx, identity, firstScope, ct, () => new MemoryStream()))["status"]!.ToString());
            var secondScope = (JsonObject)failed.DeepClone();
            secondScope["scopes"]!.AsArray().RemoveAt(0);
            Assert.Equal("accepted", (await ingest.Ingest(app, tx, identity, secondScope, ct, () => new MemoryStream()))["status"]!.ToString());
            var status = await control.Status(app, tx, Agent.ToString(), principal, access, ct);
            Assert.Equal("failed", status.GetProperty("state").GetString());
            Assert.Equal(firstObserved, status.GetProperty("reported_at").GetString());
            Assert.Equal(2, status.GetProperty("scopes").EnumerateObject().Count());

            for (var delivery = 0; delivery < 2; delivery++)
                Assert.Equal("accepted", (await ingest.Ingest(app, tx, identity, failed, ct, () => new MemoryStream()))["status"]!.ToString());
            var verifiedScopes = (await control.Status(app, tx, Agent.ToString(), principal, access, ct)).GetProperty("scopes");
            Assert.Equal(firstObserved, verifiedScopes.GetProperty("scope:files").GetProperty("observed_at_utc").GetString());
            await tx.CommitAsync(ct);
        }
        Assert.Equal(4, await Number(owner, "select count(*) from sli_plugin_file_audit.audit_receipts where command_id='multi-scope-check'", ct));
    }

    [Fact]
    public async Task Permissions_opt_in_requires_fresh_apply_and_exact_verified_directory()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();
        await fixture.StartAsync(ct,throughVersion:405);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        await Register(owner,ct);
        await PostCollectionPostgres.Sql(owner,"""
            update sli_agents set collection_policy=jsonb_set(collection_policy,'{manage_windows_audit}','true')
            where registration_host_name='files.example.test';
            """,ct);
        var (e,body,policy)=AgentFileAuditValidatorTests.ActionPacket("permissions",4670);
        var initial=DateTimeOffset.Parse(e.ObservedAtUtc);
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert=new CertificateRequest("CN=example.test",key,HashAlgorithmName.SHA256)
            .CreateSelfSigned(initial.AddDays(-1),initial.AddDays(1));
        var service=new AgentPacketService(new Clock(initial),new AgentInboxLimits(4096,268435456,32768,2147483648,65536,4294967296,17179869184),
            new AgentIngressDiagnostics(fixture.Pg.Root,NullLogger<AgentIngressDiagnostics>.Instance,new Clock(initial)));
        var identity=new AgentIdentity(Agent,AgentFileAuditValidatorTests.ActionHost,new string('a',64),"active");
        var enroll=new FileAuditIngestService(null!);
        var control=new FileAuditControlService(new AgentControlAudit());
        var client=new AgentClientControlService(new AgentControlAudit(),new Clock(initial));
        var access=new CapabilityDecisionSet(true,new HashSet<string>(),new HashSet<string>(),[],new Dictionary<string,System.Text.Json.JsonElement>());
        var principal=new Principal("session",1,"admin");
        var signer=new EcdsaPacketSigner(key);
        JsonObject Signed(JsonObject packet,string revision,long sequence=1,Cursor? before=null,Cursor? after=null)
        {
            packet["context"]!["policy_revision"]=revision;
            var sample=new Sample("sli.file-audit",e.SourceInstanceId,"Security",e.Generation,before??e.CursorBefore,after??e.CursorAfter,packet,
                PolicyRevision:revision,ContinuityState:"not_proven",FilteredCount:0,LostCount:0);
            return Packets.Make(signer,Agent.ToString(),sequence,sample,initial).ToJson();
        }
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await app.OpenAsync(ct);
        await using(var tx=await app.BeginTransactionAsync(ct))
        {
            Assert.Equal("module_disabled",(await service.ReceiveAsync(app,tx,identity,cert,Signed(body,"1"),ct))["error_code"]!.ToString());
            Assert.False(await AgentPolicyAssignments.FilePermissionsAllowedAsync(app,tx,Agent,null,false,ct));
            var command=new JsonObject { ["contract_id"]="sli.file-audit.audit-command.v1",["command_id"]="explicit-apply",
                ["action"]="apply",["policy_revision"]="2",["collection_scope_ids"]=new JsonArray("scope:files") };
            await control.Enqueue(app,tx,new JsonObject { ["agent_id"]=Agent.ToString(),["expected_revision"]=1,
                ["config"]=policy.Value.DeepClone(),["command"]=command,["enabled"]=true,["activate_collection"]=true },
                principal,access,ct);
            Assert.True(await AgentPolicyAssignments.FilePermissionsAllowedAsync(app,tx,Agent,"2",false,ct));
            var pending=await client.CheckInAsync(app,tx,identity,ct);
            Assert.Equal("apply",(string?)pending["file_audit"]?["command"]?["action"]);
            Assert.Null(AgentPolicyAssignments.FindCurrent(pending["assigned_modules"]!.AsArray(),"sli.file-audit"));
            Assert.Equal("module_disabled",(await service.ReceiveAsync(app,tx,identity,cert,Signed(body,"2"),ct))["error_code"]!.ToString());
            await tx.CommitAsync(ct);
        }
        foreach(var (objectType,offset) in new[] { ("file",-2),("directory",-1) })
        {
            var report=ReportForRoot(policy,objectType,initial.AddSeconds(offset));
            await using var tx=await app.BeginTransactionAsync(ct);
            Assert.Equal("accepted",(await enroll.Ingest(app,tx,identity,report,ct,()=>new MemoryStream()))["status"]!.ToString());
            Assert.Equal(objectType=="directory",await AgentPolicyAssignments.FilePermissionsAllowedAsync(app,tx,Agent,"2",true,ct));
            var current=(await client.CheckInAsync(app,tx,identity,ct))["assigned_modules"]!.AsArray();
            Assert.Equal(objectType=="directory",AgentPolicyAssignments.FindCurrent(current,"sli.file-audit") is not null);
            await tx.CommitAsync(ct);
        }
        await using(var tx=await app.BeginTransactionAsync(ct))
        {
            Assert.Equal("module_disabled",(await service.ReceiveAsync(app,tx,identity,cert,Signed(body,"1"),ct))["error_code"]!.ToString());
            var raw=AgentFileAuditValidatorTests.ActionPacket().Packet;
            Assert.Equal("agent_file_audit_packet_invalid",(await service.ReceiveAsync(app,tx,identity,cert,Signed(raw,"2"),ct))["error_code"]!.ToString());
            Assert.Equal("committed",(await service.ReceiveAsync(app,tx,identity,cert,Signed(body,"2"),ct))["status"]!.ToString());
            var imported=await AgentWorkstationInboxConsumer.ProcessNextAsync(app,tx,null,ct);
            Assert.True(imported.Imported,imported.PendingReason);
            await tx.CommitAsync(ct);
        }
        Assert.Equal(1,await Number(owner,"select count(*) from event_cold_facts where fields->>'operation'='permissions'",ct));
        await FileAuditReportTests.CheckNativePermissionChanges(fixture, owner, Agent, e.SourceInstanceId,
            policy.Roots[0]!["path"]!.GetValue<string>(), body["records"]![0]!["payload"]!.AsObject(), ct);
        Assert.Equal(0,await Number(owner,"select count(*) from sli_agent_packet_inbox where imported_at is null and module_disabled_at is null",ct));
        await using(var tx=await app.BeginTransactionAsync(ct))
        {
            var queuedAction=body["records"]![0]!["payload"]!.DeepClone();
            queuedAction["record_id"]=11;
            var queued=CollectionPacket.Make("files.example.test","Security",e.Generation,
                new JsonObject { ["after_record_id"]=10,["last_record_id"]=11 },
                [new PacketRecord("file_action",11,queuedAction)],"not_proven",body["context"]!.AsObject(),initial);
            var after=JsonNode.Parse(e.CursorAfter.Token)!.AsObject();after["record_id"]=11;after["bookmark"]="synthetic-11";
            var receipt=await service.ReceiveAsync(app,tx,identity,cert,
                Signed(queued,"2",2,e.CursorAfter,new Cursor("bookmark",after.ToJsonString())),ct);
            Assert.True(receipt["status"]?.ToString()=="committed",receipt["error_code"]?.ToString());
            await tx.CommitAsync(ct);
        }
        await using(var lockedInbox=await owner.BeginTransactionAsync(ct))
        {
            await using var claim=new NpgsqlCommand("select packet_id from sli_agent_packet_inbox where imported_at is null for update",owner,lockedInbox);
            Assert.NotNull(await claim.ExecuteScalarAsync(ct));
            await using var tx=await app.BeginTransactionAsync(ct);
            await using var timeout=new NpgsqlCommand("set local lock_timeout='1s'",app,tx);
            await timeout.ExecuteNonQueryAsync(ct);
            var disabled=await Disable(tx,2);
            Assert.Equal(3,disabled.GetProperty("policy_revision").GetInt32());
            Assert.Equal("module_disabled",(await service.ReceiveAsync(app,tx,identity,cert,Signed(body,"2"),ct))["error_code"]!.ToString());
            Assert.Equal("module_disabled",(await service.ReceiveAsync(app,tx,identity,cert,Signed(body,"3"),ct))["error_code"]!.ToString());
            await tx.CommitAsync(ct);
            await lockedInbox.CommitAsync(ct);
        }
        await using(var tx=await app.BeginTransactionAsync(ct))
        {
            await using var write=new NpgsqlCommand("""
                select public.write_file_actions389(packet_id,event_rows)
                from sli_agent_packet_inbox where imported_at is null
                """,app,tx);
            var denied=await Assert.ThrowsAsync<PostgresException>(()=>write.ExecuteNonQueryAsync(ct));
            Assert.Equal("55000",denied.SqlState);
            Assert.Equal("module_disabled",denied.MessageText);
            await tx.RollbackAsync(ct);
        }
        await using(var tx=await app.BeginTransactionAsync(ct))
        {
            Assert.Equal(1,await AgentPolicyAssignments.MarkDisabledAsync(app,tx,16,ct));
            await tx.CommitAsync(ct);
        }
        Assert.Equal(2,await Number(owner,"select count(*) from sli_agent_receipts",ct));
        Assert.Equal(1,await Number(owner,"select count(*) from sli_agent_packet_inbox where imported_at is null and module_disabled_at is not null",ct));
        Assert.Equal(0,await Number(owner,"select count(*) from sli_agent_packet_inbox where imported_at is null and module_disabled_at is null",ct));
        Assert.Equal(2,await Number(owner,"select count(*) from sli_plugin_file_audit.audit_receipts",ct));

        await using(var tx=await app.BeginTransactionAsync(ct))
        {
            await Command(tx,3,"restore-verified","restore");
            await Report(tx,"restore-verified","4","restore",2);
            await Command(tx,4,"apply-before-ack","apply");
            Assert.Equal("apply",(await client.CheckInAsync(app,tx,identity,ct))["file_audit"]?["command"]?["action"]?.ToString());
            await tx.CommitAsync(ct);
        }
        await using(var tx=await app.BeginTransactionAsync(ct))
        {
            await Disable(tx,5);
            Assert.False((await client.CheckInAsync(app,tx,identity,ct)).ContainsKey("file_audit"));
            await Command(tx,6,"restore-after-disable","restore");
            var next=await client.CheckInAsync(app,tx,identity,ct);
            Assert.Equal("restore",(string?)next["file_audit"]?["command"]?["action"]);
            var unrelated=ReportForRoot(policy,"directory",initial.AddSeconds(3),"unrelated-command","5","apply");
            var rejected=await Assert.ThrowsAsync<AgentControlException>(()=>enroll.Ingest(app,tx,identity,unrelated,ct,()=>new MemoryStream()));
            Assert.Equal("file_audit_result_invalid",rejected.Message);
            await Report(tx,"apply-before-ack","5","apply",3);
            await Report(tx,"apply-before-ack","5","apply",3);
            foreach(var rev in new[]{"5","6","7"})
            {
                Assert.False(await AgentPolicyAssignments.FilePermissionsAllowedAsync(app,tx,Agent,rev,true,ct));
                Assert.Equal("module_disabled",(await service.ReceiveAsync(app,tx,identity,cert,Signed(body,rev),ct))["error_code"]!.ToString());
            }
            var pending=await control.Status(app,tx,Agent.ToString(),principal,access,ct);
            Assert.Equal("pending",pending.GetProperty("state").GetString());
            await Report(tx,"restore-after-disable","7","restore",4);
            var restored=await control.Status(app,tx,Agent.ToString(),principal,access,ct);
            Assert.Equal("verified",restored.GetProperty("state").GetString());
            Assert.False(restored.GetProperty("may_own_audit").GetBoolean());
            await tx.CommitAsync(ct);
        }
        Assert.Equal(2,await Number(owner,"select count(*) from sli_agent_receipts",ct));
        Assert.Equal(1,await Number(owner,"select count(*) from event_cold_facts where fields->>'operation'='permissions'",ct));
        Assert.Equal(2,await Number(owner,"select count(*) from sli_plugin_file_audit.audit_receipts where command_id<>'explicit-apply'",ct));
        Assert.Equal(0,await Number(owner,"select count(*) from sli_plugin_file_audit.audit_receipts where command_id='apply-before-ack'",ct));

        var migration=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/405_file_permissions_opt_in.sql");
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration,".rollback.sql"),null,ct);
        Assert.Equal(404,await Number(owner,"select max(version) from schema_migrations",ct));
        Assert.Equal(2,await Number(owner,"""
            select count(*) from schema_migrations
            where (version,name) in ((403,'password_checkpoint_proof'),(404,'password_live_recovery'))
            """,ct));
        Assert.Equal(1,await Number(owner,"""
            select 1 where to_regprocedure('public.password_checkpoint_native_cost403(jsonb,jsonb,bytea,text,text[])') is not null
                and to_regprocedure('public.password_parked_history404(bytea,text)') is not null
            """,ct));
        Assert.Equal(1,await Number(owner,"select count(*) from event_cold_facts where fields->>'operation'='permissions'",ct));
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        Assert.Equal(405,await Number(owner,"select max(version) from schema_migrations",ct));
        await using(var tx=await app.BeginTransactionAsync(ct))
        {
            Assert.False(await AgentPolicyAssignments.FilePermissionsAllowedAsync(app,tx,Agent,null,true,ct));
            await tx.CommitAsync(ct);
        }

        Task<System.Text.Json.JsonElement> Disable(NpgsqlTransaction tx,int revision)=>
            control.Enqueue(app,tx,new JsonObject { ["agent_id"]=Agent.ToString(),["expected_revision"]=revision,["enabled"]=false },
                principal,access,ct);

        async Task Command(NpgsqlTransaction tx,int revision,string commandId,string action)
        {
            var command=new JsonObject { ["contract_id"]="sli.file-audit.audit-command.v1",["command_id"]=commandId,
                ["action"]=action,["policy_revision"]=(revision+1).ToString(),["collection_scope_ids"]=new JsonArray("scope:files") };
            var request=new JsonObject { ["agent_id"]=Agent.ToString(),["expected_revision"]=revision,
                ["config"]=policy.Value.DeepClone(),["command"]=command };
            if(action=="apply") { request["enabled"]=true; request["activate_collection"]=true; }
            await control.Enqueue(app,tx,request,principal,access,ct);
        }

        async Task Report(NpgsqlTransaction tx,string commandId,string revision,string action,int seconds)
        {
            var report=ReportForRoot(policy,"directory",initial.AddSeconds(seconds),commandId,revision,action);
            Assert.Equal("accepted",(await enroll.Ingest(app,tx,identity,report,ct,()=>new MemoryStream()))["status"]!.ToString());
        }
    }

        private static JsonObject ReportForRoot(FileAuditPolicy policy,string type,DateTimeOffset observed,
            string commandId="explicit-apply",string revision="2",string action="apply")
        {
            var masks=new JsonObject(policy.RequiredMasks().Select(x=>
                new KeyValuePair<string,JsonNode?>(x.Key,JsonValue.Create(x.Value))));
            var observation=Iso8601.Format(observed);
            var snapshot=new JsonObject {
                ["contract_id"]="sli.file-audit.inventory.v1",["collection_scope_id"]="scope:files",["policy_revision"]=revision,
                ["observed_at_utc"]=observation,["scan_id"]=AuthAudit.Uuid5(commandId+observation).ToString(),["page_number"]=0,
                ["has_more"]=false,["completeness"]="complete",["unread_objects"]=0,
                ["share"]=new JsonObject { ["name"]="Files",["path"]=@"C:\Files",["dacl"]="",["complete"]=true },
                ["local_groups"]=new JsonObject { ["complete"]=true,["groups"]=new JsonArray() },
                ["objects"]=new JsonArray(new JsonObject { ["path"]=@"C:\Files",["object_id"]="fixture",
                    ["object_type"]=type,["owner_sid"]="S-1-5-18",["dacl"]="",["sacl"]="",
                    ["sacl_protected"]=false,["sacl_missing"]=false })
            };
            string digest=Packets.Digest(snapshot);
            snapshot["snapshot_sha256"]=digest;
            snapshot["snapshot_id"]=AuthAudit.Uuid5(commandId+digest).ToString();
            return new JsonObject { ["contract_id"]="sli.file-audit.audit-result.v1",["command_id"]=commandId,["action"]=action,
                ["policy_revision"]=revision,["observed_at_utc"]=observation,["ownership_remaining"]=action=="apply",["snapshots"]=new JsonArray(snapshot),
                ["scopes"]=new JsonArray(new JsonObject { ["collection_scope_id"]="scope:files",["state"]="verified",["reason_code"]="ok",
                    ["required_masks"]=masks,["actual_masks"]=masks.DeepClone() }) };
        }

    [Fact]
    public async Task Signed_folded_packet_keeps_signature_identity_scope_and_duplicate_checks()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:402);
        await using var owner=new NpgsqlConnection(fixture.Pg.ConnectionString);await owner.OpenAsync(ct);
        await Register(owner,ct,@"C:\ΑΡΧΕΙΟΣ");
        var (e,writePacket,_)=AgentFileAuditValidatorTests.ActionPacket();
        var (_,deletePacket,_)=AgentFileAuditValidatorTests.ActionPacket("delete",4660);
        var (_,permissionsPacket,_)=AgentFileAuditValidatorTests.ActionPacket("permissions",4670);
        var write=writePacket["records"]![0]!["payload"]!;
        var delete=deletePacket["records"]![0]!["payload"]!;
        var permissions=permissionsPacket["records"]![0]!["payload"]!;
        write["path"]=@"C:\αρχειος\пример-🚀.txt";
        delete["record_id"]=11;
        delete["path"]=@"C:\αρχειος\удалённый.txt";
        delete["minute_utc"]="2026-09-30T01:02:00Z";
        delete["time_created"]="2026-09-30T01:02:03Z";
        delete["first_seen_utc"]="2026-09-30T01:02:03Z";
        delete["last_seen_utc"]="2026-09-30T01:02:58Z";
        permissions["record_id"]=12;
        permissions["path"]=@"C:\αρχειος\каталог";
        var now=DateTimeOffset.Parse(e.ObservedAtUtc);var clock=new Clock(now);
        var body=CollectionPacket.Make("files.example.test","Security",e.Generation,
            new JsonObject { ["after_record_id"]=null,["last_record_id"]=12 },
            [new PacketRecord("file_action",10,write),new PacketRecord("file_action",11,delete),
                new PacketRecord("file_action",12,permissions)],
            "not_proven",writePacket["context"]!.AsObject(),now);
        var after=JsonNode.Parse(e.CursorAfter.Token)!.AsObject();after["record_id"]=12;
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert=new CertificateRequest("CN=example.test",key,HashAlgorithmName.SHA256).CreateSelfSigned(now.AddDays(-1),now.AddDays(1));
        var sample=new Sample("sli.file-audit",e.SourceInstanceId,"Security",e.Generation,e.CursorBefore,new Cursor("bookmark",after.ToJsonString()),body,
            PolicyRevision:"1",ContinuityState:"not_proven",FilteredCount:0,LostCount:0);
        var signed=Packets.Make(new EcdsaPacketSigner(key),Agent.ToString(),1,sample,now).ToJson();
        var service=new AgentPacketService(clock,new AgentInboxLimits(4096,268435456,32768,2147483648,65536,4294967296,17179869184),
            new AgentIngressDiagnostics(fixture.Pg.Root,NullLogger<AgentIngressDiagnostics>.Instance,clock));
        var identity=new AgentIdentity(Agent,AgentFileAuditValidatorTests.ActionHost,new string('a',64),"active");
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user"));await app.OpenAsync(ct);
        await using(var tx=await app.BeginTransactionAsync(ct)) {
            var changed=(JsonObject)signed.DeepClone();changed["payload"]!["records"]![0]!["payload"]!["count"]=8;
            await Assert.ThrowsAsync<ProtocolException>(()=>service.ReceiveAsync(app,tx,identity,cert,changed,ct));
            Assert.Equal("module_disabled",(await service.ReceiveAsync(app,tx,identity,cert,signed,ct))["error_code"]!.GetValue<string>());
            await tx.CommitAsync(ct);
        }
        Assert.Equal(0,await Number(owner,"select count(*) from sli_agent_packet_inbox",ct));
        Assert.Equal(0,await Number(owner,"select count(*) from event_hot",ct));
        await Enable(owner,ct);
        await using(var tx=await app.BeginTransactionAsync(ct)) {
            var wrong=identity with { Id=Guid.NewGuid() };
            Assert.Equal("agent_identity_mismatch",(await service.ReceiveAsync(app,tx,wrong,cert,signed,ct))["error_code"]!.GetValue<string>());
            Assert.Equal("committed",(await service.ReceiveAsync(app,tx,identity,cert,signed,ct))["status"]!.GetValue<string>());
            await tx.CommitAsync(ct);
        }
        await using(var tx=await app.BeginTransactionAsync(ct)) {
            var step=await AgentWorkstationInboxConsumer.ProcessNextAsync(app,tx,null,ct);
            Assert.True(step.Imported,step.PendingReason+"\n"+(step.Imported?"":await fixture.Pg.DiagnosticsAsync(ct)));
            await tx.CommitAsync(ct);
        }
        await using(var tx=await app.BeginTransactionAsync(ct)) {
            Assert.Equal("duplicate",(await service.ReceiveAsync(app,tx,identity,cert,signed,ct))["status"]!.GetValue<string>());
            Assert.False((await AgentWorkstationInboxConsumer.ProcessNextAsync(app,tx,null,ct)).Scanned);
            await tx.CommitAsync(ct);
        }
        var cleared = EventXml.Parse("""
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
              <Provider Name="Microsoft-Windows-Eventlog"/><EventID>1102</EventID><EventRecordID>13</EventRecordID>
              <TimeCreated SystemTime="2026-09-30T01:02:59Z"/><Channel>Security</Channel>
            </System><EventData/></Event>
            ""","files.example.test","localhost","Security");
        var gapBody=CollectionPacket.Make("files.example.test","Security",e.Generation,
            new JsonObject { ["after_record_id"]=12,["last_record_id"]=13 },
            [new PacketRecord("event_xml",13,cleared)],"not_proven",
            new JsonObject { ["policy_revision"]="1",["filtered_count"]=0,["lost_count"]=null,["read_error"]="file_audit_journal_gap" },now);
        var gapAfter=(JsonObject)after.DeepClone();gapAfter["record_id"]=13;gapAfter["bookmark"]="after-clear";
        var gap=new Sample("sli.file-audit",e.SourceInstanceId,"Security",e.Generation,sample.CursorAfter,
            new Cursor("bookmark",gapAfter.ToJsonString()),gapBody,PolicyRevision:"1",FilteredCount:0,LostCount:null,ContinuityState:"gap");
        var signedGap=Packets.Make(new EcdsaPacketSigner(key),Agent.ToString(),2,gap,now).ToJson();
        await using(var tx=await app.BeginTransactionAsync(ct)) {
            Assert.Equal("committed",(await service.ReceiveAsync(app,tx,identity,cert,signedGap,ct))["status"]!.GetValue<string>());
            var step=await AgentWorkstationInboxConsumer.ProcessNextAsync(app,tx,null,ct);
            Assert.True(step.Imported,step.PendingReason);
            await tx.CommitAsync(ct);
        }
        Assert.Equal(1,await Number(owner,"select count(*) from sli_agent_packet_inbox where imported_at is not null and event_rows->0->>'event_id'='1102'",ct));
        Assert.Equal(3,await Number(owner,"select count(*) from event_hot",ct));
        Assert.Equal(2,await Number(owner,"select count(distinct (time_created_utc at time zone 'UTC')::date) from event_hot",ct));
        Assert.Equal(1,await Number(owner,"select count(*) from event_cold_facts where fields->>'operation'='delete'",ct));
        Assert.Equal(1,await Number(owner,"select count(*) from event_cold_facts where fields->>'operation'='permissions'",ct));
        Assert.Equal(7,await Number(owner,"select event_count from event_cold_daily",ct));
        Assert.Equal(0,await Number(owner,"select count(*) from file_action_projection389",ct));
        Assert.Equal(0,await Number(owner,"""
            select count(*) from unnest(array['adlog_user','adlog_storage_worker']) names(role_name)
            where has_table_privilege(role_name,'public.file_action_projection389','SELECT,INSERT,UPDATE,DELETE')
            """,ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
    [Fact]
    public async Task Folded_actions_are_atomic_weighted_replay_safe_and_expire_independently()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:402);
        await using var owner=new NpgsqlConnection(fixture.Pg.ConnectionString);await owner.OpenAsync(ct);
        await Register(owner,ct);await Enable(owner,ct);
        foreach(var (operation,kind) in new[] { ("read",4663),("write",4663),("delete",4660),("rename",4663),("permissions",4670),("access_denied",5145) })
            await Seed(owner,ct,operation,kind,(int)await Number(owner,"select count(*)+1 from sli_agent_receipts",ct));
        var another=await Seed(owner,ct,"write",4663,7,p=> {
            var r=p["records"]![0]!["payload"]!;
            r["path"]="C:\\Files\\another.txt";r["minute_utc"]="2026-10-01T01:03:00Z";
            r["time_created"]="2026-10-01T01:03:03Z";r["first_seen_utc"]="2026-10-01T01:03:03Z";r["last_seen_utc"]="2026-10-01T01:03:58Z";
        });
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user"));await app.OpenAsync(ct);
        for(int n=0;n<7;n++) {
            await using var tx=await app.BeginTransactionAsync(ct);
            var step=await FileAuditInboxConsumer.ProcessNextAsync(app,tx,null,ct);
            Assert.True(step.Imported,step.PendingReason+"\n"+(step.Imported?"":await fixture.Pg.DiagnosticsAsync(ct)));await tx.CommitAsync(ct);
        }
        Assert.Equal(7,await Number(owner,"select count(*) from event_hot",ct));
        Assert.Equal(3,await Number(owner,"select count(*) from event_cold_facts",ct));
        Assert.Equal(14,await Number(owner,"select event_count from event_cold_daily where method->>'operation'='write'",ct));
        Assert.Equal(7,await Number(owner,"select event_count from event_cold_daily where method->>'operation'='read'",ct));
        Assert.Equal(1,await Number(owner,"select count(*) from event_cold_daily where method->>'operation'='write' and first_seen_utc='2026-10-01T01:02:03Z' and last_seen_utc='2026-10-01T01:03:58Z'",ct));
        Assert.Equal(7,await Number(owner,"select count(*) from event_hot where source_sha256 is not null and method#>>'{$origin,plugin_id}'='sli.file-audit' and method#>>'{$origin,collection_scope_id}'='scope:files'",ct));
        Assert.Equal(0,await Number(owner,"select count(*) from event_hot where method ? '$file_packet' or method ? '$file_ordinal'",ct));
        await Write(app,another.Id,another.Rows,ct);
        Assert.Equal(14,await Number(owner,"select event_count from event_cold_daily where method->>'operation'='write'",ct));
        var concurrent=await Seed(owner,ct,"write",4663,8);
        await using(var second=new NpgsqlConnection(fixture.Dsn("adlog_user"))) {
            await second.OpenAsync(ct);
            await Task.WhenAll(Write(app,concurrent.Id,concurrent.Rows,ct),Write(second,concurrent.Id,concurrent.Rows,ct));
        }
        Assert.Equal(8,await Number(owner,"select count(*) from event_hot",ct));
        Assert.Equal(21,await Number(owner,"select event_count from event_cold_daily where method->>'operation'='write'",ct));
        await PostCollectionPostgres.Sql(owner,"select * from expire_short_storage_partitions342('2026-10-02T00:00:00Z','2026-09-01T00:00:00Z','2026-09-01T00:00:00Z')",ct);
        Assert.Equal(0,await Number(owner,"select count(*) from event_hot",ct));
        Assert.Equal(3,await Number(owner,"select count(*) from event_cold_facts",ct));
        await Write(app,another.Id,another.Rows,ct);
        Assert.Equal(0,await Number(owner,"select count(*) from event_hot",ct));
        Assert.Equal(21,await Number(owner,"select event_count from event_cold_daily where method->>'operation'='write'",ct));
        await PostCollectionPostgres.Sql(owner,"select * from expire_short_storage_partitions342('2026-11-01T00:00:00Z','2026-11-01T00:00:00Z','2026-11-01T00:00:00Z')",ct);
        Assert.Equal(0,await Number(owner,"select count(*) from event_cold_facts",ct));
        Assert.Equal(0,await Number(owner,"select count(*) from event_cold_daily",ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
    [Fact]
    public async Task Invalid_second_action_rolls_back_the_whole_packet_and_disabled_module_imports_nothing()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:402);
        await using var owner=new NpgsqlConnection(fixture.Pg.ConnectionString);await owner.OpenAsync(ct);await Register(owner,ct);
        var packet=await Seed(owner,ct,"write",4663);
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user"));await app.OpenAsync(ct);
        await using(var tx=await app.BeginTransactionAsync(ct)) {
            var step=await FileAuditInboxConsumer.ProcessNextAsync(app,tx,null,ct);
            Assert.False(step.Imported);Assert.Equal("module_disabled",step.PendingReason);await tx.RollbackAsync(ct);
        }
        Assert.Equal(0,await Number(owner,"select count(*) from event_hot",ct));
        await Enable(owner,ct);
        // Signed admission rows can still be corrupt in storage: the SQL gate
        // must fail closed even when called without the C# validator.
        var invalid=await Seed(owner,ct,"write",4663,2,p=> {
            var second=p["records"]![0]!.DeepClone();second["record_id"]=11;second["payload"]!["record_id"]=11;
            second["payload"]!["event_id"]=99999;p["records"]!.AsArray().Add(second);
        });
        var invalidError=await Assert.ThrowsAsync<PostgresException>(()=>Write(app,invalid.Id,invalid.Rows,ct));
        Assert.Equal("file_action_kind_invalid",invalidError.MessageText);
        JsonArray reordered=new(invalid.Rows.Reverse().Select(row=>row!.DeepClone()).ToArray());
        await using(var update=new NpgsqlCommand("update sli_agent_packet_inbox set event_rows=@rows where packet_id=@packet",owner)) {
            update.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,reordered.ToJsonString());
            update.Parameters.AddWithValue("packet",invalid.Id);
            await update.ExecuteNonQueryAsync(ct);
        }
        var orderError=await Assert.ThrowsAsync<PostgresException>(()=>Write(app,invalid.Id,reordered,ct));
        Assert.Equal("file_action_attestation_failed",orderError.MessageText);
        var samePath=await Seed(owner,ct,"rename",4663,3,p=> {
            var row=p["records"]![0]!["payload"]!;
            row["path"]=@"C:\Files\ΟΣ";
            row["old_path"]=@"C:\Files\ος";
        });
        var renameError=await Assert.ThrowsAsync<PostgresException>(()=>Write(app,samePath.Id,samePath.Rows,ct));
        Assert.Equal("file_action_scope_invalid",renameError.MessageText);
        Assert.Equal(0,await Number(owner,"select count(*) from event_hot",ct));
        Assert.Equal(0,await Number(owner,"select count(*) from event_cold_daily",ct));
        Assert.Equal(0,await Number(owner,"select count(*) from sli_agent_packet_inbox where imported_at is not null",ct));
        Assert.Equal(0,await Number(owner,"select count(*) from file_action_projection389",ct));
        // Missing stream receipt cannot become an attested file action.
        await PostCollectionPostgres.Sql(owner,"delete from sli_agent_stream_receipts",ct);
        var missingStream=await Assert.ThrowsAsync<PostgresException>(()=>Write(app,packet.Id,packet.Rows,ct));
        Assert.Equal("P0002",missingStream.SqlState);
        Assert.Equal(0,await Number(owner,"select count(*) from event_hot",ct));
    }
    [Theory]
    [InlineData("envelope")]
    [InlineData("body")]
    public async Task Stored_integrity_mismatch_is_rejected_before_file_actions_are_written(string corruptPart)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:402);
        await using var owner=await fixture.Pg.OpenAsync(ct);await Register(owner,ct);await Enable(owner,ct);
        var packet=await Seed(owner,ct,"write",4663);
        if(corruptPart=="envelope")
            await PostCollectionPostgres.Sql(owner,"update sli_agent_receipts set envelope_sha256=repeat('0',64)",ct);
        else
            await PostCollectionPostgres.Sql(owner,"update sli_agent_packet_inbox set packet=jsonb_set(packet,'{context,filtered_count}','1')",ct);
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user"));await app.OpenAsync(ct);
        var error=await Assert.ThrowsAsync<PostgresException>(()=>Write(app,packet.Id,packet.Rows,ct));
        Assert.Equal("file_action_attestation_failed",error.MessageText);
        Assert.Equal(0,await Number(owner,"select count(*) from event_hot",ct));
        Assert.Equal(0,await Number(owner,"select count(*) from event_cold_daily",ct));
        Assert.Equal(0,await Number(owner,"select count(*) from sli_agent_packet_inbox where imported_at is not null",ct));
    }
    [Fact]
    public async Task Migration_requires_388_and_rolls_back_without_deleting_facts()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:387);
        string migration=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/389_file_action_intake.sql");
        await using var db=await fixture.Pg.OpenAsync(ct);
        Assert.Equal(387,await Number(db,"select max(version) from schema_migrations",ct));
        var missing=await Assert.ThrowsAsync<InvalidOperationException>(()=>fixture.Pg.ApplyFileAsync(migration,null,ct));
        Assert.Contains("file_action_intake389_preflight",missing.Message);
        string previous=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/388_password_live_first.sql");
        await fixture.Pg.ApplyFileAsync(previous,null,ct);
        Assert.Equal(388,await Number(db,"select max(version) from schema_migrations",ct));

        const string fileDispatch="    if new.method ? '$file_packet' then return public.attest_file_action389(new); end if;\n";
        async Task<(string Definition,string Metadata)> ReadShortEventAttestation()
        {
            await using var command=new NpgsqlCommand("""
                select pg_get_functiondef(oid),jsonb_build_array(proowner::text,proacl::text)::text
                from pg_proc where oid='public.attest_short_event337()'::regprocedure
                """,db);
            await using var reader=await command.ExecuteReaderAsync(ct);
            Assert.True(await reader.ReadAsync(ct));
            return (reader.GetString(0),reader.GetString(1));
        }

        var original=await ReadShortEventAttestation();
        Assert.Contains("public.generic_short_event_proof388(",original.Definition);
        Assert.DoesNotContain(fileDispatch,original.Definition);
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        Assert.Equal(389,await Number(db,"select max(version) from schema_migrations",ct));
        var combined=await ReadShortEventAttestation();
        Assert.Contains(fileDispatch,combined.Definition);
        Assert.Equal(original.Definition,combined.Definition.Replace(fileDispatch,"",StringComparison.Ordinal));
        Assert.Equal(original.Metadata,combined.Metadata);
        await Register(db,ct);await Enable(db,ct);var packet=await Seed(db,ct,"delete",4660);await Write(db,packet.Id,packet.Rows,ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration,".rollback.sql"),null,ct);
        Assert.Equal(original,await ReadShortEventAttestation());
        Assert.Equal(1,await Number(db,"select count(*) from event_cold_facts",ct));
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        Assert.Equal(combined,await ReadShortEventAttestation());
        Assert.Equal(1,await Number(db,"select count(*) from event_cold_facts",ct));
    }
}
