using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Certificates;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Ingress;
using Sli.Server.Agents.Consumer;
using Sli.Server.Storage.Direct;
using Xunit;

namespace Sli.Server.Tests.Agents;

[Collection("Semantic producer environment")]
public sealed partial class AdDcImportPerformanceTests(ITestOutputHelper output)
{
    internal static readonly Guid Agent = Guid.NewGuid(), Host = Guid.NewGuid();
    internal const string Source = "dc-fixture.example.test";
    private const int Blocks = 200_000;

    [Fact]
    public async Task Allocation_preserves_packet_identity_order_and_imports_shared_entities()
    {
        using var environment=new Sli.Server.Tests.Semantic.SemanticProducerPostgresTests.Admission(mode:null);
        environment.Set("Sli__Storage__ShortEventReads","false");
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString);await admin.OpenAsync(ct);
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert=new CertificateRequest("CN=synthetic",key,HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(1));
        await SeedAsync(admin,fixture.Pg.Root,cert,ct);
        var settings=new NpgsqlConnectionStringBuilder(fixture.Dsn("sli_storage_login")) {
            Options="-c enable_nestloop=off -c enable_mergejoin=off -c enable_hashjoin=on"
        };
        await using var worker=new NpgsqlDataSourceBuilder(settings.ConnectionString).Build();
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user"));await app.OpenAsync(ct);
        string catalog=Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json");
        async Task Import(Packet packet) {
            await ReceiptAsync(admin,packet,ct);
            await using var tx=await app.BeginTransactionAsync(ct);
            await ImportAsync(app,tx,worker,packet,catalog,ct);await tx.CommitAsync(ct);
        }
        await Import(Sample(1));
        var sample=Sample(1001,24);
        var prepared=DirectAdDcPacket.PrepareBatch(sample.Rows);
        long server;
        int channel;
        await using(var query=new NpgsqlCommand("select s.id,c.id from servers s cross join storage_v2_channel c where s.hostname=@source and c.value='Security'",admin)) {
            query.Parameters.AddWithValue("source",Source);await using var reader=await query.ExecuteReaderAsync(ct);
            Assert.True(await reader.ReadAsync(ct));server=reader.GetInt64(0);channel=reader.GetInt32(1);
        }
        // Observe real row insertion order, including ON CONFLICT attempts.
        await PostCollectionPostgres.Sql(admin,"""
            create table synthetic_batch_order(ordinal bigserial,kind text,id bigint);
            grant insert on synthetic_batch_order to adlog_storage_worker;
            grant usage on sequence synthetic_batch_order_ordinal_seq to adlog_storage_worker;
            create function synthetic_batch_order_trace() returns trigger language plpgsql as $$
            begin
                insert into synthetic_batch_order(kind,id) values(tg_table_name,(to_jsonb(new)->>tg_argv[0])::bigint);
                return new;
            end $$;
            create trigger synthetic_batch_order before insert on storage_v2_event_identity_allocations
                for each row execute function synthetic_batch_order_trace('event_record_id');
            create trigger synthetic_batch_order before insert on entities_v2
                for each row execute function synthetic_batch_order_trace('id');
            create trigger synthetic_batch_order before insert on entity_details_v2
                for each row execute function synthetic_batch_order_trace('entity_id');
            """,ct);
        async Task AssertWriteOrder(string table) {
            await using var query=new NpgsqlCommand("select id from synthetic_batch_order where kind=@table order by ordinal",admin);
            query.Parameters.AddWithValue("table",table);await using var reader=await query.ExecuteReaderAsync(ct);
            long previous=0;int count=0;
            while(await reader.ReadAsync(ct)) {long id=reader.GetInt64(0);Assert.True(id>previous,$"{table}: {id} after {previous}");previous=id;count++;}
            Assert.True(count>0);
        }
        await Import(sample);
        foreach(string table in new[]{"storage_v2_event_identity_allocations","entities_v2","entity_details_v2"})await AssertWriteOrder(table);
        await PostCollectionPostgres.Sql(admin,"truncate synthetic_batch_order",ct);
        await using(var ids=new NpgsqlCommand("select id from storage_v2_event_identity_allocations where server_id=@server and event_record_id between 1001 and 1024 order by event_record_id",admin)) {
            ids.Parameters.AddWithValue("server",server);await using var reader=await ids.ExecuteReaderAsync(ct);
            long previous=0;int count=0;
            while(await reader.ReadAsync(ct)) {long id=reader.GetInt64(0);Assert.True(id>previous);previous=id;count++;}
            Assert.Equal(24,count);
        }
        // Packet order must also win when it is the reverse of conflict-key order.
        var reverse=DirectAdDcPacket.PrepareBatch(Sample(2001,24).Rows).AsEnumerable().Reverse().ToArray();
        var record=new DirectRuntimeRecord("v2","storage-v2-fresh-bootstrap/v1",new string('a',64),fixture.Pg.Root,
            new JsonObject{["kind"]="fresh-event-store",["version"]=1},"synthetic",DateTime.UtcNow,DateTime.UtcNow.AddHours(1),null,"");
        var authorization=DirectRuntimeAuthorization.Validate(record with{AuthorizationDigest=DirectRuntimeAuthorization.Digest(record)},DateTime.UtcNow);
        var reservations=await DirectEventIdentityStore.ReserveBatchAsync(authorization,worker,server,reverse.Select(x=>new DirectEventRequest(channel,
            x.Row["record_id"]!.GetValue<long>(),DirectEventTime.Utc(x.Row["time_created"]!.GetValue<string>()),x.Row,x.Projection.IdentityHash)).ToArray(),ct);
        Assert.Equal(24,reservations.Count);
        for(int i=1;i<reservations.Count;i++)Assert.True(reservations[i].Id>reservations[i-1].Id);
        await AssertWriteOrder("storage_v2_event_identity_allocations");
    }

    private static IEnumerable<JsonNode> Nodes(JsonNode plan) => new[] { plan }.Concat(plan["Plans"]?.AsArray().SelectMany(p => Nodes(p!)) ?? []);

    private static async Task AssertReadbackIntegrityAsync(NpgsqlConnection db,CancellationToken ct)
    {
        var expected=new List<DirectChunkEvent>();
        var entities=new List<DirectPreparedEntity>();
        await using(var read=new NpgsqlCommand("select e.id,e.entity_type_id,e.source_core_sha256,d.source_details_sha256 from entities_v2 e join entity_details_v2 d on d.entity_id=e.id",db)) {
            await using var reader=await read.ExecuteReaderAsync(ct);
            while(await reader.ReadAsync(ct)) {
                int id=reader.GetInt32(0);
                entities.Add(new(new(id,reader.GetInt32(1),new("synthetic","synthetic","synthetic","context",false,false,new()),null,null,
                    DateTime.UnixEpoch,DateTime.UnixEpoch,reader.GetFieldValue<byte[]>(2),reader.GetFieldValue<byte[]>(3)),id));
            }
        }
        await using(var read=new NpgsqlCommand("select id,normalized_hash from storage_v2_event_identity_allocations",db)) {
            await using var reader=await read.ExecuteReaderAsync(ct);
            while(await reader.ReadAsync(ct))expected.Add(new(reader.GetInt64(0),reader.GetFieldValue<byte[]>(1),entities));
        }
        Assert.NotEmpty(expected);Assert.NotEmpty(entities);
        async Task Check(string? error,string? sql=null,IReadOnlyList<DirectChunkEvent>? batch=null) {
            await using var tx=await db.BeginTransactionAsync(ct);
            if(sql is not null) { await using var command=new NpgsqlCommand(sql,db,tx);await command.ExecuteNonQueryAsync(ct); }
            if(error is null)await DirectVerifiedChunk.VerifyBatchAsync(db,tx,batch??expected,ct);
            else Assert.Equal(error,(await Assert.ThrowsAsync<InvalidOperationException>(()=>DirectVerifiedChunk.VerifyBatchAsync(db,tx,batch??expected,ct))).Message);
            await tx.RollbackAsync(ct);
        }
        await Check(null);
        int entity=entities[0].Model.Id;
        foreach(var (table,key,column) in new[]{("entities_v2","id","source_core_sha256"),("entity_details_v2","entity_id","source_details_sha256")})
            await Check("storage_v2_chunk_hash_mismatch",$"update {table} set {column}=decode(repeat('00',32),'hex') where {key}={entity}");
        await Check("storage_v2_entity_readback_missing",$"delete from entity_details_v2 where entity_id={entity}");
        var missing=expected.ToArray();missing[0]=missing[0] with {EventId=long.MaxValue};
        await Check("storage_v2_event_readback_missing",batch:missing);
        var corrupt=expected.ToArray();corrupt[0]=corrupt[0] with {EventHash=new byte[32]};
        await Check("storage_v2_chunk_hash_mismatch",batch:corrupt);
    }

    [Fact]
    public async Task State_jobs_are_batched_and_recreated_on_replay_with_exact_candidate_readback()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString);await admin.OpenAsync(ct);
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert=new CertificateRequest("CN=synthetic",key,HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(1));
        await SeedAsync(admin,fixture.Pg.Root,cert,ct);
        using var profile=new CommandProfile(output);
        using var logging=LoggerFactory.Create(b=>b.SetMinimumLevel(LogLevel.Debug).AddProvider(profile));
        await using var appSource=new NpgsqlDataSourceBuilder(fixture.Dsn("adlog_user")).UseLoggerFactory(logging).Build();
        await using var worker=new NpgsqlDataSourceBuilder(fixture.Dsn("sli_storage_login")).UseLoggerFactory(logging).Build();
        string catalog=Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json");
        var sample=Sample(50,2,4720);await ReceiptAsync(admin,sample,ct);
        await using var db=await appSource.OpenConnectionAsync(ct);
        async Task Import() {
            await using var tx=await db.BeginTransactionAsync(ct);await ImportAsync(db,tx,worker,sample,catalog,ct);await tx.CommitAsync(ct);
        }
        profile.Enabled=true;await Import();profile.Enabled=false;
        Assert.Single(profile.Commands,x=>x.Sql.StartsWith("insert into entity_state_projection_jobs"));
        Assert.Single(profile.Commands,x=>x.Sql.StartsWith("select source_event_db_id,candidate_states"));
        var jobs=new List<(long Event,JsonArray Candidates)>();
        await using(var read=new NpgsqlCommand("select source_event_db_id,candidate_states::text from entity_state_projection_jobs order by source_event_db_id",admin)) {
            await using var reader=await read.ExecuteReaderAsync(ct);
            while(await reader.ReadAsync(ct))jobs.Add((reader.GetInt64(0),JsonNode.Parse(reader.GetString(1))!.AsArray()));
        }
        Assert.Equal(2,jobs.Count);
        await PostCollectionPostgres.Sql(admin,"delete from entity_state_projection_jobs",ct);
        await Import(); // Independently committed publication recreates caller-owned jobs on replay.
        foreach(var job in jobs) {
            await using var tx=await admin.BeginTransactionAsync(ct);
            var changed=job.Candidates.DeepClone().AsArray();changed[0]!["summary"]="synthetic changed state";
            var error=await Assert.ThrowsAsync<InvalidOperationException>(()=>DirectStateProjection.EnqueueCandidatesAsync(admin,tx,job.Event,changed,ct));
            Assert.Equal("entity_state_job_replay_conflict",error.Message);await tx.RollbackAsync(ct);
        }
        await using var count=new NpgsqlCommand("select count(*) from entity_state_projection_jobs",admin);
        Assert.Equal(2L,await count.ExecuteScalarAsync(ct));
    }

    [Fact]
    public async Task Import_preserves_agent_lifecycle_and_assignment_serialization()
    {
        var ct=TestContext.Current.CancellationToken;
        using var environment=new Sli.Server.Tests.Semantic.SemanticProducerPostgresTests.Admission(mode:null);
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString);await admin.OpenAsync(ct);
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert=new CertificateRequest("CN=synthetic",key,HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(1));
        await SeedAsync(admin,fixture.Pg.Root,cert,ct);
        await using var worker=NpgsqlDataSource.Create(fixture.Dsn("sli_storage_login"));
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user"));await app.OpenAsync(ct);
        var sample=Sample(1);await ReceiptAsync(admin,sample,ct);
        string catalog=Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json");
        await using var tx=await app.BeginTransactionAsync(ct);
        await ImportAsync(app,tx,worker,sample,catalog,ct);
        await AssertLifecycleAsync(fixture,admin,app,tx,worker,sample,catalog,ct);
    }

    private static async Task AssertLifecycleAsync(SqlPostgresFixture fixture, NpgsqlConnection admin, NpgsqlConnection app,
        NpgsqlTransaction import, NpgsqlDataSource worker, Packet sample, string catalog, CancellationToken ct)
    {
        var audit = new AgentControlAudit();
        var management = new AgentManagementService(audit);
        var assignments = new AgentModuleAssignmentService(audit);
        // Both real writers must wait for the import; plain UPDATE would not conflict with KEY SHARE.
        await using var disableDb = new NpgsqlConnection(fixture.Dsn("adlog_user")); await disableDb.OpenAsync(ct);
        await using var disableTx = await disableDb.BeginTransactionAsync(ct);
        var disable = management.RevokeAsync(disableDb, disableTx, JsonSerializer.SerializeToElement(new { agent_id = Agent }), "session:1", true, ct);
        bool committed = false;
        try {
            await WaitBlockedAsync(admin, disableDb.ProcessID, app.ProcessID, ct);
            Assert.False(disable.IsCompleted);
            await import.CommitAsync(ct);
            committed = true;
            await disable.WaitAsync(TimeSpan.FromSeconds(5), ct);
        } finally {
            if (!committed) await import.RollbackAsync(CancellationToken.None);
            // Drain the command before rolling back its connection, including assertion failures.
            try { await disable; }
            finally { await disableTx.RollbackAsync(CancellationToken.None); }
        }
        // Test assignment independently: two queued FOR UPDATE writers can block
        // each other, which would not prove their conflict with the import lock.
        await using (var replay = await app.BeginTransactionAsync(ct)) {
            await ImportAsync(app, replay, worker, sample, catalog, ct);
            await using var assignDb = new NpgsqlConnection(fixture.Dsn("adlog_user")); await assignDb.OpenAsync(ct);
            await using var assignTx = await assignDb.BeginTransactionAsync(ct);
            var unassign = assignments.AssignAsync(assignDb, assignTx, JsonSerializer.SerializeToElement(new {
                agent_id = Agent, module_id = AgentAdDcValidator.Live, enabled = false,
                config = new { source_name = Source, connect_address = Source,
                    channels = new Dictionary<string,bool> { ["Security"]=true,["System"]=true,["Directory Service"]=true } }
            }), "session:1", ct);
            bool replayCommitted = false, assignmentCommitted = false;
            try {
                await WaitBlockedAsync(admin, assignDb.ProcessID, app.ProcessID, ct);
                Assert.False(unassign.IsCompleted);
                await replay.CommitAsync(ct);
                replayCommitted = true;
                await unassign.WaitAsync(TimeSpan.FromSeconds(5), ct); await assignTx.CommitAsync(ct);
                assignmentCommitted = true;
            } finally {
                if (!replayCommitted) await replay.RollbackAsync(CancellationToken.None);
                try { await unassign; }
                finally { if (!assignmentCommitted) await assignTx.RollbackAsync(CancellationToken.None); }
            }
        }
        await using (var tx = await app.BeginTransactionAsync(ct)) {
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() => ImportAsync(app, tx, worker, sample, catalog, ct));
            Assert.Equal("agent_module_not_assigned", error.Message); await tx.RollbackAsync(ct);
        }
        await using (var tx = await disableDb.BeginTransactionAsync(ct)) {
            await management.RevokeAsync(disableDb, tx, JsonSerializer.SerializeToElement(new { agent_id = Agent }), "session:1", true, ct);
            await tx.CommitAsync(ct);
        }
        await using (var tx = await app.BeginTransactionAsync(ct)) {
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() => ImportAsync(app, tx, worker, sample, catalog, ct));
            Assert.Equal("agent_disabled", error.Message); await tx.RollbackAsync(ct);
        }
    }
    private static async Task WaitBlockedAsync(NpgsqlConnection db, int waiter, int blocker, CancellationToken ct)
    {
        for (int n = 0; n < 100; n++) {
            await using var query = new NpgsqlCommand("select @blocker=any(pg_blocking_pids(@waiter))", db);
            query.Parameters.AddWithValue("blocker", blocker); query.Parameters.AddWithValue("waiter", waiter);
            if (await query.ExecuteScalarAsync(ct) is true) return;
            await Task.Delay(25, ct);
        }
        Assert.Fail("Lifecycle writer did not wait for the open import transaction");
    }

    private sealed record Packet(JsonObject Envelope, JsonObject Payload, JsonArray Rows);
    private static Packet Sample(int record, int count = 1,int eventKind=4624)
    {
        var scenario = JsonNode.Parse(File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(), "agent-dotnet/tests/vectors/ad-dc-scenarios.json")))!
            .AsArray().Single(x => (string?)x!["name"] == "security-initial-window-all")!;
        var step = scenario["steps"]![0]!; var expected = step["expected"]!;
        string old = scenario["host_id"]!.GetValue<string>();
        var payload = JsonNode.Parse(expected["payload_canonical"]!.GetValue<string>().Replace(old, Host.ToString()).Replace("fixture-dc", Source))!.AsObject();
        payload["records"]!.AsArray().Clear();
        for (int id = record; id < record + count; id++) {
            string xml = $"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>{id}</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00Z'/><Channel>Security</Channel><Computer>{Source}</Computer></System><EventData><Data Name='LogonType'>3</Data></EventData></Event>";
            if(eventKind==4720)xml=xml.Replace("<EventID>4624</EventID>","<EventID>4720</EventID>").Replace("</EventData>","<Data Name='TargetUserSid'>S-1-5-21-100000001-200000002-300000003-1101</Data><Data Name='TargetUserName'>synthetic-user</Data><Data Name='TargetDomainName'>EXAMPLE</Data></EventData>");
            payload["records"]!.AsArray().Add(new JsonObject { ["format"] = "event_xml", ["record_id"] = id, ["payload"] = EventXml.Parse(xml, Source, "fixture-endpoint", "Security") });
        }
        int last = record + count - 1;
        payload["header"]!["cursor"]!["last_record_id"] = last;
        payload["header"]!["record_id_range"]!["first"] = record; payload["header"]!["record_id_range"]!["last"] = last;
        var before = JsonNode.Parse(expected["cursor_before"]!.ToJsonString().Replace(old, Host.ToString()));
        var after = JsonNode.Parse(expected["cursor_after"]!.ToJsonString().Replace(old, Host.ToString()));
        var state = JsonNode.Parse(after!["token"]!.GetValue<string>())!;
        state["channels"]!["Security"]!["record_id"] = last;
        state["channels"]!["Security"]!["bookmark"] = state["channels"]!["Security"]!["bookmark"]!.GetValue<string>().Replace("RecordId='1'", $"RecordId='{last}'");
        after["token"] = CanonicalJson.Serialize(state);
        var envelope = new Envelope(Guid.NewGuid().ToString(), Agent.ToString(), Host.ToString(), AgentAdDcValidator.Live,
            "1.0.0", "1", "ad-dc", Host.ToString(), record, Cursor.FromJson(before), Cursor.FromJson(after), CollectionPacket.Contract,
            Packets.Digest(payload), count, CanonicalJson.Length(payload), step["now"]!.GetValue<string>(), "not_proven", 0, 0);
        return new(envelope.ToJson(), payload, AgentAdDcValidator.Validate(envelope, payload, null, Source));
    }
    private static Task ImportAsync(NpgsqlConnection db, NpgsqlTransaction tx, NpgsqlDataSource worker, Packet sample, string catalog, CancellationToken ct) =>
        DirectAdDcPacket.ImportAsync(db, tx, worker, Guid.Parse(sample.Envelope["packet_id"]!.GetValue<string>()), sample.Envelope, sample.Payload, sample.Rows, catalog, ct);

    private static async Task ReceiptAsync(NpgsqlConnection db, Packet sample, CancellationToken ct)
    {
        await using var query = new NpgsqlCommand("""
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            values(@agent,'sli.windows.ad-dc',@sequence,@packet,@hash,@envelope,'{"status":"committed"}')
            """, db);
        query.Parameters.AddWithValue("agent", Agent); query.Parameters.AddWithValue("sequence", sample.Envelope["sequence"]!.GetValue<long>());
        query.Parameters.AddWithValue("packet", Guid.Parse(sample.Envelope["packet_id"]!.GetValue<string>())); query.Parameters.AddWithValue("hash", Packets.Digest(sample.Envelope));
        query.Parameters.AddWithValue("envelope", NpgsqlDbType.Jsonb, sample.Envelope.ToJsonString()); await query.ExecuteNonQueryAsync(ct);
        await using var inbox = new NpgsqlCommand("insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows) values(@packet,@envelope,@payload,@rows)",db);
        inbox.Parameters.AddWithValue("packet",Guid.Parse(sample.Envelope["packet_id"]!.GetValue<string>()));
        inbox.Parameters.AddWithValue("envelope",NpgsqlDbType.Jsonb,sample.Envelope.ToJsonString());
        inbox.Parameters.AddWithValue("payload",NpgsqlDbType.Jsonb,sample.Payload.ToJsonString());
        inbox.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,sample.Rows.ToJsonString()); await inbox.ExecuteNonQueryAsync(ct);
    }
    internal static async Task SeedAsync(NpgsqlConnection db, string archive, X509Certificate2 cert, CancellationToken ct, string? keyFingerprint = null)
    {
        await PostCollectionPostgres.Sql(db, """
            insert into servers(domain_id,hostname,fqdn,role) select id,'dc-fixture.example.test','dc-fixture.example.test','domain_controller' from domains where fqdn='example.test';
            insert into log_sources(name) values('Security') on conflict do nothing;
            update plugin_installations_v1 set desired_activation='enabled_manual' where plugin_id='sli.ad';
            """, ct);
        await using (var query = new NpgsqlCommand("""
            insert into sli_agents(id,host_id,key_fingerprint,assigned_modules,policy_revision) values(@agent,@host,@fp,@modules,1);
            insert into sli_agent_module_bindings(agent_id,module_id,source_instance_id,source_name,channel,module_version,policy_revision)
            values(@agent,'sli.windows.ad-dc',@source,'dc-fixture.example.test','ad-dc','1.0.0','1');
            insert into sli_agent_certificates(agent_id,serial,fingerprint,not_before,not_after) values(@agent,@serial,@fingerprint,@before,@after);
            """, db)) {
            query.Parameters.AddWithValue("agent", Agent); query.Parameters.AddWithValue("host", Host); query.Parameters.AddWithValue("source", Host.ToString());
            var config = AgentAdDcValidator.NormalizePolicy(new JsonObject { ["source_name"] = Source, ["connect_address"] = Source,
                ["channels"]=new JsonObject { ["Security"]=true,["System"]=true,["Directory Service"]=true } }, false);
            query.Parameters.AddWithValue("modules", NpgsqlDbType.Jsonb, new JsonArray(new JsonObject {
                ["module_id"] = AgentAdDcValidator.Live, ["enabled"] = true, ["config"] = config
            }).ToJsonString());
            query.Parameters.AddWithValue("fp", keyFingerprint ?? new string('a', 64)); query.Parameters.AddWithValue("fingerprint", Convert.ToHexStringLower(SHA256.HashData(cert.RawData)));
            query.Parameters.AddWithValue("serial", cert.SerialNumber.TrimStart('0').ToLowerInvariant());
            query.Parameters.AddWithValue("before", cert.NotBefore.ToUniversalTime()); query.Parameters.AddWithValue("after", cert.NotAfter.ToUniversalTime());
            await query.ExecuteNonQueryAsync(ct);
        }
        var record = new DirectRuntimeRecord("v2", "storage-v2-fresh-bootstrap/v1", new string('a', 64), archive,
            new JsonObject { ["kind"] = "fresh-event-store", ["version"] = 1 }, "synthetic", DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddHours(1), null, "");
        // PostgreSQL timestamps have microsecond precision, as does the authorization digest.
        await using var authorization = new NpgsqlCommand("""
            insert into storage_v2_runtime_authorizations(route,authority,preflight_digest,authorization_digest,archive_root,evidence,authorized_by,authorized_at,expires_at)
            values('v2',@authority,@preflight,@digest,@archive,@evidence,'synthetic',@at,@expires)
            """, db);
        authorization.Parameters.AddWithValue("authority", record.Authority); authorization.Parameters.AddWithValue("preflight", record.PreflightDigest);
        authorization.Parameters.AddWithValue("digest", DirectRuntimeAuthorization.Digest(record)); authorization.Parameters.AddWithValue("archive", archive);
        authorization.Parameters.AddWithValue("evidence", NpgsqlDbType.Jsonb, record.Evidence.ToJsonString());
        authorization.Parameters.AddWithValue("at", record.AuthorizedAt); authorization.Parameters.AddWithValue("expires", record.ExpiresAt); await authorization.ExecuteNonQueryAsync(ct);
    }
    private sealed class Certificates : IDisposable
    {
        internal X509Certificate2 Root, Issuer;
        internal AgentIssuingCa Ca;
        internal Certificates()
        {
            static CertificateRequest Request(string name, ECDsa key, int depth) {
                var r = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256);
                r.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, depth, true));
                r.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
                r.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.2") }, true)); return r;
            }
            using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            Root = Request("Synthetic root", rootKey, 1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
            using var issuer = Request("Synthetic issuer", issuerKey, 0).Create(Root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(16));
            Issuer = issuer.CopyWithPrivateKey(issuerKey); Ca = new(Root, Issuer);
        }
        public void Dispose() { Ca.Dispose(); Root.Dispose(); Issuer.Dispose(); }
    }

    // Npgsql emits one CommandExecutionCompleted per executed SQL command,
    // including readers when disposed. Parameters are never enabled or collected.
    private sealed class CommandProfile(ITestOutputHelper output) : ILoggerProvider, ILogger
    {
        internal bool Enabled;
        internal readonly List<(string Sql,double Ms)> Commands = [];
        private int begins, commits;
        private readonly Dictionary<string,int> savepoints=[];
        public ILogger CreateLogger(string categoryName) => this;
        public bool IsEnabled(LogLevel logLevel) => true;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public void Dispose() { }
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? error, Func<TState,Exception?,string> format)
        {
            if (!Enabled) return;
            if (id.Name == "StartedTransaction") begins++;
            if (id.Name == "CommittedTransaction") commits++;
            if (id.Name?.Contains("Savepoint",StringComparison.Ordinal) is true)savepoints[id.Name]=savepoints.GetValueOrDefault(id.Name)+1;
            if (id.Name != "CommandExecutionCompleted") return;
            var fields = ((IEnumerable<KeyValuePair<string,object?>>)(object)state!).ToDictionary(x => x.Key, x => x.Value);
            Commands.Add((System.Text.RegularExpressions.Regex.Replace((string)fields["CommandText"]!, @"\s+", " ").Trim(),
                Convert.ToDouble(fields["DurationMs"], System.Globalization.CultureInfo.InvariantCulture)));
        }
        internal void Report()
        {
            output.WriteLine($"SQL commands={Commands.Count}; SQL total={Commands.Sum(x=>x.Ms):F1} ms; worker BEGIN={begins}, COMMIT={commits}; savepoint events={string.Join(',',savepoints.Select(x=>$"{x.Key}:{x.Value}"))}; caller BEGIN/COMMIT outside interval");
            foreach (var group in Commands.GroupBy(x=>x.Sql).OrderByDescending(g=>g.Sum(x=>x.Ms)))
                output.WriteLine($"{group.Count(),4} | {group.Sum(x=>x.Ms),9:F1} ms | {group.Key}");
        }
    }
}
