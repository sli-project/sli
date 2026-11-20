using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Storage;
﻿using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Behavioral vectors from tests/semantic/test_semantic_producer.py.
[Collection("Semantic producer environment")]
public sealed class SemanticProducerParityTests
{
    private const string Sid = "S-1-5-21-100000001-200000002-300000003-1001";
    private const string Auditing = "Microsoft-Windows-Security-Auditing";
    private const string Success = "0x8020000000000000";
    private const string Failure = "0x8010000000000000";

    [Fact]
    public void Mixed_batch_keeps_signal_skips_context_and_samples_six_unknowns()
    {
        var rows = new[] { new SemanticProducer.Source(1, "4719", "Security", Auditing), new(2, "4624", "Security", Auditing) }
            .Concat(Enumerable.Range(3, 100).Select(i => new SemanticProducer.Source(i, (900000 + i).ToString(), "Security", Auditing))).ToArray();
        var selection = SemanticProducer.Select(rows);
        Assert.Equal(new SemanticProducer.Candidate(1, "signal"), selection.Jobs[0]);
        Assert.Equal(Enumerable.Range(3, 6).Select(i => new SemanticProducer.Candidate(i, "descriptor_missing")), selection.Jobs.Skip(1));
        foreach (var (key, expected) in new[] { ("scanned", 102), ("queued", 7), ("signal_queued", 1), ("unknown_queued", 6),
            ("unknown_suppressed", 94), ("context_skipped", 1), ("noise_skipped", 0) })
            Assert.Equal(expected, selection.Counters.Number(key));
    }

    [Fact]
    public void Explicit_retained_vocabulary_cohort_is_never_capped_as_unknown()
    {
        var ids = Enumerable.Range(1, 39).Select(i => (long)i).ToHashSet();
        var selection = SemanticProducer.Select(ids.Select(i => new SemanticProducer.Source(i, "4727", "Security", Auditing)).ToArray(), true, ids);
        Assert.Equal(ids.Order().Select(i => new SemanticProducer.Candidate(i, "related_context")), selection.Jobs);
        Assert.Equal(0, selection.Counters.Number("unknown_queued"));
        Assert.Equal(0, selection.Counters.Number("unknown_suppressed"));
    }

    internal static async Task Prepare(NpgsqlConnection db, CancellationToken ct)
    {
        _=await ShortEventAdmissionPostgresTests.SeedAsync(db,ct);
    }

    internal static async Task Event(NpgsqlConnection db, long id, int kind, CancellationToken ct,
        string sid = Sid, int seconds = 0, long domain = 0, string provider = Auditing, string keywords = Success)
    {
        domain=domain==0?1:domain; long server=domain==1?900001:900001+domain;
        var at=new DateTime(2026,11,1,0,0,0,DateTimeKind.Utc).AddSeconds(seconds);
        var data=new JsonObject { ["TargetUserSid"]=sid,["TargetSid"]=sid,["TargetUserName"]="synthetic-user" };
        XNamespace ns=EventXml.Namespace;
        var xml=new XElement(ns+"Event",new XElement(ns+"System",new XElement(ns+"Provider",new XAttribute("Name",provider)),
            new XElement(ns+"EventID",kind),new XElement(ns+"EventRecordID",id),new XElement(ns+"TimeCreated",new XAttribute("SystemTime",at.ToString("O"))),
            new XElement(ns+"Channel","Security"),new XElement(ns+"Computer","dc.example.test"),new XElement(ns+"Keywords",keywords)),
            new XElement(ns+"EventData",data.Select(x=>new XElement(ns+"Data",new XAttribute("Name",x.Key),x.Value!.ToString()))));
        var native=EventXml.Parse(xml.ToString(),"dc.example.test","dc.example.test","Security");
        var hash=Convert.FromHexString(DirectEventIdentity.Hash(native));
        var packet=Guid.NewGuid(); var agent=ShortEventAdmissionPostgresTests.Agent;
        var envelope=new JsonObject { ["agent_id"]=agent.ToString(),["module_id"]="sli.windows.ad-dc",["source_instance_id"]=agent.ToString(),["generation"]=agent.ToString() };
        await using var command=new NpgsqlCommand("""
            insert into domains(id,forest_id,fqdn) select @domain,forest_id,'domain-'||@domain::text||'.example.test' from domains where id=1 on conflict do nothing;
            insert into servers(id,domain_id,hostname,role,is_active) values(@server,@domain,'dc.example.test','domain_controller',true) on conflict do nothing;
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                values(@agent,'sli.windows.ad-dc',@sequence,@packet,@envelope_hash,@envelope,'{"status":"committed"}');
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
                values(@packet,@envelope,'{"contract":"sli.collection-packet.v1","header":{"channel":"Security","source":"dc.example.test"}}',@rows,now());
            insert into storage_v2_event_identity_allocations(id,server_id,channel_id,event_record_id,time_created_utc,normalized_hash)
                select @id,@server,id,@id,@at,@hash from storage_v2_channel where value='Security';
            insert into event_source_representations_v2(event_id,normalized_hash,identity_version,canonical_hash,representation,representation_sha256)
                values(@id,@hash,2,@hash,@native,@digest);
            """,db);
        command.Parameters.AddWithValue("id",id); command.Parameters.AddWithValue("server",server); command.Parameters.AddWithValue("domain",domain);
        command.Parameters.AddWithValue("agent",agent); command.Parameters.AddWithValue("sequence",id+100); command.Parameters.AddWithValue("packet",packet);
        command.Parameters.AddWithValue("envelope_hash",Packets.Digest(envelope)); command.Parameters.AddWithValue("envelope",NpgsqlDbType.Jsonb,envelope.ToJsonString());
        command.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,new JsonArray(native.DeepClone()).ToJsonString());
        command.Parameters.AddWithValue("at",at); command.Parameters.AddWithValue("hash",hash); command.Parameters.AddWithValue("native",NpgsqlDbType.Jsonb,native.ToJsonString());
        command.Parameters.AddWithValue("digest",SHA256.HashData(Encoding.UTF8.GetBytes(SourceJson.SerializeSorted(native))));
        await command.ExecuteNonQueryAsync(ct);
        var method=new JsonObject { ["$server_id"]=server,["$channel"]="Security",["$provider"]=provider,["$machine_name"]="dc.example.test",["$principals"]=data };
        var row=new ShortEventRow(id,at,kind,kind is 4624 or 4625?"summary":"fact",null,sid,null,"dc.example.test",domain,
            method.ToJsonString(),new JsonObject { ["keywords"]=keywords }.ToJsonString(),new Dictionary<string,string?>(),packet,0);
        await using var tx=await db.BeginTransactionAsync(ct);
        await ShortEventWriter.WriteAsync(db,tx,[row],ct); await tx.CommitAsync(ct);
    }

    private static async Task<long> Scalar(NpgsqlConnection db, string sql, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(sql, db);
        return Convert.ToInt64(await command.ExecuteScalarAsync(ct));
    }

    [Fact]
    public async Task Publication_deduplicates_ids_and_requires_explicit_context_admission()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct); await Prepare(admin, ct);
        await Event(admin, 11, 4719, ct); await Event(admin, 12, 4624, ct);
        await Event(admin, 13, 4719, ct, provider: "Other Provider");
        await using var db = new NpgsqlConnection(fixture.Dsn("sli_storage_login")); await db.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, "set role adlog_storage_worker", ct);
        using var admission = new SemanticProducerPostgresTests.Admission();
        await using (var tx = await db.BeginTransactionAsync(ct)) {
            await SemanticProducer.PublishAsync(db, tx, [11, 11, 12, 13], ct);
            Assert.Equal(2, await Scalar(db, "select count(*) from semantic_processing_outbox", ct));
            Assert.Equal(0, await Scalar(admin, "select count(*) from semantic_processing_outbox", ct));
            await tx.CommitAsync(ct);
        }
        Assert.Equal(1, await Scalar(admin, """
            select count(*) from semantic_processing_outbox
            where source_event_id=11 and payload_json='{"selection_reason":"signal"}'::jsonb
            """, ct));
        Assert.Equal(1, await Scalar(admin, "select count(*) from semantic_processing_outbox where source_event_id=13 and payload_json->>'selection_reason'='descriptor_missing'", ct));
        Assert.Equal(0, await Scalar(admin, "select count(*) from semantic_processing_outbox where source_event_id=12", ct));
        using var facts = new SemanticProducerPostgresTests.Admission(SemanticRuntimeSettings.FactsMode);
        await using (var tx = await db.BeginTransactionAsync(ct)) {
            await SemanticProducer.PublishAsync(db, tx, [12], ct); await tx.CommitAsync(ct);
        }
        Assert.Equal(1, await Scalar(admin, "select count(*) from semantic_processing_outbox where source_event_id=12 and payload_json->>'selection_reason'='explicit_context'", ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Investigation_publication_keeps_only_report_vocabulary_and_schedules_late_reset()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct); await Prepare(admin, ct);
        await Event(admin, 31, 4719, ct); await Event(admin, 32, 4625, ct); await Event(admin, 33, 5504, ct);
        await Event(admin, 34, 4719, ct, provider: "Other Provider"); await Event(admin, 35, 4776, ct);
        await Event(admin, 36, 1102, ct, provider: "Microsoft-Windows-Eventlog");
        await Event(admin, 20, 4724, ct);
        await using var db = new NpgsqlConnection(fixture.Dsn("sli_storage_login")); await db.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, "set role adlog_storage_worker", ct);
        using var admission = new SemanticProducerPostgresTests.Admission(SemanticRuntimeSettings.InvestigationMode);
        await using var tx = await db.BeginTransactionAsync(ct); var session = new SemanticSession(db, tx);
        var selection = await SemanticProducer.ReadSelection(session, [31, 32, 33, 34, 35, 36], SemanticRuntimeSettings.InvestigationMode, ct);
        Assert.Equal(new long[] { 31, 32, 35, 36 }.Select(i => new SemanticProducer.Candidate(i, "signal")), selection.Jobs);
        Assert.Equal(4, selection.Counters.Number("queued"));
        var reset = await SemanticProducer.ReadSelection(session, [20], SemanticRuntimeSettings.InvestigationMode, ct);
        Assert.Equal(new[] { new SemanticProducer.Candidate(20, "signal"), new(20, "late_context_expansion", "investigation_context") }, reset.Jobs);
        Assert.Equal(2, reset.Counters.Number("queued"));
        await SemanticProducer.PublishAsync(db, tx, [20, 31, 32, 33, 34, 35, 36], ct);
        Assert.Equal(6, await Scalar(db, "select count(*) from semantic_processing_outbox", ct));
        await tx.CommitAsync(ct); await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Investigation_context_requires_exact_sid_domain_success_and_open_closed_hour()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct); await Prepare(admin, ct);
        await Event(admin, 20, 4724, ct);
        await Event(admin, 1, 4624, ct, seconds: 1800);
        await Event(admin, 2, 4624, ct, sid: Sid.Replace("1001", "1002"), seconds: 1800);
        await Event(admin, 3, 4624, ct, domain: 8000000, seconds: 1800);
        await Event(admin, 4, 4624, ct, seconds: 3601);
        await Event(admin, 5, 4624, ct, seconds: 0);
        await Event(admin, 6, 4624, ct, seconds: -1);
        await Event(admin, 7, 4624, ct, seconds: 3600);
        await Event(admin, 21, 4724, ct, sid: Sid.Replace("1001", "1003"), keywords: Failure);
        await Event(admin, 8, 4624, ct, sid: Sid.Replace("1001", "1003"), seconds: 1800);
        string[] invalid = ["-", Sid + " ", Sid.ToLowerInvariant(), Sid[..^4] + "٤٠٠", Sid[..Sid.LastIndexOf('-')]];
        for (int i = 0; i < invalid.Length; i++) {
            await Event(admin, 30 + i, 4724, ct, sid: invalid[i]);
            await Event(admin, 10 + i, 4624, ct, sid: invalid[i], seconds: 1800);
        }
        await using var db = new NpgsqlConnection(fixture.Dsn("sli_storage_login")); await db.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, "set role adlog_storage_worker", ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        long[] ids = [1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14];
        var selection = await SemanticProducer.ReadSelection(new SemanticSession(db, tx), ids, SemanticRuntimeSettings.InvestigationMode, ct);
        Assert.Equal(new[] { new SemanticProducer.Candidate(1, "related_context"), new(7, "related_context") }, selection.Jobs);
        Assert.Equal(2, selection.Counters.Number("queued")); Assert.Equal(0, selection.Counters.Number("context_skipped"));
        using var admission = new SemanticProducerPostgresTests.Admission(SemanticRuntimeSettings.InvestigationMode);
        await SemanticProducer.PublishAsync(db, tx, ids, ct);
        Assert.Equal(2, await Scalar(db, "select count(*) from semantic_processing_outbox where payload_json->>'selection_reason'='related_context'", ct));
        await tx.CommitAsync(ct); await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Late_reset_filters_exact_sid_before_page_and_continues_until_all_101_logons_are_queued()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct); await Prepare(admin, ct);
        for (int i = 0; i < 101; i++) {
            await Event(admin, 1000000 + i, 4624, ct, sid: Sid + " ", seconds: 1800);
            await Event(admin, 2000000 + i, 4624, ct, seconds: 1800);
        }
        // The reset arrives after the logons, with a higher source id.
        await Event(admin, 3000000, 4724, ct);
        await using var runtime = PasswordProducerRuntime.Create(n => n == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException());
        await using var db = await runtime.OpenAsync(ct);
        await using (var tx = await db.BeginTransactionAsync(ct)) {
            Assert.Equal(1, await SemanticProducer.Enqueue(new SemanticSession(db, tx), [new(3000000, "late_context_expansion", "investigation_context")], ct));
            await tx.CommitAsync(ct);
        }
        var production = new SemanticProduction(runtime, new(true, true, false, true, false, false), SemanticRuntimeSettings.InvestigationMode, 1);
        var page = await production.ProcessOutbox(db, ct);
        Assert.Equal(0, page.Number("completed")); Assert.Equal(0, page.Number("failed"));
        Assert.Equal(100, await Scalar(admin, "select count(*) from semantic_processing_outbox where job_kind='normalize_event'", ct));
        Assert.Equal(100, await Scalar(admin, "select count(*) from semantic_processing_outbox where source_event_id between 2000000 and 2000099", ct));
        Assert.Equal(1, await Scalar(admin, "select count(*) from semantic_processing_outbox where job_kind='investigation_context' and status='queued' and attempt_count=0 and lease_token is null", ct));
        // Isolate the continuation from the unrelated normalization consumer.
        await PostCollectionPostgres.Sql(admin, """
            update semantic_processing_outbox set available_at='infinity' where job_kind='normalize_event';
            update semantic_processing_outbox set available_at=now() where job_kind='investigation_context';
            """, ct);
        page = await production.ProcessOutbox(db, ct);
        Assert.Equal(1, page.Number("completed")); Assert.Equal(0, page.Number("failed"));
        Assert.Equal(101, await Scalar(admin, "select count(*) from semantic_processing_outbox where job_kind='normalize_event' and source_event_id between 2000000 and 2000100", ct));
        Assert.Equal(0, await Scalar(admin, "select count(*) from semantic_processing_outbox where source_event_id between 1000000 and 1000100", ct));
        Assert.Equal(1, await Scalar(admin, "select count(*) from semantic_processing_outbox where job_kind='investigation_context' and status='completed' and lease_token is null", ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
