using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Sli.Server.InstallationSetup;
using Sli.Server.Operations;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Operations;

// Parity: tests/reporting/test_file_audit_collection_health_postgres.py.
public sealed class FileAuditCollectionHealthPostgresTests
{
    const string Agent = "00000000-0000-4000-8000-000000000001";
    static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-10-25T00:00:00Z");
    static readonly FileAuditPolicy Policy = FileAuditPolicy.Parse(JsonNode.Parse("""
        {"roots":[{"collection_scope_id":"scope:fixture","share_name":"synthetic",
        "path":"C:\\synthetic","important":false,"sacl":{
        "trustee_sids":["S-1-5-21-100000001-200000002-300000003-1001"],
        "inherit_files":true,"inherit_directories":true}}]}
        """)!.AsObject());

    static JsonArray Agents() => new(new JsonObject {
        ["id"] = Agent, ["host_id"] = Agent, ["instance_name"] = "fixture", ["status"] = "active",
        ["last_seen"] = Now.ToString("O"), ["created_at"] = Now.AddDays(-2).ToString("O"),
        ["policy_revision"] = 1, ["applied_policy_revision"] = 1, ["applied_collection_state"] = "active",
        ["collection_policy"] = new JsonObject { ["state"] = "active", ["interval_seconds"] = 60 },
        ["assigned_modules"] = new JsonArray(new JsonObject { ["module_id"] = "sli.file-audit", ["enabled"] = true, ["config"] = new JsonObject() })
    });

    static JsonObject AcceptedPacket(string? error = null)
    {
        string generation = error == "file_audit_journal_gap" ? Agent + ":00000000-0000-4000-8000-000000000003" : Agent;
        var before = Cursor.Start("bookmark");
        var after = generation == Agent ? before : new Cursor("bookmark", new JsonObject {
            ["record_id"] = null, ["bookmark"] = "", ["generation"] = generation
        }.ToJsonString());
        var payload = CollectionPacket.Make(Agent, "Security", generation,
            new JsonObject { ["after_record_id"] = null, ["last_record_id"] = null }, [], "not_proven",
            new JsonObject { ["policy_revision"] = "1", ["filtered_count"] = 0,
                ["lost_count"] = error is null ? JsonValue.Create(0) : null, ["read_error"] = error }, Now);
        var sample = new Sample("sli.file-audit", Agent, "Security", generation, before, after, payload,
            ContinuityState: error is null ? "not_proven" : "gap", LostCount: error is null ? 0 : null);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signed = Packets.Make(new EcdsaPacketSigner(key), Agent, 1, sample, Now);
        Assert.Empty(AgentFileAuditValidator.Validate(signed.Envelope, signed.Payload, Policy, Guid.Parse(Agent)));
        // Audit-management success is never proof of Security collection.
        var management = JsonNode.Parse("""{"contract_id":"sli.file-audit.audit-result.v1","scopes":[]}""")!.AsObject();
        Assert.Throws<ProtocolException>(() => AgentFileAuditValidator.Validate(signed.Envelope, management, Policy, Guid.Parse(Agent)));
        return signed.Payload;
    }

    static Task SeedAgents(NpgsqlConnection db, CancellationToken ct) => PostCollectionPostgres.Sql(db, """
        insert into sli_agents(id,host_id,key_fingerprint) values
            ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000001',repeat('a',64)),
            ('00000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000002',repeat('b',64));
        """, ct);

    static async Task InsertPacket(NpgsqlConnection db, long sequence, int age, JsonObject packet, bool imported, CancellationToken ct, string revision = "1")
    {
        await using var command = new NpgsqlCommand("""
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt,received_at)
            values(@agent,'sli.file-audit',@sequence,@packet_id,repeat('a',64),@envelope,'{"status":"committed"}',@received);
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at,imported_at)
            values(@packet_id,@envelope,@packet,'[]',@received,@imported);
            """, db);
        command.Parameters.AddWithValue("agent", Guid.Parse(Agent));
        command.Parameters.AddWithValue("sequence", sequence);
        command.Parameters.AddWithValue("packet_id", Guid.NewGuid());
        command.Parameters.AddWithValue("envelope", NpgsqlDbType.Jsonb, new JsonObject { ["policy_revision"] = revision, ["channel"] = "Security" }.ToJsonString());
        command.Parameters.AddWithValue("packet", NpgsqlDbType.Jsonb, packet.ToJsonString());
        command.Parameters.AddWithValue("received", Now.AddSeconds(-age));
        command.Parameters.AddWithValue("imported", NpgsqlDbType.TimestampTz, imported ? Now.AddSeconds(1 - age) : DBNull.Value);
        await command.ExecuteNonQueryAsync(ct);
    }

    static async Task<JsonArray> Read(NpgsqlConnection db, string sql, string parameter, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("select coalesce(jsonb_agg(to_jsonb(s)),'[]'::jsonb)::text from (" + sql + ") s", db);
        command.Parameters.AddWithValue(parameter, SetupCollectionHealth.Requested(Agents()).ToJsonString());
        return JsonNode.Parse((string)(await command.ExecuteScalarAsync(ct))!)!.AsArray();
    }

    [Fact]
    public async Task Accepted_packets_preserve_latest_order_queue_grace_and_unknown_in_both_health_views()
    {
        var ct = TestContext.Current.CancellationToken;
        var clean = AcceptedPacket(); var failed = AcceptedPacket("file_audit_read_failed"); var gap = AcceptedPacket("file_audit_journal_gap");
        var malformed = clean.DeepClone().AsObject(); malformed["context"]!["read_error"] = new JsonArray();
        var unknown = clean.DeepClone().AsObject(); unknown["context"]!.AsObject().Remove("read_error");
        (long Sequence, int Age, JsonObject Packet, bool Imported) Row(long sequence, int age, JsonObject packet, bool imported = true) => (sequence, age, packet, imported);
        var cases = new[] {
            (Rows: new[] { Row(1, 30, failed) }, State: "error", Reason: (string?)"read_error", Flag: (bool?)true),
            (Rows: new[] { Row(1, 30, gap) }, State: "error", Reason: (string?)"read_error", Flag: (bool?)true),
            (Rows: new[] { Row(1, 30, malformed) }, State: "unknown", Reason: (string?)null, Flag: (bool?)null),
            (Rows: new[] { Row(1, 30, clean) }, State: "current", Reason: (string?)null, Flag: (bool?)false),
            (Rows: new[] { Row(2, 60, failed), Row(1, 30, clean) }, State: "current", Reason: (string?)null, Flag: (bool?)false),
            (Rows: new[] { Row(1, 30, clean), Row(2, 30, failed) }, State: "error", Reason: (string?)"read_error", Flag: (bool?)true),
            (Rows: new[] { Row(1, 30, unknown) }, State: "unknown", Reason: (string?)null, Flag: (bool?)null),
            (Rows: new[] { Row(1, 30, clean, false) }, State: "current", Reason: (string?)null, Flag: (bool?)false),
            (Rows: new[] { Row(1, 1000, failed, false), Row(2, 30, clean) }, State: "error", Reason: (string?)"import_overdue", Flag: (bool?)false)
        };
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db = await fixture.Pg.OpenAsync(ct);
        await SeedAgents(db, ct);
        foreach (var test in cases)
        {
            await PostCollectionPostgres.Sql(db, "reset role; delete from sli_agent_packet_inbox; delete from sli_agent_receipts; delete from sli_agent_stream_import_health", ct);
            foreach (var row in test.Rows) await InsertPacket(db, row.Sequence, row.Age, row.Packet, row.Imported, ct);
            // Migration 237's generated compact flag does not contain the file-audit outcome.
            await using (var compact = new NpgsqlCommand("select bool_or(collection_read_error) from sli_agent_packet_inbox", db))
                Assert.False((bool)(await compact.ExecuteScalarAsync(ct))!);
            await PostCollectionPostgres.Sql(db, "set role adlog_user", ct);
            foreach (var (sql, parameter) in new[] { (OperationsSql.Streams, "requested"), (InstallationService.Sql("setup-streams.sql"), "p0") })
            {
                var streams = await Read(db, sql, parameter, ct);
                var stream = Assert.Single(streams)!;
                Assert.Equal(test.Flag, stream["read_error"]?.GetValue<bool>());
                foreach (var view in new[] { OperationsService.AgentView(Agents(), streams, Now), SetupCollectionHealth.View(Agents(), streams, Now) })
                {
                    var item = Assert.Single(view["items"]!.AsArray())!;
                    var module = Assert.Single(item["modules"]!.AsArray())!;
                    var check = Assert.Single(module["channels"]!.AsArray())!;
                    Assert.Equal("Security", (string?)check["channel"]);
                    Assert.Equal(test.State, (string?)check["state"]);
                    Assert.Equal(test.Reason, (string?)check["failure_reason"]);
                    Assert.Equal(test.State, (string?)item["state"]);
                    Assert.Equal("online", (string?)item["connection"]);
                }
            }
        }
        var agents = Agents(); agents[0]!["policy_applied_at"] = Now.ToString("O");
        foreach (var waiting in new[] { OperationsService.AgentView(agents, [], Now), SetupCollectionHealth.View(agents, [], Now) })
        {
            Assert.Equal("waiting", (string?)waiting["items"]![0]!["state"]);
            Assert.Equal("waiting", (string?)waiting["items"]![0]!["modules"]![0]!["channels"]![0]!["state"]);
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    static IEnumerable<JsonNode> Nodes(JsonNode node) => new[] { node }.Concat(
        (node["Plans"] as JsonArray ?? []).SelectMany(child => Nodes(child!)));

    [Fact]
    public async Task Latest_payload_is_one_primary_key_probe_per_requested_file_audit_stream()
    {
        var ct = TestContext.Current.CancellationToken;
        var clean = AcceptedPacket();
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db = await fixture.Pg.OpenAsync(ct);
        await SeedAgents(db, ct);
        await PostCollectionPostgres.Sql(db, """
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt,received_at)
            select '00000000-0000-4000-8000-000000000002','sli.windows.ad-dc',n,md5(n::text)::uuid,repeat('b',64),
                '{"policy_revision":"1","channel":"Security"}','{"status":"committed"}',
                '2026-01-01'::timestamptz+n*interval '1 second' from generate_series(1,40000) n;
            """, ct);
        // Separate transactions avoid accumulating 40,000 updates of the same import-health row.
        for (int first = 1; first <= 40000; first += 1000)
        {
            await using var batch = new NpgsqlCommand("""
                insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at,imported_at)
                select packet_id,envelope,'{"contract":"sli.collection-packet.v1","header":{"channel":"Security"},
                    "context":{"ad_dc":{"read_error":null}}}','[]',received_at,received_at
                from sli_agent_receipts where sequence between @first and @last;
                """, db);
            batch.Parameters.AddWithValue("first", first); batch.Parameters.AddWithValue("last", first + 999);
            await batch.ExecuteNonQueryAsync(ct);
        }
        await InsertPacket(db, 1, 0, clean, true, ct);
        await InsertPacket(db, 2, 0, clean, true, ct, revision: "2");
        await PostCollectionPostgres.Sql(db, "analyze sli_agent_receipts; analyze sli_agent_packet_inbox; analyze sli_agent_stream_receipts; set role adlog_user", ct);
        foreach (var (sql, parameter) in new[] { (OperationsSql.Streams, "requested"), (InstallationService.Sql("setup-streams.sql"), "p0") })
        {
            await using var explain = new NpgsqlCommand("explain(analyze,buffers,format json) " + sql, db);
            explain.Parameters.AddWithValue(parameter, SetupCollectionHealth.Requested(Agents()).ToJsonString());
            var plan = JsonNode.Parse((string)(await explain.ExecuteScalarAsync(ct))!)![0]!["Plan"]!;
            var payload = Assert.Single(Nodes(plan), n => (string?)n["Alias"] == "payload");
            Assert.Equal("Index Scan", (string?)payload["Node Type"]);
            Assert.Equal(1, (double)payload["Actual Loops"]!);
            Assert.Equal(1, (double)payload["Actual Rows"]!);
            Assert.Contains("packet_id", (string)payload["Index Cond"]!);
            var stream = Assert.Single(await Read(db, sql, parameter, ct))!;
            Assert.Equal("1", (string?)stream["revision"]);
            Assert.False(stream["read_error"]!.GetValue<bool>());
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
