using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Sli.Server.Agents.Radius;
using Sli.Server.Storage.Direct;
using Xunit;

namespace Sli.Server.Tests.Agents;

// Vectors from tests/sources/test_collection_packets.py; no live source or inherited DSN.
public sealed class CollectionPacketsTests : IDisposable
{
    private static readonly DateTimeOffset Observed = new(2026, 10, 5, 12, 0, 0, TimeSpan.Zero);
    private readonly string root = Path.Combine(Path.GetTempPath(), "sli-collection-" + Guid.NewGuid().ToString("N"));
    public CollectionPacketsTests() => Directory.CreateDirectory(root);
    public void Dispose() => Directory.Delete(root, true);
    private static JsonObject Wire(JsonObject packet) => JsonNode.Parse(packet.ToJsonString())!.AsObject();
    private static JsonObject EventPacket(JsonObject row) => CollectionPacket.Make("fixture-dc", "Security", "fixture-generation",
        new JsonObject { ["after_record_id"] = 41, ["last_record_id"] = 42 },
        [new("event_xml", 42, row)], "complete", null, Observed);

    [Fact]
    public void PacketAndLegacyJsonlRestoreIdenticalRows()
    {
        var row = JsonNode.Parse("""
            {"computer_name":"fixture-dc","connect_address":"fixture-endpoint","channel":"Security",
             "record_id":42,"event_id":4624,"xml":"<Event />","message":null,"properties":[]}
            """)!.AsObject();
        string path = Path.Combine(root, "Security.jsonl");
        File.WriteAllText(path, EventPacket(row).ToJsonString() + "\n" + row.ToJsonString() + "\n", new UTF8Encoding(true));
        var rows = CollectionPacketImport.ReadEventJsonl(path).ToArray();
        Assert.Equal(2, rows.Length);
        Assert.All(rows, value => Assert.True(JsonNode.DeepEquals(row, value)));
    }

    [Fact]
    public void InvalidRecordRangeFailsBeforeRowsReachImporter()
    {
        var row = new JsonObject { ["computer_name"] = "fixture-dc", ["channel"] = "Security", ["record_id"] = 42, ["xml"] = "<Event />" };
        var packet = EventPacket(row); packet["header"]!["record_id_range"]!["last"] = 41;
        string path = Path.Combine(root, "invalid.jsonl"); File.WriteAllText(path, packet.ToJsonString());
        var error = Assert.Throws<ProtocolException>(() => CollectionPacketImport.ReadEventJsonl(path).ToArray());
        Assert.StartsWith("collection_packet", error.Code);
    }

    [Fact]
    public void LocalEventXmlRetainsNativeImportParametersAfterWireRoundTrip()
    {
        const string xml = "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>6272</EventID><EventRecordID>52</EventRecordID><TimeCreated SystemTime=\"2026-10-05T12:00:00Z\" /></System><EventData /></Event>";
        var row = EventXml.Parse(xml, "fixture-nps", "fixture-endpoint", "Security");
        var packet = CollectionPacket.Make("fixture-nps", "Security", "fixture-generation",
            new JsonObject { ["after_record_id"] = 51, ["last_record_id"] = 52 }, [new("event_xml", 52, row)], "complete", null, Observed);
        var restored = AgentCollectionRows.ExtractEvents(Wire(packet))[0]!.AsObject();
        Assert.True(JsonNode.DeepEquals(row, restored));
        Assert.Equal(xml, restored["xml"]!.GetValue<string>());
        Assert.Equal(52, restored["record_id"]!.GetValue<int>());
        Assert.Equal(6272, restored["event_id"]!.GetValue<int>());
        Assert.Equal(DirectEventIdentity.Hash(row), DirectEventIdentity.Hash(restored));
        Assert.Equal("aab857db8d0c09dfa12c3891c38bcc74552c1f96468176f1f862d602547d4224", DirectEventIdentity.Hash(restored));
        Assert.True(JsonNode.DeepEquals(DirectNativeEvent.Data(row), DirectNativeEvent.Data(restored)));
        Assert.Equal("complete", packet["continuity"]!["status"]!.GetValue<string>());
    }

    internal static JsonObject Bundle(string status) => JsonNode.Parse($$"""
        {"schema_version":"ad-context-bundle/v1","source_pack_id":"sli.windows.ad-context","source_pack_version":"0.8.0",
         "run_id":"00000000-0000-4000-8000-000000000001","mode":"full",
         "domain":{"sid":"S-1-5-21-100000001-200000002-300000003","dns_name":"example.test"},
         "scope":{"search_base":"fixture-base"},"observed_at_utc":"2026-10-05T12:00:00Z",
         "sections":[{"name":"directory_accounts","status":"{{status}}","record_count":0,"duration_ms":0,"error_code":null}],"records":[]}
        """)!.AsObject();

    private string WriteBundle(JsonObject bundle)
    {
        string path = Path.Combine(root, "bundle.json");
        byte[] raw = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(bundle.ToJsonString())).ToArray();
        File.WriteAllBytes(path, raw);
        File.WriteAllText(path + ".sha256", Convert.ToHexStringLower(SHA256.HashData(raw)));
        return path;
    }

    [Theory]
    [InlineData("complete", "complete")]
    [InlineData("partial", "not_proven")]
    public void SnapshotFilePreservesBundleAndContinuity(string status, string continuity)
    {
        var bundle = Bundle(status);
        var packet = CollectionPacketImport.ReadSnapshotPacket(WriteBundle(bundle), "ad_context_base", Observed);
        Assert.True(JsonNode.DeepEquals(bundle, packet["records"]![0]!["payload"]));
        Assert.Equal(continuity, packet["continuity"]!["status"]!.GetValue<string>());
        var restored = CollectionPacketImport.SnapshotBundle(Wire(packet));
        Assert.True(JsonNode.DeepEquals(Sli.Server.Ad.AdContextBundle.Normalize(bundle), restored));
        packet["records"]![0]!["payload"]!["sections"]![0]!["status"] = "failed";
        Assert.Equal(status, restored["sections"]![0]!["status"]!.GetValue<string>());
    }

    [Fact]
    public void SnapshotDigestMismatchCannotReachBundleImport()
    {
        string path = WriteBundle(Bundle("complete")); File.WriteAllText(path + ".sha256", new string('0', 64));
        Assert.Equal("snapshot_packet_digest_mismatch", Assert.Throws<ProtocolException>(() =>
            CollectionPacketImport.ReadSnapshotPacket(path, "ad_context_base", Observed)).Code);
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("source")]
    [InlineData("cursor")]
    public void SnapshotIdentityMustMatchHeaderBeforeImport(string field)
    {
        var packet = CollectionPacketImport.ReadSnapshotPacket(WriteBundle(Bundle("complete")), "ad_context_base", Observed);
        if (field == "cursor") packet["header"]!["cursor"]!["run_id"] = "other";
        else packet["header"]![field] = "other";
        Assert.Equal("collection_packet_snapshot_mismatch", Assert.Throws<ProtocolException>(() => CollectionPacketImport.SnapshotBundle(packet)).Code);
    }

    [Theory]
    [InlineData("complete")]
    [InlineData("partial")]
    public async Task SnapshotPacketAndLegacyBundleHaveIdenticalRepositoryEffects(string status)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(); await pg.StartAsync(ct);
        await using var db = await pg.OpenAsync(ct);
        var bundle = Bundle(status);
        var packet = Wire(CollectionPacketImport.ReadSnapshotPacket(WriteBundle(bundle), "ad_context_base", Observed));
        async Task<string> ReadState()
        {
            await using var cmd = new NpgsqlCommand("""
                select jsonb_build_object('runs',(select jsonb_agg(to_jsonb(r)-'completed_at') from ad_context_runs r),
                    'sections',(select jsonb_agg(to_jsonb(s)) from ad_context_sections s))::text
                """, db);
            // Import-start timestamps are generated by PostgreSQL, compare the stable contract columns below.
            return (string)(await cmd.ExecuteScalarAsync(ct))!;
        }
        await using var tx = await db.BeginTransactionAsync(ct);
        await tx.SaveAsync("legacy", ct);
        var legacy = await Sli.Server.Ad.AdContextStore.ImportAsync(db, tx, 7, Sli.Server.Ad.AdContextBundle.Normalize(bundle), ct);
        var oldState = JsonNode.Parse(await ReadState())!;
        foreach (var run in oldState["runs"]!.AsArray()) run!.AsObject().Remove("started_at");
        await tx.RollbackAsync("legacy", ct);
        var actual = await CollectionPacketImport.ImportSnapshotAsync(db, tx, 7, packet, ct);
        var newState = JsonNode.Parse(await ReadState())!;
        foreach (var run in newState["runs"]!.AsArray()) run!.AsObject().Remove("started_at");
        Assert.Empty(legacy); Assert.Empty(actual);
        Assert.True(JsonNode.DeepEquals(oldState, newState));
        Assert.Equal("completed", newState["runs"]![0]!["status"]!.GetValue<string>());
        Assert.Equal(status, newState["sections"]![0]!["status"]!.GetValue<string>());
        await tx.RollbackAsync(ct);
    }

    private static RadiusCursor RadiusCursor() => new("fixture-radius", "radius-accounting", "fixture-tail", "fixture-generation", 0, null);
    private static string AccountingLine()
    {
        var fields = Enumerable.Repeat("", 66).ToArray();
        fields[0] = "fixture-nps"; fields[1] = "IAS"; fields[2] = "10/05/2026"; fields[3] = "12:00:00";
        fields[4] = "4"; fields[11] = "fixture-gateway"; fields[31] = "1"; fields[35] = "fixture-session";
        return string.Join(',', fields);
    }
    private static JsonObject AccountingPacket(RadiusCursor cursor, bool rotated, bool empty = false)
    {
        var packet = CollectionPacket.Make(cursor.SourceId, cursor.StreamId, rotated ? "fixture-next-generation" : cursor.FileGeneration,
            new JsonObject { ["before"] = cursor.ToJson(), ["start_offset"] = 0, ["end_offset"] = empty ? 0 : 256 },
            empty ? [] : [new("accounting_line", null, JsonValue.Create(AccountingLine())!)], "complete",
            new JsonObject { ["source_timezone_id"] = "UTC", ["source_utc_offset_minutes"] = 0, ["candidate_count"] = 1,
                ["bytes_read"] = empty ? 0 : 256, ["partial_trailing_bytes"] = 0, ["rotation_backlog_generations"] = 0, ["cursor_generation_recovered"] = false }, Observed);
        packet["continuity"]!["previous_generation_eof"] = rotated;
        return Wire(packet);
    }

    [Fact]
    public async Task EmptyAccountingPacketDoesNotOpenConnectionOrAdvanceRevision()
    {
        // An unopened connection cannot begin a transaction; a regression must fail here.
        await using var db = new NpgsqlConnection();
        var result = await RadiusAccountingImporter.ImportAcquisitionPacketAsync(db, AccountingPacket(RadiusCursor(), false, true),
            RadiusCursor(), Guid.Empty, 7, "fixture-subscription", new(root, "fixture-nps"), TestContext.Current.CancellationToken);
        Assert.Equal("no_new_complete_records", result.Status);
        Assert.Equal(7, result.CursorRevisionBefore); Assert.Equal(7, result.CursorRevisionAfter);
        Assert.Equal(0, result.EvidenceRows); Assert.Equal(0, result.ObservationRows);
        Assert.Equal(System.Data.ConnectionState.Closed, db.State);
    }

    private static async Task RadiusSchema(NpgsqlConnection db, CancellationToken ct)
    {
        string sql = File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/058_radius_accounting_transaction_foundation.sql"));
        foreach (string table in new[] { "acquisition_source_instances", "acquisition_stream_cursors", "acquisition_consumer_subscriptions", "core_evidence_manifests", "radius_accounting_session_observations", "acquisition_delivery_outbox", "radius_accounting_class_cache" })
        {
            var match = Regex.Match(sql, @"create table if not exists " + table + @"\s*\([\s\S]*?\r?\n\);", RegexOptions.IgnoreCase);
            Assert.True(match.Success, table);
            await PostCollectionPostgres.Sql(db, match.Value, ct);
        }
        await PostCollectionPostgres.Sql(db, """
            create role adlog_radius_accounting_worker;
            grant usage on schema public to adlog_radius_accounting_worker;
            grant select,insert,update,delete on all tables in schema public to adlog_radius_accounting_worker;
            grant usage on all sequences in schema public to adlog_radius_accounting_worker;
            insert into acquisition_source_instances(source_instance_id,organization_scope,source_kind,endpoint_identity,adapter_binding,display_name,desired_activation,configuration_sha256)
              values('fixture-radius','example.test','radius','fixture-nps','fixture-tail','fixture','manual_enabled',repeat('a',64));
            insert into acquisition_stream_cursors(source_instance_id,stream_id,transport_binding,cursor_epoch,file_generation,byte_offset,revision)
              values('fixture-radius','radius-accounting','fixture-tail','00000000-0000-4000-8000-000000000007','fixture-generation',0,7);
            insert into acquisition_consumer_subscriptions(subscription_id,source_instance_id,stream_id,transport_binding,consumer_id,consumer_component_id,consumer_component_version,routing_contract_id,consumer_contract_version,replay_policy,resource_profile_id,selector_json,selector_sha256,authority_mode,desired_activation,partition_key)
              values('fixture-subscription','fixture-radius','radius-accounting','fixture-tail','fixture','fixture','1','fixture','1','no_replay','fixture','{}',repeat('a',64),'authoritative','manual_enabled','fixture');
            """, ct);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AccountingWireRoundTripKeepsPlanEvidenceAndCommit(bool rotated)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(); await pg.StartAsync(ct);
        await using var db = await pg.OpenAsync(ct); await RadiusSchema(db, ct);
        var cursor = RadiusCursor(); var packet = AccountingPacket(cursor, rotated);
        var legacy = await RadiusPlanner.ProjectAsync([AccountingLine()], cursor.SourceId, "UTC", 0, Observed, [], _ => Task.FromResult<string?>(null));
        var receipt = await RadiusAccountingImporter.ImportAcquisitionPacketAsync(db, packet, cursor,
            Guid.Parse("00000000-0000-4000-8000-000000000007"), 7, "fixture-subscription", new(root, "fixture-nps"), ct);
        Assert.Equal("committed", receipt.Status); Assert.Equal(7, receipt.CursorRevisionBefore); Assert.Equal(8, receipt.CursorRevisionAfter);
        Assert.Equal(rotated, receipt.RotationFromEof); Assert.Equal(1, receipt.EvidenceRows); Assert.Equal(1, receipt.ObservationRows);
        Assert.Equal(1, receipt.OutboxRows); Assert.Equal(0, receipt.ClassCacheRows);
        await using var query = new NpgsqlCommand("""
            select c.revision,c.file_generation,c.byte_offset,c.previous_file_generation,e.canonical_record_sha256,
                e.cursor_epoch,e.cursor_start_byte_offset,e.batch_record_ordinal,o.lifecycle_event,o.observed_at_utc,o.exact_principal_key,
                (select count(*) from acquisition_delivery_outbox)
            from acquisition_stream_cursors c join core_evidence_manifests e using(source_instance_id,stream_id,transport_binding)
            join radius_accounting_session_observations o using(evidence_uid)
            """, db);
        await using var reader = await query.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct));
        Assert.Equal(8, reader.GetInt64(0)); Assert.Equal(rotated ? "fixture-next-generation" : "fixture-generation", reader.GetString(1));
        Assert.Equal(256, reader.GetInt64(2)); Assert.Equal(rotated ? "fixture-generation" : null, reader.IsDBNull(3) ? null : reader.GetString(3));
        Assert.Equal(legacy.EvidenceHashes.Single(), reader.GetString(4));
        Assert.Equal(Guid.Parse("00000000-0000-4000-8000-000000000007"), reader.GetGuid(5)); Assert.Equal(0, reader.GetInt64(6)); Assert.Equal(0, reader.GetInt32(7));
        Assert.Equal(legacy.Observations.Single().Lifecycle, reader.GetString(8)); Assert.Equal(Observed.UtcDateTime, reader.GetDateTime(9));
        Assert.True(reader.IsDBNull(10)); Assert.Equal(1, reader.GetInt64(11)); Assert.False(await reader.ReadAsync(ct));
        var files = Directory.GetFiles(Path.Combine(root, "published"), "*.record", SearchOption.AllDirectories);
        Assert.Equal(AccountingLine(), File.ReadAllText(Assert.Single(files)));
    }

    private sealed class LocalAccountingFiles(string path) : IRadiusFileSystem
    {
        private static RadiusFile Metadata(string path)
        {
            var file = new FileInfo(path);
            return new(path, file.Name, (file.CreationTimeUtc.Ticks - DateTime.UnixEpoch.Ticks) * 100,
                (file.LastWriteTimeUtc.Ticks - DateTime.UnixEpoch.Ticks) * 100, file.Length, "fixture-device", "fixture-file");
        }
        public IEnumerable<RadiusFile> Inventory(string directory) => [Metadata(path)];
        public IRadiusReadFile Open(RadiusFile file) => new LocalRead(file);
        private sealed class LocalRead(RadiusFile file) : IRadiusReadFile
        {
            private readonly FileStream stream = File.OpenRead(file.Key);
            public RadiusFile Metadata => LocalAccountingFiles.Metadata(file.Key);
            public byte[] Read(long offset, int count)
            {
                stream.Position = offset; byte[] bytes = new byte[count];
                int read = stream.ReadAtLeast(bytes, count, throwOnEndOfStream: false); return bytes[..read];
            }
            public void Dispose() => stream.Dispose();
        }
    }

    [Fact]
    public void RealAccountingFileLeavesPartialLineOutsidePacketAndCursor()
    {
        string path = Path.Combine(root, "IN-fixture.log");
        byte[] raw = Encoding.UTF8.GetBytes(AccountingLine() + "\r\npartial"); File.WriteAllBytes(path, raw);
        var files = new LocalAccountingFiles(path); var metadata = files.Inventory(root).Single();
        var cursor = RadiusCursor() with { FileGeneration = RadiusTailSource.DeriveGeneration("fixture-radius", metadata.Name, metadata.CreationTimeNs) };
        var config = new JsonObject { ["source_instance_id"] = cursor.SourceId, ["accounting_directory"] = root,
            ["initial_cursor"] = cursor.ToJson(), ["subscription_id"] = "fixture-subscription", ["source_timezone_id"] = "UTC", ["source_utc_offset_minutes"] = 0 };
        var module = new RadiusAccountingModule("fixture-host", NpsPolicy.Parse(NpsPolicy.Accounting, config), new RadiusTailSource(files));
        var sample = module.Collect(null, Observed); var packet = Wire(sample.Payload);
        Assert.Equal(AccountingLine(), packet["records"]![0]!["payload"]!.GetValue<string>());
        Assert.Single(packet["records"]!.AsArray());
        Assert.Equal(raw.Length - 7, packet["header"]!["cursor"]!["end_offset"]!.GetValue<int>());
        Assert.Equal(7, packet["context"]!["partial_trailing_bytes"]!.GetValue<int>());
        Assert.Null(packet["header"]!["record_id_range"]!["first"]); Assert.Null(packet["header"]!["record_id_range"]!["last"]);
        Assert.Equal(raw.Length - 7, JsonNode.Parse(sample.CursorAfter.Token)!["byte_offset"]!.GetValue<int>());
    }

    [Fact]
    public void SchemaEnvelopeAndFormatsMatchProducer()
    {
        var schema = JsonNode.Parse(File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(), "config/collection_packet_v1.schema.json")))!;
        var packet = AccountingPacket(RadiusCursor(), false);
        Assert.Equal(CollectionPacket.Contract, schema["properties"]!["contract"]!["const"]!.GetValue<string>());
        Assert.Equal(schema["required"]!.AsArray().Select(n => n!.ToString()).Order(), packet.Select(p => p.Key).Order());
        Assert.Equal(schema["properties"]!["header"]!["required"]!.AsArray().Select(n => n!.ToString()).Order(), packet["header"]!.AsObject().Select(p => p.Key).Order());
        Assert.Equal(schema["properties"]!["records"]!["items"]!["properties"]!["format"]!["enum"]!.AsArray().Select(n => n!.ToString()).Order(), CollectionPacket.Formats.Order());
    }
}
