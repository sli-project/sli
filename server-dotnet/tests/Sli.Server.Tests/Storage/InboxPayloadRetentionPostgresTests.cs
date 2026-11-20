using System.Diagnostics;
using System.Globalization;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class InboxPayloadRetentionPostgresTests
{
    static string Packet(int n) => $"00000000-0000-4000-8000-{n:000000000000}";
    static NpgsqlDataSource Deletion(SqlPostgresFixture fixture) => NpgsqlDataSource.Create(
        new NpgsqlConnectionStringBuilder(fixture.Dsn("sli_storage_lifecycle_delete_login")) {
            Options = "-c role=adlog_storage_lifecycle_delete", CommandTimeout = 0 }.ConnectionString);

    static async Task Seed(NpgsqlConnection db, int count, int days, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            insert into sli_agents(id,host_id,key_fingerprint,status)
            select ('10000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
              ('10000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,repeat('a',64),
              case n when 2 then 'disabled' when 3 then 'replaced' else 'active' end from generate_series(1,3) n;
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt,received_at)
            select ('10000000-0000-4000-8000-'||lpad((case when n in (2,3) then n else 1 end)::text,12,'0'))::uuid,
              'sli.windows.ad-dc',n,('00000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,repeat('a',64),
              jsonb_build_object('agent_id','10000000-0000-4000-8000-'||lpad((case when n in (2,3) then n else 1 end)::text,12,'0'),
                'module_id','sli.windows.ad-dc','policy_revision','1','channel','transport','source_instance_id','synthetic','generation','1'),
              '{"status":"committed"}',now()-make_interval(days=>@days)+n*interval '1 microsecond'
            from generate_series(1,@count) n;
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at,imported_at)
            select packet_id,envelope,
              '{"contract":"sli.collection-packet.v1","header":{"channel":"Security"},"context":{"ad_dc":{"read_error":"synthetic"}}}',
              '[{"record_id":1}]',received_at,received_at from sli_agent_receipts;
            """, db) { CommandTimeout = 0 };
        command.Parameters.AddWithValue("days", days); command.Parameters.AddWithValue("count", count);
        await command.ExecuteNonQueryAsync(ct);
    }

    static async Task<long> Count(NpgsqlConnection db, string predicate, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("select count(*) from sli_agent_packet_inbox where " + predicate, db);
        return (long)(await command.ExecuteScalarAsync(ct))!;
    }

    [Fact]
    public async Task Inbox_and_receipts_complete_after_legacy_events_are_removed()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await Seed(db,1,10,ct);
        await using(var absent=new NpgsqlCommand("select to_regclass('events_v2_core') is null and to_regclass('event_facts_v2') is null",db))
            Assert.Equal(true,await absent.ExecuteScalarAsync(ct));
        using var state=new StorageLifecycleTests.State(); await using var deletion=Deletion(fixture);
        var inbox=await new InboxRetention(deletion,state.Files).RunAsync(DateTime.UtcNow.AddDays(-7),Guid.Empty,1000,ct);
        Assert.Equal(1,LifecycleJson.Number(inbox,"deleted_count"));
        // The seed intentionally does not attest its envelope hash. Confirm it
        // before testing receipt compaction's independent legacy-free locks.
        await using(var read=new NpgsqlCommand("select jsonb_set(jsonb_set(envelope,'{packet_id}',to_jsonb(packet_id::text)),'{sequence}',to_jsonb(sequence))::text from sli_agent_receipts",db)) {
            string envelope=(string)(await read.ExecuteScalarAsync(ct))!;
            await using var update=new NpgsqlCommand("update sli_agent_receipts set envelope=cast(@envelope as jsonb),envelope_sha256=@hash",db);
            update.Parameters.AddWithValue("envelope",envelope);
            update.Parameters.AddWithValue("hash",Sli.Agent.Protocol.Packets.Digest(System.Text.Json.Nodes.JsonNode.Parse(envelope)!));
            await update.ExecuteNonQueryAsync(ct);
        }
        var receipts=await new ReceiptRetention(deletion,state.Files).RunAsync(DateTime.UtcNow.AddDays(-7),Guid.Empty,1000,ct);
        Assert.Equal("complete",receipts["status"]?.ToString());
        Assert.Equal(1,LifecycleJson.Number(receipts,"deleted_count"));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Imported_bodies_expire_before_receipts_holds_survive_and_released_holds_are_retried()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await Seed(db, 8, 0, ct);
        await PostCollectionPostgres.Sql(db, """
            update sli_agent_packet_inbox set imported_at=null where packet_id='00000000-0000-4000-8000-000000000002';
            update sli_agents set status='active';
            insert into sli_agent_packet_quarantine(packet_id,reason_code,event_ordinal)
              values('00000000-0000-4000-8000-000000000003','source_event_allocation_hash_mismatch',0);
            insert into sli_plugin_file_audit.retention_holds(hold_id,packet_id,reason_code)
              values(gen_random_uuid(),'00000000-0000-4000-8000-000000000004','synthetic');
            update sli_agent_receipts set receipt='{}' where sequence=5;
            update sli_agent_receipts set module_id='sli.file-audit',envelope=jsonb_set(envelope,'{module_id}','"sli.file-audit"') where sequence in (6,7);
            update sli_agent_packet_inbox i set envelope=r.envelope from sli_agent_receipts r where r.packet_id=i.packet_id and r.sequence in (6,7);
            insert into sli_plugin_file_audit.payload_expirations(packet_id,events,expired_at)
              values('00000000-0000-4000-8000-000000000007','[]',now());
            """, ct);
        using var state = new StorageLifecycleTests.State(); await using var deletion = Deletion(fixture);
        var retention = new InboxRetention(deletion, state.Files);
        var result = await retention.RunAsync(DateTime.UtcNow.AddDays(-7), Guid.Empty, 1000, ct);
        Assert.Equal("complete", result["status"]?.ToString());
        Assert.Equal(3, LifecycleJson.Number(result, "payloads_cleared"));
        Assert.Equal(0, LifecycleJson.Number(result, "deleted_count"));
        Assert.Equal(5, await Count(db, "packet is not null and event_rows is not null", ct));
        Assert.Equal(8, await Count(db, "true", ct));
        Assert.Equal(0, await Count(db, "quota_payload_bytes is null or quota_payload_bytes<1024", ct));
        Assert.Equal(1, LifecycleJson.Number(result["held_reasons"]!.AsObject(), "file_payload_pending"));
        Assert.Equal(0, LifecycleJson.Number(await retention.RunAsync(DateTime.UtcNow.AddDays(-7), Guid.Empty, 1000, ct), "payloads_cleared"));

        // The inbox's generated fields change with NULL packet. Readers must use
        // the original durable stream metadata, including header-only channels.
        await using (var metadata = new NpgsqlCommand("select collection_channel,collection_read_error from sli_agent_stream_receipts where packet_id=@packet", db)) {
            metadata.Parameters.AddWithValue("packet", Guid.Parse(Packet(1)));
            await using var reader = await metadata.ExecuteReaderAsync(ct);
            Assert.True(await reader.ReadAsync(ct)); Assert.Equal("Security", reader.GetString(0)); Assert.True(reader.GetBoolean(1));
        }
        string query = await File.ReadAllTextAsync(Path.Combine(PostCollectionPostgres.Repository(), "server-dotnet/src/Sli.Server/Workspace/streams.sql"), ct);
        await using (var latest = new NpgsqlCommand(query, db)) {
            latest.Parameters.AddWithValue("requested", NpgsqlDbType.Jsonb,
                """[{"agent_id":"10000000-0000-4000-8000-000000000001","module_id":"sli.windows.ad-dc","revision":"1","channel":"Security","snapshot":false}]""");
            await using var reader = await latest.ExecuteReaderAsync(ct);
            Assert.True(await reader.ReadAsync(ct)); Assert.False(reader.IsDBNull(reader.GetOrdinal("last_packet_at")));
            Assert.True(reader.GetBoolean(reader.GetOrdinal("read_error")));
        }
        await PostCollectionPostgres.Sql(db, "delete from sli_plugin_file_audit.retention_holds", ct);
        Assert.Equal(1, LifecycleJson.Number(await retention.RunAsync(DateTime.UtcNow.AddDays(-7), Guid.Empty, 1000, ct), "payloads_cleared"));
        await PostCollectionPostgres.Sql(db, "update sli_agent_packet_inbox set received_at=now()-interval '10 days',imported_at=case when imported_at is not null then now()-interval '10 days' end", ct);
        Assert.Equal(4, LifecycleJson.Number(await retention.RunAsync(DateTime.UtcNow.AddDays(-7), Guid.Empty, 1000, ct), "deleted_count"));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Backlog_drains_in_committed_batches_skips_busy_rows_and_expires_retired_agents()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await Seed(db, 6000, 10, ct);
        await PostCollectionPostgres.Sql(db, """
            update sli_agent_packet_inbox set imported_at=null where packet_id in (
              '00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000003');
            insert into sli_agent_packet_quarantine(packet_id,reason_code,event_ordinal)
              values('00000000-0000-4000-8000-000000000004','source_event_allocation_hash_mismatch',0);
            """, ct);
        await using var busy = new NpgsqlConnection(fixture.Pg.ConnectionString); await busy.OpenAsync(ct);
        await using var tx = await busy.BeginTransactionAsync(ct);
        await PostCollectionPostgres.Sql(busy, "select packet_id from sli_agent_packet_inbox where packet_id='00000000-0000-4000-8000-000000000005' for update", ct);
        using var state = new StorageLifecycleTests.State(); await using var deletion = Deletion(fixture);
        bool checkedWriter = false;
        var retention = new InboxRetention(deletion, state.Files, waiting => {
            if (waiting || checkedWriter) return;
            checkedWriter = true;
            // Runs while the first batch's locks are held. An unrelated import
            // must complete without waiting for that transaction to commit.
            using var writer = new NpgsqlCommand("update sli_agent_packet_inbox set imported_at=imported_at where packet_id='00000000-0000-4000-8000-000000006000'", db);
            Assert.Equal(1, writer.ExecuteNonQuery());
        });
        Guid after = Guid.Empty; DateTime? afterReceived = null; long deleted = 0; int batches = 0;
        for (;;) {
            var page = await retention.RunAsync(DateTime.UtcNow.AddDays(-7), after, 127, ct, afterReceived);
            Assert.InRange(LifecycleJson.Number(page, "selected_count"), 0, 127);
            deleted += LifecycleJson.Number(page, "deleted_count"); batches++;
            var next = Guid.Parse(page["last_scanned_packet_id"]!.ToString());
            if (page["status"]!.ToString() == "complete") break;
            Assert.NotEqual(after, next); after = next;
            afterReceived = DateTime.Parse(page["last_scanned_received_at"]!.ToString(), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal);
        }
        Assert.True(checkedWriter); Assert.True(batches>1); Assert.Equal(5997, deleted);
        Assert.Equal(3, await Count(db, "true", ct));
        await tx.RollbackAsync(ct);
        Assert.Equal(1, LifecycleJson.Number(await retention.RunAsync(DateTime.UtcNow.AddDays(-7), Guid.Empty, 127, ct), "deleted_count"));
        Assert.Equal(2, await Count(db, "true", ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Cursor_follows_received_order_and_breaks_timestamp_ties_without_revisiting_held_rows()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await Seed(db, 4, 10, ct);
        await PostCollectionPostgres.Sql(db, """
            update sli_agent_packet_inbox i set received_at='2026-10-01T00:00:00.123456Z'::timestamptz+
              (case r.sequence when 4 then 0 when 2 then 2 else 1 end)*interval '1 microsecond'
            from sli_agent_receipts r where r.packet_id=i.packet_id;
            insert into sli_plugin_file_audit.retention_holds(hold_id,packet_id,reason_code)
              values(gen_random_uuid(),'00000000-0000-4000-8000-000000000004','synthetic');
            """, ct);
        using var state = new StorageLifecycleTests.State(); await using var deletion = Deletion(fixture);
        var retention = new InboxRetention(deletion, state.Files);
        Guid after = Guid.Empty; DateTime? received = null;
        foreach (int expected in new[] { 4, 1, 3, 2 }) {
            var page = await retention.RunAsync(DateTime.UtcNow.AddDays(-7), after, 1, ct, received);
            Assert.Equal(Packet(expected), page["last_scanned_packet_id"]?.ToString());
            Assert.Equal(1, LifecycleJson.Number(page, "selected_count"));
            Assert.Equal(expected == 4 ? 0 : 1, LifecycleJson.Number(page, "deleted_count"));
            after = Guid.Parse(page["last_scanned_packet_id"]!.ToString());
            received = DateTime.Parse(page["last_scanned_received_at"]!.ToString(), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal);
        }
        Assert.Equal("complete", (await retention.RunAsync(DateTime.UtcNow.AddDays(-7), after, 1, ct, received))["status"]?.ToString());
        Assert.Equal(1, await Count(db, "true", ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Batch_sizes_measure_the_same_backlog_and_use_the_received_index()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await Seed(db, 4096, 10, ct);
        string packet, eventRows;
        await using (var body = new NpgsqlCommand("select packet::text,event_rows::text from sli_agent_packet_inbox limit 1", db))
        await using (var row = await body.ExecuteReaderAsync(ct)) {
            Assert.True(await row.ReadAsync(ct)); packet = row.GetString(0); eventRows = row.GetString(1);
        }
        using var state = new StorageLifecycleTests.State(); await using var deletion = Deletion(fixture);
        var retention = new InboxRetention(deletion, state.Files);
        foreach (int size in new[] { 128, 256, 1000 }) {
            if (size != 128) {
                await using var refill = new NpgsqlCommand("""
                insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at,imported_at)
                select packet_id,envelope,@packet,@rows,received_at,received_at from sli_agent_receipts;
                """, db) { CommandTimeout = 0 };
                refill.Parameters.AddWithValue("packet", NpgsqlDbType.Jsonb, packet);
                refill.Parameters.AddWithValue("rows", NpgsqlDbType.Jsonb, eventRows);
                await refill.ExecuteNonQueryAsync(ct);
            }
            await PostCollectionPostgres.Sql(db, "analyze sli_agent_packet_inbox", ct);
            Guid after = Guid.Empty; DateTime? received = null; long deleted = 0; int batches = 0;
            var watch = Stopwatch.StartNew(); double maxBatch = 0;
            for (;;) {
                var batchWatch = Stopwatch.StartNew();
                var page = await retention.RunAsync(DateTime.UtcNow.AddDays(-7), after, size, ct, received);
                maxBatch = Math.Max(maxBatch, batchWatch.Elapsed.TotalMilliseconds);
                deleted += LifecycleJson.Number(page, "deleted_count"); batches++;
                if (page["status"]?.ToString() == "complete") break;
                after = Guid.Parse(page["last_scanned_packet_id"]!.ToString());
                received = DateTime.Parse(page["last_scanned_received_at"]!.ToString(), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal);
            }
            watch.Stop(); Assert.Equal(4096, deleted); Assert.Equal(0, await Count(db, "true", ct));
            TestContext.Current.TestOutputHelper!.WriteLine($"batch={size} rows={deleted} batches={batches} total_ms={watch.Elapsed.TotalMilliseconds:F2} max_batch_ms={maxBatch:F2}");
        }
        await using (var flush = await deletion.OpenConnectionAsync(ct))
            await PostCollectionPostgres.Sql(flush, "select pg_stat_force_next_flush()", ct);
        await PostCollectionPostgres.Sql(db, "select pg_stat_clear_snapshot()", ct);
        await using (var used = new NpgsqlCommand("select idx_scan>0 from pg_stat_user_indexes where indexrelname='sli_agent_inbox_received351'", db))
            Assert.Equal(true, await used.ExecuteScalarAsync(ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Migration_upgrades_previous_schema_rolls_back_and_latest_lookup_uses_received_index()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 349);
        string migration = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/351_inbox_payload_retention.sql");
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        // The rollback above tests 351; the runtime below requires the current schema.
        foreach(var next in MigrationDirectory.Read(352)) await fixture.Pg.ApplyFileAsync(next.Path,null,ct);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await Seed(db, 5000, 10, ct);
        await PostCollectionPostgres.Sql(db, "analyze sli_agent_packet_inbox", ct);
        await using (var latest = new NpgsqlCommand("select max(received_at)=(select received_at from sli_agent_packet_inbox where packet_id=@last) from sli_agent_packet_inbox", db)) {
            latest.Parameters.AddWithValue("last", Guid.Parse(Packet(5000)));
            Assert.Equal(true, await latest.ExecuteScalarAsync(ct));
        }
        // Check the actual index-use counter rather than pinning an EXPLAIN tree.
        await PostCollectionPostgres.Sql(db, "select pg_stat_force_next_flush()", ct);
        await PostCollectionPostgres.Sql(db, "select pg_stat_clear_snapshot()", ct);
        await using (var used = new NpgsqlCommand("select idx_scan>0 from pg_stat_user_indexes where indexrelname='sli_agent_inbox_received351'", db))
            Assert.Equal(true, await used.ExecuteScalarAsync(ct));
        await PostCollectionPostgres.Sql(db, "update sli_agent_packet_inbox set imported_at=null where packet_id in ('00000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000003')", ct);
        using var state = new StorageLifecycleTests.State(); await using var deletion = Deletion(fixture);
        // Imported old packets no longer wait for a legacy copy cursor.
        Assert.Equal(20, LifecycleJson.Number(await new InboxRetention(deletion, state.Files)
            .RunAsync(DateTime.UtcNow.AddDays(-7), Guid.Empty, 20, ct), "deleted_count"));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
