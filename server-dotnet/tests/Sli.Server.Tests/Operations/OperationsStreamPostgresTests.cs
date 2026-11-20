using System.Diagnostics;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Operations;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Operations;

public sealed partial class OperationsStreamPostgresTests(ITestOutputHelper output)
{
    const string Agent = "00000000-0000-4000-8000-000000000001";
    static string LegacyStreams => File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(), "server-dotnet/tests/Sli.Server.Tests/Operations/agent_collection_streams_before_312.sql")).Replace("\r\n", "\n");
    const string Migration = "313_agent_collection_stream_index";

    [Fact]
    public async Task Migration_313_applies_after_312_and_rolls_back_to_it()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 313);
        await using var db = await fixture.Pg.OpenAsync(ct);
        string directory = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations");
        string forward = Path.Combine(directory, Migration + ".sql"), rollback = Path.Combine(directory, Migration + ".rollback.sql");
        async Task AssertPredecessor()
        {
            await using var check = new NpgsqlCommand("""
                select (select max(version) from public.schema_migrations)=312
                    and exists(select 1 from public.schema_migrations where version=312 and name='semantic_workstation_discovery')
                    and to_regclass('public.sli_agent_stream_receipts') is null
                    and to_regprocedure('public.record_agent_stream_receipt_v313()') is null
                """, db);
            Assert.Equal(true, await check.ExecuteScalarAsync(ct));
        }
        await fixture.Pg.ApplyFileAsync(rollback, null, ct);
        await AssertPredecessor();
        await fixture.Pg.ApplyFileAsync(forward, null, ct);
        await using (var check = new NpgsqlCommand("""
            select (select max(version) from public.schema_migrations)=313
                and exists(select 1 from public.schema_migrations where version=312 and name='semantic_workstation_discovery')
                and exists(select 1 from public.schema_migrations where version=313 and name='agent_collection_stream_index')
                and to_regclass('public.sli_agent_stream_receipts') is not null
                and to_regprocedure('public.record_agent_stream_receipt_v313()') is not null
            """, db)) Assert.Equal(true, await check.ExecuteScalarAsync(ct));
        await fixture.Pg.ApplyFileAsync(rollback, null, ct);
        await AssertPredecessor();
        await fixture.Pg.ApplyFileAsync(forward, null, ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Large_history_missing_channel_and_old_revision_keep_exact_fields_under_three_seconds()
    {
        string python = File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(), "server/sli/agents/collection_health.py"))
            .Replace("\r\n", "\n").Split("_STREAMS_SQL = \"\"\"", 2)[1].Split("\"\"\"", 2)[0].Replace("?::jsonb", "@requested::jsonb");
        Assert.Equal(LegacyStreams.Trim(), python.Trim());
        // The disabled-module column arrived in 363. Its current reader has separate
        // coverage in FileAuditCollectionHealthPostgresTests on the latest schema.
        const string disabledIntakeFilter = " and i.module_disabled_at is null";
        Assert.Contains(disabledIntakeFilter, OperationsSql.Streams);
        string historicalStreams = OperationsSql.Streams.Replace(disabledIntakeFilter, "", StringComparison.Ordinal);
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 313);
        await using var db = await fixture.Pg.OpenAsync(ct);
        string directory = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations");
        string forward = Path.Combine(directory, Migration + ".sql"), rollback = Path.Combine(directory, Migration + ".rollback.sql");
        await fixture.Pg.ApplyFileAsync(rollback, null, ct);
        await using (var seed = new NpgsqlCommand("""
            insert into sli_agents(id,host_id,key_fingerprint) values
                ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000011',repeat('a',64)),
                ('00000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000012',repeat('b',64));
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt,received_at)
            select case when n<=100000 then '00000000-0000-4000-8000-000000000001' else '00000000-0000-4000-8000-000000000002' end::uuid,
                case when n%11=0 then 'sli.file-audit' else 'sli.windows.ad-dc' end,n,md5('health:'||n)::uuid,repeat('a',64),
                jsonb_build_object('policy_revision',case when n<=2 then 'old' else '2' end,'channel',case when n%13=0 then null else 'envelope-channel' end),
                '{"status":"committed"}'::jsonb,
                -- Equal times require the receipt sequence tie-breaker; inbox times deliberately differ.
                now()-interval '10 days'+(n/2)*interval '1 second'
            from generate_series(1,200000) n;
            """, db) { CommandTimeout = 120 }) await seed.ExecuteNonQueryAsync(ct);
        // Commit batches so migration 297 does not accumulate a long chain of
        // updates to the same few stream maxima in one synthetic transaction.
        for (int first = 1; first <= 200000; first += 10000) {
            await using var inbox = new NpgsqlCommand("""
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at,imported_at)
            select packet_id,envelope,jsonb_build_object('contract','sli.collection-packet.v1',
                'header',jsonb_build_object('channel',case when sequence%13=0 then null when sequence%17=0 then ''
                    when sequence%3=0 then 'Security' when sequence%3=1 then 'System' else 'Directory Service' end),
                'context',jsonb_build_object('ad_dc',jsonb_build_object('read_error',case when sequence%7=0 then 'fixture_error' else '' end),
                    'read_error',case when sequence%5=0 then '"file_audit_read_failed"'::jsonb
                        when sequence%5=1 then '"unrecognized"'::jsonb else 'null'::jsonb end)),
                '[]'::jsonb,now()-sequence*interval '1 second',
                case when sequence%100=0 then null else now()-interval '1 day'+(sequence%101)*interval '1 second' end
            from sli_agent_receipts where sequence between @first and @last;
            """, db) { CommandTimeout = 60 };
            inbox.Parameters.AddWithValue("first", first); inbox.Parameters.AddWithValue("last", first + 9999);
            await inbox.ExecuteNonQueryAsync(ct);
        }
        await using (var finish = new NpgsqlCommand("""
            insert into sli_agent_packet_quarantine(packet_id,reason_code,event_ordinal)
            select packet_id,case when sequence%400=0 then 'source_event_allocation_hash_mismatch'
                else 'published_source_event_hash_mismatch' end,0
            from sli_agent_receipts where sequence%200=0;
            analyze sli_agent_receipts; analyze sli_agent_packet_inbox;
            analyze sli_agent_stream_import_health; analyze sli_agent_packet_quarantine;
            """, db) { CommandTimeout = 120 }) await finish.ExecuteNonQueryAsync(ct);

        var requested = new JsonArray();
        void Want(string module, string revision, string? channel, bool snapshot = false) => requested.Add(new JsonObject
            { ["agent_id"] = Agent, ["module_id"] = module, ["revision"] = revision, ["channel"] = channel, ["snapshot"] = snapshot });
        foreach (string module in new[] { "sli.windows.ad-dc", "sli.file-audit" })
            foreach (string? channel in new string?[] { "Security", "System", "Directory Service", null, "" }) Want(module, "2", channel);
        Want("sli.windows.ad-dc", "old", "System"); Want("sli.windows.ad-dc", "old", "Security");
        Want("sli.ad-snapshot", "2", null, true);
        for (int n = requested.Count; n < 40; n++) Want("sli.windows.ad-dc", "2", "missing-" + n);
        string input = requested.ToJsonString();
        async Task<string> Read(string sql)
        {
            await using var command = new NpgsqlCommand("select jsonb_agg(to_jsonb(s) order by s.module_id,s.revision,s.channel nulls first)::text from (" + sql + ") s", db) { CommandTimeout = 180 };
            command.Parameters.AddWithValue("requested", input);
            var rows=JsonNode.Parse((string)(await command.ExecuteScalarAsync(ct))!)!.AsArray();
            // Compare the existing stream measurements independently of additive diagnostics.
            foreach(var row in rows.OfType<JsonObject>()) {
                row.Remove("import_failure_reason"); row.Remove("import_failure_at");
            }
            return rows.ToJsonString();
        }
        await PostCollectionPostgres.Sql(db, "set jit=off", ct);
        var watch = Stopwatch.StartNew(); string expected = await Read(LegacyStreams);
        output.WriteLine($"Legacy 40 streams: {watch.Elapsed.TotalMilliseconds:F1} ms");
        var before = JsonNode.Parse(expected)!.AsArray(); Assert.Equal(40, before.Count);
        var old = before.Single(s => (string?)s!["revision"] == "old" && (string?)s["channel"] == "System")!;
        Assert.NotNull(old["last_packet_at"]);
        Assert.All(before.Where(s => ((string?)s!["channel"])?.StartsWith("missing-") == true), s => {
            Assert.Null(s!["last_packet_at"]); Assert.Null(s["last_import_at"]); Assert.Null(s["pending_since"]);
            Assert.Null(s["read_error"]); Assert.Equal(0, (long)s["historical_unimported_packets"]!); Assert.Null(s["historical_error_at"]);
        });
        {
            watch.Restart(); await fixture.Pg.ApplyFileAsync(forward, null, ct);
            output.WriteLine($"313 build/backfill: {watch.Elapsed.TotalMilliseconds:F1} ms");
            await PostCollectionPostgres.Sql(db, "analyze sli_agent_stream_receipts", ct);
        }
        await PostCollectionPostgres.Sql(db, "set role adlog_user; set statement_timeout='3s'", ct);
        watch.Restart(); string actual = await Read(historicalStreams);
        output.WriteLine($"Optimized 40 streams: {watch.Elapsed.TotalMilliseconds:F1} ms");
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(3)); Assert.Equal(expected, actual);
        // The frozen Python reader must still work on 313; its legacy plan needs
        // the separate reference budget, never the production .NET timeout.
        await PostCollectionPostgres.Sql(db, "set statement_timeout=0", ct);
        Assert.Equal(expected, await Read(python));
        await PostCollectionPostgres.Sql(db, "set statement_timeout='3s'", ct);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user") }).Build();
        var queries = new OperationsQueries(new PostgresConnectionFactory(config));
        Assert.Equal(40, (await queries.ReadAsync(historicalStreams, ct, ("requested", input))).Count);
        await using var explain = new NpgsqlCommand("explain(analyze,buffers,format json) " + historicalStreams, db);
        explain.Parameters.AddWithValue("requested", input);
        string plan = (string)(await explain.ExecuteScalarAsync(ct))!;
        var explained = JsonNode.Parse(plan)![0]!;
        output.WriteLine($"Plan execution: {explained["Execution Time"]} ms; shared hits: {explained["Plan"]?["Shared Hit Blocks"]}; reads: {explained["Plan"]?["Shared Read Blocks"]}");
        void CheckPlan(JsonNode? node) {
            if (node is JsonObject obj) {
                if ((string?)obj["Relation Name"] == "sli_agent_receipts") {
                    output.WriteLine($"Receipt probe: {obj["Node Type"]}, rows={obj["Actual Rows"]}, loops={obj["Actual Loops"]}, index={obj["Index Name"]}");
                    Assert.Contains((string?)obj["Node Type"], new[] { "Index Scan", "Index Only Scan" });
                    Assert.True((double)obj["Actual Loops"]! <= 8000, "Receipt history was rescanned");
                    Assert.True((double)obj["Actual Rows"]! <= 1);
                }
                if ((string?)obj["Relation Name"] == "sli_agent_stream_receipts") {
                    output.WriteLine($"Stream probe: rows={obj["Actual Rows"]}, loops={obj["Actual Loops"]}, index={obj["Index Name"]}");
                    Assert.Equal("sli_agent_stream_receipts_lookup", (string?)obj["Index Name"]);
                    Assert.True((double)obj["Actual Rows"]! <= 1);
                }
                foreach (var pair in obj) CheckPlan(pair.Value);
            } else if (node is JsonArray array) foreach (var child in array) CheckPlan(child);
        }
        CheckPlan(JsonNode.Parse(plan));
        await PostCollectionPostgres.Sql(db, "reset role; set statement_timeout=0", ct);
        {
            await using var size = new NpgsqlCommand("select pg_total_relation_size('sli_agent_stream_receipts')", db);
            output.WriteLine($"313 lookup+indexes bytes: {await size.ExecuteScalarAsync(ct)}");
            await fixture.Pg.ApplyFileAsync(rollback, null, ct);
            Assert.Equal(expected, await Read(LegacyStreams));
            await fixture.Pg.ApplyFileAsync(forward, null, ct);
            Assert.Equal(expected, await Read(historicalStreams));
        }
        requested.Clear();
        Want("sli.windows.ad-dc", "tie", "System"); Want("sli.windows.ad-dc", "old", "System"); input = requested.ToJsonString();
        // Ingest, exact receipt order (not inbox time), nullable flags, retention,
        // and transactional rollback must all keep the indexed join equivalent.
        await using (var tx = await db.BeginTransactionAsync(ct)) {
            await PostCollectionPostgres.Sql(db, """
                insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt,received_at)
                select '00000000-0000-4000-8000-000000000001','sli.windows.ad-dc',9223372036854775805+n,
                    md5('tie:'||n)::uuid,repeat('a',64),'{}','{"status":"committed"}','1960-01-01T00:00:00.000001Z'
                from generate_series(1,2) n;
                insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at)
                select md5('tie:'||n)::uuid,'{"policy_revision":"tie","channel":"ignored-envelope-channel"}',
                    jsonb_build_object('contract','sli.collection-packet.v1','header',jsonb_build_object('channel','System'),
                        'context',jsonb_build_object('ad_dc',jsonb_build_object('read_error',case when n=1 then 'fixture_error' else '' end))),
                    '[]',now()-n*interval '1 day' from generate_series(1,2) n;
                """, ct);
            Assert.Equal(await Read(LegacyStreams), await Read(historicalStreams));
            var tied = JsonNode.Parse(await Read(historicalStreams))!.AsArray().Single(s => (string?)s!["revision"] == "tie")!;
            Assert.False((bool)tied["read_error"]!);
            Assert.Equal(DateTimeOffset.Parse("1960-01-01T00:00:00.000001Z"), DateTimeOffset.Parse((string)tied["last_packet_at"]!));
            await PostCollectionPostgres.Sql(db, "delete from sli_agent_packet_inbox where packet_id=md5('tie:2')::uuid", ct);
            Assert.Equal(await Read(LegacyStreams), await Read(historicalStreams));
            tied = JsonNode.Parse(await Read(historicalStreams))!.AsArray().Single(s => (string?)s!["revision"] == "tie")!;
            Assert.True((bool)tied["read_error"]!);
            await PostCollectionPostgres.Sql(db, "update sli_agent_packet_inbox set imported_at=now()+interval '1 day' where packet_id=md5('health:1')::uuid", ct);
            Assert.Equal(await Read(LegacyStreams), await Read(historicalStreams));
            await tx.RollbackAsync(ct);
        }
        Assert.Equal(await Read(LegacyStreams), await Read(historicalStreams));
        await using (var privileges = new NpgsqlCommand("""
            select relowner='adlog_storage_owner'::regrole
                and has_table_privilege('adlog_user',oid,'SELECT')
                and not has_table_privilege('adlog_user',oid,'INSERT,UPDATE,DELETE,TRUNCATE')
                and not has_function_privilege('adlog_user','public.record_agent_stream_receipt_v313()','EXECUTE')
            from pg_class where oid='public.sli_agent_stream_receipts'::regclass
            """, db)) Assert.True((bool)(await privileges.ExecuteScalarAsync(ct))!);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
