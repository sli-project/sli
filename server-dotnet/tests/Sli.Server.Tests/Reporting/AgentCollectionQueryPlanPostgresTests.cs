using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Operations;
using Sli.Server.Tests.Agents;
using Sli.Server.Workstations;
using Xunit;

namespace Sli.Server.Tests.Reporting;

// The same disposable, reduced input schema as the Python query-plan tests.
// Read models, backfill and write triggers are the real migration SQL, not mocks.
public sealed class AgentCollectionQueryPlanPostgresTests(ITestOutputHelper output)
{
    const string Agent = "00000000-0000-4000-8000-000000000001";
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static JsonObject Wanted(string agent = Agent, string module = "sli.windows.ad-dc", string revision = "2", string? channel = "Security", bool snapshot = false) =>
        new() { ["agent_id"] = agent, ["module_id"] = module, ["revision"] = revision, ["channel"] = channel, ["snapshot"] = snapshot };

    static async Task Sql(NpgsqlConnection db, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, db) { CommandTimeout = 0 };
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(Ct);
    }

    static async Task SeedSchema(NpgsqlConnection db) => await Sql(db, """
        set timezone='UTC'; set jit=off;
        create table sli_agent_receipts(
            agent_id uuid not null,module_id text not null,sequence bigint not null,
            packet_id uuid not null unique,received_at timestamptz not null,
            primary key(agent_id,module_id,sequence));
        create table sli_agent_packet_inbox(
            packet_id uuid primary key,imported_at timestamptz,collection_revision text,
            collection_channel text,collection_read_error boolean,packet jsonb,
            received_at timestamptz not null default now(),
            module_disabled_at timestamptz check(module_disabled_at is null or imported_at is null));
        create table sli_agent_packet_quarantine(
            packet_id uuid primary key,reason_code text not null,quarantined_at timestamptz not null);
        create table sli_agent_snapshot_cycles(
            agent_id uuid,module_id text,policy jsonb,created_at timestamptz,
            completed_at timestamptz,published_at timestamptz,publication_state text);
        create index sli_agent_receipts_collection_health
            on sli_agent_receipts(agent_id,received_at desc) include(packet_id,module_id,sequence);
        create index sli_agent_receipts_module_received
            on sli_agent_receipts(module_id,received_at desc) include(packet_id);
        create index sli_agent_inbox_collection_health on sli_agent_packet_inbox(packet_id)
            include(collection_revision,collection_channel,collection_read_error,imported_at);
        create index sli_agent_inbox_imported_prefix
            on sli_agent_packet_inbox(imported_at desc,packet_id) where imported_at is not null;
        create index sli_agent_packet_inbox_pending
            on sli_agent_packet_inbox(received_at,packet_id) where imported_at is null;
        """);

    static async Task InstallReadModels(NpgsqlConnection db)
    {
        string migrations = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations");
        // Apply the actual table/trigger/backfill sections to the reduced Python
        // fixture. Do not manufacture migration-ledger entries or change constraints.
        foreach (string migration in new[] { "297_agent_stream_import_health", "313_agent_collection_stream_index" })
        {
            string sql = File.ReadAllText(Path.Combine(migrations, migration + ".sql")).Replace("\r\n", "\n");
            int start = sql.IndexOf("create table public.sli_agent_stream_", StringComparison.Ordinal);
            int end = sql.IndexOf(migration.StartsWith("297", StringComparison.Ordinal)
                ? "reset role;" : "insert into public.schema_migrations", start, StringComparison.Ordinal);
            Assert.True(start >= 0 && end > start);
            // Migrations revoke/grant access to this role, just as on the native schema.
            await Sql(db, sql[start..end]);
        }
    }

    static async Task<JsonArray> Read(NpgsqlConnection db, JsonArray requested, string? sql = null)
    {
        await using var command = new NpgsqlCommand("select coalesce(jsonb_agg(to_jsonb(s) order by s.agent_id,s.module_id,s.revision,s.channel nulls first),'[]'::jsonb)::text from (" + (sql ?? OperationsSql.Streams) + ") s", db) { CommandTimeout = 0 };
        command.Parameters.AddWithValue("requested", requested.ToJsonString());
        return JsonNode.Parse((string)(await command.ExecuteScalarAsync(Ct))!)!.AsArray();
    }

    static async Task<JsonNode> Plan(NpgsqlConnection db, string sql, string parameter, object value)
    {
        await using var command = new NpgsqlCommand("explain(analyze,buffers,format json) " + sql, db) { CommandTimeout = 0 };
        command.Parameters.AddWithValue(parameter, value);
        return JsonNode.Parse((string)(await command.ExecuteScalarAsync(Ct))!)![0]!;
    }

    static IEnumerable<JsonNode> Nodes(JsonNode node)
    {
        yield return node;
        foreach (var child in node["Plans"] as JsonArray ?? [])
            foreach (var nested in Nodes(child!)) yield return nested;
    }

    static DateTimeOffset Time(JsonNode? node) => DateTimeOffset.Parse((string)node!, CultureInfo.InvariantCulture);

    [Theory]
    [InlineData("1960-01-01T00:00:00.000001Z", "1960-01-01T00:00:00.000002Z", 1L, 2L, false)]
    [InlineData("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", long.MaxValue - 1, long.MaxValue, false)]
    [InlineData("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", 1L, 2L, null)]
    public async Task Latest_receipt_preserves_microseconds_bigint_and_nullable_flag(string first, string last, long firstSequence, long lastSequence, bool? flag)
    {
        await using var fixture = new PostCollectionPostgres(canonicalSchema: true); await fixture.StartAsync(Ct);
        await using var db = await fixture.OpenAsync(Ct); await SeedSchema(db);
        await Sql(db, "create role adlog_user");
        foreach (var sample in new[] { (first, firstSequence, (bool?)true), (last, lastSequence, flag) })
        {
            Guid packet = Guid.NewGuid();
            await Sql(db, "insert into sli_agent_receipts values(@agent,'sli.windows.ad-dc',@sequence,@packet,@received)",
                ("agent", Guid.Parse(Agent)), ("sequence", sample.Item2), ("packet", packet), ("received", DateTimeOffset.Parse(sample.Item1, CultureInfo.InvariantCulture)));
            await Sql(db, "insert into sli_agent_packet_inbox values(@packet,@received,'2','Security',@flag,'{}')",
                ("packet", packet), ("received", DateTimeOffset.Parse(sample.Item1, CultureInfo.InvariantCulture)), ("flag", sample.Item3));
        }
        await InstallReadModels(db);
        var row = Assert.Single(await Read(db, new(Wanted())))!;
        Assert.Equal(flag, (bool?)row["read_error"]);
        Assert.Equal(DateTimeOffset.Parse(last, CultureInfo.InvariantCulture), Time(row["last_packet_at"]));
        Assert.Null(row["pending_since"]);
    }

    [Fact]
    public async Task Current_revision_keeps_old_live_backlog_terminal_conflicts_and_snapshot_revisions_separate()
    {
        await using var fixture = new PostCollectionPostgres(canonicalSchema: true); await fixture.StartAsync(Ct);
        await using var db = await fixture.OpenAsync(Ct); await SeedSchema(db);
        await Sql(db, """
            create role adlog_user;
            insert into sli_agent_receipts
            select '00000000-0000-4000-8000-000000000001'::uuid,'sli.windows.ad-dc',n,md5(n::text)::uuid,
                   now()-case n when 2 then interval '30 days' when 3 then interval '40 days'
                        when 6 then interval '60 days' else interval '1 minute' end
            from generate_series(1,6) n;
            insert into sli_agent_packet_inbox
            select packet_id,case when sequence in (2,3,6) then null else received_at end,
                   case when sequence=4 then '9' else '2' end,
                   case when sequence=5 then 'System' else 'Security' end,
                   sequence in (4,5),'{}'::jsonb from sli_agent_receipts;
            update sli_agent_packet_inbox set module_disabled_at=now()
              where packet_id=(select packet_id from sli_agent_receipts where sequence=6);
            insert into sli_agent_packet_quarantine
            select packet_id,'source_event_allocation_hash_mismatch',received_at from sli_agent_receipts where sequence=3;
            insert into sli_agent_snapshot_cycles values
                ('00000000-0000-4000-8000-000000000001','sli.ad-snapshot','{"policy_revision":"1"}',
                 '2025-01-01',null,null,'pending'),
                ('00000000-0000-4000-8000-000000000001','sli.ad-snapshot','{"policy_revision":"2"}',
                 '2025-02-01','2025-02-02','2025-02-03','published');
            """);
        await InstallReadModels(db);
        var rows = await Read(db, new(Wanted(), Wanted(module: "sli.ad-snapshot", channel: null, snapshot: true)));
        Assert.Equal(2, rows.Count); Assert.All(rows, row => Assert.Equal("2", (string?)row!["revision"]));
        var events = rows.Single(row => (string?)row!["module_id"] == "sli.windows.ad-dc")!;
        await using var pending = new NpgsqlCommand("select received_at from sli_agent_receipts where sequence=2", db);
        Assert.Equal(new DateTimeOffset((DateTime)(await pending.ExecuteScalarAsync(Ct))!), Time(events["pending_since"]));
        Assert.Equal(1, (long)events["historical_unimported_packets"]!); Assert.NotNull(events["historical_error_at"]);
        Assert.False((bool)events["read_error"]!);
        var snapshot = rows.Single(row => (string?)row!["module_id"] == "sli.ad-snapshot")!;
        Assert.Null(snapshot["pending_since"]); Assert.Equal(DateTimeOffset.Parse("2025-02-03T00:00:00Z", CultureInfo.InvariantCulture), Time(snapshot["last_import_at"]));
        var empty = Assert.Single(await Read(db, new(Wanted(revision: "missing"))))!;
        Assert.Null(empty["last_packet_at"]); Assert.Null(empty["last_import_at"]); Assert.Null(empty["pending_since"]);
    }

    [Fact]
    public async Task Unassigned_history_does_not_expand_requested_result()
    {
        await using var fixture = new PostCollectionPostgres(canonicalSchema: true); await fixture.StartAsync(Ct);
        await using var db = await fixture.OpenAsync(Ct); await SeedSchema(db);
        await Sql(db, """
            create role adlog_user;
            insert into sli_agent_receipts
            select '00000000-0000-4000-8000-000000000002'::uuid,'sli.windows.ad-dc',n,md5(n::text)::uuid,
                   '2025-01-01'::timestamptz+n*interval '1 second' from generate_series(1,40000) n;
            insert into sli_agent_packet_inbox
            select packet_id,received_at,'1','Security',false,'{}'::jsonb from sli_agent_receipts;
            analyze sli_agent_receipts; analyze sli_agent_packet_inbox;
            """);
        await InstallReadModels(db);
        var requested = new JsonArray(Wanted());
        var row = Assert.Single(await Read(db, requested))!;
        Assert.Equal(Agent, (string?)row["agent_id"]); Assert.Null(row["last_packet_at"]);
        var plan = await Plan(db, OperationsSql.Streams, "requested", requested.ToJsonString());
        Assert.Equal(1d, (double)plan["Plan"]!["Actual Rows"]!);
    }

    [Fact]
    public async Task Large_history_keeps_all_stream_facts_without_global_import_scan()
    {
        await using var fixture = new PostCollectionPostgres(canonicalSchema: true); await fixture.StartAsync(Ct);
        await using var db = await fixture.OpenAsync(Ct); await SeedSchema(db);
        // Keep the initial 30k-row column statistics until the explicit ANALYZE
        // below, even when a slower test host crosses an autovacuum interval.
        await Sql(db, """
            create role adlog_user;
            alter table sli_agent_receipts set (autovacuum_enabled=false);
            alter table sli_agent_packet_inbox set (autovacuum_enabled=false);
            alter table sli_agent_packet_quarantine set (autovacuum_enabled=false);
            """);
        foreach (var (first, last) in new[] { (1, 30000), (30001, 1060000) })
        {
            await Sql(db, """
                insert into sli_agent_receipts
                select md5('agent-'||(n%2)::text)::uuid,
                       (array['sli.windows.ad-dc','sli.file-audit'])[1+(n/2)%2],n,md5('history-'||n::text)::uuid,
                       '2026-01-01'::timestamptz+n*interval '1 second'
                from generate_series(@first::integer,@last::integer) n;
                insert into sli_agent_packet_inbox
                select packet_id,received_at,'old','Security',false,'{}'::jsonb from sli_agent_receipts
                where sequence between @first and @last;
                """, ("first", first), ("last", last));
            if (first == 1) await Sql(db, "analyze sli_agent_receipts; analyze sli_agent_packet_inbox");
        }
        var agents = new List<string>();
        await using (var command = new NpgsqlCommand("select md5('agent-'||n::text)::uuid::text from generate_series(0,1) n", db))
        await using (var reader = await command.ExecuteReaderAsync(Ct)) while (await reader.ReadAsync(Ct)) agents.Add(reader.GetString(0));
        var requested = new JsonArray();
        foreach (string agent in agents)
            foreach (string module in new[] { "sli.windows.ad-dc", "sli.file-audit" })
                foreach (string? channel in new string?[] { "Security", "System", "Application", null })
                    requested.Add(Wanted(agent: agent, module: module, channel: channel));
        for (int number = 0; number < requested.Count; number++)
        {
            var wanted = requested[number]!;
            foreach (var sample in new[] {
                (1, "30 days", (string?)null, false), (2, "20 days", null, false),
                (3, "1 minute", "2 hours", false), (4, "2 minutes", "1 hour", true),
                (5, "10 days", null, false), (6, "6 days", null, false) })
            {
                Guid packet = Guid.NewGuid();
                await Sql(db, """
                    insert into sli_agent_receipts values(@agent,@module,@sequence,@packet,now()-@age::interval);
                    insert into sli_agent_packet_inbox values(@packet,now()-@imported::interval,'2',@channel,@flag,
                        '{"context":{"read_error":"file_audit_read_failed"}}');
                    """, ("agent", Guid.Parse((string)wanted["agent_id"]!)), ("module", (string)wanted["module_id"]!),
                    ("sequence", 2000000L + sample.Item1 + number * 10), ("packet", packet),
                    ("age", sample.Item2), ("imported", sample.Item3), ("channel", (string?)wanted["channel"]), ("flag", sample.Item4));
                if (sample.Item1 is 1 or 5 or 6)
                    await Sql(db, "insert into sli_agent_packet_quarantine values(@packet,@reason,now()-@age::interval)",
                        ("packet", packet), ("reason", sample.Item1 == 5 ? "other" : number % 2 == 0 ? "published_source_event_hash_mismatch" : "source_event_allocation_hash_mismatch"), ("age", sample.Item2));
            }
        }
        foreach (string agent in agents) requested.Add(Wanted(agent: agent, module: "sli.ad-snapshot", channel: null, snapshot: true));
        await Sql(db, """
            insert into sli_agent_snapshot_cycles values
                (@agent,'sli.ad-snapshot','{"policy_revision":"2"}','2025-01-01',null,null,'pending'),
                (@agent,'sli.ad-snapshot','{"policy_revision":"2"}','2025-02-01','2025-02-02','2025-02-03','published');
            """, ("agent", Guid.Parse(agents[0])));
        await InstallReadModels(db);
        foreach (string table in new[] { "sli_agent_receipts", "sli_agent_packet_inbox", "sli_agent_packet_quarantine" })
            await Sql(db, "vacuum " + table);
        string reference = File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(), "tests/reporting/sql/agent_collection_streams_before_t108.sql"))
            .Replace("?::jsonb", "@requested::jsonb");
        await using (var tx = await db.BeginTransactionAsync(Ct))
        {
            var expected = await Read(db, requested, reference);
            foreach (bool analyze in new[] { false, true })
            {
                if (analyze) await Sql(db, "analyze sli_agent_receipts; analyze sli_agent_packet_inbox; analyze sli_agent_packet_quarantine");
                var actual = await Read(db, requested);
                Assert.Equal(18, actual.Count);
                for (int i = 0; i < actual.Count; i++)
                {
                    var comparable = actual[i]!.DeepClone().AsObject();
                    comparable.Remove("import_failure_reason");
                    comparable.Remove("import_failure_at");
                    // The frozen query predates terminal quarantine and reports those rows as pending.
                    if ((string?)comparable["module_id"] != "sli.ad-snapshot")
                        comparable["pending_since"] = expected[i]!["pending_since"]?.DeepClone();
                    Assert.True(JsonNode.DeepEquals(expected[i], comparable), $"Stream identity, receipt or import history changed: {comparable}");
                }
                foreach (var row in actual.Where(row => (string?)row!["module_id"] != "sli.ad-snapshot"))
                {
                    Assert.Equal(1, (long)row!["historical_unimported_packets"]!);
                    Assert.NotNull(row["historical_error_at"]);
                    string module = (string)row["module_id"]!;
                    await using var backlog = new NpgsqlCommand("""
                        select r.received_at from sli_agent_receipts r join sli_agent_packet_inbox i using(packet_id)
                        where r.agent_id=@agent and r.module_id=@module and i.collection_channel is not distinct from @channel
                          and r.sequence > 2000000 and r.sequence % 10=2
                        """, db);
                    backlog.Parameters.AddWithValue("agent", Guid.Parse((string)row["agent_id"]!));
                    backlog.Parameters.AddWithValue("module", module);
                    backlog.Parameters.AddWithValue("channel", NpgsqlTypes.NpgsqlDbType.Text, (object?)(string?)row["channel"] ?? DBNull.Value);
                    Assert.Equal(new DateTimeOffset((DateTime)(await backlog.ExecuteScalarAsync(Ct))!), Time(row["pending_since"]));
                    Assert.Contains((string?)row["import_failure_reason"], new[] { "published_source_event_hash_mismatch", "source_event_allocation_hash_mismatch" });
                    Assert.True(Time(row["historical_error_at"]) < Time(row["import_failure_at"]));
                    Assert.Equal(module == "sli.file-audit", (bool)row["read_error"]!);
                }
                var events = actual.Single(row => (string?)row!["agent_id"] == agents[0] && (string?)row["module_id"] == "sli.windows.ad-dc" && (string?)row["channel"] == "Security")!;
                await using var imported = new NpgsqlCommand("select i.imported_at from sli_agent_packet_inbox i join sli_agent_receipts r using(packet_id) where r.agent_id=@agent and r.module_id='sli.windows.ad-dc' and r.sequence=2000004", db) { CommandTimeout = 0 };
                imported.Parameters.AddWithValue("agent", Guid.Parse(agents[0]));
                Assert.Equal(new DateTimeOffset((DateTime)(await imported.ExecuteScalarAsync(Ct))!), Time(events["last_import_at"]));
                var plan = await Plan(db, OperationsSql.Streams, "requested", requested.ToJsonString());
                var nodes = Nodes(plan["Plan"]!).ToArray();
                Assert.DoesNotContain(nodes, n => (string?)n["Index Name"] == "sli_agent_inbox_imported_prefix");
                Assert.DoesNotContain(nodes, n => (string?)n["Alias"] is "import_packet" or "import_receipt");
                Assert.Contains(nodes, n => (string?)n["Relation Name"] == "sli_agent_stream_import_health");
                foreach (var node in nodes.Where(n => (string?)n["Relation Name"] is "sli_agent_receipts" or "sli_agent_packet_inbox" or "sli_agent_stream_receipts"))
                {
                    double examined = (double)node["Actual Rows"]! + ((double?)node["Rows Removed by Filter"] ?? 0);
                    Assert.True(examined * (double)node["Actual Loops"]! < 5000, node.ToJsonString());
                }
                Assert.Null(plan["JIT"]);
                double buffers = new[] { "Shared Hit Blocks", "Shared Read Blocks", "Local Hit Blocks", "Local Read Blocks" }.Sum(key => (double?)plan["Plan"]![key] ?? 0);
                Assert.True(buffers < 20000, plan.ToJsonString());
                Assert.True((double)plan["Execution Time"]! < 300, plan.ToJsonString());
                output.WriteLine($"Synthetic only: history=1060000 streams=18 analyzed={analyze} execution_ms={plan["Execution Time"]} buffers={buffers}");
            }
        }
    }

    [Fact]
    public async Task Legacy_station_name_uses_four_indexed_lookups_instead_of_observation_scan()
    {
        await using var fixture = new PostCollectionPostgres(canonicalSchema: true); await fixture.StartAsync(Ct);
        await using var db = await fixture.OpenAsync(Ct);
        await Sql(db, """
            set jit=off;
            create schema sli_plugin_workstations;
            create table sli_plugin_workstations.observations(
                id text primary key,agent_key text,family text,observed_at timestamptz,source_xml text);
            create index workstation_report_window on sli_plugin_workstations.observations(agent_key,family,observed_at,id);
            insert into sli_plugin_workstations.observations
            select md5(n::text||family),'fixture-agent',family,'2026-01-01'::timestamptz+n*interval '1 second','<Event/>'
            from generate_series(1,40000) n cross join (values ('logons'),('processes'),('usb'),('protection')) f(family);
            analyze sli_plugin_workstations.observations;
            """);
        await using (var command = new NpgsqlCommand(WorkstationReports.EventNamesSql, db) { CommandTimeout = 0 })
        {
            command.Parameters.AddWithValue("p0", new[] { "fixture-agent" });
            await using var reader = await command.ExecuteReaderAsync(Ct); int count = 0;
            while (await reader.ReadAsync(Ct)) { Assert.Equal("fixture-agent", reader.GetString(0)); Assert.Equal("<Event/>", reader.GetString(1)); count++; }
            Assert.Equal(4, count);
        }
        var plan = await Plan(db, WorkstationReports.EventNamesSql, "p0", new[] { "fixture-agent" });
        var lookups = Nodes(plan["Plan"]!).Where(n => (string?)n["Relation Name"] == "observations").ToArray();
        Assert.NotEmpty(lookups); Assert.All(lookups, n => Assert.Equal("workstation_report_window", (string?)n["Index Name"]));
        Assert.Equal(4, lookups.Sum(n => (double)n["Actual Rows"]! * (double)n["Actual Loops"]!));
        output.WriteLine($"Synthetic only: history=160000 event_rows_read=4 execution_ms={plan["Execution Time"]}");
    }
}
