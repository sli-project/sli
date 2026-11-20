using System.Globalization;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.InstallationSetup;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.InstallationSetup;

// Parity with tests/reporting/test_plugin_receipts_query_plan_postgres.py.
// Each test owns a disposable cluster, never an inherited DSN or stand database.
public sealed class PluginReceiptsQueryPlanPostgresTests
{
    static readonly string[] Modules = ["sli.ad-snapshot", "sli.file-audit", "sli.gpo-snapshot", "sli.radius-accounting",
        "sli.vpn-nps", "sli.windows.ad-dc", "sli.windows.ad-dc-history", "sli.workstations"];
    static readonly string RuntimeSql = InstallationService.Sql("plugin-receipts.sql");
    const string BaselineSql = """
        select module_id,max(last_received_at) as last_received_at,
               max(last_imported_at) as last_imported_at,
               max(last_snapshot_completed_at) as last_snapshot_completed_at
        from (
            select r.module_id,max(r.received_at) as last_received_at,
                   max(i.imported_at) filter(where r.module_id not in ('sli.ad-snapshot','sli.gpo-snapshot')) as last_imported_at,
                   null::timestamptz as last_snapshot_completed_at
            from sli_agent_receipts r left join sli_agent_packet_inbox i using(packet_id)
            where r.module_id=any(@p0)
            group by r.module_id
            union all
            select module_id,null::timestamptz,
                   max(published_at) filter(where publication_state='published'),
                   max(completed_at) filter(where transport_state='complete')
            from sli_agent_snapshot_cycles where module_id=any(@p1)
            group by module_id
        ) facts group by module_id
        """;
    sealed record Fact(string Module, DateTimeOffset? Received, DateTimeOffset? Imported, DateTimeOffset? Completed);
    static DateTimeOffset? Stamp(JsonNode? value) => value is null ? null : DateTimeOffset.Parse(value.ToString(), CultureInfo.InvariantCulture);
    static DateTimeOffset Utc(string day) => DateTimeOffset.Parse(day + "T00:00:00Z", CultureInfo.InvariantCulture);
    static async Task<Fact[]> Rows(IInstallationDatabase database, string sql, string[] modules, CancellationToken ct)
    {
        var rows = await database.ReadAsync(s => s.QueryAsync(sql, ct, modules, modules), ct);
        return rows.OfType<JsonObject>().Select(r => new Fact(r["module_id"]!.ToString(), Stamp(r["last_received_at"]),
            Stamp(r["last_imported_at"]), Stamp(r["last_snapshot_completed_at"]))).OrderBy(r => r.Module, StringComparer.Ordinal).ToArray();
    }
    static async Task Compare(IInstallationDatabase database, CancellationToken ct, params string[][] scopes)
    {
        foreach (var modules in scopes)
            Assert.Equal(await Rows(database, BaselineSql, modules, ct), await Rows(database, RuntimeSql, modules, ct));
    }
    static async Task<InstallationDatabase> Prepare(NpgsqlConnection db, string dsn, CancellationToken ct)
    {
        // Same compact queried columns and existing indexes as the Python oracle.
        // No payloads, production DDL, new hot-layer indexes or timing SLA.
        await PostCollectionPostgres.Sql(db, """
            create table sli_agent_receipts(
                agent_id uuid not null,module_id text not null,sequence bigint not null,
                packet_id uuid not null unique,received_at timestamptz not null,
                primary key(agent_id,module_id,sequence));
            create table sli_agent_packet_inbox(
                packet_id uuid primary key,received_at timestamptz not null,
                imported_at timestamptz,collection_revision text,
                collection_channel text,collection_read_error boolean);
            create table sli_agent_snapshot_cycles(
                module_id text not null,transport_state text not null,
                completed_at timestamptz,publication_state text not null,published_at timestamptz);
            create index receipt_existing on sli_agent_receipts(agent_id,received_at desc)
                include(packet_id,module_id,sequence);
            create index inbox_existing on sli_agent_packet_inbox(packet_id)
                include(collection_revision,collection_channel,collection_read_error,imported_at);
            create index inbox_pending on sli_agent_packet_inbox(received_at,packet_id) where imported_at is null;
            """, ct);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["ConnectionStrings:Sli"] = dsn
        }).Build();
        return new InstallationDatabase(new PostgresConnectionFactory(configuration));
    }

    [Fact]
    public async Task Plugin_receipt_read_uses_no_write_transaction_or_statement_deadline()
    {
        await using var f = new InstallationFixture();
        f.Database.Override = (sql, _) => sql == RuntimeSql ? new JsonArray(new JsonObject {
            ["module_id"] = "sli.windows.ad-dc", ["last_received_at"] = "2026-01-03T00:00:00Z",
            ["last_imported_at"] = "2026-02-01T00:00:00Z", ["last_snapshot_completed_at"] = null
        }) : null;
        await f.StartAsync();
        var result = await f.SendAsync("GET", "/api/v1/plugins");
        Assert.Equal(200, result.Status);
        var receipts = result.Body["items"]![0]!["data_receipts"]!;
        Assert.Equal("observed", receipts["state"]!.ToString());
        Assert.Equal(Utc("2026-01-03"), Stamp(receipts["last_received_at"]));
        Assert.Equal(Utc("2026-02-01"), Stamp(receipts["last_imported_at"]));
        Assert.False(Assert.Single(f.Database.Calls, c => c.Sql == RuntimeSql).Write);
        Assert.DoesNotContain(f.Database.Calls, c => c.Sql.Contains("statement_timeout", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(0, f.Database.Commits);
    }

    [Fact]
    public async Task Exact_receipt_import_and_snapshot_facts_survive_prefix_boundaries_and_orphans()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(ct);
        await using var db = await pg.OpenAsync(ct);
        var database = await Prepare(db, pg.ConnectionString, ct);
        await PostCollectionPostgres.Sql(db, """
            insert into sli_agent_receipts values
              ('00000000-0000-4000-8000-000000000001','sli.windows.ad-dc',1,md5('old')::uuid,'2026-01-01'),
              ('00000000-0000-4000-8000-000000000001','sli.windows.ad-dc',2,md5('new')::uuid,'2026-01-03'),
              ('00000000-0000-4000-8000-000000000002','sli.windows.ad-dc',1,md5('tie')::uuid,'2026-01-03'),
              ('00000000-0000-4000-8000-000000000001','sli.ad-snapshot',1,md5('chunk')::uuid,'2026-01-05'),
              ('00000000-0000-4000-8000-000000000001','sli.file-audit',1,md5('orphan')::uuid,'2026-01-06');
            insert into sli_agent_packet_inbox(packet_id,received_at,imported_at) values
              (md5('old')::uuid,'2026-01-01','2026-02-01'),
              (md5('new')::uuid,'2026-01-03',null),
              (md5('tie')::uuid,'2026-01-03','2026-01-04'),
              (md5('chunk')::uuid,'2026-01-05','2026-03-01');
            insert into sli_agent_snapshot_cycles values
              ('sli.ad-snapshot','complete','2026-01-05','pending',null),
              ('sli.ad-snapshot','complete','2026-01-04','published','2026-01-07'),
              ('sli.gpo-snapshot','complete','2026-01-06','superseded',null),
              ('sli.gpo-snapshot','pending',null,'pending',null);
            """, ct);
        await Compare(database, ct, [], Modules, ["sli.windows.ad-dc"], ["sli.ad-snapshot"], ["sli.gpo-snapshot"],
            ["sli.workstations"], ["sli.windows.ad-dc", "sli.windows.ad-dc", "unknown"]);
        Assert.Equal(new[] {
            new Fact("sli.ad-snapshot", Utc("2026-01-05"), Utc("2026-01-07"), Utc("2026-01-05")),
            new Fact("sli.file-audit", Utc("2026-01-06"), null, null),
            new Fact("sli.gpo-snapshot", null, null, Utc("2026-01-06")),
            new Fact("sli.windows.ad-dc", Utc("2026-01-03"), Utc("2026-02-01"), null)
        }, await Rows(database, RuntimeSql, Modules, ct));

        // More than the entire 1024-row optimization prefix belongs to another module.
        await PostCollectionPostgres.Sql(db, """
            insert into sli_agent_receipts
              select '00000000-0000-4000-8000-000000000003'::uuid,'unrequested',n,
                md5('unrequested-'||n)::uuid,'2026-01-01'::timestamptz from generate_series(1,1100) n;
            insert into sli_agent_packet_inbox(packet_id,received_at,imported_at)
              select packet_id,received_at,'2032-01-01'::timestamptz from sli_agent_receipts where module_id='unrequested';
            insert into sli_agent_receipts values
              ('00000000-0000-4000-8000-000000000004','sli.workstations',1,md5('pending')::uuid,'2026-01-01');
            insert into sli_agent_packet_inbox(packet_id,received_at,imported_at) values(md5('pending')::uuid,'2026-01-01',null);
            """, ct);
        await Compare(database, ct, Modules, ["sli.workstations"], ["sli.windows.ad-dc"], ["absent"], []);
        foreach (string day in new[] { "2032-01-01", "2033-01-01" })
        {
            await using var update = new NpgsqlCommand("update sli_agent_packet_inbox set imported_at=@stamp where packet_id=md5('old')::uuid", db);
            update.Parameters.AddWithValue("stamp", Utc(day)); await update.ExecuteNonQueryAsync(ct);
            await Compare(database, ct, Modules);
            Assert.Equal(Utc(day), Assert.Single(await Rows(database, RuntimeSql, ["sli.windows.ad-dc"], ct)).Imported);
        }
        await PostCollectionPostgres.Sql(db, """
            delete from sli_agent_receipts where module_id='unrequested';
            update sli_agent_packet_inbox i set imported_at='2034-01-01'
              where not exists(select 1 from sli_agent_receipts r where r.packet_id=i.packet_id);
            """, ct);
        await Compare(database, ct, Modules, ["sli.workstations"], ["sli.gpo-snapshot"], ["absent"]);
    }

    [Fact]
    public async Task Dominant_sparse_pending_late_and_absent_modules_match_the_unbounded_oracle()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(ct);
        await using var db = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(pg.ConnectionString) { CommandTimeout = 0 }.ConnectionString);
        await db.OpenAsync(ct);
        var database = await Prepare(db, pg.ConnectionString, ct);
        // Original synthetic cardinality; parity assertions do not impose a latency SLA.
        await PostCollectionPostgres.Sql(db, """
            insert into sli_agent_receipts
              select ('00000000-0000-4000-8000-'||lpad((n % 16+1)::text,12,'0'))::uuid,
                case when n % 20 < 12 then 'sli.windows.ad-dc'
                  else (array['sli.file-audit','sli.workstations','sli.vpn-nps','sli.radius-accounting',
                    'sli.windows.ad-dc-history','sli.ad-snapshot','sli.gpo-snapshot','unknown'])[(n % 20-11)::int] end,
                n,md5(n::text)::uuid,'2026-01-01'::timestamptz+(n/2)*interval '1 second'
              from generate_series(1,750000) n;
            insert into sli_agent_packet_inbox
              select packet_id,received_at,case when sequence % 5=0 then null
                when sequence % 101=0 then '2027-01-01'::timestamptz else received_at+interval '1 second' end,
                '1','Security',false from sli_agent_receipts;
            insert into sli_agent_snapshot_cycles
              select module,'complete','2026-01-01'::timestamptz+n*interval '1 hour',
                case when n % 3=0 then 'published' else 'pending' end,
                case when n % 3=0 then '2026-01-01'::timestamptz+n*interval '2 hours' end
              from unnest(array['sli.ad-snapshot','sli.gpo-snapshot']) module cross join generate_series(1,250) n;
            """, ct);
        await using (var count = new NpgsqlCommand("select count(*) from sli_agent_receipts", db))
            Assert.Equal(750_000L, await count.ExecuteScalarAsync(ct));
        string[][] scopes = [Modules, ["sli.file-audit"], ["sli.windows.ad-dc"], ["not-present"]];
        await Compare(database, ct, scopes);
        await database.ReadAsync(s => s.QueryAsync("""
            update sli_agent_packet_inbox set imported_at='2029-01-01' where packet_id in (
              select distinct on(module_id) packet_id from sli_agent_receipts
              where module_id=any(@p0) and module_id not in ('sli.ad-snapshot','sli.gpo-snapshot')
              order by module_id,sequence)
            """, ct, (object)Modules), ct);
        await Compare(database, ct, scopes);
        // The favorable case must actually avoid historical fallback, as in the Python test.
        string ctes = RuntimeSql[..RuntimeSql.IndexOf("SELECT module_id,max(last_received_at)", StringComparison.Ordinal)];
        var counts = await database.ReadAsync(s => s.QueryAsync(ctes + "SELECT count(*) AS n FROM missing_imports", ct, (object)Modules), ct);
        Assert.Equal(0, counts[0]!["n"]!.GetValue<long>());

        await PostCollectionPostgres.Sql(db, """
            update sli_agent_packet_inbox i set imported_at=null from sli_agent_receipts r
              where i.packet_id=r.packet_id and r.module_id='sli.workstations';
            """, ct);
        await Compare(database, ct, Modules, ["sli.workstations"]);
        Assert.Null(Assert.Single(await Rows(database, RuntimeSql, ["sli.workstations"], ct)).Imported);
        await PostCollectionPostgres.Sql(db, """
            update sli_agent_packet_inbox i set imported_at=null from sli_agent_receipts r
              where i.packet_id=r.packet_id and r.module_id='sli.file-audit';
            update sli_agent_packet_inbox set imported_at='2025-01-01' where packet_id=(
              select packet_id from sli_agent_receipts where module_id='sli.file-audit' order by sequence limit 1);
            """, ct);
        await Compare(database, ct, Modules, ["sli.file-audit"]);
        Assert.Equal(Utc("2025-01-01"), Assert.Single(await Rows(database, RuntimeSql, ["sli.file-audit"], ct)).Imported);
        await PostCollectionPostgres.Sql(db, """
            update sli_agent_packet_inbox set imported_at='2030-01-01' where packet_id=(
              select packet_id from sli_agent_receipts where module_id='sli.file-audit' order by sequence limit 1);
            """, ct);
        await Compare(database, ct, Modules, ["sli.file-audit"]);
        Assert.Equal(Utc("2030-01-01"), Assert.Single(await Rows(database, RuntimeSql, ["sli.file-audit"], ct)).Imported);
        await PostCollectionPostgres.Sql(db, """
            update sli_agent_packet_inbox i set imported_at='2031-01-01' from sli_agent_receipts r
              where i.packet_id=r.packet_id and r.module_id='unknown';
            """, ct);
        await Compare(database, ct, Modules, ["absent"]);
        counts = await database.ReadAsync(s => s.QueryAsync(ctes + "SELECT count(*) AS n FROM prefix_imports", ct, (object)Modules), ct);
        Assert.Equal(0, counts[0]!["n"]!.GetValue<long>());
        await PostCollectionPostgres.Sql(db, """
            insert into sli_agent_packet_inbox(packet_id,received_at,imported_at)
              select md5('orphan-'||n)::uuid,'2026-01-01'::timestamptz,'2032-01-01'::timestamptz from generate_series(1,1100) n;
            """, ct);
        await Compare(database, ct, Modules, ["sli.file-audit"]);
    }
}
