using System.Diagnostics;
using System.Globalization;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Ad;
using Sli.Server.Infrastructure;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Agents;
using Xunit;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Tests.Ad;

public sealed class UsersPostgresPerformanceTests
{
    private const string SidPrefix = "S-1-5-21-100000001-200000002-300000003-";
    private static readonly string[] Tabs = ["checks", "privileged", "changes", "all", "disabled_active"];

    [Fact]
    public async Task Users_tabs_stay_within_budget_on_a_busy_domain()
    {
        var test = TestContext.Current;
        var ct = test.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 434);
        var day = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-1), TimeSpan.Zero);
        await using var setup = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.Pg.ConnectionString)
            { CommandTimeout = 0 }.ConnectionString);
        await setup.OpenAsync(ct);
        await using (var seed = new NpgsqlCommand(Seed, setup) { CommandTimeout = 0 })
        {
            seed.Parameters.AddWithValue("day", day);
            seed.Parameters.AddWithValue("prefix", SidPrefix);
            await seed.ExecuteNonQueryAsync(ct);
        }
        string migration = MigrationDirectory.Read(435).Single(item => item.Version == 435).Path;
        // Run against a pre-435 server assembly to reproduce the before measurements.
        bool baseline = Environment.GetEnvironmentVariable("SLI_USERS_PERF_BASELINE") == "1";
        if (!baseline) await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await PostCollectionPostgres.Sql(setup, "vacuum (analyze) event_hot", ct);
        var violations = new List<string>();
        foreach (int accounts in new[] { 54, 10_000 })
        {
            var snapshotDay = accounts == 54 ? day : day.AddSeconds(1);
            await SeedSnapshot(setup, snapshotDay.AddHours(22), accounts, previous: true, ct);
            await SeedSnapshot(setup, snapshotDay.AddHours(23), accounts, previous: false, ct);
            await PostCollectionPostgres.Sql(setup, "analyze", ct);
            var connections = new ExplainedConnections(fixture.Pg.ConnectionString);
            var store = new AdV2Store(connections, new ConfigurationBuilder().Build());
            foreach (string tab in Tabs)
            {
                connections.Plans.Clear();
                var parameters = Obj(new { period = new { from_utc = Iso(day), to_utc = Iso(day.AddDays(1)) } });
                if (tab is "checks" or "all") parameters["account_rows"] = "yes";
                var request = new AdV2Request("ad.users.v2", "view", null, [1], parameters, tab, null, false, 50, null, "UTC");
                var timer = Stopwatch.StartNew();
                var result = await store.ReadAsync(request, _ => true, ct);
                timer.Stop();
                Assert.NotEmpty(connections.Plans);
                long blocks = connections.Plans.Sum(p => p["Plan"].Int("Shared Hit Blocks") + p["Plan"].Int("Shared Read Blocks"));
                double sqlMs = connections.Plans.Sum(p => p["Execution Time"]?.GetValue<double>() ?? 0);
                string measurement = FormattableString.Invariant($"{accounts} | {tab} | {blocks} | {sqlMs:F1} ms SQL | {timer.Elapsed.TotalMilliseconds:F1} ms report | {AdJobPlugin.Digest(result)}");
                test.TestOutputHelper!.WriteLine(measurement);
                if (blocks > 5_000 || timer.Elapsed.TotalSeconds > 2)
                {
                    violations.Add(measurement);
                    if (!baseline)
                        foreach (var plan in connections.Plans.Where(p => p["Plan"].Int("Shared Hit Blocks") + p["Plan"].Int("Shared Read Blocks") > 1_000))
                            test.TestOutputHelper.WriteLine(plan.ToJsonString());
                }
                Assert.NotEqual("error", result.Text("state"));
                var page = tab == "disabled_active" ? result["collections"]![tab] : result["items"];
                Assert.NotEmpty(page!.AsArray());
                if (tab == "all")
                {
                    Assert.Equal(accounts, result["coverage"].Int("population"));
                    Assert.Equal(50, page.AsArray().Count);
                }
            }
        }
        if (!baseline)
        {
            // Creating a later day must automatically attach the hot indexes.
            await PostCollectionPostgres.Sql(setup, "select create_event_storage_partitions(current_date+40,current_date+40)", ct);
            await using var attached = new NpgsqlCommand("""
                select count(*) from pg_inherits i join pg_index idx on idx.indexrelid=i.inhrelid
                where i.inhparent in ('event_hot_user_logon_coverage435'::regclass,
                    'event_hot_user_logon_account435'::regclass,'event_hot_user_workplace435'::regclass,
                    'event_hot_user_card_sid435'::regclass,'event_hot_user_card_name435'::regclass,
                    'event_hot_user_workplace_long435'::regclass)
                  and idx.indrelid=to_regclass('event_hot_d'||to_char(current_date+40,'YYYYMMDD'))
                """, setup);
            Assert.Equal(6L, await attached.ExecuteScalarAsync(ct));
            await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
        }
        Assert.Empty(violations);
    }

    private sealed class ExplainedConnections(string dsn) : IPostgresConnectionFactory
    {
        internal List<JsonObject> Plans { get; } = [];

        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        {
            var db = new NpgsqlConnection(dsn);
            await db.OpenAsync(ct);
            await PostCollectionPostgres.Sql(db, """
                load 'auto_explain';
                set auto_explain.log_analyze=on;
                set auto_explain.log_buffers=on;
                set auto_explain.log_timing=off;
                set auto_explain.log_format='json';
                set auto_explain.log_level='notice';
                set auto_explain.log_min_duration=0;
                set role adlog_user;
                """, ct);
            db.Notice += (_, args) =>
            {
                string message = args.Notice.MessageText;
                const string marker = "plan:\n";
                int json = message.IndexOf(marker, StringComparison.Ordinal);
                if (message.StartsWith("duration:", StringComparison.Ordinal) && json >= 0)
                {
                    var parsed = JsonNode.Parse(message[(json + marker.Length)..])!;
                    var plan = parsed is JsonArray array ? array.Single()!.AsObject() : parsed.AsObject();
                    plan["Execution Time"] = double.Parse(message[10..message.IndexOf(" ms", StringComparison.Ordinal)], CultureInfo.InvariantCulture);
                    Plans.Add(plan);
                }
            };
            return db;
        }
    }

    private static async Task SeedSnapshot(NpgsqlConnection db, DateTimeOffset at, int count, bool previous, CancellationToken ct)
    {
        var members = new[] { new { group_id = 20001, group = "Synthetic administrators", relation = "direct" } };
        var snapshot = Obj(new
        {
            metadata = new
            {
                observed_at = Iso(at), collection_status = "complete", user_count = count,
                coverage = new { state = "complete", privilege_state = "complete" },
                watch_groups = new[] { new { id = "group:20001", name = "Synthetic administrators", watchGroup = true } }
            },
            users = Enumerable.Range(1, count).Select(n => new
            {
                entityId = n + 10000, domainId = 1, sid = SidPrefix + (n + 1000), enabled = previous || n != 1,
                samAccountName = "synthetic-" + n, displayName = "Synthetic user " + n,
                doesNotRequirePreAuth = n == 1,
                privilegedMemberships = n == 11 ? members : [],
                memberships = new { status = "observed" }
            })
        });
        await using var command = new NpgsqlCommand("""
            insert into users_report_v2_snapshots(snapshot_id,domain_id,contract_id,scope_json,scope_sha256,bucket_start_utc,
                captured_at_utc,source_observed_at_utc,source_state,user_count,payload_json,payload_sha256)
            values(@id,1,'sli.users-report.v2','{}',sha256('{}'::bytea),@slot,@at,@at,'complete',@count,@snapshot::jsonb,@hash);
            insert into ad_snapshot_manifests(manifest_id,domain_id,domain_sid,domain_dns,slot_start_utc,assembled_at_utc,
                contract_version,coverage_state,manifest_sha256)
            values(@manifest,1,@domain_sid,'example.test',@slot,@at,'sli.ad-snapshot-manifest/1.0','complete',@hash);
            insert into ad_snapshot_manifest_sources(manifest_id,family,contract_id,source_id,observed_at_utc,source_state,payload_sha256)
            values(@manifest,'users_v2','sli.users-report.v2',@id::text,@at,'complete',@hash);
            """, db);
        command.Parameters.AddWithValue("at", at);
        // The immutable 54-account pair occupies the previous day's slots.
        command.Parameters.AddWithValue("slot", new DateTimeOffset(at.UtcDateTime.Date, TimeSpan.Zero)
            .AddDays(count == 54 ? -1 : 0).AddHours(previous ? 0 : 12));
        long snapshotId = 2L * count + (previous ? 0 : 1);
        command.Parameters.AddWithValue("id", snapshotId);
        command.Parameters.AddWithValue("count", count);
        command.Parameters.AddWithValue("snapshot", snapshot.ToJsonString());
        command.Parameters.AddWithValue("hash", Convert.FromHexString(AdJobPlugin.Digest(snapshot)));
        var manifest = Guid.Parse(FormattableString.Invariant($"10000000-0000-4000-8000-{snapshotId:000000000000}"));
        command.Parameters.AddWithValue("manifest", manifest);
        command.Parameters.AddWithValue("domain_sid", SidPrefix.TrimEnd('-'));
        await command.ExecuteNonQueryAsync(ct);
        if (previous) return;
        await using var tx = await db.BeginTransactionAsync(ct);
        var change = Obj(new { row_id = "synthetic-change", type = "account_disabled", field = "enabled", domain_id = 1,
            entity_id = 10001, display_name = "Synthetic user 1", before = true, after = false, observed_at_utc = Iso(at) });
        await SnapshotChangeStore.WriteAsync(db, tx, manifest, AdJobPlugin.Digest(Obj(new { snapshotId })), 1, "users_v2", at.UtcDateTime,
            [], [], [change], Iso(at.AddHours(-1)), Iso(at), ct);
        await tx.CommitAsync(ct);
    }

    private const string Seed = """
        insert into servers(id,domain_id,hostname,fqdn,role)
        values(900001,1,'dc01','dc01.example.test','domain_controller');
        select create_event_storage_partitions((@day at time zone 'UTC')::date,(@day at time zone 'UTC')::date);
        insert into event_hot(event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields)
        select n,@day+n*interval '0.15 seconds',case when n%10=0 then 4624 else 4625 end,1,
            @prefix||(1001+n%10000),null,
            case when n%100=0 then 'pc01.example.test' else '192.0.2.1' end,'dc01.example.test',
            jsonb_build_object('$server_id',900001,'$channel','Security','$provider','Microsoft-Windows-Security-Auditing',
                'LogonType',case when n%100=0 then '10' else '3' end),
            '{}'::jsonb,jsonb_build_object('SyntheticPayload',repeat(md5(n::text),20))
        from generate_series(1,500000) n;
        insert into event_hot(event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields)
        select n,@day+seconds*interval '1 second',kind,1,actor,target,source,'dc01.example.test',
            '{"$server_id":900001,"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing","LogonType":"10"}',
            '{}',case when kind in (4728,4729) then jsonb_build_object('MemberSid',@prefix||'1011') else '{}' end
        from (values (500001,1,4725,@prefix||'1002',@prefix||'1001',null),
            (500002,2,4624,@prefix||'1001',null,'pc01.example.test'),
            (500003,3,4728,@prefix||'1002',@prefix||'20000',null),
            (500004,4,4624,@prefix||'1011',null,'pc01.example.test'),
            (500005,5,4729,@prefix||'1002',@prefix||'20000',null)) v(n,seconds,kind,actor,target,source);
        insert into storage_v2_entity_type(value) values('ad_user') on conflict(value) do nothing;
        insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
        select n+10000,entity_type.id,'synthetic-'||n,'Synthetic account '||n,1,sha256(n::text::bytea)
        from generate_series(1,10001) n cross join storage_v2_entity_type entity_type where entity_type.value='ad_user';
        insert into ad_context_runs(run_id,source_pack_id,source_pack_version,domain_id,mode,observed_at_utc,bundle_sha256,status)
        values('10000000-0000-4000-8000-000000000011','synthetic','1',1,'full',@day,sha256('synthetic-context'::bytea),'completed');
        insert into ad_context_entity_aliases(entity_id,domain_id,alias_type,alias_value,normalized_value,first_seen_utc,last_seen_utc,source_run_id)
        select n+10000,1,'object_sid',sid,lower(sid),@day,@day,'10000000-0000-4000-8000-000000000011'
        from generate_series(1,10001) n cross join lateral (select @prefix||(case when n=10001 then 20000 else 1000+n end) as sid) a;
        """;
}
