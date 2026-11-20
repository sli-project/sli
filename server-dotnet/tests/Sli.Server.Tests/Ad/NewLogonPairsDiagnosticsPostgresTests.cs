using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Ad;
using Sli.Server.Entities;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Ad;

// Synthetic disposable context only: no stand, ClickHouse or end-to-end speed claim.
public sealed class NewLogonPairsDiagnosticsPostgresTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;

    static Task Schema(NpgsqlConnection db) => PostCollectionPostgres.Sql(db, """
        create table domains(id bigint primary key,fqdn text);
        insert into domains values(1,'example.test');
        create table servers(id bigint primary key,domain_id bigint,role text);
        insert into servers values(10,1,'domain_controller');
        create table computers_v6_source_snapshots(source_snapshot_id bigint,domain_id bigint,snapshot_uuid uuid,
            source_completed_at_utc timestamptz,collection_status text,base_inventory_status text,
            object_count int,payload_json jsonb,payload_sha256 bytea);
        create table users_report_v2_snapshots(snapshot_id bigserial primary key,domain_id bigint,
            captured_at_utc timestamptz,source_state text,payload_json jsonb,payload_sha256 bytea);
        create table ad_context_entity_aliases(domain_id bigint,alias_type text,normalized_value text,entity_id bigint);
        """, Ct);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RealContextQueryCancellationRemainsAnErrorWithoutLeakingStorageDetails(bool users)
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct); await Schema(db);
        using var stream = typeof(NewLogonPairsDiagnosticsPostgresTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Domains.home-computer-source.json")!;
        var payload = (await JsonNode.ParseAsync(stream, cancellationToken: Ct))!.AsObject();
        payload["objects"]![0]!["classification"]!["result"] = "workstation";
        await using (var seed = new NpgsqlCommand("""
            insert into computers_v6_source_snapshots values(1,1,@uuid,'2026-10-01T00:00:00Z','complete','observed',1,@payload,decode(@hash,'hex'));
            """, db))
        {
            seed.Parameters.AddWithValue("uuid", Guid.Parse(payload["metadata"]!["snapshot_id"]!.ToString()));
            seed.Parameters.AddWithValue("payload", NpgsqlDbType.Jsonb, payload.ToJsonString());
            seed.Parameters.AddWithValue("hash", AdJobPlugin.Digest(payload));
            await seed.ExecuteNonQueryAsync(Ct);
        }
        var usersPayload = new JsonObject { ["users"] = new JsonArray(new JsonObject { ["samAccountName"] = "synthetic-user" }) };
        await using (var seedUsers = new NpgsqlCommand("insert into users_report_v2_snapshots(domain_id,captured_at_utc,source_state,payload_json,payload_sha256) values(1,now(),'complete',@payload,decode(@hash,'hex'))", db))
        {
            seedUsers.Parameters.AddWithValue("payload", NpgsqlDbType.Jsonb, usersPayload.ToJsonString());
            seedUsers.Parameters.AddWithValue("hash", AdJobPlugin.Digest(usersPayload));
            await seedUsers.ExecuteNonQueryAsync(Ct);
        }
        await using var blocker = await pg.OpenAsync(Ct);
        await using var transaction = await blocker.BeginTransactionAsync(Ct);
        await PostCollectionPostgres.Sql(blocker, users
            ? "lock table users_report_v2_snapshots in access exclusive mode"
            : "lock table computers_v6_source_snapshots in access exclusive mode", Ct);
        string dsn = new NpgsqlConnectionStringBuilder(pg.ConnectionString)
        {
            ApplicationName = "sli-new-logon-diagnostics"
        }.ConnectionString;
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Sli"] = dsn,
            ["Sli:Storage:HistoryReadMode"] = "disabled"
        }).Build();
        var parameters = JsonNode.Parse("""{"period":{"preset":"custom","from_utc":"2026-10-01T00:00:00Z","to_utc":"2026-10-02T00:00:00Z"},"baseline_days":30}""")!.AsObject();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        var report = new AdV2Store(new PostgresConnectionFactory(config), config).ReadAsync(
            new("ad.new-logon-pairs", "view", null, [1], parameters, "table", null, false, 50, null, "UTC"),
            _ => true, deadline.Token);

        // Driver command deadlines are intentionally disabled. Cancel the actual
        // query only after PostgreSQL confirms it is waiting for our snapshot lock.
        await using var cancel = new NpgsqlCommand("""
            select pg_cancel_backend(a.pid)
            from pg_stat_activity a
            where a.application_name = 'sli-new-logon-diagnostics'
              and a.datname = current_database()
              and @blocker = any(pg_blocking_pids(a.pid))
            """, db);
        cancel.Parameters.AddWithValue("blocker", blocker.ProcessID);
        bool cancelled = false;
        while (!report.IsCompleted && !cancelled)
        {
            cancelled = await cancel.ExecuteScalarAsync(deadline.Token) is true;
            if (!cancelled) await Task.Delay(TimeSpan.FromMilliseconds(25), deadline.Token);
        }
        Assert.True(cancelled, "The report never waited for the snapshot lock");
        var result = await report;

        Assert.Equal("error", result["state"]?.ToString());
        Assert.Empty(result["items"]!.AsArray());
        Assert.Equal("context_read_cancelled", Assert.Single(result["limitations"]!.AsArray())!["code"]?.ToString());
        string body = result.ToJsonString();
        Assert.DoesNotContain("computers_v6_source_snapshots", body);
        Assert.DoesNotContain("users_report_v2_snapshots", body);
        Assert.DoesNotContain("ad_context_entity_aliases", body);
        Assert.DoesNotContain(dsn, body);
        Assert.DoesNotContain(pg.ConnectionString, body);
    }

    sealed class CountingReader(IWhatWhereWhenTransaction db) : IWhatWhereWhenTransaction
    {
        internal int Queries, Rows;
        public async Task<JsonArray> Query(string sql, Dictionary<string, object> args, CancellationToken ct)
        {
            Queries++;
            var result = await db.Query(sql, args, ct); Rows += result.Count; return result;
        }
        public Task<int> Execute(string sql, Dictionary<string, object> args, CancellationToken ct) => throw new NotSupportedException();
        public IReadOnlyList<JsonObject> Archive(JsonObject block, CancellationToken ct) => throw new NotSupportedException();
    }

    [Fact]
    public async Task LatestUserClassificationReadsOneSnapshotWithRetainedVolume()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct); await Schema(db);
        var payload = new JsonObject { ["users"] = new JsonArray(Enumerable.Range(0, 2000)
            .Select(i => (JsonNode)new JsonObject { ["samAccountName"] = $"synthetic-user-{i}" }).ToArray()) };
        await using (var seed = new NpgsqlCommand("""
            insert into users_report_v2_snapshots(domain_id,captured_at_utc,source_state,payload_json,payload_sha256)
            select 1,'2026-10-01'::timestamptz+n*interval '1 hour','complete',@payload,decode(@hash,'hex')
            from generate_series(0,167) n;
            analyze users_report_v2_snapshots;
            """, db))
        {
            seed.Parameters.AddWithValue("payload", NpgsqlDbType.Jsonb, payload.ToJsonString());
            seed.Parameters.AddWithValue("hash", AdJobPlugin.Digest(payload));
            await seed.ExecuteNonQueryAsync(Ct);
        }
        await using var expectedQuery = new NpgsqlCommand("select max(snapshot_id) from users_report_v2_snapshots where domain_id=1", db);
        long expected = (long)(await expectedQuery.ExecuteScalarAsync(Ct))!;
        await using var transaction = await db.BeginTransactionAsync(Ct);
        var reader = new CountingReader(new WhatWhereWhenDatabase(db, transaction));
        var (snapshot, accounts) = await WhatWhereWhenCycle.LoadServiceAccounts(reader, 1, Ct);

        Assert.Equal(168, expected);
        Assert.Equal(expected, snapshot);
        Assert.Equal(2000, accounts.Count);
        for (int i = 0; i < 2000; i++) Assert.False(accounts[$"synthetic-user-{i}"]);
        Assert.Equal(1, reader.Queries);
        Assert.Equal(1, reader.Rows);
    }
}
