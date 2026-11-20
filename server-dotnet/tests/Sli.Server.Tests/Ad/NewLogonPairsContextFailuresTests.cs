using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Ad;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Ad;

public sealed class NewLogonPairsContextFailuresTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData(false, "context_read_timeout")]
    [InlineData(true, "context_read_timeout")]
    public async Task Inventory_timeout_keeps_its_reason_at_the_context_boundary(bool wrapped, string expected)
    {
        Exception error = new TimeoutException("private SQL");
        if (wrapped) error = new NpgsqlException("private SQL", error);
        int calls = 0;
        var context = await AdLogonPairs.ReadContextAsync(() =>
        {
            calls++;
            return Task.FromException<List<JsonObject>>(error);
        });
        Assert.Equal(1, calls);
        Assert.Empty(context.Sources);
        AssertFailure(context.Error!, expected);
    }

    [Theory]
    [InlineData("permission")]
    [InlineData("cancelled")]
    [InlineData("cancelled-token")]
    public async Task Permission_and_task_cancellation_escape_unchanged(string kind)
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        Exception error = kind switch
        {
            "permission" => new UnauthorizedAccessException("private SQL"),
            "cancelled-token" => new OperationCanceledException("private SQL", cancelled.Token),
            _ => new OperationCanceledException("private SQL")
        };
        int calls = 0;
        var actual = await Assert.ThrowsAnyAsync<Exception>(() => AdLogonPairs.ReadContextAsync(() =>
        {
            calls++;
            return Task.FromException<List<JsonObject>>(error);
        }));
        Assert.Same(error, actual);
        Assert.Equal(1, calls);
    }

    [Theory]
    [InlineData("logon_inventory_unavailable", "computer_inventory_unavailable")]
    [InlineData("stored_snapshot_hash_mismatch", "context_verification_failed")]
    [InlineData("stored_snapshot_object_count_mismatch", "context_verification_failed")]
    [InlineData("stored_snapshot_identity_mismatch", "context_verification_failed")]
    [InlineData("stored_snapshot_status_mismatch", "context_verification_failed")]
    [InlineData("stored_base_inventory_status_mismatch", "context_verification_failed")]
    public void Explicit_inventory_and_integrity_reasons_are_allowlisted(string reason, string expected)
    {
        AssertFailure(AdLogonPairs.Failure(new InvalidOperationException(reason), "context_read_failed"), expected);
    }

    [Theory]
    [InlineData(false, PostgresErrorCodes.QueryCanceled)]
    [InlineData(true, PostgresErrorCodes.QueryCanceled)]
    [InlineData(false, PostgresErrorCodes.InsufficientPrivilege)]
    [InlineData(true, PostgresErrorCodes.InsufficientPrivilege)]
    public async Task Database_inventory_failure_survives_the_real_report_boundary(bool users, string sqlState)
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct);
        await Seed(db);
        // Only these fixed, synthetic SQLSTATE values enter the fixture function.
        Assert.Contains(sqlState, new[] { PostgresErrorCodes.QueryCanceled, PostgresErrorCodes.InsufficientPrivilege });
        string table = users ? "users_report_v2_snapshots" : "computers_v6_source_snapshots";
        await PostCollectionPostgres.Sql(db, $"""
            alter table {table} rename to retained_inventory;
            create function inventory_failure() returns boolean language plpgsql as $$
            begin raise exception 'private SQL' using errcode='{sqlState}'; end $$;
            create view {table} as select * from retained_inventory where inventory_failure();
            """, Ct);
        var store = Store(pg);
        if (sqlState == PostgresErrorCodes.InsufficientPrivilege)
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() => store.ReadAsync(Request(), _ => true, Ct));
            Assert.Equal(sqlState, error.SqlState);
            Assert.Equal("private SQL", error.MessageText);
        }
        else AssertFailure(await store.ReadAsync(Request(), _ => true, Ct), "context_read_cancelled");
        // The fixture has no history/server tables: proceeding past failed context cannot succeed.
    }

    [Theory]
    [InlineData("object_count")]
    [InlineData("snapshot_identity")]
    [InlineData("collection_status")]
    [InlineData("base_inventory_status")]
    public async Task Computer_integrity_failures_stop_before_history(string field)
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct);
        await Seed(db);
        string change = field switch
        {
            "object_count" => "object_count=2",
            "snapshot_identity" => "snapshot_uuid='00000000-0000-4000-8000-000000000999'",
            "collection_status" => "collection_status='partial'",
            _ => "base_inventory_status='unavailable'"
        };
        await PostCollectionPostgres.Sql(db, "update computers_v6_source_snapshots set " + change, Ct);
        AssertFailure(await Store(pg).ReadAsync(Request(), _ => true, Ct), "context_verification_failed");
    }

    [Fact]
    public async Task Unavailable_inventory_fails_closed_with_no_items()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct);
        await Seed(db);
        await PostCollectionPostgres.Sql(db, "delete from computers_v6_source_snapshots", Ct);
        AssertFailure(await Store(pg).ReadAsync(Request(), _ => true, Ct), "computer_inventory_unavailable");
    }

    static void AssertFailure(JsonObject body, string expected)
    {
        Assert.Equal("error", body["state"]?.ToString());
        Assert.Empty(body["items"]!.AsArray());
        Assert.Equal(expected, body["limitations"]![0]!["code"]?.ToString());
        Assert.DoesNotContain("private SQL", body.ToJsonString());
        Assert.False(body["has_more"]!.GetValue<bool>());
        Assert.Null(body["next_cursor"]);
    }

    static AdV2Request Request() => new("ad.new-logon-pairs", "view", null, [7],
        JsonNode.Parse("""{"period":{"preset":"custom","from_utc":"2026-01-01T00:00:00Z","to_utc":"2026-01-02T00:00:00Z"},"baseline_days":30}""")!.AsObject(),
        "table", null, false, 50, null, "UTC");

    static AdV2Store Store(PostCollectionPostgres pg)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Sli"] = pg.ConnectionString,
            ["Sli:Storage:HistoryReadMode"] = "disabled"
        }).Build();
        return new(new PostgresConnectionFactory(config), config);
    }

    static async Task Seed(NpgsqlConnection db)
    {
        await PostCollectionPostgres.Sql(db, """
            create table domains(id bigint primary key,fqdn text);
            insert into domains values(7,'example.test');
            create table servers(id bigint primary key,domain_id bigint,role text);
            insert into servers values(10,7,'domain_controller');
            create table computers_v6_source_snapshots(source_snapshot_id bigint,domain_id bigint,snapshot_uuid uuid,source_completed_at_utc timestamptz,
                collection_status text,base_inventory_status text,object_count int,payload_json jsonb,payload_sha256 bytea);
            create table users_report_v2_snapshots(snapshot_id bigint,domain_id bigint,captured_at_utc timestamptz,source_state text,payload_json jsonb,payload_sha256 bytea);
            create table ad_context_entity_aliases(domain_id bigint,alias_type text,normalized_value text,entity_id bigint);
            """, Ct);
        using var stream = typeof(NewLogonPairsContextFailuresTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Domains.home-computer-source.json")!;
        var payload = (await JsonNode.ParseAsync(stream, cancellationToken: Ct))!.AsObject();
        payload["objects"]![0]!["classification"]!["result"] = "workstation";
        string guid = payload["objects"]![0]!["objectGuid"]!.ToString();
        var users = JsonNode.Parse("""{"users":[{"samAccountName":"synthetic-user"}]}""")!.AsObject();
        await using var seed = new NpgsqlCommand("""
            insert into computers_v6_source_snapshots values(1,7,@uuid,now(),'complete','observed',1,@payload,decode(@hash,'hex'));
            insert into users_report_v2_snapshots values(1,7,now(),'complete',@users,decode(@userHash,'hex'));
            insert into ad_context_entity_aliases values(7,'object_guid',@guid,1);
            """, db);
        seed.Parameters.AddWithValue("uuid", Guid.Parse(payload["metadata"]!["snapshot_id"]!.ToString()));
        seed.Parameters.AddWithValue("payload", NpgsqlDbType.Jsonb, payload.ToJsonString());
        seed.Parameters.AddWithValue("users", NpgsqlDbType.Jsonb, users.ToJsonString());
        seed.Parameters.AddWithValue("hash", AdJobPlugin.Digest(payload));
        seed.Parameters.AddWithValue("userHash", AdJobPlugin.Digest(users));
        seed.Parameters.AddWithValue("guid", guid.ToLowerInvariant());
        await seed.ExecuteNonQueryAsync(Ct);
    }
}
