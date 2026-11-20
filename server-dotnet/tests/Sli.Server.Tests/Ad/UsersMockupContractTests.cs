using System.Globalization;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Ad;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Xunit;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Tests.Ad;

// Behavioral vectors from tests/reporting/test_users_mockup_contract.py, through the real reader.
public sealed class UsersMockupContractTests : IAsyncLifetime
{
    readonly PostCollectionPostgres pg = new(canonicalSchema: true);
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static readonly DateTimeOffset Day = new(DateTime.UtcNow.Date.AddDays(-2), TimeSpan.Zero);
    static string AsOf => Day.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
    AdV2Store store = null!;

    public async ValueTask InitializeAsync()
    {
        await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db, """
            create role adlog_user;
            create table domains(id bigint primary key,fqdn text);
            insert into domains values(1,'example.test');
            create table platform_settings(key text,value text);
            create table ad_snapshot_manifests(manifest_id uuid primary key,domain_id bigint,slot_start_utc timestamptz,
                assembled_at_utc timestamptz,coverage_state text);
            create table ad_snapshot_manifest_sources(manifest_id uuid,family text,source_id text,
                source_state text,observed_at_utc timestamptz,payload_sha256 bytea);
            create table users_report_v2_snapshots(domain_id bigint,snapshot_id bigint,payload_json jsonb,payload_sha256 bytea,scope_json jsonb);
            """, Ct);
        await PostCollectionPostgres.InstallSnapshotChangeStorageAsync(db, Ct);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        { ["ConnectionStrings:Sli"] = pg.ConnectionString }).Build();
        store = new(new PostgresConnectionFactory(config), config);
    }

    public ValueTask DisposeAsync() => pg.DisposeAsync();

    static JsonObject User(int id, bool? enabled = true, bool reversible = false, bool privileged = false) => Obj(new
    {
        id = "user:" + id, entityId = id, domainId = 1, displayName = "Synthetic account " + id,
        samAccountName = "synthetic-account-" + id, sid = "S-1-5-21-100000001-200000002-300000003-" + id,
        enabled, allowReversiblePasswordEncryption = reversible, userAccountControl = reversible ? 640 : 512, servicePrincipalNames = System.Array.Empty<string>(),
        privilegedMemberships = privileged ? new[] { new { relation = "direct", group = "Synthetic admin group" } } : [],
        memberships = new { status = "observed", direct = System.Array.Empty<object>(), effective = System.Array.Empty<object>() },
        sourceStates = new { directory = new { status = "observed" } }
    });

    async Task Save(long id, DateTimeOffset slot, JsonObject[] users, bool observation = true, bool publishChanges = false)
    {
        string? observed = observation ? Iso(slot) : null;
        var payload = Obj(new { metadata = new { observed_at = observed, collection_status = "complete",
            coverage = new { state = "complete", privilege_state = "complete" }, user_count = users.Length }, users, groups = System.Array.Empty<object>() });
        await using var db = await pg.OpenAsync(Ct);
        await using var command = new NpgsqlCommand("""
            insert into ad_snapshot_manifests values(@manifest,1,@slot,@slot,'complete');
            insert into ad_snapshot_manifest_sources values(@manifest,'users_v2',@source,'complete',@observed,decode(@hash,'hex'));
            insert into users_report_v2_snapshots values(1,@id,@payload,decode(@hash,'hex'),'{}');
            """, db);
        var manifest = Guid.NewGuid();
        command.Parameters.AddWithValue("manifest", manifest);
        command.Parameters.AddWithValue("slot", slot);
        command.Parameters.AddWithValue("source", id.ToString(CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("observed", NpgsqlDbType.TimestampTz, observation ? slot : DBNull.Value);
        command.Parameters.AddWithValue("hash", AdJobPlugin.Digest(payload));
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("payload", NpgsqlDbType.Jsonb, payload.ToJsonString());
        await command.ExecuteNonQueryAsync(Ct);
        if (publishChanges) await PostCollectionPostgres.PublishSnapshotChangesAsync(db, manifest, Ct);
    }

    static AdV2Request Request(string query, string action = "view")
    {
        var context = new DefaultHttpContext(); context.Request.QueryString = new("?" + query);
        return AdV2Endpoints.Parse(context.Request, "ad.users.v2", action, [1]);
    }
    Task<JsonObject> Read(string query, bool allFields = false) => store.ReadAsync(Request(query),
        fields => allFields || !fields.Contains("technical"), Ct);
    static long[] Ids(JsonObject data) => data["items"]!.AsArray().Select(r => r.Int("entity_id")).ToArray();

    [Fact]
    public void Owner_tabs_support_inventory_views_and_fifty_row_default()
    {
        var declaration = AdV2Endpoints.Definitions["ad.users.v2"]!["declaration"]!;
        foreach (string tab in new[] { "checks", "privileged", "changes", "all" })
            Assert.Contains(declaration["views"]!.AsArray(), v => v.Text("key") == tab);
        Assert.Equal(50, Request("").Limit);
    }

    [Fact]
    public async Task All_accounts_include_enabled_disabled_and_unknown_across_pages()
    {
        await Save(1, Day, [User(1), User(2, false), User(3, null)]);
        var first = await Read("tab=all&limit=2");
        Assert.Equal(new long[] { 1, 2 }, Ids(first));
        Assert.True(first["items"]![0]!["enabled"]!.GetValue<bool>());
        Assert.False(first["items"]![1]!["enabled"]!.GetValue<bool>());
        Assert.Equal(3, first.Int("filtered_count")); Assert.Equal("2", first.Text("next_cursor"));
        var tail = await Read("tab=all&limit=2&cursor=2");
        Assert.Equal(new long[] { 3 }, Ids(tail)); Assert.Null(tail["items"]![0]!["enabled"]);
        Assert.False(tail["has_more"]!.GetValue<bool>()); Assert.Null(tail["next_cursor"]);
    }

    [Fact]
    public async Task Check_objects_are_paged_searchable_and_catalog_exports_supported_checks()
    {
        await Save(1, Day, [.. Enumerable.Range(1, 7).Select(i => User(i, reversible: true)), User(8)]);
        const string query = "tab=checks&check=reversible_password&limit=5";
        var first = await Read(query, allFields: true); var tail = await Read(query + "&cursor=5", allFields: true);
        Assert.Equal(7, first.Int("filtered_count")); Assert.Equal(5, first["items"]!.AsArray().Count);
        Assert.Equal("5", first.Text("next_cursor")); Assert.Equal(2, tail["items"]!.AsArray().Count);
        Assert.False(tail["has_more"]!.GetValue<bool>()); Assert.Empty(Ids(first).Intersect(Ids(tail)));
        Assert.All(first["items"]!.AsArray(), r => Assert.StartsWith("synthetic-account-", r.Text("name")));
        Assert.Equal(Enumerable.Range(1, 7).Select(i => (long)i), Ids(first).Concat(Ids(tail)).Order());
        var searched = await Read(query + "&q=synthetic-account-7", allFields: true);
        Assert.Equal(1, searched.Int("filtered_count")); Assert.Equal(new long[] { 7 }, Ids(searched));
        var request = Request("tab=checks", "export");
        var catalog = await store.ReadAsync(request, _ => true, Ct);
        var view = AdV2Endpoints.Definitions["ad.users.v2"]!["declaration"]!["views"]!.AsArray().Single(v => v.Text("key") == "checks")!;
        var rows = catalog["collections"]!["checks"]!.AsArray();
        string body = AdV2Endpoints.Csv(view["columns"]!.AsArray(), rows);
        Assert.Contains(rows, row => row.Text("key") == "reversible_password"); Assert.DoesNotContain("Synthetic", body); Assert.Contains("Проверка", body);
    }

    [Fact]
    public async Task Historical_privileges_use_the_saved_end_of_day_baseline_without_current_workplaces()
    {
        await Save(1, Day.AddDays(1).AddTicks(-10), [User(9, privileged: true)]);
        await Save(2, Day.AddDays(1), [User(99, privileged: true)]);
        // No workplace tables exist; the PostgreSQL log also catches swallowed optional-read errors.
        var data = await Read("tab=privileged&as_of=" + AsOf, allFields: true);
        Assert.Equal(new long[] { 9 }, Ids(data)); Assert.Equal(AsOf, data["coverage"].Text("as_of"));
        Assert.Equal(Iso(Day.AddDays(1).AddTicks(-10)), data["coverage"].Text("observed_at_utc"));
        Assert.DoesNotContain("ERROR:", await pg.DiagnosticsAsync(Ct));
    }

    [Fact]
    public async Task Missing_historical_snapshot_never_falls_back_to_current()
    {
        await Save(1, Day.AddDays(1), [User(99, privileged: true)]);
        var data = await Read("tab=privileged&as_of=" + AsOf, allFields: true);
        Assert.Equal("not_collected", data.Text("state")); Assert.Empty(Ids(data));
    }

    [Fact]
    public async Task Historical_snapshot_without_observation_time_keeps_rows_but_stays_partial()
    {
        var saved = User(9, privileged: true);
        saved["sourceStates"]!["directory"]!["observed_at"] = Iso(Day.AddDays(1));
        saved["passwordLastSet"] = Iso(Day.AddDays(-5));
        await Save(1, Day, [saved], observation: false);
        await Save(2, Day.AddDays(1), [User(99)]);
        var data = await Read("tab=privileged&as_of=" + AsOf, allFields: true);
        Assert.Equal("partial", data.Text("state")); Assert.Null(data["coverage"]!["observed_at_utc"]);
        Assert.Equal(new long[] { 9 }, Ids(data)); Assert.Null(data["items"]![0]!["observed_at_utc"]);
        Assert.Equal("observation_time_missing_or_invalid", data["items"]![0]!["hygiene"]!["password_age"].Text("reason"));
    }

    [Fact]
    public async Task Check_search_scopes_previous_and_current_counts_together()
    {
        await Save(1, Day, [User(1, reversible: true), User(2, reversible: true)]);
        await Save(2, Day.AddDays(1), [User(1, reversible: true)]);
        var data = await Read("tab=checks&q=synthetic-account-1", allFields: true);
        var check = data["items"]!.AsArray().Single(r => r.Text("key") == "reversible_password")!;
        Assert.Equal(1, check.Int("previous_total")); Assert.Equal(1, check.Int("total"));
        Assert.Equal("unchanged", check.Text("status"));
    }

    [Fact]
    public async Task Changes_expose_change_count_observation_and_comparison_interval()
    {
        var prior = DateTimeOffset.Parse("2026-10-06T00:00:00Z", CultureInfo.InvariantCulture);
        var current = prior.AddDays(1);
        await Save(1, prior, [User(1, false)]);
        await Save(2, current, [User(1), User(2, false), User(3, null)], publishChanges: true);
        var data = await Read("tab=changes");
        var changes = data["collections"]!["changes"]!.AsArray();
        Assert.NotEmpty(changes); Assert.Equal(changes.Count, data.Int("filtered_count"));
        Assert.Contains(changes, r => r.Text("type") == "enabled_changed");
        Assert.Equal(Iso(prior), data["window"].Text("from_utc")); Assert.Equal(Iso(current), data["window"].Text("to_utc"));
        Assert.All(changes, r => Assert.Equal(Iso(current), r.Text("observed_at_utc")));
    }
}
