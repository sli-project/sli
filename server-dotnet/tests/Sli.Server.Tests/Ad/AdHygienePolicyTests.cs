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

namespace Sli.Server.Tests.Ad;

// Behavioral vectors from tests/reports/test_ad_hygiene_policy.py.
public sealed class AdHygienePolicyTests
{
    const string At = "2026-10-01T00:00:00Z";
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static string Ago(int days, int seconds = 0) => DateTimeOffset.Parse(At, CultureInfo.InvariantCulture)
        .AddDays(-days).AddSeconds(-seconds).ToString("O", CultureInfo.InvariantCulture);
    static JsonObject Policy(int password = 365, int inactivity = 90) => new() { ["password_age"] = password, ["inactivity"] = inactivity };
    static JsonObject User(string? password, string? logon, bool enabled = true) => new()
    { ["enabled"] = enabled, ["passwordLastSet"] = password, ["lastLogonTimestamp"] = logon };
    static string[] Keys(JsonObject row, string field) => row[field]!.AsArray().Select(n => n!.ToString()).ToArray();
    static void Statuses(JsonObject row, string status)
    {
        Assert.Equal(status, row["password_age_policy"]!.ToString());
        Assert.Equal(status, row["inactivity_policy"]!.ToString());
    }

    [Theory]
    [InlineData(true, 0, false, false)]
    [InlineData(true, 1, true, true)]
    [InlineData(false, 1, true, false)]
    public void Defaults_use_365_and_90_with_strict_age_and_enabled_inactivity(bool enabled, int seconds, bool password, bool inactive)
    {
        var row = AdInventoryRows.User(User(Ago(365, seconds), Ago(90, seconds), enabled), At);
        Assert.Equal(password, Keys(row, "reason_keys").Contains("password_age"));
        Assert.Equal(inactive, Keys(row, "reason_keys").Contains("inactive_threshold"));
        Assert.Equal(365, row["hygiene"]!["password_age"]!["threshold_days"]!.GetValue<int>());
        Assert.Equal(90, row["hygiene"]!["inactivity"]!["threshold_days"]!.GetValue<int>());
    }

    [Theory]
    [InlineData(90)]
    [InlineData(365)]
    public void Fractional_days_are_not_rounded_at_the_boundary(int days)
    {
        foreach (int seconds in new[] { 0, 1 })
        {
            var values = AdInventoryRows.Hygiene(User(Ago(days, seconds), Ago(days, seconds)), At, Policy(days, days));
            Assert.All(values, entry => Assert.Equal(seconds == 0 ? "within_policy" : "exceeded", entry.Value!["status"]!.ToString()));
        }
    }

    [Theory]
    [InlineData(null, At, null, "fact_missing_or_invalid")]
    [InlineData("invalid", At, null, "fact_missing_or_invalid")]
    [InlineData("2026-01-01T00:00:00", At, null, "fact_missing_or_invalid")]
    [InlineData(At, null, null, "observation_time_missing_or_invalid")]
    [InlineData("2026-10-01T00:00:01Z", At, null, "fact_after_observation")]
    [InlineData(At, At, "partial", "source_untrustworthy")]
    [InlineData(At, At, "failed", "source_untrustworthy")]
    public void Untrustworthy_facts_remain_unknown_with_the_reference_reason(string? fact, string? observed, string? source, string reason)
    {
        var user = User(fact, fact);
        user["sourceStates"] = new JsonObject { ["directory"] = new JsonObject { ["status"] = source } };
        var values = AdInventoryRows.Hygiene(user, observed!, Policy(60, 60));
        Assert.All(values, entry =>
        {
            Assert.Equal("unknown", entry.Value!["status"]!.ToString());
            Assert.Equal(reason, entry.Value["reason"]!.ToString());
        });
        if (observed is not null)
        {
            var row = AdInventoryRows.User(user, observed);
            Statuses(row, "unknown");
            Assert.DoesNotContain("password_age", Keys(row, "reason_keys"));
            Assert.DoesNotContain("inactive_threshold", Keys(row, "reason_keys"));
        }
    }

    [Fact]
    public void Missing_facts_are_information_limitations_and_never_compliance_or_failures()
    {
        var row = AdInventoryRows.User(User(null, null), At);
        Statuses(row, "unknown");
        foreach (string key in new[] { "password_age_unknown", "enabled_activity_unknown" })
        {
            Assert.Contains(key, Keys(row, "information_keys"));
            Assert.Contains(row["information_limitations"]!.AsArray(), item => item!["key"]!.ToString() == key);
            Assert.DoesNotContain(key, Keys(row, "reason_keys"));
            Assert.DoesNotContain(row["reasons"]!.AsArray(), item => item!["key"]!.ToString() == key);
        }
        Assert.All(row["hygiene"]!.AsObject(), entry => Assert.Equal("fact_missing_or_invalid", entry.Value!["reason"]!.ToString()));
    }

    [Fact]
    public void Partial_directory_keeps_its_own_observation_date_beside_a_new_publication()
    {
        const string observed = "2026-09-15T00:00:00Z";
        var user = User(observed, observed);
        user["sourceStates"] = JsonNode.Parse("""{"directory":{"status":"partial","observed_at":"2026-09-15T00:00:00Z"}}""");
        var row = AdInventoryRows.User(user, "2026-10-16T00:00:00Z");
        Statuses(row, "unknown");
        Assert.DoesNotContain("password_age", Keys(row, "reason_keys"));
        Assert.DoesNotContain("inactive_threshold", Keys(row, "reason_keys"));
        Assert.All(row["hygiene"]!.AsObject(), entry =>
        {
            Assert.Equal("source_untrustworthy", entry.Value!["reason"]!.ToString());
            Assert.Equal("2026-09-15T00:00:00+00:00", entry.Value["observed_at"]!.ToString());
        });
    }

    [Fact]
    public void Account_observation_time_takes_precedence_over_newer_snapshot_time()
    {
        var user = User(At, At);
        user["sourceStates"] = JsonNode.Parse("""{"directory":{"status":"observed","observed_at":"2026-09-30T00:00:00Z"}}""");
        var values = AdInventoryRows.Hygiene(user, At, Policy());
        Assert.All(values, entry =>
        {
            Assert.Equal("unknown", entry.Value!["status"]!.ToString());
            Assert.Equal("fact_after_observation", entry.Value["reason"]!.ToString());
        });
    }

    [Fact]
    public void Exact_logon_cannot_replace_the_replicated_policy_fact()
    {
        var user = JsonNode.Parse("""{"exactLastLogon":"2026-10-01T00:00:00Z","sourceStates":{"exact_last_logon":{"status":"observed"}}}""")!.AsObject();
        var row = AdInventoryRows.User(user, At);
        Assert.NotNull(row["activity_at"]);
        Assert.Equal("unknown", row["inactivity_policy"]!.ToString());
        Assert.Equal("fact_missing_or_invalid", row["hygiene"]!["inactivity"]!["reason"]!.ToString());
    }

    [Fact]
    public void Request_cannot_override_server_policy()
    {
        var context = new DefaultHttpContext(); context.Request.QueryString = new("?view=all&threshold=365");
        Assert.Equal("report_parameter_unknown:threshold", Assert.Throws<AdInputException>(() =>
            AdV2Endpoints.Parse(context.Request, "ad.users.v2", "view", [1])).Message);
        Assert.DoesNotContain(AdV2Endpoints.Definitions["ad.users.v2"]!["declaration"]!["params"]!.AsArray(), item => item!["key"]!.ToString() == "threshold");
    }

    [Fact]
    public async Task Saved_snapshot_is_re_evaluated_with_absent_and_changed_platform_settings()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db, """
            create table domains(id bigint primary key,fqdn text);
            insert into domains values(1,'example.test');
            create table platform_settings(key text primary key,value text);
            create table ad_snapshot_manifests(manifest_id uuid,domain_id bigint,coverage_state text,slot_start_utc timestamptz);
            insert into ad_snapshot_manifests values('00000000-0000-0000-0000-000000000001',1,'complete',now());
            create table ad_snapshot_manifest_sources(manifest_id uuid,family text,source_state text,observed_at_utc timestamptz,payload_sha256 bytea,source_id text);
            create table users_report_v2_snapshots(snapshot_id bigint,domain_id bigint,payload_json jsonb,payload_sha256 bytea,scope_json jsonb);
            """, Ct);
        var user = User(Ago(95), Ago(95)); user["id"] = "user:1";
        var snapshot = new JsonObject { ["metadata"] = new JsonObject { ["observed_at"] = At }, ["users"] = new JsonArray(user) };
        string hash = AdJobPlugin.Digest(snapshot);
        await using (var seed = new NpgsqlCommand("""
            insert into users_report_v2_snapshots values(1,1,@snapshot,decode(@hash,'hex'),'{}');
            insert into ad_snapshot_manifest_sources values('00000000-0000-0000-0000-000000000001','users_v2','complete','2026-10-01T00:00:00Z',decode(@hash,'hex'),'1');
            """, db))
        {
            seed.Parameters.AddWithValue("snapshot", NpgsqlDbType.Jsonb, snapshot.ToJsonString()); seed.Parameters.AddWithValue("hash", hash);
            await seed.ExecuteNonQueryAsync(Ct);
        }
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["ConnectionStrings:Sli"] = pg.ConnectionString }).Build();
        var store = new AdV2Store(new PostgresConnectionFactory(config), config);
        var request = new AdV2Request("ad.users.v2", "view", null, [1], new JsonObject { ["view"] = "all", ["threshold"] = 365 }, "users", null, false, 100, null, "UTC");
        async Task<JsonObject> Read() => (await store.ReadAsync(request, fields => !fields.Contains("technical"), Ct))["items"]![0]!.AsObject();
        var defaults = await Read();
        Assert.Equal("within_policy", defaults["password_age_policy"]!.ToString());
        Assert.Equal("exceeded", defaults["inactivity_policy"]!.ToString());
        Assert.Equal(365, defaults["hygiene"]!["password_age"]!["threshold_days"]!.GetValue<int>());
        await PostCollectionPostgres.Sql(db, "insert into platform_settings values('ad.password_max_age_days','120'),('ad.inactivity_days','100')", Ct);
        var relaxed = await Read(); Statuses(relaxed, "within_policy");
        Assert.DoesNotContain("password_age", Keys(relaxed, "reason_keys")); Assert.DoesNotContain("inactive_threshold", Keys(relaxed, "reason_keys"));
        Assert.Equal(120, relaxed["hygiene"]!["password_age"]!["threshold_days"]!.GetValue<int>());
        Assert.Equal(100, relaxed["hygiene"]!["inactivity"]!["threshold_days"]!.GetValue<int>());
        await PostCollectionPostgres.Sql(db, "update platform_settings set value=case key when 'ad.password_max_age_days' then '10' else '20' end", Ct);
        var strict = await Read(); Statuses(strict, "exceeded");
        foreach (var (key, kind, days) in new[] { ("password_age", "password_age", 10), ("inactive_threshold", "inactivity", 20) })
        {
            Assert.Contains(key, Keys(strict, "reason_keys"));
            var reason = Assert.Single(strict["reasons"]!.AsArray(), item => item!["key"]!.ToString() == key)!;
            Assert.Equal(days, reason["policy"]!["threshold_days"]!.GetValue<int>());
            Assert.Contains(days.ToString(CultureInfo.InvariantCulture), reason["condition"]!.ToString());
            Assert.Equal(days, strict["hygiene"]![kind]!["threshold_days"]!.GetValue<int>());
        }
        await using var unchanged = new NpgsqlCommand("select encode(payload_sha256,'hex') from users_report_v2_snapshots", db);
        Assert.Equal(hash, await unchanged.ExecuteScalarAsync(Ct));
        Assert.DoesNotContain("ERROR:", await pg.DiagnosticsAsync(Ct));
    }
}
