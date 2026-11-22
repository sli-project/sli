using System.Text.Json.Nodes;
using Sli.Server.Reports;
using Xunit;

namespace Sli.Server.Tests.Reports;

public class AdHardeningTests
{
    [Fact] public void ObservedQuotaAndDisabledLockoutAreLowSeverity()
    {
        var domain = Item("example.test", "domain");
        domain["attributes"]!["machine_account_quota"] = 10;
        var policy = Item("default-policy", "password_policy");
        policy["attributes"]!["lockout_threshold"] = 0;
        var rows = Run(domain, policy);
        Assert.Equal(new[] { "lockout_threshold", "machine_account_quota" }, rows.Select(row => row!["check"]!.ToString()));
        Assert.All(rows, row => Assert.Equal("low", row!["severity"]!.ToString()));
        domain["attributes"]!["machine_account_quota"] = 0;
        policy["attributes"]!.AsObject().Remove("lockout_threshold");
        Assert.Empty(Run(domain.DeepClone().AsObject(), policy.DeepClone().AsObject()));
    }

    [Fact] public void Duplicate_record_key_uses_last_object()
    {
        Assert.Empty(Run(Item("duplicate", "ad_user", spn: true), Item("duplicate", "ad_user")));
        Assert.True(Has(Run(Item("duplicate", "ad_user"), Item("duplicate", "ad_user", spn: true)), "spn_users"));
    }

    [Theory]
    [InlineData("2025-01-01T00:00:00", false)]
    [InlineData("01/01/2025 00:00:00", false)]
    [InlineData("2025-01-01T00:00:00Z", true)]
    [InlineData("2025-01-01T07:00:00+07:00", true)]
    public void Dates_require_iso_offset_and_do_not_assume_local_zone(string passwordAt, bool old)
    {
        var user = Item("user", "ad_user", spn: true);
        user["attributes"]!["password_last_set_utc"] = passwordAt;
        Assert.Equal(old, Has(Run(user), "old_service_password"));
        var snapshot = new JsonObject { ["observed_at_utc"] = "2026-10-29T00:00:00", ["objects"] = new JsonArray(Item("user", "ad_user", spn: true)), ["edges"] = new JsonArray() };
        Assert.Empty(AdHardening.Evaluate(snapshot));
    }
    private static JsonObject Item(string key, string kind, int? uac = 512, int? enc = null, bool spn = false, string sid = "S-1-5-21-111-222-333-1101") => new() {
        ["record_key"] = key, ["identity"] = new JsonObject { ["kind"] = kind, ["object_sid"] = sid },
        ["attributes"] = new JsonObject { ["sam_account_name"] = key, ["user_account_control"] = uac, ["msds_supported_encryption_types"] = enc, ["service_principal_names"] = spn ? new JsonArray("HTTP/x") : new JsonArray() }
    };
    private static JsonArray Run(params JsonObject[] objects) => AdHardening.Evaluate(new JsonObject { ["observed_at_utc"] = "2026-10-29T00:00:00Z", ["domain_id"] = 7, ["run_id"] = "synthetic", ["objects"] = new JsonArray(objects), ["edges"] = new JsonArray() });
    private static bool Has(JsonArray rows, string check) => rows.Any(x => (string?)x!["check"] == check);

    [Theory]
    [InlineData(null, false)] [InlineData(0, false)] [InlineData(1, false)] [InlineData(4, true)] [InlineData(8, false)] [InlineData(16, false)] [InlineData(24, false)] [InlineData(28, false)]
    public void Rc4_requires_rc4_without_aes_on_user_with_spn(int? enc, bool expected)
    {
        Assert.Equal(expected, Has(Run(Item("user", "ad_user", enc: enc, spn: true)), "rc4"));
        Assert.False(Has(Run(Item("user", "ad_user", enc: enc)), "rc4"));
        Assert.False(Has(Run(Item("computer", "ad_computer", enc: enc, spn: true)), "rc4"));
    }

    [Fact] public void Laps_absent_everywhere_does_not_enumerate_computers()
    {
        var computer = Item("host", "ad_computer"); var a = computer["attributes"]!;
        a["laps_password_expiration_status"] = "schema_absent"; a["legacy_laps_password_expiration_status"] = "not_set";
        var row = Assert.Single(Run(computer)); Assert.Equal("laps", (string?)row!["check"]); Assert.True((bool)row["laps_none_found"]!); Assert.Empty((JsonArray)row["objects"]!);
    }

    [Fact] public void Nested_privilege_and_nonexpiring_severity()
    {
        var user = Item("user", "ad_user", uac: 512 | 65536, spn: true);
        var group = Item("group", "ad_group", sid: "S-1-5-21-111-222-333-512");
        var snap = new JsonObject { ["observed_at_utc"] = "2026-10-29T00:00:00Z", ["objects"] = new JsonArray(user, group), ["edges"] = new JsonArray(new JsonArray("user", "group")) };
        var rows = AdHardening.Evaluate(snap);
        Assert.Equal("low", (string?)rows.Single(x => (string?)x!["check"] == "privileged_nonexpiring")!["severity"]);
        Assert.Equal("high", (string?)rows.Single(x => (string?)x!["check"] == "spn_users")!["severity"]);
    }
}
