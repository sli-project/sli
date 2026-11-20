using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Ad;
using Xunit;

namespace Sli.Server.Tests.Ad;

// SQL is shared by both servers. Keep the frozen Python file's migration
// contract checks here rather than implementing a second expiry algorithm.
public sealed class AdSnapshotSevenDayRingTests
{
    static readonly DateTimeOffset Now = new(2026, 9, 1, 12, 0, 0, TimeSpan.Zero);
    static readonly string[] Relations = [
        "ad_snapshot_manifests", "ad_snapshot_manifest_sources", "ad_snapshot_projection_receipts",
        "ad_snapshot_projection_outputs", "users_report_v2_snapshots", "computers_v6_source_snapshots",
        "gpo_report_v2_source_snapshots"
    ];
    static JsonObject SafeInventory() => new(Relations.Select(name => KeyValuePair.Create<string, JsonNode?>(name, new JsonObject {
        ["candidate_count"] = 0, ["root_mapping_proven"] = true, ["anchor_proven"] = true,
        ["owner_admitted"] = true, ["shared_source"] = false, ["dependency_state"] = "safe",
        ["independent_legacy_cleaner"] = false, ["whole_unit_admitted"] = true
    })));
    static string Migrations([System.Runtime.CompilerServices.CallerFilePath] string path = "") =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(path)!, "../../../../config/postgres_migrations"));
    static string Migration(bool rollback = false) => File.ReadAllText(Path.Combine(Migrations(),
        "131_ad_snapshot_seven_day_ring" + (rollback ? ".rollback.sql" : ".sql"))).ToLowerInvariant();
    static string Between(string text, string start, string end)
    {
        int from = text.IndexOf(start, StringComparison.Ordinal); Assert.True(from >= 0, start);
        int to = text.IndexOf(end, from + start.Length, StringComparison.Ordinal); Assert.True(to > from, end);
        return text[from..to];
    }

    [Fact]
    public void ReadOnlyPolicyIsSevenDaysAndExcludesAdContext()
    {
        Assert.Equal(7, AdSnapshotRetention.PolicyHorizonDays);
        Assert.Equal(Relations, AdSnapshotRetention.RequiredRelations);
        Assert.DoesNotContain("ad_context_runs", AdSnapshotRetention.RequiredRelations);
        var inventory = SafeInventory(); var original = inventory.DeepClone();
        var result = AdSnapshotRetention.Plan(Now, inventory);
        Assert.Equal(7, result["policy_horizon_days"]!.GetValue<int>());
        Assert.Equal("2026-08-25T12:00:00Z", result["horizon_before_utc"]!.GetValue<string>());
        Assert.Equal("completed", result["status"]!.GetValue<string>());
        Assert.Equal(0, result["eligible_before"]!.GetValue<long>());
        Assert.Equal(0, result["eligible_after"]!.GetValue<long>());
        Assert.True(JsonNode.DeepEquals(original, inventory));
        foreach (string relation in Relations) Assert.Equal(0, result["relations"]![relation]!["classification_counts"]!["eligible"]!.GetValue<long>());
        Assert.Contains("fixed at 7", Assert.Throws<ArgumentException>(() => AdSnapshotRetention.Plan(Now, policyHorizonDays: 365)).Message);
        // The same instant expressed outside UTC must produce the same horizon.
        Assert.True(JsonNode.DeepEquals(result, AdSnapshotRetention.Plan(Now.ToOffset(TimeSpan.FromHours(7)), inventory)));
    }

    [Fact]
    public void PlannerDoesNotAdmitUnknownRootsOrPartOfABlockedUnit()
    {
        var unknown = AdSnapshotRetention.Plan(Now);
        Assert.Equal("blocked", unknown["status"]!.ToString());
        Assert.Equal(7, unknown["relations"]!.AsObject().Count);
        Assert.Null(unknown["relations"]![Relations[0]]!["candidate_count"]);
        var inventory = SafeInventory(); inventory[Relations[0]]!["candidate_count"] = 2;
        inventory[Relations[1]]!["shared_source"] = true;
        var result = AdSnapshotRetention.Plan(Now, inventory);
        Assert.Equal("blocked", result["status"]!.ToString());
        Assert.Equal(0, result["eligible_after"]!.GetValue<long>());
        Assert.Equal(0, result["relations"]![Relations[1]]!["classification_counts"]!["blocked_shared_source"]!.GetValue<long>());
        inventory[Relations[1]]!["shared_source"] = false;
        Assert.Equal("not_due", AdSnapshotRetention.Plan(Now, inventory, due: false)["status"]!.ToString());
    }

    [Theory]
    [InlineData("root_mapping_proven", "false", "blocked_missing_root_mapping")]
    [InlineData("anchor_proven", "false", "blocked_missing_anchor")]
    [InlineData("owner_admitted", "false", "blocked_missing_owner_admission")]
    [InlineData("shared_source", "true", "blocked_shared_source")]
    [InlineData("independent_legacy_cleaner", "true", "blocked_independent_legacy_cleaner")]
    [InlineData("dependency_state", "\"restrictive\"", "blocked_dependency_restrictive")]
    [InlineData("dependency_state", "\"unknown\"", "blocked_dependency_unknown")]
    [InlineData("candidate_count", "null", "blocked_unknown_candidate_count")]
    [InlineData("whole_unit_admitted", "false", "blocked_unapproved_whole_unit")]
    public void PlannerPreservesReferenceAdmissionGates(string field, string raw, string classification)
    {
        var inventory = SafeInventory(); inventory[Relations[0]]!["candidate_count"] = 3;
        var eligible = AdSnapshotRetention.Plan(Now, inventory);
        Assert.Equal(3, eligible["eligible_before"]!.GetValue<long>());
        Assert.Equal(3, eligible["eligible_after"]!.GetValue<long>());
        inventory[Relations[0]]![field] = JsonNode.Parse(raw);
        var blocked = AdSnapshotRetention.Plan(Now, inventory);
        Assert.Equal("blocked", blocked["status"]!.ToString());
        Assert.Equal(0, blocked["eligible_after"]!.GetValue<long>());
        Assert.Equal(field == "candidate_count" ? 1 : 3, blocked["relations"]![Relations[0]]!["classification_counts"]![classification]!.GetValue<long>());
        if (field == "candidate_count") Assert.Null(blocked["eligible_before"]);
    }

    [Theory]
    [InlineData("ad_context_runs", "ad_context_runs is outside the AD snapshot retention scope")]
    [InlineData("ad_snapshot_manifests", "compatibility root duplicates a canonical relation")]
    public void CompatibilityRootsCannotExpandScopeOrDuplicateCanonicalRoots(string name, string error)
    {
        var inventory = SafeInventory(); inventory["compatibility_roots"] = new JsonObject { [name] = new JsonObject() };
        var result = AdSnapshotRetention.Plan(Now, inventory);
        Assert.Equal("failed", result["status"]!.ToString());
        Assert.Equal("ValueError:" + error, result["error"]!.ToString());
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("true")]
    [InlineData("1.5")]
    [InlineData("\"1\"")]
    public void InvalidCountsFailClosed(string raw)
    {
        var inventory = SafeInventory(); inventory[Relations[0]]!["candidate_count"] = JsonNode.Parse(raw);
        var result = AdSnapshotRetention.Plan(Now, inventory);
        Assert.Equal("failed", result["status"]!.ToString());
        Assert.Equal("ValueError:candidate_count must be a non-negative integer or null", result["error"]!.ToString());
        Assert.Empty(result["relations"]!.AsObject());
    }

    [Fact]
    public void MigrationDefinesRestrictedSevenDayExpiryAndNullableEvidenceReferences()
    {
        string forward = Migration(), rollback = Migration(true);
        foreach (string token in new[] {
            "create or replace procedure public.expire_ad_snapshot_seven_day_ring", "security definer",
            "session_user <> 'adlog_user'", "revoke all on procedure public.expire_ad_snapshot_seven_day_ring(uuid) from public",
            "grant execute on procedure public.expire_ad_snapshot_seven_day_ring(uuid) to adlog_user",
            "interval '7 days'", "asia/novosibirsk", "latest published scheduled manifest", "scheduled_local_at <= cutoff_local_at",
            "current_setting('ad_snapshot_retention.expiry_active', true) = 'on'",
            "set_config('ad_snapshot_retention.expiry_active', 'on', true)", "set_config('ad_snapshot_retention.expiry_active', 'off', true)",
            "trg_ad_snapshot_manifests_immutable", "trg_ad_snapshot_manifest_sources_immutable", "trg_ad_snapshot_projection_outputs_immutable",
            "what_where_when_observations_computer_source_snapshot_id_fkey", "what_where_when_observations_user_snapshot_id_fkey",
            "www_projection_state_computer_source_snapshot_fkey", "what_where_when_projection_state_user_snapshot_id_fkey",
            "alter column computer_source_snapshot_id drop not null", "alter column user_snapshot_id drop not null"
        }) Assert.Contains(token, forward);
        Assert.DoesNotContain("update public.ad_snapshot", forward);
        Assert.DoesNotContain("ad_context_runs", forward);
        foreach (string relation in Relations) Assert.Contains("delete from public." + relation, forward);
        Assert.True(Regex.Matches(forward, "on delete set null").Count >= 4);
        foreach (string token in new[] { "rollback: what-where-when null snapshot references exist",
            "where computer_source_snapshot_id is null", "or user_snapshot_id is null", "delete from public.schema_migrations", "where version = 131" })
            Assert.Contains(token, rollback);
    }

    [Theory]
    [InlineData("ad_snapshot_manifest_reject_mutation")]
    [InlineData("ad_snapshot_projection_output_reject_mutation")]
    public void AuthorizedRetentionDeletesReturnOldInsteadOfCancellingTheDelete(string function)
    {
        string start = $"create or replace function public.{function}()";
        string forward = Between(Migration(), start, "alter function");
        Assert.Contains("tg_op = 'delete'", forward);
        Assert.Contains("return old;", forward);
        Assert.Contains("raise exception", forward);
        Assert.Contains("return null;", Between(Migration(true), start, "alter function"));
    }

    [Fact]
    public void LiveProjectionForeignKeyIsReplacedByShortCanonicalName()
    {
        const string live = "what_where_when_projection_sta_computer_source_snapshot_id_fkey";
        const string canonical = "www_projection_state_computer_source_snapshot_fkey";
        const string rejected = "what_where_when_projection_state_computer_source_snapshot_id_fk";
        string forward = Migration(), rollback = Migration(true);
        Assert.Equal(63, Encoding.UTF8.GetByteCount(live));
        Assert.True(Encoding.UTF8.GetByteCount(canonical) < 63);
        Assert.Contains($"drop constraint if exists {live}", forward);
        Assert.Contains($"add constraint {canonical}", forward);
        Assert.True(forward.IndexOf($"drop constraint if exists {live}", StringComparison.Ordinal) < forward.IndexOf($"add constraint {canonical}", StringComparison.Ordinal));
        Assert.Contains("on delete set null", Between(forward, $"add constraint {canonical}", "alter table public.what_where_when_projection_state"));
        Assert.Contains($"drop constraint if exists {canonical}", rollback);
        Assert.Contains($"add constraint {live}", rollback);
        Assert.True(rollback.IndexOf($"drop constraint if exists {canonical}", StringComparison.Ordinal) < rollback.IndexOf($"add constraint {live}", StringComparison.Ordinal));
        Assert.Contains("on delete restrict", Between(rollback, $"add constraint {live}", "alter table public.what_where_when_projection_state"));
        Assert.DoesNotContain(rejected, forward); Assert.DoesNotContain(rejected, rollback);
        Assert.Contains("add constraint what_where_when_projection_state_user_snapshot_id_fkey", forward);
    }

    [Fact]
    public void RollbackOnlyBlocksExpiredObservationReferences()
    {
        string rollback = Migration(true);
        string preflight = rollback.Split("drop procedure if exists public.expire_ad_snapshot_seven_day_ring(uuid);")[0];
        Assert.Contains("from public.what_where_when_observations", preflight);
        Assert.Contains("where computer_source_snapshot_id is null", preflight);
        Assert.Contains("or user_snapshot_id is null", preflight);
        Assert.DoesNotContain("what_where_when_projection_state", preflight);
        Assert.DoesNotMatch(@"alter table public\.what_where_when_projection_state\s+alter column (computer_source_snapshot_id|user_snapshot_id) set not null", rollback);
    }

    [Fact]
    public void ExpiryDeletesAllOldUnretainedSourcePayloadsInTheCorrectDomain()
    {
        string forward = Migration();
        Assert.Contains("cutoff_at_utc timestamptz;", forward);
        Assert.Contains("cutoff_at_utc := cutoff_local_at at time zone 'asia/novosibirsk';", forward);
        Assert.Contains("-- gpo snapshots have no captured_at_utc; migration 116 indexes created_at for retention.", forward);
        string gpoReference = File.ReadAllText(Path.Combine(Migrations(), "116_gpo_report_v2_reference.sql")).ToLowerInvariant();
        Assert.Contains("on gpo_report_v2_source_snapshots(created_at,snapshot_id);", gpoReference);
        Assert.Equal(new[] { "users_report_v2_snapshots", "computers_v6_source_snapshots", "gpo_report_v2_source_snapshots",
            "ad_snapshot_projection_outputs", "ad_snapshot_projection_receipts", "ad_snapshot_manifest_sources", "ad_snapshot_manifests" },
            Regex.Matches(forward, @"delete from public\.([a-z0-9_]+)").Select(m => m.Groups[1].Value));
        foreach (var (relation, timestamp, family, identifier, next) in new[] {
            ("users_report_v2_snapshots", "captured_at_utc", "users_v2", "snapshot_id", "delete from public.computers_v6_source_snapshots snapshot"),
            ("computers_v6_source_snapshots", "captured_at_utc", "computers_v6", "snapshot_uuid", "delete from public.gpo_report_v2_source_snapshots snapshot"),
            ("gpo_report_v2_source_snapshots", "created_at", "gpo_v2", "source_run_id", "delete from public.ad_snapshot_projection_outputs output")
        }) {
            string block = Between(forward, $"delete from public.{relation} snapshot", next);
            Assert.Contains("snapshot.domain_id = anchor_domain_id", block);
            Assert.Contains($"snapshot.{timestamp} <= cutoff_at_utc", block);
            Assert.DoesNotContain("expired_manifest", block);
            Assert.Contains($"retained_source.family = '{family}'", block);
            Assert.Contains($"retained_source.source_id = snapshot.{identifier}::text", block);
            Assert.Contains("retained_manifest.domain_id = anchor_domain_id", block);
            Assert.Contains("retained_manifest.contract_version = 'sli.ad-snapshot-manifest/2.0'", block);
            Assert.Contains("retained_manifest.schedule_timezone = 'asia/novosibirsk'", block);
            Assert.Contains("retained_manifest.scheduled_local_at > cutoff_local_at", block);
        }
    }
}
