using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Server.Ad;
using Sli.Server.Storage.History;
using Xunit;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Tests.Ad;

// Behavioral vectors from tests/reporting/test_new_logon_pairs_v2.py.
public sealed partial class AdV2Tests
{
    static readonly DateTimeOffset PairStart = new(2026, 10, 6, 0, 0, 0, TimeSpan.Zero);
    static DateTimeOffset PairEnd => PairStart.AddDays(1);
    static DateTimeOffset PairBaseline => PairStart.AddDays(-30);
    const string PairSid = "S-1-5-21-100000001-200000002-300000003-1001";
    static JsonObject PairEvent(int id, string user = "user-1", string computer = "PC-1", DateTimeOffset? at = null, string? sid = PairSid, string type = "3") =>
        Obj(new { id, event_id = 4624, server_id = 10, domain_id = 1, channel = "Security", time_created_utc = Iso(at ?? PairStart),
            target_domain_name = "example.test", target_user_name = user, target_user_sid = sid,
            workstation_name = computer, computer = "DC-1", logon_type = type });
    static AdLogonPairs.Context PairContext(bool partial = false) => new(
        Enumerable.Range(1, 2).Select(i => Obj(new { object_guid = $"guid-{i}", display_name = $"PC-{i}", dns_host_name = $"pc-{i}.example.test", ip_addresses = new string[0], entity_id = 100 + i })).ToList(),
        [Obj(new { samAccountName = "user-1", sid = PairSid, entityId = 201 }), Obj(new { samAccountName = "user-2" }), Obj(new { samAccountName = "service-1" })], [10], partial);
    static AdLogonPairs.History PairHistory(List<JsonObject>? prior = null, List<JsonObject>? current = null) => new(prior ?? [], current ?? [],
        [Obj(new { server_id = 10, first_utc = "2026-09-01 00:00:00.000000", last_utc = "2026-10-07 00:00:00.000000" })]);
    static AdV2Request PairRequest(int limit = 50, string? cursor = null, string preset = "24h", DateTimeOffset? start = null) =>
        new("ad.new-logon-pairs", "view", null, [1], Obj(new { baseline_days = 30, period = new { preset, from_utc = Iso(start ?? PairStart), to_utc = Iso((start ?? PairStart).AddDays(1)) } }), "table", null, false, limit, cursor, "UTC");
    static Task<JsonObject> PairQuery(AdLogonPairs.History history, AdV2Request? request = null, bool partial = false) =>
        AdLogonPairs.QueryAsync(request ?? PairRequest(), () => Task.FromResult(PairContext(partial)), (_, _, _, _) => Task.FromResult(history), Ct);
    static JsonObject PairRow(JsonObject result) => Assert.Single(result["items"]!.AsArray())!.AsObject();
    static HashSet<string> PairCodes(JsonObject result) => result["limitations"]!.AsArray().Select(l => l!.Text("code")!).ToHashSet();
    static List<JsonObject> ComparePairs(List<JsonObject> prior, List<JsonObject> current, bool covered = true) =>
        AdLogonPairs.Compute(prior, current, PairContext().Computers, PairContext().Users, PairStart, covered, baselineStart: PairBaseline, end: PairEnd);

    [Fact] public void Pair_novelty_distinguishes_new_user_new_pair_and_known_pair()
    {
        var rows = ComparePairs([PairEvent(1, at: PairStart.AddDays(-2))],
            [PairEvent(2), PairEvent(3, computer: "PC-2"), PairEvent(4, user: "user-2", sid: PairSid + "2")]);
        Assert.Equal(2, rows.Count);
        Assert.Contains(rows, r => r.Text("user") == "example.test\\user-1" && r.Text("novelty") == "new_pair" && r.Text("prior_user_logon") == "yes");
        Assert.Contains(rows, r => r.Text("user") == "example.test\\user-2" && r.Text("novelty") == "new_user" && r.Text("prior_user_logon") == "no");
    }

    [Fact] public void Pair_exact_sid_survives_rename_and_distinguishes_recreated_account()
    {
        var rows = ComparePairs([PairEvent(1, at: PairStart.AddDays(-1))], [PairEvent(2, user: "user-2"), PairEvent(3, sid: PairSid + "3")]);
        Assert.Equal("new_user", Assert.Single(rows).Text("novelty"));
    }

    [Fact]
    public void Pair_missing_login_uses_only_unique_case_insensitive_sid()
    {
        JsonObject SidOnly()
        {
            var observation = PairEvent(1, sid: PairSid.ToLowerInvariant());
            observation.Remove("target_user_name");
            return observation;
        }

        var context = PairContext();
        var row = Assert.Single(AdLogonPairs.Compute([], [SidOnly()], context.Computers, context.Users, PairStart, true));
        Assert.Equal("example.test\\user-1", row.Text("user"));
        Assert.Equal(201, row.Int("user_entity_id"));

        JsonObject[] ambiguous = [..context.Users, Obj(new { sid = PairSid, samAccountName = "user-2" })];
        Assert.Empty(AdLogonPairs.Compute([], [SidOnly()], context.Computers, ambiguous, PairStart, true));
    }

    [Fact] public void Pair_uncovered_baseline_excludes_known_pairs_without_claiming_novelty()
    {
        var rows = ComparePairs([PairEvent(1, at: PairStart.AddDays(-1))], [PairEvent(2), PairEvent(3, computer: "PC-2"), PairEvent(4, user: "user-2", sid: PairSid + "2")], false);
        Assert.Equal(2, rows.Count); Assert.All(rows, r => Assert.Equal("no_baseline", r.Text("novelty")));
        Assert.Equal(new[] { "unknown", "yes" }, rows.Select(r => r.Text("prior_user_logon")).Order().ToArray());
    }

    [Fact] public async Task Pair_unresolved_prior_computer_retains_prior_user_and_exposes_identity_limitation()
    {
        var result = await PairQuery(PairHistory([PairEvent(1, computer: "UNRESOLVED", at: PairStart.AddDays(-1))], [PairEvent(2)]));
        Assert.Equal("partial", result.Text("state")); Assert.False(result["coverage"]!["baseline_covered"]!.GetValue<bool>());
        var row = PairRow(result); Assert.Equal("no_baseline", row.Text("novelty")); Assert.Equal("yes", row.Text("prior_user_logon"));
        Assert.Subset(PairCodes(result), new HashSet<string> { "novelty_unverified", "identity_incomplete" });
    }

    [Fact] public void Pair_half_open_windows_deduplicate_and_retain_first_evidence_types_sources()
    {
        var later = PairEvent(2, at: PairStart.AddHours(2), type: "10"); later["computer"] = "DC-2";
        var earlier = PairEvent(3);
        var row = Assert.Single(ComparePairs([PairEvent(1, at: PairBaseline.AddTicks(-10))], [later, earlier, earlier, PairEvent(4, at: PairEnd)]));
        Assert.Equal(2, row.Int("count")); Assert.Equal(3, row.Int("source_event_id")); Assert.Equal(AdInventoryRows.PythonIso(PairStart), row.Text("first_seen"));
        Assert.Equal(new[] { "10", "3" }, Strings(row["logon_types"])); Assert.Equal(new[] { "DC-1", "DC-2" }, Strings(row["sources"]));
        Assert.Equal("new_user", row.Text("novelty")); Assert.Empty(ComparePairs([PairEvent(1, at: PairBaseline)], [earlier]));
    }

    static IEnumerable<string> Strings(JsonNode? node) => node!.AsArray().Select(n => n!.ToString());

    [Fact] public void Pair_system_service_unknown_and_missing_sid_do_not_become_new_users()
    {
        var rows = ComparePairs([], [PairEvent(1, user: "service-1"), PairEvent(2, user: "SYSTEM", sid: "S-1-5-18"), PairEvent(3, user: "device$"), PairEvent(4, user: "unclassified"), PairEvent(5)]);
        Assert.Equal("no_baseline", Assert.Single(rows).Text("novelty"));
        Assert.Equal("no_baseline", Assert.Single(ComparePairs([], [PairEvent(6, sid: null)])).Text("novelty"));
    }

    [Theory]
    [InlineData(false, false, false, false)] [InlineData(false, false, false, true)]
    [InlineData(true, true, false, false)] [InlineData(true, true, false, true)]
    [InlineData(true, false, true, false)] [InlineData(true, false, true, true)]
    public async Task Pair_partial_results_including_empty_do_not_assert_novelty(bool covered, bool truncated, bool partial, bool events)
    {
        var history = PairHistory(current: events ? [PairEvent(1)] : []) with { BaselineCovered = covered, BaselineTruncated = truncated, PeriodTruncated = truncated };
        var result = await PairQuery(history, partial: partial);
        Assert.Equal("partial", result.Text("state")); Assert.False(result["coverage"]!["baseline_covered"]!.GetValue<bool>());
        Assert.Equal("2026-09-01T00:00:00+00:00", result["coverage"].Text("history_from_utc"));
        Assert.Contains(covered ? "novelty_unverified" : "no_baseline", PairCodes(result));
        if (events) { Assert.Equal("no_baseline", PairRow(result).Text("novelty")); Assert.Equal("unknown", PairRow(result).Text("prior_user_logon")); }
        else Assert.Empty(result["items"]!.AsArray());
    }

    [Theory] [InlineData(true, "ok")] [InlineData(false, "empty")]
    public async Task Pair_covered_results_keep_completed_state(bool events, string state)
    {
        var result = await PairQuery(PairHistory(current: events ? [PairEvent(1)] : []));
        Assert.Equal(state, result.Text("state")); Assert.True(result["coverage"]!["baseline_covered"]!.GetValue<bool>());
        Assert.DoesNotContain("no_baseline", PairCodes(result)); Assert.Contains("observations", PairCodes(result));
        if (events) { Assert.Equal("new_user", PairRow(result).Text("novelty")); Assert.Equal("no", PairRow(result).Text("prior_user_logon")); }
    }

    [Fact] public async Task Pair_defaults_filters_entity_links_cursor_binding_and_pinned_window()
    {
        var parsed = AdV2Endpoints.Parse(new DefaultHttpContext().Request, "ad.new-logon-pairs", "view", [1]);
        Assert.Equal(30, parsed.Params.Int("baseline_days")); Assert.Equal("24h", parsed.Params["period"].Text("preset"));
        var history = PairHistory(current: [PairEvent(1), PairEvent(2, computer: "PC-2", at: PairStart.AddHours(1))]);
        var first = await PairQuery(history, PairRequest(1)); Assert.True(first["has_more"]!.GetValue<bool>());
        Assert.Equal(101, PairRow(first).Int("computer_entity_id")); Assert.Equal(201, PairRow(first).Int("user_entity_id"));
        var next = PairRequest(1, first.Text("next_cursor"), start: PairStart.AddHours(1));
        var second = await AdLogonPairs.QueryAsync(next, () => Task.FromResult(PairContext()), (_, baseline, start, end) =>
        {
            Assert.Equal(PairBaseline, baseline); Assert.Equal(PairStart, start); Assert.Equal(PairEnd, end); return Task.FromResult(history);
        }, Ct);
        Assert.True(JsonNode.DeepEquals(first["window"], second["window"])); Assert.Equal(102, PairRow(second).Int("computer_entity_id")); Assert.False(second["has_more"]!.GetValue<bool>());
        var filtered = PairRequest(preset: "7d"); filtered.Params["baseline_days"] = 14; filtered.Params["q"] = "pc-2"; filtered.Params["user"] = "USER-1";
        Assert.Equal("PC-2", PairRow(await PairQuery(history, filtered)).Text("computer"));
        Assert.Equal("invalid_cursor", (await Assert.ThrowsAsync<AdInputException>(() => PairQuery(history, filtered with { Cursor = next.Cursor }))).Message);
        filtered.Params["baseline_days"] = 366;
        Assert.Contains("baseline_days", (await Assert.ThrowsAsync<AdInputException>(() => PairQuery(history, filtered))).Message);
    }

    [Theory] [InlineData(false, true, false)] [InlineData(false, false, true)] [InlineData(true, true, false)] [InlineData(true, false, true)]
    public async Task Pair_each_truncated_window_preserves_rows_and_reports_coverage(bool events, bool baseline, bool period)
    {
        var result = await PairQuery(PairHistory(current: events ? [PairEvent(1)] : []) with { BaselineTruncated = baseline, PeriodTruncated = period });
        Assert.Equal("partial", result.Text("state")); var coverage = result["coverage"]!;
        Assert.Equal(baseline, coverage["baseline_truncated"]!.GetValue<bool>()); Assert.Equal(period, coverage["period_truncated"]!.GetValue<bool>());
        Assert.Equal("2026-10-07T00:00:00+00:00", coverage.Text("history_to_utc")); Assert.Equal(events ? 1 : 0, result["items"]!.AsArray().Count);
        if (events) Assert.Equal("no_baseline", PairRow(result).Text("novelty"));
    }

    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Pair_missing_current_window_explains_partial_but_keeps_verified_baseline(bool events)
    {
        var result = await PairQuery(PairHistory(current: events ? [PairEvent(1)] : []) with { PeriodCovered = false });
        Assert.Equal("partial", result.Text("state")); Assert.True(result["coverage"]!["baseline_history_covered"]!.GetValue<bool>());
        Assert.True(result["coverage"]!["baseline_covered"]!.GetValue<bool>()); Assert.False(result["coverage"]!["period_covered"]!.GetValue<bool>());
        Assert.Contains("period_missing", PairCodes(result)); Assert.DoesNotContain("no_baseline", PairCodes(result));
        if (events) Assert.Equal("new_user", PairRow(result).Text("novelty"));
    }

    [Fact] public async Task Pair_missing_published_facts_suppress_novelty_and_empty_history_is_explicit()
    {
        var result = await PairQuery(PairHistory(current: [PairEvent(1)]) with { FactsIncomplete = true });
        Assert.Equal("partial", result.Text("state")); Assert.Equal("no_baseline", PairRow(result).Text("novelty")); Assert.Contains("facts_incomplete", PairCodes(result));
        var empty = await PairQuery(new([], [], [], BaselineCovered: false, PeriodCovered: false));
        Assert.Equal("empty", empty.Text("state")); Assert.Empty(empty["items"]!.AsArray()); Assert.Contains("history_empty", PairCodes(empty)); Assert.False(empty["coverage"]!["baseline_covered"]!.GetValue<bool>());
    }

    [Theory]
    [InlineData(true, "private endpoint and credentials", "context_read_failed")]
    [InlineData(false, "private endpoint and credentials", "history_read_failed")]
    [InlineData(true, "what_where_when_users_snapshot_unavailable", "users_context_missing")]
    [InlineData(false, "published_history_event_mismatch", "history_verification_failed")]
    public async Task Pair_source_failures_are_safe_actionable_errors(bool context, string reason, string code)
    {
        var result = await AdLogonPairs.QueryAsync(PairRequest(), () => context ? throw new InvalidOperationException(reason) : Task.FromResult(PairContext()), (_, _, _, _) => throw (code=="history_verification_failed" ? (Exception)new InvalidDataException(reason) : new InvalidOperationException(reason)), Ct);
        Assert.Equal("error", result.Text("state")); Assert.Empty(result["items"]!.AsArray()); Assert.Equal(code, result["limitations"]![0].Text("code"));
        Assert.False(string.IsNullOrWhiteSpace(result["limitations"]![0].Text("text"))); Assert.DoesNotContain("private endpoint", result.ToJsonString());
        Assert.Equal(AdInventoryRows.PythonIso(PairStart), result["window"].Text("from_utc"));
    }

    [Theory] [InlineData(true, false)] [InlineData(false, false)] [InlineData(true, true)] [InlineData(false, true)]
    public async Task Pair_timeout_and_cancellation_hide_exception_text(bool context, bool timeout)
    {
        Exception error = timeout ? new TimeoutException("private SQL") : new PostgresException("private SQL", "ERROR", "ERROR", "57014");
        var result = await AdLogonPairs.QueryAsync(PairRequest(), () => context ? throw error : Task.FromResult(PairContext()), (_, _, _, _) => throw error, Ct);
        Assert.Equal("error", result.Text("state")); Assert.Equal((context ? "context_" : "") + (timeout ? "read_timeout" : "read_cancelled"), result["limitations"]![0].Text("code"));
        Assert.DoesNotContain("private SQL", result.ToJsonString());
    }

    [Theory] [InlineData(true)] [InlineData(false)]
    public async Task Pair_permission_errors_and_request_cancellation_propagate(bool context)
    {
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => AdLogonPairs.QueryAsync(PairRequest(), () => context ? throw new UnauthorizedAccessException() : Task.FromResult(PairContext()), (_, _, _, _) => throw new UnauthorizedAccessException(), Ct));
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => AdLogonPairs.QueryAsync(PairRequest(), () => context ? throw new OperationCanceledException(cancellation.Token) : Task.FromResult(PairContext()), (_, _, _, _) => throw new OperationCanceledException(cancellation.Token), cancellation.Token));
    }

    [Fact]
    public async Task Pair_history_failure_does_not_expose_storage_exception_text()
    {
        var result=await AdLogonPairs.QueryAsync(PairRequest(),()=>Task.FromResult(PairContext()),(_,_,_,_)=>throw new InvalidOperationException("private SQL"),Ct);
        Assert.Equal("history_read_failed",result["limitations"]![0].Text("code"));Assert.DoesNotContain("private SQL",result.ToJsonString());
    }

    [Theory] [InlineData("domain", false, true)] [InlineData("server", false, true)] [InlineData("domain", true, false)]
    public async Task Pair_ineligible_scope_or_export_only_grant_denied_before_history(string kind, bool rightDomain, bool view)
    {
        var store = new Store(); using var host = await Host(store, facts: new ScopedFacts(kind: kind, ids: rightDomain ? [1] : [8], view: view)); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v2/reports/ad.new-logon-pairs/data", Ct);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Equal(0, store.Reads);
    }

    [Theory] [InlineData("all")] [InlineData("domain")]
    public async Task Pair_api_reads_only_server_resolved_domain(string kind)
    {
        var store = new Store(); using var host = await Host(store, facts: new ScopedFacts(kind: kind, ids: [1, 8])); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v2/reports/ad.new-logon-pairs/data?period=custom&from=2026-10-06T00:00:00Z&to=2026-10-07T00:00:00Z", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Equal(1, store.Reads); Assert.Equal(new long[] { 1 }, store.LastRequest!.Domains);
    }

    [Fact] public async Task Pair_domain_context_failure_is_a_safe_error_before_history()
    {
        var store = new Store { DomainFailure = new InvalidOperationException("test_history_unavailable private endpoint") };
        using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v2/reports/ad.new-logon-pairs/data", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Equal(0, store.Reads);
        string json = await response.Content.ReadAsStringAsync(Ct); var result = JsonNode.Parse(json)!;
        Assert.Equal("error", result.Text("state")); Assert.Equal("domain_context_unavailable", result["limitations"]![0].Text("code"));
        Assert.DoesNotContain("private endpoint", json);
    }
}
