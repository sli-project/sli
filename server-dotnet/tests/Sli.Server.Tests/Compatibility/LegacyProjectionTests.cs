using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Sli.Server.Compatibility;
using Xunit;

namespace Sli.Server.Tests.Compatibility;

public sealed class LegacyProjectionTests
{
    [Theory]
    [InlineData("EXAMPLE\\alice", "example\\alice", "alice")]
    [InlineData("alice@host13.example.test", "alice@host13.example.test", "alice")]
    public void Account_timeline_normalizes_domain_and_UPN_without_wildcards_in_exact_values(string account, string qualified, string login)
    {
        var sql = new LegacySql();
        string predicate = sql.Account(account, "e.subject_user_name", "e.target_user_name");

        // Exact values stay separate from the optional prefix lookup patterns.
        Assert.Equal(new object[] { qualified, qualified + "%", login, login + "%", qualified, qualified + "%", login, login + "%" }, sql.Parameters);
        foreach (string column in new[] { "e.subject_user_name", "e.target_user_name" })
        {
            Assert.Contains($"lower(coalesce({column},''))=@p", predicate);
            Assert.Contains($"lower(coalesce({column},'')) like @p", predicate);
        }
        Assert.DoesNotContain(qualified, predicate);
        Assert.DoesNotContain(login, predicate);
    }

    // tests/core/test_week5_ai_safety_time_format.py: Windows precision is
    // retained as evidence but omitted from human labels and AI UTC seconds.
    [Fact] public void Windows_event_time_is_readable_and_AI_UTC_is_truncated_to_seconds()
    {
        const string raw = "2026-07-07T02:34:28.9127653Z";
        Assert.Equal("07.07.2026 02:34:28 UTC", LegacySemantics.Display(JsonValue.Create(raw)));
        var item = new AiPreviewRedaction("strict").Event(new JsonObject { ["time_created_utc"] = raw }, null);
        Assert.Equal("07.07.2026 02:34:28 UTC", item["time_display"]!.ToString());
        Assert.Equal("2026-07-07T02:34:28Z", item["time_utc"]!.ToString());
    }

    [Fact] public void Event_detail_exposes_readable_time_and_preserves_original_evidence()
    {
        const string raw = "2026-07-07T02:34:28.9127653Z";
        var row = new JsonObject { ["id"] = 1, ["server"] = "DC1", ["channel"] = "Security", ["event_id"] = 4625,
            ["event_record_id"] = 1, ["time_created_utc"] = raw, ["subject_user_name"] = "svc-backup", ["event_data_json"] = "{}" };
        var item = Sli.Server.Storage.EventReports.EventDetailProjection.Normalize(row, []);
        Assert.Equal("07.07.2026 02:34:28 UTC", item["time_created_utc_display"]!.ToString());
        Assert.Equal(raw, item["time_created_utc"]!.ToString());
    }

    internal static JsonObject Round2RawEvent() => JsonNode.Parse("""
        {"id":17,"event_db_id":17,"event_id":4624,"event_record_id":99,"time_created_utc":"2026-07-22T00:00:00Z",
         "server":"dc.example.test","channel":"Security","provider_name":"Microsoft-Windows-Security-Auditing",
         "message_text":"ROUND2-RAW-MARKER","event_data_json":"{\"SubjectUserName\":\"ROUND2-IDENTITY-MARKER\"}",
         "event_data":{"SubjectUserName":"ROUND2-IDENTITY-MARKER"},"subject_user_name":"ROUND2-IDENTITY-MARKER",
         "target_user_name":"ROUND2-TARGET-MARKER","ip_address":"192.0.2.55","workstation_name":"ROUND2-WORKSTATION-MARKER",
         "logon_id":"0xdeadbeef","correlation_id":"ROUND2-CORRELATION-MARKER","raw_xml":"<ROUND2-RAW-XML />"}
        """)!.AsObject();

    internal static void AssertRound2SummaryOnly(JsonNode? value)
    {
        string[] sensitive = ["message_text", "event_data_json", "event_data", "raw_xml", "xml", "rendered_description", "properties",
            "subject_sid", "target_sid", "subject_name", "target_name", "subject_user_name", "target_user_name", "ip_address", "workstation", "workstation_name", "logon_id", "correlation_id"];
        if (value is JsonObject obj)
            foreach (var pair in obj) { Assert.DoesNotContain(pair.Key, sensitive); AssertRound2SummaryOnly(pair.Value); }
        else if (value is JsonArray array)
            foreach (var child in array) AssertRound2SummaryOnly(child);
        if (value is not null) { Assert.DoesNotContain("ROUND2-RAW-MARKER", value.ToJsonString()); Assert.DoesNotContain("ROUND2-IDENTITY-MARKER", value.ToJsonString()); }
    }

    [Fact]
    public void Round2SummaryProjectionRecursivelyRemovesExactEvidence()
    {
        var summary = LegacySemantics.Summary(Round2RawEvent());
        AssertRound2SummaryOnly(summary);
        Assert.Equal(17, summary["event_db_id"]!.GetValue<long>());
        Assert.Equal(4624, summary["event_id"]!.GetValue<long>());
    }

    [Fact] public void Summary_matches_frozen_Python_vectors_without_releasing_raw_fields()
    {
        using var stream = typeof(LegacyProjectionTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Compatibility.legacy-source.json")!;
        foreach (var vector in JsonNode.Parse(stream)!.AsArray())
        {
            var actual = LegacySemantics.Summary(vector!["row"]!.AsObject());
            Assert.True(JsonNode.DeepEquals(vector["expected"], actual), "event_id=" + vector["row"]!["event_id"] + "\n" + actual.ToJsonString());
            foreach (string key in new[] { "subject_user_name", "ip_address", "event_data_json", "message_text" }) Assert.False(actual.ContainsKey(key));
        }
    }
    [Theory]
    [InlineData("2026-11-01", "2026-11-02", "Asia/Bangkok", "2026-10-31T17:00:00Z", "2026-11-02T17:00:00Z")]
    [InlineData("2026-11-01T00:00:00+07:00", "2026-11-02T00:00:00Z", "UTC", "2026-10-31T17:00:00Z", "2026-11-02T00:00:00Z")]
    public void Date_bounds_are_local_days_with_exclusive_upper_bound(string from, string to, string zone, string start, string end)
    { Assert.Equal((start, end), LegacyQuery.Range(from, to, zone)); }
    [Theory, InlineData("2026-03-08T02:30:00", "nonexistent_local_datetime"), InlineData("2026-11-01T01:30:00", "ambiguous_local_datetime_requires_offset")]
    public void Invalid_DST_wall_times_are_rejected(string value, string error)
    { Assert.Equal(error, Assert.Throws<LegacyInputException>(() => LegacyQuery.Range(value, null, "America/New_York")).Message); }
    [Fact] public void Query_aliases_clamps_and_fallbacks_match_Python()
    {
        var query = LegacyQuery.Parse("/api/events/search", new QueryCollection(new Dictionary<string, StringValues>
        { ["user"] = " fake ", ["source"] = "provider", ["initiator"] = "subject", ["object"] = "target", ["server"] = "one,two,one", ["event_id"] = new StringValues(["4624;4625", "4624"]), ["limit"] = "bad", ["offset"] = "9", ["cursor"] = "bad", ["view"] = "accounts" }));
        Assert.Equal("fake", query.Text("account")); Assert.Equal("provider", query.Text("provider")); Assert.Equal(200, query.Number("limit")); Assert.Null(query.Filters["cursor_values"]);
        Assert.Equal("account_management", query.Text("category")); Assert.Equal(2, query.Filters["servers"]!.AsArray().Count); Assert.Equal(2, query.Filters["event_ids"]!.AsArray().Count); Assert.Null(query.Filters["time_from"]);
    }
    [Fact] public void Recursive_AI_draft_provenance_removes_model_authority()
    {
        var input = JsonNode.Parse("""{"status":"completed","ai_call_performed":true,"analysis":{"summary":"untrusted","severity":"critical","confidence":"high","facts":[{"status":"confirmed","statement":"fake"}]}}""")!.AsObject();
        var result = LegacyRender.Draft(input);
        Assert.Equal("completed", result["status"]!.ToString()); Assert.Null(result["analysis"]!["severity"]); Assert.Null(result["analysis"]!["confidence"]);
        Assert.Equal("draft_only", result["analysis"]!["facts"]![0]!["provenance"]!["authority"]!.ToString());
    }
    [Fact] public async Task HTML_and_CSV_escape_untrusted_host_values_and_preserve_UTF8_BOM()
    {
        var context = new DefaultHttpContext(); context.Response.Body = new MemoryStream();
        var data = new JsonObject { ["generated_at_utc"] = "time", ["items"] = new JsonArray(new JsonObject { ["server"] = "=HYPERLINK(\"evil\")", ["event_id"] = 4625 }), ["filters"] = new JsonObject(), ["matched_total"] = 1, ["returned_count"] = 1, ["truncated"] = false };
        await LegacyRender.CsvAsync(context, data, TestContext.Current.CancellationToken);
        var bytes = ((MemoryStream)context.Response.Body).ToArray(); Assert.Equal(new byte[] { 239, 187, 191 }, bytes.Take(3)); Assert.Contains("'=HYPERLINK", System.Text.Encoding.UTF8.GetString(bytes));
        context = new DefaultHttpContext(); context.Response.Body = new MemoryStream();
        await LegacyRender.HtmlAsync(context, "/reports/ai-reports.html", new JsonObject { ["items"] = new JsonArray(new JsonObject { ["id"] = 7, ["model"] = "<script>alert(1)</script>" }) }, TestContext.Current.CancellationToken);
        string html = System.Text.Encoding.UTF8.GetString(((MemoryStream)context.Response.Body).ToArray()); Assert.Contains("&lt;script&gt;", html); Assert.DoesNotContain("<script>", html); Assert.Contains("черновик ИИ, не решение", html);
    }
}
