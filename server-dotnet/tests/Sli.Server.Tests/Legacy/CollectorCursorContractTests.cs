using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Legacy;
using Sli.Server.Workspace;
using Xunit;

namespace Sli.Server.Tests.Legacy;

// Vectors from tests/core/test_collector_cursor_contract_hotfix.py.
public sealed class CollectorCursorContractTests
{
    const string Start = "2026-07-25T00:00:00+00:00";
    const string Generation = "generation-stable";
    static string Xml(long? record) => $$"""
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
        <Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><Version>2</Version>
        <TimeCreated SystemTime="2026-07-25T10:00:00.000000000Z"/>
        {{(record is null ? "" : $"<EventRecordID>{record}</EventRecordID>")}}
        <Computer>dc.example.test</Computer><Security/></System>
        <EventData><Data Name="TargetUserName">someone</Data></EventData></Event>
        """;

    [Theory]
    [InlineData(500000L, 42L, "time_window_fallback", null, "latest_record_id_before_saved_cursor")]
    [InlineData(500000L, 500123L, "record_id", 500000L, null)]
    [InlineData(500000L, 500000L, "record_id", 500000L, null)]
    [InlineData(500000L, null, "record_id", 500000L, null)]
    [InlineData(null, null, "time_window", null, null)]
    public void Cursor_reset_and_unknown_probe(long? saved, long? latest, string strategy, long? after, string? reason)
    {
        Assert.Equal((strategy, after, reason), CollectorCursorContract.Resolve(saved, latest));
        string xpath = CollectorCursorContract.XPath(after, Start);
        if (after is null) { Assert.DoesNotContain("EventRecordID", xpath); Assert.Contains("TimeCreated", xpath); }
        else Assert.Contains($"EventRecordID > {saved}", xpath);
    }

    [Fact]
    public void Message_request_fails_closed_and_disabled_message_preserves_event()
    {
        Assert.Contains("message_rendering_not_supported", Assert.Throws<InvalidOperationException>(() =>
            CollectorCursorContract.ParseEvent(Xml(777), "DC1", "192.0.2.1", "Security", true)).Message);
        var row = CollectorCursorContract.ParseEvent(Xml(777), "DC1", "192.0.2.1", "Security", false);
        Assert.Null(row["message"]); Assert.Equal(777, Number(row["record_id"])); Assert.Equal(4624, Number(row["event_id"]));
        Assert.Contains("TargetUserName", row["xml"]!.ToString()); Assert.Equal("someone", Assert.Single(row["properties"]!.AsArray())!.ToString());
    }

    [Fact]
    public void Channel_metadata_retains_boundaries_and_python_generation_digest()
    {
        var state = CollectorCursorContract.ChannelState("Security","2026-09-03T01:02:03+00:00",9001,8765);
        Assert.Equal(9001,Number(state["latest_record_id"])); Assert.Equal(8765,Number(state["oldest_record_id"]));
        Assert.Equal("sli.windows-event-channel-generation.v1:c9d4d83a4b669fcdfc5e252fb2742cd47c6ba139fa0cd0bd456a5fc13c36693c",state["generation_identity"]!.ToString());
    }

    public static TheoryData<long?[], long?> Maxima => new() {
        { [500,400,300], 500 }, { [0], 0 }, { [0,5], 5 }, { [null,7,null,3], 7 }, { [null,null], null }
    };

    static CollectorChannelCapture Capture(long boundary = 500, int[]? selectors = null)
        => new("Security", 100, boundary, 1, Generation, Generation, selectors);
    static void Write(CollectorChannelCapture capture, params long?[] records)
    {
        foreach (var record in records) capture.Write(Xml(record), "DC1", "192.0.2.1", false, _ => { });
    }
    static long? Number(JsonNode? node) => CollectorCursorContract.Integer(node);

    [Theory, MemberData(nameof(Maxima))]
    public void Maximum_is_over_written_rows_including_zero_and_missing(long?[] records, long? expected)
    {
        var capture = Capture(); var persisted = new List<long?>();
        foreach (var record in records) capture.Write(Xml(record), "DC1", "192.0.2.1", false, row => persisted.Add(Number(row["record_id"])));
        var result = capture.Finish(Generation, true);
        Assert.Equal(records, persisted); Assert.Equal(records.Length, Number(result["count"]));
        Assert.Equal("completed", result["status"]!.ToString()); Assert.Equal(expected, Number(result["latest_available_record_id"]));
    }

    [Theory]
    [InlineData(103, false, true, "complete", false)] // frozen boundary reached
    [InlineData(110, false, true, "not_proven", true)] // overflow or unknown lookahead
    [InlineData(110, true, true, "complete", false)] // explicit empty lookahead
    [InlineData(150, true, false, "complete", false)] // sparse selector exhausted
    public void Completeness_requires_boundary_or_explicit_exhaustion(long boundary, bool exhausted, bool stopped, string status, bool truncated)
    {
        var capture = Capture(boundary); Write(capture, 101, 102, 103);
        Assert.Contains($"EventRecordID <= {boundary}", capture.XPath(Start));
        var result = capture.Finish(Generation, exhausted, stopped); var continuity = result["continuity"]!;
        Assert.Equal(status, continuity["status"]!.ToString()); Assert.Equal(truncated, continuity["truncated"]!.GetValue<bool>());
        Assert.Equal(status == "complete", continuity["query_exhausted"]!.GetValue<bool>());
        Assert.Equal(103, Number(result["latest_available_record_id"])); Assert.Equal(3, Number(result["count"]));
    }

    [Fact]
    public void Zero_matches_and_sparse_matches_complete_on_exhaustion()
    {
        var capture = Capture(103); var empty = capture.Finish(Generation, true);
        Assert.Equal(0, Number(empty["count"])); Assert.Equal("complete", empty["continuity"]!["status"]!.ToString());
        Assert.False(empty["continuity"]!["truncated"]!.GetValue<bool>()); Assert.True(empty["continuity"]!["query_exhausted"]!.GetValue<bool>());
        capture = Capture(150, [4672,4624,4634,4608,4624]); Write(capture, 101,105,110);
        var sparse = capture.Finish(Generation, true);
        Assert.Equal(110, Number(sparse["latest_available_record_id"])); Assert.Equal("complete", sparse["continuity"]!["status"]!.ToString());
        Assert.Equal(new long?[] { 4608,4624,4634,4672 }, sparse["event_ids"]!.AsArray().Select(Number));
        Assert.True(JsonNode.DeepEquals(sparse["event_ids"], sparse["continuity"]!["selector_event_ids"]));
    }

    [Theory]
    [InlineData("overflow", "not_proven", true)]
    [InlineData("timeout", "not_proven", true)]
    [InlineData("empty", "complete", false)]
    public void Lookahead_is_proof_only_and_timeout_is_not_exhaustion(string next,string expected,bool truncated)
    {
        var capture = Capture(110); Write(capture,101,102,103); int calls = 0;
        var result = capture.FinishAfterStop(Generation, () => { calls++; return next switch { "overflow" => [Xml(104)], "timeout" => null, _ => [] }; });
        Assert.Equal(1,calls); Assert.Equal(3,Number(result["count"])); Assert.Equal(103,Number(result["latest_available_record_id"]));
        Assert.Equal(expected,result["continuity"]!["status"]!.ToString()); Assert.Equal(truncated,result["continuity"]!["truncated"]!.GetValue<bool>());
        Assert.Equal(!truncated,result["continuity"]!["query_exhausted"]!.GetValue<bool>());
        capture = Capture(103); Write(capture,101,102,103);
        result = capture.FinishAfterStop(Generation,() => throw new InvalidOperationException("must not read past frozen boundary"));
        Assert.Equal("complete",result["continuity"]!["status"]!.ToString());
    }

    [Fact]
    public void Generation_change_during_or_before_read_cannot_prove_continuity()
    {
        var capture = Capture(103); Write(capture,101,102,103);
        var changed = capture.Finish("generation-recreated", true);
        Assert.Equal("not_proven", changed["continuity"]!["status"]!.ToString()); Assert.False(changed["continuity"]!["generation_stable_during_read"]!.GetValue<bool>());
        Assert.Equal("generation-recreated", changed["channel_generation_identity_after_read"]!.ToString());
        capture = new("Security",100,150,1,"generation-old","generation-new");
        var refilled = capture.Finish("generation-new",true);
        Assert.Equal("time_window_fallback",refilled["cursor_strategy"]!.ToString());
        Assert.Equal("channel_generation_changed",refilled["cursor_fallback_reason"]!.ToString());
        Assert.Equal("generation-new", refilled["channel_generation_identity"]!.ToString());
        Assert.Equal("not_proven",refilled["continuity"]!["status"]!.ToString()); Assert.DoesNotContain("EventRecordID > 100",capture.XPath(Start));
    }

    [Theory]
    [InlineData("EvtOpenSession failed for DC2", "open_session")]
    [InlineData("EvtQuery rejected the xpath", "query")]
    [InlineData("EvtNext: the handle is invalid", "next")]
    [InlineData("EvtRender could not render the event", "render")]
    [InlineData("not well-formed (invalid token)", "parse")]
    [InlineData("permission denied", "write")]
    [InlineData("something entirely new", "unknown")]
    public void Partial_failure_is_attributed_and_never_authorizes_commit(string message, string stage)
    {
        var fields = CollectorCursorContract.PartialFailure(new Exception(message),12);
        Assert.Equal(stage, fields["failure_stage"]!.ToString()); Assert.Equal("partial_failure_"+stage,fields["partial_failure_code"]!.ToString());
        Assert.Equal("failure",fields["partial_kind"]!.ToString()); Assert.Equal(12,Number(fields["partial_events_written"]));
        Assert.False(fields["cursor_commit_allowed"]!.GetValue<bool>());
    }

    [Fact]
    public void Null_failure_is_empty_and_security_context_still_blocks()
    {
        Assert.Empty(CollectorCursorContract.PartialFailure(null,0));
        Assert.Equal("windows_security_context_invalid",CollectorCursorContract.BlockingFailure([new Exception("(1749, 'EvtOpenSession', ...)")]));
        Assert.Null(CollectorCursorContract.BlockingFailure([new Exception("EvtNext exploded")]));
    }

    [Fact]
    public void Failed_write_does_not_advance_maximum_and_broken_read_is_failed_in_batch()
    {
        var capture = Capture(); Write(capture,101);
        var error = Assert.Throws<UnauthorizedAccessException>(() => capture.Write(Xml(999),"DC1","192.0.2.1",false,_ => throw new UnauthorizedAccessException("permission denied")));
        var result = capture.Finish(Generation,false,failure:error);
        Assert.Equal(101,Number(result["batch_max_record_id"])); Assert.Equal(1,Number(result["count"]));
        Assert.False(result["cursor_commit_allowed"]!.GetValue<bool>());
        var batch = LegacyCollectionBatch.FromChannels([result],[]);
        Assert.Equal("failed",batch.Status); Assert.Empty(batch.Warnings!); Assert.Contains("permission denied", Assert.Single(batch.Errors!));
    }

    [Theory]
    [InlineData(1000L,9999L,1000L,"batch_scoped")]
    [InlineData(9999L,1000L,1000L,"published_clamped")]
    [InlineData(null,500L,500L,"published_only")]
    [InlineData(500L,null,500L,"batch_only")]
    [InlineData(null,null,null,"published_only")]
    public void Cursor_is_scoped_to_batch_and_publication(long? batch,long? published,long? expected,string bound)
        => Assert.Equal((expected,bound),CollectorCursorContract.Watermark(batch,published));

    [Fact]
    public void Filtered_boundary_requires_durable_ack_and_exhaustion()
    {
        var channel = JsonNode.Parse("""{"cursor_strategy":"record_id","channel_latest_record_id_before_read":175,"continuity":{"status":"complete","selector_event_ids":[4608,4624,4634,4672],"query_exhausted":true}}""")!.AsObject();
        Assert.Equal(175,CollectorCursorContract.FilteredBoundary(channel,new() { ["source_capture_continuity_persisted"]=true }));
        Assert.Null(CollectorCursorContract.FilteredBoundary(channel,new() { ["source_capture_continuity_persisted"]=false }));
        Assert.Null(CollectorCursorContract.FilteredBoundary(channel,new()));
        channel["continuity"]!["query_exhausted"]=false;
        Assert.Null(CollectorCursorContract.FilteredBoundary(channel,new() { ["source_capture_continuity_persisted"]=true }));
    }

    [Theory]
    [InlineData("failure",false,1,0,false)]
    [InlineData(null,true,0,1,true)]
    public void Broken_partial_and_genuine_timeout_are_distinct(string? kind,bool allowed,int failed,int partial,bool warning)
    {
        var result = CollectorCursorContract.Summarize([new JsonObject { ["channel"]="Security",["status"]="partial_timeout",["count"]=10,
            ["error"]=kind is null ? "Channel timed out after 120 seconds." : "EvtNext exploded",["partial_kind"]=kind,["cursor_commit_allowed"]=allowed }]);
        Assert.Equal(failed,Number(result["channels_failed"])); Assert.Equal(partial,Number(result["channels_partial"]));
        Assert.Equal(warning,result["partial_warning"]!.GetValue<bool>());
        if (warning) { Assert.Empty(result["errors"]!.AsArray()); Assert.Contains("timed out",Assert.Single(result["warnings"]!.AsArray())!.ToString()); }
        else Assert.Contains("EvtNext exploded",Assert.Single(result["errors"]!.AsArray())!.ToString());
    }

    [Fact]
    public void Truncated_completed_wire_status_is_partial_warning()
    {
        var result = CollectorCursorContract.Summarize([new JsonObject { ["channel"]="System",["status"]="completed",["count"]=100,["max_events"]=100,
            ["continuity"]=new JsonObject { ["status"]="not_proven",["truncated"]=true } }]);
        Assert.Equal(0,Number(result["channels_completed"])); Assert.Equal(1,Number(result["channels_partial"])); Assert.True(result["partial_warning"]!.GetValue<bool>());
        string warning = Assert.Single(result["warnings"]!.AsArray())!.ToString(); Assert.Contains("System",warning); Assert.Contains("limit",warning);
    }

    sealed class RecentRows(bool timeout) : IWorkspaceRows
    {
        public Task<IReadOnlyList<JsonElement>> ReadAsync(string sql,CancellationToken ct,params NpgsqlParameter[] parameters)
        {
            Assert.Contains("entities_v2_active",sql);
            if (timeout) throw new PostgresException("synthetic timeout","ERROR","ERROR","57014");
            return Task.FromResult<IReadOnlyList<JsonElement>>([JsonSerializer.SerializeToElement(new { id=7,object_type="account",display_name="DC1",natural_key="dc1",
                last_seen_utc="2026-07-25T10:00:00Z",domain_id=1,server_id=7 })]);
        }
    }

    [Theory]
    [InlineData(true,"temporarily_unavailable")]
    [InlineData(false,"available")]
    public async Task Workspace_recent_objects_failure_is_soft_and_normal_path_is_preserved(bool timeout,string expected)
    {
        var facts = new AccessFacts(true,"platform-owner",[],[],[],[],[],[],[JsonSerializer.SerializeToElement(new {
            report_key="ad.test",name="AD",status="published",version=1,dataset_version=1,actions_json=new[] { "view" },
            definition_json=new { required_capabilities=Array.Empty<string>(),dashboard_metrics=Array.Empty<object>(),actions=new[] { "view" } }
        })]);
        var caps = new CapabilityComposer().Compose(facts);
        var access = new AccessReadEvaluation(facts,caps,new ReportEligibility().Compose(facts,caps));
        var reader = new WorkspaceCompatibilityReader(new RecentRows(timeout),new ConfigurationBuilder().Build(),null!,null!,null!);
        var result = await reader.ReadAsync("/api/v1/workspace",new QueryCollection(),new Principal("session",1,"platform-owner"),access,TestContext.Current.CancellationToken);
        Assert.Equal(expected,result["recent_objects_state"]!.ToString()); Assert.Equal("available",result["state"]!.ToString());
        Assert.NotEmpty(result["reports"]!.AsArray()); Assert.NotNull(result["composition"]);
        if (timeout) Assert.Empty(result["recent_objects"]!.AsArray()); else Assert.Equal("DC1",Assert.Single(result["recent_objects"]!.AsArray())!["display_name"]!.ToString());
    }
}
