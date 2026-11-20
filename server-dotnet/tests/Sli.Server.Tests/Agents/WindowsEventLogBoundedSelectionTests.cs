using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Server.Agents.WindowsEventLog;
using Xunit;

namespace Sli.Server.Tests.Agents;

// Behavioral vectors from tests/sources/test_windows_eventlog_bounded_selection.py.
public sealed class WindowsEventLogBoundedSelectionTests
{
    private const string Start = "2026-08-01T01:00:00Z";
    private const string End = "2026-08-01T01:20:00+00:00";
    private static WindowsEventLogOptions Request() => new()
    {
        EventIdsJson = "[6272]", StartTimeUtc = Start, EndTimeUtc = End,
        Server = "radius01.example.test", ConnectAddress = "radius01.example.test"
    };
    private static JsonObject Route() => new()
    {
        ["source_name"] = "radius01.example.test", ["source_instance_id"] = "radius01.example.test",
        ["event_log_ready"] = true, ["event_log_adapter"] = "windows-eventlog-pywin32"
    };
    private static WindowsEventLogOptions Canary() => Request() with
    {
        EventIdsJson = "[4608,4624,4634,4672]", SourceContinuityCanary = true,
        Archive = true, UseRecordIdCursor = true, AdaptiveStateMode = "update",
        MaxEventsPerChannel = 5000, ChannelTimeoutSeconds = 120, CommandTimeoutSeconds = 180,
        AfterRecordIds = new() { ["Security"] = 42 }, CursorGenerations = new() { ["Security"] = "saved-generation" }
    };
    private static string Arg(string[] args, string name) => args[Array.IndexOf(args, name) + 1];

    [Fact]
    public void PythonCommandForwardsBoundedSelection()
    {
        var command = WindowsEventLogAdapter.BuildCommand(new(Request()));
        Assert.Equal("[6272]", Arg(command, "--event-ids-json"));
        Assert.Equal(End, Arg(command, "--end-time-utc"));
    }

    [Theory]
    [InlineData("[6272]", End)]
    [InlineData(null, End)]
    [InlineData("[6272]", null)]
    public void PowerShellRejectsBoundedSelectionBeforeExecution(string? ids, string? end)
    {
        var error = Assert.Throws<ArgumentException>(() => WindowsEventLogAdapter.BuildCommand(new(Request() with
            { Backend = "powershell", EventIdsJson = ids, EndTimeUtc = end })));
        Assert.Contains("python backend", error.Message);
    }

    [Fact]
    public void UnboundedPowerShellCommandRetainsLegacyArguments()
    {
        var command = WindowsEventLogAdapter.BuildCommand(new(Request() with { Backend = "powershell", EventIdsJson = null, EndTimeUtc = null })
            { PowerShellScript = "collect.ps1" });
        Assert.Equal(new[] { "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "collect.ps1",
            "-ComputerName", "radius01.example.test", "-SourceName", "radius01.example.test", "-Hours", "1",
            "-MaxEventsPerChannel", "500", "-ChannelTimeoutSeconds", "30", "-OutputRoot", "raw", "-CollectMessage:$false",
            "-RequestedCollectionMode", "current", "-Channels", "Security", "-StartTimeUtc", Start }, command);
        Assert.DoesNotContain(command, s => s.Contains("EventIds") || s.Contains("EndTime") || s is "--event-ids-json" or "--end-time-utc");
    }

    [Fact]
    public void ExactIdsAndExplicitUtcAreNormalized()
    {
        var selection = WindowsEventLogSelection.Parse("[6272]", Start, End)!;
        Assert.Equal(new[] { 6272 }, selection.EventIds);
        Assert.Equal("2026-08-01T01:00:00+00:00", selection.StartTimeUtc);
        Assert.Equal(End, selection.EndTimeUtc);
    }

    [Theory]
    [InlineData("not-json")]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("[true]")]
    [InlineData("[\"6272\"]")]
    [InlineData("[0]")]
    [InlineData("[65536]")]
    [InlineData("[6272,6272]")]
    [InlineData("[6272.0]")]
    public void InvalidEventIdAllowlistsAreRejected(string ids)
    {
        Assert.Contains("event ID", Assert.Throws<ArgumentException>(() => WindowsEventLogSelection.Parse(ids, Start, End)).Message);
    }

    [Fact]
    public void SelectorCardinalityAndIdEndpoints()
    {
        var ids = Enumerable.Range(1, 65).ToArray();
        Assert.Contains("event ID", Assert.Throws<ArgumentException>(() => WindowsEventLogSelection.Parse(JsonSerializer.Serialize(ids), Start, End)).Message);
        Assert.Equal(ids[..64], WindowsEventLogSelection.Parse(JsonSerializer.Serialize(ids[..64]), Start, End)!.EventIds);
        Assert.Equal(new[] { 1, 65535 }, WindowsEventLogSelection.Parse("[1,65535]", Start, End)!.EventIds);
    }

    [Theory]
    [InlineData(null, End)]
    [InlineData(Start, null)]
    [InlineData("2026-08-01T01:00:00", End)]
    [InlineData("2026-08-01T08:00:00+07:00", "2026-08-01T08:20:00+07:00")]
    [InlineData("2026-08-01T01:20:00Z", "2026-08-01T01:00:00Z")]
    [InlineData(Start, Start)]
    public void MissingOrInvalidUtcRangeIsRejected(string? start, string? end)
    {
        Assert.Contains("UTC", Assert.Throws<ArgumentException>(() => WindowsEventLogSelection.Parse("[6272]", start, end)).Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(Start)]
    public void NoBoundedParametersOrLegacyLowerBoundPreservesLegacySelection(string? start)
    {
        Assert.Null(WindowsEventLogSelection.Parse(null, start, null));
    }

    private const string ExpectedXPath = "*[System[EventID=6272 and TimeCreated[@SystemTime >= '2026-08-01T01:00:00.000000Z' and @SystemTime <= '2026-08-01T01:20:00.000000Z']]]";

    [Fact]
    public void XPathAppliesExactIdsAndInclusiveUtcBoundsBeforeFirstRead()
    {
        Assert.Equal(ExpectedXPath, WindowsEventLogSelection.Parse("[6272]", Start, End)!.BuildXPath());
        bool opened = false, disposed = false;
        using var output = new StringWriter();
        var result = BoundedWindowsEventLogCollector.Collect(Request(), read =>
        {
            Assert.Equal("Security", read.Channel); Assert.Equal("radius01.example.test", read.ComputerName);
            Assert.Equal(ExpectedXPath, read.XPath); opened = true;
            return new Reader(() => { Assert.True(opened); return null; }, () => disposed = true);
        }, output, TestContext.Current.CancellationToken);
        Assert.Equal(new(0, "completed", 0), result);
        Assert.True(disposed); Assert.Equal("", output.ToString());
    }

    [Fact]
    public void RegisteredNpsRouteIsAcceptedAndComparedCaseInsensitively()
    {
        Assert.Equal(new[] { 6272 }, WindowsEventLogAdmission.Nps(Request(), Route)!.EventIds);
        Assert.NotNull(WindowsEventLogAdmission.Nps(Request() with { Server = "RADIUS01.EXAMPLE.TEST", ConnectAddress = "RADIUS01.EXAMPLE.TEST" }, Route));
    }

    public static IEnumerable<object[]> NpsDrift()
    {
        var request = Request();
        yield return [request with { Server = "other.example.test" }, "bounded_nps_server_mismatch"];
        yield return [request with { ConnectAddress = "other.example.test" }, "bounded_nps_connect_address_mismatch"];
        yield return [request with { Backend = "auto" }, "bounded_nps_python_backend_required"];
        yield return [request with { Backend = "powershell" }, "bounded_nps_python_backend_required"];
        yield return [request with { Channels = ["Security", "System"] }, "bounded_nps_security_channel_required"];
        yield return [request with { Archive = true }, "bounded_nps_runtime_state_mutation_forbidden"];
        yield return [request with { UseRecordIdCursor = true }, "bounded_nps_runtime_state_mutation_forbidden"];
        yield return [request with { AdaptiveStateMode = "update" }, "bounded_nps_runtime_state_mutation_forbidden"];
        yield return [request with { CollectMessage = true }, "bounded_nps_message_collection_forbidden"];
        yield return [request with { MaxEventsPerChannel = 0 }, "bounded_nps_event_limit_invalid"];
        yield return [request with { MaxEventsPerChannel = 501 }, "bounded_nps_event_limit_invalid"];
        yield return [request with { ChannelTimeoutSeconds = 0 }, "bounded_nps_channel_timeout_invalid"];
        yield return [request with { ChannelTimeoutSeconds = 61 }, "bounded_nps_channel_timeout_invalid"];
        yield return [request with { CommandTimeoutSeconds = 0 }, "bounded_nps_command_timeout_invalid"];
        yield return [request with { CommandTimeoutSeconds = 76 }, "bounded_nps_command_timeout_invalid"];
    }

    [Theory]
    [MemberData(nameof(NpsDrift))]
    public void NpsRejectsScopeDriftBeforeOpeningTheSource(WindowsEventLogOptions request, string code)
    {
        Assert.Equal(code, Assert.Throws<ArgumentException>(() => WindowsEventLogAdmission.Nps(request, Route)).Message);
        using var output = new StringWriter();
        var result = BoundedWindowsEventLogCollector.RunNps(request, Route,
            _ => throw new Xunit.Sdk.XunitException("source must not open after admission failure"), output, TestContext.Current.CancellationToken);
        Assert.Equal(64, result.ExitCode); Assert.Equal(code, result.Error); Assert.Equal("", output.ToString());
    }

    [Fact]
    public void UnregisteredNpsRouteFailsBeforeOpeningTheSource()
    {
        Assert.Throws<InvalidOperationException>(() => WindowsEventLogAdmission.Nps(Request(), () => throw new InvalidOperationException("unregistered")));
        bool contacted = false;
        using var output = new StringWriter();
        var result = BoundedWindowsEventLogCollector.RunNps(Request(), () => throw new InvalidOperationException("unregistered"),
            _ => { contacted = true; throw new InvalidOperationException(); }, output, TestContext.Current.CancellationToken);
        Assert.Equal(64, result.ExitCode); Assert.False(contacted);
        foreach (var route in new[] { Route(), Route(), Route(), Route() }.Select((route, index) =>
        {
            route[new[] { "source_name", "source_instance_id", "event_log_ready", "event_log_adapter" }[index]] = null;
            return route;
        }))
            Assert.Equal("bounded_nps_registered_route_required", Assert.Throws<ArgumentException>(() => WindowsEventLogAdmission.Nps(Request(), () => route)).Message);
    }

    [Fact]
    public void UnboundedRunnerDoesNotLoadRadiusRegistration()
    {
        Assert.Null(WindowsEventLogAdmission.Nps(Request() with
        {
            EventIdsJson = null, StartTimeUtc = null, EndTimeUtc = null, Backend = "auto", Channels = [],
            AdaptiveStateMode = "update", MaxEventsPerChannel = 200, ChannelTimeoutSeconds = 300, CommandTimeoutSeconds = 600, UseRecordIdCursor = true
        }, () => throw new Xunit.Sdk.XunitException("normal collection must not load the RADIUS route")));
    }

    [Fact]
    public void CanaryAcceptsExactSecurityContractAndRejectsReorderedIds()
    {
        Assert.Equal(new[] { 4608, 4624, 4634, 4672 }, WindowsEventLogAdmission.Canary(Canary()).EventIds);
        Assert.Equal("source_continuity_canary_event_ids_mismatch", Assert.Throws<ArgumentException>(() =>
            WindowsEventLogAdmission.Canary(Canary() with { EventIdsJson = "[4672,4634,4624,4608]" })).Message);
    }

    [Fact]
    public void CanaryCommandAndCollectorReceiveSavedCursorAndGeneration()
    {
        var request = Canary();
        var command = WindowsEventLogAdapter.BuildCommand(new(request));
        Assert.Contains("--source-continuity-canary", command);
        Assert.Equal(42, JsonNode.Parse(Arg(command, "--channel-after-record-ids-json"))!["Security"]!.GetValue<int>());
        Assert.Equal("saved-generation", JsonNode.Parse(Arg(command, "--channel-cursor-generations-json"))!["Security"]!.GetValue<string>());
        using var output = new StringWriter();
        var result = BoundedWindowsEventLogCollector.Collect(request, read =>
        {
            Assert.Equal(42, read.AfterRecordId); Assert.Equal("saved-generation", read.SavedGeneration);
            Assert.Equal("*[System[(EventID=4608 or EventID=4624 or EventID=4634 or EventID=4672) and EventRecordID > 42]]", read.XPath);
            return new Reader(() => null);
        }, output, TestContext.Current.CancellationToken);
        Assert.Equal(new(0, "completed", 0), result);
    }

    [Theory]
    [InlineData(4624, "2026-08-01T01:10:00Z", "bounded_selection_event_id_mismatch")]
    [InlineData(6272, "2026-08-01T00:59:59Z", "bounded_selection_event_time_out_of_range")]
    [InlineData(6272, "2026-08-01T01:20:00.000001Z", "bounded_selection_event_time_out_of_range")]
    [InlineData(6272, "2026-08-01T01:10:00", "bounded_selection_event_time_invalid")]
    public void CollectorRejectsOutOfSelectionRowsBeforePersisting(int id, string at, string error)
    {
        using var output = new StringWriter();
        bool disposed = false;
        var result = BoundedWindowsEventLogCollector.Collect(Request(), _ => new Reader(() => Xml(id, at), () => disposed = true), output, TestContext.Current.CancellationToken);
        Assert.Equal(new(1, "failed", 0, error), result);
        Assert.True(disposed); Assert.Equal("", output.ToString());
    }

    [Fact]
    public void InclusiveEndpointsAreWrittenAndProgressReported()
    {
        var events = new Queue<EventRow>([Xml(6272, Start), Xml(6272, "2026-08-01T01:10:00Z"), Xml(6272, End)]);
        var progress = new List<int>();
        using var output = new StringWriter();
        var result = BoundedWindowsEventLogCollector.Collect(Request(), _ => new Reader(() => events.TryDequeue(out var item) ? item : null), output, TestContext.Current.CancellationToken, progress.Add);
        Assert.Equal(new(0, "completed", 3), result); Assert.Equal(new[] { 1, 2, 3 }, progress);
        var rows = output.ToString().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries).Select(s => JsonNode.Parse(s)!).ToArray();
        Assert.Equal(3, rows.Length); Assert.All(rows, row => Assert.Equal(6272, row["event_id"]!.GetValue<int>()));
    }

    [Fact]
    public void BoundedNonCanaryCursorIsRejectedBeforeSourceContact()
    {
        bool contacted = false;
        using var output = new StringWriter();
        var result = BoundedWindowsEventLogCollector.Collect(Request() with { AfterRecordIds = new() { ["Security"] = 42 } },
            _ => { contacted = true; throw new InvalidOperationException(); }, output, TestContext.Current.CancellationToken);
        Assert.Equal(new(12, "failed", 0, "record-id cursor is forbidden"), result); Assert.False(contacted);
    }

    private static EventRow Xml(int id, string at) => new($"""
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
        <Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>{id}</EventID><EventRecordID>43</EventRecordID>
        <TimeCreated SystemTime="{at}"/><Channel>Security</Channel><Computer>radius01.example.test</Computer>
        </System></Event>
        """, "bookmark");

    private sealed class Reader(Func<EventRow?> read, Action? dispose = null) : INpsEventLogReader
    {
        public EventRow? Read() => read();
        public void Seek(string bookmark) => throw new NotSupportedException();
        public void Dispose() => dispose?.Invoke();
    }
}
