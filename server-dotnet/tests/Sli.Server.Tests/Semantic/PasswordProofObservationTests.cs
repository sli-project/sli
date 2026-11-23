using System.Text.Json.Nodes;
using Sli.Server.Semantic.Password;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordProofObservationTests
{
    [Fact]
    public void A_committed_retry_reports_the_split_and_aggregates_both_attempts()
    {
        var clock = new TestClock();
        var observation = new PasswordProofObservation(clock);
        clock.Advance(4);

        observation.BeginAttempt();
        observation.ReadWindow();
        observation.ReadNative();
        observation.Verify(2, 18);
        observation.Charge(18);
        observation.ReadHistory();
        observation.ReceiveHistory(3);
        observation.EnterSplit();
        observation.EnterSplit();
        observation.ReceiveWindow(2);
        observation.ReceiveNative(3);
        observation.ParseNative();
        using (observation.Measure(PasswordProofTiming.HistoryRead)) clock.Advance(4);
        clock.Advance(3);
        observation.RejectAttempt();
        observation.EndAttempt();

        clock.Advance(2);
        observation.BeginAttempt();
        observation.ReadWindow();
        observation.ReadNative();
        observation.ReadNative();
        observation.ReadHistory();
        observation.ReceiveHistory(1);
        observation.Verify(1, 11);
        observation.Charge(11);
        observation.Charge(18);
        observation.ReceiveNative(2);
        observation.ReuseParse();
        using (observation.Measure(PasswordProofTiming.Rule)) clock.Advance(5);
        observation.EndAttempt();
        using (observation.Measure(PasswordProofTiming.Commit)) clock.Advance(3);

        var summary = Assert.IsType<JsonObject>(observation.Report(committed: true));
        Assert.True(JsonNode.DeepEquals(summary, JsonNode.Parse("""
            {"attempts":2,"rejected_attempts":1,"split_attempts":1,"split_entities":2,
             "window_reads":2,"native_reads":3,"history_reads":2,"history_rows":4,
             "window_rows":2,"native_rows":5,"managed_parses":1,"managed_parse_reuses":1,
             "parse_memo_entries":0,"parse_memo_payload_bytes":0,
             "phase_ms":{"window_read":0,"window_parse":0,"prepare":0,"native_check":0,"native_read":0,
                         "history_read":4,"history_check":0,"rule":5,"checkpoint":0,"publication":0,
                         "finalizer":0,"commit":3},
             "verified_refs":3,"verified_xml_bytes":29,"charged_refs":3,"charged_xml_bytes":47,
             "attempt_elapsed_ms":12,"max_attempt_ms":7,
             "invocation_elapsed_ms":21,"committed":true}
            """)));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void A_split_without_backoff_or_a_terminal_rejection_is_visible(bool split, bool rejected)
    {
        var observation = new PasswordProofObservation(new TestClock());
        observation.BeginAttempt();
        if (split) observation.EnterSplit();
        if (rejected) observation.RejectAttempt();
        observation.EndAttempt();

        bool committed = split && !rejected;
        var summary = Assert.IsType<JsonObject>(observation.Report(committed));
        Assert.Equal(split ? 1 : 0, summary["split_attempts"]!.GetValue<int>());
        Assert.Equal(rejected ? 1 : 0, summary["rejected_attempts"]!.GetValue<int>());
        Assert.Equal(committed, summary["committed"]!.GetValue<bool>());
    }

    [Fact]
    public void A_normal_attempt_does_not_add_a_log_entry()
    {
        var observation = new PasswordProofObservation(new TestClock());
        observation.BeginAttempt();
        observation.ReadWindow();
        observation.EndAttempt();

        using var sink = new StringWriter();
        PasswordProofObservation.Write(observation.Report(committed: true), sink);
        Assert.Equal("", sink.ToString());
    }

    [Fact]
    public void The_log_contains_one_record_and_cumulative_bytes_are_64_bit()
    {
        var observation = new PasswordProofObservation(new TestClock());
        observation.BeginAttempt();
        observation.EnterSplit();
        for (int i = 0; i < 64; i++)
        {
            observation.Verify(1, 33_554_432);
            observation.Charge(33_554_432);
        }
        observation.EndAttempt();
        var report = observation.Report(committed: true);

        using var sink = new StringWriter();
        PasswordProofObservation.Write(report, sink);
        var line = Assert.Single(sink.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries)).TrimEnd('\r');
        const string prefix = "password_producer_retained_proof:";
        Assert.StartsWith(prefix, line);
        var logged = Assert.IsType<JsonObject>(JsonNode.Parse(line[prefix.Length..]));
        Assert.Equal(2_147_483_648L, logged["verified_xml_bytes"]!.GetValue<long>());
        Assert.Equal(2_147_483_648L, logged["charged_xml_bytes"]!.GetValue<long>());
        Assert.True(JsonNode.DeepEquals(report, logged));

        using var unavailable = new UnavailableSink();
        PasswordProofObservation.Write(report, unavailable);
    }

    private sealed class UnavailableSink : StringWriter
    {
        public override void WriteLine(string? value) => throw new IOException();
    }

    private sealed class TestClock : TimeProvider
    {
        private long ticks;
        public override long TimestampFrequency => 1000;
        public override long GetTimestamp() => ticks;
        internal void Advance(long milliseconds) => ticks += milliseconds;
    }
}
