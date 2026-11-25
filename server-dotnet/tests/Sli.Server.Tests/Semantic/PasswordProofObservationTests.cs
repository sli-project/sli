using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
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
             "read_attempts":{
               "rejected":{"native":{"calls":1,"rows":3,"ms":0,"repeats":0,"untracked":0},
                           "history":{"calls":1,"rows":3,"ms":4,"repeats":0,"untracked":0}},
               "committed":{"native":{"calls":2,"rows":2,"ms":0,"repeats":0,"untracked":0},
                            "history":{"calls":1,"rows":1,"ms":0,"repeats":0,"untracked":0}}},
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
    public void Read_attempts_count_exact_repeats_and_bound_tracking_per_invocation()
    {
        const string request = "[1,2]";
        const string reordered = "[2,1]";
        var clock = new TestClock();
        var observation = new PasswordProofObservation(clock);
        observation.BeginAttempt();
        Read(observation, PasswordProofTiming.NativeRead, request, 2, 3);
        Read(observation, PasswordProofTiming.HistoryRead, request, 1, 4);
        observation.RejectAttempt();
        observation.EndAttempt();

        observation.BeginAttempt();
        Read(observation, PasswordProofTiming.NativeRead, reordered, 2, 5);
        Read(observation, PasswordProofTiming.HistoryRead, request, 1, 6);
        observation.RejectAttempt();
        observation.EndAttempt();

        observation.BeginAttempt();
        Read(observation, PasswordProofTiming.NativeRead, request, 2, 7);
        Read(observation, PasswordProofTiming.HistoryRead, reordered, 1, 8);
        observation.EndAttempt();

        var summary = Assert.IsType<JsonObject>(observation.Report(committed: true));
        Assert.True(JsonNode.DeepEquals(summary["read_attempts"], JsonNode.Parse("""
            {"rejected":{"native":{"calls":2,"rows":4,"ms":8,"repeats":0,"untracked":0},
                         "history":{"calls":2,"rows":2,"ms":10,"repeats":1,"untracked":0}},
             "committed":{"native":{"calls":1,"rows":2,"ms":7,"repeats":1,"untracked":0},
                          "history":{"calls":1,"rows":1,"ms":8,"repeats":0,"untracked":0}}}
            """)));
        Assert.Null(observation.Report(committed: false)!["read_attempts"]!["committed"]);

        var nextInvocation = new PasswordProofObservation(clock);
        nextInvocation.BeginAttempt();
        Read(nextInvocation, PasswordProofTiming.NativeRead, request, 2, 1);
        for (int i = 0; i < 512; i++)
            Read(nextInvocation, PasswordProofTiming.NativeRead, i.ToString(), 0, 0);
        string largeRequest = new('q', 512 * 1024);
        Read(nextInvocation, PasswordProofTiming.HistoryRead, largeRequest, 0, 0);
        Read(nextInvocation, PasswordProofTiming.HistoryRead, largeRequest, 0, 0);
        nextInvocation.EnterSplit();
        nextInvocation.EndAttempt();
        Assert.True(JsonNode.DeepEquals(nextInvocation.Report(committed: true)!["read_attempts"]!["committed"],
            JsonNode.Parse("""
                {"native":{"calls":513,"rows":2,"ms":1,"repeats":0,"untracked":1},
                 "history":{"calls":2,"rows":0,"ms":0,"repeats":0,"untracked":1}}
                """)));

        void Read(PasswordProofObservation target, PasswordProofTiming phase, string serialized, int rows, long ms)
        {
            bool native = phase == PasswordProofTiming.NativeRead;
            if (native) target.ReadNative();
            else target.ReadHistory();
            using (target.Measure(phase))
            {
                target.ObserveReadRequest(phase, serialized);
                clock.Advance(ms);
            }
            if (native) target.ReceiveNative(rows);
            else target.ReceiveHistory(rows);
        }
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


    [Theory]
    [InlineData(10_001, 26_000_000L, "records")]
    [InlineData(10_000, 33_554_433L, "xml_bytes")]
    [InlineData(10_001, 33_554_433L, "records")]
    public void Records_limit_has_diagnostics_separate_from_the_adaptive_proof_budget(
        int records, long xmlBytes, string limit)
    {
        const string lastSqlStep = "read_password_episode_portions_v2";
        var error = new PasswordFailure("password_v2_proof_bound") { RecordsProofLimit = (records, xmlBytes) };
        var diagnostic = DetectionDiagnostics.Describe(error, lastSqlStep);
        var logged = Assert.IsType<JsonObject>(JsonNode.Parse(diagnostic.ToJsonString()));

        Assert.Equal(lastSqlStep, logged["step"]!.GetValue<string>());
        Assert.Equal("password_v2_proof_bound", logged["reason"]!.GetValue<string>());
        Assert.Null(error.ProofBudget);
        Assert.False(logged.ContainsKey("proof_budget"));

        var recordLimit = Assert.IsType<JsonObject>(logged["records_proof_limit"]);
        Assert.Equal("PasswordRule.Records", recordLimit["check"]!.GetValue<string>());
        Assert.Equal(records, recordLimit["records"]!.GetValue<int>());
        Assert.Equal(xmlBytes, recordLimit["xml_bytes"]!.GetValue<long>());
        Assert.Equal(limit, recordLimit["limit"]!.GetValue<string>());
        Assert.Equal(PasswordProofBudget.MaxReferences, recordLimit["max_records"]!.GetValue<int>());
        Assert.Equal(PasswordProofBudget.MaxXmlBytes, recordLimit["max_xml_bytes"]!.GetValue<int>());

        var planned = Assert.Throws<PasswordFailure>(
            () => PasswordProofBudget.Check(PasswordProofPhase.RetainedChain, records, xmlBytes));
        var plannedDiagnostic = DetectionDiagnostics.Describe(planned, lastSqlStep);
        Assert.Equal("RetainedChain", plannedDiagnostic["proof_budget"]!["phase"]!.GetValue<string>());
        Assert.False(plannedDiagnostic.ContainsKey("records_proof_limit"));
    }

    [Theory]
    [InlineData("password_v2_tracking_invalid", "complete_password_producer_batch_v2", "22023", "tracking_invalid")]
    [InlineData("password_v2_emission_hash_conflict", "complete_password_producer_batch_v2", "22023", "emission_hash_conflict")]
    [InlineData("password_v2_tracking_invalid with extra context", "complete_password_producer_batch_v2", "22023", "unclassified_22023")]
    [InlineData("password_v2_tracking_invalid", "read_password_episode_portions_v2", "22023", null)]
    [InlineData("password_v2_tracking_invalid", "complete_password_producer_batch_v2", "40001", null)]
    public void Finalizer_check_serializes_only_for_invalid_parameters_at_completion(
        string messageText, string step, string sqlState, string? expected)
    {
        var error = new PostgresException(messageText, "ERROR", "ERROR", sqlState);
        string json = DetectionDiagnostics.Describe(error, step).ToJsonString();
        var logged = Assert.IsType<JsonObject>(JsonNode.Parse(json));

        Assert.Equal(step, logged["step"]!.GetValue<string>());
        Assert.Equal(sqlState, logged["sql_state"]!.GetValue<string>());
        Assert.Equal("operation_failed", logged["reason"]!.GetValue<string>());
        Assert.DoesNotContain(messageText, json);
        if (expected is null)
            Assert.False(logged.ContainsKey("finalizer_check"));
        else
            Assert.Equal(expected, logged["finalizer_check"]!.GetValue<string>());
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
