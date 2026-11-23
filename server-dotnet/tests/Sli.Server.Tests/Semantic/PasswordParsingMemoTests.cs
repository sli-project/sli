using System.Diagnostics;
using System.Text.Json.Nodes;
using Sli.Server.Semantic.Password;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordParsingMemoTests(ITestOutputHelper output)
{
    [Fact]
    public void Only_exact_fresh_input_reuses_managed_parsing()
    {
        var input = PasswordRuleTests.Event(1, 10, user: "fixture");
        var observation = new PasswordProofObservation();
        var memo = new PasswordNativeParsing(observation);
        PasswordNative Read(string raw, string hash, bool normalized = true) =>
            memo.Parse(input.Witness.Scope, input.Witness.NativeId, hash, input.EventId, input.Witness.At, raw, normalized);

        var original = Read(input.SourceXml, input.Witness.Sha256);
        Assert.Same(original, Read(new string(input.SourceXml.AsSpan()), input.Witness.Sha256));
        Assert.NotSame(original, Read(input.SourceXml, new string('b', 64)));
        Assert.NotSame(original, Read(input.SourceXml, input.Witness.Sha256, normalized: false));
        var changed = Read(input.SourceXml.Replace("fixture", "other", StringComparison.Ordinal), input.Witness.Sha256);
        Assert.NotEqual(original.Witness.XmlSha256, changed.Witness.XmlSha256);
        Assert.ThrowsAny<Exception>(() => Read("<broken", input.Witness.Sha256));
        Assert.NotSame(original, new PasswordNativeParsing(observation)
            .Parse(input.Witness.Scope, input.Witness.NativeId, input.Witness.Sha256, input.EventId,
                input.Witness.At, input.SourceXml, true));
        observation.EnterSplit();
        var report = observation.Report(false)!;
        Assert.Equal(6, report["managed_parses"]!.GetValue<long>());
        Assert.Equal(1, report["managed_parse_reuses"]!.GetValue<long>());
    }

    [Fact]
    public void A_cached_raw_parse_does_not_validate_a_modified_managed_witness()
    {
        var input = PasswordRuleTests.Event(1, 10, user: "fixture");
        var rule = new PasswordRule(input.Witness.Scope, "spray", 395);
        var memo = new PasswordNativeParsing(new PasswordProofObservation());
        var checkedNative = memo.Parse(rule.Scope, input.Witness.NativeId, input.Witness.Sha256,
            input.EventId, input.Witness.At, input.SourceXml, true);
        var modified = checkedNative with { Member = checkedNative.Member with { Failure = "other_failure" } };
        var error = Assert.Throws<PasswordFailure>(() => rule.Advance(new(), [modified],
            modified.Witness.At.AddSeconds(120), [], [], null, memo));
        Assert.Equal("password_v2_native_content_conflict", error.Message);
    }

    [Fact]
    public void Repeated_speculative_attempts_keep_identical_managed_commit_payload()
    {
        var initial = Enumerable.Range(1, 5).Select(i => PasswordRuleTests.Event(i, i, user: $"fixture{i}")).ToArray();
        var rule = new PasswordRule(initial[0].Witness.Scope, "spray", 395);
        PasswordNative Parse(PasswordNativeParsing memo, PasswordNative raw) =>
            memo.Parse(rule.Scope, raw.Witness.NativeId, raw.Witness.Sha256, raw.EventId,
                raw.Witness.At, raw.SourceXml, rule.NormalizedAccounts);
        var seedMemo = new PasswordNativeParsing(new PasswordProofObservation());
        var rootNative = initial.Select(n => Parse(seedMemo, n)).ToArray();
        var start = rule.Advance(new(), rootNative, rootNative[^1].Witness.At.AddSeconds(120));
        Assert.Single(start.Emissions);
        var retainedInput = Enumerable.Range(100, 1800).Select(i => PasswordRuleTests.Event(i, 10, user: "fixture")).ToArray();
        var candidates = Enumerable.Range(3000, 64).Select(i => PasswordRuleTests.Event(i, 20 + (i - 3000) / 2, user: "fixture")).ToArray();

        (PasswordProposal Committed, long Parses, long Reuses, long Bytes, double Milliseconds) Run(bool reuse)
        {
            var observation = new PasswordProofObservation();
            var memo = new PasswordNativeParsing(observation, reuse);
            var saved = PasswordState.Read(start.State.Document);
            var begin = Stopwatch.GetTimestamp();
            long allocated = GC.GetAllocatedBytesForCurrentThread();
            PasswordProposal? committed = null;
            foreach (int count in new[] { 64, 32, 16, 8, 4, 2 })
            {
                observation.BeginAttempt();
                observation.EnterSplit();
                var retained = retainedInput.Select(n => Parse(memo, n)).ToArray();
                var due = candidates.Take(count).Select(n => Parse(memo, n)).ToArray();
                var replay = rule.AdvanceWithRetainedChain(saved, due, due[^1].Witness.At.AddSeconds(120),
                    start.Emissions, retained, null, rootNative, null, memo);
                Assert.Single(replay.Emissions);
                if (count == 2) committed = replay;
                else observation.RejectAttempt();
                observation.EndAttempt();
            }
            var bytes = GC.GetAllocatedBytesForCurrentThread() - allocated;
            var elapsed = Stopwatch.GetElapsedTime(begin).TotalMilliseconds;
            var report = observation.Report(true)!;
            Assert.Equal(5, report["rejected_attempts"]!.GetValue<int>());
            Assert.True(JsonNode.DeepEquals(saved.Document, start.State.Document));
            return (Assert.IsType<PasswordProposal>(committed), report["managed_parses"]!.GetValue<long>(),
                report["managed_parse_reuses"]!.GetValue<long>(), bytes, elapsed);
        }

        _ = Run(false);
        _ = Run(true);
        for (int pair = 0; pair < 3; pair++)
        {
            var first = Run(pair % 2 != 0);
            var second = Run(pair % 2 == 0);
            var (baseline, memoized) = pair % 2 == 0 ? (first, second) : (second, first);
            Assert.True(JsonNode.DeepEquals(baseline.Committed.State.Serialize(indexed: true), memoized.Committed.State.Serialize(indexed: true)));
            Assert.True(JsonNode.DeepEquals(baseline.Committed.State.Serialize(indexed: false), memoized.Committed.State.Serialize(indexed: false)));
            Assert.Equal(baseline.Committed.Emissions.Select(e => e.Id), memoized.Committed.Emissions.Select(e => e.Id));
            var oldEmission = Assert.Single(baseline.Committed.Emissions);
            var newEmission = Assert.Single(memoized.Committed.Emissions);
            string rootId = Assert.Single(start.Emissions).Id;
            var oldContext = Assert.Single(oldEmission.Contexts(rootId));
            var newContext = Assert.Single(newEmission.Contexts(rootId));
            Assert.True(JsonNode.DeepEquals(oldContext, newContext));
            var signalNative = rootNative.Concat(candidates.Take(2).Select(n => Parse(seedMemo, n))).ToArray();
            var observedAt = oldEmission.Endpoint.At.AddSeconds(120);
            Assert.True(JsonNode.DeepEquals(
                PasswordSignal.Create(rule, oldEmission, oldContext, observedAt, signalNative, start.Emissions),
                PasswordSignal.Create(rule, newEmission, newContext, observedAt, signalNative, start.Emissions)));
            Assert.Equal(baseline.Parses, memoized.Parses + memoized.Reuses);
            Assert.True(memoized.Bytes < baseline.Bytes);
            output.WriteLine($"pair={pair + 1} plain_parses={baseline.Parses} memo_parses={memoized.Parses} " +
                $"memo_reuses={memoized.Reuses} plain_bytes={baseline.Bytes} memo_bytes={memoized.Bytes} " +
                $"plain_ms={baseline.Milliseconds:F2} memo_ms={memoized.Milliseconds:F2}");
        }
    }
}
