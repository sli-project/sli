using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordRetainedProofTests
{
    private static PasswordNative Witness(int id, int second, string name = "fixture")
    {
        var value = PasswordRuleTests.Event(id, second, user: name);
        return PasswordNative.Parse(value.Witness.Scope, id, value.Witness.Sha256, value.EventId,
            value.Witness.At, value.SourceXml, normalizeAccount: true);
    }

    private static PasswordNative WithIdentity(PasswordNative value, long id, string? hash = null)
    {
        var witness = value.Witness with { NativeId = id, Sha256 = hash ?? value.Witness.Sha256 };
        return value with { Witness = witness, Member = value.Member with { Witness = witness } };
    }

    private static (PasswordRule Rule, PasswordNative[] Native, PasswordProposal Proposal) Initial()
    {
        var native = Enumerable.Range(1, 5).Select(i => Witness(i, i, $"fixture{i}")).ToArray();
        var rule = new PasswordRule(native[0].Witness.Scope, "spray", 395);
        return (rule, native, rule.Advance(new(), native, native[^1].Witness.At.AddSeconds(120)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Independently_bounded_units_keep_the_same_continuation_signal_and_restart(bool wide)
    {
        var (rule, history, initial) = Initial();
        var current = Witness(6, 20);
        var endpoint = history[^1];
        var candidates = history.Skip(4)
            .Concat(Enumerable.Range(100, 9996).Select(id => WithIdentity(current, id))).ToArray();
        var now = current.Witness.At.AddSeconds(120);
        var readFrom = wide ? now.AddSeconds(-721) : (DateTimeOffset?)null;
        var state = PasswordState.Read(initial.State.Document);
        var reference = rule.Advance(state, [current], now, initial.Emissions, history, readFrom);
        var original = Assert.Throws<PasswordFailure>(() => rule.Advance(
            state, [current], now, initial.Emissions, history.Concat(candidates.Skip(1)).ToArray(), readFrom));
        Assert.Equal("password_v2_proof_bound", original.Message);

        var split = rule.AdvanceWithRetainedChain(state, [current], now, initial.Emissions, candidates,
            readFrom, history, original);
        Assert.True(JsonNode.DeepEquals(reference.State.Document, split.State.Document));
        var expected = Assert.Single(reference.Emissions);
        var actual = Assert.Single(split.Emissions);
        Assert.Equal(expected.Id, actual.Id);
        Assert.Equal(endpoint.Witness, actual.Predecessor);
        Assert.Equal(7, Assert.Single(split.State.Episodes).Budget.RefOccurrences);
        var context = Assert.Single(actual.Contexts(initial.Emissions[0].Id));
        var native = history.Append(current).ToArray();
        Assert.True(JsonNode.DeepEquals(
            PasswordSignal.Create(rule, expected, context, now, native, initial.Emissions),
            PasswordSignal.Create(rule, actual, context, now, native.Concat(candidates), initial.Emissions)));

        var replay = rule.AdvanceWithRetainedChain(PasswordState.Read(split.State.Document), [current], now,
            initial.Emissions.Append(actual).ToArray(), candidates, null, native, original);
        Assert.Empty(replay.Diagnostics);
        Assert.Empty(replay.Emissions);
        Assert.True(JsonNode.DeepEquals(split.State.Document, replay.State.Document));
    }

    [Fact]
    public void A_new_origin_after_a_frozen_barrier_does_not_use_already_finalized_window_members()
    {
        var (rule, history, initial) = Initial();
        var frozen = Assert.Single(initial.State.Episodes) with { Frozen = true };
        var older = Enumerable.Range(10, 4).Select(i => Witness(i, 600 + i, $"fixture{i}")).ToArray();
        var next = Enumerable.Range(20, 5).Select(i => Witness(i, 600 + i, $"fixture{i}")).ToArray();
        var saved = PasswordState.Read((initial.State with
        {
            Watermark = older[^1].Witness.At,
            Members = older.Select(n => n.Member).ToArray(),
            Active = [frozen],
        }).Document);
        var first = rule.Advance(saved, [next[0]], next[0].Witness.At.AddSeconds(120),
            retained: history.Concat(older).ToArray());
        Assert.Empty(first.Diagnostics);
        Assert.Empty(first.Emissions);
        Assert.Equal(next[0].Witness.At, first.State.Watermark);
        Assert.All(older, n => Assert.Contains(n.Member, first.State.Window));
        Assert.Equal(new[] { next[0].Witness }, Assert.Single(first.State.Episodes).Prequalification);

        var restored = PasswordState.Read(first.State.Document);
        var full = rule.Advance(restored, next[1..], next[^1].Witness.At.AddSeconds(120),
            retained: history.Concat(older).Append(next[0]).ToArray());
        var root = Assert.Single(full.Emissions);
        Assert.Equal(next.Select(n => n.Witness), root.RootProof);
        Assert.Equal(root.RootProof, root.Origin);
        Assert.NotEqual(frozen.Key, root.EpisodeKey);
        Assert.Equal(5, rule.VerifyChain([root], next).RefOccurrences);
    }

    [Fact]
    public async Task A_reserved_successor_consumes_its_barrier_once_in_emission_order()
    {
        var barriers = new Dictionary<string, JsonObject>
        {
            ["entity"] = new() { ["episode_key"] = "predecessor" },
        };
        var calls = new List<string>();

        async Task Stage(string key, string signal)
        {
            await PasswordProducer.StageReservation(barriers, "entity", key, [signal],
                predecessor => {
                    calls.Add("track:" + predecessor);
                    return Task.FromResult<JsonNode?>(new JsonObject {
                        ["status"] = "successor_authorized", ["successor_episode_key"] = key,
                    });
                },
                () => {
                    calls.Add("reserve:" + signal);
                    return Task.FromResult<JsonNode?>(new JsonObject {
                        ["status"] = "reserved", ["signal_ids"] = new JsonArray(signal),
                    });
                });
        }

        await Stage("successor", "root");
        await Stage("successor", "continuation");
        await Stage("later", "separate-root");

        Assert.Equal(new[] { "track:predecessor", "reserve:root", "reserve:continuation", "reserve:separate-root" }, calls);
        Assert.Empty(barriers);

        // A successful reservation can still roll back with the finalizer.
        barriers = new() { ["entity"] = new() { ["episode_key"] = "predecessor" } };
        await Stage("successor", "retry-root");
        Assert.Equal(new[] { "track:predecessor", "reserve:retry-root" }, calls.Skip(4));
    }

    [Theory]
    [InlineData("frozen", "signal", "successor", "password_v2_reservation_conflict")]
    [InlineData("reserved", "different-signal", "successor", "password_v2_reservation_conflict")]
    [InlineData("reserved", "signal", "wrong-episode", "password_v2_successor_conflict")]
    public async Task A_rejected_transition_cannot_consume_the_barrier(
        string status, string returnedSignal, string authorizedKey, string reason)
    {
        Dictionary<string, JsonObject> Prepared() => new()
        {
            ["entity"] = new() { ["episode_key"] = "predecessor" },
        };
        int tracked = 0, reservations = 0;

        Task Stage(Dictionary<string, JsonObject> barriers, string reserveStatus, string signal, string successor) =>
            PasswordProducer.StageReservation(barriers, "entity", "successor", ["signal"],
                predecessor => {
                    Assert.Equal("predecessor", predecessor);
                    tracked++;
                    return Task.FromResult<JsonNode?>(new JsonObject {
                        ["status"] = "successor_authorized", ["successor_episode_key"] = successor,
                    });
                },
                () => {
                    reservations++;
                    return Task.FromResult<JsonNode?>(new JsonObject {
                        ["status"] = reserveStatus, ["signal_ids"] = new JsonArray(signal),
                    });
                });

        var first = Prepared();
        var failure = await Assert.ThrowsAsync<PasswordFailure>(() => Stage(first, status, returnedSignal, authorizedKey));
        Assert.Equal(reason, failure.Message);
        Assert.Contains("entity", first.Keys);
        Assert.Equal(authorizedKey == "successor" ? 1 : 0, reservations);

        var retried = Prepared(); // The new savepoint loads its own locked context from SQL.
        await Stage(retried, "reserved", "signal", "successor");
        Assert.Equal(2, tracked);
    }

    [Theory]
    [InlineData("password_v2_episode_absent")]
    [InlineData("password_v2_barrier_conflict")]
    [InlineData("password_v2_lifetime_immutable")]
    public void Frozen_transition_diagnostics_allow_only_exact_reason_tokens(string reason)
    {
        var error = new PostgresException(reason, "ERROR", "ERROR", "55000",
            detail: "private-detail", where: "private-context");
        var safe = DetectionDiagnostics.Describe(error, "track_password_frozen_entity_v2");
        Assert.Equal(reason, safe["reason"]!.GetValue<string>());
        Assert.Equal("55000", safe["sql_state"]!.GetValue<string>());
        Assert.DoesNotContain("private-", safe.ToJsonString());

        var modified = new PostgresException(reason + ": private-detail", "ERROR", "ERROR", "55000");
        Assert.Equal("operation_failed",
            DetectionDiagnostics.Describe(modified, "track_password_frozen_entity_v2")["reason"]!.GetValue<string>());
    }

    [Fact]
    public void A_conflicting_overlap_or_missing_history_cannot_continue()
    {
        var (rule, history, initial) = Initial();
        var current = Witness(6, 20);
        var now = current.Witness.At.AddSeconds(120);
        var conflicting = WithIdentity(history[0], history[0].Witness.NativeId, new string('f', 64));
        var error = Assert.Throws<PasswordFailure>(() => rule.AdvanceWithRetainedChain(
            initial.State, [current], now, initial.Emissions, [conflicting], null, history, null));
        Assert.Equal("password_v2_native_content_conflict", error.Message);

        var incomplete = Assert.Throws<PasswordFailure>(() => rule.AdvanceWithRetainedChain(
            initial.State, [current], now, initial.Emissions, [], null, history[1..], null));
        Assert.Equal("password_v2_native_unavailable", incomplete.Message);
    }

    [Fact]
    public void Neither_unit_can_exceed_the_native_proof_limit()
    {
        var (rule, history, initial) = Initial();
        var current = Witness(6, 20);
        var now = current.Witness.At.AddSeconds(120);
        var oversized = Enumerable.Range(100, 10001).Select(id => WithIdentity(current, id)).ToArray();
        foreach (var (candidateUnit, chainUnit) in new[] { (oversized, history), (history, oversized) })
        {
            var error = Assert.Throws<PasswordFailure>(() => rule.AdvanceWithRetainedChain(
                initial.State, [current], now, initial.Emissions, candidateUnit, null, chainUnit, null));
            Assert.Equal("password_v2_proof_bound", error.Message);
        }
    }

    [Fact]
    public void Formerly_rejected_group_cannot_freeze_or_advance_when_the_first_pair_still_fits()
    {
        var (rule, history, initial) = Initial();
        var root = Assert.Single(initial.Emissions);
        var chain = new List<PasswordEmission> { root };
        var native = history.ToList();
        for (int sequence = 2; sequence <= 255; sequence++)
        {
            var previous = chain[^1];
            var next = Witness(sequence + 4, sequence + 4);
            native.Add(next);
            chain.Add(new PasswordEmission(root.EpisodeKey, root.Pin, root.Epoch, root.Entity, sequence,
                root.Seed, [], [next.Witness], previous.Endpoint, previous.Id, 1, 0, 0, 1, []));
        }
        var budget = rule.VerifyChain(chain, native);
        var endpoint = chain[^1];
        var state = initial.State with
        {
            Watermark = endpoint.Endpoint.At,
            Active = [Assert.Single(initial.State.Episodes) with
            {
                Sequence = endpoint.Sequence, LastEmission = endpoint.Id, Last = endpoint.Endpoint, EvidenceBudget = budget,
            }],
        };
        var candidate = Witness(2000, 310);
        var group = Enumerable.Range(2000, 256).Select(id => WithIdentity(candidate, id)).ToArray();
        Assert.Equal(256, budget.Reserve([endpoint.Endpoint, group[0].Witness]).Portions);
        Assert.Throws<PasswordFailure>(() => budget.Reserve(group.Select(n => n.Witness).Prepend(endpoint.Endpoint).ToArray()));
        var overUnion = Assert.Throws<PasswordFailure>(() => PasswordProofBudget.Check(
            PasswordProofPhase.RetainedChain, 10001, 1));
        var before = state.Document;
        var error = Assert.Throws<PasswordFailure>(() => rule.AdvanceWithRetainedChain(
            state, group, candidate.Witness.At.AddSeconds(120), chain, [], null, native, overUnion));
        Assert.Same(overUnion, error);
        Assert.True(JsonNode.DeepEquals(before, state.Document));
    }
}
