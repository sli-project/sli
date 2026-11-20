using System.Text.Json.Nodes;
using Sli.Server.Domains;
using Sli.Server.Problems;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Detections;
using Sli.Server.Semantic.Password;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class AgentStopDetectionTests
{
    private static readonly DateTimeOffset At = DateTimeOffset.Parse("2026-11-13T10:00:00Z");
    private static readonly PasswordScope Scope = new("00000000-0000-0000-0000-000000000001", "sli.windows.ad-dc", "dc.example.test", "generation", "");
    private static DetectionRow Row(string id, int eventId, JsonObject fields) =>
        new(new(Scope, "core_event", id, new('a', 64)), At, eventId, "dc.example.test", fields);

    [Theory]
    [InlineData(7036, "param1", "SLIAgentNet", "param2", "stopped")]
    [InlineData(7040, "param4", "SLIAgentNet", "param3", "disabled")]
    public async Task Native_service_events_keep_one_problem_identity_across_repetitions(int eventId, string serviceKey, string service, string stateKey, string state)
    {
        var row = Row("1", eventId, new() { [serviceKey] = service, [stateKey] = state });
        var native = DetectionNative.ParseEvents(Scope, [DetectionTests.Native(row, false)]);
        var first = Assert.Single(AttackPrecursors.DetectEvents(native, At));
        var repeated = Assert.Single(AttackPrecursors.DetectEvents([row with { Ref = row.Ref with { NativeId = "2" }, At = At.AddHours(1) }], At.AddHours(1)));
        Assert.Equal("qw.agent-tamper", first["rule_id"]!.ToString());
        Assert.Equal("high", first["effective_severity"]!.ToString());
        Assert.Equal(first["entity_key"]!.ToString(), repeated["entity_key"]!.ToString());
        var proposal = await Proposal(first);
        var repeatProposal = await Proposal(repeated);
        Assert.Equal(proposal.Identity, repeatProposal.Identity);
        Assert.NotEqual(proposal.Contribution, repeatProposal.Contribution);
        Assert.Equal("dc.example.test", proposal.Strict["target_entity"]!.ToString());
        Assert.NotEqual(DetectionSignal.Id(first), DetectionSignal.Id(repeated));
        AttackPrecursors.Validate(first);
    }

    [Theory]
    [InlineData("ru", "Агент SLI остановлен или отключён", "Служба агента на dc.example.test остановлена в 2026-11-13T10:00:00Z, запуск изменил example.test\\admin.", "1) Запустите службу `SLIAgentNet` на компьютере. 2) Если её останавливали не вы — проверьте «Изменения в домене» по example.test\\admin.")]
    [InlineData("en", "The SLI agent was stopped or disabled", "The agent service on dc.example.test was stopped at 2026-11-13T10:00:00Z; startup changed by example.test\\admin.", "1) Start the `SLIAgentNet` service on the computer. 2) If you did not stop it, check Domain changes for example.test\\admin.")]
    public void Home_and_queue_render_catalog_text_without_adding_the_counter(string language, string title, string what, string next)
    {
        var finding = new JsonObject { ["rule_code"] = "semantic.qw.agent-tamper", ["title"] = "SLI agent service tampering", ["target"] = "dc.example.test", ["actor"] = "example.test\\admin", ["last_seen_utc"] = "2026-11-13T10:00:00Z", ["occurrence_count"] = 3 };
        var home = HomePresentation.Finding(finding, language);
        var queue = ProblemPresentation.Finding(finding, Problems.ProblemLifecycleTests.Access("security.queue"), language);
        Assert.Equal(title, home["title"]!.ToString());
        Assert.Equal(what, home["what"]!.ToString());
        Assert.Equal(next, home["next_step"]!.ToString());
        Assert.Equal(title, queue["title"]!.ToString());
        Assert.Equal(what, queue["summary"]!.ToString());
        Assert.Equal(next, queue["recommended_action"]!.ToString());
    }

    [Theory]
    [InlineData("ru", "Служба агента на dc.example.test остановлена в 2026-11-13T10:00:00Z.")]
    [InlineData("en", "The agent service on dc.example.test was stopped at 2026-11-13T10:00:00Z.")]
    public void Missing_initiator_omits_only_the_initiator_clause(string language, string what)
    {
        var finding = new JsonObject { ["rule_code"] = "semantic.qw.agent-tamper", ["target"] = "dc.example.test", ["last_seen_utc"] = "2026-11-13T10:00:00Z", ["evidence_count"] = 1 };
        var view = HomePresentation.Finding(finding, language);
        Assert.Equal(what, view["what"]!.ToString());
        Assert.Contains("SLIAgentNet", view["next_step"]!.ToString());
        Assert.Contains(language == "en" ? "Domain changes" : "Изменения в домене", view["next_step"]!.ToString());
    }

    [Fact]
    public void Running_or_other_service_does_not_raise_an_agent_stop()
    {
        Assert.Empty(AttackPrecursors.DetectEvents([Row("1", 7036, new() { ["param1"] = "SLIAgentNet", ["param2"] = "running" }), Row("2", 7036, new() { ["param1"] = "OtherService", ["param2"] = "stopped" })], At));
    }

    private static Task<SemanticProposal> Proposal(JsonObject signal)
    {
        var definition = AttackPrecursors.PolicyDefinition(signal);
        var policy = SemanticPolicy.Compile(new JsonObject { ["policy_id"] = "synthetic-agent-stop", ["policy_version"] = 1, ["source_kind"] = "qw_signal", ["definition_json"] = definition });
        return SemanticProduction.Proposal(new SourceSession(signal), policy, DetectionSignal.Id(signal), "enabled", TestContext.Current.CancellationToken);
    }

    private sealed class SourceSession(JsonObject signal) : ISemanticSession
    {
        public Task CommitAsync(CancellationToken ct) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values) => Task.FromResult(sql switch {
            "select * from semantic_qw_signals where signal_id=$1" => new JsonArray(new JsonObject { ["document_json"] = signal.DeepClone() }),
            "select public.qw_signal_evidence_allowed($1,true) as verified" => new JsonArray(new JsonObject { ["verified"] = true }),
            "select public.resolve_finding_evidence_ref($1,$2,$3,$4,$5,$6,$7,$8) as verified" => new JsonArray(new JsonObject { ["verified"] = true }),
            _ => throw new InvalidOperationException(sql)
        });
    }
}
