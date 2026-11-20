using System.Text.Json;
using Sli.Server.Agents.Control;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentRecoveryInputTests
{
    private const string Agent = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    private const string Other = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    private static JsonElement Json(string text) => JsonDocument.Parse(text).RootElement.Clone();
    private static JsonElement Authorization(string ids, string confirmation = "true", string token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") =>
        Json($$"""{"agent_id":"{{Agent}}","observation_ids":{{ids}},"preview_token":"{{token}}","confirm_loss":{{confirmation}}} """);

    [Fact]
    public void ExactOwnerConfirmationKeepsIdsAsStringsAndAllowsFullBigintBoundary()
    {
        var command = AgentRecoveryInput.Authorization(Authorization("[\"9223372036854775807\",\"1\"]"));
        Assert.Equal(Guid.Parse(Agent), command.Agent);
        Assert.Equal(new[] { "9223372036854775807", "1" }, command.ObservationIds);
        Assert.Equal(new string('a', 64), command.PreviewToken);
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("[1]")]
    [InlineData("[true]")]
    [InlineData("[\"0\"]")]
    [InlineData("[\"01\"]")]
    [InlineData("[\"-1\"]")]
    [InlineData("[\"１\"]")]
    [InlineData("[\" 1\"]")]
    [InlineData("[\"9223372036854775808\"]")]
    [InlineData("[\"1\",\"1\"]")]
    public void LossAuthorizationRejectsNoncanonicalOrDuplicateJournalIds(string ids)
    {
        Assert.Equal("agent_sequence_recovery_invalid", Assert.Throws<AgentControlException>(() => AgentRecoveryInput.Authorization(Authorization(ids))).Message);
    }

    [Theory]
    [InlineData("false")]
    [InlineData("1")]
    [InlineData("null")]
    public void ConfirmationMustBeLiteralTrue(string confirmation) =>
        Assert.Equal("agent_sequence_recovery_invalid", Assert.Throws<AgentControlException>(() => AgentRecoveryInput.Authorization(Authorization("[\"1\"]", confirmation))).Message);

    [Fact]
    public void PreviewTokenAndExactBodyShapeAreRequired()
    {
        Assert.Throws<AgentControlException>(() => AgentRecoveryInput.Authorization(Authorization("[\"1\"]", token: new string('A', 64))));
        Assert.Throws<AgentControlException>(() => AgentRecoveryInput.Authorization(Json("{}")));
        Assert.Throws<AgentControlException>(() => AgentRecoveryInput.Authorization(Json(Authorization("[\"1\"]").GetRawText().TrimEnd() .Replace("}", ",\"extra\":true}"))));
        var many = "[" + string.Join(',', Enumerable.Range(1, 101).Select(i => "\"" + i + "\"")) + "]";
        Assert.Throws<AgentControlException>(() => AgentRecoveryInput.Authorization(Authorization(many)));
    }

    [Theory]
    [InlineData("prepare")]
    [InlineData("complete")]
    public void ReplacementPassesOnlyDistinctCanonicalAgentIdsAndSourcePhases(string phase)
    {
        var command = AgentRecoveryInput.Replacement(Json($$"""{"old_agent_id":"{{Agent}}","new_agent_id":"{{Other}}","phase":"{{phase}}","confirm":true}"""));
        Assert.Equal(Guid.Parse(Agent), command.OldAgent); Assert.Equal(Guid.Parse(Other), command.NewAgent); Assert.Equal(phase, command.Phase);
    }

    [Fact]
    public void ReplacementNeverAcceptsSelfReplacementOrCoercedConfirmation()
    {
        foreach (string text in new[] {
            $$"""{"old_agent_id":"{{Agent}}","new_agent_id":"{{Agent}}","phase":"prepare","confirm":true}""",
            $$"""{"old_agent_id":"{{Agent}}","new_agent_id":"{{Other}}","phase":"PREPARE","confirm":true}""",
            $$"""{"old_agent_id":"{{Agent}}","new_agent_id":"{{Other}}","phase":"complete","confirm":1}""" })
            Assert.Equal("agent_replacement_invalid", Assert.Throws<AgentControlException>(() => AgentRecoveryInput.Replacement(Json(text))).Message);
    }
}