using System.Globalization;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Sli.Server.Entities;
using Sli.Server.Access;
using Xunit;

namespace Sli.Server.Tests.Entities;

public sealed class EntityReadContractTests
{
    [Fact]
    public void UiAdContextProjectionKeepsOnlyAuthorizedKnownAttributesAndOmitsRelations()
    {
        var facts = new AccessFacts(false, "viewer", [], [], new[] { "objects.view", "evidence.exact", "field.security", "field.technical" }
            .Select(c => System.Text.Json.JsonSerializer.SerializeToElement(new { capability_key = c, effect = "allow", scope_json = new { kind = "all" } })).ToArray(), [], [], [], []);
        var context = JsonNode.Parse("""
            {"entity_id":7,"resolution":"shared_entity_id","returned_count":2,"bounded":true,"items":[
              {"context_kind":"entity","context_evidence_id":1,"integrity_sha256":"hidden","subject_entity_id":7,
               "attributes":{"identity":{"object_sid":"S-1-5-21-100000001-200000002-300000003-7"},"attributes":{"enabled":true,"unknown_secret":"hidden"}}},
              {"context_kind":"relation","related_entity_id":8,"attributes":{"membership_type":"direct"}}]}
            """)!.AsObject();
        var result = EntityDirectoryReader.Project(context, new CapabilityComposer().Compose(facts), new JsonObject { ["id"] = 7, ["domain_id"] = 1, ["server_id"] = 7 }, false);
        Assert.Equal(1, result["returned_count"]!.GetValue<int>());
        var item = Assert.Single(result["items"]!.AsArray());
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"enabled":true,"object_sid":"S-1-5-21-100000001-200000002-300000003-7"}"""), item!["attributes"]));
        Assert.DoesNotContain("hidden", result.ToJsonString());
    }
    [Fact]
    public void SecurityActionProjectionMatchesEverySourceEventFamilyAndObservedChanges()
    {
        using var stream = typeof(EntityReadContractTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Entities.entity-security-vectors.json")!;
        var fixture = JsonNode.Parse(stream)!;
        foreach (var item in fixture["cases"]!.AsArray().OfType<JsonObject>())
        {
            var row = item["input"]!.AsObject();
            if (item["event_data"] is JsonObject data) Assert.True(JsonNode.DeepEquals(row["source_native_change"], EntitySecurityProjection.SourceChange(checked((int)EntityReader.Number(row, "event_id")), data)));
            var actual = EntitySecurityProjection.Present(row);
            Assert.True(JsonNode.DeepEquals(item["expected"], actual), $"Source event {row["event_id"]}: expected {item["expected"]}, actual {actual}");
        }
    }
    [Theory]
    [InlineData("?time_from=2026-01-01&time_to=2026-01-01&timezone=Asia/Bangkok", "2025-12-31T17:00:00Z", "2026-01-01T17:00:00Z")]
    [InlineData("?time_from=2026-01-01T03:00:00%2B03:00&time_to=2026-01-02T03:00:00%2B03:00", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")]
    public void NormalizesDateEndToNextLocalMidnightExactlyOnce(string query, string start, string end)
    {
        var context = new DefaultHttpContext(); context.Request.QueryString = new(query);
        var options = EntityReadInput.Detail(context.Request.Query, false); Assert.Equal(start, options.From); Assert.Equal(end, options.To);
    }
    [Theory]
    [InlineData("2026-03-08T02:30:00", "nonexistent_local_datetime")]
    [InlineData("2026-11-01T01:30:00", "ambiguous_local_datetime_requires_offset")]
    public void LocalDstGapsAndAmbiguityAreRejected(string time, string error)
    { Assert.Equal(error, Assert.Throws<EntityInputException>(() => EntityReadInput.Range(time, "2026-11-02", "America/New_York")).Message); }
    [Theory] [InlineData("١_٠", 10)] [InlineData("+20", 20)] [InlineData("99999999999999999999999999999999999999999", int.MaxValue)]
    public void NumericInputUsesPythonDecimalAndClampingRules(string value, int expected)
    { Assert.Equal(expected, EntityReadInput.Limit(value, 50, "invalid")); }
    [Theory] [InlineData("1__0")] [InlineData("_1")] [InlineData("1_")] [InlineData("--1")] [InlineData("+_1")]
    public void MalformedNumericInputIsRejected(string value)
    { Assert.Equal("invalid", Assert.Throws<EntityInputException>(() => EntityReadInput.Limit(value, 50, "invalid")).Message); }
    [Fact]
    public void PriorObservationDoesNotClaimContinuousState()
    {
        var rows = new JsonArray();
        foreach (var (eventId, id) in new[] { (4740, 1), (4767, 2) }) rows.Add(EntitySecurityProjection.Present(new() { ["event_id"] = eventId, ["event_db_id"] = id, ["time_created_utc"] = $"2026-01-01T00:00:0{id}Z", ["target_user_sid"] = "S-1-5-21-100000001-200000002-300000003-4" }));
        EntitySecurityProjection.ApplyHistory(rows);
        Assert.Equal("unknown", rows[0]!["account_change"]!["observed_transition"]!["before"]!["state"]!.ToString());
        Assert.Equal("partial", rows[1]!["account_change"]!["observed_transition"]!["before"]!["state"]!.ToString());
        Assert.Equal("locked", rows[1]!["account_change"]!["observed_transition"]!["before"]!["last_observed"]!["value"]!.ToString());
    }
    [Theory]
    [InlineData("domain:1|account_sid:S-1-5-21-100000001-200000002-300000003-4", true)]
    [InlineData("domain:1|member_sid:S-1-5-21-100000001-200000002-300000003-4|group_sid:S-1-5-21-100000001-200000002-300000003-5", true)]
    [InlineData("domain:1|account_member_sid:S-1-5-21-100000001-200000002-300000003-4", true)]
    [InlineData("domain:1|account_sid:S-1-5-18", false)]
    [InlineData("domain:1|account_sid:S-1-5-21-100000001-200000002-300000003-4|domain:2", false)]
    [InlineData("domain:01|account_sid:S-1-5-21-100000001-200000002-300000003-4", false)]
    public void IdentityBasisRequiresClosedExactDomainSidPartition(string partition, bool valid)
    { Assert.Equal(valid, EntitySecurityProjection.IdentityBasis(partition) is not null); }
}
