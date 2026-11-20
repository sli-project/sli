using System.Net;
using System.Text.Json;
using Xunit;

namespace Sli.Server.Tests.Access;

[Collection("Owned access requests")]
public sealed class AccessRequestInputTests
{
    private const string Requests = "/api/v1/access/report-requests";
    private static string Decision(long id) => Requests + "/" + id + "/decision";
    private static void Plain((HttpStatusCode Status, JsonElement Body) actual, string error)
    {
        Assert.Equal(HttpStatusCode.BadRequest, actual.Status);
        Assert.True(JsonElement.DeepEquals(JsonSerializer.SerializeToElement(new { error }), actual.Body), actual.Body.GetRawText());
    }
    private static async Task Pending(AccessRequestFixture f, long id, CancellationToken ct)
    {
        var state = await f.StateAsync(id, ct); Assert.Equal("submitted", state.Status); Assert.Null(state.DecidedBy); Assert.Null(state.AssignmentId);
        Assert.Equal(0, state.Grants); Assert.Equal(0, state.DecisionAudits); Assert.Equal(0, state.AssignmentAudits);
    }

    [Fact]
    public async Task ScalarDecisionIterablesReturnSourceTypeError400InBothLocalesWithoutClaim()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await AccessRequestFixture.OpenAsync(ct); using var host = f.Host(); using var client = f.Client(host);
        var created = await f.Send(client, "POST", Requests, f.Request(), f.RequesterCookie); Assert.Equal(HttpStatusCode.Created, created.Status);
        long id = created.Body.GetProperty("item").GetProperty("id").GetInt64();
        var evidence = new List<object>();
        foreach (string language in new[] { "ru", "en" })
        foreach (string field in new[] { "field_categories", "allowed_actions" })
        foreach ((string raw, string type) in new[] { ("null", "NoneType"), ("false", "bool"), ("true", "bool"), ("0", "int"), ("12", "int"), ("1.5", "float"), ("2e0", "float") })
        {
            using var value = JsonDocument.Parse(raw); var payload = f.Decision(); payload[field] = value.RootElement.Clone();
            var result = await f.Send(client, "POST", Decision(id), payload, f.ReviewerCookie, language: language);
            string error = "'" + type + "' object is not iterable"; Plain(result, error); await Pending(f, id, ct);
            evidence.Add(new { language, field, input = raw, status = (int)result.Status, body = result.Body });
        }
        Assert.False((await f.EffectiveAsync(client)).GetProperty("allowed").GetBoolean()); Assert.Empty(await f.DomainsAsync(client));
        await AccessRequestFixture.RecordAsync("gap051-scalars", new { requests = evidence, final_state = await f.StateAsync(id, ct) });
    }

    [Fact]
    public async Task OmittedDefaultsObjectKeysStringIterationAndEmptyFieldGuardStayDistinct()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = await AccessRequestFixture.OpenAsync(ct); using var host = f.Host(); using var client = f.Client(host);
        async Task<long> Create()
        {
            var r = await f.Send(client, "POST", Requests, f.Request("domain"), f.RequesterCookie); Assert.Equal(HttpStatusCode.Created, r.Status);
            return r.Body.GetProperty("item").GetProperty("id").GetInt64();
        }
        long id = await Create();
        foreach ((string field, object value) in new (string, object)[] {
            ("field_categories", "identity_basic"), ("allowed_actions", "view"),
            ("field_categories", ""), ("field_categories", Array.Empty<string>()), ("field_categories", new Dictionary<string, object>()),
            ("allowed_actions", Array.Empty<string>()) })
        {
            var payload = f.Decision(); payload[field] = value;
            Plain(await f.Send(client, "POST", Decision(id), payload, f.ReviewerCookie), "decision_may_not_expand_request"); await Pending(f, id, ct);
        }
        var objects = f.Decision(); objects["field_categories"] = AccessRequestFixture.Fields.ToDictionary(v => v, _ => (object?)null);
        objects["allowed_actions"] = new Dictionary<string, object?> { ["view"] = false };
        var approvedObjects = await f.Send(client, "POST", Decision(id), objects, f.ReviewerCookie); Assert.Equal(HttpStatusCode.OK, approvedObjects.Status);
        Assert.Equal(AccessRequestFixture.Fields, approvedObjects.Body.GetProperty("item").GetProperty("granted_field_categories").EnumerateArray().Select(v => v.GetString()));
        Assert.Equal(new long[] { 101 }, await f.DomainsAsync(client));
        await f.ResetOwnRequestsAsync(ct); id = await Create();
        var omitted = await f.Send(client, "POST", Decision(id), f.Decision(), f.ReviewerCookie); Assert.Equal(HttpStatusCode.OK, omitted.Status);
        Assert.Equal(AccessRequestFixture.Fields, omitted.Body.GetProperty("item").GetProperty("granted_field_categories").EnumerateArray().Select(v => v.GetString()));
        Assert.Equal("view", Assert.Single(omitted.Body.GetProperty("item").GetProperty("granted_actions").EnumerateArray()).GetString());
        var state = await f.StateAsync(id, ct); Assert.Equal(1, state.Grants); Assert.Equal(1, state.DecisionAudits);
        await AccessRequestFixture.RecordAsync("gap051-iterables", new { string_iteration_rejected_by_subset = true, empty_field_guard_retained = true, object_key_iteration_approved = true, omitted_defaults_approved = true, state });
    }
}
