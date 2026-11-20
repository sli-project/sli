using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Sli.Server.Ad;
using Sli.Server.Semantic;
using Sli.Server.Storage.EventReports;
using Sli.Server.Access;
using Xunit;

namespace Sli.Server.Tests.Ad;

// Behavioral vectors from tests/reporting/test_security_event_reporting.py.
public sealed partial class SecurityEventReportingTests
{
    static readonly CancellationToken Ct = TestContext.Current.CancellationToken;
    static readonly AdPeriod Period = new(DateTimeOffset.Parse("2026-09-01T10:00:00Z"), DateTimeOffset.Parse("2026-09-01T11:00:00Z"));
    const string Actor = "S-1-5-21-100000001-200000002-300000003-1001";
    const string Target = "S-1-5-21-100000001-200000002-300000003-1002";
    const string Member = "S-1-5-21-100000001-200000002-300000003-1003";
    static JsonObject O(string json) => JsonNode.Parse(json)!.AsObject();
    static void Equal(string json, JsonNode? actual) => Assert.True(JsonNode.DeepEquals(JsonNode.Parse(json), actual), actual?.ToJsonString());
    static AdReportRequest Request(JsonObject? filters = null, int limit = 200, string? cursor = null, long domain = 7) => new("security", false, false, domain, Period, limit, filters ?? new(), cursor);
    static JsonObject Event(long id, int code, int minute = 1, long domain = 7) => new()
    {
        ["event_db_id"] = id, ["event_record_id"] = 9000 + id, ["event_id"] = code, ["domain_id"] = domain,
        ["time_created_utc"] = AdJson.Iso(Period.Start.AddMinutes(minute)), ["source_host"] = "dc01.example.test",
        ["subject_user_sid"] = Actor, ["subject_user_name"] = "operator", ["target_user_sid"] = Target,
        ["target_user_name"] = "affected", ["source_core_sha256"] = string.Concat(Enumerable.Repeat("61", 32)),
        ["source_facts_sha256"] = string.Concat(Enumerable.Repeat("62", 32))
    };
    static JsonObject Compose(params JsonObject[] events) => AdSecurity.Compose(Request(), events, true, false, new());
    static JsonObject Item(JsonObject page, long id) => page["items"]!.AsArray().OfType<JsonObject>().Single(r => r["event_db_id"]!.GetValue<long>() == id);
    static JsonObject Filters(params (string Key, string Value)[] values) => AdSecurity.Normalize(new QueryCollection(values.ToDictionary(p => p.Key, p => new StringValues(p.Value))));

    [Fact]
    public void Required_vocabulary_and_unrestricted_default_include_authentication()
    {
        int[] expected = [4740,4767,4723,4724,4720,4722,4725,4726,4738,4781,4728,4729,4732,4733,4756,4757,4727,4730,4737,4731,4734,4735,4754,4755,4758,4764,4719,1102];
        Assert.Equal(expected.Order(), AdHistory.Ids("SECURITY_EVENTS_REPORT_DEFAULT_EVENT_IDS").Order());
        Assert.Equal(expected.Concat([4624,4625,4771,4776]).Order(), AdSecurityQuery.Create(Request()).Selected.Order());
        Assert.Equal(new[] { "account_change","account_lifecycle","account_lock","audit_configuration","group_lifecycle","group_membership","password_operation" }, expected.Select(i => AdSecurity.Family(i)).Distinct().Order());
        Assert.Empty(Filters());
        Assert.Equal(new[] {4624,4625,4771,4776}, AdSecurityQuery.Create(Request(Filters(("category","authentication")))).Selected);
        Assert.Equal(new[] {4771}, AdSecurityQuery.Create(Request(Filters(("event_id","4771")))).Selected);
        var page = Compose(Event(1,4624),Event(2,4625),Event(3,4776),Event(4,4720));
        Assert.Equal(new[] {4624,4625,4720,4776}, page["items"]!.AsArray().Select(r => r!["event_id"]!.GetValue<int>()).Order());
    }

    [Fact]
    public void Roles_outcome_exact_evidence_and_reverse_cursor_are_preserved()
    {
        var member = Event(8,4728,8); member["membership_member_sid"] = Member; member["membership_member_name"] = "CN=Alice,DC=example,DC=test";
        member["member_entity_id"] = 101; member["target_entity_id"] = 202;
        var password = Event(9,4724,9); password["result_code"] = "0xC000006D"; password["audit_keywords"] = "0x8010000000000000"; password["source_facts_sha256"] = null;
        var page = AdSecurity.Compose(Request(limit:3), [member,password,Event(10,4740,10)], true, true, new());
        Assert.Equal(new long[] {10,9,8}, page["items"]!.AsArray().Select(r => r!["event_db_id"]!.GetValue<long>()));
        Equal("""{"state":"observed","value":"failure","result_code":"0xC000006D","basis":"audit_keywords"}""", Item(page,9)["outcome"]);
        var evidence = Item(page,9)["evidence"]!; Assert.Equal("partial", evidence["state"]!.ToString());
        Equal("""["source_facts_sha256"]""", evidence["missing_fields"]); Assert.Equal(string.Concat(Enumerable.Repeat("61",32)), evidence["source_core_sha256"]!.ToString());
        Assert.Null(evidence["source_facts_sha256"]); Assert.Equal(9009, evidence["event_record_id"]!.GetValue<long>());
        Equal($$"""{"state":"observed","sid":"{{Actor}}","name":"operator"}""", Item(page,10)["actor"]);
        Equal($$"""{"state":"observed","sid":"{{Target}}","name":"affected"}""", Item(page,10)["affected_account"]);
        Equal("""{"state":"unknown"}""", Item(page,10)["member"]); Equal("""{"state":"unknown"}""", Item(page,10)["group"]);
        Assert.Equal("unknown", Item(page,10)["outcome"]!["state"]!.ToString());
        Assert.Equal(101, Item(page,8)["member"]!["entity_id"]!.GetValue<long>()); Assert.Equal(202, Item(page,8)["group"]!["entity_id"]!.GetValue<long>());
        Equal("""{"state":"unknown"}""", Item(page,8)["affected_account"]);
        Assert.True(page["has_more"]!.GetValue<bool>());
        Assert.Equal((Period.Start.AddMinutes(8),8L), AdSecurity.DecodeCursor(page["next_cursor"]!.ToString(),7,Period,new()));
    }

    [Theory]
    [InlineData(null,"0x0","unknown")]
    [InlineData("AuditSuccess","0xC000006D","success")]
    [InlineData("AuditFailure","0x0","failure")]
    public void Password_outcome_requires_native_keywords(string? keywords, string result, string expected)
    {
        var e = Event(1,4724); e["audit_keywords"] = keywords; e["result_code"] = result;
        e["subject_user_sid"] = null; e["subject_user_name"] = null; e["target_user_sid"] = null; e["target_user_name"] = null;
        var item = Item(Compose(e),1); Equal("""{"state":"unknown"}""",item["actor"]); Equal("""{"state":"unknown"}""",item["affected_account"]);
        Assert.Equal(result,item["outcome"]!["result_code"]!.ToString());
        if (expected == "unknown") Equal("""{"state":"unknown","reason":"event_outcome_not_proven_by_scoped_contract","result_code":"0x0"}""",item["outcome"]);
        else { Assert.Equal(expected,item["outcome"]!["value"]!.ToString()); Assert.Equal("audit_keywords",item["outcome"]!["basis"]!.ToString()); }
    }

    [Fact]
    public void Account_transition_uses_previous_observation_without_claiming_continuity()
    {
        var page = Compose(Event(1,4720),Event(2,4722,2));
        Equal("""{"kind":"enabled"}""",Item(page,2)["account_change"]!["change"]);
        Equal("""{"before":{"state":"partial","last_observed":{"value":"present","event_db_id":1,"time_created_utc":"2026-09-01T10:01:00Z"},"reason":"intervening_account_state_not_proven"},"after":{"state":"observed","value":"enabled"}}""",Item(page,2)["account_change"]!["observed_transition"]);
        Assert.Equal("unknown",Item(Compose(Event(1,4720),Event(2,4722,2,8)),2)["account_change"]!["observed_transition"]!["before"]!["state"]!.ToString());
    }

    public static IEnumerable<object[]> ChangeVectors()
    {
        yield return [4738,"""{"DisplayName":"Alice Example","UserPrincipalName":"alice@example.test"}""","""{"state":"observed","kind":"attributes_changed","attributes":{"display_name":"Alice Example","user_principal_name":"alice@example.test"}}"""];
        yield return [4737,"""{"Description":"Tier zero","GroupType":"Security-enabled global group"}""","""{"state":"observed","kind":"group_changed","attributes":{"description":"Tier zero","group_type":"Security-enabled global group"}}"""];
        yield return [4764,"""{"OldGroupType":"Global","NewGroupType":"Universal"}""","""{"state":"observed","kind":"group_type_changed","old_group_type":"Global","new_group_type":"Universal"}"""];
        yield return [4719,"""{"CategoryId":"{cat}","SubcategoryId":"{sub}","AuditPolicyChanges":"Success removed"}""","""{"state":"observed","kind":"audit_policy_changed","category_id":"{cat}","subcategory_id":"{sub}","observed_value":"Success removed"}"""];
        yield return [1102,"""{"Channel":"Security"}""","""{"state":"observed","kind":"security_log_cleared","observed_value":"Security"}"""];
        yield return [4738,"""{"DisplayName":" - ","UserPrincipalName":"alice@example.test"}""","""{"state":"observed","kind":"attributes_changed","attributes":{"user_principal_name":"alice@example.test"}}"""];
        yield return [4737,"""{"Description":"-","GroupType":"Security-enabled global group"}""","""{"state":"observed","kind":"group_changed","attributes":{"group_type":"Security-enabled global group"}}"""];
        yield return [4738,"""{"DisplayName":"-","UserPrincipalName":" - "}""","""{"state":"partial","kind":"attributes_changed","detail":{"state":"unknown","reason":"account_attributes_not_present"}}"""];
        yield return [4737,"""{"Description":"-","GroupType":" - "}""","""{"state":"partial","kind":"group_changed","detail":{"state":"unknown","reason":"group_change_attributes_not_present"}}"""];
        yield return [4764,"{}","""{"state":"partial","kind":"group_type_changed","detail":{"state":"unknown","reason":"group_type_values_not_present"}}"""];
        yield return [4719,"{}","""{"state":"partial","kind":"audit_policy_changed","detail":{"state":"unknown","reason":"audit_policy_fields_not_present"}}"""];
        yield return [1102,"{}","""{"state":"observed","kind":"security_log_cleared"}"""];
    }

    static SemanticEvent Projection(int code, JsonObject data) => SemanticNormalization.ProjectSource(new JsonObject {
        ["id"] = 1, ["event_id"] = code, ["server_id"] = 1, ["source_host_id"] = 1, ["domain_id"] = 7,
        ["channel"] = "Security", ["provider_name"] = code == 1102 ? "Microsoft-Windows-Eventlog" : "Microsoft-Windows-Security-Auditing",
        ["time_created_utc"] = "2026-09-01T10:01:00Z", ["event_data_json"] = data.DeepClone() });

    [Theory]
    [InlineData(4722)] [InlineData(4723)] [InlineData(4725)] [InlineData(4726)] [InlineData(4738)] [InlineData(4781)]
    [InlineData(4727)] [InlineData(4730)] [InlineData(4731)] [InlineData(4734)] [InlineData(4735)] [InlineData(4737)]
    [InlineData(4754)] [InlineData(4755)] [InlineData(4758)] [InlineData(4764)]
    public void Supported_report_events_have_specific_semantics(int code) => Assert.NotEqual("event.unknown",Projection(code,new()).Type);

    [Theory] [InlineData("Application","Microsoft-Windows-Security-Auditing")] [InlineData("Security","untrusted")]
    public void Supplemental_semantics_still_require_exact_source_descriptor(string channel,string provider)
    {
        var source = Event(1,4764); source["id"] = 1; source["server_id"] = 1; source["channel"] = channel; source["provider_name"] = provider; source["event_data_json"] = new JsonObject();
        Assert.Equal("event.unknown",SemanticNormalization.ProjectSource(source).Type);
    }

    [Theory] [MemberData(nameof(ChangeVectors))]
    public async Task Allowlisted_changes_match_projection_and_public_report(int code, string native, string expected)
    {
        var e = Event(1,code); var details = new Details { Native = O(native) }; details.Native["raw_xml"] = "untrusted";
        await AdSecurityHydration.HydrateAsync([e],7,details,Ct);
        var item = Item(Compose(e),1); Equal(expected,item["change"]);
        Equal(expected,Projection(code,O(native)).Facts["observed_change"]);
        Assert.False(item.ContainsKey("event_data")); Assert.DoesNotContain("untrusted",item.ToJsonString());
        // The composition boundary also accepts flattened source-native fields.
        foreach (var pair in O(native)) e[pair.Key] = pair.Value?.DeepClone();
        e.Remove("source_native_change"); Equal(expected,Item(Compose(e),1)["change"]);
    }

    [Theory] [InlineData(4738,"attributes_changed","account_attributes_not_present")]
    [InlineData(4737,"group_changed","group_change_attributes_not_present")]
    [InlineData(4764,"group_type_changed","group_type_values_not_present")]
    [InlineData(4719,"audit_policy_changed","audit_policy_fields_not_present")]
    public void Missing_details_are_partial(int code,string kind,string reason) =>
        Equal($$$"""{"state":"partial","kind":"{{{kind}}}","detail":{"state":"unknown","reason":"{{{reason}}}"}}""",Item(Compose(Event(1,code)),1)["change"]);

    [Fact]
    public void Caller_changes_and_server_coverage_survive_csv_with_no_formula_cells()
    {
        var e = Event(1,4740); e["caller_computer"] = "=CLIENT"; e["archive_field_state"] = "partial_archive_unavailable";
        var coverage = O("""{"account_lock":{"state":"no_retained_match"},"group_membership":{"state":"retained_match_present"},"audit_configuration":{"state":"processing_unfinished"},"account_change":{"state":"coverage_unavailable"}}""");
        var page = AdSecurity.Compose(Request(),[e,Event(2,4728,2),Event(3,4727,3)],true,false,coverage.DeepClone().AsObject());
        Assert.True(JsonNode.DeepEquals(coverage,page["category_coverage"]));
        Equal("""{"state":"observed","hostname":"dc01.example.test"}""",Item(page,1)["source_host"]);
        Equal("""{"state":"observed","hostname":"=CLIENT"}""",Item(page,1)["caller_computer"]);
        Equal("""{"state":"partial","reason":"archive_unavailable"}""",Item(page,1)["archive_fields"]);
        Equal("""{"state":"observed","kind":"member_added"}""",Item(page,2)["change"]);
        Equal("""{"state":"observed","kind":"group_created"}""",Item(page,3)["change"]);
        var csv = AdSecurity.Csv(page); Assert.Contains("caller_computer,change_state,change_kind",csv); Assert.Contains("'=CLIENT",csv);
        Assert.Contains("# category_coverage=",csv); Assert.Contains("account_lock",csv);
    }

    [Fact]
    public async Task Archive_reads_exact_page_ids_in_batches_and_keeps_only_allowlisted_fields()
    {
        var rows = Enumerable.Range(1,101).Select(i => Event(i,4740)).ToList(); var reader = new Details();
        await AdSecurityHydration.HydrateAsync(rows,7,reader,Ct);
        Assert.Equal(2,reader.Batches.Count); Assert.Equal(Enumerable.Range(1,100).Select(i => (long)i),reader.Batches[0]); Assert.Equal(new long[]{101},reader.Batches[1]);
        Assert.All(rows,e => Assert.Equal("client-"+e["event_db_id"],e["caller_computer"]!.ToString()));
        Assert.All(rows,e => Assert.False(e.ContainsKey("raw_xml")));
        Assert.Equal("CLIENT-42", Projection(4740,O("""{"CallerComputerName":"CLIENT-42"}""")).Facts["caller_computer"]!.ToString());
        Assert.Equal("1",Projection(4740,new()).Roles["source_host"]!.ToString());
    }

    [Theory] [InlineData("missing","archive_missing")] [InlineData("failure","archive_unavailable")] [InlineData("corrupt","archive_corrupt")]
    public async Task Archive_failure_preserves_available_rows_with_safe_partial_reason(string mode,string reason)
    {
        var e = Event(17,4728); await AdSecurityHydration.HydrateAsync([e],7,new Details { Mode = mode },Ct);
        Equal($$"""{"state":"partial","reason":"{{reason}}"}""",Item(Compose(e),17)["archive_fields"]);
    }

    sealed class Details : IEventReadService
    {
        public string Mode = "ok"; public JsonObject? Native; public List<long[]> Batches = [];
        public Task<IReadOnlyList<AccessResource>> ResourcesAsync(long id,CancellationToken ct) => Task.FromResult<IReadOnlyList<AccessResource>>([new("domain",7)]);
        public async Task<Dictionary<long,JsonObject>> DetailsAsync(long[] ids,bool exact,Func<long,CancellationToken,Task<bool>> admitted,CancellationToken ct)
        {
            Assert.False(exact); Batches.Add(ids); Assert.False(await admitted(999999,ct));
            if (Mode == "failure") throw new IOException("synthetic"); if (Mode == "corrupt") throw new InvalidDataException("synthetic");
            var result = new Dictionary<long,JsonObject>();
            foreach(long id in ids) { Assert.True(await admitted(id,ct)); if(Mode != "missing") result[id] = new() { ["event_data"] = Native?.DeepClone() ?? new JsonObject { ["CallerComputerName"] = "client-"+id, ["raw_xml"] = "untrusted" } }; }
            return result;
        }
        public Task<JsonObject> RelationsAsync(long id,Func<long,CancellationToken,Task<bool>> admitted,CancellationToken ct) => throw new NotSupportedException();
    }
}
