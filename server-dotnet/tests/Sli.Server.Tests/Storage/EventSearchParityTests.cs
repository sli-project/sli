using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Storage.EventReports;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Behavioral vectors from tests/events/test_evsearch_contract.py.
public sealed class EventSearchParityTests
{
    static readonly DateTimeOffset Now=DateTimeOffset.Parse("2026-11-05T12:00:00Z");
    static JsonObject Request(string overrides="{}")
    {
        var raw=JsonNode.Parse("""{"contract_version":"evsearch.v1","conditions":[],"period":{"preset":"24h","timezone":"UTC"}}""")!.AsObject();
        foreach(var p in JsonNode.Parse(overrides)!.AsObject()) raw[p.Key]=p.Value?.DeepClone();
        return raw;
    }
    static Dictionary<string,string[]> Query(string json)=>JsonSerializer.Deserialize<Dictionary<string,string[]>>(json)!;
    static EventSearchInput Input(string overrides="{}")=>EventSearchInput.Parse(Request(overrides),Now);
    static JsonElement Grant(string kind="domain",int id=7,string[]? categories=null,string[]? actions=null)=>JsonSerializer.SerializeToElement(new
    {
        report_key="events.explorer",effect="allow",
        scope_json=kind=="all"?(object)new {kind}:kind=="channel"?new {kind,values=new[]{"Security"}}:new {kind,ids=new[]{id}},
        field_categories=categories??["technical","security"],allowed_actions=actions??["view","export"]
    });
    static AccessFacts Facts(params JsonElement[] grants)
    {
        string[] keys=["id","channel","event_id","account","server_id","q","account_kind","provider","outcome"];
        var original=EventQueryEndpointTests.MakeFacts();
        return original with
        {
            DirectCapabilities=[..original.DirectCapabilities,JsonSerializer.SerializeToElement(new {capability_key="reports.export",effect="allow",scope_json=new {kind="all"}})],
            ReportAssignments=grants.Length==0?[Grant()]:grants,
            Definitions=[JsonSerializer.SerializeToElement(new
            {
                report_key="events.explorer",version=1,dataset_version=1,dataset_key="events.v2",dataset_status="published",
                fields_json=keys.Select(key=>new {key,category=key is "id" or "channel" or "server_id"?"technical":"security"}),
                actions_json=new[]{"view","export"},definition_json=new {columns=keys,actions=new[]{"view","export"},export_policy="controlled",evsearch_q_fields=new[]{"channel"},evsearch_questions=new {failed_logons=new[]{"account_kind"}}}
            })]
        };
    }
    static EventSearchPolicy Authorize(AccessFacts facts,EventSearchInput? input=null,string action="view")=>EventSearchPolicy.Authorize(facts,
        new ReportEligibility().Compose(facts,new CapabilityComposer().Compose(facts)),input??Input(),action,["id"]);
    static AccessFacts EditPublication(AccessFacts facts,Action<JsonObject> edit)
    {
        var publication=JsonNode.Parse(facts.Definitions[0].GetRawText())!.AsObject(); edit(publication);
        return facts with {Definitions=[JsonSerializer.SerializeToElement(publication)]};
    }
    static void Denied(Action action)=>Assert.Equal("evsearch.policy_denied",Assert.Throws<EventSearchException>(action).Code);

    [Theory]
    [InlineData("""{"contract_version":"evsearch.v2"}""")]
    [InlineData("""{"grouping_version":"future"}""")]
    [InlineData("""{"conditions":[{"field":"sql","operator":"eq","value":"opaque"}]}""")]
    [InlineData("""{"conditions":[{"field":"channel","operator":"contains","value":"opaque"}]}""")]
    [InlineData("""{"conditions":[{"field":"channel","operator":"in","value":[]}]}""")]
    [InlineData("""{"conditions":[{"field":"account","operator":"eq","value":"ambiguous","role":"any"}]}""")]
    [InlineData("""{"conditions":[{"field":"account","operator":"eq","value":true,"role":"any"}]}""")]
    [InlineData("""{"conditions":[{"field":"ip","operator":"eq","value":"invalid-ip"}]}""")]
    [InlineData("""{"conditions":[{"field":"channel","operator":"missing","value":null}]}""")]
    [InlineData("""{"conditions":[{"field":"legacy_journal_view","operator":"eq","value":"future"}]}""")]
    [InlineData("""{"conditions":[{"field":"channel","operator":"eq","value":"opaque","scope":"all"}]}""")]
    [InlineData("""{"sort":[]}""")]
    [InlineData("""{"exclude_machine_system":"false"}""")]
    [InlineData("""{"period":{"preset":"all","timezone":"UTC"}}""")]
    [InlineData("""{"period":{"preset":"custom","timezone":"UTC","from":"2026-01-01"}}""")]
    [InlineData("""{"period":{"preset":"24h","timezone":"UTC","from":"2026-01-01"}}""")]
    public void Invalid_input_never_becomes_an_unfiltered_request(string overrides)
    {
        var error=Assert.Throws<EventSearchException>(()=>Input(overrides));
        Assert.StartsWith("evsearch.",error.Code); Assert.DoesNotContain("opaque",error.Message);
    }
    [Fact] public void Free_text_limit_is_enforced_without_echoing_input()
    {
        var raw=Request(); raw["q"]=new string('x',257);
        Assert.Equal("evsearch.invalid_request",Assert.Throws<EventSearchException>(()=>EventSearchInput.Parse(raw,Now)).Code);
    }
    [Theory] [InlineData("eq")] [InlineData("in")] [InlineData("not_in")]
    public void Event_id_requires_positive_context_for_every_value_operator(string op)
    {
        var raw=Request(); var conditions=raw["conditions"]!.AsArray();
        conditions.Add(new JsonObject { ["field"]="event_id",["operator"]=op,["value"]=JsonNode.Parse(op=="eq"?"4625":"[4625]") });
        Assert.Equal("evsearch.event_context_required",Assert.Throws<EventSearchException>(()=>EventSearchInput.Parse(raw,Now)).Code);
        conditions.Add(JsonNode.Parse("""{"field":"channel","operator":"eq","value":"Security"}"""));
        Assert.NotNull(EventSearchInput.Parse(raw,Now));
        conditions[1]!["operator"]="not_in"; conditions[1]!["value"]=new JsonArray("Security");
        Assert.Equal("evsearch.event_context_required",Assert.Throws<EventSearchException>(()=>EventSearchInput.Parse(raw,Now)).Code);
    }
    [Fact] public void Wire_validation_copies_exclusion_and_explicit_presence_without_rewriting()
    {
        var raw=Request("""{"conditions":[{"field":"account","role":"target","operator":"not_in","value":[11]},{"field":"account","role":"target","operator":"exists"}]}""");
        var wire=EventSearchInput.Validate(raw); Assert.True(JsonNode.DeepEquals(raw,wire));
        var input=EventSearchInput.Parse(raw,Now);
        raw["conditions"]![0]!["value"]!.AsArray().Add(12);
        Assert.Single(wire["conditions"]![0]!["value"]!.AsArray());
        Assert.Single(input.Conditions.Single(c=>c.Operator=="not_in").Values);
        Assert.Contains(input.Conditions,c=>c.Operator=="exists" && c.Role=="target");
    }
    [Fact] public void Issued_policy_preserves_legacy_resource_scopes_without_mutation()
    {
        var facts=Facts(Grant(),Grant("server",9),Grant("channel")); var before=JsonSerializer.Serialize(facts);
        var policy=Authorize(facts); Assert.Equal(before,JsonSerializer.Serialize(facts));
        Assert.Equal(3,policy.Scopes.Length);
        var sql=new EventSearchSql(); var predicate=sql.Scope(policy.Scopes);
        Assert.Contains("domain_id",predicate); Assert.Contains("server_id",predicate); Assert.Contains("channel",predicate);
        Assert.Contains(7L,sql.Parameters.Values); Assert.Contains(9L,sql.Parameters.Values); Assert.DoesNotContain(8L,sql.Parameters.Values);
    }
    [Theory] [InlineData("no_report")] [InlineData("no_actions")] [InlineData("export_only")] [InlineData("unknown_scope")]
    [InlineData("technical_only")] [InlineData("different_domain")] [InlineData("split_categories")]
    public void Hidden_predicates_cannot_combine_partial_grants(string change)
    {
        var facts=change switch
        {
            "no_report"=>Facts() with {ReportAssignments=[]},
            "no_actions"=>Facts(Grant(actions:[])),
            "export_only"=>Facts(Grant(actions:["export"])),
            "unknown_scope"=>Facts(Grant("unknown")),
            "technical_only"=>Facts(Grant(categories:["technical"])),
            "different_domain"=>Facts(Grant(categories:["technical"]),Grant(id:8)),
            _=>Facts(Grant(categories:["security"]),Grant(categories:["technical"]))
        };
        Denied(()=>Authorize(facts,Input("""{"conditions":[{"field":"account","operator":"eq","value":11,"role":"any"}]}""")));
    }
    [Fact] public void All_scope_does_not_publish_a_hidden_field()=>Denied(()=>Authorize(Facts(Grant("all")),Input("""{"conditions":[{"field":"reason","operator":"eq","value":"opaque"}]}""")));
    [Theory] [InlineData("dataset")] [InlineData("columns")] [InlineData("action")] [InlineData("export_policy")] [InlineData("capability")] [InlineData("grant_action")]
    public void Export_requires_publication_capability_and_independent_grant(string change)
    {
        var facts=Facts();
        if(change=="capability") facts=facts with {DirectCapabilities=facts.DirectCapabilities.Where(c=>c.GetProperty("capability_key").GetString()!="reports.export").ToArray()};
        else if(change=="grant_action") facts=Facts(Grant(actions:["view"]));
        else facts=EditPublication(facts,p=>
        {
            var d=p["definition_json"]!;
            if(change=="dataset") p["dataset_key"]="other";
            if(change=="columns") d["columns"]!.AsArray().RemoveAt(0);
            if(change=="action") d["actions"]=new JsonArray("view");
            if(change=="export_policy") d["export_policy"]="disabled";
        });
        Denied(()=>Authorize(facts,action:"export"));
    }
    [Fact] public void Export_has_the_same_resource_scope_as_view()
    {
        var facts=Facts(); Assert.Equal(Authorize(facts).Scopes.Select(s=>s.GetRawText()),Authorize(facts,action:"export").Scopes.Select(s=>s.GetRawText()));
        // Export granted on another resource cannot authorize the view scope.
        Denied(()=>Authorize(Facts(Grant(actions:["view"]),Grant(id:8)),action:"export"));
        Assert.Equal("evsearch.unsupported_action",Assert.Throws<EventSearchException>(()=>Authorize(facts,action:"delete")).Code);
    }
    [Theory] [InlineData("q","q")] [InlineData("machine","account_kind")] [InlineData("question","account_kind")]
    public void Executable_options_require_their_published_dependencies(string option,string dependency)
    {
        var input=Input(option=="q"?"""{"q":"opaque"}""":option=="machine"?"""{"exclude_machine_system":true}""":"""{"question_id":"failed_logons"}""");
        var facts=Facts(); Assert.NotNull(Authorize(facts,input));
        facts=EditPublication(facts,p=>
        {
            var columns=p["definition_json"]!["columns"]!.AsArray();
            columns.Remove(columns.Single(c=>c!.GetValue<string>()==dependency));
        });
        Denied(()=>Authorize(facts,input));
        Assert.Equal("evsearch.unsupported_question",Assert.Throws<EventSearchException>(()=>Input("""{"question_id":"future"}""")).Code);
    }
    [Fact] public void Legacy_journal_retains_exact_predicates_and_resets_paging()
    {
        var seen=new List<(string,string?)>();
        var result=EventSearchLegacy.Translate(Query("""{"q":["opaque"],"view":["authentication"],"server":["synthetic-source"],"cursor":["obsolete"],"offset":["50"],"return_to":["/app/events"]}"""),resolveIdentity:(field,_,role)=> {seen.Add((field,role)); return [9];});
        Assert.Equal(["evsearch.legacy_paging_reset"],result.Notices); Assert.False(result.StartEmpty);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""[{"field":"legacy_journal_view","operator":"eq","value":"authentication"},{"field":"legacy_journal_q","operator":"eq","value":"opaque"},{"field":"server_id","operator":"in","value":[9]}]"""),result.Request["conditions"]));
        Assert.Equal(new[]{("server_id",(string?)null)},seen); Assert.False(result.Request.ContainsKey("cursor")); Assert.False(result.Request.ContainsKey("offset"));
        Assert.True(EventSearchLegacy.Translate(Query("{}")).StartEmpty);
    }
    [Fact] public void Legacy_search_retains_roles_event_identity_period_and_explicit_category()
    {
        var result=EventSearchLegacy.Translate(Query("""{"account":["synthetic-account"],"subject":["synthetic-actor"],"target":["synthetic-target"],"event_id":["4625","4624"],"provider":["synthetic-provider"],"channel":["Security"],"view":["authentication"],"category":["account_management"],"time_from":["2026-10-01T00:00:00Z"],"time_to":["2026-10-02T00:00:00Z"],"timezone":["UTC"]}"""),"search",(_,_,_)=>[11]);
        var conditions=result.Request["conditions"]!.AsArray();
        Assert.Equal(new[]{"actor","any","target"},conditions.Where(c=>c!["field"]!.ToString()=="account").Select(c=>c!["role"]!.ToString()).Order());
        Assert.Equal("account_management",Assert.Single(conditions,c=>c!["field"]!.ToString()=="category")!["value"]!.ToString());
        Assert.Equal("[4625,4624]",conditions.Single(c=>c!["field"]!.ToString()=="event_id")!["value"]!.ToJsonString());
        Assert.Contains(conditions,c=>c!["field"]!.ToString()=="provider" && c["value"]!.ToString()=="synthetic-provider");
        Assert.Contains(conditions,c=>c!["field"]!.ToString()=="channel" && c["value"]!.ToString()=="Security");
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"preset":"custom","from":"2026-10-01T00:00:00Z","to":"2026-10-02T00:00:00Z","timezone":"UTC"}"""),result.Request["period"]));
    }
    [Theory] [InlineData("category")] [InlineData("risk")] [InlineData("tier")] [InlineData("account")] [InlineData("event_id")] [InlineData("provider")] [InlineData("channel")]
    public void Journal_rejects_search_only_filters(string key)=>Assert.Equal("evsearch.legacy_unsupported_filter",Assert.Throws<EventSearchException>(()=>EventSearchLegacy.Translate(new Dictionary<string,string[]> {[key]=["opaque"]})).Code);
    [Fact] public void Search_translation_failures_do_not_drop_filters()
    {
        Assert.Equal("evsearch.event_context_required",Assert.Throws<EventSearchException>(()=>EventSearchLegacy.Translate(Query("""{"event_id":["4625"]}"""),"search")).Code);
        Assert.Equal("evsearch.legacy_identity_unresolved",Assert.Throws<EventSearchException>(()=>EventSearchLegacy.Translate(Query("""{"account":["ambiguous"]}"""),"search",(_,_,_)=>[11,12])).Code);
    }
    [Fact] public void Only_search_splits_a_comma_separated_server_list()
    {
        var seen=new List<string>(); long[] Resolve(string field,string value,string? role) {seen.Add(value); return [9];}
        var query=Query("""{"server":["synthetic-one,synthetic-two"]}""");
        EventSearchLegacy.Translate(query,resolveIdentity:Resolve); Assert.Equal(["synthetic-one,synthetic-two"],seen);
        seen.Clear(); EventSearchLegacy.Translate(query,"search",Resolve); Assert.Equal(["synthetic-one","synthetic-two"],seen);
    }
    [Theory]
    [InlineData("""{"unknown":["opaque"]}""")]
    [InlineData("""{"q":["one","two"]}""")]
    [InlineData("""{"q":[""]}""")]
    [InlineData("""{"view":["unknown"]}""")]
    [InlineData("""{"event_id":["4625"]}""")]
    [InlineData("""{"event_id":["invalid"],"channel":["Security"]}""")]
    [InlineData("""{"account":["opaque"],"user":["different"]}""")]
    [InlineData("""{"provider":["one"],"source":["two"]}""")]
    [InlineData("""{"account":["ambiguous"]}""")]
    [InlineData("""{"server":["unresolved"]}""")]
    [InlineData("""{"time_from":["2026-10-01T00:00:00Z"]}""")]
    [InlineData("""{"time_from":["2026-10-01"],"time_to":["2026-10-02"],"period":["7d"]}""")]
    [InlineData("""{"return_to":["https://example.test/"]}""")]
    [InlineData("""{"return_to":["/app/../external"]}""")]
    public void Unsupported_legacy_links_fail_closed(string query)=>Assert.Throws<EventSearchException>(()=>EventSearchLegacy.Translate(Query(query),resolveIdentity:(_,_,_)=>[11,12]));
    [Theory]
    [InlineData("//example.test/app/events")] [InlineData("/app/%2e%2e/events")] [InlineData("/app/events\\other")]
    [InlineData("/app/events%0a")] [InlineData("/app/settings")] [InlineData("https://[")] [InlineData("/app/events?x=%7f")]
    public void Return_context_uses_a_safe_local_allowlist(string value)
    {
        var raw=Request(); raw["entry_context"]=new JsonObject { ["kind"]="question",["return_to"]=value };
        Assert.Equal("evsearch.invalid_request",Assert.Throws<EventSearchException>(()=>EventSearchInput.Parse(raw,Now)).Code);
    }
    [Fact] public void Contract_codes_have_both_server_translations()
    {
        HashSet<string> Keys(string language)=>JsonNode.Parse(File.ReadAllText(Path.Combine(EventCardSemanticsTests.Repository(),"config","i18n","server."+language+".json")))!.AsObject().Select(p=>p.Key).Where(k=>k.StartsWith("evsearch.",StringComparison.Ordinal)).ToHashSet();
        var keys=Keys("ru"); Assert.True(keys.SetEquals(Keys("en")));
        foreach(string code in new[]{"legacy_paging_reset","invalid_request","unsupported_version","invalid_period","invalid_condition","unsupported_field","unsupported_operator","event_context_required","unsupported_action","policy_denied","unsupported_question","legacy_unsupported_filter","legacy_ambiguous_filter","legacy_identity_unresolved"}) Assert.Contains("evsearch."+code,keys);
    }
}
