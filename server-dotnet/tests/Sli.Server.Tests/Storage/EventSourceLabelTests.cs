using System.Text.Json.Nodes;
using Sli.Server.Compatibility;
using Sli.Server.Investigations;
using Sli.Server.Storage.EventReports;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Behavioral vectors from tests/events/test_event_source_labels.py.
public sealed class EventSourceLabelTests
{
    const string ServiceTitle="Изменение состояния службы";
    const string Unknown="неизвестный тип события";
    const string ServiceCode="System:Service Control Manager:7036.title";
    static JsonObject ServiceEvent()=>new()
    {
        ["id"]=17,["event_id"]=7036,["channel"]="System",["provider_name"]="Service Control Manager",
        ["time_created_utc"]="2026-01-01T00:00:00Z",["server"]="fixture.example.test",["event_record_id"]=42,
        ["raw_xml"]="<fixture />",["event_data_json"]="{\"param1\":\"Fixture service\",\"param2\":\"running\"}"
    };
    static void Unchanged(JsonObject original,JsonObject source)=>Assert.True(JsonNode.DeepEquals(original,source));
    static void UnknownSearch(JsonObject source)
    {
        foreach(var summary in new[]{EventListProjection.Project(source),LegacySemantics.Summary(source)})
        {
            Assert.Equal(Unknown,summary["label"]!.ToString());
            Assert.False(summary["catalog_match"]!.GetValue<bool>());
        }
    }
    [Theory]
    [InlineData("ru",ServiceTitle)]
    [InlineData("en","Service state changed")]
    public void Label_uses_exact_catalog_when_short_label_is_missing(string language,string expected)
    { Assert.Equal(expected,EventListProjection.Label(ServiceEvent(),language)); }

    [Theory]
    [InlineData("ru",Unknown)]
    [InlineData("en","Unknown event type")]
    public void Wrong_provider_never_receives_service_label(string language,string expected)
    {
        var source=ServiceEvent(); source["provider_name"]="Fixture provider";
        Assert.Equal(expected,EventListProjection.Label(source,language));
    }
    [Fact]
    public void Summary_resolves_source_label_preserves_identity_and_does_not_expose_or_mutate_evidence()
    {
        var source=ServiceEvent(); var original=(JsonObject)source.DeepClone();
        foreach(var summary in new[]{EventListProjection.Summary(source),EventListProjection.Project(source)})
        {
            Assert.Equal(ServiceTitle,summary["label"]!.ToString());
            Assert.Equal("17",summary["event_db_id"]!.ToString());
            foreach(string key in new[]{"event_id","channel","provider_name","event_record_id"})
                Assert.True(JsonNode.DeepEquals(source[key],summary[key]));
            Assert.False(summary.ContainsKey("raw_xml")); Assert.False(summary.ContainsKey("event_data_json"));
        }
        Unchanged(original,source);
    }
    [Theory]
    [InlineData(7036)]
    [InlineData(4740)]
    public void Search_does_not_borrow_meaning_from_numeric_id(int eventId)
    {
        var source=ServiceEvent(); source["event_id"]=eventId; source["provider_name"]="Fixture provider";
        UnknownSearch(source);
    }
    [Fact]
    public void Summary_keeps_existing_source_label()
    {
        var source=ServiceEvent(); source["label"]="Fixture source title";
        Assert.Equal("Fixture source title",EventListProjection.Summary(source)["label"]!.ToString());
    }
    [Theory]
    [InlineData(null,null)]
    [InlineData("System",null)]
    [InlineData("Security","Service Control Manager")]
    public void Missing_or_wrong_identity_does_not_borrow_an_event_label(string? channel,string? provider)
    {
        var source=new JsonObject { ["event_id"]=4740 };
        if(channel is not null) source["channel"]=channel;
        if(provider is not null) source["provider_name"]=provider;
        Assert.Equal(Unknown,EventListProjection.Summary(source)["label"]!.ToString());
    }
    [Theory]
    [InlineData(" ")]
    [InlineData("\t")]
    public void Whitespace_provider_is_missing_for_summary_search_and_metadata_timeline(string provider)
    {
        var source=ServiceEvent(); source["event_id"]=4740; source["channel"]="Security"; source["provider_name"]=provider;
        Assert.Equal(Unknown,EventListProjection.Summary(source)["label"]!.ToString());
        UnknownSearch(source);
        var item=InvestigationTimeline.Build(source,"Fixture inclusion",true).Item;
        Assert.Equal(Unknown,item["title"]!.ToString()); Assert.Null(item["title_code"]);
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Timeline_resolves_source_without_inventing_actor_or_target(bool metadataOnly)
    {
        var source=ServiceEvent(); var original=(JsonObject)source.DeepClone();
        var item=InvestigationTimeline.Build(source,"Fixture inclusion",metadataOnly).Item;
        Assert.Equal(ServiceTitle,item["title"]!.ToString()); Assert.Equal(ServiceCode,item["title_code"]!.ToString());
        Assert.Null(item["actor"]); Assert.Null(item["target"]); Unchanged(original,source);
        if(metadataOnly)
        {
            foreach(string key in new[]{"severity","base_risk","confidence","assessment_confidence"}) Assert.Equal("unknown",item[key]!.ToString());
            Assert.Equal("unavailable",item["classification_origin"]!.ToString()); Assert.Null(item["summary"]);
        }
    }
    [Fact]
    public void Metadata_source_keeps_exact_title_and_unknown_assessment()
    {
        // Build(metadata:true) is the .NET entity-history metadata source and timeline projection.
        var item=InvestigationTimeline.Build(ServiceEvent(),"Fixture inclusion",true).Item;
        Assert.Equal(ServiceTitle,item["title"]!.ToString()); Assert.Equal(ServiceCode,item["title_code"]!.ToString());
        Assert.Null(item["actor"]); Assert.Equal("unknown",item["assessment_confidence"]!.ToString());
        Assert.Equal("Fixture inclusion",item["inclusion_reason"]!.ToString());
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Unknown_timeline_source_never_gets_service_semantics(bool metadataOnly)
    {
        var source=ServiceEvent(); source["provider_name"]="Fixture provider";
        var item=InvestigationTimeline.Build(source,"Fixture inclusion",metadataOnly).Item;
        Assert.Equal(Unknown,item["title"]!.ToString()); Assert.Null(item["title_code"]);
        Assert.Null(item["actor"]); Assert.Equal("unknown",item["assessment_confidence"]!.ToString());
    }
}
