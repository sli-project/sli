using System.Globalization;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Sli.Server.Reporting;
using Sli.Server.Reporting.V2;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class EventsJournalPresetTests
{
    private static ReportDefinition Journal => new ReportDefinitionRegistry().Get("events.journal")!;

    [Fact]
    public void EveryPresetEventIdBelongsToItsView()
    {
        var presets = Journal.Declaration["presets"]!.AsArray();
        Assert.NotEmpty(presets);
        foreach (var preset in presets)
        {
            string view = preset!["params"]!["view"]!.GetValue<string>();
            long eventId = long.Parse(preset["params"]!["q"]!.GetValue<string>(), CultureInfo.InvariantCulture);
            if (view == "all") continue;
            Assert.True(ReportQuery.EventViews.TryGetValue(view, out var ids), preset["label"]!.ToString());
            Assert.Contains(eventId, ids!);
        }
    }

    [Theory]
    [InlineData("Сбои входа (подбор)", "4625", "authentication")]
    [InlineData("Входы администраторов", "4672", "all")]
    [InlineData("Изменение групп и прав", "4728", "accounts")]
    [InlineData("Создание учётных записей", "4720", "accounts")]
    [InlineData("Очистка журнала аудита", "1102", "attention")]
    public void ReferencePresetReachesEventFilters(string label, string search, string view)
    {
        var definition = Journal;
        var preset = Assert.Single(definition.Declaration["presets"]!.AsArray(), p => p!["label"]!.GetValue<string>() == label);
        var parameters = preset!["params"]!.AsObject();
        Assert.Equal(2, parameters.Count);
        Assert.Equal(search, parameters["q"]!.GetValue<string>());
        Assert.Equal(view, parameters["view"]!.GetValue<string>());

        var input = new QueryCollection(parameters.ToDictionary(p => p.Key, p => new StringValues(p.Value!.GetValue<string>())));
        var (parsed, _) = ReportParameters.Parse(definition, input, DateTimeOffset.Parse("2026-11-09T00:00:00Z", CultureInfo.InvariantCulture));
        Assert.Equal(search, parsed["q"]!.GetValue<string>());
        Assert.Equal(view, parsed["view"]!.GetValue<string>());

        var query = new ReportQuery();
        query.Interactive("events.v2", new Dictionary<string, string>
        {
            ["q"] = parsed["q"]!.GetValue<string>(),
            ["view"] = parsed["view"]!.GetValue<string>()
        }, 90);
        long eventId = long.Parse(search, CultureInfo.InvariantCulture);
        int eventParameter = query.Values.FindIndex(value => value is long id && id == eventId);
        Assert.True(eventParameter >= 0);
        Assert.Contains(query.Predicates, predicate => predicate.Contains("event.event_id=@p" + eventParameter, StringComparison.Ordinal));
        if (view == "all")
        {
            // 4672 must not be restricted to the authentication view.
            Assert.DoesNotContain(query.Values, value => value is long[]);
            Assert.DoesNotContain(query.Predicates, predicate => predicate.Contains("event.event_id=any(", StringComparison.Ordinal));
        }
        else
        {
            int viewParameter = query.Values.FindIndex(value => value is long[]);
            Assert.True(viewParameter >= 0);
            Assert.Contains(eventId, Assert.IsType<long[]>(query.Values[viewParameter]));
            Assert.Contains("event.event_id=any(@p" + viewParameter + ")", query.Predicates);
        }
    }

    [Theory]
    [InlineData("attention")]
    [InlineData("authentication")]
    [InlineData("accounts")]
    public void PresetViewsAreKnownToQueryLayer(string view)
    {
        Assert.True(ReportQuery.EventViews.ContainsKey(view));
        var query = new ReportQuery();
        query.Interactive("events.v2", new Dictionary<string, string> { ["view"] = view }, 90);
        Assert.NotEmpty(Assert.IsType<long[]>(Assert.Single(query.Values)));
        Assert.Equal("event.event_id=any(@p0)", Assert.Single(query.Predicates));
    }
}
