using System.Xml;
using Sli.Agent.Core;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

/// <summary>Selection must preserve collection and resume bounds as the table changes.</summary>
public class EventQueriesTests
{
    private static readonly EventCatalog Catalog = EventCatalog.Load();

    [Theory]
    [InlineData(null, false)]
    [InlineData(10L, false)]
    [InlineData(10L, true)]
    public void QueryHonorsResumeBounds(long? after, bool bookmark)
    {
        var progress = new ChannelProgress(after, bookmark ? "<BookmarkList/>" : "", "g");
        foreach (var record in new[] { 9, 10, 11 })
        {
            var doc = new XmlDocument();
            doc.LoadXml($"<Event><System><EventID>4624</EventID><EventRecordID>{record}</EventRecordID></System></Event>");
            var selected = doc.SelectNodes(EventQueries.Build("Security", progress, Catalog))!.Count > 0;
            Assert.Equal(bookmark || after is null || record > after, selected);
        }
    }

    [Fact]
    public void WindowsTimePredicatesRespectFirstReadAndHistoryBounds()
    {
        var progress = new ChannelProgress(10, "", "g", "2026-10-07T11:00:00+00:00", "2026-10-07T13:00:00+00:00");
        var query = EventQueries.Build("Security", progress, Catalog);
        Assert.Contains("TimeCreated[@SystemTime >= '2026-10-07T11:00:00Z']", query);
        Assert.Contains("TimeCreated[@SystemTime < '2026-10-07T13:00:00Z']", query);
        query = EventQueries.Build("Security", progress with { Bookmark = "<BookmarkList/>" }, Catalog);
        Assert.DoesNotContain("2026-10-07T11:00:00Z", query);
        Assert.Contains("TimeCreated[@SystemTime < '2026-10-07T13:00:00Z']", query);
    }

    [Fact]
    public void SecurityFilterCoversEveryCatalogEventAndNoFileAuditNoise()
    {
        var filter = EventQueries.CatalogFilter("Security", ChannelProgress.Start("g"), Catalog)!;
        Assert.All(Catalog.EventIds("Security"), id => Assert.True(Covers(filter, id), id.ToString()));
        Assert.All(new[] { 4656, 4658, 4659, 4660, 4663, 4664, 4670, 5145 }, id => Assert.False(Covers(filter, id), id.ToString()));
    }

    private static bool Covers(string filter, int id)
    {
        foreach (System.Text.RegularExpressions.Match single in System.Text.RegularExpressions.Regex.Matches(filter, @"EventID=(\d+)"))
            if (int.Parse(single.Groups[1].Value) == id) return true;
        foreach (System.Text.RegularExpressions.Match range in System.Text.RegularExpressions.Regex.Matches(filter, @"EventID >= (\d+) and EventID <= (\d+)"))
            if (int.Parse(range.Groups[1].Value) <= id && id <= int.Parse(range.Groups[2].Value)) return true;
        return false;
    }

    [Fact]
    public void AnchorStaysQueryableWhileABookmarkExists()
    {
        var withBookmark = new ChannelProgress(500, "<BookmarkList/>", "g");
        Assert.Contains("EventRecordID=500", EventQueries.CatalogFilter("Security", withBookmark, Catalog));
        Assert.DoesNotContain("EventRecordID=", EventQueries.CatalogFilter("Security", ChannelProgress.Start("g"), Catalog));
    }

    [Fact]
    public void OtherChannelsAreReadUnfiltered()
    {
        Assert.Null(EventQueries.CatalogFilter("System", ChannelProgress.Start("g"), Catalog));
        Assert.Equal("*", EventQueries.Build("Directory Service", ChannelProgress.Start("g"), Catalog));
    }

    [Fact]
    public void CatalogMatchesProviderCaseInsensitively()
    {
        Assert.True(Catalog.Contains("Security", "Microsoft-Windows-Security-Auditing", 4624));
        Assert.True(Catalog.Contains("Security", "MICROSOFT-WINDOWS-SECURITY-AUDITING", 4624));
        Assert.False(Catalog.Contains("Security", "Microsoft-Windows-Security-Auditing", 4656));
        Assert.False(Catalog.Contains("Security", null, 4624));
        Assert.False(Catalog.Contains("Security", "Microsoft-Windows-Security-Auditing", null));
        Assert.False(Catalog.Contains("Security", "Microsoft-Windows-Security-Auditing", long.MaxValue));
        Assert.Contains(1102, Catalog.KnownEventIds);
        Assert.Contains("Microsoft-Windows-PowerShell/Operational", Catalog.Channels);
        Assert.True(Catalog.Contains("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4104));
    }
}
