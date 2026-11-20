using Sli.Agent.Core;
using Sli.Server.Storage.Direct;
using Xunit;
namespace Sli.Server.Tests.Storage;
public class DirectRepresentationConflictTests
{
    private const string Xml="<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>4</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00Z'/><Channel>Security</Channel><Computer>dc.synthetic</Computer></System><EventData><Data Name='LogonType'>3</Data></EventData></Event>";
    private static System.Text.Json.Nodes.JsonObject Row(string x)=>EventXml.Parse(x,"dc.synthetic","fixture-endpoint","Security");
    [Fact]
    public void Same_identity_conflicting_common_xml_is_proven_source_conflict()
    {
        var a=Row(Xml);var b=Row(Xml.Replace("Name='LogonType'>3","Name='LogonType'>10"));
        Assert.Equal(DirectEventIdentity.Hash(a),DirectEventIdentity.Hash(b));Assert.True(DirectRepresentationConflict.IsProven(a,b));
        Assert.Equal("published_source_event_hash_mismatch",new DirectSourceConflict(true).Reason);Assert.Equal(0,new DirectSourceConflict(true).Ordinal);
        Assert.Equal("source_event_allocation_hash_mismatch",new DirectSourceConflict(false).Reason);
    }
    [Fact]
    public void Compatible_superset_and_identical_xml_are_not_quarantined()
    {
        var a=Row(Xml);var b=Row(Xml.Replace("</EventData>","<Data Name='WorkstationName'>ws01</Data></EventData>"));
        Assert.False(DirectRepresentationConflict.IsProven(a,a));Assert.False(DirectRepresentationConflict.IsProven(a,b));Assert.False(DirectRepresentationConflict.IsProven(b,a));
    }
    [Fact]
    public void Distinct_overlapping_attribute_values_are_source_conflict()
    {
        var a=Row(Xml.Replace("<Provider Name=","<Provider Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' Name="));
        var b=Row(Xml.Replace("<Provider Name=","<Provider Guid='{54849625-5478-4994-A5BA-3E3B0328C30E}' Name="));
        Assert.True(DirectRepresentationConflict.IsProven(a,b));
    }
}