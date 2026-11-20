using Sli.Server.Storage.Direct;
using Sli.Agent.Core;
using Xunit;
namespace Sli.Server.Tests.Storage;
public class DirectEventTimeTests
{
    [Theory]
    [InlineData("2026-10-07T00:00:00.1234565Z","2026-10-07T00:00:00.123456+00:00")]
    [InlineData("2026-10-07T00:00:00.50000050000000000000000000001Z","2026-10-07T00:00:00.500000+00:00")]
    [InlineData("2026-10-07T00:00:00.50000050000000000000000000009Z","2026-10-07T00:00:00.500001+00:00")]
    [InlineData("2026-10-07T00:00:00.5000005000000000000000000001Z","2026-10-07T00:00:00.500001+00:00")]
    [InlineData("2026-10-07T00:00:00.50000150000000000000000000001Z","2026-10-07T00:00:00.500002+00:00")]
    [InlineData("2026-10-07T00:00:00.00000050000000000000000000001Z","2026-10-07T00:00:00.000001+00:00")]
    [InlineData("2026-10-07T00:00:00.99999949999999999999999999999Z","2026-10-07T00:00:01+00:00")]
    [InlineData("2026-10-07T00:00:00.1234575Z","2026-10-07T00:00:00.123458+00:00")]
    [InlineData("2026-10-07T00:00:00.9999995+02:00","2026-10-06T22:00:01+00:00")]
    [InlineData("2026-10-07T00:00:00.1234567+02:00:30","2026-10-06T21:59:30.123456+00:00")]
    [InlineData("2026-10-07T00:00:00","2026-10-07T00:00:00+00:00")]
    public void Parses_source_utc_timestamp(string input,string expected) => Assert.Equal(expected,DirectEventTime.IsoUtc(input));
    public static IEnumerable<object[]> MicrosecondRoundingCases()
    {
        yield return ["2026-11-17T00:01:12.518787500Z","2026-11-17T00:01:12.518788+00:00"];
        yield return ["2026-11-17T00:00:00.123456Z","2026-11-17T00:00:00.123456+00:00"];
        foreach(int digits in new[] { 7,8,9,10,16,28 }) {
            string zeros=new('0',digits-7), nines=new('9',digits-7);
            foreach(string micros in new[] { "123456","123457" }) {
                string even=micros=="123456" ? "123456" : "123458";
                yield return [$"2026-11-17T00:00:00.{micros}4{nines}Z",$"2026-11-17T00:00:00.{micros}+00:00"];
                yield return [$"2026-11-17T00:00:00.{micros}5{zeros}Z",$"2026-11-17T00:00:00.{even}+00:00"];
                if(digits>7) yield return [$"2026-11-17T00:00:00.{micros}5{new string('0',digits-8)}1Z",
                    $"2026-11-17T00:00:00.{(micros=="123456" ? "123457" : "123458")}+00:00"];
            }
            yield return [$"2026-11-17T00:00:00.1234566{zeros}Z","2026-11-17T00:00:00.123457+00:00"];
            yield return [$"2026-11-17T00:00:00.0000005{zeros}Z","2026-11-17T00:00:00+00:00"];
            yield return [$"2026-11-17T00:00:00.9999995{zeros}Z","2026-11-17T00:00:01+00:00"];
            yield return [$"2026-11-17T23:59:59.9999995{zeros}Z","2026-11-18T00:00:00+00:00"];
        }
        yield return ["2026-11-17T00:00:00.518787500+02:30","2026-11-16T21:30:00.518788+00:00"];
        yield return ["2026-11-17T23:59:59.9999995000-03:00","2026-11-18T03:00:00+00:00"];
    }
    [Theory]
    [MemberData(nameof(MicrosecondRoundingCases))]
    public void Rounds_the_entire_decimal_tail_to_even(string input,string expected) => Assert.Equal(expected,DirectEventTime.IsoUtc(input));
    [Fact] public void Logoff_identity_uses_source_rounded_utc() {
        const string xml="<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4634</EventID><EventRecordID>6</EventRecordID><TimeCreated SystemTime='2026-10-07T02:00:00.1234575+02:00'/><Channel>Security</Channel><Computer>dc.synthetic</Computer></System><EventData><Data Name='LogonType'>3</Data></EventData></Event>";
        var row=EventXml.Parse(xml,"dc.synthetic","fixture","Security");
        Assert.Equal("779618c6dbbf95443de535e1864391adf5214fd63d80bdf11bb9f7034d121142",DirectEventIdentity.Hash(row));
        var projection=Direct4624Projection.Create(row);
        Assert.Equal("3",projection.LogonType);
        Assert.Equal("cef1f102f2019747e468d97b3310a7bb1a39ae6e12db293c9ad749f3e79d1af5",Convert.ToHexStringLower(Direct4624Facts.Hash(6,projection)));
        var normalized=new DateTime(2026,10,7,0,0,0,DateTimeKind.Utc);
        Assert.Equal("fe42025e7829dea0ff8c9f7321178247ae2a2f3c3b34ae52a613d903f32546ee",Convert.ToHexStringLower(Direct4624Core.SourceHash(6,2,3,4,null,5,normalized,row,projection)));
    }
    [Fact] public void Mixed_catalogued_rows_validate_before_native_tampering() {
        const string xml="<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>5</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00Z'/><Channel>Security</Channel><Computer>dc.synthetic</Computer></System><EventData><Data Name='LogonType'>3</Data></EventData></Event>";
        var a=EventXml.Parse(xml,"dc.synthetic","fixture","Security");
        var b=EventXml.Parse(xml.Replace("4624","4634").Replace("EventRecordID>5","EventRecordID>6"),"dc.synthetic","fixture","Security");
        var ready=DirectAdDcPacket.PrepareBatch(new System.Text.Json.Nodes.JsonArray(a.DeepClone(),b.DeepClone()));
        Assert.Equal(new[]{4624,4634},ready.Select(x=>x.Row["event_id"]!.GetValue<int>()));
        var unsupported=EventXml.Parse(xml.Replace("4624","4725"),"dc.synthetic","fixture","Security");
        Assert.Equal(2,DirectAdDcPacket.PrepareBatch(new System.Text.Json.Nodes.JsonArray(a.DeepClone(),unsupported.DeepClone())).Count);
        unsupported["record_id"]=999; // Does not match EventRecordID in native XML.
        Assert.Throws<InvalidDataException>(()=>DirectAdDcPacket.PrepareBatch(new System.Text.Json.Nodes.JsonArray(a.DeepClone(),unsupported)));
    }
    [Theory]
    [InlineData("0xc000006a","0xc000006a")]
    [InlineData("0","0xc000006d")]
    [InlineData("bad-status","0xc000006d")]
    public void Failed_logon_result_uses_source_substatus_rules(string sub,string expected) {
        string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><EventRecordID>7</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00Z'/><Channel>Security</Channel><Computer>dc.synthetic</Computer></System><EventData><Data Name='LogonType'>3</Data><Data Name='Status'>0xc000006d</Data><Data Name='SubStatus'>{sub}</Data></EventData></Event>";
        var p=Direct4624Projection.Create(EventXml.Parse(xml,"dc.synthetic","fixture","Security"));
        Assert.Equal(expected,(string?)Direct4624Facts.Document(7,p)["result_code"]);
        if(sub=="0xc000006a")Assert.Equal("fb65aa3f50dedaac4b3f7130c3f7424f48ef402ff90689fb0dd67821c976fcc5",Convert.ToHexStringLower(Direct4624Facts.Hash(7,p)));
    }
    [Theory]
    [InlineData(4624,6,20,"86191673138364566933509db52353a17403d1685c41984e509d6aa9926a2d3a","860ff43a422949099f33efaffb70a5d3bb06853c5477bb7ebc39ac11ff2e65c5","801c0cce644f1338b871bdaf32d792d17c87d4675893e46d0bfcdf02ea10e088")]
    [InlineData(4625,7,21,"404dc51b8af3dc55b98b5483728bae9cc8acc385355191328ac7cdf7b2494234","1a3abdee4a9513f92eb1f82ca4c19a28e83dafe04b2f09980defaab4b4ed0468","f552a8e606bd44aa3348337708e2e6c56a3707eb8767187c127bcfed582aedae")]
    [InlineData(4634,8,22,"b738e64c912e9b8c82a90e20e02c2a371881e2839139636a56a4f2ab2ef029aa","e3e4604ad654aa0b98b1afe43e683336e6bad9e510b7aa2462588467bdef6802","31730a5913a031cb0b18845275eb843bceafd55ebaf3e72cd434b17528e6d34a")]
    public void Public_source_admitted_rows_match_identity_core_and_facts(int kind,int record,int id,string identity,string core,string facts) {
        string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>{kind}</EventID><EventRecordID>{record}</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00.1234575Z'/><Channel>Security</Channel><Computer>fixture-dc</Computer></System><EventData><Data Name='LogonType'>3</Data></EventData></Event>";
        var row=EventXml.Parse(xml,"fixture-dc","fixture-endpoint","Security");var projection=Direct4624Projection.Create(row);
        Assert.Equal(identity,projection.IdentityHash);
        Assert.Equal(core,Convert.ToHexStringLower(Direct4624Core.SourceHash(id,2,3,4,null,5,new DateTime(2026,10,7,0,0,0,DateTimeKind.Utc),row,projection)));
        Assert.Equal(facts,Convert.ToHexStringLower(Direct4624Facts.Hash(id,projection)));
    }
    [Fact] public void Public_source_batch_raw_jsonl_is_exact() {
        var rows=new System.Text.Json.Nodes.JsonArray();
        foreach(var (kind,record) in new[]{(4624,6),(4625,7),(4634,8)}) {
            string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>{kind}</EventID><EventRecordID>{record}</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00.1234575Z'/><Channel>Security</Channel><Computer>fixture-dc</Computer></System><EventData><Data Name='LogonType'>3</Data></EventData></Event>";
            rows.Add(EventXml.Parse(xml,"fixture-dc","fixture-endpoint","Security"));
        }
        var raw=DirectPacketJsonl.Create(rows);
        Assert.Equal(2337,raw.SizeBytes);Assert.Equal("7e69552e810144731aa459330e067030d0bbc468bd829a53b6a9e9051ed5efba",raw.Sha256);
    }
    [Theory]
    [InlineData(4624,6,20,"da431b32a32b7057c0ea6ec54703a2458f582eef74d4d703ba05769e27c4475a","fbab0a290b0cac14e75778d0996817be4373b9ba46fbbdf27942884d0f9302ae","801c0cce644f1338b871bdaf32d792d17c87d4675893e46d0bfcdf02ea10e088")]
    [InlineData(4625,7,21,"12dbc6dfaaf7b914658d585cd09654b716e8b845ef8c7df4ef8ceeb1b616918e","2852edb6cf21b9d5144f1cd5deb0d2d455b831fbbba3b83548d0a2210110a669","f552a8e606bd44aa3348337708e2e6c56a3707eb8767187c127bcfed582aedae")]
    [InlineData(4634,8,22,"d5120f024f809f99c70389b624536eec69f8f459d85b39c6f55915c80d978df8","ddd5a8709e5496a6a773706cef76696db39a3352ab0ac68ba81db7a971fd5f0e","31730a5913a031cb0b18845275eb843bceafd55ebaf3e72cd434b17528e6d34a")]
    public void Long_fraction_public_source_rows_match_identity_core_facts(int kind,int record,int id,string identity,string core,string facts) {
        string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>{kind}</EventID><EventRecordID>{record}</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00.50000050000000000000000000001Z'/><Channel>Security</Channel><Computer>fixture-dc</Computer></System><EventData><Data Name='LogonType'>3</Data></EventData></Event>";
        var row=EventXml.Parse(xml,"fixture-dc","fixture-endpoint","Security");var projection=Direct4624Projection.Create(row);
        Assert.Equal(identity,projection.IdentityHash);
        Assert.Equal(core,Convert.ToHexStringLower(Direct4624Core.SourceHash(id,2,3,4,null,5,new DateTime(2026,10,7,0,0,0,DateTimeKind.Utc),row,projection)));
        Assert.Equal(facts,Convert.ToHexStringLower(Direct4624Facts.Hash(id,projection)));
    }
}
