using System.Net;
using System.Text.Json.Nodes;
using System.Text;
using Sli.Server.Workstations;
using Xunit;
using Microsoft.Extensions.Configuration;
namespace Sli.Server.Tests.Workstations;
public sealed partial class WorkstationHistoryTests
{
    [Fact] public void Disabled_history_does_not_load_credentials()
    {
        Assert.Null(WorkstationHistory.Configured(new ConfigurationBuilder().Build()));
        Assert.Null(WorkstationHistory.Configured(null, _ => throw new InvalidOperationException("credentials accessed")));
    }
    [Fact]public void Disabled_publisher_does_not_load_credentials()
    {
        Assert.Null(WorkstationHistory.Configured(new ConfigurationBuilder().Build()));
        Assert.Null(WorkstationHistory.Configured(null, _ => throw new InvalidOperationException("credentials accessed")));
    }
    sealed class Transport:HttpMessageHandler
    {
        public readonly Queue<string> Responses=new();public readonly List<(string Query,string Sql)> Calls=[];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
        {Calls.Add((request.RequestUri!.Query,await request.Content!.ReadAsStringAsync(ct)));return new(HttpStatusCode.OK){Content=new StringContent(Responses.Dequeue(),Encoding.UTF8,"application/json")};}
    }
    static JsonObject Row()
    {
        var body=new JsonObject{["agent_key"]="fixture-agent",["source_sha256"]=Ws.Sha("<fixture/>"),["semantic_type"]="process.started.fragment",["facts"]=new JsonObject{["process_name"]="fixture.exe"},["quality"]=new JsonObject()};
        return new(){["id"]=new string('a',64),["agent_key"]="fixture-agent",["entity_id"]=100,["ad_computer_id"]=null,["family"]="processes",["event_id"]=4688,["observed_at"]="2026-10-19T12:00:00+00:00",["observation"]=body,["observation_sha256"]=Ws.Hash(body),["source_xml"]="<fixture/>"};
    }
    static string Schema(string ddl="CREATE TABLE fixture ENGINE=ReplacingMergeTree ORDER BY id SETTINGS fsync_after_insert=1, fsync_part_directory=1")=>new JsonObject{["engine"]="ReplacingMergeTree",["sorting_key"]="id",["partition_key"]="tuple()",["create_table_query"]=ddl}.ToJsonString();
    [Fact]public async Task Disabled_preservation_never_contacts_history()
    {
        var transport=new Transport(); using var http=new HttpClient(transport);
        using var history=new WorkstationHistory(http,new Uri("http://192.0.2.1/"));
        var error=await Assert.ThrowsAsync<WorkstationException>(()=>history.PreserveAsync(Row(),TestContext.Current.CancellationToken));
        Assert.Equal("module_disabled",error.Message); Assert.Empty(transport.Calls);
    }
    [Fact]public async Task Disabled_preservation_cannot_insert_on_retry()
    {
        var transport=new Transport(); using var http=new HttpClient(transport);
        using var history=new WorkstationHistory(http,new Uri("http://192.0.2.1/"));
        var error=await Assert.ThrowsAsync<WorkstationException>(()=>history.PreserveAsync(Row(),TestContext.Current.CancellationToken));
        Assert.Equal("module_disabled",error.Message); Assert.Empty(transport.Calls);
    }
    [Theory][InlineData("CREATE TABLE fixture TTL observed_at SETTINGS fsync_after_insert=1,fsync_part_directory=1")][InlineData("CREATE TABLE fixture SETTINGS fsync_after_insert=0,fsync_part_directory=1")][InlineData("CREATE TABLE fixture SETTINGS fsync_after_insert=1")]
    public async Task Disabled_preservation_never_inspects_retired_schema(string ddl)
    {
        var transport=new Transport(); transport.Responses.Enqueue(Schema(ddl)); using var http=new HttpClient(transport);
        using var history=new WorkstationHistory(http,new Uri("http://192.0.2.1/"));
        var error=await Assert.ThrowsAsync<WorkstationException>(()=>history.PreserveAsync(Row(),TestContext.Current.CancellationToken));
        Assert.Equal("module_disabled",error.Message); Assert.Empty(transport.Calls);
    }
    [Theory][InlineData("agent_key","foreign-agent")][InlineData("payload_sha256","bad")][InlineData("id","bad")][InlineData("family","usb")]
    public void All_routing_columns_are_checked_against_the_payload(string field,string value)
    {var record=WorkstationHistory.Record(Row());record[field]=value;Assert.Equal("workstation_history_receipt_mismatch",Assert.Throws<WorkstationException>(()=>WorkstationHistory.Decode(record)).Message);}
    [Fact]public void Numeric_clickhouse_strings_decode_without_losing_identity()
    {var row=Row();var record=WorkstationHistory.Record(row);record["entity_id"]="100";record["event_id"]="4688";Assert.True(JsonNode.DeepEquals(row,WorkstationHistory.Decode(record)));}
    [Fact]public void Source_xml_and_observation_hashes_must_match_before_transport()
    {var row=Row();row["source_xml"]="<changed/>";Assert.Throws<WorkstationException>(()=>WorkstationHistory.Record(row));}
    [Fact]public async Task Disabled_reader_cannot_read_old_evidence()
    {
        var transport=new Transport(); using var http=new HttpClient(transport);
        using var history=new WorkstationHistory(http,new Uri("http://192.0.2.1/"));
        var start=DateTimeOffset.Parse("2026-10-19T00:00:00Z");
        var error=await Assert.ThrowsAsync<WorkstationException>(()=>history.ReadAsync(["foreign-agent"],"processes",start,start.AddDays(1),"",26,null,TestContext.Current.CancellationToken));
        Assert.Equal("module_disabled",error.Message); Assert.Empty(transport.Calls);
    }
    [Fact]public async Task Disabled_reader_cannot_read_foreign_agent()
    {
        var transport=new Transport(); using var http=new HttpClient(transport);
        using var history=new WorkstationHistory(http,new Uri("http://192.0.2.1/"));
        var start=DateTimeOffset.Parse("2026-10-19T00:00:00Z");
        var error=await Assert.ThrowsAsync<WorkstationException>(()=>history.ReadAsync(["foreign-agent"],"processes",start,start.AddDays(1),"",26,null,TestContext.Current.CancellationToken));
        Assert.Equal("module_disabled",error.Message); Assert.Empty(transport.Calls);
    }
    [Fact]public void Hot_cold_conflicting_receipts_fail_closed()
    {
        var hot=WorkstationHistory.ReportRow(Row(),false);var cold=(JsonObject)hot.DeepClone();cold["facts"]!["process_name"]="changed.exe";Assert.Throws<WorkstationException>(()=>WorkstationReports.Merge([hot],[cold],26));
        Assert.Single(WorkstationReports.Merge([hot],[(JsonObject)hot.DeepClone()],26));
    }
    [Fact]public void Exact_evidence_uses_server_hash_and_agent_binding()
    {
        var row=Row();var reference=new JsonObject{["observation_id"]=row["id"]!.DeepClone(),["agent_key"]=row["agent_key"]!.DeepClone(),["source_sha256"]=row["observation"]!["source_sha256"]!.DeepClone()};
        Assert.Equal("<fixture/>",WorkstationReports.ObservationEvidence(row,reference).Text("source_xml"));reference["agent_key"]="foreign-agent";Assert.Throws<WorkstationException>(()=>WorkstationReports.ObservationEvidence(row,reference));
    }
}
