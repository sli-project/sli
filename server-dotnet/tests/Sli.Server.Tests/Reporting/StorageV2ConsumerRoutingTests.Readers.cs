using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Sli.Server.Access;
using Sli.Server.Compatibility;
using Sli.Server.Investigations;
using Sli.Server.Legacy;
using Sli.Server.Storage.EventReports;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed partial class StorageV2ConsumerRoutingTests
{
    static JsonObject Event(long id) => new() { ["id"]=id,["event_id"]=4624,["server"]="dc.example.test",["server_id"]=7,
        ["channel"]="Security",["provider_name"]="Microsoft-Windows-Security-Auditing",["event_record_id"]=41,
        ["time_created_utc"]="2026-07-17T00:30:00Z",["time_created_local"]="2026-07-17T00:30:00Z",
        ["subject_user_name"]="synthetic-actor",["target_user_name"]="synthetic-target",["message_text"]="logon",["event_data_json"]="{}" };
    sealed class SearchRows : ILegacyRows
    {
        internal readonly List<string> Calls=[];
        public Task<JsonArray> QueryAsync(string sql,IReadOnlyList<object> p,int timeoutMs,CancellationToken ct)
        {
            V2Only(sql); Calls.Add(Sql(sql));
            return Task.FromResult(sql.Contains("select e.*")?new JsonArray(Event(17)):new JsonArray());
        }
        public Task<JsonArray> HistoryAsync(string sql,IReadOnlyDictionary<string,string> p,CancellationToken ct)=>throw new InvalidOperationException("unexpected_history_read");
        public Task<Dictionary<long,JsonObject>> HistoryEventsAsync(long[] ids,CancellationToken ct)=>throw new InvalidOperationException("unexpected_history_read");
    }
    sealed class Evidence : IEventReadService
    {
        internal readonly List<(string Kind,long[] Ids)> Calls=[];
        internal readonly List<Func<long,CancellationToken,Task<bool>>> Admissions=[];
        internal bool Missing;
        public Task<IReadOnlyList<AccessResource>> ResourcesAsync(long id,CancellationToken ct)=>Task.FromResult<IReadOnlyList<AccessResource>>([new("server",7)]);
        public async Task<Dictionary<long,JsonObject>> DetailsAsync(long[] ids,bool exact,Func<long,CancellationToken,Task<bool>> admitted,CancellationToken ct)
        {
            Calls.Add((exact?"detail":"batch",ids)); Admissions.Add(admitted);
            var result=new Dictionary<long,JsonObject>();
            foreach(long id in ids) if(!Missing && await admitted(id,ct)) result[id]=Event(id);
            return result;
        }
        public Task<JsonObject> RelationsAsync(long id,Func<long,CancellationToken,Task<bool>> admitted,CancellationToken ct)
        {
            Calls.Add(("relations",[id])); Admissions.Add(admitted);
            return Task.FromResult(new JsonObject { ["items"]=new JsonArray(new JsonObject { ["related_event_db_id"]=18,["reason"]="same_logon_id_same_server" }),["truncated"]=false });
        }
    }
    [Fact]
    public async Task Search_and_exact_detail_remain_V2_only_with_client_route_override()
    {
        var rows=new SearchRows(); var events=new Evidence();
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:Storage:HistoryReadMode"]="disabled",["Sli:Legacy:ADLOG_STORAGE_V2_ENABLED"]="0" }).Build();
        var reader=new LegacyHttpReader(events,NullLogger<LegacyHttpReader>.Instance);
        var query=new QueryCollection(new Dictionary<string,Microsoft.Extensions.Primitives.StringValues> {
            ["time_from"]="2026-07-17T00:00:00Z",["time_to"]="2026-07-17T01:00:00Z",["limit"]="1",["route"]="v1",["authorization"]="invalid",["event_db_id"]="17" });
        var error=await Assert.ThrowsAsync<LegacyInputException>(()=>reader.ReadAsync("/api/events/search",LegacyQuery.Parse("/api/events/search",query),Ct));
        Assert.Equal("module_disabled",error.Message); Assert.Empty(rows.Calls);
        int before=rows.Calls.Count;
        var detail=await reader.ReadAsync("/api/events/details",LegacyQuery.Parse("/api/events/details",query),Ct);
        Assert.Equal(1,detail["total"]!.GetValue<int>()); Assert.Equal(17L,detail["items"]![0]!["id"]!.GetValue<long>());
        Assert.Equal(before,rows.Calls.Count); Assert.Equal("detail",Assert.Single(events.Calls).Kind);
    }
    [Fact]
    public async Task Missing_exact_detail_never_falls_back_to_legacy_rows()
    {
        var rows=new SearchRows(); var reader=new LegacyHttpReader(new Evidence { Missing=true },NullLogger<LegacyHttpReader>.Instance);
        var query=LegacyQuery.Parse("/api/events/details",new QueryCollection(new Dictionary<string,Microsoft.Extensions.Primitives.StringValues> { ["event_db_id"]="17" }));
        var error=await Assert.ThrowsAsync<InvalidDataException>(()=>reader.ReadAsync("/api/events/details",query,Ct));
        Assert.Equal("event_not_found",error.Message); Assert.Empty(rows.Calls);
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Recommendation_scope_reads_only_V2_counts_and_renders_report(bool overview)
    {
        var error=await Assert.ThrowsAsync<InvalidOperationException>(()=>LegacyAnalysis.RenderScopeAsync(71,["dc.example.test"],overview,
            (_,_,_)=>throw new Exception("event storage accessed"),Ct));
        Assert.Equal("module_disabled",error.Message);
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Anchored_workspace_keeps_same_reader_and_admission_for_detail_relations_and_batch(bool missing)
    {
        var reader=new Evidence { Missing=missing };
        Func<long,CancellationToken,Task<bool>> admitted=(id,ct)=>Task.FromResult(true);
        var result=await InvestigationWorkspaceEndpoints.Anchor(new(17,null,"synthetic-actor",null,null,null,"UTC",null),reader,admitted,Ct);
        Assert.Equal(missing?"empty":"ok",result["state"]!.ToString());
        Assert.Equal(missing?new[]{"detail"}:new[]{"detail","relations","batch"},reader.Calls.Select(c=>c.Kind));
        Assert.All(reader.Admissions,a=>Assert.Same(admitted,a));
        if(!missing) Assert.Equal(new long[]{18},reader.Calls[2].Ids);
    }
    [Fact]
    public void Search_admission_needs_no_legacy_history_configuration()
    {
        using var host=new Microsoft.Extensions.Hosting.HostBuilder().Build();
        var reader=new EventReadService(new NeverConnect(),new ConfigurationBuilder().Build(),(Microsoft.Extensions.Hosting.IHostEnvironment)host.Services.GetService(typeof(Microsoft.Extensions.Hosting.IHostEnvironment))!);
        reader.AdmitSearch();
    }
}
