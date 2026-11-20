using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Sli.Server.Ad;
using Sli.Server.Tests.Agents;
using Xunit;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Tests.Ad;

public sealed class NewLogonPairsVolumeTests
{
    const string Sid="S-1-5-21-100000001-200000002-300000003-1001";
    [Fact]
    public async Task Both_full_windows_keep_counts_without_external_history_or_scan_caps()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var pg=new PostCollectionPostgres(canonicalSchema:true);await pg.StartAsync(ct);
        await using var db=await pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db,"""
            create table servers(id bigint,domain_id bigint,role text);
            insert into servers values(10,7,'domain_controller');
            create table event_hot(event_id bigint,time_created_utc timestamptz,event_kind int,domain_id bigint,actor text,target text,source text,computer text,method jsonb,outcome jsonb,fields jsonb);
            create table event_cold_facts(like event_hot);
            create table event_cold_daily(day date,event_kind int,domain_id bigint,actor text,target text,source text,computer text,method jsonb,outcome jsonb,grouping_key bytea,event_count bigint,first_seen_utc timestamptz,last_seen_utc timestamptz);
            insert into event_hot select n,date_trunc('day',now())-interval '2 days'+n*interval '0.5 seconds',4624,7,
                'S-1-5-21-100000001-200000002-300000003-1001',null,'pc-1.example.test','dc01.example.test',
                '{"$server_id":10,"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing","LogonType":"3"}','{}','{}' from generate_series(1,50000) n;
            insert into event_hot select n+50000,date_trunc('day',now())-interval '1 day'+n*interval '0.5 seconds',4624,7,
                'S-1-5-21-100000001-200000002-300000003-1001',null,'pc-2.example.test','dc01.example.test',
                '{"$server_id":10,"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing","LogonType":"3"}','{}','{}' from generate_series(1,50000) n;
            """,ct);
        var start=new DateTimeOffset(DateTime.UtcNow.Date,TimeSpan.Zero).AddDays(-1);var end=start.AddDays(1);
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"Sli:Storage:ShortEventReads","false"},{"Sli:Storage:HistoryReadMode","invalid"}}).Build();
        var prior=await AdAuthenticationHistory.ReadAsync(db,7,[10],start.AddDays(-1),start,ct,config:config);
        var current=await AdAuthenticationHistory.ReadAsync(db,7,[10],start,end,ct,config:config);
        Assert.Equal(50000,prior.Events.Count);Assert.Equal(50000,current.Events.Count);
        Assert.False(prior.Truncated);Assert.False(current.Truncated);Assert.Empty(prior.Bounds);Assert.Empty(current.Bounds);
        Assert.Equal(Enumerable.Range(1,50000).Select(i=>(long)i),prior.Events.Select(e=>e.Int("id")));
        var computers=new[]{1,2}.Select(i=>Obj(new{object_guid=$"guid-{i}",display_name=$"PC-{i}",dns_host_name=$"pc-{i}.example.test",ip_addresses=System.Array.Empty<string>()})).ToList();
        var row=Assert.Single(AdLogonPairs.Compute(prior.Events,current.Events,computers,[Obj(new{samAccountName="synthetic-user",sid=Sid})],start,false));
        Assert.Equal(50000,row.Int("count"));Assert.Equal("no_baseline",row.Text("novelty"));Assert.Equal("PC-2",row.Text("computer"));Assert.Equal(50001,row.Int("source_event_id"));
        Assert.DoesNotContain("ERROR:",await pg.DiagnosticsAsync(ct));
    }
}
