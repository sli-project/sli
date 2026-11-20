using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Auth;
using Sli.Server.Auth.ReportKeys;
using Sli.Server.Compatibility;
using Sli.Server.Infrastructure;
using Sli.Server.Legacy;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Workspace;
using Sli.Server.Workspace;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class DomainModuleShortReadsPostgresTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static IConfiguration Config(string dsn) => new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
        ["ConnectionStrings:Sli"]=dsn, ["Sli:Storage:ShortEventReads"]="false"
    }).Build();

    static async Task Seed(SqlPostgresFixture fixture)
    {
        await using var db = await fixture.Pg.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db,"""
            insert into domains(id,forest_id,fqdn) select 2,forest_id,'other.example.test' from domains where id=1;
            insert into servers(id,domain_id,hostname,role,is_active) values
                (1,1,'dc01.example.test','domain_controller',true),(2,2,'dc02.example.test','domain_controller',true);
            """,Ct);
        var now = DateTimeOffset.UtcNow;
        var events = new[] {
            EventShortReadPostgresTests.Event(1001,4625,now.AddMinutes(-5),1),
            EventShortReadPostgresTests.Event(1002,4720,now.AddDays(-20),1),
            EventShortReadPostgresTests.Event(1003,4625,now.AddMinutes(-4),2,server:2),
            EventShortReadPostgresTests.Event(1004,4625,now.AddMinutes(-3),1,server:2)
        };
        await EntityShortReadsPostgresTests.Write(fixture,events.Select(e=>e.Short).ToArray(),Ct);
        await PostCollectionPostgres.Sql(db,"""
            insert into event_cold_daily(day,grouping_key,event_kind,domain_id,actor,target,source,computer,method,outcome,event_count,first_seen_utc,last_seen_utc)
                select (now() at time zone 'UTC')::date-20,sha256('synthetic-daily'::bytea),4625,1,'synthetic-user',null,'192.0.2.10','dc01.example.test',
                    '{"$server_id":1,"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing"}','{}',7,now()-interval '20 days',now()-interval '20 days';
            """,Ct);
    }

    [Fact]
    public async Task Report_key_authorizes_only_individual_retained_events_in_its_domain()
    {
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(Ct); await Seed(fixture);
        await using var owner = await fixture.Pg.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(owner,"""
            insert into auth_users(id,username,password_hash,role,is_service) values(9001,'synthetic-reader','synthetic-unusable-hash','viewer',true);
            insert into access_capability_assignments(subject_type,subject_id,capability_id,effect,scope_json,business_reason)
                select 'user',9001,id,'allow','{"kind":"all"}','synthetic read' from access_capabilities
                where capability_key in ('events.view','field.raw_evidence','field.technical','field.security','evidence.exact');
            insert into access_report_assignments(subject_type,subject_id,report_key,effect,scope_json,field_categories,allowed_actions,source_type,business_reason)
                values('user',9001,'events.explorer','allow','{"kind":"domain","ids":[1]}',array['raw_evidence','technical','security'],array['view'],'temporary','synthetic read');
            """,Ct);
        var guard = new ExactEventAuthorization(new PostgresConnectionFactory(Config(fixture.Dsn("adlog_user"))));
        var principal = new Principal("api_key",1,"viewer",ReportSubjectId:9001);
        Assert.Null(await guard.CheckAsync(principal,"/api/v1/events/1001",Ct));
        Assert.Null(await guard.CheckAsync(principal,"/api/v1/events/1002",Ct));
        foreach (long id in new long[] { 0,1003,1004,9999 })
            Assert.Equal("event_not_found",(await guard.CheckAsync(principal,"/api/v1/events/"+id,Ct))?.Code);
        await PostCollectionPostgres.Sql(owner,"update access_report_assignments set field_categories=array['technical','security'] where subject_id=9001",Ct);
        Assert.Equal("event_not_found",(await guard.CheckAsync(principal,"/api/v1/events/1001",Ct))?.Code);
        await PostCollectionPostgres.Sql(owner,"""
            insert into access_report_assignments(subject_type,subject_id,report_key,effect,scope_json,field_categories,allowed_actions,source_type,business_reason)
                values('user',9001,'events.explorer','allow','{"kind":"domain","ids":[1]}',array['raw_evidence'],array['view'],'temporary','synthetic split');
            """,Ct);
        Assert.Equal("event_not_found",(await guard.CheckAsync(principal,"/api/v1/events/1001",Ct))?.Code);
        await PostCollectionPostgres.Sql(owner,"""
            delete from access_report_assignments where business_reason='synthetic split';
            update access_report_assignments set field_categories=array['raw_evidence','technical','security'],allowed_actions=array['export'] where subject_id=9001;
            """,Ct);
        Assert.Equal("event_not_found",(await guard.CheckAsync(principal,"/api/v1/events/1001",Ct))?.Code);
        await PostCollectionPostgres.Sql(owner,"update access_report_assignments set allowed_actions=array['view'],valid_until=now()-interval '1 second' where subject_id=9001",Ct);
        Assert.Equal("event_not_found",(await guard.CheckAsync(principal,"/api/v1/events/1001",Ct))?.Code);
        await PostCollectionPostgres.Sql(owner,"update access_report_assignments set valid_until=null,effect='deny' where subject_id=9001",Ct);
        Assert.Equal("event_not_found",(await guard.CheckAsync(principal,"/api/v1/events/1001",Ct))?.Code);
        await fixture.AssertNoSqlErrorsAsync(Ct);
    }

    [Fact]
    public async Task Dashboard_counts_each_layer_once_and_activity_keeps_daily_totals_out_of_events()
    {
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(Ct); await Seed(fixture);
        var config = Config(fixture.Dsn("adlog_user")); var connections = new PostgresConnectionFactory(config);
        using var rows = new PostgresLegacyRows(connections);
        var dashboard = new DashboardSnapshotReader(rows,null!,null!,new LegacySettings(config),null!,null!,config:config);
        var events = await dashboard.Events(Ct);
        // One hot failure in each domain, one durable cold change, seven daily
        // failures; the event with inconsistent server/domain routing is excluded.
        Assert.Equal(10,events["total_events"]!.GetValue<long>());
        Assert.Equal(10,Assert.Single(events["by_channel"]!.AsArray())!["count"]!.GetValue<long>());
        Assert.Equal(9,events["by_server"]!.AsArray().Single(r=>r!["hostname"]!.ToString()=="dc01.example.test")!["count"]!.GetValue<long>());
        Assert.Equal(10,events["top_event_ids"]!.AsArray().Sum(r=>r!["count"]!.GetValue<long>()));
        var snapshot = UiWorkspaceParityTests.Snapshot(); snapshot["events_summary"] = events;
        var query = new QueryCollection(new Dictionary<string,Microsoft.Extensions.Primitives.StringValues> {
            ["time_from"]=DateTimeOffset.UtcNow.AddDays(-1).ToString("O"),["time_to"]=DateTimeOffset.UtcNow.ToString("O"),["server"]="dc01.example.test"
        });
        var overview = UiWorkspaceParityTests.Overview(new PostgresWorkspaceRows(connections),snapshot);
        var result = JsonSerializer.SerializeToNode(await overview.ReadAsync(query,Ct))!;
        Assert.Equal(1,result["activity"]!["items"]!.AsArray().Sum(b=>new[] { "critical","important","informational" }.Sum(k=>b![k]!.GetValue<long>())));
        Assert.True(result["activity"]!["available"]!.GetValue<bool>());
        query = new QueryCollection(new Dictionary<string,Microsoft.Extensions.Primitives.StringValues> {
            ["time_from"]=DateTimeOffset.UtcNow.Date.AddDays(-20).ToString("O"),["time_to"]=DateTimeOffset.UtcNow.Date.AddDays(-19).ToString("O"),["server"]="dc01.example.test"
        });
        result = JsonSerializer.SerializeToNode(await overview.ReadAsync(query,Ct))!;
        Assert.Equal(1,result["activity"]!["items"]!.AsArray().Sum(b=>new[] { "critical","important","informational" }.Sum(k=>b![k]!.GetValue<long>())));
        Assert.True(result["activity"]!["available"]!.GetValue<bool>());
        await fixture.AssertNoSqlErrorsAsync(Ct);
    }
}
