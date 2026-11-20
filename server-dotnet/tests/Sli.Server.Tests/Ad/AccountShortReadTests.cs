using System.Text.Json.Nodes;
using System.Xml.Linq;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Ad;
using Sli.Server.Storage.Direct;
using Sli.Server.Storage.EventReports;
using Sli.Server.Tests.Agents;
using Xunit;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Tests.Ad;

public sealed class AccountShortReadTests(AccountShortReadTests.Database database) : IClassFixture<AccountShortReadTests.Database>
{
    public sealed class Database : IAsyncLifetime
    {
        internal readonly SqlPostgresFixture Fixture = new();
        public async ValueTask InitializeAsync() {
            await Fixture.StartAsync(CancellationToken.None);
            await using var db=new NpgsqlConnection(Fixture.Pg.ConnectionString);await db.OpenAsync();
            await PostCollectionPostgres.Sql(db,"insert into forests(id,name) values(700001,'account.example.test'); insert into domains(id,forest_id,fqdn) select id,700001,'domain-'||id::text||'.example.test' from unnest(array[1,2,7,8,9,21,22]) id on conflict(id) do nothing; insert into servers(id,domain_id,hostname,role) values(1,1,'dc01.example.test','domain_controller'),(2,2,'dc02.example.test','domain_controller'),(10,7,'dc07.example.test','domain_controller'),(11,7,'dc08.example.test','domain_controller'),(30,21,'dc21.example.test','domain_controller'),(12,9,'dc09.example.test','domain_controller')",CancellationToken.None);
        }
        public ValueTask DisposeAsync() => Fixture.DisposeAsync();
    }
    const string Sid = "S-1-5-21-100000001-200000002-300000003-1001";
    const string Actor = "S-1-5-21-100000001-200000002-300000003-1002";
    const string Group = "S-1-5-21-100000001-200000002-300000003-512";
    static ShortEventRow Event(long id, int kind, DateTimeOffset time, long domain, string? target = null, long server = 1,string source="192.0.2.10")
    {
        XNamespace ns = EventXml.Namespace;
        var data = new Dictionary<string,string> { ["SubjectUserSid"] = Actor, ["TargetUserSid"] = target ?? Sid,
            ["MemberSid"] = Sid, ["LogonType"] = "10", ["TargetLogonId"] = "0x123",
            ["IpAddress"] = System.Net.IPAddress.TryParse(source,out _)?source:"-",["WorkstationName"]=source };
        var xml = new XElement(ns+"Event", new XElement(ns+"System",
            new XElement(ns+"Provider", new XAttribute("Name", "Microsoft-Windows-Security-Auditing")),
            new XElement(ns+"EventID", kind), new XElement(ns+"EventRecordID", id),
            new XElement(ns+"TimeCreated", new XAttribute("SystemTime", time.ToString("O"))),
            new XElement(ns+"Channel", "Security"), new XElement(ns+"Computer", "dc01.example.test")),
            new XElement(ns+"EventData", data.Select(p => new XElement(ns+"Data", new XAttribute("Name",p.Key),p.Value))));
        var native = EventXml.Parse(xml.ToString(), "dc01.example.test", "dc01.example.test", "Security");
        return ShortEventRow.Create(id,domain,native,Direct4624Projection.Create(native),server)!;
    }

    [Fact]
    public async Task Writer_events_feed_account_activity_without_old_events_or_normalization()
    {
        var ct = TestContext.Current.CancellationToken;
        var fixture = database.Fixture;
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        var at = EventReadService.ShortBoundary(null).AddDays(3);
        ShortEventRow[] events = [Event(101,4725,at,1),Event(102,4624,at.AddMinutes(1),1),
            Event(103,4728,at.AddMinutes(2),1,Group),Event(104,4729,at.AddMinutes(4),1,Group),
            Event(105,4624,at.AddMinutes(3),1),Event(106,4624,at.AddMinutes(3),2,server:2)];
        await using (var tx = await db.BeginTransactionAsync(ct)) {
            await ShortEventWriter.WriteAsync(db,tx,events,ct); await tx.CommitAsync(ct);
        }
        var (sql,args) = AdUsersActivity.EventSql([1],[4624,4725,4728,4729],new(at,at.AddDays(1)));
        var rows = await AdJson.ReadAsync(db,sql,ct,args);
        Assert.Equal(new long[]{101,102,103,105,104},rows.Select(r=>r.Int("id")));
        var user = Obj(new { entityId=1,displayName="Synthetic user",enabled=false });
        var group = Obj(new { id="group:2",name="Synthetic group" });
        var actual = AdUsersActivity.Shape(rows,new(){[(1,Sid)]=user},new(){[(1,Group)]=group},[],60,1);
        // The same .NET consumer receives the same old-path event fields.
        var legacy = events.Where(e=>e.DomainId==1).Select(e=>Obj(new {
            id=e.EventId,domain_id=e.DomainId,event_id=e.Kind,time_created_utc=e.Time,
            target_user_sid=e.Kind==4624?Sid:e.Target,subject_user_sid=e.Kind==4624?null:Actor,
            server_id=1,logon_type=e.Kind==4624?"10":null,membership_member_sid=e.Kind is 4728 or 4729?Sid:null,
            processing_status="normalized",semantic_type=e.Kind switch {4624=>"authentication.session.created",4725=>"directory.account.disabled",4728=>"group.member.added",_=>"group.member.removed"},
            facts_json=new {} }));
        var expected = AdUsersActivity.Shape(legacy,new(){[(1,Sid)]=user},new(){[(1,Group)]=group},[],60,1);
        Assert.True(JsonNode.DeepEquals(expected,actual),actual.ToJsonString());
        Assert.Equal(2,actual["disabled_active"]!.AsArray().Count);
        Assert.Single(actual["temporary_memberships"]!.AsArray());
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Expired_hot_rows_use_daily_counts_and_exact_changes_without_sessions_or_fake_event_ids()
    {
        var ct=TestContext.Current.CancellationToken;var fixture=database.Fixture;
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString);await db.OpenAsync(ct);
        var boundary=EventReadService.ShortBoundary(null);var at=boundary.AddDays(-3);
        ShortEventRow[] events=[Event(201,4725,at.AddHours(1),7,server:10),Event(202,4624,at.AddHours(2),7,server:10,source:"pc01.example.test"),
            Event(203,4624,at.AddHours(3),7,server:10,source:"pc01.example.test"),
            Event(204,4624,at.AddHours(4),7,server:11),Event(205,4624,at.AddHours(4),8,server:10),
            Event(206,4624,boundary,7,server:10),Event(207,4728,at.AddMinutes(90),7,Group,server:10),Event(208,4729,at.AddMinutes(210),7,Group,server:10),
            Event(209,4624,at.AddHours(1),7,server:11),Event(210,4725,at.AddMinutes(135),9,server:12),
            Event(211,4624,at.AddHours(2),9,server:12),Event(212,4624,at.AddHours(3),9,server:12)];
        await using(var tx=await db.BeginTransactionAsync(ct)){
            await ShortEventWriter.WriteAsync(db,tx,events,ct);
            await ShortEventWriter.WriteAsync(db,tx,events,ct);
            await tx.CommitAsync(ct);
        }
        // Retention removes the old individual rows. Neither core nor CH is populated.
        await using(var remove=new NpgsqlCommand("delete from event_hot where time_created_utc<@boundary",db)){
            remove.Parameters.AddWithValue("boundary",boundary);await remove.ExecuteNonQueryAsync(ct);
        }
        var read=await AdAuthenticationHistory.ReadAsync(db,7,[10],at,boundary,ct);
        var daily=Assert.Single(read.Events);
        Assert.Equal(2,daily.Int("event_count"));Assert.Null(daily["id"]);Assert.Null(daily["event_db_id"]);
        Assert.Null(daily["logon_id"]);Assert.Null(daily["authentication_session"]);
        Assert.Equal(at.AddHours(2),daily.Time("first_seen_utc"));Assert.Equal(at.AddHours(3),daily.Time("last_seen_utc"));
        Assert.Empty(read.Bounds);Assert.False(read.Truncated);
        var clipped=await AdAuthenticationHistory.ReadAsync(db,7,[10],at.AddMinutes(150),at.AddMinutes(210),ct);
        Assert.Null(Assert.Single(clipped.Events)["event_count"]);
        Assert.Equal(at.AddHours(3),clipped.Events[0].Time("time_created_utc"));
        var (clippedSql,clippedArgs)=AdUsersActivity.EventSql([9],[4725,4624],new(at,at.AddMinutes(150)));
        var clippedRows=await AdJson.ReadAsync(db,clippedSql,ct,clippedArgs);
        var clippedActivity=AdUsersActivity.Shape(clippedRows,new(){[(9,Sid)]=Obj(new{entityId=1,enabled=false})},[],[],60,1);
        Assert.Empty(clippedActivity["disabled_active"]!.AsArray()); // the only known later logon is outside the requested window
        var hot=await AdAuthenticationHistory.ReadAsync(db,7,[10],boundary,boundary.AddDays(1),ct);
        Assert.Equal(206,Assert.Single(hot.Events).Int("id")); // boundary day is counted only once

        await using var transaction=await db.BeginTransactionAsync(ct);
        var review=await AdReviewChecks.EventsAsync(db,[7],true,ct);
        var user=Obj(new{entityId=1,sid=Sid,enabled=false,servicePrincipalNames=new[]{"synthetic/service"}});
        Assert.True(AdReviewChecks.Evaluate(true,user,DateTimeOffset.UtcNow,events:review.Rows)["disabled_logon"]);
        Assert.True(AdReviewChecks.Evaluate(true,user,DateTimeOffset.UtcNow,events:review.Rows)["service_interactive_logon"]);
        var(sql,args)=AdUsersActivity.EventSql([7],[4624,4725,4728,4729],new(at,boundary));
        var rows=await AdJson.ReadAsync(db,sql,ct,args);
        var activity=AdUsersActivity.Shape(rows,new(){[(7,Sid)]=user},new(){[(7,Group)]=Obj(new{id="group:2",name="Synthetic group"})},[],1440,1);
        Assert.Equal(2,activity["disabled_active"]!.AsArray().Count); // two distinct daily source groups
        var membership=Assert.Single(activity["temporary_memberships"]!.AsArray())!;
        Assert.Null(membership["activity_count"]); // the other group crosses removal; its exact interval count was not retained
        Assert.Empty(membership["activity_evidence"]!.AsArray());
        var workplaces=await AdLastWorkplace.ReadAsync(db,[7],[Sid.ToLowerInvariant()],ct);
        Assert.Equal("pc01.example.test",workplaces[(7,Sid.ToLowerInvariant())].Text("computer"));
        Assert.Equal(at.AddHours(3),workplaces[(7,Sid.ToLowerInvariant())].Time("at_utc"));
        var computers=new List<JsonObject>{Obj(new{object_guid="synthetic-pc",display_name="pc01",dns_host_name="pc01.example.test",ip_addresses=System.Array.Empty<string>(),entity_id=10})};
        var users=new[]{Obj(new{samAccountName="synthetic-user",sid=Sid,entityId=1})};
        var pairs=AdLogonPairs.Compute([],read.Events,computers,users,at,false,baselineStart:at.AddDays(-1),end:boundary);
        var pair=Assert.Single(pairs);Assert.Equal(2,pair.Int("count"));Assert.Null(pair["source_event_id"]);
        Assert.Equal(at.AddHours(2),pair.Time("first_seen"));
        await transaction.RollbackAsync(ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Application_role_reads_account_events_from_hot_and_daily_tables()
    {
        var ct=TestContext.Current.CancellationToken;var fixture=database.Fixture;
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString);await db.OpenAsync(ct);
        var boundary=EventReadService.ShortBoundary(null);var at=boundary.AddDays(-2);
        ShortEventRow[] events=[Event(301,4624,at.AddHours(1),21,server:30,source:"pc02.example.test"),
            Event(302,4725,at.AddHours(2),21,server:30),Event(303,4624,boundary.AddHours(1),21,server:30),Event(304,4624,boundary.AddHours(2),22,server:30)];
        await using(var tx=await db.BeginTransactionAsync(ct)){await ShortEventWriter.WriteAsync(db,tx,events,ct);await tx.CommitAsync(ct);}
        await using var role=await db.BeginTransactionAsync(ct);
        await PostCollectionPostgres.Sql(db,"set local role adlog_user",ct);
        var history=await AdAuthenticationHistory.ReadAsync(db,21,[30],at,boundary.AddDays(1),ct);
        Assert.Equal(2,history.Events.Count);
        Assert.DoesNotContain(history.Events,e=>e.Int("domain_id")==22);
        var full = await AdAccountEvents.ReadAsync(db, [21], [4624], new(at, boundary.AddDays(1)), ct, servers: [30]);
        Assert.Equal(full.Count, history.Events.Count);
        foreach (var (projected, original) in history.Events.Zip(full))
        {
            Assert.False(projected.ContainsKey("facts_json"));
            Assert.All(projected, field => Assert.True(original.ContainsKey(field.Key) &&
                JsonNode.DeepEquals(original[field.Key], field.Value), field.Key));
        }
        var(sql,args)=AdUsersActivity.EventSql([21],[4624,4725],new(at,boundary.AddDays(1)));
        Assert.Equal(3,(await AdJson.ReadAsync(db,sql,ct,args)).Count);
        var review=await AdReviewChecks.EventsAsync(db,[21],true,ct);
        Assert.NotEmpty(review.Rows!);
        var workplaces=await AdLastWorkplace.ReadAsync(db,[21],[Sid.ToLowerInvariant()],ct);
        Assert.Single(workplaces);
        await role.RollbackAsync(ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
