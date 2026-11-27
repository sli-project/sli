using System.Text.Json.Nodes;
using System.Xml.Linq;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Ad;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Ad;

public sealed class DomainChangesAuthenticationTests
{
    const string Sid = "S-1-5-21-100000001-200000002-300000003-1002";
    static async Task Seed(PostCollectionPostgres pg, NpgsqlConnection db, CancellationToken ct)
    {
        await PostCollectionPostgres.Sql(db, """
            create role adlog_storage_owner; create role adlog_storage_worker; create role adlog_user; create role adlog_storage_lifecycle_worker;
            grant adlog_storage_owner to postgres;
            grant create on schema public to adlog_storage_owner;
            create table schema_migrations(version integer primary key,name text);
            insert into schema_migrations values(334,'account_decoy_restore');
            grant select,insert on schema_migrations to adlog_storage_owner;
            create table servers(id bigint primary key,domain_id bigint,hostname text,role text);
            create table storage_v2_channel(id bigint primary key,value text);
            create table storage_v2_provider(id bigint primary key,value text);
            create table storage_v2_keywords(id bigint primary key,value text);
            create table events_v2_core(id bigint primary key,domain_id bigint,server_id bigint,channel_id bigint,provider_id bigint,keywords_id bigint,event_record_id bigint,event_id integer,time_created_utc timestamptz,subject_user_sid text,subject_user_name text,target_user_sid text,target_user_name text,source_core_sha256 bytea,ip_address text,workstation_name text);
            create table event_facts_v2(event_id bigint primary key,account_target_sid text,account_target_name text,membership_member_sid text,membership_member_name text,account_name_before text,account_name_after text,result_code text,source_facts_sha256 bytea);
            create table entities_v2(id bigint primary key,domain_id bigint);
            create table ad_context_entity_aliases(domain_id bigint,entity_id bigint,alias_type text,normalized_value text);
            create function entity_v2_is_active(bigint) returns boolean language sql immutable as $$select true$$;
            create table semantic_processing_outbox(source_event_id bigint,job_kind text,status text);
            create table ad_context_entity_versions(entity_id bigint,source_run_id text,source_section text,valid_to_utc timestamptz,last_observed_at_utc timestamptz,attributes_json jsonb);
            create table ad_context_runs(run_id text,status text,scope_json jsonb);
            create table ad_context_evidence(id bigint,source_run_id text,locator_json jsonb);
            insert into servers values(1,7,'dc01.example.test','domain_controller'),(2,8,'dc01.example.test','domain_controller'),(3,7,'member.example.test','member');
            insert into storage_v2_channel values(1,'Security');
            insert into storage_v2_provider values(1,'Microsoft-Windows-Security-Auditing');
            insert into storage_v2_keywords values(1,'AuditSuccess');
            """, ct);
        await pg.ApplyFileAsync(Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/335_event_storage_s2.sql"), null, ct);
        await pg.ApplyFileAsync(Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/336_event_storage_read_grants.sql"), null, ct);
        await PostCollectionPostgres.Sql(db, "grant select on servers,semantic_processing_outbox,ad_context_entity_aliases,entities_v2 to adlog_user", ct);
    }
    static ShortEventRow Event(long id, int kind, DateTimeOffset time, long domain=7, long server=1)
    {
        XNamespace ns=EventXml.Namespace;
        var data=new Dictionary<string,string> { ["TargetUserSid"]=Sid,["TargetUserName"]="synthetic-user",
            ["TargetDomainName"]="example.test",["IpAddress"]="192.0.2.10",["LogonType"]="3",["Status"]="0xC000006A" };
        var xml=new XElement(ns+"Event",new XElement(ns+"System",
            new XElement(ns+"Provider",new XAttribute("Name",AdReportStore.SecurityProvider)),
            new XElement(ns+"EventID",kind),new XElement(ns+"EventRecordID",id),
            new XElement(ns+"TimeCreated",new XAttribute("SystemTime",AdJson.Iso(time))),
            new XElement(ns+"Keywords",kind==4624?"0x8020000000000000":"0x8010000000000000"),
            new XElement(ns+"Channel","Security"),new XElement(ns+"Computer","dc01.example.test")),
            new XElement(ns+"EventData",data.Select(p=>new XElement(ns+"Data",new XAttribute("Name",p.Key),p.Value))));
        var native=EventXml.Parse(xml.ToString(),"dc01.example.test","dc01.example.test","Security");
        return ShortEventRow.Create(id,domain,native,Direct4624Projection.Create(native),server)!;
    }
    [Fact]
    public async Task Authentication_reads_hot_events_and_older_daily_groups_under_application_role()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var pg=new PostCollectionPostgres(canonicalSchema:true); await pg.StartAsync(ct);
        await using var db=await pg.OpenAsync(ct); await Seed(pg,db,ct);
        await PostCollectionPostgres.Sql(db,"update servers set hostname='dc01' where id=1",ct);
        var today=new DateTimeOffset(DateTime.UtcNow.Date,TimeSpan.Zero);
        var recent=today.AddHours(1); var old=today.AddDays(-16).AddHours(2);
        var rows=new[] {Event(1,4624,recent),Event(2,4625,recent.AddMinutes(1)),
            Event(3,4624,old),Event(4,4624,old.AddHours(1)),Event(5,4625,old),
            Event(6,4625,old) with {Source="192.0.2.11"},
            Event(7,4625,recent,8,2),Event(8,4625,old,8,2),
            Event(9,4625,today.AddDays(-14))};
        await SeedCompact(db,rows,ct);
        await PostCollectionPostgres.Sql(db,"delete from event_hot where time_created_utc<date_trunc('day',now())-interval '14 days'",ct);
        await using var app=await pg.OpenAsync(ct,"adlog_user");
        async Task<JsonObject> Read(AdPeriod period,int limit=20,string? cursor=null) {
            await using var tx=await app.BeginTransactionAsync(ct);
            var result=await AdSecurity.ReadAsync(app,new("security",false,false,7,period,limit,
                new JsonObject {["category"]="authentication"},cursor),ct,null!);
            await tx.CommitAsync(ct); return result;
        }
        var hot=await Read(new(today,today.AddDays(1)));
        Assert.Equal(new long[]{2,1},hot["items"]!.AsArray().Select(r=>r!["event_db_id"]!.GetValue<long>()));
        Assert.Equal("retained_match_present",hot["category_coverage"]!["authentication"]!["state"]!.ToString());
        var period=new AdPeriod(today.AddDays(-17),today.AddDays(-14));
        var cold=await Read(period);
        Assert.Empty(cold["items"]!.AsArray());
        var items=cold["daily_summaries"]!.AsArray(); Assert.Equal(3,items.Count);
        var success=Assert.Single(items,r=>r!["event_id"]!.GetValue<long>()==4624)!;
        Assert.Null(success["event_db_id"]); Assert.Equal(2,success["event_count"]!.GetValue<long>());
        Assert.Equal(Sid,success["actor"]!.ToString()); Assert.Equal("192.0.2.10",success["source"]!.ToString());
        Assert.Equal("dc01.example.test",success["computer"]!.ToString());
        Assert.Equal(old.ToString("yyyy-MM-dd"),success["day"]!.ToString());
        Assert.All(items,r=>Assert.Equal(7,r!["domain_id"]!.GetValue<long>()));
        var page=await Read(period,1); var keys=new HashSet<string>();
        while(true) {
            Assert.True(keys.Add(Assert.Single(page["daily_summaries"]!.AsArray())!["summary_key"]!.ToString()));
            if(!page["has_more"]!.GetValue<bool>())break;
            page=await Read(period,1,page["next_cursor"]!.ToString());
        }
        Assert.Equal(3,keys.Count);
        var query=AdSecurityQuery.Create(new("security",false,false,7,period,20,new JsonObject {["category"]="authentication"},null),useColdFacts:true);
        var daily=await AdJson.ReadAsync(app,query.DailySql,ct,query.DailyArgs.Concat(new object?[]{"UTC"}).ToArray());
        Assert.Equal(4,daily.Sum(r=>AdJson.Int(r,"count")));
        var boundary=await Read(new(today.AddDays(-14),today.AddDays(-13)));
        Assert.Equal(9,Assert.Single(boundary["items"]!.AsArray())!["event_db_id"]!.GetValue<long>());
    }
    [Fact]
    public async Task Timestamp_seek_returns_the_same_rows_as_the_full_window_on_every_page()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var pg=new PostCollectionPostgres(canonicalSchema:true); await pg.StartAsync(ct);
        await using var db=await pg.OpenAsync(ct); await Seed(pg,db,ct);
        var today=new DateTimeOffset(DateTime.UtcNow.Date,TimeSpan.Zero);
        var at=today.AddHours(1);
        // Reimport, paired failure kinds, equal timestamps and distinct attempts.
        await SeedCompact(db,[Event(1,4625,at),Event(2,4771,at),Event(3,4776,at),
            Event(4,4625,at),Event(5,4624,at.AddMinutes(1)),Event(6,4625,at.AddMinutes(2)),
            Event(7,4625,at.AddMinutes(3),8,2)],ct);
        await using var app=await pg.OpenAsync(ct,"adlog_user");
        foreach(int limit in new[]{1,2,10}) {
            string? cursor=null;
            do {
                var request=new AdReportRequest("security",false,false,7,new(today,today.AddDays(1)),limit,
                    new JsonObject { ["category"]="authentication" },cursor);
                var query=AdSecurityQuery.Create(request,useColdFacts:true);
                // Previous reader paired the entire retained window before paging.
                // Execute that unbounded relational calculation on the same data.
                string full=query.SelectSql.Replace("and event.time_created_utc>=(select min(time_created_utc) from page_times)","");
                var expected=await AdJson.ReadAsync(app,full,ct,query.Args.ToArray());
                var actual=await AdJson.ReadAsync(app,query.SelectSql,ct,query.Args.ToArray());
                Assert.Equal(expected.Select(r=>r.ToJsonString()),actual.Select(r=>r.ToJsonString()));
                await using var tx=await app.BeginTransactionAsync(ct);
                var page=await AdSecurity.ReadAsync(app,request,ct,null!); await tx.CommitAsync(ct);
                cursor=page["has_more"]!.GetValue<bool>()?page["next_cursor"]!.ToString():null;
            } while(cursor is not null);
        }
    }

    [Fact]
    public async Task Last_workplace_propagates_permission_denial()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var pg=new PostCollectionPostgres(canonicalSchema:true); await pg.StartAsync(ct);
        await using var db=await pg.OpenAsync(ct); await Seed(pg,db,ct);
        await PostCollectionPostgres.Sql(db, """
            alter table event_hot add column ad_user_logon_recorder435 bigint, add column ad_user_workplace_type435 smallint;
            revoke select on event_hot from adlog_user;
            """, ct);
        await using var app=await pg.OpenAsync(ct,"adlog_user"); await using var tx=await app.BeginTransactionAsync(ct);
        var error=await Assert.ThrowsAsync<PostgresException>(()=>AdLastWorkplace.ReadAsync(app,[7],[Sid],ct));
        Assert.Equal("42501",error.SqlState);
    }
    static async Task SeedCompact(NpgsqlConnection db,IEnumerable<ShortEventRow> rows,CancellationToken ct)
    {
        foreach(var row in rows) {
            await using(var partition=new NpgsqlCommand("select public.create_event_storage_partitions($1::date,$1::date)",db)) {
                partition.Parameters.AddWithValue(DateOnly.FromDateTime(row.Time));await partition.ExecuteNonQueryAsync(ct);
            }
            await using var insert=new NpgsqlCommand("""
                insert into event_hot(event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields)
                values($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11::jsonb);
                """,db);
            foreach(object? value in new object?[]{row.EventId,row.Time,row.Kind,row.DomainId,row.Actor,row.Target,row.Source,row.Computer,row.Method,row.Outcome,System.Text.Json.JsonSerializer.Serialize(row.Fields)})
                insert.Parameters.Add(new(){Value=value??DBNull.Value});
            await insert.ExecuteNonQueryAsync(ct);
            if(row.Layer=="fact") {
                await using var fact=new NpgsqlCommand("insert into event_cold_facts select * from event_hot where event_id=$1 and time_created_utc=$2",db);
                fact.Parameters.AddWithValue(row.EventId);fact.Parameters.AddWithValue(row.Time);await fact.ExecuteNonQueryAsync(ct);
            }
        }
        await PostCollectionPostgres.Sql(db,"""
            insert into event_cold_daily
            select (time_created_utc at time zone 'UTC')::date,sha256(convert_to(jsonb_build_array(event_kind,domain_id,actor,target,source,computer,method,outcome)::text,'UTF8')),
                event_kind,domain_id,actor,target,source,computer,method,outcome,count(*),min(time_created_utc),max(time_created_utc)
            from event_hot where event_kind in(4624,4625,4771,4776)
            group by 1,event_kind,domain_id,actor,target,source,computer,method,outcome
            """,ct);
    }

}
