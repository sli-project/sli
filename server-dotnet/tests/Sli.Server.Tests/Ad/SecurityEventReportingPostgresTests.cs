using System.Text.Json.Nodes;
using System.Net;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Ad;
using Sli.Server.Reports.SecurityCandidates;
using Sli.Server.Tests.Agents;
using Sli.Server.Reporting.V2;
using Sli.Server.Storage.History;
using Sli.Server.Tests.Reporting;
using Xunit;

namespace Sli.Server.Tests.Ad;

public sealed partial class SecurityEventReportingTests
{
    [Fact]
    public async Task Category_presence_does_not_rescan_the_window_for_each_absent_kind()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct);
        await using (var seed = new NpgsqlCommand("""
            create table servers(id bigint primary key,hostname text,role text,domain_id bigint);
            create table event_hot(event_id bigint,time_created_utc timestamptz,event_kind int,domain_id bigint,actor text,target text,source text,computer text,method jsonb,outcome jsonb,fields jsonb);
            create table event_cold_facts(like event_hot);
            create table event_cold_daily(day date,event_kind int,domain_id bigint,actor text,target text,source text,computer text,method jsonb,outcome jsonb,grouping_key bytea,event_count bigint,first_seen_utc timestamptz,last_seen_utc timestamptz);
            create index on event_cold_facts(event_kind,time_created_utc desc,event_id desc);

            create table storage_v2_channel(id bigint primary key,value text);
            create table storage_v2_provider(id bigint primary key,value text);
            create table storage_v2_keywords(id bigint primary key,value text);
            create table events_v2_core(id bigint primary key,domain_id bigint,server_id bigint,channel_id bigint,provider_id bigint,keywords_id bigint,event_record_id bigint,event_id integer,time_created_utc timestamptz,subject_user_sid text,subject_user_name text,target_user_sid text,target_user_name text,source_core_sha256 bytea);
            create table event_facts_v2(event_id bigint primary key,account_target_sid text,account_target_name text,membership_member_sid text,membership_member_name text,account_name_before text,account_name_after text,result_code text,source_facts_sha256 bytea);
            create table semantic_processing_outbox(source_event_id bigint,job_kind text,status text);
            create index idx_events_v2_event_id_time on events_v2_core(event_id,time_created_utc desc,id desc);
            create index idx_semantic_processing_outbox_claim on semantic_processing_outbox(status);
            insert into servers values(1,'dc01.example.test','domain_controller',7);
            insert into storage_v2_channel values(1,'Security');
            insert into storage_v2_provider values(1,'Microsoft-Windows-Security-Auditing');
            insert into events_v2_core(id,domain_id,server_id,channel_id,provider_id,event_id,time_created_utc)
                select n,7,1,1,1,case when n%100=0 then 4728 else 4625 end,
                    '2026-09-01T10:00:00Z'::timestamptz+n*interval '0.01 seconds' from generate_series(1,200000) n;
            insert into event_cold_facts select id,time_created_utc,event_id,domain_id,null,null,null,'dc01.example.test',
                '{"$server_id":1,"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing"}','{}','{}' from events_v2_core;
            analyze;
            """, db) { CommandTimeout = 0 }) await seed.ExecuteNonQueryAsync(Ct);
        var q = AdSecurityQuery.Create(Request());
        var categories = await q.CategoriesAsync(db, Ct);
        Equal("""{"state":"retained_match_present"}""", categories["authentication"]);
        Equal("""{"state":"retained_match_present"}""", categories["group_membership"]);
        Equal("""{"state":"no_retained_match"}""", categories["account_lock"]);
        await using var explain = new NpgsqlCommand("explain(analyze,buffers,format json) " + q.CategorySql, db) { CommandTimeout = 0 };
        foreach (var value in q.CategoryArgs) explain.Parameters.Add(new() { Value = value });
        var plan = JsonNode.Parse((string)(await explain.ExecuteScalarAsync(Ct))!)![0]!["Plan"]!;
        static long EventRows(JsonNode node) => (node["Relation Name"]?.ToString() is "event_hot" or "event_cold_facts" or "event_cold_daily"
            ? (long)((double.Parse(node["Actual Rows"]!.ToString(), System.Globalization.CultureInfo.InvariantCulture)
                + double.Parse(node["Rows Removed by Filter"]?.ToString() ?? "0", System.Globalization.CultureInfo.InvariantCulture))
                * double.Parse(node["Actual Loops"]!.ToString(), System.Globalization.CultureInfo.InvariantCulture)) : 0)
            + (node["Plans"] as JsonArray ?? []).Sum(n => EventRows(n!));
        Assert.True(EventRows(plan) <= 200000, "Category presence rescanned the retained window: " + EventRows(plan)+" "+plan.ToJsonString());
    }

    [Fact]
    public async Task Postgres_page_resolution_exact_filters_candidates_categories_and_daily_match_reference()
    {
        // Private disposable cluster, never an inherited DSN or installed database.
        await using var pg = new PostCollectionPostgres(canonicalSchema:true); await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db,"""
            create table servers(id bigint primary key,hostname text,role text,domain_id bigint);
            create table event_hot(event_id bigint,time_created_utc timestamptz,event_kind int,domain_id bigint,actor text,target text,source text,computer text,method jsonb,outcome jsonb,fields jsonb);
            create table event_cold_facts(like event_hot);
            create table event_cold_daily(day date,event_kind int,domain_id bigint,actor text,target text,source text,computer text,method jsonb,outcome jsonb,grouping_key bytea,event_count bigint,first_seen_utc timestamptz,last_seen_utc timestamptz);
            create index on event_cold_facts(event_kind,time_created_utc desc,event_id desc);

            create table storage_v2_channel(id bigint primary key,value text);
            create table storage_v2_provider(id bigint primary key,value text);
            create table storage_v2_keywords(id bigint primary key,value text);
            create table events_v2_core(id bigint primary key,domain_id bigint,server_id bigint,channel_id bigint,provider_id bigint,keywords_id bigint,event_record_id bigint,event_id integer,time_created_utc timestamptz,subject_user_sid text,subject_user_name text,target_user_sid text,target_user_name text,source_core_sha256 bytea,ip_address text,workstation_name text);
            create table event_facts_v2(event_id bigint primary key,account_target_sid text,account_target_name text,membership_member_sid text,membership_member_name text,account_name_before text,account_name_after text,result_code text,source_facts_sha256 bytea);
            create table entities_v2(id integer primary key,domain_id bigint,active boolean);
            create table ad_context_entity_aliases(domain_id bigint,entity_id integer,alias_type text,normalized_value text);
            create function entity_v2_is_active(bigint) returns boolean language sql stable as $$select active from public.entities_v2 where id=$1$$;
            create function resolve_entity_identity_v2(bigint) returns bigint language sql immutable as $$select $1$$;
            create table event_entity_link_blocks_v2(entity_id bigint,first_event_id bigint,last_event_id bigint,event_ids bigint[],role_ids integer[]);
            create table semantic_processing_outbox(source_event_id bigint,job_kind text,status text);
            insert into servers values(1,'dc01.example.test','domain_controller',7),(2,'dc02.example.test','domain_controller',8),(3,'member.example.test','member',7);
            insert into storage_v2_channel values(1,'Security'),(2,'Application');
            insert into storage_v2_provider values(1,'Microsoft-Windows-Security-Auditing'),(2,'Microsoft-Windows-Eventlog'),(3,'untrusted');
            insert into storage_v2_keywords values(1,'AuditSuccess');
            insert into entities_v2 values(101,7,true),(102,7,false),(103,7,true),(104,7,true),(105,7,true),(201,8,true);
            insert into event_entity_link_blocks_v2 values(105,10,10,array[10]::bigint[],array[1]);
            insert into semantic_processing_outbox values(10,'normalize_event','queued');
            """,Ct);
        foreach(var (domain,entity,sid) in new[]{(7,101,Actor),(7,102,Target),(7,103,Member),(7,104,Member),(8,201,Actor)})
        {
            await using var alias = new NpgsqlCommand("insert into ad_context_entity_aliases values($1,$2,'object_sid',lower($3))",db);
            alias.Parameters.AddWithValue(domain); alias.Parameters.AddWithValue(entity); alias.Parameters.AddWithValue(sid); await alias.ExecuteNonQueryAsync(Ct);
        }
        await PostCollectionPostgres.Sql(db,"""
            alter table entities_v2 add column natural_key text,add column server_id bigint;
            create table entity_identity_merges_v2(source_entity_id bigint,source_natural_key text,target_entity_id bigint);
            create table entity_details_v2(entity_id bigint,attributes_json jsonb);
            """,Ct);
        string shortMigration=await File.ReadAllTextAsync(Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/339_short_entity_reads.sql"),Ct);
        foreach(System.Text.RegularExpressions.Match function in System.Text.RegularExpressions.Regex.Matches(shortMigration,@"create function [\s\S]*?\$\$;"))
            await PostCollectionPostgres.Sql(db,function.Value,Ct);
        async Task Seed(long id,int minute,long domain=7,int code=4728,long channel=1,long provider=1,long server=1)
        {
            await using var cmd = new NpgsqlCommand("""
                insert into events_v2_core values($1,$2,$3,$4,$5,1,9000+$1,$6,$7,$8,'operator',$9,'affected',decode(repeat('61',32),'hex'))
                """,db);
            foreach(object value in new object[]{id,domain,server,channel,provider,code,Period.Start.AddMinutes(minute).UtcDateTime,Actor,Target}) cmd.Parameters.Add(new(){Value=value});
            await cmd.ExecuteNonQueryAsync(Ct);
            await using var facts = new NpgsqlCommand("insert into event_facts_v2(event_id,membership_member_sid,membership_member_name,source_facts_sha256) values($1,$2,'Alice',decode(repeat('62',32),'hex'))",db);
            facts.Parameters.AddWithValue(id); facts.Parameters.AddWithValue(Member); await facts.ExecuteNonQueryAsync(Ct);
            await using var stored=new NpgsqlCommand("""
                insert into event_cold_facts select e.id,e.time_created_utc,e.event_id,e.domain_id,
                    case when e.event_id=4624 then e.target_user_sid else e.subject_user_sid end,
                    case when e.event_id<>4624 then e.target_user_sid end,null,s.hostname,
                    jsonb_build_object('$server_id',e.server_id,'$channel',c.value,'$provider',p.value)
                        || case when e.event_id=4624 then jsonb_build_object('$principals',jsonb_build_object(
                            'SubjectUserSid',e.subject_user_sid,'SubjectUserName',e.subject_user_name,
                            'TargetUserSid',e.target_user_sid,'TargetUserName',e.target_user_name)) else '{}'::jsonb end,
                    jsonb_build_object('keywords','AuditSuccess'),jsonb_build_object('MemberSid',f.membership_member_sid,'MemberName','Alice')
                from events_v2_core e join event_facts_v2 f on f.event_id=e.id join servers s on s.id=e.server_id
                join storage_v2_channel c on c.id=e.channel_id join storage_v2_provider p on p.id=e.provider_id where e.id=$1
                """,db);
            stored.Parameters.AddWithValue(id);await stored.ExecuteNonQueryAsync(Ct);
        }
        await Seed(30,30); await Seed(20,20); await Seed(10,10); await Seed(40,40,8,4624,server:2);
        await PostCollectionPostgres.Sql(db,"update events_v2_core set subject_user_sid='S-1-5-21-100000001-200000002-300000003-1004' where id=10; update event_cold_facts set actor='S-1-5-21-100000001-200000002-300000003-1004' where event_id=10",Ct);
        // These must never contaminate the Security/DC/provider-scoped window.
        await Seed(50,50,channel:2); await Seed(51,51,provider:3); await Seed(52,52,server:3); await Seed(60,60);
        var query = AdSecurityQuery.Create(Request(limit:2)); var all = await AdJson.ReadAsync(db,query.SelectSql,Ct,query.Args.ToArray());
        Assert.Equal(new long[]{30,20,10},all.Select(r=>AdJson.Int(r,"event_db_id")));
        var page = all.Take(2).ToList(); await AdSecurityQuery.ResolveEntitiesAsync(db,page,7,Ct);
        Assert.False(all[2].ContainsKey("actor_entity_id"));
        Assert.All(page,r => { Assert.Equal(101,AdJson.Int(r,"actor_entity_id")); Assert.False(r.ContainsKey("target_entity_id")); Assert.False(r.ContainsKey("member_entity_id")); });
        var domain8 = await AdJson.ReadAsync(db,AdSecurityQuery.Create(Request(domain:8)).SelectSql,Ct,AdSecurityQuery.Create(Request(domain:8)).Args.ToArray());
        await AdSecurityQuery.ResolveEntitiesAsync(db,domain8,8,Ct);
        var signIn = Assert.Single(domain8);
        Assert.Equal(201,AdJson.Int(signIn,"actor_entity_id"));
        Assert.Equal(Target,AdJson.Text(signIn,"target_user_sid"));
        var publicPage = AdSecurity.Compose(Request(limit:2),page,true,true,await query.CategoriesAsync(db,Ct));
        var legacy = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string,string?> { ["Sli:Storage:ShortEventReads"] = "false" }).Build();
        var archive = new Details(); var report = await AdSecurity.ReadAsync(db,Request(limit:2),Ct,archive,legacy);
        Assert.Empty(archive.Batches); Assert.True(report["has_more"]!.GetValue<bool>());
        Assert.Equal(101,Item(report,30)["actor"]!["entity_id"]!.GetValue<long>());
        string cursor = publicPage["next_cursor"]!.ToString();
        var reverse = AdSecurityQuery.Create(Request(limit:2,cursor:cursor));
        Assert.Equal(10,AdJson.Int(Assert.Single(await AdJson.ReadAsync(db,reverse.SelectSql,Ct,reverse.Args.ToArray())),"event_db_id"));


        async Task<long[]> Selected(JsonObject filters)
        {
            var q = AdSecurityQuery.Create(Request(filters,limit:2));
            return (await AdJson.ReadAsync(db,q.SelectSql,Ct,q.Args.ToArray())).Select(r=>AdJson.Int(r,"event_db_id")).ToArray();
        }
        Assert.Equal(new long[]{30,20},await Selected(Filters(("entity_id","101"))));
        Assert.Empty(await Selected(Filters(("entity_id","105"),("event_db_id","10"))));
        Assert.Empty(await Selected(Filters(("entity_id","102"))));
        Assert.Equal(new long[]{30,20,10},await Selected(Filters(("category","group_membership"))));
        Assert.Equal(new long[]{30,20,10},await Selected(Filters(("event_id","4728"))));
        Assert.Empty(await Selected(Filters(("category","authentication"))));
        Assert.Equal(new long[]{30,20},await Selected(Filters(("actor",Actor),("group",Target),("source","dc01.example.test"),("q","Alice"))));
        Assert.Empty(await Selected(Filters(("target","affected"))));

        var category = AdSecurityQuery.Create(Request(Filters(("category","group_membership")),cursor:AdSecurity.EncodeCursor(7,Period,Filters(("category","group_membership")),Period.Start.AddMinutes(20),20)));
        var coverage = await category.CategoriesAsync(db,Ct);
        Equal("""{"state":"processing_unfinished"}""",coverage["group_membership"]);
        Equal("""{"state":"not_selected"}""",coverage["account_lock"]);
        var daily = await AdJson.ReadAsync(db,category.DailySql,Ct,category.DailyArgs.Concat(new object?[]{"Asia/Novosibirsk"}).ToArray());
        Assert.Equal(3,AdJson.Int(Assert.Single(daily),"count")); Assert.Equal("2026-09-01",daily[0]["date"]!.ToString());


        // Ad no longer consults external history, including when the old flag is false.
        var store=new AdReportStore(new Sli.Server.Infrastructure.PostgresConnectionFactory(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string,string?>{{"ConnectionStrings:Sli",pg.ConnectionString},{"Sli:Storage:ShortEventReads","false"}}).Build()),new Details());
        var direct=await store.ReadAsync(Request(limit:2),false,Ct);
        Assert.Equal(new long[]{30,20},direct["items"]!.AsArray().Select(r=>AdJson.Int(r!,"event_db_id")));
    }
}
