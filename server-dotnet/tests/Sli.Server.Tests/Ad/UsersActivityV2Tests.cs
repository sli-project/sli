using Microsoft.AspNetCore.Http;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using static Sli.Server.Ad.AdJson;
using Sli.Server.Ad;
using Xunit;

namespace Sli.Server.Tests.Ad;

public sealed class UsersActivityV2Tests
{
    static readonly IConfiguration Legacy = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:Storage:ShortEventReads"]="false" }).Build();
    static readonly DateTimeOffset At = Sli.Server.Storage.EventReports.EventReadService.ShortBoundary(null).AddDays(3);
    const string Sid = "S-1-5-21-100000001-200000002-300000003-1001";
    const string GroupSid = "S-1-5-21-100000001-200000002-300000003-2001";
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static JsonObject User() => Obj(new { id = "user:1", entityId = 1, displayName = "Synthetic account", samAccountName = "fixture", enabled = false });
    static JsonObject Current() => Obj(new { users = new[] { User() }, groups = new[] { Group() }, metadata = new { observed_at = Iso(At), watch_groups = new[] { Group() }, collection_status = "completed" } });
    static JsonObject Group() => Obj(new { id = "group:2", name = "Synthetic control group", watchGroup = true });
    static JsonObject Parameters() => Obj(new { period = new { from_utc = Iso(At), to_utc = Iso(At.AddDays(1)) } });
    static AdV2Request Request(string tab, JsonObject? p = null, long[]? domains = null) => new("ad.users.v2", "view", null, domains ?? [1], p ?? Parameters(), tab, null, false, 100, null, "UTC");
    static JsonObject Event(int id, int code, double minutes)
    {
        bool member = code is 4728 or 4729 or 4732 or 4733 or 4756 or 4757;
        return Obj(new { id, event_id = code, domain_id = 1, server_id = 7, time_created_utc = Iso(At.AddMinutes(minutes)),
            target_user_sid = member ? GroupSid : Sid, subject_user_sid = code == 6272 ? Sid : "S-1-5-21-100000001-200000002-300000003-3001",
            membership_member_sid = member ? Sid : null, normalized_event_id = $"00000000-0000-0000-0000-{id:000000000000}", processing_status = "normalized",
            semantic_type = code switch { 4624 => "authentication.session.created", 6272 => "remote_access.authentication.allowed", 4725 => "directory.account.disabled", 4722 => "directory.account.enabled", 4728 or 4732 or 4756 => "group.member.added", _ => "group.member.removed" },
            facts_json = member ? Obj(new { relation_member_sid = Sid, relation_group_sid = GroupSid }) : new JsonObject() });
    }
    static JsonObject Shape(IEnumerable<JsonObject> events, JsonObject? user = null, Dictionary<long, JsonObject>? candidates = null, int repeats = 1) =>
        AdUsersActivity.Shape(events, new() { [(1, Sid)] = user ?? User() }, new() { [(1, GroupSid)] = Group() }, candidates ?? [], 60, repeats);
    static long[][] Evidence(JsonObject data, string key) => data[key]!.AsArray().Select(r => r!["evidence"]!.AsArray().Select(n => long.Parse(n!.ToString())).ToArray()).ToArray();

    [Fact]
    public void DisabledRequiresObservedDisableExactDomainAndLaterSuccessfulAuthentication()
    {
        var events = new[] { Event(1,4725,10),Event(2,4624,9),Event(3,4624,10),Event(4,4624,11),Event(5,6272,12),Event(6,6272,13),Event(7,4624,14),Event(8,4624,15),Event(9,4624,16) };
        events[5]["subject_user_sid"] = null; events[6]["domain_id"] = 2; events[7]["processing_status"] = "ignored"; events[8]["semantic_type"] = "event.unknown";
        var data = Shape([.. events, events[3]]);
        Assert.Equal(new long[][] { [1,4], [1,5] }, Evidence(data,"disabled_active"));
        Assert.Equal(2, data.Int("unknown_identity_events")); Assert.Equal(1, data.Int("unprocessed_events"));
        Assert.Equal(1, data["disabled_active"]![0].Int("delay_minutes"));
        var enabled = User(); enabled["enabled"] = true; Assert.Empty(Shape(events,enabled)["disabled_active"]!.AsArray());
        var changed = User(); changed["whenChanged"] = Iso(At); Assert.Empty(Shape([Event(1,4624,11)],changed)["disabled_active"]!.AsArray());
    }
    [Fact]
    public void ReenableAndLatestDisableDiscardOldActivity()
    {
        var events = new[] { Event(1,4725,1), Event(2,4624,2), Event(3,4722,3) };
        Assert.Empty(Shape(events)["disabled_active"]!.AsArray());
        Assert.Equal(new long[][] { [4,5] }, Evidence(Shape([..events,Event(4,4725,4),Event(5,6272,5)]),"disabled_active"));
    }
    [Theory]
    [InlineData(4728,4729)] [InlineData(4732,4733)] [InlineData(4756,4757)]
    public void MembershipFamiliesCountEpisodesAndActivityWithoutCountingReplay(int add,int remove)
    {
        var events = new[] { Event(1,add,1),Event(2,4624,2),Event(3,remove,3),Event(4,add,4),Event(5,remove,5) };
        var rows = Shape([..events,events[0]],repeats:2)["temporary_memberships"]!.AsArray();
        Assert.Equal(2,rows.Count); Assert.All(rows,r=>Assert.Equal(2,r.Int("repeats")));
        Assert.Equal("[2]", rows[0]!["activity_evidence"]!.ToJsonString()); Assert.Equal(2,rows[0].Int("interval_minutes"));
        var enriched = User(); enriched["temporaryMemberships"] = rows.DeepClone();
        var row = AdInventoryRows.User(enriched,Iso(At));
        Assert.Contains(row["reason_keys"]!.AsArray(),r=>r!.ToString()=="temporary_membership");
        var reason = Assert.Single(row["reasons"]!.AsArray(),r=>r!.Text("key")=="temporary_membership")!;
        Assert.Contains("не доказывают",reason.Text("limitation")); Assert.Equal("[[1,3],[4,5]]",reason["evidence"]!.ToJsonString());
        Assert.Empty(Shape(events,repeats:3)["temporary_memberships"]!.AsArray());
    }
    [Theory]
    [InlineData(4733,2,1,null)] [InlineData(4729,2,2,null)] [InlineData(4729,62,1,null)]
    [InlineData(4729,1,1,null)] [InlineData(4729,2,1,"S-1-5-32-555")]
    public void PairingNeverCrossesFamilyDomainWindowOrGroup(int remove,int minutes,int domain,string? sid)
    {
        var end=Event(2,remove,minutes);end["domain_id"]=domain;
        if(sid is not null){end["target_user_sid"]=sid;end["facts_json"]!["relation_group_sid"]=sid;}
        Assert.Empty(Shape([Event(1,4728,1),end])["temporary_memberships"]!.AsArray());
    }
    [Fact]
    public void MissingMemberIsCountedAsUnknown()
    {
        var unknown=Event(3,4728,2);unknown["membership_member_sid"]=null;unknown["facts_json"]=new JsonObject();
        Assert.Equal(1,Shape([unknown]).Int("unknown_identity_events"));
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public void AlternativeRemovalsOrCandidateEvidenceKeepIntervalAmbiguous(bool candidate)
    {
        var events=new List<JsonObject>{Event(1,4728,1),Event(2,4729,2)};
        if(!candidate)events.Add(Event(3,4729,3));
        var data=Shape(events,candidates:candidate?new(){[1]=Obj(new{candidate_id="00000000-0000-0000-0000-000000000001",evidence_count=3,confidence="medium"})}:null);
        var row=Assert.Single(data["temporary_memberships"]!.AsArray())!;
        Assert.Equal("ambiguous",row.Text("quality")); Assert.Null(row["interval_minutes"]);Assert.Null(row["removed_at"]);Assert.Null(row["activity_count"]);Assert.Empty(row["activity_evidence"]!.AsArray());
        Assert.Equal(candidate?"00000000-0000-0000-0000-000000000001":null,row.Text("candidate_id"));
    }
    static async Task Schema(NpgsqlConnection db)
    {
        await PostCollectionPostgres.Sql(db,"""
            create table entities_v2(id bigint,domain_id bigint);
            insert into entities_v2 values(1,1),(2,1);
            create table ad_context_entity_aliases(entity_id bigint,alias_type text,alias_value text);
            create table servers(id bigint,domain_id bigint,role text);
            insert into servers values(7,1,'domain_controller'),(8,2,'domain_controller');
            create table event_hot(event_id bigint,time_created_utc timestamptz,event_kind int,domain_id bigint,actor text,target text,source text,computer text,method jsonb,outcome jsonb,fields jsonb);
            create table event_cold_facts (like event_hot);
            alter table event_hot add column ad_user_logon_recorder435 bigint generated always as (
                case when event_kind=4624 and method->>'$channel'='Security'
                    and method->>'$provider'='Microsoft-Windows-Security-Auditing'
                then (method->>'$server_id')::bigint end) stored;
            create table event_cold_daily(day date,event_kind int,domain_id bigint,actor text,target text,source text,computer text,method jsonb,outcome jsonb,grouping_key bytea,event_count bigint,first_seen_utc timestamptz,last_seen_utc timestamptz);
            create table normalized_events(normalized_event_id uuid,source_event_id bigint,semantic_contract_version int,normalized_at timestamptz,processing_status text,semantic_type text,facts_json jsonb);
            create table semantic_correlation_candidates(candidate_id uuid,rule_id text,rule_version int,candidate_status text,window_start_utc timestamptz,last_matched_at timestamptz,evidence_count int,confidence text);
            create table semantic_correlation_candidate_evidence(candidate_id uuid,normalized_event_id uuid,evidence_order int);
            create table semantic_correlation_rules(rule_id text,rule_version int,lifecycle_status text);
            """,Ct);
        await using var seed=new NpgsqlCommand("insert into ad_context_entity_aliases values(1,'object_sid',$1),(2,'object_sid',$2)",db);
        seed.Parameters.AddWithValue(Sid);seed.Parameters.AddWithValue(GroupSid);await seed.ExecuteNonQueryAsync(Ct);
    }
    static async Task Seed(NpgsqlConnection db,params JsonObject[] events)
    {
        foreach(var e in events)
        {
            await using var command=new NpgsqlCommand("""
                insert into event_hot values(@id,@at,@code,@domain,
                    case when @code=4624 then @target else @subject end,@target,'192.0.2.10','dc01.example.test',
                    jsonb_build_object('$server_id',@server::bigint,'$channel','Security','$provider','Microsoft-Windows-Security-Auditing'),
                    '{}'::jsonb,jsonb_build_object('MemberSid',@member::text));
                insert into normalized_events values(@normalized,@id,1,@at,@status,@semantic,@facts);
                """,db);
            object?[] values=[e.Int("id"),(int)e.Int("event_id"),e.Int("domain_id"),e.Int("server_id"),e.Time("time_created_utc"),e.Text("target_user_sid"),e.Text("subject_user_sid"),e.Text("membership_member_sid"),Guid.Parse(e.Text("normalized_event_id")!),e.Text("processing_status"),e.Text("semantic_type")];
            string[] names=["id","code","domain","server","at","target","subject","member","normalized","status","semantic"];
            for(int i=0;i<values.Length;i++)command.Parameters.Add(new(){ParameterName=names[i],Value=values[i]??DBNull.Value});
            command.Parameters.Add(new(){ParameterName="facts",Value=e["facts_json"]!.ToJsonString(),NpgsqlDbType=NpgsqlTypes.NpgsqlDbType.Jsonb});
            await command.ExecuteNonQueryAsync(Ct);
        }
    }
    [Fact]
    public async Task SourceQueryAppliesCodesHalfOpenPeriodAndDomainServerScope()
    {
        await using var pg=new PostCollectionPostgres(canonicalSchema:true);await pg.StartAsync(Ct);await using var db=await pg.OpenAsync(Ct);await Schema(db);
        var other=Event(3,4624,2);other["domain_id"]=2;other["server_id"]=8;
        await Seed(db,Event(1,4624,0),Event(2,6272,1),other,Event(4,4624,-1),Event(5,4624,1440),Event(6,4725,2));
        foreach(var(scope,expected)in new (long[]?,long[])[]{(null,[1,2,3]),([] ,[]),([1],[1,2]),([1,2],[1,2,3])})
        {
            var(sql,args)=AdUsersActivity.EventSql(scope,[4624,6272],new(At,At.AddDays(1)),Legacy);
            var rows=await AdJson.ReadAsync(db,sql,Ct,args);
            Assert.Equal(expected,rows.Select(r=>r.Int("id")));
            Assert.All(rows,r=>Assert.Null(r["processing_status"]));
            if(rows.Any(r=>r.Int("id")==1))Assert.Equal(Sid,rows.Single(r=>r.Int("id")==1).Text("target_user_sid"));
        }
    }

    [Fact]
    public async Task Account_scoped_activity_matches_the_unfiltered_reader()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct);
        await Schema(db);
        var unresolved = Event(6, 4624, 6);
        unresolved["target_user_sid"] = Sid.ToLowerInvariant(); // Activity requires the exact alias.
        var wrongRecorder = Event(7, 4624, 7);
        wrongRecorder["server_id"] = 8;
        await Seed(db, Event(1, 4725, 1), Event(2, 4728, 2), Event(3, 4624, 3),
            Event(4, 4729, 4), Event(5, 4624, 5), unresolved, wrongRecorder);
        var period = new AdPeriod(At, At.AddDays(1));
        await using var tx = await db.BeginTransactionAsync(Ct);
        foreach (bool disabled in new[] { false, true })
        {
            int[] codes = disabled ? [4722, 4725, 4624, 6272] : [4728, 4729, 4732, 4733, 4756, 4757, 4624, 6272];
            var events = await AdAccountEvents.ReadAsync(db, [1], codes, period, Ct, Legacy);
            var expected = Shape(events);
            var actual = await AdUsersActivity.LoadAsync(db, Current(), [1], Parameters(), disabled, Ct, Legacy);
            Assert.Equal(1, actual.Int("unknown_identity_events"));
            Assert.All(expected, field => Assert.True(JsonNode.DeepEquals(field.Value, actual[field.Key]), field.Key));
        }
    }
    [Fact]
    public async Task UserCardCountsDailyLogonsWithinTheDomainAndOmitsDirectoryChanges()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct);
        await Schema(db);
        var today = new DateTimeOffset(DateTime.UtcNow.Date, TimeSpan.Zero);
        await using (var command = new NpgsqlCommand("""
            insert into event_hot
            select id, @stamp::timestamptz - interval '1 day' + id * interval '1 minute',
                   code, domain_id, actor, target, 'test-ws', 'dc01.example.test',
                   jsonb_build_object('$server_id', server_id, '$channel', 'Security',
                                      '$provider', 'Microsoft-Windows-Security-Auditing', 'LogonType', '2'),
                   '{}'::jsonb, jsonb_build_object('MemberSid',member)
              from (values (1,4624,1,7,@sid,null,null), (2,4625,1,7,'test-user@example.test',null,null),
                           (3,4728,1,7,'admin@example.test','Test group',@sid),
                           (4,4738,1,7,@sid,'other@example.test',null),
                           (5,4624,2,8,@sid,null,null), (6,4738,1,7,'admin@example.test',@sid,null),
                           (7,4625,1,7,'test-user@other.example.test',null,null))
                   v(id,code,domain_id,server_id,actor,target,member);
            insert into event_cold_daily values(
                (@stamp::timestamptz at time zone 'UTC')::date-10,4624,1,@sid,null,'test-ws','dc01.example.test',
                jsonb_build_object('$server_id',7,'$channel','Security','$provider','Microsoft-Windows-Security-Auditing','LogonType','2'),
                '{}'::jsonb,decode('01','hex'),3,@stamp::timestamptz-interval '10 days',@stamp::timestamptz-interval '10 days');
            """, db))
        {
            command.Parameters.AddWithValue("stamp", today);
            command.Parameters.AddWithValue("sid", Sid);
            await command.ExecuteNonQueryAsync(Ct);
        }
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["Sli:Storage:HotRetentionDays"] = "7" }).Build();
        var result = Assert.Single(await AdJson.ReadAsync(db,
            AdAccountEvents.Source(config) + AdUserCard.ActivitySql, Ct, new[] { 4624, 4625 }, today.AddDays(-30),
            today, 1L, Sid, new[] { "test-user@example.test" }, today));
        var totals = JsonNode.Parse(result.Text("logon_totals")!)!;
        Assert.Equal(4, totals.Int("successes"));
        Assert.Equal(1, totals.Int("failures"));
        Assert.Equal(0, totals.Int("typical"));
        var computers = JsonNode.Parse(result.Text("computers")!)!.AsArray();
        Assert.Equal(1, Assert.Single(computers).Int("id"));
        var timeline = JsonNode.Parse(result.Text("timeline")!)!.AsArray();
        Assert.Equal([1L, 2L], timeline.Where(row => row.Int("id") > 0).Select(row => row.Int("id")).Order());
    }

    [Fact]
    public async Task LoaderDoesNotAttachLegacyCandidatesToShortEvents()
    {
        await using var pg=new PostCollectionPostgres(canonicalSchema:true);await pg.StartAsync(Ct);await using var db=await pg.OpenAsync(Ct);await Schema(db);await Seed(db,Event(1,4728,1),Event(2,4729,2));
        await using(var command=new NpgsqlCommand("""
            insert into semantic_correlation_candidates values('00000000-0000-0000-0000-000000000001',@chain,1,'matched',@at,@at,2,'medium');
            insert into semantic_correlation_candidate_evidence values('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',0),('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002',1);
            """,db)){command.Parameters.AddWithValue("chain",AdUsersActivity.Chain);command.Parameters.AddWithValue("at",At);await command.ExecuteNonQueryAsync(Ct);}
        await using var tx=await db.BeginTransactionAsync(Ct);
        async Task<JsonObject> Load()=>await AdUsersActivity.LoadAsync(db,Current(),[1],Parameters(),false,Ct,Legacy);
        var data=await Load();var row=Assert.Single(data["temporary_memberships"]!.AsArray())!;
        Assert.Null(row["candidate_id"]);Assert.Equal("partial",data.Text("state"));Assert.False(data["truncated"]!.GetValue<bool>());
        await PostCollectionPostgres.Sql(db,"insert into semantic_correlation_rules select rule_id,2,'shadow' from semantic_correlation_candidates",Ct);
        Assert.Null((await Load())["temporary_memberships"]![0]!["candidate_id"]);
        await PostCollectionPostgres.Sql(db,"delete from semantic_correlation_rules; insert into normalized_events select '00000000-0000-0000-0000-000000000102',2,2,normalized_at,processing_status,semantic_type,facts_json from normalized_events where source_event_id=2",Ct);
        Assert.Null((await Load())["temporary_memberships"]![0]!["candidate_id"]);
        await PostCollectionPostgres.Sql(db,"insert into entities_v2 values(3,1); insert into ad_context_entity_aliases select 3,alias_type,alias_value from ad_context_entity_aliases where entity_id=1",Ct);
        var current=Current();var duplicate=User();duplicate["entityId"]=3;current["users"]!.AsArray().Add(duplicate);
        Assert.Empty((await AdUsersActivity.LoadAsync(db,current,[1],Parameters(),false,Ct,Legacy))["temporary_memberships"]!.AsArray());
    }
    [Fact]
    public async Task EmptyScopeDoesNotOpenOrReadDatabase()
    {
        await using var closed=new NpgsqlConnection();
        var data=await AdUsersActivity.LoadAsync(closed,Current(),[],Parameters(),true,Ct);
        Assert.Empty(data["disabled_active"]!.AsArray());Assert.Equal("partial",data.Text("state"));
    }
    [Fact]
    public async Task ActivityTabsFilterMetricsAndReportUnreadableSourcesHonestly()
    {
        await using var pg=new PostCollectionPostgres(canonicalSchema:true);await pg.StartAsync(Ct);await using var db=await pg.OpenAsync(Ct);await Schema(db);
        await Seed(db,Event(1,4725,1),Event(2,4624,2),Event(3,4624,3));
        await using var tx=await db.BeginTransactionAsync(Ct);
        var sources=new List<JsonObject>{new(){["snapshot"]=Current(),["domain_id"]=1,["observed_at_utc"]=Iso(At)}};
        var p=Parameters();p["activity_type"]="4624";
        var result=await AdUsersActivity.QueryAsync(db,Request("disabled_active",p),sources,_=>true,Ct,Legacy);
        Assert.Equal("partial",result.Text("state"));Assert.Equal("not_proven",result["coverage"].Text("completeness"));
        Assert.All(result["collections"]!["disabled_active"]!.AsArray(),row=>Assert.Equal("4624",row.Text("activity_type")));
        Assert.Equal(2,result["metrics"]![0].Int("value"));Assert.Empty(result["items"]!.AsArray());
        Assert.Equal("denied",(await AdUsersActivity.QueryAsync(db,Request("temporary_memberships"),sources,fields=>!fields.Contains("privilege"),Ct)).Text("state"));
        await PostCollectionPostgres.Sql(db,"create role fixture_activity_reader; grant usage on schema public to fixture_activity_reader; grant select on entities_v2,ad_context_entity_aliases to fixture_activity_reader; set local role fixture_activity_reader",Ct);
        result=await AdUsersActivity.QueryAsync(db,Request("disabled_active"),sources,_=>true,Ct,Legacy);
        Assert.Equal("error",result.Text("state"));Assert.Empty(result["metrics"]!.AsArray());
        Assert.Equal("unavailable",result["coverage"].Text("state"));
        Assert.Contains(result["limitations"]!.AsArray(),n=>n.Text("code")=="activity_unavailable");
        Assert.Equal(1,(await AdJson.ReadAsync(db,"select 1 as alive",Ct))[0].Int("alive"));
    }
    [Fact]
    public async Task MainUserListLoadsTemporaryReasonAndFiltersWithoutChangingSavedSnapshot()
    {
        await using var pg=new PostCollectionPostgres(canonicalSchema:true);await pg.StartAsync(Ct);await using var db=await pg.OpenAsync(Ct);await Schema(db);
        await Seed(db,Event(1,4728,1),Event(2,4729,2),Event(3,4728,3),Event(4,4729,4));
        await PostCollectionPostgres.Sql(db,"""
            create table domains(id bigint,fqdn text);insert into domains values(1,'example.test');
            create table ad_snapshot_manifests(manifest_id uuid,domain_id bigint,coverage_state text,slot_start_utc timestamptz);
            insert into ad_snapshot_manifests values('00000000-0000-0000-0000-000000000001',1,'complete',now());
            create table ad_snapshot_manifest_sources(manifest_id uuid,family text,source_state text,observed_at_utc timestamptz,payload_sha256 bytea,source_id text);
            create table users_report_v2_snapshots(snapshot_id bigint,domain_id bigint,payload_json jsonb,payload_sha256 bytea,scope_json jsonb);
            create table platform_settings(key text,value text);
            """,Ct);
        var current=Current();
        await using(var seed=new NpgsqlCommand("""
            insert into users_report_v2_snapshots values(1,1,@payload,decode(@hash,'hex'),'{}');
            insert into ad_snapshot_manifest_sources values('00000000-0000-0000-0000-000000000001','users_v2','complete',now(),decode(@hash,'hex'),'1');
            """,db)){seed.Parameters.AddWithValue("payload",NpgsqlTypes.NpgsqlDbType.Jsonb,current.ToJsonString());seed.Parameters.AddWithValue("hash",AdJobPlugin.Digest(current));await seed.ExecuteNonQueryAsync(Ct);}
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{["ConnectionStrings:Sli"]=pg.ConnectionString,["Sli:Storage:ShortEventReads"]="false"}).Build();
        var store=new AdV2Store(new PostgresConnectionFactory(config),config);var p=Parameters();p["reason"]="temporary_membership";p["min_repeats"]=2;
        var result=await store.ReadAsync(Request("users",p),_=>true,Ct);
        var row=Assert.Single(result["items"]!.AsArray())!;Assert.Contains(row["reason_keys"]!.AsArray(),n=>n!.ToString()=="temporary_membership");Assert.Equal("partial",result.Text("state"));
        Assert.Null(current["users"]![0]!["temporaryMemberships"]);
        var stored=(await AdJson.ReadAsync(db,"select payload_json::text as payload from users_report_v2_snapshots",Ct))[0].Text("payload")!;
        Assert.Null(JsonNode.Parse(stored)!["users"]![0]!["temporaryMemberships"]);
        var activity=await store.ReadAsync(Request("temporary_memberships",p),_=>true,Ct);Assert.Equal(2,activity["collections"]!["temporary_memberships"]!.AsArray().Count);
    }
    [Theory]
    [InlineData("disabled_active")]
    [InlineData("temporary_memberships")]
    [InlineData("users")]
    public void ActivityParametersAndViewsAreAccepted(string tab)
    {
        var context = new DefaultHttpContext();
        context.Request.QueryString = new("?tab=" + tab + "&max_minutes=60&min_repeats=2&activity_type=6272");
        Assert.Equal(tab, AdV2Endpoints.Parse(context.Request, "ad.users.v2", "view", [1]).Tab);
    }
    [Theory]
    [InlineData("max_minutes=1441")]
    [InlineData("min_repeats=101")]
    [InlineData("max_minutes=-1")]
    [InlineData("period=custom&from=2026-10-01T00:00:00Z&to=2026-11-02T00:00:00Z")]
    [InlineData("period=custom&from=2026-10-01T00:00:00Z&to=2026-10-01T00:00:00Z")]
    public void InvalidActivityWindowsAndThresholdsAreRejected(string query)
    {
        var context = new DefaultHttpContext();
        context.Request.QueryString = new("?tab=disabled_active&" + query);
        Assert.Throws<AdInputException>(() => AdV2Endpoints.Parse(context.Request, "ad.users.v2", "view", [1]));
    }
}
