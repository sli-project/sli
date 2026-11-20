using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Sli.Server.Storage.EventReports;
using Xunit;

namespace Sli.Server.Tests.Storage;
public sealed class EventReportBoundaryTests
{
    [Theory]
    [InlineData(3)] [InlineData(21)]
    public async Task Relation_anchor_and_rules_use_configured_hot_retention(int days)
    {
        var configuration=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["Sli:Storage:HotRetentionDays"]=days.ToString(System.Globalization.CultureInfo.InvariantCulture)
        }).Build();
        var boundaries=new List<DateTimeOffset>();
        Task<List<JsonObject>> Query(string sql,IReadOnlyDictionary<string,object> args,CancellationToken ct)
        {
            boundaries.Add(Assert.IsType<DateTimeOffset>(args["boundary"]));
            return Task.FromResult<List<JsonObject>>(boundaries.Count==1 ?
                [new() { ["server_id"]=7,["time_created_utc"]=DateTimeOffset.UtcNow,["logon_id"]="0x123" }] : []);
        }
        Assert.Empty(await new EventRelationStore(Query,configuration).QueryAsync(1,10,null,TestContext.Current.CancellationToken));
        Assert.Equal(2,boundaries.Count);
        Assert.All(boundaries,b=>Assert.Equal(new DateTimeOffset(DateTime.UtcNow.Date,TimeSpan.Zero).AddDays(-days),b));
    }
    [Fact]
    public void UiEventFiltersDefaultMalformedPagingAndForwardSemanticFields()
    {
        var context = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        context.Request.QueryString = new("?limit=not-a-number&offset=broken&provider=Microsoft-Windows-Security-Auditing&subject=alice&target=server-01");
        var input = EventListInput.Parse(context.Request.Query, DateTimeOffset.Parse("2026-07-17T04:00:00Z"));
        Assert.Equal(200, input.Limit); Assert.Null(input.Cursor);
        Assert.Equal("Microsoft-Windows-Security-Auditing", input.Provider); Assert.Equal("alice", input.Subject); Assert.Equal("server-01", input.Target);
    }
    [Theory]
    [InlineData("2026-07-16T20:30:15+07:00", "2026-07-16T13:30:15Z")]
    [InlineData("2026-07-16T20:30:15.123456+07:00", "2026-07-16T13:30:15.123456Z")]
    public void UiEventListNormalizesDatabaseTimeToUtc(string time, string expected)
    {
        var row = new JsonObject { ["id"] = 17, ["event_id"] = 4624, ["time_created_utc"] = DateTimeOffset.Parse(time),
            ["channel"] = "Security", ["provider_name"] = "Microsoft-Windows-Security-Auditing" };
        var result = EventListProjection.Project(row);
        var payload = System.Text.Json.JsonSerializer.SerializeToElement(result);
        Assert.Equal(expected, payload.GetProperty("time_created_utc").GetString());
    }
    [Fact]
    public async Task UiEventEntitiesPreserveBigintThroughShortRows()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db=new Npgsql.NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await Sli.Server.Tests.Agents.PostCollectionPostgres.Sql(db,"""
            insert into servers(id,domain_id,hostname,role,is_active)
                values(1,1,'dc01.example.test','domain_controller',true);
            insert into storage_v2_entity_type(value) values('ad_user') on conflict do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
                select 70001,id,'sid:S-1-5-21-100000001-200000002-300000003-1002','Synthetic',1,sha256('synthetic'::bytea)
                from storage_v2_entity_type where value='ad_user';
            """,ct);
        var row=EventShortReadPostgresTests.Event(2_147_483_648,4625,DateTimeOffset.UtcNow.AddMinutes(-1),1,sid:true).Short;
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            await Sli.Server.Tests.Agents.PostCollectionPostgres.Sql(db,"set local role adlog_storage_worker",ct);
            await Sli.Server.Storage.Direct.ShortEventWriter.WriteAsync(db,tx,[row],ct); await tx.CommitAsync(ct);
        }
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["ConnectionStrings:Sli"]=fixture.Dsn("adlog_user") }).Build();
        await using var reader=new EventReadService(new Sli.Server.Infrastructure.PostgresConnectionFactory(config),config,null!);
        var result=await reader.EntitiesAsync(2_147_483_648,ct);
        Assert.Equal(2_147_483_648,result["event_db_id"]!.GetValue<long>()); Assert.True(result["event_found"]!.GetValue<bool>());
        var item=Assert.Single(result["items"]!.AsArray()); Assert.Equal(70001,item!["id"]!.GetValue<int>());
        Assert.Equal("target",item["link_role"]!.ToString());
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
    [Theory] [InlineData(true,"e.logon_id")] [InlineData(false,"e.task_name")]
    public void Both_evidence_queries_bind_exact_decimal_and_negative_id_without_offset(bool logon,string field)
    {
        using var connection=new Npgsql.NpgsqlConnection();
        using var command=EventRelationStore.CreateRuleCommand(connection,null,1,7,new DateTime(2026,10,1,0,0,0,DateTimeKind.Utc),logon ? "0x123" : "synthetic-task",3,(1.000001m,4),logon);
        Assert.Contains(field+"=@key",command.CommandText);
        Assert.Contains("(abs(extract(epoch from (e.time_created_utc - @base))),-e.id) > (@delta,@negid)",command.CommandText);
        Assert.DoesNotContain("offset",command.CommandText,StringComparison.OrdinalIgnoreCase);
        Assert.Equal(1.000001m,command.Parameters["delta"].Value);
        Assert.Equal(NpgsqlTypes.NpgsqlDbType.Numeric,command.Parameters["delta"].NpgsqlDbType);
        Assert.Equal(-4L,command.Parameters["negid"].Value); Assert.Equal(3,command.Parameters["limit"].Value);
        Assert.Equal(1L,command.Parameters["anchor"].Value); Assert.Equal(7L,command.Parameters["server"].Value);
    }
    [Theory] [InlineData("")] [InlineData("garbage")] [InlineData("W10")] [InlineData("oversized")]
    public async Task Invalid_relation_cursor_never_reaches_storage(string token)
    {
        if(token=="oversized") token=new string('a',2049);
        int calls=0;
        var reader=new EventRelationsReader((anchor,count,after,ct)=>{calls++;throw new InvalidOperationException("invalid cursor read");},(id,ct)=>Task.FromResult(true));
        var error=await Assert.ThrowsAsync<InvalidDataException>(()=>reader.ReadAsync(1,2,token,TimeSpan.FromSeconds(5),TestContext.Current.CancellationToken));
        Assert.Equal("invalid_cursor",error.Message); Assert.Equal(0,calls);
    }
    [Fact] public async Task Relation_continuation_preserves_microseconds_and_tied_id_for_both_evidence_keys()
    {
        var positions=new List<(decimal Delta,long Id)?>();
        Task<IReadOnlyList<RelationCandidate>> Query(long anchor,int count,(decimal Delta,long Id)? after,CancellationToken ct)
        {
            Assert.Equal(1,anchor); Assert.Equal(3,count); positions.Add(after);
            RelationCandidate[] Rule(string kind,string reason)=>new long[]{5,4,3}.Select(id=>new RelationCandidate(id,4624,null,kind,"synthetic",reason,1.000001m)).ToArray();
            return Task.FromResult<IReadOnlyList<RelationCandidate>>([..Rule("auth_session","same_logon_id_same_server"),..Rule("scheduled_task","same_task_same_server_time_window")]);
        }
        var reader=new EventRelationsReader(Query,(id,ct)=>Task.FromResult(true));
        var first=await reader.ReadAsync(1,2,null,TimeSpan.FromSeconds(5),TestContext.Current.CancellationToken);
        Assert.Equal(new long[]{5,4},first["items"]!.AsArray().Select(x=>x!["related_event_db_id"]!.GetValue<long>()));
        string cursor=first["next_cursor"]!.GetValue<string>(); positions.Clear();
        var second=await reader.ReadAsync(1,2,cursor,TimeSpan.FromSeconds(5),TestContext.Current.CancellationToken);
        Assert.Equal((1.000001m,4L),Assert.Single(positions));
        Assert.Equal(3,Assert.Single(second["items"]!.AsArray())!["related_event_db_id"]!.GetValue<long>()); Assert.Null(second["next_cursor"]);
        positions.Clear();
        var error=await Assert.ThrowsAsync<InvalidDataException>(()=>reader.ReadAsync(2,2,cursor,TimeSpan.FromSeconds(5),TestContext.Current.CancellationToken));
        Assert.Equal("invalid_cursor",error.Message); Assert.Empty(positions);
    }
    [Fact] public async Task Merged_relation_rules_preserve_all_pages_after_deduplication_and_denials()
    {
        RelationCandidate Candidate(int id, bool logon) => new(id, 1, null, logon ? "auth_session" : "scheduled_task", "synthetic", logon ? "same_logon_id_same_server" : "same_task_same_server_time_window", id / 3);
        var first = Enumerable.Range(1, 25).Where(i => i % 2 == 1).Select(i => Candidate(i, true)).ToArray();
        var second = Enumerable.Range(1, 25).Where(i => i % 2 == 0 || i % 5 == 0).Select(i => Candidate(i, false)).ToArray();
        Task<IReadOnlyList<RelationCandidate>> Query(long anchor, int count, (decimal Delta, long Id)? after, CancellationToken ct)
        {
            RelationCandidate[] Page(IEnumerable<RelationCandidate> rows) => rows.Where(r => after is null || r.Delta > after.Value.Delta || r.Delta == after.Value.Delta && r.RelatedId < after.Value.Id)
                .OrderBy(r => r.Delta).ThenByDescending(r => r.RelatedId).Take(count).ToArray();
            return Task.FromResult<IReadOnlyList<RelationCandidate>>([.. Page(first), .. Page(second)]);
        }
        bool Allowed(long id) => id == 42 || id % 4 == 0;
        var reader = new EventRelationsReader(Query, (id, ct) => Task.FromResult(Allowed(id)));
        var seen = new List<long>(); string? cursor = null;
        do
        {
            var page = await reader.ReadAsync(42, 2, cursor, TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
            seen.AddRange(page["items"]!.AsArray().Select(r => r!["related_event_db_id"]!.GetValue<long>()));
            cursor = page["next_cursor"]?.GetValue<string>();
            if (cursor is not null) Assert.True(Allowed(EventRelationCursor.Decode(42, cursor).Id));
            Assert.True(seen.Count <= 6);
        } while (cursor is not null);
        Assert.Equal(first.Concat(second).Where(r => Allowed(r.RelatedId)).OrderBy(r => r.Delta).ThenByDescending(r => r.RelatedId).Select(r => r.RelatedId).Distinct(), seen);
    }
    [Theory]
    [InlineData("\"invalid\"", null)]
    [InlineData("{}", null)]
    [InlineData("[]", null)]
    [InlineData("null", -1L)]
    [InlineData("\"42\"", 42L)]
    public void Event_list_cursor_record_is_normalized_or_cursor_is_ignored(string record, long? expected)
    {
        string json = "{\"time\":\"2026-01-02T03:04:05Z\",\"id\":7,\"record\":" + record + "}";
        string token = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+','-').Replace('/','_');
        var query = new Microsoft.AspNetCore.Http.QueryCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues> { ["cursor"] = token });
        var input = EventListInput.Parse(query, DateTimeOffset.UtcNow);
        if (expected is null) Assert.Null(input.Cursor);
        else Assert.Equal(expected, input.Cursor!["record"]!.GetValue<long>());
    }
    [Theory] [InlineData(0.1,1)] [InlineData(1.2,2)] [InlineData(30,3)]
    public void Archive_block_query_has_a_bounded_command_timeout(double seconds,int timeout)
    {
        using var connection=new Npgsql.NpgsqlConnection();
        using var command=Sli.Server.Storage.History.EventDetailStore.CreateBlocksCommand(connection,null,[7],TimeSpan.FromSeconds(seconds));
        Assert.Equal(timeout,command.CommandTimeout);
        Assert.Equal(new long[]{7},command.Parameters["ids"].Value);
        Assert.Throws<TimeoutException>(()=>Sli.Server.Storage.History.EventDetailStore.CreateBlocksCommand(connection,null,[7],TimeSpan.Zero));
    }
    [Fact] public async Task Relations_fill_visible_page_past_denied_candidates()
    {
        var rows=Enumerable.Range(1,12).Select(i=>new RelationCandidate(i,1,null,"auth_session","x","same_logon_id_same_server",i)).ToArray();
        Task<IReadOnlyList<RelationCandidate>> Query(long anchor,int count,(decimal Delta,long Id)? after,CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<RelationCandidate>>(rows.Where(r=>after is null || r.Delta>after.Value.Delta).Take(count).ToArray());
        var reader=new EventRelationsReader(Query,(id,ct)=>Task.FromResult(id==42 || id>=9));
        var page=await reader.ReadAsync(42,2,null,TimeSpan.FromSeconds(5),TestContext.Current.CancellationToken);
        Assert.Equal(new long[]{9,10},page["items"]!.AsArray().Select(x=>x!["related_event_db_id"]!.GetValue<long>()));
        Assert.True(page["truncated"]!.GetValue<bool>());
        string cursor=page["next_cursor"]!.GetValue<string>();
        Assert.Equal(10,EventRelationCursor.Decode(42,cursor).Id);
        var next=await reader.ReadAsync(42,2,cursor,TimeSpan.FromSeconds(5),TestContext.Current.CancellationToken);
        Assert.Equal(new long[]{11,12},next["items"]!.AsArray().Select(x=>x!["related_event_db_id"]!.GetValue<long>()));
        Assert.False(next["truncated"]!.GetValue<bool>()); Assert.Null(next["next_cursor"]);
    }
    [Fact] public void Relation_cursor_matches_frozen_source_and_binds_event()
    {
        const string source="eyJiaW5kaW5nIjoiYzZjYzUxYzFkMzZhMDQ3MTRlMzY0MTBiMTY4MjIyYWVmMTMwMjBiYWUwZTQ4OTM0YTM0YjllMGYwZWJjOTFmNyIsInBvc2l0aW9uIjp7ImRlbHRhIjoiMS4yNTAwMDAiLCJpZCI6OX19";
        Assert.Equal(source,EventRelationCursor.Encode(42,1.250000m,9));
        Assert.Equal((1.250000m,9L),EventRelationCursor.Decode(42,source));
        Assert.Throws<InvalidDataException>(()=>EventRelationCursor.Decode(43,source));
    }
    [Fact] public void Projection_preserves_expired_state_and_formats_source_fields()
    {
        var row=JsonNode.Parse("{\"id\":7,\"subject_domain_name\":\" LAB \",\"subject_user_name\":\" alice \",\"target_user_sid\":\"S-1\",\"ip_address\":\"192.0.2.1\",\"time_created_utc\":\"2026-01-02T03:04:05Z\",\"event_data_json\":null,\"source_payload_state\":\"expired\",\"message_text\":null}")!.AsObject();
        var result=EventDetailProjection.Normalize(row,[]);
        Assert.Equal("LAB\\alice",result["subject"]!.GetValue<string>());
        Assert.Equal("S-1",result["target"]!.GetValue<string>());
        Assert.Equal("02.01.2026 03:04:05 UTC",result["time_created_utc_display"]!.GetValue<string>());
        Assert.Equal("expired",result["source_payload_state"]!.GetValue<string>());
        Assert.Equal("",result["message_text"]!.GetValue<string>());
        Assert.NotEmpty(result["investigation_links"]!.AsArray());
    }
    [Fact] public void Relation_dedupe_preserves_strongest_tie_and_continuation()
    {
        var rows=new[] { new RelationCandidate(9,4625,"2026-01-02T03:04:05Z","auth_session","x","same_logon_id_same_server",1.25m), new RelationCandidate(9,4625,"2026-01-02T03:04:05Z","scheduled_task","x","same_task_same_server_time_window",1.25m), new RelationCandidate(8,1,"2026-01-02T03:04:06Z","scheduled_task","x","same_task_same_server_time_window",2m) };
        var page=EventRelationContract.Build(42,rows,1);
        Assert.True(page["truncated"]!.GetValue<bool>());
        Assert.Equal("strong",page["items"]![0]!["relation_strength"]!.GetValue<string>());
        Assert.Equal(9L,EventRelationCursor.Decode(42,page["next_cursor"]!.GetValue<string>()).Id);
    }
    [Fact] public async Task Every_event_is_admitted_before_hydration_and_denied_id_never_leaves_boundary()
    {
        var decisions=new List<long>(); int calls=0;
        var result=await EventReportAdmission.ReadAsync([7,8],(id,ct)=>{ decisions.Add(id); return Task.FromResult(id==7); },
            (ids,ct)=>{ calls++; Assert.Equal(new long[]{7},ids); Assert.Equal(new long[]{7,8},decisions); return Task.FromResult(new Dictionary<long,JsonObject>{{7,new JsonObject { ["id"]=7 }}}); },TestContext.Current.CancellationToken);
        Assert.Single(result); Assert.Equal(1,calls);
        await Assert.ThrowsAsync<InvalidDataException>(()=>EventReportAdmission.ReadAsync([7],(id,ct)=>Task.FromResult(true),
            (ids,ct)=>Task.FromResult(new Dictionary<long,JsonObject>{{8,new JsonObject { ["id"]=8 }}}),TestContext.Current.CancellationToken));
    }
    [Fact] public void Invalid_event_data_does_not_invent_content_and_unicode_preview_has_source_limit()
    {
        var row=new JsonObject { ["message_text"]=string.Concat(Enumerable.Repeat("😀",241)),["event_data_json"]="invalid" };
        var result=EventDetailProjection.Normalize(row,[]);
        Assert.Empty(result["event_data"]!.AsObject()); Assert.Equal("—",result["event_data_summary"]!.GetValue<string>());
        Assert.Equal(string.Concat(Enumerable.Repeat("😀",239))+"…",result["message_preview"]!.GetValue<string>());
    }    [Fact] public void Source_links_and_event_data_order_are_stable()
    {
        var row=new JsonObject { ["server"]="dc 1",["target_user_name"]="a b",["ip_address"]="127.0.0.1",["time_created_utc"]="2026-01-02T03:04:05Z",["event_data_json"]="{\"TaskName\":\"Task A\",\"TargetUserName\":\"alice\"}" };
        var result=EventDetailProjection.Normalize(row,[]);
        Assert.Equal("TargetUserName=alice; TaskName=Task A",result["event_data_summary"]!.GetValue<string>());
        var links=result["investigation_links"]!.AsArray();
        Assert.Equal("/reports/account-timeline.html?q=a+b&limit=500&order=asc",links[0]!["url"]!.GetValue<string>());
        Assert.DoesNotContain(links,x=>x!["label"]!.GetValue<string>()=="Тот же IP");
        Assert.Contains(links,x=>x!["label"]!.GetValue<string>()=="Изменения этого задания за период");
    }
    [Fact] public async Task Relation_anchor_denial_precedes_query_and_candidate_denial_filters_cursor()
    {
        int queries=0;
        Task<IReadOnlyList<RelationCandidate>> Query(long anchor,int count,(decimal Delta,long Id)? after,CancellationToken ct)
        {
            queries++;
            return Task.FromResult<IReadOnlyList<RelationCandidate>>([
                new(8,1,null,"auth_session","hidden","same_logon_id_same_server",0),
                new(7,1,null,"auth_session","visible","same_logon_id_same_server",1)]);
        }
        var denied=new EventRelationsReader(Query,(id,ct)=>Task.FromResult(false));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>denied.ReadAsync(42,1,null,TimeSpan.FromSeconds(5),TestContext.Current.CancellationToken));
        Assert.Equal(0,queries);
        var reader=new EventRelationsReader(Query,(id,ct)=>Task.FromResult(id!=8));
        var page=await reader.ReadAsync(42,1,null,TimeSpan.FromSeconds(5),TestContext.Current.CancellationToken);
        Assert.Equal(7,page["items"]![0]!["related_event_db_id"]!.GetValue<long>());
        Assert.Null(page["next_cursor"]); Assert.DoesNotContain("hidden",page.ToJsonString());
    }
    [Theory] [InlineData("")] [InlineData("bad")]
    public void Malformed_cursor_fails_closed(string token) => Assert.Throws<InvalidDataException>(()=>EventRelationCursor.Decode(42,token));    [Fact] public async Task Bundled_normalizer_resolves_frozen_dc_family_and_rejects_unknown_bundle()
    {
        var repo=new DirectoryInfo(AppContext.BaseDirectory);
        while(repo is not null && !Directory.Exists(Path.Combine(repo.FullName,"config","source_packs"))) repo=repo.Parent;
        Assert.NotNull(repo);
        var adapter=new KnownBundleNormalizer(repo.FullName,null,null);
        var row=new JsonObject { ["channel"]="Security",["provider_name"]="Microsoft-Windows-Security-Auditing",["event_id"]=4625 };
        var family=await adapter.ResolveAsync(row,TestContext.Current.CancellationToken);
        Assert.Equal(new[]{100,102,106,129,140,200,201,324},family);
        var unknown=new KnownBundleNormalizer(Path.Combine(Path.GetTempPath(),"missing-"+Guid.NewGuid().ToString("N")),null,null);
        var error=await Assert.ThrowsAsync<InvalidOperationException>(()=>unknown.ResolveAsync(row,TestContext.Current.CancellationToken));
        Assert.Equal("source_normalizer_bundle_unsupported",error.Message);
    }}

