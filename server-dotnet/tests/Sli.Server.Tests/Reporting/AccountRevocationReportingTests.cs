using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Ad;
using Sli.Server.Auth;
using Sli.Server.Reporting.V2;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Reporting;

// Behavioral vectors from tests/reporting/test_account_revocation_reporting.py.
public sealed class AccountRevocationReportingTests
{
    static IConfiguration Legacy => new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:Storage:ShortEventReads"]="false" }).Build();
    const string Sid = "S-1-5-21-100000001-200000002-300000003-1001";
    static readonly DateTimeOffset Start = DateTimeOffset.Parse("2026-10-01T00:00:00Z");
    static ReportDefinition Definition => new ReportDefinitionRegistry().Get("security.events.chains")!;
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static JsonObject Event(long id, int code, int minute, string? field = null, JsonNode? value = null)
    {
        var row = new JsonObject {
            ["event_db_id"] = id, ["domain_id"] = 7, ["event_id"] = code,
            ["time_created_utc"] = Start.AddMinutes(minute).ToString("O"),
            ["target_user_sid"] = Sid, ["subject_user_sid"] = Sid,
            ["target_user_name"] = "account-a", ["subject_user_name"] = "account-a",
            ["normalized_event_id"] = id.ToString(), ["processing_status"] = "normalized",
            ["semantic_type"] = code switch { 4725 => "directory.account.disabled", 4726 => "directory.account.deleted", 4722 => "directory.account.enabled", 4624 => "authentication.session.created", 6272 => "remote_access.authentication.allowed", _ => throw new ArgumentOutOfRangeException(nameof(code)) },
            ["source"] = "source-a", ["logon_type"] = "3"
        };
        if (field is not null) row[field] = value;
        return row;
    }
    static JsonObject Session(string id = "session-a", string? field = null, JsonNode? value = null)
    {
        var row = new JsonObject { ["session_row_id"] = id, ["domain_id"] = 7, ["target_user_sid"] = Sid,
            ["started_at_utc"] = Start.AddMinutes(-10).ToString("O"), ["last_observed_at_utc"] = Start.AddMinutes(20).ToString("O"),
            ["stopped_at_utc"] = null, ["completeness"] = "missing_stop" };
        if (field is not null) row[field] = value;
        return row;
    }
    static JsonObject[] Shape(IEnumerable<JsonObject> events, IEnumerable<JsonObject>? sessions = null,
        string? account = null, string? source = null, string? kind = null, int delay = 0, bool exact = false, bool truncated = false)
        => SecurityObservationReader.Revocations(events, sessions ?? [], Start, Start.AddHours(1), 60, account, source, kind, delay, exact, truncated);
    static string? Text(JsonNode row, string key) => row[key]?.ToString();
    static void Evidence(JsonObject row, string expected) => Assert.True(JsonNode.DeepEquals(JsonNode.Parse(expected), row["evidence"]), row.ToJsonString());

    [Fact]
    public void DisableDeleteAuthenticationReenableAndDuplicateEvidenceMatchReference()
    {
        var rows = Shape([Event(1,4725,0), Event(2,4624,1), Event(3,6272,5), Event(4,4722,3), Event(5,4726,10), Event(6,4624,12), Event(2,4624,1)]);
        Assert.Equal(new[] { "logon", "nps_allow", "logon" }, rows.Select(r => Text(r,"activity_type")));
        Assert.Equal(new[] { 4725,4725,4726 }, rows.Select(r => r["disable_code"]!.GetValue<int>()));
        Evidence(rows[0],"[1,2,4]"); Evidence(rows[1],"[1,3,4]");
        Assert.Equal("after_activity", Text(rows[0],"reenable_relation")); Assert.Equal("before_activity", Text(rows[1],"reenable_relation"));
        Assert.Equal(60, rows[0]["delay_seconds"]!.GetValue<double>()); Assert.Equal("uncertain", Text(rows[0],"clock_quality"));
        Assert.Null(rows[2]["reenabled_at"]); Assert.Equal("not_observed",Text(rows[2],"reenable_relation"));
        Assert.All(rows,r => { Assert.Equal("candidate",Text(r,"qualification")); Assert.Equal("exact_sid",Text(r,"quality")); });
        Assert.Equal(3, rows.Select(r => Text(r,"candidate_key")).Distinct().Count());
    }
    [Fact]
    public void NpsUsesSubjectSidAndNeverTargetNameOrAnotherDomain()
    {
        var row = Assert.Single(Shape([Event(1,4725,0), Event(2,6272,5,"target_user_sid",Sid+"9"), Event(3,6272,6,"subject_user_sid",Sid+"9"), Event(4,4624,7,"target_user_sid",Sid+"9"), Event(5,4624,8,"domain_id",8)]));
        Assert.Equal(2, row["activity_event"]!.GetValue<long>());
    }
    [Theory]
    [InlineData(null)] [InlineData("-")] [InlineData("S-1-0-0")] [InlineData("S-1-5-21-invalid")] [InlineData("invalid")]
    public void UnknownIdentitiesRemainSeparateWithoutNameCorrelation(string? sid)
    {
        var events = new[] { Event(1,4725,0,"target_user_sid",sid), Event(2,4726,5,"target_user_sid",sid), Event(3,4624,6,"target_user_sid",sid), Event(4,6272,7,"subject_user_sid",sid) };
        var rows = Shape(events);
        Assert.Equal(4,rows.Length); Assert.Equal(4,rows.Select(r=>Text(r,"candidate_key")).Distinct().Count());
        Assert.All(rows,r=> { Assert.Equal("unknown_sid",Text(r,"quality")); Assert.Equal("insufficient",Text(r,"activity_type")); Assert.Single(r["evidence"]!.AsArray()); });
        Assert.Empty(Shape(events,exact:true));
        // An unusable SID must not acquire a reenable link either.
        Assert.Null(Shape([Event(1,4725,0,"target_user_sid",sid),Event(2,4722,1,"target_user_sid",sid)])[0]["reenable_event"]);
    }
    [Fact]
    public void StrictWindowUsesLatestEarlierDisableAndSameTimeReenable()
    {
        var rows = Shape([Event(1,4725,-1),Event(2,4725,0),Event(3,4624,0),Event(4,4624,60),Event(5,4726,10),Event(6,4624,11),Event(7,4725,60),Event(8,4624,70)]);
        Assert.Equal(new[] { (5L,6L),(5L,4L) },rows.Select(r=>(r["disable_event"]!.GetValue<long>(),r["activity_event"]!.GetValue<long>())));
        Assert.Empty(Shape([Event(1,4725,0),Event(2,4624,60)]));
        Assert.Equal("same_time",Text(Assert.Single(Shape([Event(1,4725,0),Event(2,4722,5),Event(3,4624,5)])),"reenable_relation"));
    }
    [Theory]
    [InlineData("processing_status","ignored")] [InlineData("processing_status",null)] [InlineData("semantic_type","unknown")]
    public void MissingOrIgnoredCurrentSemanticsNeverCorrelate(string field, string? value)
    {
        Assert.Equal("insufficient",Text(Assert.Single(Shape([Event(1,4725,0,field,value),Event(2,4624,1)])),"activity_type"));
        var row = Assert.Single(Shape([Event(1,4725,0),Event(2,4624,1,field,value)]));
        Assert.Null(row["disable_event"]); Assert.Equal("partial",Text(row,"quality"));
    }
    [Fact]
    public void AccountingRequiresObservedSpanAndPreservesStringIdsAndDistinctSessions()
    {
        var rows = Shape([Event(1,4725,0),Event(2,4624,5)], [Session(),Session(),Session("new","started_at_utc",Start.AddMinutes(1).ToString("O")),Session("missing-start","started_at_utc",null),Session("stopped","stopped_at_utc",Start.ToString("O")),Session("other","target_user_sid",Sid+"9"),Session("different-domain","domain_id",8)]);
        Assert.Equal(new[] { "logon","vpn_continuation" },rows.Select(r=>Text(r,"activity_type")));
        var row = rows[1]; Assert.Null(row["activity_event"]); Evidence(row,"[1,\"session-a\"]");
        Assert.Equal("2026-09-30T23:50:00Z",Text(row,"session_started_at")); Assert.Equal("missing_stop",Text(row,"session_completeness")); Assert.Equal("RADIUS Accounting",Text(row,"source"));
        Assert.Empty(Shape([Event(1,4725,0)],[Session(field:"last_observed_at_utc",value:Start.ToString("O"))]));
        rows = Shape([Event(1,4725,0)],[Session(),Session("second")]);
        Assert.Equal(2,rows.Length); Assert.Equal(2,rows.Select(r=>Text(r,"candidate_key")).Distinct().Count()); Evidence(rows[1],"[1,\"second\"]");
    }
    [Theory]
    [InlineData("account","ACCOUNT-A",1)] [InlineData("account","s-1-5-21-100000001-200000002-300000003-1001",1)] [InlineData("account","other",0)]
    [InlineData("source","SOURCE-A",1)] [InlineData("source","other",0)] [InlineData("kind","logon",1)] [InlineData("kind","nps_allow",0)]
    [InlineData("delay","301",0)] [InlineData("delay","300",1)] [InlineData("exact","true",1)]
    public void FiltersApplyToCandidateRows(string filter, string value, int expected)
    {
        Assert.Equal(expected,Shape([Event(1,4725,0),Event(2,4624,5)],account:filter=="account"?value:null,source:filter=="source"?value:null,kind:filter=="kind"?value:null,delay:filter=="delay"?int.Parse(value):0,exact:filter=="exact").Length);
    }
    [Fact]
    public void TruncationKeepsExactIdentityButMarksQualityPartial()
    {
        var row = Assert.Single(Shape([Event(1,4725,0),Event(2,4624,5)],exact:true,truncated:true));
        Assert.Equal("partial",Text(row,"quality")); Assert.Equal(Sid.ToLowerInvariant(),Text(row,"sid"));
    }

    static AccessFacts Facts(int domain = 7, bool assigned = true, bool capability = true, bool allFields = true)
    {
        string[] fields = allFields ? ["security","technical","raw_evidence"] : ["security"];
        JsonElement J(object o) => JsonSerializer.SerializeToElement(o);
        var scope = new { kind = "domain", ids = new[] { domain } };
        return new(false,"viewer",[],[], (capability ? new[] { "events.view" } : []).Concat(["evidence.exact"]).Concat(fields.Select(f=>"field."+f)).Select(c=>J(new { capability_key=c,effect="allow",scope_json=scope })).ToArray(),[],[],
            assigned ? [J(new { report_key=Definition.AccessKey,effect="allow",allowed_actions=new[]{"view"},field_categories=fields,scope_json=scope })] : [],
            [J(new { report_key=Definition.AccessKey,version=1,dataset_version=1,actions_json=new[]{"view","export"},fields_json=new[]{"security","technical","raw_evidence"}.Select(f=>new{category=f}),definition_json=new{actions=new[]{"view","export"}} })]);
    }
    static ReportQueryContext Context(AccessFacts? facts = null)
    {
        facts ??= Facts(); var access = new ReportEligibility().Compose(facts,new CapabilityComposer().Compose(facts));
        return new(Definition,access,new Principal("session",7,"viewer"),new JsonObject { ["domain"]=7,["period"]=new JsonObject { ["from_utc"]=Start.ToString("O"),["to_utc"]=Start.AddHours(1).ToString("O") } },new(null,100,"UTC",null,"asc","account-revocation"),ReportScope.None,null,"view",_=>true,[]);
    }
    sealed class Database : ISemanticDatabase, ISemanticSession
    {
        public JsonArray Anchors = [], Enables = [], Activity = [], Sessions = [];
        public readonly List<(string Sql,object?[] Args)> Calls = [];
        public int Opens; public bool Installed = true, Relation = true; public string? AccountingError;
        public Task<ISemanticSession> OpenAsync(bool write,CancellationToken ct) { Assert.False(write); Opens++; return Task.FromResult<ISemanticSession>(this); }
        public Task<JsonArray> QueryAsync(string sql,CancellationToken ct,params object?[] values)
        {
            Calls.Add((sql,values));
            Assert.DoesNotContain("statement_timeout",sql);
            if (sql.Contains("with short_events")) return Task.FromResult(new JsonArray((((int[])values[1]!)[0] switch {4725=>Anchors,4722=>Enables,4624=>Activity,_=>throw new InvalidOperationException()}).Select(e=>(JsonNode?)ReportingShortEventFixture.Stored(e!)).ToArray()));
            if (sql.Contains("read_plugin_states")) return Task.FromResult(new JsonArray(new JsonObject { ["installed"]=Installed }));
            if (sql.Contains("to_regclass")) return Task.FromResult(new JsonArray(new JsonObject { ["relation"]=Relation?"radius_vpn_session_rows_v1":null }));
            if (sql.Contains("session.*,alias")) { if(AccountingError is not null) throw new PostgresException("synthetic","ERROR","ERROR",AccountingError); return Task.FromResult((JsonArray)Sessions.DeepClone()); }
            Assert.Contains("savepoint revocation_accounting",sql);
            return Task.FromResult(new JsonArray());
        }
        public Task CommitAsync(CancellationToken ct) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    static Task<JsonObject> Read(Database db,ReportQueryContext? c = null) => new SecurityObservationReader(db, Legacy).Read(c??Context(),Ct);
    static JsonArray Rows(JsonObject raw) => raw["collections"]!["account_revocation"]!.AsArray();
    static Database Sample() => new() { Anchors=[Event(1,4725,0)], Enables=[Event(4,4722,3)], Activity=[Event(2,4624,1)], Sessions=[Session()] };

    [Theory] [InlineData("assignment")] [InlineData("domain")] [InlineData("capability")] [InlineData("fields")]
    public async Task DeniesBeforeOpeningDatabase(string reason)
    {
        var db = new Database(); var facts = Facts(domain:reason=="domain"?8:7,assigned:reason!="assignment",capability:reason!="capability",allFields:reason!="fields");
        Assert.Equal("denied",Text(await Read(db,Context(facts)),"state")); Assert.Equal(0,db.Opens);
    }
    [Theory]
    [InlineData("empty-period")] [InlineData("wide-period")] [InlineData("follow-high")] [InlineData("follow-zero")]
    [InlineData("negative-delay")] [InlineData("limit")] [InlineData("domain")] [InlineData("activity")] [InlineData("action")]
    public async Task InvalidBoundsAreRejectedBeforeOpeningDatabase(string vector)
    {
        var c = Context(); var db = new Database();
        switch(vector) {
            case "empty-period": c.Params["period"]!["to_utc"]=Start.ToString("O"); break;
            case "wide-period": c.Params["period"]!["to_utc"]=Start.AddDays(32).ToString("O"); break;
            case "follow-high": c.Params["revocation_window"]=1441; break;
            case "follow-zero": c.Params["revocation_window"]=0; break;
            case "negative-delay": c.Params["minimum_delay"]=-1; break;
            case "limit": c=c with { Paging=c.Paging with { Limit=501 } }; break;
            case "domain": c.Params["domain"]=0; break;
            case "activity": c.Params["activity_type"]="unknown"; break;
            case "action": c=c with { Action="delete" }; break;
        }
        // Domain selection is checked by the public parser before delegated authorization.
        if(vector=="domain") {
            Assert.Throws<ReportRequestException>(()=>ReportParameters.Parse(Definition,Query("domain","0")));
        } else await Assert.ThrowsAsync<ReportRequestException>(()=>Read(db,c));
        Assert.Equal(0,db.Opens);
    }
    [Fact]
    public async Task ServiceReadsNewFactsWithIndependentWindowsAndIgnoresAccounting()
    {
        var db = Sample(); var raw = await Read(db);
        var row = Assert.Single(Rows(raw)); Assert.Equal("logon",Text(row!,"activity_type"));
        Assert.Equal(2,row!["activity_event"]!.GetValue<long>());
        Assert.Equal(new[]{1,0,0,0},raw["metrics"]!.AsArray().Select(m=>m!["value"]!.GetValue<int>()));
        Assert.Equal("not_checked",Text(raw["coverage"]!,"accounting_state"));
        Assert.Equal(3,db.Calls.Count);
        Assert.Equal(new[]{4725,4726},(int[])db.Calls[0].Args[1]!);
        Assert.Equal(new[]{4722},(int[])db.Calls[1].Args[1]!);
        Assert.Equal(new[]{4624,6272},(int[])db.Calls[2].Args[1]!);
        Assert.Equal(Start.AddHours(1),db.Calls[0].Args[3]); Assert.Equal(Start.AddHours(25),db.Calls[2].Args[3]);
        Assert.All(db.Calls,call=> { Assert.Equal(7L,call.Args[0]); Assert.Equal(10001,call.Args[5]); });
    }
    [Theory] [InlineData("42P01")] [InlineData("42703")] [InlineData("42501")]
    public async Task OptionalAccountingFailuresDoNotAffectNewEventReads(string sqlState)
    {
        var db = new Database { Anchors=[Event(1,4725,0)],Activity=[Event(2,4624,1)],AccountingError=sqlState };
        var raw = await Read(db); Assert.Equal("logon",Text(Assert.Single(Rows(raw))!,"activity_type"));
        Assert.Equal("not_checked",Text(raw["coverage"]!,"accounting_state"));
        Assert.Equal(3,db.Calls.Count);
        Assert.DoesNotContain(db.Calls,call=>call.Sql.Contains("savepoint",StringComparison.Ordinal));
    }
    [Fact]
    public async Task EmptyAndMissingAccountingNeverClaimAbsence()
    {
        foreach (var db in new[]{new Database(),new Database { Anchors=[Event(1,4725,0)],Relation=false },new Database { Anchors=[Event(1,4725,0)],Installed=false }}) {
            var raw=await Read(db); Assert.Equal("partial",Text(raw,"state"));
            Assert.Equal("not_checked",Text(raw["coverage"]!,"accounting_state"));
            Assert.Equal("not_proven",Text(raw["coverage"]!,"completeness"));
        }
    }
    [Fact]
    public async Task SourceAndOutputTruncationRemainExplicit()
    {
        var db = new Database { Anchors=new JsonArray(Enumerable.Range(0,10001).Select(_=>(JsonNode)Event(1,4725,0)).ToArray()),Activity=[Event(2,4624,5)] };
        var raw = await Read(db); Assert.True(raw["coverage"]!["source_truncated"]!.GetValue<bool>()); Assert.Equal("partial",Text(Assert.Single(Rows(raw))!,"quality"));
        db=new Database { Anchors=[Event(1,4725,0),Event(2,4726,1)],Activity=new JsonArray(Enumerable.Range(3,10000).Select(i=>(JsonNode)Event(i,4624,5)).ToArray()) };
        raw=await Read(db); Assert.True(raw["coverage"]!["rows_truncated"]!.GetValue<bool>()); Assert.False(raw["coverage"]!["source_truncated"]!.GetValue<bool>()); Assert.Equal(10000,raw["filtered_count"]!.GetValue<int>());
    }
    static QueryCollection Query(params string[] pairs) => new(pairs.Chunk(2).ToDictionary(p=>p[0],p=>new StringValues(p[1])));
    sealed class Store : IAdReportStore
    {
        public Task<IReadOnlyList<long>> DomainsAsync(long after,CancellationToken ct) => Task.FromResult<IReadOnlyList<long>>([]);
        public Task<bool> HasSourceAsync(string kind,long domain,CancellationToken ct) => throw new InvalidOperationException("main query");
        public Task<JsonObject> ReadAsync(AdReportRequest request,bool sensitive,CancellationToken ct) => throw new InvalidOperationException("main query");
    }
    [Fact]
    public async Task Internal_revocation_preserves_defaults_and_denial_while_hidden_tab_is_rejected()
    {
        var (parameters,paging)=ReportParameters.Parse(Definition,Query("domain","7","period","custom","from",Start.ToString("O"),"to",Start.AddHours(1).ToString("O")),Start);
        Assert.Equal("1440",Text(parameters,"revocation_window")); Assert.Null(parameters["minimum_delay"]);
        var db = new Database { Anchors=[Event(1,4725,0)],Activity=[Event(2,4624,5)] };
        var reader = new SecurityEventsReader(new Store(),db,null!,Legacy);
        var c=Context() with { Params=parameters,Paging=paging with { Tab = "account-revocation" } };
        var raw=await reader.QueryAsync(c,Ct);
        Assert.Equal(Definition.Key,Text(raw,"report_key")); Assert.Empty(raw["items"]!.AsArray()); Assert.Equal("candidate",Text(Assert.Single(Rows(raw))!,"qualification"));
        Assert.Equal(4,raw["metrics"]!.AsArray().Count); Assert.Equal(4,raw["limitations"]!.AsArray().Count);
        Assert.Equal("delegated",Text(Definition.Declaration["access_rule"]!,"scope"));
        raw=await reader.QueryAsync(Context(Facts(assigned:false)),Ct); Assert.Equal("denied",Text(raw,"state")); Assert.Equal(1,db.Opens);
        await using var host=await ReportFixture.Start(Facts(),Definition,nativeReader:reader);
        using var response=await host.Client.GetAsync("/api/v2/reports/security.events.chains/data?domain=7&tab=account-revocation&period=custom&from=2026-10-01T00:00:00Z&to=2026-10-01T01:00:00Z",Ct);
        Assert.Equal(HttpStatusCode.BadRequest,response.StatusCode); Assert.Equal("report_tab_invalid",Text(await ReportFixture.Body(response),"error")); Assert.Equal(1,db.Opens);
    }
}
