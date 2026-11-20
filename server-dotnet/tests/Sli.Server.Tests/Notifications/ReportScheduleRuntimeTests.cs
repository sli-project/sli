using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Notifications;
using Xunit;
namespace Sli.Server.Tests.Notifications;
public class ReportScheduleRuntimeTests
{
    static JsonElement J(string s)=>JsonDocument.Parse(s).RootElement.Clone();
    static AccessDecision Access(bool export=true,bool identity=true,string scope="{\"kind\":\"all\"}")
    {
        var caps=new CapabilityDecisionSet(false,new HashSet<string>{"reports.export"},new HashSet<string>(),[],new Dictionary<string,JsonElement>());
        return new("viewer",caps,[new("security.queue",true,[new(J(scope),identity?new HashSet<string>{"security","identity_basic"}:new HashSet<string>{"security"},export?new HashSet<string>{"view","export"}:new HashSet<string>{"view"},1,1)])]);
    }
    [Fact] public void SelectionWithholdsCountIfAnyParticipantLostExport()
    {var selection=ReportScheduleProjection.Select("security.problems",1,new Dictionary<long,AccessDecision>{{1,Access()},{2,Access(false)}},[2],J("""{"report_key":"security.problems","quality":"partial","counts":{"individual":{"total":3,"has_more":false},"cohorts":{"total":2,"has_more":false}},"roots":[]}"""));Assert.False(selection["include_count"]!.GetValue<bool>());Assert.Equal("cohorts",selection["variant"]!.GetValue<string>());}
    [Fact] public void SelectionCannotUnionScopedGrantsIntoGlobalAuthority()
    {var selection=ReportScheduleProjection.Select("security.problems",1,new Dictionary<long,AccessDecision>{{1,Access(scope:"{\"kind\":\"domain\",\"ids\":[1]}")}},[],J("""{"report_key":"security.problems","quality":"error","counts":{},"roots":[]}"""));Assert.Equal("denied",selection["owner_state"]!.GetValue<string>());Assert.False(selection["include_count"]!.GetValue<bool>());}
    [Fact] public void IndividualVariantDoesNotDiscloseIdentityCohorts()
    {var selection=ReportScheduleProjection.Select("security.problems",1,new Dictionary<long,AccessDecision>{{1,Access(identity:false)}},[],J("""{"report_key":"security.problems","quality":"empty","counts":{"individual":{"total":0,"has_more":false},"cohorts":{"total":0,"has_more":false}},"roots":[]}"""));Assert.Equal("individual",selection["variant"]!.GetValue<string>());Assert.True(selection["include_count"]!.GetValue<bool>());}
    [Fact] public void DigestContainsMetadataAndEncodedBoundedFiltersOnly()
    {
        var run=J("""{"id":"00000000-0000-4000-8000-000000000001","report_key":"security.problems","filters":{"severity":"high","q":"private-data"},"timezone":"UTC","period_from":"2026-11-01T00:00:00Z","period_to":"2026-11-02T00:00:00Z","generated_at":"2026-11-02T00:00:05Z","language":"en","quality":"partial","item_count":null,"truncated":true,"delayed":false}""");
        var job=new NotificationJob(Guid.NewGuid(),Guid.NewGuid(),1,"report_schedule",run.GetProperty("id").GetGuid(),7,1,Guid.NewGuid(),DateTime.UtcNow,null,"live",0){ReportRun=run};
        string text=NotificationMessage.Format(job,"https://sli.invalid",null,null);Assert.Contains("Count: unavailable",text);Assert.Contains("severity=high",text);Assert.Contains("time_from=",text);Assert.DoesNotContain("private-data",text);Assert.Contains("Security problems",text);
    }
    [Fact] public void BothWorkersClaimReportsWithChannelIsolation()
    {Assert.Contains("'report_schedule'",SmtpWorker.ClaimSql);Assert.Contains("channel='smtp'",SmtpWorker.ClaimSql);Assert.Contains("'report_schedule'",TelegramWorker.ClaimSql);Assert.Contains("channel='telegram'",TelegramWorker.ClaimSql);}
    [Fact] public void NativeDeliveryUsesDatabaseFairnessAcrossChannels()
    {Assert.Contains("public.notification_claim_fair()",NotificationDeliveryWorker.ClaimSql);Assert.DoesNotContain("where channel",NotificationDeliveryWorker.ClaimSql);}
    [Fact] public void RetryBudgetAlwaysReachesTerminalFailure()
    {Assert.Equal("failed",SmtpWorker.Completion("retry",5,0).State);Assert.Equal("failed",TelegramWorker.Completion("retry",5,0).State);Assert.Equal("delivery_unknown",SmtpOutcome.State("smtp_outcome_unknown"));}
    [Fact] public void RunListingExcludesCount()
    {Assert.DoesNotContain("item_count",ReportScheduleRepository.RunFields);}

    static (NotificationJob,JsonObject) Delivery(bool count=true)
    {
        var job=new NotificationJob(Guid.NewGuid(),Guid.NewGuid(),3,"report_schedule",Guid.NewGuid(),8,1,Guid.NewGuid(),DateTime.UtcNow,null,"live",0){Channel="smtp"};
        var payload=new JsonObject{["owner_user_id"]=7,["channel_revision"]=5,["selection"]=new JsonObject{["variant"]="cohorts"},["root_scope"]=new JsonArray(),
            ["subscription"]=new JsonObject{["id"]=job.Subscription.ToString(),["owner_user_id"]=7,["recipient_user_id"]=8,["revision"]=3,["channel"]="smtp",["enabled"]=true},
            ["run"]=new JsonObject{["id"]=job.ObjectId.ToString(),["report_key"]="security.problems",["item_count"]=count?1:null}};
        return(job,payload);
    }
    [Theory,InlineData(0),InlineData(7),InlineData(8),InlineData(9)]
    public async Task DispatchRechecksOwnerRecipientExportAndIdentity(int revoked)
    {
        var(job,payload)=Delivery();var reads=new List<long>();
        Task<AccessDecision?> Load(long id){reads.Add(id);return Task.FromResult<AccessDecision?>(Access(export:id!=revoked,identity:!(id==7 && revoked==9)));}
        if(revoked==0) {var prepared=await ReportScheduleDelivery.AuthorizeAsync(job,J(payload.ToJsonString()),Load);Assert.Equal(5,prepared.ReportChannelRevision);Assert.NotNull(prepared.ReportRun);Assert.Equal(new long[]{7,8},reads);}
        else await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>ReportScheduleDelivery.AuthorizeAsync(job,J(payload.ToJsonString()),Load));
    }
    [Fact] public async Task CountlessDispatchRequiresViewButNotExport()
    {
        var(job,payload)=Delivery(false);await ReportScheduleDelivery.AuthorizeAsync(job,J(payload.ToJsonString()),_=>Task.FromResult<AccessDecision?>(Access(false)));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>ReportScheduleDelivery.AuthorizeAsync(job,J(payload.ToJsonString()),id=>Task.FromResult<AccessDecision?>(id==8?null:Access())));
    }
    [Theory,InlineData("run"),InlineData("recipient"),InlineData("revision"),InlineData("channel"),InlineData("enabled"),InlineData("owner")]
    public async Task DispatchRejectsChangedJobBinding(string field)
    {
        var(job,payload)=Delivery();
        if(field=="run")payload["run"]!["id"]=Guid.NewGuid().ToString();
        else if(field=="recipient")payload["subscription"]!["recipient_user_id"]=99;
        else if(field=="revision")payload["subscription"]!["revision"]=4;
        else if(field=="channel")payload["subscription"]!["channel"]="telegram";
        else if(field=="enabled")payload["subscription"]!["enabled"]=false;
        else payload["owner_user_id"]=99;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>ReportScheduleDelivery.AuthorizeAsync(job,J(payload.ToJsonString()),_=>throw new InvalidOperationException("must reject before ACL reads")));
    }
    static JsonObject Actor(long id)
    {
        var fact=new JsonObject();foreach(var key in new[]{"is_owner","groups","role_packages","subject_packages","owner_packages","package_capabilities","direct_capabilities","all_capabilities","package_reports","report_assignments","definitions"})fact[key]=new JsonArray();
        fact["is_owner"]=new JsonArray(new JsonObject{["is_owner"]=true});
        fact["definitions"]=JsonNode.Parse("""[{"report_key":"security.queue","version":1,"dataset_version":1,"definition_json":{"actions":["view","export"]},"actions_json":["view","export"],"fields_json":[{"category":"security"},{"category":"identity_basic"}]}]""");
        return new JsonObject{["subject"]=new JsonObject{["type"]="session",["id"]=id,["role"]="admin",["is_active"]=true},["facts"]=fact};
    }
    sealed class Backend:IReportProducerBackend
    {
        public string Mode="ok";public List<string> Calls=[];public JsonObject? Selection;
        public Task<Guid?> LeadAsync(Guid? leader,CancellationToken ct){Calls.Add("lead");return Task.FromResult<Guid?>(Mode=="standby"?null:Guid.NewGuid());}
        public Task<IReadOnlyList<ReportScheduleClaim>> ClaimAsync(Guid leader,CancellationToken ct)
        {Calls.Add("claim");var now=DateTimeOffset.Parse("2026-11-02T10:00:00Z");var schedule=JsonNode.Parse(ReportScheduleTests.Body)!.AsObject();schedule["created_at"]="2026-11-01T00:00:00Z";schedule["owner_user_id"]=7;schedule["revision"]=1;return Task.FromResult<IReadOnlyList<ReportScheduleClaim>>([new(Guid.NewGuid(),Guid.NewGuid(),J(schedule.ToJsonString()),now,DateTimeOffset.Parse(Mode=="calendar"?"2026-11-02T08:00:00Z":"2026-11-02T09:00:00Z"),DateTimeOffset.Parse("2026-11-01T09:00:00Z"))]);}
        public Task<JsonElement> FactsAsync(ReportScheduleClaim c,CancellationToken ct)
        {Calls.Add("facts");return Task.FromResult(J(new JsonObject{["report_key"]="security.problems",["schedule_revision"]=1,["owner_user_id"]=7,["evaluated_at"]="2026-11-02T10:00:00Z",["actors"]=new JsonArray(Actor(7),Actor(8)),["bindings"]=new JsonArray(new JsonObject{["recipient_user_id"]=8}),["dependencies"]=new JsonObject()}.ToJsonString()));}
        public Task<JsonElement> CandidatesAsync(ReportScheduleClaim c,CancellationToken ct)
        {Calls.Add("candidates");return Task.FromResult(J("""{"report_key":"security.problems","quality":"partial","counts":{"individual":{"total":3,"has_more":false},"cohorts":{"total":2,"has_more":false}},"roots":[]}"""));}
        public Task FailureAsync(ReportScheduleClaim c,CancellationToken ct){Calls.Add("failure");return Task.CompletedTask;}
        public Task<bool> PublishAsync(ReportScheduleClaim c,JsonObject selection,CancellationToken ct)
        {Calls.Add("publish");Selection=selection;if(Mode=="capacity")throw new Npgsql.PostgresException("synthetic","ERROR","ERROR","P7001");return Task.FromResult(Mode!="duplicate");}
    }
    [Theory,InlineData("ok","ok",1),InlineData("duplicate","ok",0),InlineData("capacity","backpressure",0),InlineData("calendar","failed",0),InlineData("standby","standby",0)]
    public async Task ProducerUsesFencedPipelineAndHandlesTerminalCycleStates(string mode,string state,int published)
    {
        var backend=new Backend{Mode=mode};var result=await new ReportScheduleProducer(backend).TickAsync(null,TestContext.Current.CancellationToken);Assert.Equal(state,result.State);Assert.Equal(published,result.Published);
        if(mode is "ok" or "duplicate" or "capacity"){Assert.Equal(new[]{"lead","claim","facts","candidates","publish"},backend.Calls);Assert.True(backend.Selection!["include_count"]!.GetValue<bool>());}
        else Assert.DoesNotContain("publish",backend.Calls);
    }
    [Fact] public void ProducerConfigurationNeverFallsBackToApiOrDeliveryCredentials()
    {
        var env=new Dictionary<string,string>{{"ADLOG_PG_DSN","Host=database.invalid;Database=sli;Username=api"},{"ADLOG_PG_PASSWORD","synthetic"}};
        Assert.False(ReportProducerCommand.Configuration(env.GetValueOrDefault,_=>throw new InvalidOperationException(),out _));
        env["SLI_REPORT_PRODUCER_PG_DSN"]="Host=database.invalid;Database=sli;Username=producer";env["SLI_REPORT_PRODUCER_PG_PASSWORD_FILE"]=Path.GetFullPath("synthetic-password");
        Assert.True(ReportProducerCommand.Configuration(env.GetValueOrDefault,_=>System.Text.Encoding.UTF8.GetBytes("synthetic"),out string? dsn));Assert.Contains("Username=producer",dsn);Assert.DoesNotContain("Username=api",dsn);
        env["SLI_REPORT_PRODUCER_PG_PASSWORD"]="synthetic";Assert.False(ReportProducerCommand.Configuration(env.GetValueOrDefault,_=>throw new InvalidOperationException(),out _));
    }
    [Theory,InlineData("ok",true),InlineData("standby",true),InlineData("backpressure",true),InlineData("failed",false),InlineData("stopped",false)]
    public void ProducerHealthRequiresFreshSuccessfulCycle(string state,bool healthy)
    {var now=DateTimeOffset.Parse("2026-11-02T10:00:00Z");var row=new JsonObject{["pid"]=1,["at"]=now.ToUnixTimeSeconds(),["state"]=state};Assert.Equal(healthy,ReportProducerCommand.Healthy(J(row.ToJsonString()),now));Assert.False(ReportProducerCommand.Healthy(J(row.ToJsonString()),now.AddSeconds(91)));}
    static AccessDecision FileAccess(bool export=true,bool rootDeny=false)
    {
        var policies=rootDeny?new[]{new CapabilityPolicy("file-audit.export","deny",true,false,J("""{"mode":"restricted","clauses":[{"plugin_ids":["sli.file-audit"],"source_instance_ids":["host1"],"collection_scope_ids":["scope1"]}]}"""))}:Array.Empty<CapabilityPolicy>();
        var caps=new CapabilityDecisionSet(false,export?new HashSet<string>{"file-audit.view","file-audit.export","reports.export"}:new HashSet<string>{"file-audit.view"},new HashSet<string>(),policies,new Dictionary<string,JsonElement>());
        return new("viewer",caps,[new("file-audit.mass-operations",true,[new(J("""{"kind":"all"}"""),new HashSet<string>{"identity_basic","technical","security","privilege"},export?new HashSet<string>{"view","export"}:new HashSet<string>{"view"},1,1)])]);
    }
    [Theory,InlineData(false,true),InlineData(true,false)]
    public void FileProjectionPreservesRootCapabilityDenials(bool deny,bool include)
    {
        var actors=new Dictionary<long,AccessDecision>{{7,FileAccess()},{8,FileAccess(rootDeny:deny)}};
        var candidate=J("""{"report_key":"file-audit.mass-operations","quality":"partial","counts":{},"root_limit":false,"roots":[{"agent_id":"agent1","source_instance_id":"host1","collection_scope_id":"scope1","source_kind":"server"}]}""");
        var selection=ReportScheduleProjection.Select("file-audit.mass-operations",7,actors,[8],candidate,Access());Assert.Equal(include,selection["include_count"]!.GetValue<bool>());Assert.Equal(0,selection["root_indexes"]![0]!.GetValue<int>());Assert.Equal(0,selection["qw_root_indexes"]![0]!.GetValue<int>());
    }
    [Fact] public void FileExportRequiresIndependentCapability()
    {Assert.True(ReportScheduleAccess.Report(FileAccess(false),"file-audit.mass-operations"));Assert.False(ReportScheduleAccess.Report(FileAccess(false),"file-audit.mass-operations","export"));}
}
