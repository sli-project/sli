using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Investigations;
using Xunit;

namespace Sli.Server.Tests.Investigations;

public sealed class InvestigationCaseMutationTests
{
    private sealed class Transaction : IInvestigationCaseTransaction
    {
        public JsonObject Row = JsonNode.Parse("""{"id":1,"status":"new","owner":"alice"}""")!.AsObject();
        public JsonObject? Pending; public int Writes, Commits; public bool FailAudit;
        public Task<JsonObject> ReadAsync(InvestigationIdentity identity, CancellationToken ct) => Task.FromResult((JsonObject)(Pending ?? Row).DeepClone());
        public Task WriteAsync(long id, InvestigationCaseMutationInput input, string? old, string actor, CancellationToken ct)
        {
            Writes++; Pending = (JsonObject)Row.DeepClone(); Pending[input.Operation] = input.Value;
            if (FailAudit) throw new InvalidOperationException("audit failure");
            return Task.CompletedTask;
        }
        public Task CommitAsync(CancellationToken ct) { Commits++; if (Pending is not null) Row = Pending; return Task.CompletedTask; }
    }
    static InvestigationCaseMutationInput Input(string op,string json) => InvestigationCaseMutationInput.Parse(op, JsonDocument.Parse(json).RootElement);
    [Theory]
    [InlineData("new","active",true)] [InlineData("new","review",false)] [InlineData("active","confirmed",true)]
    [InlineData("review","active",true)] [InlineData("confirmed","review",false)] [InlineData("closed","active",true)]
    [InlineData("closed","closed",true)] [InlineData("closed","new",false)]
    public async Task TransitionAndNoopStateMatchesFrozenSource(string initial,string target,bool allowed)
    {
        var tx=new Transaction();tx.Row["status"]=initial;
        var input=Input("status", "{\"status\":\""+target+"\"}");
        if (!allowed)
        {
            var ex=await Assert.ThrowsAsync<InvestigationException>(()=>InvestigationCaseMutation.ExecuteAsync(tx,new(1,null),input,"analyst",TestContext.Current.CancellationToken));
            Assert.Equal("conflict",ex.Code); Assert.Equal(0,tx.Writes); Assert.Equal(0,tx.Commits); return;
        }
        var result=await InvestigationCaseMutation.ExecuteAsync(tx,new(1,null),input,"analyst",TestContext.Current.CancellationToken);
        Assert.Equal(target,result.Case["status"]!.GetValue<string>()); Assert.Equal(initial==target,result.Replay);
        Assert.Equal(initial==target?0:1,tx.Writes); Assert.Equal(1,tx.Commits);
    }
    [Fact]
    public async Task AuditFailureNeverCommitsTheChangedOwner()
    {
        var tx=new Transaction{FailAudit=true};
        await Assert.ThrowsAsync<InvalidOperationException>(()=>InvestigationCaseMutation.ExecuteAsync(tx,new(1,null),Input("owner","{\"owner\":\"bob\"}"),"analyst",TestContext.Current.CancellationToken));
        Assert.Equal("alice",tx.Row["owner"]!.GetValue<string>());Assert.Equal(0,tx.Commits);
    }
    [Theory]
    [InlineData("{}", null)] [InlineData("{\"owner\":false}", null)] [InlineData("{\"owner\":\"  Alice  \"}", "Alice")]
    [InlineData("{\"owner\":42}", "42")] [InlineData("{\"owner\":[1,true]}", "[1, True]")]
    public void OwnerUsesPythonTruthAndStringRules(string json,string? expected) => Assert.Equal(expected,Input("owner",json).Value);
    [Fact]
    public void InvalidStatusFailsBeforeAnyDatabaseMutation()
    {
        var error=Assert.Throws<InvestigationException>(()=>Input("status","{\"status\":\"unknown\"}"));
        Assert.Equal("invalid_status",error.Code);
    }
    private sealed class Visibility : IInvestigationVpnEvidence
    {
        public bool Allowed(AccessDecision access,long domainId)=>domainId==1;
    }
    [Fact]
    public void ResponseHidesOnlyUnauthorizedTypedEvidenceAndHasFullShape()
    {
        var row=JsonNode.Parse("""{"id":4,"public_id":null,"title":"T","status":"active","owner":null,"created_by":"a","created_at":"2026-01-01T00:00:00+00:00","updated_at":"2026-01-01T00:00:00+00:00","closed_at":null,"events":[{"event_db_id":2,"added_at":"2026-01-01T07:00:00+07:00"}],"notes":[],"evidence_refs":[{"source_domain_id":1,"reference_id":"a"},{"source_domain_id":2,"reference_id":"b"}]}""")!.AsObject();
        var result=InvestigationCaseRenderer.Render(new(row,false),null!,new Visibility());
        Assert.Equal("partially_authorized",result["evidence_refs_state"]!.GetValue<string>());
        Assert.Single(result["evidence_refs"]!.AsArray());Assert.Equal("a",result["evidence_refs"]![0]!["reference_id"]!.GetValue<string>());
        Assert.Equal("INV-0000004",result["case_number"]!.GetValue<string>());Assert.Equal("v1",result["api_version"]!.GetValue<string>());
        Assert.Equal("2026-01-01T00:00:00Z",result["created_at"]!.GetValue<string>());Assert.Equal("2026-01-01T07:00:00+07:00",result["events"]![0]!["added_at"]!.GetValue<string>());Assert.Empty(result["audit"]!.AsArray()); Assert.True(result.ContainsKey("evidence_page_size")); Assert.Null(result["evidence_page_size"]); Assert.Null(result["events_total"]); Assert.Null(result["events_next_cursor"]); Assert.Null(result["evidence_refs_total"]); Assert.Null(result["evidence_refs_next_cursor"]); Assert.Null(result["anchor_event"]);
    }
    [Fact]
    public void CaseResponseHasShortNumberAndKeepsUuidForInternalIdentity()
    {
        var row=JsonNode.Parse("""{"id":1,"public_id":"00000000-0000-0000-0000-000000000101","title":"Synthetic","status":"open","created_by":"synthetic","created_at":"2026-10-01T00:00:00Z","updated_at":"2026-10-01T00:00:00Z","events":[],"notes":[],"evidence_refs":[]}""")!.AsObject();
        var result=InvestigationCaseRenderer.Render(new(row,false),null!,new Visibility());
        var serialized=JsonNode.Parse(result.ToJsonString())!;
        Assert.Equal("INV-0000001",serialized["case_number"]!.GetValue<string>());
        Assert.Equal("00000000-0000-0000-0000-000000000101",serialized["public_id"]!.GetValue<string>());
    }
    [Fact]
    public void DetailResponseKeepsAuditHistory()
    {
        var row=JsonNode.Parse("""{"id":4,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","events":[],"notes":[],"evidence_refs":[],"audit":[{"id":3,"created_at":"2026-01-01T00:00:00Z"}]}""")!.AsObject();
        var result=InvestigationCaseRenderer.Render(new(row,false),null!,new Visibility());
        Assert.Single(result["audit"]!.AsArray());
    }
    [Fact]
    public void DetailPageRendererPreservesPageMetadata()
    {
        var row=JsonNode.Parse("""{"id":4,"events":[],"notes":[],"evidence_refs":[],"audit":[],"evidence_page_size":100,"events_total":201,"events_next_cursor":101,"evidence_refs_total":0,"evidence_refs_next_cursor":null,"anchor_event":{"event_db_id":2,"added_at":"2026-01-01T00:00:00+00:00"}}""")!.AsObject();
        var result=InvestigationCaseRenderer.Render(new(row,false),null!,new Visibility());
        Assert.Equal(100,result["evidence_page_size"]!.GetValue<int>());
        Assert.Equal(201,result["events_total"]!.GetValue<int>());
        Assert.Equal(2,result["anchor_event"]!["event_db_id"]!.GetValue<int>());
        Assert.Equal("2026-01-01T00:00:00Z",result["anchor_event"]!["added_at"]!.GetValue<string>());
    }
    [Fact]
    public void PageRendererRetainsPartiallyAuthorizedStateAfterSqlFiltering()
    {
        var row=JsonNode.Parse("""{"id":4,"events":[],"notes":[],"evidence_refs":[],"audit":[],"evidence_page_size":100,"evidence_refs_state":"partially_authorized"}""")!.AsObject();
        var result=InvestigationCaseRenderer.Render(new(row,false),null!,new Visibility());
        Assert.Equal("partially_authorized",result["evidence_refs_state"]!.GetValue<string>());
    }
    [Fact]
    public async Task AllStatusTransitionsMatchExecutedFrozenPython()
    {
        var assembly=typeof(InvestigationCaseMutationTests).Assembly;
        using var stream=assembly.GetManifestResourceStream("Sli.Server.Tests.Investigations.Fixtures.mutation-source-vectors.json")!;
        using var document=await JsonDocument.ParseAsync(stream,cancellationToken:TestContext.Current.CancellationToken);
        Assert.Equal(25,document.RootElement.GetArrayLength());
        foreach(var vector in document.RootElement.EnumerateArray())
        {
            string old=vector.GetProperty("old").GetString()!, target=vector.GetProperty("target").GetString()!;
            var tx=new Transaction(); tx.Row["status"]=old;
            var input=Input("status","{\"status\":\""+target+"\"}");
            if(vector.GetProperty("status").GetString()=="conflict")
            {
                var error=await Assert.ThrowsAsync<InvestigationException>(()=>InvestigationCaseMutation.ExecuteAsync(tx,new(1,null),input,"a",TestContext.Current.CancellationToken));
                Assert.Equal(vector.GetProperty("message").GetString(),error.Message);Assert.Equal(0,tx.Commits);
            }
            else
            {
                var result=await InvestigationCaseMutation.ExecuteAsync(tx,new(1,null),input,"a",TestContext.Current.CancellationToken);
                Assert.Equal(vector.GetProperty("replay").GetBoolean(),result.Replay);
                Assert.Equal(vector.GetProperty("commands").GetArrayLength()==0?0:1,tx.Writes);
                Assert.Equal(target,result.Case["status"]!.GetValue<string>());
            }
        }
    }
    [Fact]
    public async Task OwnerNoopAndChangedOwnerHaveExpectedCommitBehavior()
    {
        var tx=new Transaction();
        var replay=await InvestigationCaseMutation.ExecuteAsync(tx,new(1,null),Input("owner","{\"owner\":\"alice\"}"),"a",TestContext.Current.CancellationToken);
        Assert.True(replay.Replay);Assert.Equal(0,tx.Writes);Assert.Equal(1,tx.Commits);
        var changed=await InvestigationCaseMutation.ExecuteAsync(tx,new(1,null),Input("owner","{\"owner\":\" bob \"}"),"a",TestContext.Current.CancellationToken);
        Assert.False(changed.Replay);Assert.Equal("bob",tx.Row["owner"]!.GetValue<string>());Assert.Equal(1,tx.Writes);
    }
    private sealed class Env : Microsoft.Extensions.Hosting.IHostEnvironment
    {
        public string EnvironmentName {get;set;}="Testing";
        public string ApplicationName {get;set;}="Sli.Server.Tests";
        public string ContentRootPath {get;set;}=Directory.GetCurrentDirectory();
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider {get;set;}=new Microsoft.Extensions.FileProviders.NullFileProvider();
    }
    [Fact]
    public void BundledVpnEvidenceRequiresBothReportAndCapabilityForDomain()
    {
        static JsonElement J(string s)=>JsonDocument.Parse(s).RootElement.Clone();
        static AccessDecision Access(bool cap,bool report)
        {
            var facts=new AccessFacts(false,"viewer",[],[],
                cap?[J("""{"capability_key":"vpn.session.evidence.read","effect":"allow","scope_json":{"kind":"domain","ids":[1]}}""")]:[],[],[],
                report?[J("""{"report_key":"vpn.audit","effect":"allow","allowed_actions":["view"],"field_categories":[],"scope_json":{"kind":"domain","ids":[1]}}""")]:[],
                [J("""{"report_key":"vpn.audit","version":1,"dataset_version":1,"definition_json":{"actions":["view"]},"actions_json":["view"],"fields_json":[]}""")]);
            var caps=new CapabilityComposer().Compose(facts);return new ReportEligibility().Compose(facts,caps);
        }
        var hook=new InvestigationVpnEvidence(new Env());
        Assert.True(hook.Allowed(Access(true,true),1));
        Assert.False(hook.Allowed(Access(true,true),2));
        Assert.False(hook.Allowed(Access(false,true),1));
        Assert.False(hook.Allowed(Access(true,false),1));
    }
    [Fact]
    public void ActiveExternalGenerationCannotUseBundledHook()
    {
        string root=Path.Combine(Path.GetTempPath(),"sli-investigation-"+Guid.NewGuid().ToString("N"));
        string plugin=Path.Combine(root,"sli.remote-access"), pointer=Path.Combine(plugin,"active.json");
        Directory.CreateDirectory(plugin);
        try
        {
            File.WriteAllText(pointer,"{}");
            var error=Assert.Throws<InvalidOperationException>(()=>Sli.Server.Agents.Control.AgentAssignmentPluginAdmission.Enter("sli.remote-access",root,null));
            Assert.Equal("plugin_generation_unavailable",error.Message);
        }
        finally { File.Delete(pointer);Directory.Delete(plugin);Directory.Delete(root); }
    }
}
