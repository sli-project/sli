using System.ComponentModel;
using System.Text.Json.Nodes;
using Sli.Server.Sources;
using Sli.Server.Infrastructure;
using Npgsql;
using Microsoft.Extensions.Configuration;
using Sli.Server.Legacy;
using Xunit;

namespace Sli.Server.Tests.Sources;

// Offline vectors from tests/sources/test_collection_dpapi_auth.py.
public sealed class CollectionDpapiAuthTests
{
    private const string Password = "synthetic-only-password!", Sid = "S-1-5-21-100000001-200000002-300000003-1000";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private sealed class Session : IEventLogSession { public bool Closed; public void Dispose() => Closed=true; }
    private sealed class EventLog : IWindowsEventLog
    {
        internal readonly List<EventLogLogin> Logins=[];
        internal readonly List<string> Operations=[];
        internal readonly List<Session> Sessions=[];
        internal Exception? OpenError;
        internal string? FailedStage;
        internal int FailedCode=1326, Probes, Queries;
        internal bool Empty;
        internal IReadOnlyList<string> Rows=[];
        internal Action? OnRead;
        public IEventLogSession Open(EventLogLogin login) {
            Logins.Add(login);Operations.Add("open");
            if(OpenError is not null)throw OpenError;
            var session=new Session();Sessions.Add(session);return session;
        }
        public EventLogState Probe(IEventLogSession? session,string channel) {
            Probes++;Operations.Add("probe:"+channel);
            if(FailedStage=="cursor_probe" || FailedStage=="post_probe" && Probes==2)throw new Win32Exception(FailedCode,"TEST\\Collector "+Password);
            return new(Empty?null:2,Empty?null:1,"synthetic-generation");
        }
        public IReadOnlyList<string> Read(IEventLogSession? session,string channel,string xpath,Action? heartbeat,CancellationToken ct) {
            Queries++;Operations.Add("query:"+channel);Assert.Equal("*",xpath);OnRead?.Invoke();heartbeat?.Invoke();
            if(FailedStage=="query")throw new Win32Exception(FailedCode,Password);
            return Rows;
        }
    }
    private sealed class Blocks : ICollectionBlockStore
    {
        internal string? Active;
        internal readonly List<string> Operations=[];
        internal int Activations, Clears;
        internal bool ActivationFails;
        public Task<string?> ActiveAsync(CancellationToken ct) { Operations.Add("active");return Task.FromResult(Active); }
        public Task ActivateAsync(CollectionFailure failure,string server,string worker,CancellationToken ct) {
            Assert.True(failure.Blocked);Assert.Equal("DC1",server);Assert.Equal("offline-worker",worker);
            Assert.DoesNotContain(Password,failure.ToString());
            Operations.Add("activate");Activations++;
            if(ActivationFails)throw new IOException("synthetic-durability-failure");
            Active=failure.Code;return Task.CompletedTask;
        }
        public Task ClearAsync(string server,string actor,CancellationToken ct) {
            Assert.Equal("DC1",server);Operations.Add("clear");Clears++;Active=null;return Task.CompletedTask;
        }
    }
    private sealed class Fixture
    {
        internal readonly EventLog Events=new();
        internal readonly Blocks Blocks=new();
        internal readonly Dictionary<string,string?> Env=new() {
            ["ADLOG_COLLECTION_PRINCIPAL"]="TEST\\Owner",["ADLOG_COLLECTION_PRINCIPAL_SID"]=Sid
        };
        internal IReadOnlyList<AdSourceTarget> Targets=[new("DC1","dc1.example.test")];
        internal CollectionIdentity Identity=new("TEST\\Owner",Sid,7);
        internal string Resolved="dc1.example.test",Username="TEST\\Collector";
        internal Exception? StoreError;
        internal readonly List<string> Profiles=[];
        internal AdSourceAuth Auth() => new(()=>Targets,_=>Resolved,profile=> {
            Profiles.Add(profile);if(StoreError is not null)throw StoreError;return new(Username,Password);
        },Events,Env.GetValueOrDefault);
        internal WindowsCollection Collection() => new(Auth(),Events,Blocks,()=>Identity,Env.GetValueOrDefault);
    }
    private static void Safe(string text) {
        Assert.DoesNotContain(Password,text);Assert.DoesNotContain("TEST\\Collector",text);
        Assert.DoesNotContain("TEST\\\\Collector",text);
        Assert.DoesNotContain("synthetic-private-store-path",text);Assert.DoesNotContain("invalid-private-value",text);
    }

    [Theory]
    [InlineData("MiXeD\\Collector","Collector","MiXeD")]
    [InlineData("Collector@MiXeD.example.test","Collector@MiXeD.example.test",null)]
    public void ExplicitDpapiPreservesExactNativeLogin(string username,string user,string? domain)
    {
        var f=new Fixture {Username=username};using var session=f.Auth().Open("DC1",AdSourceAuth.Dpapi);
        var login=Assert.Single(f.Events.Logins);Assert.Equal("dc1.example.test",login.Server);
        Assert.Equal(user,login.User);Assert.Equal(domain,login.Domain);Assert.Equal(Password,login.Password);Assert.Equal(0,login.Flags);
        Assert.Equal(["ad"],f.Profiles);Safe(login.ToString());Safe(new AdSourceLogin(username,Password).ToString());
    }
    [Fact]
    public void SharedHelperIgnoresAdModeEnvironmentAndDoesNotLoadStore()
    {
        var f=new Fixture();f.Env[AdSourceAuth.ModeKey]=AdSourceAuth.Dpapi;
        using var session=f.Auth().Open("radius01.example.test");
        var login=Assert.Single(f.Events.Logins);Assert.Equal("radius01.example.test",login.Server);
        Assert.Null(login.User);Assert.Null(login.Domain);Assert.Null(login.Password);Assert.Empty(f.Profiles);
    }
    [Fact]
    public void EventLogVpnProfileDoesNotChangeAdStoreDefault()
    {
        var f=new Fixture {Username="EventReader@example.test"};f.Env[AdSourceAuth.ProfileKey]="vpn";
        using var session=f.Auth().Open("DC1",AdSourceAuth.Dpapi);
        Assert.Equal(["vpn"],f.Profiles);var login=Assert.Single(f.Events.Logins);
        Assert.Equal("EventReader@example.test",login.User);Assert.Null(login.Domain);
        Assert.Equal(Password,login.Password);
        f.Env.Remove(AdSourceAuth.ProfileKey);using var next=f.Auth().Open("DC1",AdSourceAuth.Dpapi);
        Assert.Equal(["vpn","ad"],f.Profiles);
    }
    [Fact]
    public void UnknownProfileBlocksBeforeStoreAndRpc()
    {
        var f=new Fixture();f.Env[AdSourceAuth.ProfileKey]="unexpected";
        var e=Assert.Throws<CollectionSourceException>(()=>f.Auth().Open("DC1",AdSourceAuth.Dpapi));
        Assert.Equal("ad_source_credential_profile_invalid",e.Message);Assert.True(CollectionFailurePolicy.Classify(e).Blocked);
        Assert.Empty(f.Profiles);Assert.Empty(f.Events.Logins);
    }
    [Theory]
    [InlineData("radius01.example.test")][InlineData("dc1.attacker.test")]
    [InlineData("127.0.0.1")][InlineData("localhost")][InlineData("")]
    public void DpapiRequiresExactlyConfiguredEndpointBeforeSecretOrRpc(string target)
    {
        var f=new Fixture();var e=Assert.Throws<CollectionSourceException>(()=>f.Auth().Open(target,AdSourceAuth.Dpapi));
        Assert.Equal("ad_source_endpoint_invalid",e.Code);Assert.Empty(f.Profiles);Assert.Empty(f.Events.Logins);
    }
    [Theory][InlineData("dns")][InlineData("ambiguous")][InlineData("connect_address")]
    public void EndpointAdmissionRejectsChangedReadbackAndAmbiguity(string failure)
    {
        var f=new Fixture();
        if(failure=="dns")f.Resolved="dc1.attacker.test";
        if(failure=="ambiguous")f.Targets=[new("DC1","dc1.example.test"),new("DC1","dc2.example.test")];
        var e=Assert.Throws<CollectionSourceException>(()=>f.Auth().ConfiguredEndpoint("DC1",failure=="connect_address"?"dc2.example.test":null));
        Assert.Equal("ad_source_endpoint_invalid",e.Code);Assert.Empty(f.Profiles);Assert.Empty(f.Events.Logins);
    }
    [Fact]
    public void UnreadableStoreIsSanitizedWithoutInnerExceptionOrRpc()
    {
        var f=new Fixture {StoreError=new IOException("synthetic-private-store-path "+Password)};
        var e=Assert.Throws<CollectionSourceException>(()=>f.Auth().Open("DC1",AdSourceAuth.Dpapi));
        Assert.Equal("ad_source_credentials_unavailable",e.Message);Assert.Null(e.InnerException);Safe(e.ToString());Assert.Empty(f.Events.Logins);
    }
    [Theory]
    [InlineData(1317)][InlineData(1326)][InlineData(1327)][InlineData(1328)][InlineData(1329)]
    [InlineData(1330)][InlineData(1331)][InlineData(1385)][InlineData(1793)][InlineData(1907)][InlineData(1909)]
    public void TerminalNativeAndWireCodesRequireOperator(int code)
    {
        object[] errors=[new Win32Exception(code,"synthetic localized error"),$"winerror {code}",$"({code}, 'EvtOpenSession', 'synthetic localized error')",
            new System.Runtime.InteropServices.COMException("synthetic localized error",unchecked((int)0x80070000)|code)];
        foreach(var error in errors) {
            var decision=CollectionFailurePolicy.Classify(error);Assert.True(decision.Blocked);
            Assert.Equal("windows_event_log_authentication_failed",decision.Code);Assert.Equal("source_authentication",decision.Phase);
            var fields=decision.Fields();Assert.False(fields["retryable"]!.GetValue<bool>());
            Assert.Equal("operator_recovery_required",fields["retry_policy"]!.GetValue<string>());
            Assert.Equal("blocked_pre_import",fields["pipeline_disposition"]!.GetValue<string>());
        }
        Assert.True(CollectionFailurePolicy.Classify("windows_event_log_authentication_failed").Blocked);
    }
    [Fact]
    public void NativeAuthErrorNeverExposesAccountOrPassword()
    {
        var f=new Fixture();f.Events.OpenError=new Win32Exception(1326,"TEST\\Collector "+Password);
        var e=Assert.Throws<CollectionSourceException>(()=>f.Auth().Open("DC1",AdSourceAuth.Dpapi));
        Assert.Equal(1326,e.WinError);Assert.Null(e.InnerException);Safe(e.ToString());Assert.True(CollectionFailurePolicy.Classify(e).Blocked);
    }
    [Theory][InlineData(AdSourceAuth.Process)][InlineData(AdSourceAuth.Dpapi)]
    public async Task WorkerPreflightUsesCanonicalFqdnAndLocalIdentity(string mode)
    {
        var f=new Fixture();f.Env[AdSourceAuth.ModeKey]=mode;
        var result=await f.Collection().PreflightAsync("DC1","offline-worker",Ct);
        Assert.Equal("ok",result["status"]!.GetValue<string>());var login=Assert.Single(f.Events.Logins);
        Assert.Equal("dc1.example.test",login.Server);Assert.Equal(mode==AdSourceAuth.Dpapi?"Collector":null,login.User);
        Assert.Equal(["open","probe:Security"],f.Events.Operations);Assert.True(Assert.Single(f.Events.Sessions).Closed);
        Assert.Equal(0,f.Blocks.Activations);
    }
    [Theory][InlineData("store")][InlineData("1326")][InlineData("mode")][InlineData("powershell")]
    public async Task FailureBlocksJobsAndRestartCannotReauthenticate(string failure)
    {
        var f=new Fixture();f.Env[AdSourceAuth.ModeKey]=failure=="mode"?"invalid-private-value":AdSourceAuth.Dpapi;
        f.Env["ADLOG_COLLECTOR_BACKEND"]=failure=="powershell"?"powershell":"python";
        if(failure=="store")f.StoreError=new IOException(Password);
        f.Events.OpenError=new Win32Exception(1326,Password);
        var result=await f.Collection().PreflightAsync("DC1","offline-worker",Ct);
        Assert.Equal("failed",result["status"]!.GetValue<string>());Assert.Equal(1,f.Blocks.Activations);Safe(result.ToJsonString());
        int loads=f.Profiles.Count,rpc=f.Events.Logins.Count;
        // A new instance models a restarted worker against the same durable state.
        var repeated=await f.Collection().PreflightAsync("DC1","offline-worker",Ct);
        Assert.Equal("failed",repeated["status"]!.GetValue<string>());
        var cycle=await f.Collection().RunCycleAsync("DC1","offline-worker",_=>throw new InvalidOperationException("unexpected job creation"),Ct);
        Assert.Equal("blocked",cycle["status"]!.GetValue<string>());Assert.Equal(loads,f.Profiles.Count);Assert.Equal(rpc,f.Events.Logins.Count);
        Assert.Equal(1,f.Blocks.Activations);
        if(failure is "mode" or "powershell") {Assert.Empty(f.Profiles);Assert.Empty(f.Events.Logins);}
    }
    [Fact]
    public async Task TerminalFailureStopsChannelsAndOtherDcsAndQuarantinesBeforeImport()
    {
        var f=new Fixture();f.Events.OpenError=new Win32Exception(1326,Password);
        var result=await f.Collection().CollectAsync(["DC1","DC2"],["Security","System"],AdSourceAuth.Dpapi,"offline-worker",
            (_,_,_)=>throw new InvalidOperationException("unexpected import"),null,Ct);
        Assert.Equal(74,result["exit_code"]!.GetValue<int>());Assert.Single(f.Events.Logins);Assert.Equal(1,f.Blocks.Activations);
        var batch=Assert.Single(result["batches"]!.AsArray())!.AsObject();
        Assert.Equal("not_attempted",batch["channels"]![1]!["status"]!.GetValue<string>());
        Assert.False(batch["cursor_advanced"]!.GetValue<bool>());Assert.True(batch["terminal_block"]!.GetValue<bool>());
        Assert.False(batch["import_allowed"]!.GetValue<bool>());Assert.False(batch["import_attempted"]!.GetValue<bool>());Safe(result.ToJsonString());
        string directory=Path.Combine(Path.GetTempPath(),"sli-dpapi-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(directory);
        try {
            await WindowsCollection.WriteBlockMarkerAsync(directory,batch,Ct);
            string marker=await File.ReadAllTextAsync(Path.Combine(directory,"collection-blocked.json"),Ct);Safe(marker);
            Assert.False(JsonNode.Parse(marker)!["import_attempted"]!.GetValue<bool>());
        }
        finally {Directory.Delete(directory,true);}
    }
    [Fact]
    public async Task QueryFailureAfterEarlierEventsBlocksWholeBatchBeforeImport()
    {
        var f=new Fixture();f.Events.Rows=["<Event />"];f.Events.OnRead=()=>f.Events.FailedStage=f.Events.Queries==2?"query":null;
        var result=await f.Collection().CollectAsync(["DC1","DC2"],["System","Security","Application"],AdSourceAuth.Dpapi,"offline-worker",
            (_,_,_)=>throw new InvalidOperationException("unexpected import"),null,Ct);
        Assert.Equal("blocked",result["status"]!.GetValue<string>());Assert.Equal(2,f.Events.Queries);
        Assert.Equal("windows_event_log_authentication_failed",f.Blocks.Active);Safe(result.ToJsonString());
        Assert.Equal(1,result["batches"]![0]!["channels"]![0]!["count"]!.GetValue<int>());
    }
    [Fact]
    public async Task DurabilityFailureCannotContinueOrImport()
    {
        var f=new Fixture();f.Events.OpenError=new Win32Exception(1326,Password);f.Blocks.ActivationFails=true;
        await Assert.ThrowsAsync<IOException>(()=>f.Collection().CollectAsync(["DC1","DC2"],["Security"],AdSourceAuth.Dpapi,"offline-worker",
            (_,_,_)=>throw new InvalidOperationException("unexpected import"),null,Ct));
        Assert.Single(f.Events.Logins);
    }
    [Theory]
    [InlineData("cursor_probe",5)][InlineData("query",5)][InlineData("post_probe",5)]
    [InlineData("cursor_probe",1326)][InlineData("query",1326)][InlineData("post_probe",1326)]
    public void QueryAuthFailureNeverFallsBackOrProbesAgain(string stage,int code)
    {
        var f=new Fixture();f.Events.FailedStage=stage;f.Events.FailedCode=code;
        var result=f.Collection().CollectChannel("DC1","Security",AdSourceAuth.Dpapi,"*",null,Ct);
        Assert.False(result["retryable"]!.GetValue<bool>());Assert.False(result["cursor_commit_allowed"]!.GetValue<bool>());
        Safe(result.ToJsonString());Assert.Equal(stage=="post_probe"?2:1,f.Events.Probes);Assert.Equal(stage=="cursor_probe"?0:1,f.Events.Queries);
        Assert.True(Assert.Single(f.Events.Sessions).Closed);Assert.Single(f.Profiles);Assert.Single(f.Events.Logins);
        Assert.Equal(code==5?"windows_event_log_access_denied":"windows_event_log_authentication_failed",result["failure_code"]!.GetValue<string>());
    }
    [Theory][InlineData(null)][InlineData("invalid-private-value")][InlineData(AdSourceAuth.Dpapi)]
    public async Task ExplicitRecoveryRequiresValidModeAndUsesSameIdentityAndReverseProbe(string? mode)
    {
        var f=new Fixture();f.Blocks.Active="ad_source_credentials_unavailable";
        var result=await f.Collection().RecoverAsync("DC1",mode,"operator",Ct);Safe(result.ToJsonString());
        Assert.Equal(mode==AdSourceAuth.Dpapi?"ok":"failed",result["status"]!.GetValue<string>());
        if(mode==AdSourceAuth.Dpapi) {
            Assert.Equal(1,f.Blocks.Clears);var login=Assert.Single(f.Events.Logins);
            Assert.Equal("dc1.example.test",login.Server);Assert.Equal("Collector",login.User);Assert.Equal("TEST",login.Domain);
            Assert.Equal(["open","probe:Security"],f.Events.Operations);Assert.True(Assert.Single(f.Events.Sessions).Closed);
        }
        else {Assert.Empty(f.Events.Logins);Assert.Empty(f.Profiles);Assert.Equal(0,f.Blocks.Clears);}
    }
    [Theory][InlineData(0)][InlineData(7)]
    public async Task UnicodeLocalIdentityRetainsSessionGuard(int session)
    {
        var f=new Fixture();const string principal="ТЕСТ-ПК\\оператор";
        f.Identity=new(principal,Sid,session);f.Env["ADLOG_COLLECTION_PRINCIPAL"]=principal;
        var result=await f.Collection().PreflightAsync("DC1","offline-worker",Ct);
        Assert.Equal(principal,f.Identity.Principal);Assert.Equal(Sid,f.Identity.Sid);Assert.Equal(session!=0,f.Identity.Interactive);
        Assert.Equal(session==0?"failed":"ok",result["status"]!.GetValue<string>());
        if(session==0) {Assert.Empty(f.Profiles);Assert.Empty(f.Events.Logins);Assert.Equal(1,f.Blocks.Activations);}
    }
    [Theory][InlineData("process","powershell",null)][InlineData(AdSourceAuth.Dpapi,"auto",null)]
    [InlineData(AdSourceAuth.Dpapi,"python",null)][InlineData(AdSourceAuth.Dpapi,"powershell","ad_source_backend_unsupported")]
    [InlineData("invalid-private-value","python","ad_source_credential_mode_invalid")]
    public void ClosedModeAndBackendContractNeverEchoesInput(string mode,string backend,string? code)
    {
        if(code is null)Assert.Equal(mode,AdSourceAuth.ValidateMode(mode,backend));
        else {var e=Assert.Throws<CollectionSourceException>(()=>AdSourceAuth.ValidateMode(mode,backend));Assert.Equal(code,e.Code);Safe(e.ToString());}
    }
    [Theory][InlineData("invalid-private-value")][InlineData(AdSourceAuth.Dpapi)]
    public async Task RecoveryCommandPassesOnlyModeAndNeverEchoesInvalidValue(string mode)
    {
        var f=new Fixture();f.Blocks.Active="ad_source_credentials_unavailable";int created=0;var output=new StringWriter();
        int exit=await CollectionBlockCommand.RunCoreAsync(["--probe-server","DC1","--confirm",CollectionBlockCommand.Confirmation,"--ad-source-credential-mode",mode],
            _=> {created++;return Task.FromResult(f.Collection());},output,Ct);
        Assert.Equal(mode==AdSourceAuth.Dpapi?0:2,exit);Assert.Equal(mode==AdSourceAuth.Dpapi?1:0,created);Safe(output.ToString());
    }
    [Fact]
    public async Task RecoveryRequiresConfirmationAndDoesNotPrintParserInput()
    {
        foreach(string[] args in new[] {new[]{"--probe-server","DC1","--confirm","invalid-private-value"},new[]{"--unknown","invalid-private-value"}}) {
            var output=new StringWriter();
            int exit=await CollectionBlockCommand.RunCoreAsync(args,_=>throw new InvalidOperationException("unexpected runtime"),output,Ct);
            Assert.Equal(2,exit);Safe(output.ToString());
        }
    }
    [Fact]
    public async Task SuccessfulEmptyProbeStillProvesQueryAccessAndDisposesSession()
    {
        var f=new Fixture();f.Events.Empty=true;
        var result=await f.Collection().PreflightAsync("DC1","offline-worker",Ct);
        Assert.Equal("ok",result["status"]!.GetValue<string>());Assert.False(result["event_observed"]!.GetValue<bool>());
        Assert.Equal("verified",result["query_access"]!.GetValue<string>());Assert.True(Assert.Single(f.Events.Sessions).Closed);
    }
    [Fact]
    public async Task CompletedChannelsAreImportedOnlyAfterPostProbeAndReportHeartbeat()
    {
        var f=new Fixture();f.Events.Rows=["<Event />"];int imported=0,beats=0;
        var result=await f.Collection().CollectAsync(["DC1"],["Security"],AdSourceAuth.Dpapi,"offline-worker",(server,batch,_)=> {
            Assert.Equal("DC1",server);Assert.Equal(2,f.Events.Probes);Assert.Equal(1,f.Events.Queries);
            Assert.Equal(1,batch["channels"]![0]!["count"]!.GetValue<int>());
            Assert.True(Assert.Single(f.Events.Sessions).Closed);Assert.Equal(0,f.Blocks.Activations);
            imported++;return Task.CompletedTask;
        },()=>beats++,Ct);
        Assert.Equal("ok",result["status"]!.GetValue<string>());Assert.Equal(1,imported);Assert.Equal(1,beats);
    }
    [Fact]
    public async Task NonterminalReadFailureNeverClaimsSuccessOrImportsIncompleteBatch()
    {
        var f=new Fixture();f.Events.FailedStage="query";f.Events.FailedCode=1722;
        var result=await f.Collection().CollectAsync(["DC1"],["Security"],AdSourceAuth.Dpapi,"offline-worker",
            (_,_,_)=>throw new InvalidOperationException("unexpected import"),null,Ct);
        Assert.Equal("failed",result["status"]!.GetValue<string>());Assert.Equal(0,f.Blocks.Activations);
        Assert.False(result["batches"]![0]!["import_allowed"]!.GetValue<bool>());Safe(result.ToJsonString());
    }
    private sealed class Connections(string dsn) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct) {
            var db=new NpgsqlConnection(dsn);await db.OpenAsync(ct);return db;
        }
    }
    private sealed class ForbiddenConnections : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => throw new Xunit.Sdk.XunitException("unexpected database access");
    }
    [Fact]
    public async Task RuntimeCannotBypassLegacyCutoverViaRecovery()
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["Sli:Legacy:SLI_LEGACY_COLLECTION_DISABLED"]="1"
        }).Build();
        var error=await Assert.ThrowsAsync<InvalidOperationException>(()=>CollectionRuntime.CreateAsync(new ForbiddenConnections(),new LegacySettings(config),Ct));
        Assert.Equal("legacy_collection_disabled",error.Message);
    }
    [Fact]
    public async Task PostgresBlockSurvivesNewRuntimeAndExplicitProbeClearsOnlyAfterSuccess()
    {
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(Ct);
        var factory=new Connections(fixture.Dsn("adlog_user"));
        var first=new PostgresCollectionBlocks(factory);
        Assert.Null(await first.ActiveAsync(Ct));
        var failure=CollectionFailurePolicy.Classify("windows_event_log_authentication_failed");
        await first.ActivateAsync(failure,"DC1","offline-worker",Ct);
        var restarted=new PostgresCollectionBlocks(factory);
        Assert.Equal(failure.Code,await restarted.ActiveAsync(Ct));
        await restarted.ActivateAsync(failure,"DC1","offline-worker",Ct);
        await using(var db=await factory.OpenAsync(Ct)) {
            await using var read=new NpgsqlCommand("select observed_count,retry_policy,evidence_json::text from runtime_collection_blocks where singleton_id=1",db);
            await using var row=await read.ExecuteReaderAsync(Ct);Assert.True(await row.ReadAsync(Ct));
            Assert.Equal(2,row.GetInt64(0));Assert.Equal("operator_recovery_required",row.GetString(1));Safe(row.GetString(2));
            var evidence=JsonNode.Parse(row.GetString(2))!.AsObject();
            Assert.Equal(3,evidence.Count);Assert.Equal("dotnet",evidence["collector_backend"]!.GetValue<string>());
        }
        var f=new Fixture();f.Events.OpenError=new Win32Exception(1326,Password);
        WindowsCollection Runtime()=>new(f.Auth(),f.Events,restarted,()=>f.Identity,f.Env.GetValueOrDefault);
        var result=await Runtime().RecoverAsync("DC1",AdSourceAuth.Dpapi,"operator",Ct);
        Assert.Equal("failed",result["status"]!.GetValue<string>());Assert.Equal(failure.Code,await restarted.ActiveAsync(Ct));
        f.Events.OpenError=null;
        result=await Runtime().RecoverAsync("DC1",AdSourceAuth.Dpapi,"operator",Ct);
        Assert.Equal("ok",result["status"]!.GetValue<string>());Assert.Null(await restarted.ActiveAsync(Ct));
        await using(var db=await factory.OpenAsync(Ct)) {
            await using var read=new NpgsqlCommand("select active,last_probe_result,cleared_by,evidence_json->>'successful_probe_server' from runtime_collection_blocks where singleton_id=1",db);
            await using var row=await read.ExecuteReaderAsync(Ct);Assert.True(await row.ReadAsync(Ct));
            Assert.False(row.GetBoolean(0));Assert.Equal("success",row.GetString(1));Assert.Equal("operator",row.GetString(2));Assert.Equal("DC1",row.GetString(3));
        }
        await fixture.AssertNoSqlErrorsAsync(Ct);
    }
}
