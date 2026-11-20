using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;
using B = Sli.Server.Semantic.SemanticInvestigationBackfill;

namespace Sli.Server.Tests.Semantic;

public sealed partial class SemanticInvestigationBackfillTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static string H(char c) => new(c,64);
    private const string Sid="S-1-5-21-100000001-200000002-300000003-400";
    private static JsonObject Identity()=>new() { ["host"]="local",["database"]="sli",["role"]="owner" };
    private static JsonObject Cohort(long high,long count,string digest,long? min,long? max)=>new() { ["high_watermark"]=high,["count"]=count,["cohort_digest"]=digest,["min_id"]=min,["max_id"]=max };
    private static JsonObject Cohorts()=>new() { ["4740"]=Cohort(9,2,B.CohortDigest([(7,H('a')),(9,H('b'))]),7,9) };
    private static JsonObject Context(long id=8,string? sid=Sid,string? resetSid=Sid,string keywords="Audit Success")=>new() { ["source_event_id"]=id,["normalized_hash"]=H('a'),["login_target_user_sid"]=sid,["reset_target_user_sid"]=resetSid,["reset_keywords"]=keywords };
    private sealed class Session : ISemanticStreamingSession,ISemanticDatabase
    {
        internal readonly List<(string Sql,object?[] Args)> Calls=[];
        internal Func<string,object?[],JsonArray> Query=(_,_)=>new();
        internal Func<string,object?[],IEnumerable<JsonObject>> Stream=(_,_)=>[];
        internal bool Streaming,Finished,Opened,Committed;
        internal int Streamed;
        public Task<JsonArray> QueryAsync(string sql,CancellationToken ct,params object?[] values) {
            Assert.False(Streaming,"aggregate must wait for the source reader"); ct.ThrowIfCancellationRequested(); Calls.Add((sql,values)); return Task.FromResult(Query(sql,values));
        }
        public async IAsyncEnumerable<JsonObject> StreamAsync(string sql,[System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct,params object?[] values) {
            Calls.Add((sql,values)); Streaming=true; Finished=false;
            try { foreach(var row in Stream(sql,values)) { ct.ThrowIfCancellationRequested(); Streamed++; yield return row; } Finished=true; }
            finally { Streaming=false; }
            await Task.CompletedTask;
        }
        public Task<ISemanticSession> OpenAsync(bool write,CancellationToken ct) { Opened=true; return Task.FromResult<ISemanticSession>(this); }
        public Task CommitAsync(CancellationToken ct) { Committed=true; return Task.CompletedTask; }
        public ValueTask DisposeAsync()=>ValueTask.CompletedTask;
    }
    [Fact] public async Task Vocabulary_provider_compact_manifest_and_streaming_digest_match_python()
    {
        Assert.Equal(new[]{4740,4767,4723,4724,4720,4722,4725,4726,4738,4781,4728,4729,4732,4733,4756,4757,4727,4730,4737,4731,4734,4735,4754,4755,4758,4764,4624,4625,4771,4776,4719,1102},B.HistoryEventIds);
        Assert.NotEqual(B.CohortDigest([(7,H('a')),(9,H('b')),(11,H('c'))]),B.CohortDigest([(7,H('a')),(9,H('d')),(11,H('c'))]));
        var session=new Session { Query=(_,_)=>new JsonArray(new JsonObject { ["id"]=7 }) };
        Assert.Equal(new long[]{7},await B.SelectHistoryTargets(session,1102,0,9,999,Ct));
        Assert.Contains("provider.value=$1",session.Calls[0].Sql); Assert.Equal("Microsoft-Windows-Eventlog",session.Calls[0].Args[0]); Assert.Equal(999,session.Calls[0].Args[7]);
        session.Stream=(_,args)=>(int)args[1]! == 4740?[new JsonObject { ["id"]=7,["normalized_hash"]=H('a') },new JsonObject { ["id"]=9,["normalized_hash"]=H('b') }]:[];
        var cohorts=await B.HistoryCohorts(session,Ct);
        Assert.Equal(32,session.Calls.Count-1); Assert.Equal(2,cohorts["4740"].Number("count")); Assert.Equal(9,cohorts["4740"].Number("high_watermark")); Assert.Equal(7,cohorts["4740"].Number("min_id"));
        Assert.Equal("3f79137b4ce393198ac9c652dd4e5291966c6ff74db26bf4782e5a117e01dd4f",cohorts["4740"].Text("cohort_digest")); Assert.Equal(0,cohorts["1102"].Number("count"));
        var manifest=B.NewManifest(Identity(),H('c'),cohorts); B.ValidateManifest(manifest,Identity(),cohorts,H('c'));
        Assert.Equal(B.ManifestV1,manifest.Text("manifest_type")); Assert.Equal("no_retained_events",manifest["events"]!["1102"].Text("state"));
        Assert.DoesNotContain("\"source_event_ids\"",manifest.ToJsonString()); Assert.DoesNotContain("\"normalized_hashes\"",manifest.ToJsonString());
        Assert.Equal("4556f8b134a27bd5d1b6aa7d8fdc290a1e537b21d982502e67497c961065fc72",manifest.Text("selection_fingerprint"));
    }
    [Theory] [InlineData(100)] [InlineData(5000)]
    public void Legacy_manifest_keeps_frozen_page_size(int batch)
    {
        var manifest=B.NewManifest(Identity(),H('c'),Cohorts(),batch); Assert.Equal(batch,manifest.Number("batch_limit")); B.ValidateManifest(manifest,Identity(),planDigest:H('c'));
        Assert.Equal(5000,B.NewManifest(Identity(),H('c'),Cohorts()).Number("batch_limit"));
    }
    [Fact] public void V2_supersedes_without_turning_routine_logons_into_semantic_work()
    {
        var cohorts=new JsonObject { ["4624"]=Cohort(9,3,B.CohortDigest([(7,H('a')),(8,H('b')),(9,H('c'))]),7,9),["4724"]=Cohort(6,1,B.CohortDigest([(6,H('d'))]),6,6) };
        var legacy=B.NewManifest(Identity(),H('c'),cohorts,100);
        var manifest=B.NewManifestV2(Identity(),H('d'),cohorts,new JsonObject { ["count"]=1,["cohort_digest"]=B.CohortDigest([(8,H('b'))]),["reset_high_watermark"]=6 },new JsonObject { ["manifest_type"]=B.ManifestV1,["plan_digest"]=legacy["plan_digest"].Copy(),["reason"]=B.SupersedeReason });
        Assert.Equal(B.ManifestV2,manifest.Text("manifest_type")); Assert.Equal(5000,manifest.Number("batch_limit")); Assert.Equal(H('c'),manifest["supersedes"].Text("plan_digest"));
        var logons=manifest["events"]!["4624"]!; Assert.Equal(3,logons.Number("raw_retained_count")); Assert.Equal("password_reset_context_only",logons.Text("semantic_scope")); Assert.Equal(1,logons.Number("semantic_expected_count")); Assert.Equal(1,logons.Number("count"));
        Assert.Equal("842718a615f6ada7acf392be70b181853332414b90cee17749569ac5eede499a",manifest.Text("selection_fingerprint"));
        B.ValidateManifest(manifest,Identity(),cohorts,H('d'));
        manifest["supersedes"]!["reason"]="silent"; Assert.Contains("supersedes",Assert.Throws<InvalidDataException>(()=>B.ValidateManifest(manifest,Identity())).Message);
        manifest["supersedes"]!["reason"]=B.SupersedeReason; logons["semantic_context_reset_high_watermark"]=5;
        Assert.Contains("logon context coverage",Assert.Throws<InvalidDataException>(()=>B.ValidateManifest(manifest,Identity())).Message);
    }
    [Fact] public void Manifest_rejects_invented_state_and_mutated_plan()
    {
        var manifest=B.NewManifest(Identity(),H('c'),Cohorts()); var entry=manifest["events"]!["4740"]!;
        entry["state"]="not-a-real-progress-state"; Assert.Contains("state",Assert.Throws<InvalidDataException>(()=>B.ValidateManifest(manifest,Identity(),Cohorts(),H('c'))).Message);
        entry["state"]="planned"; manifest["plan_digest"]=H('b'); Assert.Contains("immutable contract",Assert.Throws<InvalidDataException>(()=>B.ValidateManifest(manifest,Identity(),Cohorts(),H('c'))).Message);
    }
    [Theory]
    [InlineData("planned",null,"must-not-be-terminal")]
    [InlineData("publishing",null,"must-not-be-terminal")]
    [InlineData("queued",null,"must-not-be-terminal")]
    [InlineData("processing",null,"must-not-be-terminal")]
    [InlineData("complete","current_version_normalized_hash_reconciled",null)]
    [InlineData("no_retained_events","no_retained_events","wrong-reason")]
    [InlineData("incomplete_original","frozen_original_integrity_mismatch",null)]
    [InlineData("incomplete_normalization","current_version_non_unknown_normalization_missing",null)]
    [InlineData("blocked","operator_blocked_after_evidence","wrong-blocked-reason")]
    [InlineData("failed","failed_current_version_work",null)]
    [InlineData("quarantined","quarantined_current_version_work",null)]
    public void Progress_and_terminal_states_require_exact_evidence_reason(string state,string? reason,string? invalid)
    {
        var cohorts=Cohorts(); var manifest=B.NewManifest(Identity(),H('c'),cohorts); var entry=manifest["events"]![state=="no_retained_events"?"1102":"4740"]!;
        entry["state"]=state; entry["terminal_reason"]=reason; B.ValidateManifest(manifest,Identity(),cohorts,H('c'));
        entry["terminal_reason"]=invalid; Assert.Contains("reason",Assert.Throws<InvalidDataException>(()=>B.ValidateManifest(manifest,Identity(),cohorts,H('c'))).Message);
    }
    [Fact] public async Task Context_freezes_reset_boundary_filters_before_page_and_keeps_full_cohort()
    {
        var session=new Session { Stream=(sql,_)=>sql.Contains("from normalized_events normalized")?[]:[Context()] };
        var cohort=await B.ContextCohort(session,9,6,Ct); Assert.Equal(1,cohort.Number("count")); Assert.Equal("dcddd2043ede59dbf319e63e70277579ccbd5ae9ea2ef074e98181984e1687be",cohort.Text("cohort_digest"));
        Assert.Empty(await B.SelectContextTargets(session,0,9,6,5000,Ct));
        session.Stream=(_,_)=>[Context(7,keywords:"Audit Failure"),Context()]; Assert.Equal(new long[]{8},await B.SelectContextTargets(session,7,99,55,1,Ct));
        var (sql,args)=session.Calls[^1]; Assert.Contains("reset_event.id<=$4",sql); Assert.DoesNotContain("limit",sql,StringComparison.OrdinalIgnoreCase); Assert.IsType<DateTimeOffset>(args[^1]);
        Assert.Equal("Security",args[0]); Assert.Equal("Microsoft-Windows-Security-Auditing",args[1]); Assert.Equal(new[]{4724},Assert.IsType<int[]>(args[2])); Assert.Equal(55L,args[3]); Assert.Equal(7L,args[6]); Assert.Equal(99L,args[7]);
    }
    [Fact] public async Task Context_rejects_noncanonical_sid_and_deduplicates_eligible_rows()
    {
        var session=new Session { Stream=(_,_)=>[Context(),Context(),Context(9,Sid+" ",Sid+" "),Context(10,Sid,Sid.ToLowerInvariant()),Context(11,keywords:"Audit Failure")] };
        Assert.Equal(new long[]{8},await B.SelectContextTargets(session,0,11,7,5000,Ct));
    }
    [Fact] public async Task Reconciliation_finishes_5001_source_rows_before_5000_and_1_aggregates()
    {
        var session=new Session { Stream=(_,_)=>Enumerable.Range(1,5001).Select(i=>Context(i)) };
        session.Query=(_,args)=> { Assert.True(session.Finished); int count=Assert.IsType<long[]>(args[6]).Length; var row=new JsonObject(); foreach(string field in new[]{"retained_count","normalized_count","normalization_failed","normalization_quarantined","outbox_queued","outbox_leased","outbox_completed","outbox_failed","outbox_quarantined","action_evidence_count"}) row[field]=field is "retained_count" or "normalized_count" or "outbox_completed" or "action_evidence_count"?count:0; return new(row); };
        var result=await B.ReconcileContext(session,6000,6000,Ct);
        Assert.Equal(5001,session.Streamed); Assert.Equal(new[]{5000,1},session.Calls.Skip(1).Select(x=>Assert.IsType<long[]>(x.Args[6]).Length)); Assert.Equal(5001,result.Number("retained_count")); Assert.Equal(5001,result.Number("normalized_count"));
    }
    private static JsonObject Repair(string? status,bool normalized)=>new() {
        ["source_event_id"]=260,["source_hash"]=H('a'),["original_job_count"]=1,["original_job_id"]="12345678-1234-5678-1234-567812345678",["original_status"]="quarantined",["original_attempt_count"]=5,["original_max_attempts"]=5,["original_error_code"]="UniqueViolation",
        ["original_error_detail"]="duplicate key value violates unique constraint \"canonical_actions_pkey\"",["original_error_detail_sha256"]=H('b'),["original_source_hash"]=H('a'),["repair_job_count"]=status is null?0:1,["repair_status"]=status,["repair_processor_id"]=B.Processor,["repair_processor_version"]=SemanticEvent.Version,["repair_source_hash"]=H('a'),["repair_payload_source_hash"]=H('a'),["repair_semantic_contract_version"]=1,
        ["repair_original_job_id"]="12345678-1234-5678-1234-567812345678",["repair_history_plan_digest"]=H('c'),["repair_plan_digest"]=H('d'),["repair_original_attempt_count"]=5,["repair_original_max_attempts"]=5,["repair_original_error_code"]="UniqueViolation",["repair_original_error_detail_sha256"]=H('b'),
        ["normalized_current_count"]=normalized?1:0,["normalized_proof_count"]=normalized?1:0,["normalized_proof_hash"]=normalized?H('a'):null,["normalized_action_count"]=normalized?1:0 };
    [Theory]
    [InlineData(null,false,"absent")] [InlineData("queued",false,"queued")] [InlineData("leased",false,"leased")]
    [InlineData("completed",true,"completed")] [InlineData("failed",false,"failed")] [InlineData("quarantined",false,"quarantined")]
    [InlineData("completed",false,"conflict")] [InlineData("queued",true,"conflict")]
    public void Repair_requires_bound_terminal_job_and_current_proof(string? status,bool normalized,string expected)=>Assert.Equal(expected,B.ClassifyRepair(Repair(status,normalized),H('a'),H('c')));
    [Theory] [InlineData("repair_job_count","2")] [InlineData("repair_original_job_id","not-the-original")] [InlineData("repair_payload_source_hash","b")] [InlineData("repair_semantic_contract_version","2")]
    public void Repair_rejects_duplicate_and_mismatched_binding(string key,string value)
    {
        var row=Repair("completed",true); row[key]=key is "repair_job_count" or "repair_semantic_contract_version"?JsonValue.Create(int.Parse(value)):JsonValue.Create(value=="b"?H('b'):value);
        Assert.Equal("conflict",B.ClassifyRepair(row,H('a'),H('c')));
    }
    [Fact] public async Task V2_reconciliation_reads_exact_selected_repair_lineage_without_hiding_quarantine()
    {
        var session=new Session { Stream=(_,_)=>[Context(260)] };
        session.Query=(sql,args)=> {
            if(sql.Contains("with selected")) { var row=Repair("completed",true); row["repair_original_error_detail_sha256"]=Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(row.Text("original_error_detail")!))); return new(row); }
            return new(new JsonObject { ["retained_count"]=1,["normalized_count"]=1,["normalization_failed"]=0,["normalization_quarantined"]=0,["outbox_queued"]=0,["outbox_leased"]=0,["outbox_completed"]=1,["outbox_failed"]=0,["outbox_quarantined"]=1,["action_evidence_count"]=1 });
        };
        var result=await B.ReconcileV2Context(session,300,100,H('c'),Ct);
        Assert.Equal(1,result.Current.Number("outbox_quarantined")); Assert.Equal(1,result.RepairStates.Number("completed")); Assert.Equal(1,result.RepairStates.Sum(x=>x.Value!.GetValue<long>()));
        var call=session.Calls[^1]; Assert.Contains("job_kind='semantic_v2_quarantine_repair'",call.Sql); Assert.Equal(new long[]{260},Assert.IsType<long[]>(call.Args[0])); Assert.Equal(new[]{H('a')},Assert.IsType<string[]>(call.Args[1]));
    }
}
