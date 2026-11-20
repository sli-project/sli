using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;
using B = Sli.Server.Semantic.SemanticInvestigationBackfill;

namespace Sli.Server.Tests.Semantic;

public sealed partial class SemanticInvestigationBackfillTests
{
    [Fact] public async Task Accepted_rules_and_frozen_fact_and_relation_selectors_match_python()
    {
        var rules=B.SelectedRules(); Assert.Equal(SemanticRelations.RuleIds,rules.Select(x=>x.Text("rule_id"))); Assert.DoesNotContain(rules,x=>x.Text("rule_id")=="auth.session.lifecycle");
        Assert.Equal(new[]{4625,4720,4724,4728,4729,4732,4733,4740,4756,4757,4767},B.AnchorIds);
        Assert.Equal("f2a9c539107d27ab59fbff3c9f605c42af2f0bb72ebad965a9f9f1d9cf15d20f",B.RulesFingerprint());
        var session=new Session { Query=(sql,_)=>sql.Contains("select id")?new(new JsonObject { ["id"]=17 },new JsonObject { ["id"]=19 }):new(new JsonObject { ["normalized_event_id"]="n-1",["source_event_id"]=11 }) };
        var anchors=await B.SelectFactTargets(session,10,99,999,"anchors",Ct); Assert.Equal(new long[]{17,19},anchors.Select(x=>x.Number("id")));
        var call=session.Calls[^1]; Assert.Contains("from semantic_event_rows",call.Sql); Assert.Contains("order by id",call.Sql); Assert.Equal(10L,call.Args[0]); Assert.Equal(99L,call.Args[1]); Assert.Equal(B.AnchorIds,Assert.IsType<int[]>(call.Args[2])); Assert.Equal(100,call.Args[^2]);
        await B.SelectFactTargets(session,10,99,999,"context",Ct); call=session.Calls[^1];
        foreach(string fragment in new[]{"reset.semantic_type='account.password.reset.succeeded'","reset_event.event_id=$4","login.event_id=any","login.target_user_sid","reset_event.target_user_sid","relation_account_identity","interval '1 hour'","order by login.id"}) Assert.Contains(fragment,call.Sql);
        Assert.Equal(4724,call.Args[3]); Assert.Equal(new[]{4624},Assert.IsType<int[]>(call.Args[6])); Assert.Equal(100,call.Args[^2]);
        var frozen=DateTimeOffset.Parse("2026-09-11T00:00:00+00:00"); var targets=await B.SelectRelationTargets(session,10,99,999,frozen,Ct); Assert.Equal("n-1",targets[0].Text("normalized_event_id")); Assert.Equal(11,targets[0].Number("source_event_id")); call=session.Calls[^1];
        foreach(string fragment in new[]{"from normalized_events","join semantic_event_rows source_event","source_event.event_id=source_contract.event_id","join semantic_event_rows reset_source_event","reset_source_event.event_id=$10","order by normalized_events.source_event_id","normalized_events.normalizer_id=$4","normalized_events.normalized_at<=$6","normalized_events.semantic_type<>'authentication.session.created'","reset.semantic_type='account.password.reset.succeeded'","normalized_events.facts_json->>'relation_account_sid'"}) Assert.Contains(fragment,call.Sql);
        Assert.Equal(4724,call.Args[9]); Assert.Equal(frozen,call.Args[5]); Assert.Equal(frozen,call.Args[13]); Assert.Equal(100,call.Args[^2]);
        foreach(string fragment in new[]{" and semantic_contract_version="," and normalizer_id="," and normalizer_version="," and source_event_id>"," and source_event_id<="," and semantic_type=any"}) Assert.DoesNotContain(fragment,call.Sql.Replace("\n"," "));
    }
    [Theory] [InlineData(true)] [InlineData(false)]
    public void Checkpoints_freeze_contract_source_range_and_roll_forward_without_reprocessing(bool facts)
    {
        long high=facts?99:88; string suffix=facts?"event_id":"source_event_id";
        var checkpoint=B.NewCheckpoint(high,H('a'),facts,frozen:"2026-09-12T20:00:00+00:00"); B.ValidateCheckpoint(checkpoint,H('a'),facts);
        Assert.Equal(high,checkpoint.Number("frozen_high_watermark_"+suffix)); Assert.Equal(0,checkpoint.Number("last_committed_"+suffix)); Assert.False(checkpoint.Flag("contacts_sources")); Assert.False(checkpoint.Flag("moves_collection_cursors"));
        Assert.Equal(new[]{4624},checkpoint["source_event_ids_by_semantic_type"]!["authentication.session.created"]!.AsArray().Select(x=>x!.GetValue<int>()));
        if(facts) { Assert.Equal("anchors",checkpoint.Text("phase")); Assert.Equal(new[]{4624},checkpoint["context_windows_event_ids"]!.AsArray().Select(x=>x!.GetValue<int>())); }
        else { Assert.Equal("normalized_events",checkpoint.Text("source")); Assert.Equal(SemanticEvent.Normalizer,checkpoint["facts_contract"].Text("normalizer_id")); Assert.NotNull(checkpoint["frozen_normalized_at"]); }
        Assert.Throws<InvalidDataException>(()=>B.ValidateCheckpoint(checkpoint,H('b'),facts));
        checkpoint["status"]="complete"; checkpoint["last_committed_"+suffix]=high; checkpoint["phase"]=facts?"context":null; checkpoint["database_identity"]=Identity();
        var snapshot=new JsonObject { ["database_identity"]=Identity(),[facts?"retained_fact_high_watermark_event_id":"high_watermark_source_event_id"]=facts?123:120,["frozen_normalized_at"]="2026-09-13T00:00:00+00:00" };
        var resumed=B.ResumeCheckpoint(checkpoint,snapshot,H('a'),facts); Assert.NotSame(checkpoint,resumed); Assert.Equal("active",resumed.Text("status")); Assert.Equal(high+1,resumed.Number("range_start_"+suffix)); Assert.Equal(high,resumed.Number("last_committed_"+suffix)); Assert.Equal(facts?123:120,resumed.Number("frozen_high_watermark_"+suffix));
        var range=Assert.Single(resumed["completed_ranges"]!.AsArray())!; Assert.Equal(1,range.Number("start")); Assert.Equal(high,range.Number("end"));
        if(facts) { B.AdvanceFacts(resumed,"anchors",[],123); Assert.Equal("context",resumed.Text("phase")); Assert.Equal(high,resumed.Number("last_committed_event_id")); }
        else Assert.Equal("2026-09-13T00:00:00+00:00",resumed.Text("frozen_normalized_at"));
        var bad=checkpoint.DeepClone().AsObject(); bad["contacts_sources"]=true; Assert.Throws<InvalidDataException>(()=>B.ValidateCheckpoint(bad,H('a'),facts));
    }
    [Fact] public void Facts_finish_anchors_then_context()
    {
        var checkpoint=B.NewCheckpoint(99,H('a')); B.AdvanceFacts(checkpoint,"anchors",[],99);
        Assert.Equal("context",checkpoint.Text("phase")); Assert.Equal(0,checkpoint.Number("last_committed_event_id")); Assert.Equal("active",checkpoint.Text("status"));
        B.AdvanceFacts(checkpoint,"context",[],99); Assert.Equal("context",checkpoint.Text("phase")); Assert.Equal(99,checkpoint.Number("last_committed_event_id")); Assert.Equal("complete",checkpoint.Text("status"));
    }
    [Theory] [InlineData("leased")] [InlineData("quarantined")]
    public async Task Pending_exact_job_blocks_checkpoint_and_reports_unresolved_source(string status)
    {
        var checkpoint=B.NewCheckpoint(10,H('a')); var session=new Session(); long[]? processed=null;
        session.Query=(sql,_)=>sql.Contains("from unnest")?new(new JsonObject { ["source_event_id"]=7,["processing_status"]="normalized",["outbox_status"]="completed" },new JsonObject { ["source_event_id"]=8,["processing_status"]=null,["outbox_status"]=status }):new(new JsonObject { ["id"]=7 },new JsonObject { ["id"]=8 });
        var state=await B.FactsCompletion(session,[7,8],Ct); Assert.Equal("pending",state.Text("state")); Assert.Equal(1,state.Number("completed")); Assert.Equal(1,state.Number(status)); Assert.Equal(new long[]{8},state["unresolved_event_ids"]!.AsArray().Select(x=>x!.GetValue<long>()));
        Assert.Contains("normalizer_id=$3",session.Calls[^1].Sql); Assert.Contains("processor_version=$7",session.Calls[^1].Sql);
        var result=await B.PollFacts(session,checkpoint,H('a'),(ids,_)=> { processed=ids; return Task.CompletedTask; },Ct);
        Assert.Equal(new long[]{7,8},processed); Assert.Equal("blocked_batch",result.Text("status")); Assert.Equal(0,checkpoint.Number("last_committed_event_id")); Assert.False(result.Flag("source_contacted")); Assert.False(result.Flag("collection_cursors_changed")); Assert.Equal(0,result.Number("findings_created"));
    }
    [Fact] public async Task Exact_terminal_current_jobs_allow_checkpoint_progress()
    {
        var checkpoint=B.NewCheckpoint(10,H('a')); var session=new Session { Query=(sql,_)=>sql.Contains("from unnest")?new(new JsonObject { ["source_event_id"]=7,["processing_status"]="ignored",["outbox_status"]="completed" }):new(new JsonObject { ["id"]=7 }) };
        var result=await B.PollFacts(session,checkpoint,H('a'),(_,_)=>Task.CompletedTask,Ct); Assert.Equal("active",result.Text("status")); Assert.Equal(7,checkpoint.Number("last_committed_event_id"));
    }
    [Fact] public async Task Activation_checks_ledger_before_worker_role_stops_at_shadow_and_retires_old_versions()
    {
        var definitions=B.SelectedRules().ToDictionary(x=>x.Text("rule_id")!); var states=definitions.Keys.ToDictionary(x=>x,_=>"draft"); var subscriptions=new Dictionary<string,JsonArray>(); var transitions=new List<(string Id,int Version,string Status)>();
        var session=new Session();
        session.Query=(sql,args)=> {
            if(sql.Contains("from schema_migrations")) { Assert.DoesNotContain(session.Calls,x=>x.Sql=="set local role adlog_storage_worker"); return new(new JsonObject { ["ready"]=true }); }
            if(sql.StartsWith("select lifecycle_status")) return new(new JsonObject { ["lifecycle_status"]=states[(string)args[0]!] });
            if(sql.StartsWith("select rule_kind")) { var stored=definitions[(string)args[0]!].DeepClone().AsObject(); stored["lifecycle_status"]=states[(string)args[0]!]; return new(stored); }
            if(sql.StartsWith("delete from semantic_correlation_subscriptions")) subscriptions[(string)args[0]!]=new();
            if(sql.StartsWith("insert into semantic_correlation_subscriptions")) subscriptions[(string)args[0]!].Add(new JsonObject { ["semantic_type"]=(string)args[2]!,["subscription_order"]=(int)args[3]!,["definition_sha256"]=Convert.ToHexStringLower((byte[])args[4]!) });
            if(sql.StartsWith("select semantic_type")) return subscriptions[(string)args[0]!].DeepClone().AsArray();
            if(sql.StartsWith("select rule_version")) return new(new JsonObject { ["rule_version"]=1,["lifecycle_status"]="shadow" });
            if(sql.StartsWith("update semantic_correlation_rules")) { string id=(string)args[1]!,target=(string)args[0]!; int version=(int)args[2]!; transitions.Add((id,version,target)); if(version==definitions[id].Number("rule_version")) states[id]=target; return new(new JsonObject { ["lifecycle_status"]=target }); }
            return new();
        };
        var result=await B.Activate(session,Ct); Assert.All(result,x=>Assert.Equal("shadow",x.Value!.GetValue<string>())); Assert.Equal(5,result.Count);
        Assert.All(transitions,x=>Assert.NotEqual("enabled",x.Status)); Assert.Equal(new[]{"validated","test","shadow"},transitions.Where(x=>x.Id==SemanticRelations.RuleIds[0]).Select(x=>x.Status));
        Assert.Contains(transitions,x=>x.Id=="investigation.password.reset-then-logon" && x.Version==1 && x.Status=="deprecated");
        Assert.DoesNotContain(session.Calls,x=>x.Sql.Contains("delete from semantic_correlation_rules") || x.Sql.Contains("delete from semantic_correlation_candidates"));
        var ledgerMissing=new Session { Query=(_,_)=>new(new JsonObject { ["ready"]=false }) }; await Assert.ThrowsAsync<InvalidDataException>(()=>B.Activate(ledgerMissing,Ct)); Assert.Single(ledgerMissing.Calls);
    }
    [Fact] public void Readiness_rejects_extra_executable_version()
    {
        var rows=new JsonArray(B.SelectedRules().Select(x=> { var r=x.DeepClone().AsObject(); r["lifecycle_status"]="shadow"; return (JsonNode)r; }).ToArray()); Assert.True(B.RulesReady(rows));
        rows.Add(new JsonObject { ["rule_id"]=SemanticRelations.RuleIds[0],["rule_version"]=999,["definition_sha256"]=H('f'),["lifecycle_status"]="test" }); Assert.False(B.RulesReady(rows));
    }
    private static JsonObject RecoveryRow()
    {
        var rule=B.SelectedRules().Single(x=>x.Text("rule_id")=="investigation.account.unlock.after-lock");
        return new() { ["job_id"]="00000000-0000-0000-0000-000000000001",["normalized_event_id"]="10000000-0000-0000-0000-000000000001",["source_event_id"]=123,["normalized_at"]="2026-09-14T09:00:00+00:00",["rule_id"]=rule["rule_id"].Copy(),["rule_version"]=rule["rule_version"].Copy(),["definition_sha256"]=rule["definition_sha256"].Copy(),["dispatch_status"]="quarantined",["attempt_count"]=5,["max_attempts"]=5,["last_error_code"]="InsufficientPrivilege",["last_error_detail"]="permission denied for table semantic_correlation_rules" };
    }
    [Fact] public async Task Recovery_is_exact_plan_bound_auditable_and_rejects_candidate_drift()
    {
        var frozen=DateTimeOffset.Parse("2026-09-14T09:00:00+00:00"); var row=RecoveryRow(); var session=new Session { Query=(sql,_)=>sql.StartsWith("update")?new(new JsonObject { ["job_id"]=row["job_id"].Copy() }):new(row.DeepClone()) };
        var candidates=await B.RecoveryCandidates(session,frozen,123,Ct,true); Assert.True(JsonNode.DeepEquals(candidates[0],row)); var call=session.Calls[^1];
        Assert.Contains("dispatch_status='quarantined'",call.Sql); Assert.Contains("last_error_code=$1",call.Sql); Assert.Contains("for update of job",call.Sql); Assert.Contains("%semantic_correlation_rules%",call.Args); Assert.DoesNotContain("{",call.Sql);
        string digest=B.RecoveryDigest(candidates,Identity(),frozen,123); Assert.Equal("e2300e8d0377729edfad3a2a8ef86047f0a4415e00b4201f5a6be8243b04f702",digest);
        var recovered=await B.RecoverDispatch(session,digest,B.RecoveryConfirmation(digest),Identity(),frozen,123,_=>null,Ct); Assert.Equal(new[]{row.Text("job_id")},recovered); Assert.True(session.Committed);
        call=session.Calls[^1]; Assert.Contains("dispatch_status='failed'",call.Sql); Assert.Contains("attempt_count=max_attempts-1",call.Sql); Assert.DoesNotContain("last_error_code=null",call.Sql); Assert.DoesNotContain("last_error_detail=null",call.Sql);
        var changed=new Session(); Assert.Contains("candidate set changed",(await Assert.ThrowsAsync<InvalidDataException>(()=>B.RecoverDispatch(changed,H('0'),B.RecoveryConfirmation(H('0')),Identity(),frozen,123,_=>null,Ct))).Message); Assert.False(changed.Committed); Assert.Single(changed.Calls);
    }
    [Fact] public async Task Recovery_refuses_enabled_runtime_before_open_and_requires_confirmation_for_digest()
    {
        Assert.Equal("RECOVER-INVESTIGATION-DISPATCH-1111111111111111",B.RecoveryConfirmation(H('1'))); Assert.NotEqual(B.RecoveryConfirmation(H('1')),B.RecoveryConfirmation(H('2')));
        var session=new Session(); await Assert.ThrowsAsync<InvalidDataException>(()=>B.RecoverDispatch(session,H('1'),B.RecoveryConfirmation(H('1')),Identity(),DateTimeOffset.UtcNow,1,key=>key=="ADLOG_SEMANTIC_PRODUCTION_ENABLED"?"1":"investigation-v1",Ct)); Assert.False(session.Opened);
        await Assert.ThrowsAsync<InvalidDataException>(()=>B.RecoverDispatch(session,H('1'),B.RecoveryConfirmation(H('2')),Identity(),DateTimeOffset.UtcNow,1,_=>null,Ct)); Assert.False(session.Opened);
    }
}
