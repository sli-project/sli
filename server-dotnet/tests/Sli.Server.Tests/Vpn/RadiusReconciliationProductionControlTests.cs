using System.Text;
using System.Text.Json.Nodes;
using Sli.Server.Vpn;
using Xunit;
using Control = Sli.Server.Vpn.RadiusReconciliationControl;

namespace Sli.Server.Tests.Vpn;

public sealed class RadiusReconciliationProductionControlTests
{
    static string Repository()
    {
        for(var dir=new DirectoryInfo(AppContext.BaseDirectory);dir is not null;dir=dir.Parent)
            if(File.Exists(Path.Combine(dir.FullName,"config","stage9_radius_session_consumer_v1.json"))) return dir.FullName;
        throw new InvalidOperationException("repository_required");
    }
    static JsonObject Clone(JsonObject value)=>(JsonObject)value.DeepClone();
    static JsonObject Baseline()=>new() { ["source_instance_sha256"]=new string('a',64),["cursor_revision"]=3,["observations"]=83,
        ["terminal_unresolved_receipts"]=83,["nonterminal_deliveries"]=0,["attempts_table"]=false,["overlays_table"]=false,["writer_role"]=false,
        ["migration_role_can_create_role"]=true,["attempt_count"]=0,["overlay_count"]=0 };
    static Dictionary<int,bool> Markers()=>Control.MigrationNames.Keys.ToDictionary(v=>v,v=>v==61);
    static Control.Batch Summary(int count,int projected)=>new(new JsonObject { ["terminal_receipt_count"]=count,["projected_count"]=projected,["still_unresolved_count"]=count-projected },new(),new());
    static Control.Batch[] Summaries()=>[Summary(17,9),Summary(50,41),Summary(16,12)];
    static JsonObject Plan(JsonObject? baseline=null)=>Control.BuildPlan(baseline??Baseline(),Markers(),Summaries(),new(),new(),new());
    static string Line(string packet,string classValue,string session="opaque-session")
    {
        var fields=Enumerable.Repeat("",66).ToArray();fields[1]="NPS";fields[2]="08/11/2026";fields[3]="12:00:00";fields[4]=packet;
        // CSV-escaped exact DN; principal lookup stays exact and scoped to example.test.
        if(packet=="2") fields[6]="\"CN=User,DC=example,DC=test\"";
        fields[11]="vpn-gateway";fields[26]=classValue;
        if(packet=="4") { fields[31]="1";fields[35]=session; }
        return string.Join(',',fields);
    }
    static JsonObject Acceptance(string repository)
    {
        var safety=new JsonObject();
        foreach(string key in new[]{"original_rows_unchanged","writer_role_restricted_nologin","original_observation_update_denied",
            "terminal_receipt_update_denied","evidence_delete_denied","append_only_output_update_denied","consumer_overlay_update_denied",
            "outer_transaction_postcondition_readable","conflicting_second_resolution_blocked","reader_rollback_guarded_after_evidence","rollback_guarded_after_evidence"}) safety[key]=true;
        safety["attempt_counts_total_projected_unresolved"]=new JsonArray(2,1,1);safety["projected_session_count"]=1;
        var value=new JsonObject { ["status"]="passed",["acceptance"]=safety,["production_database_changed"]=false,["radius_source_contacted"]=false,
            ["runtime_enabled"]=false,["autostart_enabled"]=false,["disposable_cluster_removed"]=true,["database"]=new JsonObject{["server_version_num"]=180004} };
        foreach(var (key,version,rollback) in new[]{("forward_sha256",65,false),("rollback_sha256",65,true),("projection_forward_sha256",80,false),("projection_rollback_sha256",80,true)})
            value[key]=Control.Hash(File.ReadAllBytes(Path.Combine(repository,"config","postgres_migrations",$"{version:000}_{Control.MigrationNames[version]}{(rollback?".rollback":"")}.sql")));
        return value;
    }
    sealed class Fixture : IDisposable
    {
        public string Root { get; }=Path.Combine(Path.GetTempPath(),"sli-radius-reconciliation-"+Guid.NewGuid().ToString("N"));
        public string RepositoryRoot { get; }=Repository();
        public string AcceptancePath=>Path.Combine(Root,"acceptance.json");
        public readonly List<JsonObject> Observations=[],Manifests=[],Attempts=[],Overlays=[],Projections=[];
        public readonly List<(string Sql,object?[] Args,string Role)> Calls=[];
        public readonly List<string> Progress=[];
        public string Role="session_owner";
        public bool CanCreateRole=true;
        public int PageSize=250;
        public string Subscription { get; }
        public Control Controller { get; }
        public Fixture(int count=83)
        {
            Directory.CreateDirectory(Root);File.WriteAllText(AcceptancePath,Acceptance(RepositoryRoot).ToJsonString());
            Subscription=ControlText(JsonNode.Parse(File.ReadAllText(Path.Combine(RepositoryRoot,"config","stage9_radius_session_consumer_v1.json")))!.AsObject(),"subscription_id");
            Controller=new(Query,RepositoryRoot,Root,Progress.Add);
            for(int i=0;i<count;i++)
            {
                var manifest=AddEvidence(Line("4",i==17?"cross-batch-class":"missing-class","opaque-session-"+i),i<17?10:i<67?20:30,i);
                var observation=Clone(manifest);observation["observation_id"]=Id(1000+i);observation["lifecycle_event"]="start";observation["timestamp_state"]="ready";
                observation["observed_at_utc"]="2026-08-11T05:00:00Z";Observations.Add(observation);
            }
            AddEvidence(Line("2","cross-batch-class"),5,0);
            AddEvidence(Line("2","cross-batch-class"),40,0); // outside all terminal batches
        }
        static string Id(int value)=>$"00000000-0000-4000-8000-{value:000000000000}";
        public JsonObject AddEvidence(string record,long offset,int ordinal)
        {
            string uid=Id(2000+Manifests.Count),hash=ControlHash(record);
            var manifest=new JsonObject { ["evidence_uid"]=uid,["canonical_record_sha256"]=hash,["object_sha256"]=hash,["object_size_bytes"]=Encoding.UTF8.GetByteCount(record),
                ["cursor_start_byte_offset"]=offset,["batch_record_ordinal"]=ordinal };
            string path=EvidencePath(manifest);Directory.CreateDirectory(Path.GetDirectoryName(path)!);File.WriteAllText(path,record,new UTF8Encoding(false));
            Manifests.Add(manifest);return manifest;
        }
        public string EvidencePath(JsonObject manifest)
        { string uid=Guid.Parse(ControlText(manifest,"evidence_uid")).ToString("N");return Path.Combine(Root,"published","acquisition-radius",uid[..2],uid+".record"); }
        public Task<List<JsonObject>> Query(string sql,object?[] args)
        {
            Calls.Add((sql,args,Role));List<JsonObject> rows=[];
            if(sql==RadiusReconciliationSql.Sources) rows.Add(new(){["source_instance_id"]="source",["organization_scope"]="example.test"});
            else if(sql==RadiusReconciliationSql.Subscriptions) rows.Add(new(){["subscription_id"]=Subscription});
            else if(sql==RadiusReconciliationSql.Cursor || sql==RadiusReconciliationSql.LockedCursor) rows.Add(new(){["revision"]=3});
            else if(sql==RadiusReconciliationSql.Baseline || sql==RadiusReconciliationSql.LockedBaseline)
            {
                var row=Baseline();foreach(string key in new[]{"source_instance_sha256","cursor_revision","attempt_count","overlay_count"}) row.Remove(key);
                row["migration_role_can_create_role"]=CanCreateRole;row["observations"]=Observations.Count;row["terminal_unresolved_receipts"]=Observations.Count;rows.Add(row);
            }
            else if(sql==RadiusReconciliationSql.Markers) rows.Add(new(){["version"]=61,["name"]=Control.MigrationNames[61]});
            else if(sql==RadiusReconciliationSql.Terminal) rows.AddRange(Observations.Select(Clone));
            else if(sql.StartsWith(Control.EvidencePage,StringComparison.Ordinal))
            {
                IEnumerable<JsonObject> page=Manifests.OrderBy(m=>Control.Number(m,"cursor_start_byte_offset")).ThenBy(m=>Control.Number(m,"batch_record_ordinal")).ThenBy(m=>ControlText(m,"evidence_uid"),StringComparer.Ordinal);
                if(args.Length==6) page=page.Where(m=>(Control.Number(m,"cursor_start_byte_offset"),Control.Number(m,"batch_record_ordinal"),ControlText(m,"evidence_uid")).CompareTo(((long)args[3]!, (long)args[4]!, (string)args[5]!))>0);
                rows.AddRange(page.Take(PageSize).Select(Clone));
            }
            else if(sql.StartsWith("select sli_radius_resolve_principal_key",StringComparison.Ordinal)) rows.Add(new(){["exact_principal_key"]="entity:101"});
            else if(sql.StartsWith("set local role ",StringComparison.Ordinal)) Role=sql[15..];
            else if(sql=="reset role") Role="session_owner";
            else if(sql.StartsWith("select observation.evidence_uid::text",StringComparison.Ordinal))
            {
                var original=Observations.Single(o=>ControlText(o,"observation_id")==args[0]!.ToString());
                rows.Add(new(){["evidence_uid"]=original["evidence_uid"]!.DeepClone(),["identity_state"]="unresolved",["terminal"]=true});
            }
            else if(sql.StartsWith("select attempt_key",StringComparison.Ordinal)) rows.AddRange(Overlays.Where(o=>ControlText(o,"observation_id")==args[0]!.ToString()).Select(Clone));
            else if(sql.StartsWith("select exists(select 1 from entities_v2",StringComparison.Ordinal)) rows.Add(new(){["present"]=true});
            else if(sql.StartsWith("insert into radius_session_reconciliation_attempts",StringComparison.Ordinal))
                Attempts.Add(new(){["observation_id"]=args[1]!.ToString(),["outcome"]=(string)args[3]!});
            else if(sql.StartsWith("insert into radius_session_identity_overlays",StringComparison.Ordinal))
                Overlays.Add(new(){["observation_id"]=args[0]!.ToString(),["session_identity_key"]=(string)args[3]!,["exact_principal_key"]=(string)args[4]!});
            else if(sql==RadiusReconciliationSql.ProjectionRequests)
                rows.AddRange(((Guid[])args[1]!).Select(id=>new JsonObject { ["delivery_id"]=1L,["session_identity_key"]=Overlays.Single(o=>ControlText(o,"observation_id")==id.ToString("D"))["session_identity_key"]!.DeepClone() }));
            else if(sql==RadiusConsumerSql.OverlayReadable+" as readable") rows.Add(new(){["readable"]=true});
            else if(sql==RadiusConsumerSql.ProjectionLock || sql==RadiusConsumerSql.DeleteProjection) { }
            else if(sql==RadiusConsumerSql.ObservationsOverlay.Replace("limit $4","",StringComparison.Ordinal))
                foreach(var overlay in Overlays.Where(o=>ControlText(o,"session_identity_key")==(string)args[1]!))
                {
                    var o=Clone(Observations.Single(o=>ControlText(o,"observation_id")==ControlText(overlay,"observation_id")));
                    o["identity_state"]="exact";o["session_identity_key"]=overlay["session_identity_key"]!.DeepClone();o["exact_principal_key"]=overlay["exact_principal_key"]!.DeepClone();rows.Add(o);
                }
            else if(sql==RadiusConsumerSql.InsertProjection) Projections.Add(new(){["session_identity_key"]=(string)args[1]!});
            else if(sql==RadiusReconciliationSql.Postcondition) rows.Add(new(){["attempt_count"]=Attempts.Count,["projected_attempt_count"]=Overlays.Count,["still_unresolved_attempt_count"]=Attempts.Count-Overlays.Count,
                ["overlay_count"]=Overlays.Count,["projection_row_count"]=Projections.Count,["original_unresolved_observation_count"]=Observations.Count,["original_unresolved_receipt_count"]=Observations.Count});
            else if(Control.MigrationNames.Where(x=>x.Key!=61).Any(x=>sql.Contains($"values ({x.Key},",StringComparison.Ordinal) || sql.Contains($"values({x.Key},",StringComparison.Ordinal)))
            { if(sql.Contains("set local role adlog_storage_owner",StringComparison.Ordinal)) Role="adlog_storage_owner"; }
            else throw new InvalidOperationException("Unexpected SQL: "+sql);
            return Task.FromResult(rows);
        }
        static string ControlText(JsonObject o,string k)=>RadiusReconciliationControl.Text(o,k);
        static string ControlHash(string s)=>RadiusReconciliationControl.Hash(s);
        public void Dispose() { Directory.Delete(Root,true); }
    }

    [Fact] public void PlanBindingRefusesCursorAndPrivilegeDriftBeforeWrites()
    {
        var plan=Plan();var baseline=Clone(plan["baseline"]!.AsObject());Control.ValidatePlanBinding(plan,baseline);
        baseline["cursor_revision"]=4;
        Assert.Equal("production_apply_without_plan_binding",Assert.Throws<RadiusReconciliationException>(()=>Control.ValidatePlanBinding(plan,baseline)).Message);
        baseline=Clone(plan["baseline"]!.AsObject());baseline.Remove("writer_role");
        Assert.Throws<RadiusReconciliationException>(()=>Control.ValidatePlanBinding(plan,baseline));
        plan["plan_schema_version"]=2;Assert.Throws<RadiusReconciliationException>(()=>Control.ValidatePlanBinding(plan,Baseline()));
        plan=Plan();Control.ValidatePlan(plan,Clone(plan));var fresh=Clone(plan);fresh["plan_identity_sha256"]=new string('f',64);
        Assert.Throws<RadiusReconciliationException>(()=>Control.ValidatePlan(plan,fresh));
        fresh=Clone(plan);plan["reconciliation"]!["projected_count"]=1;
        Assert.Throws<RadiusReconciliationException>(()=>Control.ValidatePlan(plan,fresh));
    }
    [Fact] public void PlanBlocksUnprivilegedMigrationAndForeign079Leaves080Ready()
    {
        var baseline=Baseline();baseline["migration_role_can_create_role"]=false;
        var blocked=Plan(baseline);Assert.Equal("blocked",Control.Text(blocked,"status"));
        Assert.Equal("production_reconciliation_migration_role_create_role_required",Assert.Single(blocked["blockers"]!.AsArray())!.GetValue<string>());
        var markers=Control.Markers([new(){["version"]=79,["name"]="plugin_runtime_control_requests"}]);markers[61]=true;
        Assert.False(markers[80]);Assert.False(markers.ContainsKey(79));
        var ready=Control.BuildPlan(Baseline(),markers,Summaries(),new(),new(){["evidence_sha256"]=new string('b',64)},new(){["80"]=new string('c',64)});
        Assert.Equal("ready",Control.Text(ready,"status"));Assert.NotNull(ready["migration_sha256"]!["80"]);Assert.Null(ready["migration_sha256"]!["79"]);
    }
    [Fact] public void OnlyAuthorized83ReceiptsWithConsistentMixedOutcomesAreAdmitted()
    {
        Assert.Empty(Control.AuthorizedBlockers(Summaries().Select(b=>b.Summary)));
        var batches=Summaries();batches[2].Summary["terminal_receipt_count"]=15;
        Assert.Equal("production_reconciliation_batch_scope_invalid",Assert.Single(Control.AuthorizedBlockers(batches.Select(b=>b.Summary))));
        batches=Summaries();batches[0].Summary["projected_count"]=-1;
        Assert.Equal("production_reconciliation_partial_count_invalid",Assert.Single(Control.AuthorizedBlockers(batches.Select(b=>b.Summary))));
        Assert.Equal("production_reconciliation_no_exact_projection",Assert.Single(Control.AuthorizedBlockers(new[]{Summary(17,0),Summary(50,0),Summary(16,0)}.Select(b=>b.Summary))));
    }
    [Fact] public void ResolutionAndTerminalDigestsBindExactLookupAndImmutableEvidence()
    {
        var attempts=new JsonArray(new JsonObject { ["observation_id"]="11111111-1111-1111-1111-111111111111",["evidence_uid"]="22222222-2222-2222-2222-222222222222",
            ["outcome"]="projected",["resolution_input_sha256"]=new string('c',64) });
        var proposal=new JsonObject { ["session_identity_key"]="radius-session:"+new string('d',64),["exact_principal_key"]="entity:101" };
        var proposals=new Dictionary<string,JsonObject> { ["11111111-1111-1111-1111-111111111111"]=proposal };
        string before=Control.ResolutionIdentity(attempts,proposals);proposal["session_identity_key"]="radius-session:"+new string('e',64);proposal["exact_principal_key"]="entity:102";
        Assert.NotEqual(before,Control.ResolutionIdentity(attempts,proposals));
        using var f=new Fixture(1);before=Control.TerminalIdentity(f.Observations);f.Observations[0]["canonical_record_sha256"]=new string('f',64);
        Assert.NotEqual(before,Control.TerminalIdentity(f.Observations));
    }
    [Fact] public async Task LockedPrivilegeDriftStopsBeforeMigrationQueryOrDdl()
    {
        using var f=new Fixture();var plan=await f.Controller.BuildPlanAsync(f.AcceptancePath);f.Calls.Clear();f.CanCreateRole=false;
        var error=await Assert.ThrowsAsync<RadiusReconciliationException>(()=>f.Controller.LockInputsAsync(new("source","example.test",f.Subscription),plan,Markers()));
        Assert.Equal("production_reconciliation_plan_input_drift",error.Message);Assert.Equal(2,f.Calls.Count);
        Assert.Equal(RadiusReconciliationSql.LockedCursor,f.Calls[0].Sql);Assert.Contains("for share",f.Calls[0].Sql);
        Assert.DoesNotContain(f.Calls,c=>c.Sql.Contains("schema_migrations",StringComparison.Ordinal));
    }
    [Fact] public async Task LockedDiscoveryIncludesTerminalIdentityAndRejectsSameCountDrift()
    {
        using var f=new Fixture();var plan=await f.Controller.BuildPlanAsync(f.AcceptancePath);
        await f.Controller.LockInputsAsync(new("source","example.test",f.Subscription),plan,Markers());
        f.Observations[0]["lifecycle_event"]="stop";
        var error=await Assert.ThrowsAsync<RadiusReconciliationException>(()=>f.Controller.LockInputsAsync(new("source","example.test",f.Subscription),plan,Markers()));
        Assert.Equal("production_reconciliation_plan_input_drift",error.Message);
    }
    [Fact] public async Task ReviewedMigrationsUseOuterTransactionAndRestoreSessionRoleEveryVersion()
    {
        using var f=new Fixture();var applied=await f.Controller.ApplyMigrationsAsync(Markers(),Baseline());Assert.Equal(new[]{62,63,64,65,80},applied);
        var bodies=f.Calls.Where(c=>c.Sql!="reset role").ToArray();Assert.Equal(5,bodies.Length);Assert.All(bodies,c=>Assert.Equal("session_owner",c.Role));
        Assert.All(bodies,c=>{Assert.DoesNotContain("begin;",c.Sql,StringComparison.OrdinalIgnoreCase);Assert.DoesNotContain("commit;",c.Sql,StringComparison.OrdinalIgnoreCase);});
        Assert.Equal(5,f.Calls.Count(c=>c.Sql=="reset role"));Assert.Equal("session_owner",f.Role);
        Assert.Single(bodies,c=>c.Sql.Contains("create role adlog_radius_session_reconciliation_writer",StringComparison.Ordinal));
        Assert.Throws<RadiusReconciliationException>(()=>Control.MigrationBody("select 1;"));
    }
    [Fact] public async Task CorpusWideAccessAcceptEvidenceCrossesPagesAndTerminalBatches()
    {
        using var f=new Fixture(18);f.PageSize=2;
        var (batches,discovery)=await f.Controller.BuildBatchesAsync(new("source","example.test",f.Subscription));
        Assert.Equal(new long[]{17,1},batches.Select(b=>Control.Number(b.Summary,"terminal_receipt_count")));
        Assert.Equal(new long[]{0,1},batches.Select(b=>Control.Number(b.Summary,"projected_count")));
        Assert.Equal(new long[]{17,0},batches.Select(b=>Control.Number(b.Summary,"still_unresolved_count")));
        Assert.All(batches,b=>Assert.Equal(2,Control.Number(b.Summary,"access_accept_count")));
        Assert.Equal(20,Control.Number(discovery,"manifest_count"));Assert.Equal(2,Control.Number(discovery,"selected_access_accept_count"));
        Assert.Equal(Control.TerminalIdentity(f.Observations),Control.Text(discovery,"terminal_identity_sha256"));
        // Byte-exact outputs computed with the frozen Python batch/attempt builders.
        Assert.Equal("dd0bf10915ae4011b8a1e5daa82e7c98ebbb9e2471b172db5e14945f6405742c",Control.Text(batches[0].Summary,"evidence_corpus_sha256"));
        Assert.Equal("5a2fef3d83762b4cc816296116abaf4b8eb46fb7bd8f23ac29d4a7c84f72ce5e",Control.Text(batches[0].Summary,"attempt_set_sha256"));
        Assert.Equal("c9ff2097e08ca65ef76c23406bc7269aba19d8de7a272075e2b17bfa1c2aa577",Control.Text(batches[1].Summary,"evidence_corpus_sha256"));
        var proposal=Assert.Single(batches[1].Proposals).Value;
        Assert.Equal("radius-session:9bc3879e1e9b046543709d50e1d0dd2f07cea8d5b6c1d6f47939d242336c2057",Control.Text(proposal,"session_identity_key"));
        Assert.Equal("10ecd3cb3f57816852d719c93d0f319b04b124f003b3b13e66f01577331cb1e5",Control.Text(proposal,"resolution_input_sha256"));
        Assert.All(f.Calls.Where(c=>c.Sql.StartsWith(Control.EvidencePage,StringComparison.Ordinal) || c.Sql==RadiusReconciliationSql.Subscriptions),c=>Assert.Equal(new object?[]{"source",Control.Stream,Control.Transport},c.Args.Take(3)));
    }
    [Fact] public async Task ExactBridgeRejectsConflictingPrincipalsAndChangedTerminalTimestamp()
    {
        using var f=new Fixture(18);
        var observations=new[]{f.Observations[17]};
        var records=f.Manifests.ToDictionary(m=>Control.Text(m,"evidence_uid"),m=>File.ReadAllText(f.EvidencePath(m)));
        records[Control.Text(f.Manifests[^1],"evidence_uid")]=Line("2","cross-batch-class").Replace("CN=User","CN=Other",StringComparison.Ordinal);
        var scope=new Control.Scope("source","example.test",f.Subscription);
        var conflict=await Assert.ThrowsAsync<RadiusReconciliationException>(()=>Control.BuildBatchAsync(scope,records,observations,
            dn=>Task.FromResult<string?>(dn.Contains("CN=Other",StringComparison.Ordinal)?"entity:102":"entity:101")));
        Assert.Equal("production_reconciliation_class_identity_conflict",conflict.Message);
        observations[0]["observed_at_utc"]="2026-08-11T05:00:01Z";
        var timestamp=await Assert.ThrowsAsync<RadiusReconciliationException>(()=>Control.BuildBatchAsync(scope,records,observations,_=>Task.FromResult<string?>("entity:101")));
        Assert.Equal("production_reconciliation_timestamp_mismatch",timestamp.Message);
    }
    [Fact] public void EvidenceMustMatchBothManifestHashesSizeAndUtf8()
    {
        using var f=new Fixture(1);var manifest=Clone(f.Manifests[0]);
        Assert.Equal(File.ReadAllText(f.EvidencePath(manifest)),f.Controller.ReadVerifiedRecord(manifest));
        manifest["object_size_bytes"]=1;
        Assert.Equal("production_reconciliation_evidence_size_mismatch",Assert.Throws<RadiusReconciliationException>(()=>f.Controller.ReadVerifiedRecord(manifest)).Message);
        manifest=Clone(f.Manifests[0]);manifest["canonical_record_sha256"]=new string('0',64);
        Assert.Equal("production_reconciliation_evidence_hash_mismatch",Assert.Throws<RadiusReconciliationException>(()=>f.Controller.ReadVerifiedRecord(manifest)).Message);
        manifest=Clone(f.Manifests[0]);byte[] invalid=[0xff];File.WriteAllBytes(f.EvidencePath(manifest),invalid);
        manifest["object_size_bytes"]=1;manifest["canonical_record_sha256"]=Control.Hash(invalid);manifest["object_sha256"]=Control.Hash(invalid);
        Assert.Equal("production_reconciliation_evidence_utf8_invalid",Assert.Throws<RadiusReconciliationException>(()=>f.Controller.ReadVerifiedRecord(manifest)).Message);
    }
    [Fact] public async Task ScanTraversesCorpusBeyondLegacyRunLimitAndShowsProgress()
    {
        using var f=new Fixture(1);
        for(int i=0;i<2251;i++) f.AddEvidence(Line("1",""),100+i,0);
        var result=await f.Controller.ScanEvidenceAsync(new("source","example.test",f.Subscription),f.Observations.Select(o=>Control.Text(o,"evidence_uid")));
        Assert.Equal(2254,result.Manifests.Count);Assert.Equal(2,result.Accepts.Count);Assert.True(f.Progress.Count>1);
        Assert.Contains("manifests=2254",f.Progress[^1]);Assert.Contains("cursor=",f.Progress[^1]);
    }
    [Fact] public void DisposableAcceptanceBindsBothMigrationsRollbackAndEverySafetyOutcome()
    {
        using var f=new Fixture(1);Assert.Equal(Control.Hash(File.ReadAllBytes(f.AcceptancePath)),Control.Text(f.Controller.ValidateDisposableAcceptance(f.AcceptancePath),"evidence_sha256"));
        var acceptance=Acceptance(f.RepositoryRoot);
        foreach(var key in acceptance["acceptance"]!.AsObject().Where(k=>k.Value is JsonValue v && v.TryGetValue<bool>(out _)).Select(k=>k.Key).ToArray())
        {
            var changed=Clone(acceptance);changed["acceptance"]![key]=false;File.WriteAllText(f.AcceptancePath,changed.ToJsonString());
            Assert.Equal("production_reconciliation_disposable_acceptance_invalid",Assert.Throws<RadiusReconciliationException>(()=>f.Controller.ValidateDisposableAcceptance(f.AcceptancePath)).Message);
        }
        acceptance["projection_forward_sha256"]=new string('0',64);File.WriteAllText(f.AcceptancePath,acceptance.ToJsonString());
        Assert.Throws<RadiusReconciliationException>(()=>f.Controller.ValidateDisposableAcceptance(f.AcceptancePath));
        Assert.Equal("production_reconciliation_disposable_acceptance_required",Assert.Throws<RadiusReconciliationException>(()=>f.Controller.ValidateDisposableAcceptance(Path.Combine(f.Root,"missing.json"))).Message);
    }
    [Fact] public void MigrationStateOnlyAcceptsDependencyPrefixAndExactControlledMarkers()
    {
        var markers=Markers();Assert.Equal("resumable",Control.MigrationState(markers,Baseline()));markers[63]=true;
        Assert.Equal("inconsistent",Control.MigrationState(markers,Baseline()));
        Assert.Equal("production_reconciliation_migration_version_conflict",Assert.Throws<RadiusReconciliationException>(()=>Control.Markers([new(){["version"]=80,["name"]="unrelated_migration"}])).Message);
        markers=Markers();markers[80]=true;Assert.Equal("inconsistent",Control.MigrationState(markers,Baseline()));
    }
    [Fact] public async Task PostconditionBindsAllSevenQueriesToExactly83ImmutableMembers()
    {
        using var f=new Fixture();var ids=f.Observations.Select(o=>Guid.Parse(Control.Text(o,"observation_id"))).ToArray();await f.Controller.PostconditionAsync(ids);
        var call=Assert.Single(f.Calls);Assert.Equal(7,call.Args.Length);Assert.All(call.Args,arg=>Assert.Same(ids,arg));
        for(int i=1;i<=7;i++) Assert.Contains($"observation_id=any(${i}::uuid[])",call.Sql);
        Assert.Equal("production_reconciliation_postcondition_scope_invalid",(await Assert.ThrowsAsync<RadiusReconciliationException>(()=>f.Controller.PostconditionAsync(ids[..^1]))).Message);
    }
    [Fact] public async Task ApplyRebuildsOnlyProjectedMembersAndPreservesOriginalFactsAndQueue()
    {
        using var f=new Fixture();var before=new JsonArray(f.Observations.Select(o=>(JsonNode)Clone(o)).ToArray()).ToJsonString();
        var plan=await f.Controller.BuildPlanAsync(f.AcceptancePath);Assert.Equal("ready",Control.Text(plan,"status"));
        var result=await f.Controller.ApplyAsync(plan,f.AcceptancePath);Assert.Equal("passed",Control.Text(result,"status"));
        Assert.Equal(83,f.Attempts.Count);Assert.Single(f.Overlays);Assert.Single(f.Projections);
        var call=Assert.Single(f.Calls,c=>c.Sql==RadiusReconciliationSql.ProjectionRequests);
        Assert.Equal(new[]{Guid.Parse(Control.Text(f.Observations[17],"observation_id"))},(Guid[])call.Args[1]!);
        Assert.Equal(83,Control.Number(result["reconciliation"]!.AsObject(),"attempt_count"));Assert.Equal(82,Control.Number(result["reconciliation"]!.AsObject(),"still_unresolved_count"));
        Assert.Equal(before,new JsonArray(f.Observations.Select(o=>(JsonNode)Clone(o)).ToArray()).ToJsonString());
        Assert.DoesNotContain(f.Calls,c=>c.Sql.Contains("update acquisition_stream_cursors",StringComparison.OrdinalIgnoreCase) || c.Sql.Contains("acquisition_delivery_outbox set",StringComparison.OrdinalIgnoreCase));
        Assert.All(f.Calls.Where(c=>c.Sql.StartsWith("insert into radius_session_",StringComparison.Ordinal)),c=>Assert.Equal("adlog_radius_session_reconciliation_writer",c.Role));
        Assert.Equal("session_owner",f.Role);Assert.False(result["source_contacted"]!.GetValue<bool>());Assert.False(result["queue_or_lease_changed"]!.GetValue<bool>());
    }
    [Fact] public void DurableOutputIsExclusivePlanBoundAndFinalizesOnlyItsReservationOnce()
    {
        using var f=new Fixture(1);string output=Path.Combine(f.Root,"artifacts","g11a3","apply.json");var plan=Plan();
        Assert.Throws<RadiusReconciliationException>(()=>RadiusReconciliationCommand.Parse(["--action","apply","--plan","plan.json","--confirmation",Control.Confirmation]));
        string reservation=RadiusReconciliationCommand.PrepareOutput(f.Root,output,plan);
        var reserved=JsonNode.Parse(File.ReadAllBytes(output))!.AsObject();Assert.Equal("apply_started",Control.Text(reserved,"status"));Assert.Equal("unknown",Control.Text(reserved,"production_database_changed"));
        Assert.Equal(Control.Digest(plan),Control.Text(reserved,"plan_sha256"));
        Assert.Throws<RadiusReconciliationException>(()=>RadiusReconciliationCommand.ExclusiveWrite(output,plan));
        Assert.Throws<RadiusReconciliationException>(()=>RadiusReconciliationCommand.PrepareOutput(f.Root,output,plan));
        Assert.Throws<RadiusReconciliationException>(()=>RadiusReconciliationCommand.FinalizeOutput(output,new(){["status"]="passed"},"wrong"));
        RadiusReconciliationCommand.FinalizeOutput(output,new(){["status"]="passed",["production_database_changed"]=true},reservation);
        var final=JsonNode.Parse(File.ReadAllBytes(output))!.AsObject();Assert.Equal("passed",Control.Text(final,"status"));Assert.Equal(reservation,Control.Text(final,"reservation_id"));Assert.Equal(Control.Digest(plan),Control.Text(final,"plan_sha256"));
        Assert.Throws<RadiusReconciliationException>(()=>RadiusReconciliationCommand.FinalizeOutput(output,plan,reservation));
        Assert.Throws<RadiusReconciliationException>(()=>RadiusReconciliationCommand.PrepareOutput(f.Root,Path.Combine(f.Root,"outside.json"),plan));
    }
}
