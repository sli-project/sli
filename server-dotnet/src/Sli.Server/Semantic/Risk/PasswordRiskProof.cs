using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic.Password;

namespace Sli.Server.Semantic.Risk;

internal static class PasswordRiskProof
{
    internal static async Task<PasswordRiskSignal> LoadSignal(RiskSql sql,string id,CancellationToken ct)
    {
        var rows=await sql.Rows("select signal_id,evaluation_mode,document_json from public.semantic_qw_signals where signal_id=@id",ct,("id",id));
        RiskJson.Require(rows.Count==1,"password_risk_signal_unavailable");var signal=PasswordRiskSignal.Read(RiskJson.Obj(rows[0]["document_json"]));
        RiskJson.Require(signal.Id==id&&signal.Mode==RiskJson.String(rows[0],"evaluation_mode"),"password_risk_signal_conflict");return signal;
    }

    internal static async Task<PasswordRiskEpisode> LoadEpisode(RiskSql sql,PasswordRiskSignal signal,CancellationToken ct)
    {
        var rows=await sql.Rows("select signal_id,document_json from public.read_password_episode_portions_v2(@scope::jsonb,@execution::jsonb,@episode)",ct,("scope",signal.Rule.Scope.Document),("execution",signal.Rule.Execution),("episode",signal.Episode));
        RiskJson.Require(rows.Count is >=1 and <=256,"password_risk_evidence_pending");var signals=new List<PasswordRiskSignal>();
        foreach(var row in rows){var item=PasswordRiskSignal.Read(RiskJson.Obj(row["document_json"]));RiskJson.Require(item.Id==RiskJson.String(row,"signal_id"),"password_risk_chain_invalid");signals.Add(item);}
        return PasswordRiskEpisode.Read(signals,signal.Id);
    }

    internal static async Task<JsonObject?> Lock(RiskSql sql,PasswordRiskSignal signal,CancellationToken ct)
    {
        await sql.Execute("savepoint password_risk_publication_lock",ct);
        try {
            var rows=await sql.Rows("select public.lock_password_publication_v2(@scope::jsonb,@execution::jsonb,@episode) as publication",ct,("scope",signal.Rule.Scope.Document),("execution",signal.Rule.Execution),("episode",signal.Episode));
            await sql.Execute("release savepoint password_risk_publication_lock",ct);
            RiskJson.Require(rows.Count==1&&rows[0]["publication"] is JsonObject,"password_risk_episode_invalid");
            var ledger=RiskJson.Obj(rows[0]["publication"]);return ledger["frozen"]?.GetValue<bool>()==true?null:ledger;
        }catch(PostgresException error)when(error.MessageText=="episode_frozen") {
            await sql.Execute("rollback to savepoint password_risk_publication_lock",ct);await sql.Execute("release savepoint password_risk_publication_lock",ct);return null;
        }
    }

    internal static async Task<IReadOnlyList<PasswordRiskSignal>> ScenarioSignals(RiskSql sql,Guid scenario,PasswordRiskSignal expected,CancellationToken ct)
    {
        var invalid=await sql.Rows("""
            select 1 as invalid from public.semantic_scenario_steps step left join public.semantic_qw_signals signal on signal.signal_id=step.qw_signal_id
            where step.scenario_id=@scenario and (step.source_kind is distinct from 'qw_signal' or step.qw_signal_id is null or signal.signal_id is null) limit 1
            """,ct,("scenario",scenario));RiskJson.Require(invalid.Count==0,"password_risk_scenario_invalid");
        var rows=await sql.Rows("select distinct qw_signal_id from public.semantic_scenario_steps where scenario_id=@scenario order by qw_signal_id limit 257",ct,("scenario",scenario));
        RiskJson.Require(rows.Count is >=1 and <=256,"password_risk_scenario_invalid");var signals=new List<PasswordRiskSignal>();
        foreach(var row in rows) {
            var signal=await LoadSignal(sql,RiskJson.String(row,"qw_signal_id"),ct);
            RiskJson.Require(signal.Rule.Pin==expected.Rule.Pin&&signal.Episode==expected.Episode&&signal.Entity==expected.Entity,"password_risk_scenario_invalid");signals.Add(signal);
        }return signals;
    }

    internal static async Task<IReadOnlyList<PasswordNative>> Native(RiskSql sql,PasswordRule rule,IReadOnlyList<PasswordWitness> witnesses,CancellationToken ct)
    {
        var scope=rule.Scope;
        RiskJson.Require(witnesses.Count<=10000&&witnesses.Sum(w=>(long)w.XmlBytes)<=33554432,"password_risk_proof_bound");
        var rows=await sql.Rows("select * from public.read_password_retained_proof_v2(@scope::jsonb,@refs::jsonb)",ct,("scope",scope.Document),("refs",PasswordJson.Array(witnesses,w=>w.Document)));
        RiskJson.Require(rows.Count==witnesses.Count,"password_risk_native_unavailable");var natives=new List<PasswordNative>();long bytes=0;
        for(int i=0;i<rows.Count;i++) {
            var row=rows[i];RiskJson.Require(RiskJson.Int(row,"occurrence_index")==i+1&&RiskJson.Long(row,"source_event_id")==witnesses[i].NativeId,"password_risk_native_unavailable");
            var native=PasswordNative.Parse(scope,RiskJson.Long(row,"source_event_id"),RiskJson.String(row,"sha256"),RiskJson.Int(row,"event_id"),PasswordJson.Time(row["occurred_at_utc"]),RiskJson.String(row,"source_xml"),rule.NormalizedAccounts);
            bytes+=native.Witness.XmlBytes;RiskJson.Require(bytes<=33554432,"password_risk_proof_bound");
            RiskJson.Require(native.Witness==witnesses[i]&&RiskJson.Int(row,"xml_bytes")==native.Witness.XmlBytes&&RiskJson.String(row,"xml_sha256")==native.Witness.XmlSha256,"password_risk_native_content_conflict");natives.Add(native);
        }return natives;
    }

    internal static async Task VerifyPortion(RiskSql sql,PasswordRiskSignal signal,CancellationToken ct)
    {
        var native=await Native(sql,signal.Rule,signal.Witnesses,ct);
        RiskJson.Require(native.All(n=>n.ProvesEntity(signal.Rule,signal.Entity)),"password_risk_native_entity_conflict");
    }

    private static PasswordWitness ReleaseWitness(JsonNode? document,PasswordScope scope)
    {
        try {
            var d=RiskJson.Obj(document);RiskJson.Require(d.Count==4&&new[]{"ref","at","xml_sha256","xml_bytes"}.All(d.ContainsKey));
            var r=RiskJson.Obj(d["ref"]);RiskJson.Require(r.Count==4&&new[]{"storage_kind","native_id","sha256","scope"}.All(r.ContainsKey)&&JsonNode.DeepEquals(r["scope"],scope.Document));
            var witness=PasswordWitness.Read(d);RiskJson.Require(witness.Scope==scope);return witness;
        }catch(Exception error)when(error is PasswordFailure or PasswordRiskFailure or InvalidOperationException or NullReferenceException or FormatException){throw new PasswordRiskFailure("password_risk_release_invalid");}
    }

    internal static PasswordWitness? Historical(JsonObject ledger,PasswordRiskEpisode episode)
    {
        if(ledger["historical_barrier"]==null)return null;
        var descriptor=RiskJson.Obj(ledger["historical_barrier"]);string[] fields=["version","barrier_episode_key","barrier_first_ledger_revision","barrier_seed","target_last_admitted_revision","target_last_sequence","target_last_emission_id"];
        RiskJson.Require(descriptor.Count==fields.Length&&fields.All(descriptor.ContainsKey)&&RiskJson.String(descriptor,"version")=="sli.password.v2.historical-barrier.1","password_risk_historical_invalid");
        var last=episode.Emissions[^1];
        foreach(var key in new[]{"barrier_episode_key","target_last_emission_id"})RiskJson.Require(PasswordJson.Hex(RiskJson.String(descriptor,key)),"password_risk_historical_invalid");
        foreach(var key in new[]{"barrier_first_ledger_revision","target_last_admitted_revision","target_last_sequence"})RiskJson.Require(RiskJson.Long(descriptor,key)>0,"password_risk_historical_invalid");
        RiskJson.Require(RiskJson.String(descriptor,"barrier_episode_key")!=last.EpisodeKey&&RiskJson.Long(descriptor,"target_last_admitted_revision")<RiskJson.Long(descriptor,"barrier_first_ledger_revision")&&RiskJson.Long(descriptor,"target_last_sequence")==last.Sequence&&RiskJson.String(descriptor,"target_last_emission_id")==last.Id,"password_risk_historical_invalid");
        return ReleaseWitness(descriptor["barrier_seed"],episode.Rule.Scope);
    }

    // Called twice by publication: no native content, verdict or retained proof crosses passes.
    internal static async Task<IReadOnlyList<IReadOnlyList<PasswordWitness>>> VerifyScenario(RiskSql sql,Guid scenario,PasswordRiskSignal signal,CancellationToken ct)
    {
        var members=await ScenarioSignals(sql,scenario,signal,ct);RiskJson.Require(members.All(s=>s.Mode=="enabled"),"password_risk_mode_mismatch");
        var episode=await LoadEpisode(sql,signal,ct);RiskJson.Require(episode.ContainsExactly(members.Select(s=>s.Id)),"password_risk_evidence_pending");
        var ledger=await Lock(sql,signal,ct)??throw new PasswordRiskFailure("password_risk_episode_frozen");
        var witnesses=episode.Witnesses.ToList();int chainCount=witnesses.Count;PasswordWitness? release=null;
        if(ledger["predecessor_episode_key"]!=null) {
            release=ReleaseWitness(ledger["predecessor_endpoint"],episode.Rule.Scope);var seed=ReleaseWitness(ledger["successor_seed"],episode.Rule.Scope);
            RiskJson.Require(seed==episode.Emissions[0].Seed&&RiskJson.Long(ledger,"successor_epoch")==episode.Emissions[0].Epoch&&PasswordJson.Time(ledger["predecessor_tracking_through"])>=seed.At&&seed.At-release.At>TimeSpan.FromSeconds(600),"password_risk_release_invalid");
            if(!witnesses.Contains(release))witnesses.Add(release);
        }
        var historical=Historical(ledger,episode);if(historical!=null&&!witnesses.Contains(historical))witnesses.Add(historical);
        var native=await Native(sql,episode.Rule,witnesses,ct);var budget=episode.Verify(native.Take(chainCount));
        string entity=native[0].Member.EntityFor(signal.Rule)??throw new PasswordRiskFailure("password_risk_native_entity_invalid");
        if(release!=null)RiskJson.Require(native.All(n=>n.ProvesEntity(signal.Rule,entity)),"password_risk_release_invalid");
        var last=episode.Emissions[^1];
        if(historical!=null) {
            var barrier=native.First(n=>n.Witness==historical);var endpoint=native.First(n=>n.Witness==last.Endpoint);
            RiskJson.Require(barrier.Member.EntityFor(signal.Rule)==entity&&endpoint.Witness.At.AddSeconds(600)<barrier.Witness.At,"password_risk_historical_invalid");
        }
        var expected=new JsonObject{["episode_key"]=last.EpisodeKey,["entity"]=entity,["epoch"]=last.Epoch,["root_id"]=episode.Emissions[0].Id,["last_sequence"]=last.Sequence,["last_emission_id"]=last.Id,["totals"]=budget.Document,["frozen"]=false};
        RiskJson.Require(expected.All(p=>JsonNode.DeepEquals(ledger[p.Key],p.Value)),"password_risk_episode_invalid");
        var checkedRows=historical==null
            ?await sql.Rows("select public.assert_password_publication_entity_v2(@scope::jsonb,@execution::jsonb,@episode,@entity) as publication",ct,("scope",signal.Rule.Scope.Document),("execution",signal.Rule.Execution),("episode",signal.Episode),("entity",entity))
            :await sql.Rows("select public.assert_password_publication_entity_v2(@scope::jsonb,@execution::jsonb,@episode,@entity,@historical::jsonb) as publication",ct,("scope",signal.Rule.Scope.Document),("execution",signal.Rule.Execution),("episode",signal.Episode),("entity",entity),("historical",ledger["historical_barrier"]));
        RiskJson.Require(checkedRows.Count==1&&JsonNode.DeepEquals(checkedRows[0]["publication"],ledger),"password_risk_episode_invalid");
        return episode.Emissions.SelectMany(e=>e.Occurrences.Chunk(256).Select(w=>(IReadOnlyList<PasswordWitness>)w)).ToArray();
    }
}
