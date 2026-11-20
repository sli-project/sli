using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Core;
using Sli.Server.Agents.Radius;
using Sli.Server.Compatibility;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Vpn;

public sealed partial class RadiusReconciliationControl
{
    internal const string EvidencePage = """
        select evidence_uid::text,canonical_record_sha256,object_sha256,
               object_size_bytes,cursor_start_byte_offset,batch_record_ordinal
        from core_evidence_manifests
        where source_instance_id=$1 and stream_id=$2 and transport_binding=$3
        """;
    internal static string ManifestIdentity(IEnumerable<JsonObject> manifests) => Hash(string.Join('\n', manifests.Select(m =>
        string.Join('\0', Text(m,"evidence_uid"), Text(m,"canonical_record_sha256"), Text(m,"object_sha256"),
            Number(m,"object_size_bytes").ToString(CultureInfo.InvariantCulture), Number(m,"cursor_start_byte_offset").ToString(CultureInfo.InvariantCulture),
            Number(m,"batch_record_ordinal").ToString(CultureInfo.InvariantCulture)))));
    internal static string TerminalIdentity(IEnumerable<JsonObject> observations) => Hash(string.Join('\n', observations.OrderBy(m => Text(m,"observation_id"),StringComparer.Ordinal).Select(m =>
        string.Join('\0', Text(m,"observation_id"), Text(m,"evidence_uid"), Text(m,"canonical_record_sha256"), Text(m,"lifecycle_event"), Text(m,"timestamp_state"),
            PythonTimestamp(m.At("observed_at_utc"))))));
    static string PythonTimestamp(DateTimeOffset? value)
    {
        if (value is null) return "None";
        var utc=value.Value.UtcDateTime;
        string fraction=utc.Ticks%TimeSpan.TicksPerSecond==0?"":"."+((utc.Ticks%TimeSpan.TicksPerSecond)/10).ToString("D6",CultureInfo.InvariantCulture);
        return utc.ToString("yyyy-MM-dd HH:mm:ss",CultureInfo.InvariantCulture)+fraction+"+00:00";
    }
    internal static string ResolutionIdentity(JsonArray attempts, IReadOnlyDictionary<string,JsonObject> proposals) => Hash(string.Join('\n',
        attempts.Cast<JsonObject>().OrderBy(a => Text(a,"observation_id"),StringComparer.Ordinal).Select(a =>
        {
            proposals.TryGetValue(Text(a,"observation_id"),out var p);
            return string.Join('\0',Text(a,"observation_id"),Text(a,"evidence_uid"),Text(a,"outcome"),Text(a,"resolution_input_sha256"),
                p is null?"":Text(p,"session_identity_key"),p is null?"":Text(p,"exact_principal_key"));
        })));
    internal string ReadVerifiedRecord(JsonObject manifest)
    {
        string uid = Guid.Parse(Text(manifest,"evidence_uid")).ToString("N");
        string path = Path.Combine(evidenceRoot,"published","acquisition-radius",uid[..2],uid+".record");
        byte[] bytes;
        try { bytes = File.ReadAllBytes(path); }
        catch (IOException) { throw Error("evidence_read_failed"); }
        if (bytes.LongLength != Number(manifest,"object_size_bytes")) throw Error("evidence_size_mismatch");
        string hash = Hash(bytes);
        if (hash != Text(manifest,"object_sha256") || hash != Text(manifest,"canonical_record_sha256")) throw Error("evidence_hash_mismatch");
        try { return new UTF8Encoding(false,true).GetString(bytes); }
        catch (DecoderFallbackException) { throw Error("evidence_utf8_invalid"); }
    }
    internal async Task<(List<JsonObject> Manifests, Dictionary<string,string> Accepts, JsonObject Discovery)> ScanEvidenceAsync(Scope scope, IEnumerable<string> terminalUids)
    {
        var manifests = new List<JsonObject>(); var accepts = new Dictionary<string,string>(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal); JsonObject? after = null;
        while (true)
        {
            // Page size controls allocation only; scan continues until the corpus is exhausted.
            string predicate = after is null ? "" : " and (cursor_start_byte_offset,batch_record_ordinal,evidence_uid::text)>($4,$5,$6)";
            object?[] args = after is null ? scope.Binding : [..scope.Binding,Number(after,"cursor_start_byte_offset"),Number(after,"batch_record_ordinal"),Text(after,"evidence_uid")];
            var page = await Query(EvidencePage + predicate + " order by cursor_start_byte_offset,batch_record_ordinal,evidence_uid::text limit 250",args);
            if (page.Count == 0) break;
            foreach (var item in page)
            {
                if (!seen.Add(Text(item,"evidence_uid"))) throw Error("evidence_duplicate");
                string record = ReadVerifiedRecord(item);
                if (PythonInt.TryParse(RadiusAccountingRecord.ParseFields(record)[4].Trim(),out var packet) && packet == 2)
                    accepts.Add(Text(item,"evidence_uid"),record);
                manifests.Add(item);
            }
            after = page[^1];
            progress?.Invoke($"radius_reconciliation identity_scan manifests={manifests.Count} cursor={Number(after,"cursor_start_byte_offset")}:{Number(after,"batch_record_ordinal")}");
        }
        if (manifests.Count == 0) throw Error("authorized_corpus_missing");
        if (terminalUids.Except(seen).Any()) throw Error("observation_corpus_missing");
        return (manifests, accepts, new JsonObject { ["manifest_count"]=manifests.Count, ["manifest_bytes"]=manifests.Sum(m=>Number(m,"object_size_bytes")),
            ["manifest_identity_sha256"]=ManifestIdentity(manifests), ["selected_access_accept_count"]=accepts.Count,
            ["selected_access_accept_sha256"]=ManifestIdentity(manifests.Where(m=>accepts.ContainsKey(Text(m,"evidence_uid"))).OrderBy(m=>Text(m,"evidence_uid"),StringComparer.Ordinal)) });
    }
    internal async Task<(List<Batch> Batches, JsonObject Discovery)> BuildBatchesAsync(Scope scope)
    {
        var observations = await Query(RadiusReconciliationSql.Terminal,scope.Binding);
        if (observations.Select(o=>Text(o,"evidence_uid")).Distinct().Count() != observations.Count) throw Error("terminal_evidence_duplicate");
        var (manifests, accepts, discovery) = await ScanEvidenceAsync(scope,observations.Select(o=>Text(o,"evidence_uid")));
        var built = new List<Batch>();
        await Query("set local role adlog_radius_accounting_worker");
        try
        {
            async Task<string?> Resolve(string dn) => await RadiusIdentity.ResolveAsync(dn,scope.Organization,async candidate =>
                (await Query("select sli_radius_resolve_principal_key($1,$2) as exact_principal_key",UnicodeCaseFold.Fold(PythonText.Strip(scope.Organization)),candidate)).SingleOrDefault() is {} r ? Text(r,"exact_principal_key") is {Length:>0} p ? p : null : null);
            foreach (var group in observations.GroupBy(o=>Number(o,"cursor_start_byte_offset")).OrderBy(g=>g.Key))
            {
                var records = new Dictionary<string,string>(accepts,StringComparer.Ordinal);
                foreach (var observation in group) records[Text(observation,"evidence_uid")] = ReadVerifiedRecord(observation);
                built.Add(await BuildBatchAsync(scope,records,group.ToArray(),Resolve));
                progress?.Invoke($"radius_reconciliation batch={built.Count} observations={group.Count()}");
            }
        }
        finally { await Query("reset role"); }
        discovery["terminal_identity_sha256"] = TerminalIdentity(observations);
        return (built,discovery);
    }
    internal static async Task<Batch> BuildBatchAsync(Scope scope, IReadOnlyDictionary<string,string> records, IReadOnlyList<JsonObject> observations, Func<string,Task<string?>> resolve)
    {
        var bindings = new Dictionary<string,(string Principal,string Record,string Hash)>(StringComparer.Ordinal);
        var hashes = records.ToDictionary(x=>x.Key,x=>Hash(x.Value),StringComparer.Ordinal);
        int accepts=0,unresolved=0;
        foreach (var (uid,line) in records)
        {
            var fields = RadiusAccountingRecord.ParseFields(line);
            if (!PythonInt.TryParse(fields[4].Trim(),out var packet) || packet!=2) continue;
            accepts++;
            string? principal = await resolve(fields[6]); string classValue = fields[26].Trim();
            if (classValue.Length==0 || fields[6].Trim().Length==0) throw Error("access_accept_missing");
            if (string.IsNullOrWhiteSpace(principal)) { unresolved++; continue; }
            if (!Regex.IsMatch(principal,@"\Aentity:[1-9][0-9]*\z")) throw Error("exact_keys_required");
            if (bindings.TryGetValue(classValue,out var prior) && prior.Principal!=principal) throw Error("class_identity_conflict");
            if (!bindings.ContainsKey(classValue) || StringComparer.Ordinal.Compare(hashes[uid],bindings[classValue].Hash)<0)
                bindings[classValue]=(principal,line,hashes[uid]);
        }
        string corpus = Hash(string.Join('\n',hashes.OrderBy(x=>x.Key,StringComparer.Ordinal).Select(x=>x.Key+"\0"+x.Value)));
        var attempts = new JsonArray(); var proposals = new Dictionary<string,JsonObject>(); var seen = new HashSet<string>();
        foreach (var observation in observations.OrderBy(o=>Text(o,"observation_id"),StringComparer.Ordinal))
        {
            string id = Guid.Parse(Text(observation,"observation_id")).ToString("D"), uid=Guid.Parse(Text(observation,"evidence_uid")).ToString("D");
            if (!seen.Add(id)) throw Error("observation_duplicate");
            if (!records.TryGetValue(uid,out var line)) throw Error("observation_evidence_missing");
            var fields = RadiusAccountingRecord.ParseFields(line); string? resolution = null;
            if (bindings.TryGetValue(fields[26].Trim(),out var binding))
            {
                var projected = await RadiusPlanner.ProjectAsync([binding.Record,line],scope.Source,"N. Central Asia Standard Time",420,
                    observation.At("observed_at_utc") ?? throw Error("timestamp_invalid"),new(),_=>Task.FromResult<string?>(binding.Principal));
                var rebuilt = projected.Observations.SingleOrDefault();
                if (rebuilt?.SessionIdentityKey is null) throw Error("session_identity_required");
                if (rebuilt.Lifecycle!=Text(observation,"lifecycle_event")) throw Error("lifecycle_mismatch");
                if (Text(observation,"timestamp_state")!="ready") throw Error("timestamp_ready_required");
                if (rebuilt.ObservedAt!=observation.At("observed_at_utc")) throw Error("timestamp_mismatch");
                resolution = Digest(new JsonObject { ["access_accept_record_sha256"]=binding.Hash,["accounting_record_sha256"]=hashes[uid],
                    ["evidence_uid"]=uid,["exact_principal_key"]=rebuilt.Principal,["observation_id"]=id,["session_identity_key"]=rebuilt.SessionIdentityKey,["source_instance_id"]=scope.Source });
                proposals[id] = new JsonObject { ["observation_id"]=id,["session_identity_key"]=rebuilt.SessionIdentityKey,["exact_principal_key"]=rebuilt.Principal,["resolution_input_sha256"]=resolution };
            }
            attempts.Add(new JsonObject { ["attempt_key"]=Hash(id+"\0"+corpus+"\0"+Resolver),["observation_id"]=id,["evidence_uid"]=uid,
                ["outcome"]=resolution is null?"still_unresolved":"projected",["evidence_corpus_sha256"]=corpus,["resolver_contract_id"]=Resolver,["resolution_input_sha256"]=resolution });
        }
        return new Batch(new JsonObject { ["evidence_record_count"]=records.Count,["terminal_receipt_count"]=observations.Count,["access_accept_count"]=accepts,
            ["unresolved_access_accept_count"]=unresolved,["projected_count"]=proposals.Count,["still_unresolved_count"]=observations.Count-proposals.Count,["evidence_corpus_sha256"]=corpus,
            ["attempt_set_sha256"]=Hash(string.Join('\n',attempts.Cast<JsonObject>().Select(a=>Text(a,"attempt_key")).Order(StringComparer.Ordinal))),
            ["resolution_identity_sha256"]=ResolutionIdentity(attempts,proposals) },attempts,proposals);
    }
}
