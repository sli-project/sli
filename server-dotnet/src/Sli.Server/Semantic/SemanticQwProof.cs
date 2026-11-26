using System.Text.Json.Nodes;
using Sli.Server.Agents.FileAudit;

namespace Sli.Server.Semantic;

internal sealed partial class SemanticProduction
{
    internal static async Task VerifyQWContext(ISemanticSession session, JsonObject document, CancellationToken ct)
    {
        string rule = document.Text("rule_id") ?? "", mode = document.Text("evaluation_mode") ?? ""; int revision = (int)document.Number("policy_revision");
        var refs = document["evidence_refs"]!.AsArray(); var scope = refs[0]!["scope"]!.AsObject();
        if (document.Number("rule_version") != 1 || document["policy_revision"] is not JsonValue revisionValue || !revisionValue.TryGetValue<int>(out _) || refs.Select(r => r!.ToJsonString()).Distinct().Count() != refs.Count
            || document["evidence_total"] is not null && (document.Number("evidence_total") < refs.Count || document.Number("evidence_total") > 32768)
            || rule == "qw.file-ransom" && (document.Text("kind") != "ransom" || document.Text("base_severity") != "high" || document.Text("effective_severity") != "high")
            || rule == "qw.nps-denials" && document["threshold_context"] is null || rule == "qw.account-watch" && document["watch_context"] is null
            || rule == "qw.account-decoy" && document["decoy_context"] is null || rule == "qw.file-decoy" && document["file_decoy_context"] is null || rule == "qw.file-acl-broad-write" && document["acl_context"] is null)
            throw new InvalidDataException("qw_signal_invalid");
        if (mode is not ("test" or "shadow" or "enabled") || revision < 1 || refs.Any(x => !JsonNode.DeepEquals(x!["scope"], scope)) || document.Text("quality") is not ("good" or "degraded" or "unknown") || document.Text("conclusion_state") is not ("observed" or "not_found" or "not_checked")) throw new InvalidDataException("qw_signal_invalid");
        if (document["password_threshold_context"] is not null) Detections.PasswordAttacks.Validate(document);
        string processing = document.Text("processing_mode") ?? "live"; if (processing is not ("live" or "historical_replay" or "history_import")) throw new InvalidDataException("qw_processing_mode_invalid");
        var now = SigmaProjection.At(document, "received_at_utc");
        string? contextKey = document["watch_context"] is not null ? "watch_context" : document["decoy_context"] is not null ? "decoy_context" : document["file_decoy_context"] is not null ? "file_decoy_context" : null;
        if (contextKey is not null)
        {
            bool file = contextKey == "file_decoy_context", watch = contextKey == "watch_context";
            if (rule != (file ? "qw.file-decoy" : watch ? "qw.account-watch" : "qw.account-decoy")) throw new InvalidDataException("qw_context_rule_mismatch");
            var context = document[contextKey]!; var definition = Definition(rule, scope, file ? context.Text("agent_id") : null); JsonArray rows;
            if (file) rows = await session.QueryAsync("select * from public.read_file_decoy_observations($1::jsonb,$2,$3,$4)", ct, scope, Guid.Parse(context.Text("agent_id")!), FileCheckpoint(scope, context.Text("agent_id")!, rule, mode, revision, processing), context.Text("observation_key"));
            else rows = await session.QueryAsync($"select * from public.read_account_{(watch ? "watch" : "decoy")}_events($1,$2,$3,$4,$5,$6::uuid)", ct, Guid.Parse(scope.Text("installation_id")!), scope.Text("plugin_id"), scope.Text("source_instance_id"), scope.Text("source_generation"), AccountCheckpoint(scope, watch, mode, revision, processing), Guid.Parse(context.Text("normalized_event_id")!));
            if (rows.Count != 1) throw new InvalidDataException("qw_source_mismatch");
            var rebuilt = file ? EvaluateFileDecoy(definition, context.Text("agent_id")!, rows[0]!, now).Signals : EvaluateAccount(definition, rows[0]!, now, watch).Signals;
            bool same = false;
            foreach (var signal in rebuilt)
            {
                signal!["evaluation_mode"] = mode; signal["policy_revision"] = revision; if (processing != "live") signal["processing_mode"] = processing;
                if (JsonNode.DeepEquals(signal, document)) same = true;
            }
            if (!same) throw new InvalidDataException("qw_source_mismatch");
        }
        if (document["acl_context"] is { } acl)
        {
            ValidateAclDocument(document);
            var portion = (await session.QueryAsync("select public.read_file_acl_portion_v265($1::jsonb,$2) as portion", ct, acl["resource"], acl.Text("portion_id")))[0]?["portion"];
            if (!JsonNode.DeepEquals(portion?["document"], document)) throw new InvalidDataException("file_acl_signal_conflict");
            foreach (var member in acl["members"]!.AsArray())
            {
                var bundle = (await session.QueryAsync("select public.read_file_acl_result_by_id($1::jsonb,$2,$3) as bundle", ct, acl["resource"], member.Text("result_id"), member.Text("result_sha256")))[0]?["bundle"];
                if (bundle.Text("status") != "verified") throw new InvalidDataException("file_acl_native_verdict_blocked");
                var result = bundle!["result"]!.AsObject(); var config = bundle["config"]!.DeepClone().AsObject(); config["service_account_exclusions"] ??= new JsonArray();
                var snapshot = bundle["snapshot"]!.DeepClone().AsObject(); snapshot["agent_id"] = acl["resource"]!["agent_id"].Copy(); snapshot["source_instance_id"] = acl["resource"]!["source_instance_id"].Copy();
                var principals = new JsonObject { [result.Text("subject_sid")!] = result["details"]!["principal"].Copy() };
                if (result.Text("rule_code") is not ("file-audit.broad-write" or "file-audit.direct-user-rights") || result.Text("conclusion_state") != "observed" || !FileAuditPermissionRules.Evaluate(snapshot, config, principals).Any(x => JsonNode.DeepEquals(x, result))) throw new InvalidDataException("file_acl_native_verdict_conflict");
                var details = result["details"]!; var principal = details["principal"]!;
                var root = config["roots"]!.AsArray().Single(x => x.Text("collection_scope_id") == result.Text("collection_scope_id"))!;
                long effective = details.Number("effective_smb_mask"); string? effectiveState = details.Text("effective_smb_state");
                if (config.Text("source_kind") == "workstation" && details.Text("layer") == "ntfs")
                {
                    var obj = snapshot["objects"]!.AsArray().Single(x => x.Text("path") == details.Text("path"))!;
                    var parsed = FileAuditAcl.Parse(obj.Text("dacl")); var (token,complete) = FileAuditPermissionRules.Token(result.Text("subject_sid")!,principal.AsObject(),snapshot["local_groups"]!.AsObject());
                    effective = parsed.Complete && complete ? FileAuditAcl.AccessMask(parsed.Aces,token) : 0; effectiveState = parsed.Complete && complete ? "dacl_model" : "requires_review";
                }
                if (result.Text("rule_code") == "file-audit.direct-user-rights" && root.Flag("important") && principal.Text("kind") == "user" && principal.Flag("enabled") && details.Text("layer") == "ntfs" && details.Flag("membership_complete") && effectiveState == "dacl_model" && effective > 0)
                {
                    var obj = snapshot["objects"]!.AsArray().Single(x => x.Text("path") == details.Text("path"))!; var parsed = FileAuditAcl.Parse(obj.Text("dacl"));
                    uint direct = parsed.Complete ? FileAuditAcl.AccessMask(parsed.Aces.Where(x => x.Sid == result.Text("subject_sid") && !x.Inherited).ToArray(), new HashSet<string> { result.Text("subject_sid")! }) : 0;
                    if ((effective & direct & 0xd0046) != 0) throw new InvalidDataException("file_acl_medium_required");
                }
                var nativeResource = acl["resource"]!.DeepClone().AsObject();
                foreach (string field in new[] { "agent_id","source_instance_id","collection_scope_id" }) nativeResource[field] = result[field].Copy();
                if (FileAclResourceKey(nativeResource) != document.Text("entity_key")) throw new InvalidDataException("file_acl_native_verdict_conflict");
            }
        }
        if (document["threshold_context"] is { } threshold)
        {
            string[] fields = ["count", "previous_count", "threshold", "window_seconds", "surge_factor", "dimension", "comparison", "current_quality", "previous_quality", "from_utc", "to_utc", "identity_state"];
            if (!threshold.AsObject().Select(x => x.Key).Order().SequenceEqual(fields.Order()) || rule != "qw.nps-denials" || document.Number("rule_version") != 1 || document.Text("kind") != "threshold") throw new InvalidDataException("nps_context_invalid");
            foreach (string field in new[] { "count","previous_count","threshold","window_seconds","surge_factor" })
                if (threshold[field] is not JsonValue number || number.GetValueKind() != System.Text.Json.JsonValueKind.Number || !long.TryParse(number.ToJsonString(),out long n) || n < 0 || n > 10000) throw new InvalidDataException("nps_context_invalid");
            long count = threshold.Number("count"), previous = threshold.Number("previous_count"), limit = threshold.Number("threshold"), window = threshold.Number("window_seconds"), factor = threshold.Number("surge_factor");
            if (threshold.Text("current_quality") is not ("good" or "partial" or "stale" or "not_collected" or "truncated") || threshold.Text("previous_quality") is not ("good" or "partial" or "stale" or "not_collected" or "truncated") || threshold.Text("identity_state") is not ("unknown" or "observed")) throw new InvalidDataException("nps_context_invalid");
            bool good = threshold.Text("current_quality") == "good" && threshold.Text("previous_quality") == "good"; string comparison = threshold.Text("comparison")!;
            string hash = Digest(new JsonObject { ["contract"] = "sli.nps-threshold.v1", ["dimension"] = threshold["dimension"].Copy(), ["threshold"] = limit, ["window_seconds"] = window, ["surge_factor"] = factor });
            if (count > 10000 || previous > 10000 || previous < 0 || limit < 1 || count < limit || window is < 60 or > 3600 || factor is < 2 or > 100 || threshold.Text("dimension") is not ("account" or "nas_identifier" or "network_policy" or "reason_code" or "client_ip") || comparison is not ("threshold" or "surge" or "new_activity") || comparison == "surge" && (!good || previous <= 0 || count < factor * previous) || SigmaProjection.At(threshold, "to_utc") - SigmaProjection.At(threshold, "from_utc") != TimeSpan.FromSeconds(window) || document.Text("rule_sha256") != hash || document.Text("base_severity") != (comparison == "surge" ? "high" : "medium") || document.Text("effective_severity") != document.Text("base_severity") || document.Text("quality") != (good ? "good" : "degraded")) throw new InvalidDataException("nps_context_invalid");
        }
    }
    internal static string FileAclResourceKey(JsonObject resource)
    {
        string[] keys = ["installation_id","plugin_id","agent_id","source_instance_id","collection_scope_id"];
        if (resource.Count != keys.Length || resource.Any(p => !keys.Contains(p.Key) || p.Value is not System.Text.Json.Nodes.JsonValue value || !value.TryGetValue<string>(out var s) || s.Length is < 1 or > 256) || resource.Text("plugin_id") != "sli.file-audit") throw new InvalidDataException("file_acl_resource_invalid");
        foreach (string key in new[] { "installation_id","agent_id" }) if (!Guid.TryParseExact(resource.Text(key),"D",out var id) || id.ToString() != resource.Text(key)) throw new InvalidDataException("file_acl_resource_invalid");
        return Digest(new JsonArray("file-acl-resource.v1",resource["installation_id"].Copy(),resource["agent_id"].Copy(),resource["source_instance_id"].Copy(),resource["collection_scope_id"].Copy()));
    }
    internal static void ValidateAclDocument(JsonObject document)
    {
        void Require(bool value) { if (!value) throw new InvalidDataException("file_acl_signal_invalid"); }
        var ctx = document["acl_context"]!.AsObject(); var resource = ctx["resource"]!.AsObject(); string key = FileAclResourceKey(resource);
        Require(ctx.Count == 6 && new[] { "version","resource","resource_key","portion_id","proof_sha256","members" }.All(ctx.ContainsKey) && ctx.Text("version") == "sli.file-acl-context.v1" && ctx["members"] is JsonArray { Count: > 0 and <= 32 } && EncodingSize(ctx) <= 49152);
        Require(document.Text("kind") == "acl" && document.Text("rule_id") == "qw.file-acl-broad-write" && document.Number("rule_version") == 1 && document.Text("rule_sha256") == Digest(new JsonArray("sli.qw.file-acl-broad-write.v1","everyone","medium","native-v265")) && document.Text("entity_key") == key && ctx.Text("resource_key") == key && document.Text("episode_key") == Digest(new JsonArray("file-acl-episode.v1",key,"qw.file-acl-broad-write")) && document.Text("base_severity") == "medium" && document.Text("effective_severity") == "medium" && document["severity_reasons"] is JsonArray { Count: 0 } && document.Text("conclusion_state") == "observed" && document.Number("policy_revision") == 1 && new[] { "threshold_context","decoy_context","file_decoy_context","watch_context" }.All(c => document[c] is null));
        var members = ctx["members"]!.AsArray(); var ids = new List<string>(); var refs = new JsonArray();
        bool Hash(JsonNode? value) => value is JsonValue v && v.TryGetValue<string>(out var text) && System.Text.RegularExpressions.Regex.IsMatch(text,@"\A[a-f0-9]{64}\z");
        foreach (var member in members)
        {
            Require(member is JsonObject m && m.Count == 6 && new[] { "result_id","result_sha256","snapshot_id","snapshot_sha256","command_id","domain_id" }.All(m.ContainsKey));
            Require(Hash(member!["result_id"]) && Hash(member["result_sha256"]) && Hash(member["snapshot_sha256"]) && member["domain_id"] is JsonValue domain && domain.GetValueKind() == System.Text.Json.JsonValueKind.Number && long.TryParse(domain.ToJsonString(),out long d) && d > 0 && System.Text.RegularExpressions.Regex.IsMatch(member.Text("command_id") ?? "",@"\A[a-zA-Z0-9_-]{1,128}\z") && Guid.TryParseExact(member.Text("snapshot_id"),"D",out var snapshot) && snapshot.ToString() == member.Text("snapshot_id"));
            ids.Add(member.Text("result_id")!); var scope = new JsonObject { ["installation_id"] = resource["installation_id"].Copy(), ["plugin_id"] = "sli.file-audit", ["source_instance_id"] = resource["source_instance_id"].Copy(), ["source_generation"] = "audit-command:" + member.Text("command_id"), ["collection_scope_id"] = resource["collection_scope_id"].Copy() };
            var reference = Reference(scope,"file_audit_snapshot",member.Text("snapshot_id")!,member.Text("snapshot_sha256")!); if (!refs.Any(r => JsonNode.DeepEquals(r,reference))) refs.Add(reference);
        }
        var actual = document["evidence_refs"]!.AsArray(); Require(ids.SequenceEqual(ids.Distinct().Order(StringComparer.Ordinal)) && members.Select(m => m.Number("domain_id")).Distinct().Count() == 1 && actual.Count == refs.Count && actual.All(r => refs.Any(e => JsonNode.DeepEquals(r,e))) && document.Number("evidence_total") == refs.Count && ctx.Text("portion_id") == Digest(new JsonArray("file-acl-portion.v1",key,members.DeepClone())) && ctx.Text("proof_sha256") == Digest(new JsonArray("file-acl-proof.v1",key,members.DeepClone())));
    }
}
