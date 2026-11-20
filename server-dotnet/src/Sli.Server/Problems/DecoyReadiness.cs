using System.Text.Json.Nodes;
using Sli.Server.Agents.Ingress;

namespace Sli.Server.Problems;

public static class DecoyReadiness
{
    public static JsonObject Evaluate(string kind, JsonObject identity, bool active, JsonArray accounts, JsonObject agent,
        bool present, JsonObject coverage, DateTimeOffset now)
    {
        var reasons = new List<string>(); JsonNode? observed;
        if (kind == "account")
        {
            var record = accounts.Count == 1 ? ProblemJson.Object(accounts[0]) : new JsonObject();
            var exact = ProblemJson.Object(record["attributes_json"]?["identity"]);
            observed = record["last_observed_at_utc"];
            if (ProblemJson.Text(exact["kind"]) != "ad_user" || ProblemJson.Text(exact["object_sid"]) != ProblemJson.Text(identity["sid"]) ||
                ProblemJson.Text(exact["object_guid"]).ToLowerInvariant() != ProblemJson.Text(identity["guid"])) reasons.Add("identity_unverified");
            if (!ProblemJson.Fresh(observed, now)) reasons.Add("identity_stale");
            reasons.Add("authentication_audit_unverified");
        }
        else
        {
            var audit = ProblemJson.Object(agent["file_audit"]); var request = ProblemJson.Object(audit["request"]);
            var config = ProblemJson.Object(request["config"]); observed = audit["reported_at"];
            var roots = ProblemJson.Array(config["roots"]).OfType<JsonObject>().Where(r => ProblemJson.Text(r["collection_scope_id"]) == ProblemJson.Text(identity["collection_scope_id"])).ToArray();
            var root = roots.Length == 1 ? roots[0] : new JsonObject();
            var modules = ProblemJson.Array(agent["assigned_modules"]).OfType<JsonObject>().Where(m => ProblemJson.Text(m["module_id"]) == "sli.file-audit" && ProblemJson.Bool(m["enabled"])).ToArray();
            JsonObject WithoutRevision(JsonNode? value) { var copy = ProblemJson.Object(value).DeepClone().AsObject(); copy.Remove("policy_revision"); return copy; }
            if (ProblemJson.Text(agent["host_id"]) != ProblemJson.Text(identity["source_instance_id"]) || ProblemJson.Text(agent["status"]) != "active" || modules.Length == 0 ||
                !JsonNode.DeepEquals(WithoutRevision(modules.FirstOrDefault()?["config"]), WithoutRevision(config)) ||
                (agent["collection_policy"]?["state"] is { } state && ProblemJson.Text(state) != "active") || !JsonNode.DeepEquals(agent["applied_policy_revision"], agent["policy_revision"])) reasons.Add("source_not_ready");
            if (!ProblemJson.Fresh(agent["last_seen"], now) || !ProblemJson.Fresh(observed, now)) reasons.Add("audit_stale");
            if (config["source_kind"] is { } profile && ProblemJson.Text(profile) != "server") reasons.Add("server_profile_required");
            bool covered = false;
            if (root.Count > 0)
            {
                try {
                    string path = AgentFileAuditPolicy.NormalizePath(ProblemJson.Text(identity["path"])).ToLowerInvariant();
                    string rootPath = AgentFileAuditPolicy.NormalizePath(ProblemJson.Text(root["path"])).ToLowerInvariant();
                    covered = path == rootPath || path.StartsWith(rootPath.TrimEnd('\\') + "\\", StringComparison.Ordinal);
                } catch (Sli.Agent.Core.AgentException) { }
            }
            if (!covered) reasons.Add("root_not_covered");
            var sacl = ProblemJson.Object(root["sacl"]);
            if (!ProblemJson.Bool(root["important"]) || !ProblemJson.Bool(sacl["inherit_files"]) || !ProblemJson.Array(sacl["trustee_sids"]).Any(s => ProblemJson.Text(s) == "S-1-1-0")) reasons.Add("read_audit_missing");
            if (ProblemJson.Array(config["service_account_exclusions"]).Count > 0) reasons.Add("exclusions_conflict");
            var receipt = ProblemJson.Object(audit["scopes"]?[ProblemJson.Text(identity["collection_scope_id"])]);
            var command = ProblemJson.Object(request["command"]);
            if (ProblemJson.Text(receipt["state"]) != "verified" || ProblemJson.Text(receipt["reason_code"]) != "ok" ||
                ProblemJson.Text(command["action"]) is not ("check" or "apply") || !JsonNode.DeepEquals(command["policy_revision"], config["policy_revision"])) reasons.Add("audit_missing");
            if (!present) reasons.Add("file_unverified");
            if (ProblemJson.Text(coverage["state"]) != "complete" || !ProblemJson.Bool(coverage["read_audit_enabled"]) || coverage["lost_count"] is null || ProblemJson.Long(coverage["lost_count"]) != 0 ||
                !ProblemJson.Fresh(coverage["window_end"], now)) reasons.Add("collection_gap");
        }
        if (!active) reasons.Add("label_disabled");
        var result = new JsonObject { ["state"] = reasons.Count == 0 ? "ready" : "not_ready", ["reasons"] = new JsonArray(reasons.Select(r => (JsonNode?)JsonValue.Create(r)).ToArray()),
            ["checked_at"] = ProblemJson.Iso(now), ["last_observation_at"] = observed?.DeepClone() };
        if (kind == "account") ProblemJson.RawTimes(result, "last_observation_at");
        return result;
    }
}
