using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

public sealed record CollectionControl(string State, int IntervalSeconds, int BatchSize, int RateLimitPerMinute,
    long SpoolMaxBytes, bool ManageWindowsAudit, bool AuditProcessCommandLine)
{
    public bool ManageDomainRootSacl { get; init; }
    public static CollectionControl Parse(JsonNode? node)
    {
        static AgentException Invalid() => new("agent_collection_policy_invalid");
        var allowed = new[] { "state", "interval_seconds", "batch_size", "rate_limit_per_minute", "spool_max_bytes", "manage_windows_audit", "audit_process_command_line", "manage_domain_root_sacl" };
        if (node is not JsonObject body || body.Any(item => !allowed.Contains(item.Key))) throw Invalid();
        long Number(string name, long minimum, long maximum, long fallback)
        {
            if (!body.ContainsKey(name)) return fallback;
            if (!JsonRead.TryInteger(body[name], out var number) || number < minimum || number > maximum) throw Invalid();
            return (long)number;
        }
        bool Flag(string name)
        {
            if (!body.ContainsKey(name)) return false;
            if (body[name] is not JsonValue value || !value.TryGetValue<bool>(out var flag)) throw Invalid();
            return flag;
        }
        var state = body.ContainsKey("state") && JsonRead.TryString(body["state"], out var text) ? text : body.ContainsKey("state") ? "" : "active";
        if (state is not ("active" or "paused" or "drain")) throw Invalid();
        return new(state, (int)Number("interval_seconds", 1, 86400, 60), (int)Number("batch_size", 1, 128, 32),
            (int)Number("rate_limit_per_minute", 1, 10000, 120), Number("spool_max_bytes", 65536, 1073741824, 67108864),
            Flag("manage_windows_audit"), Flag("audit_process_command_line")) { ManageDomainRootSacl = Flag("manage_domain_root_sacl") };
    }
}

public sealed record AgentPolicy(long Revision, CollectionControl Control, JsonArray Assignments, JsonObject? AdDc,
    JsonObject? Workstations, string? RightsProbeRequest)
{
    public IReadOnlyDictionary<string, SnapshotPolicy> Snapshots { get; init; } = new Dictionary<string, SnapshotPolicy>();
    public FileAuditPolicy? FileAudit { get; init; }
    public JsonObject? FileAuditRequest { get; init; }
    public IReadOnlyDictionary<string,int> FileAuditMasks { get; init; } = new Dictionary<string,int>();
    public bool FileAuditManage { get; init; }
    public IReadOnlyDictionary<string, NpsPolicy> NpsModules { get; init; } = new Dictionary<string, NpsPolicy>();
    public RuntimeHandoff? Handoff { get; init; }

    public static AgentPolicy Parse(JsonObject body, string agentId, EventCatalog catalog)
    {
        if (!JsonRead.TryString(body["agent_id"], out var actual) || actual != agentId) throw new AgentException("agent_module_identity_mismatch");
        if (!JsonRead.TryInteger(body["policy_revision"], out var revision) || revision < 1 || revision > 9007199254740991)
            throw new AgentException("agent_policy_revision_invalid");
        var control = CollectionControl.Parse(body["collection_policy"]);
        if (body["assigned_modules"] is not JsonArray modules || modules.Count > 64) throw new AgentException("agent_module_config_invalid");
        JsonObject? dc = null, workstation = null;
        FileAuditPolicy? fileAudit = null;
        var snapshots = new Dictionary<string, SnapshotPolicy>();
        var nps = new Dictionary<string, NpsPolicy>();
        var seen = new HashSet<string>();
        foreach (var node in modules)
        {
            if (node is not JsonObject item || !JsonRead.TryString(item["module_id"], out var moduleId) || !seen.Add(moduleId)
                || item["enabled"] is not JsonValue enabled || !enabled.TryGetValue<bool>(out var on)) throw new AgentException("agent_module_config_invalid");
            if (!on) continue;
            if (moduleId == "sli.heartbeat") continue;
            if (item["config"] is not JsonObject settings) throw new AgentException("agent_module_config_invalid");
            var config = (JsonObject)settings.DeepClone();
            if (moduleId == AdDcModule.ModuleId)
            {
                var parsed = AdDcConfig.Parse(config, catalog);
                config["batch_size"] = Math.Min(parsed.BatchSize, control.BatchSize);
                dc = config;
            }
            else if (moduleId == WorkstationsModule.ModuleId)
            {
                var parsed = WorkstationPolicy.Parse(config);
                config["batch_size"] = Math.Min(parsed.BatchSize, control.BatchSize);
                workstation = config;
            }
            else if (moduleId is SnapshotPolicy.Ad or SnapshotPolicy.Gpo)
                snapshots[moduleId] = SnapshotPolicy.Parse(moduleId, config);
            else if (moduleId == FileAuditPolicy.ModuleId) fileAudit = FileAuditPolicy.Parse(config);
            else if (moduleId is NpsPolicy.Nps or NpsPolicy.Accounting)
            {
                var parsed = NpsPolicy.Parse(moduleId, config);
                // A tighter collection-wide limit is also valid under the owner's module batch bound.
                parsed.Value["batch_size"] = Math.Min(parsed.BatchSize, control.BatchSize);
                if (parsed.Active) nps[moduleId] = parsed;
            }
            else throw new AgentException("agent_module_unsupported");
        }
        if (dc is not null && workstation is not null) throw new AgentException("agent_channel_owner_conflict");
        var fileRequest = body["file_audit"] is JsonObject file ? FileAuditPolicy.ParseRequest(file) : null;
        if (body["file_audit"] is not null && fileRequest is null) throw new AgentException("file_audit_request_invalid");
        string? request = null;
        if (body["rights_probe_request"] is JsonObject probe)
        {
            if (!JsonRead.TryString(probe["request_id"], out request) || !Guid.TryParseExact(request, "D", out _))
                throw new AgentException("agent_rights_probe_invalid");
        }
        return new((long)revision, control, (JsonArray)modules.DeepClone(), dc, workstation, request) { Snapshots = snapshots, FileAudit = fileAudit, FileAuditRequest = fileRequest, NpsModules = nps, Handoff = RuntimeHandoff.Parse(body["runtime_handoff"]) };
    }

    public JsonObject Report(string state, string rightsStatus = "unavailable")
    {
        var body = new JsonObject { ["applied_policy_revision"] = Revision, ["collection_state"] = state, ["runtime_handoff_supported"] = true };
        body["agent_version"]=typeof(AgentPolicy).Assembly.GetName().Version!.ToString(3);
        if (RightsProbeRequest is not null) body["rights_probe"] = new JsonObject { ["request_id"] = RightsProbeRequest, ["status"] = rightsStatus };
        return body;
    }
}
