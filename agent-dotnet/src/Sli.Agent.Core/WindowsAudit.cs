using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

public interface IWindowsAudit
{
    JsonObject Reconcile(AgentPolicy policy, DateTimeOffset now);
}

public interface IWindowsAuditApi
{
    DomainRootAuditSnapshot? ReadDomainRootAudit() => null;
    string WithDomainRootAudit(string sddl) => throw new AgentException("agent_domain_audit_unavailable");
    void SetDomainRootAudit(string domain, string expected, string sddl) => throw new AgentException("agent_domain_audit_unavailable");
    Dictionary<string, int> Query(IReadOnlyCollection<string> guids);
    void Set(IReadOnlyDictionary<string, int> changes);
    string Ownership();
    string Ownership(IReadOnlyCollection<string> guids) => Ownership();
    bool IsSystem { get; }
    int? CommandLine { get; set; }
    string CommandLineOwnership();
    IReadOnlyDictionary<string, string> PolicyNames(IReadOnlyCollection<string> guids) => new Dictionary<string, string>();
    JsonObject PowershellLogging() => new() { ["channel_enabled"] = null, ["script_block_logging_enabled"] = null };
}

public sealed record AuditRequirement(string Name, string Guid, int Mask, int[]? Detections = null, bool DomainChanges = false);
public sealed record DomainRootAuditSnapshot(string Domain, string Sddl, bool Configured);

/// <summary>Write intent before mutation, retain original values, verify readback and stop on external drift.</summary>
public sealed class WindowsAuditManager(string directory, IDurableFiles files, IWindowsAuditApi api) : IWindowsAudit
{
    public static readonly AuditRequirement DomainRootRequirement = new("domain_root_sacl", "domain_root_sacl", 1, DomainChanges: true);
    private static AuditRequirement Spec(string name, string suffix, int mask) => new(name, $"0cce{suffix}-69ae-11d9-bed3-505054503030", mask);
    public static readonly AuditRequirement[] AdditionalDcRequirements = [
        // Directory Service Access is high-volume without the agent's 4662 replication-rights filter.
        Spec("directory_service_access", "923b", 1), // 4662
        Spec("other_account_management", "923a", 3), // 4765, 4766, 4794
        Spec("authentication_policy_change", "9230", 1), // 4706, 4707, 4713, 4716, 4739
        Spec("authorization_policy_change", "9231", 1),
    ];
    public static readonly IReadOnlyDictionary<string, AuditRequirement[]> Families = new Dictionary<string, AuditRequirement[]>
    {
        ["logons"] = [Spec("logon", "9215", 3), Spec("logoff", "9216", 1)],
        ["processes"] = [Spec("process_creation", "922b", 1)],
        ["local_admins"] = [Spec("security_group_management", "9237", 1)],
        ["protection"] = [Spec("security_system_extension", "9211", 1), Spec("other_object_access", "9227", 1), Spec("audit_policy_change", "922f", 1)],
        ["usb"] = [Spec("pnp_activity", "9248", 1)],
        ["domain_controller"] = [
            Spec("kerberos_authentication_service", "9242", 3) with { Detections = [1, 2, 5] },
            Spec("kerberos_service_ticket_operations", "9240", 1) with { Detections = [4] },
            Spec("credential_validation", "923f", 3) with { Detections = [1, 2] },
            Spec("logon", "9215", 3) with { Detections = [1, 2, 3] },
            Spec("user_account_management", "9235", 1) with { Detections = [1], DomainChanges = true },
            Spec("security_group_management", "9237", 1) with { Detections = [6] },
            Spec("computer_account_management", "9236", 1) with { DomainChanges = true },
            Spec("audit_policy_change", "922f", 1) with { Detections = [8] },
            Spec("other_object_access", "9227", 1) with { Detections = [10] },
            Spec("directory_service_changes", "923c", 1) with { DomainChanges = true },
            ..AdditionalDcRequirements,
        ],
    };
    private static readonly string[] KnownGuids = Families.Values.SelectMany(value => value).Select(value => value.Guid)
        .Concat(new[] {"921d","9224","9244","9223"}.Select(s => $"0cce{s}-69ae-11d9-bed3-505054503030")).Distinct().ToArray();
    private string StatePath => Path.Combine(directory, "state.json");
    private string RootStatePath => Path.Combine(directory, "domain-root-sacl.json");
    private void Save(JsonObject state) => files.WriteAtomic(StatePath, CanonicalJson.ToBytes(state));
    private JsonObject? _cached;
    private long _revision;
    private DateTimeOffset _checkedAt, _verifyUntil;

    public JsonObject Reconcile(AgentPolicy policy, DateTimeOffset now)
    {
        // Restart, changed assignment and command always force a fresh native read.
        // Brief readback checks also catch the next group-policy refresh after an apply.
        var cacheable = policy.AdDc is not null && policy.FileAuditMasks.Count == 0;
        if (cacheable && _cached is not null && _revision == policy.Revision && now >= _checkedAt
            && now > _verifyUntil && now - _checkedAt < TimeSpan.FromDays(1)) return (JsonObject)_cached.DeepClone();
        if (_cached is null || _revision != policy.Revision) _verifyUntil = now.AddMinutes(2);
        var report = ReconcileNow(policy, now);
        _cached = report["windows_audit"]?["management_state"]?.ToString() == "unknown" ? null : (JsonObject)report.DeepClone();
        _revision = policy.Revision; _checkedAt = now;
        return report;
    }

    private JsonObject ReconcileNow(AgentPolicy policy, DateTimeOffset now)
    {
        var scopedDc = policy.AdDc is not null && policy.FileAuditMasks.Count == 0;
        var ws = policy.Workstations is null ? null : WorkstationPolicy.Parse(policy.Workstations);
        var required = Families.Where(pair => pair.Key == "domain_controller" ? policy.AdDc is not null : ws?.FamilyEnabled(pair.Key) == true).ToDictionary(pair => pair.Key, pair => pair.Value);
        var needed = required.Values.SelectMany(value => value).GroupBy(value => value.Guid).ToDictionary(group => group.Key, group => group.Aggregate(0, (mask, item) => mask | item.Mask));
        foreach (var pair in policy.FileAuditMasks) needed[pair.Key] = needed.GetValueOrDefault(pair.Key) | pair.Value;
        var actual = new Dictionary<string, int>();
        var ownership = "unknown";
        var management = "unknown";
        int? command = null;
        var commandKnown = false;
        var saved = new JsonObject();
        IReadOnlyDictionary<string, string> policyNames = new Dictionary<string, string>();
        var policyGuids = new HashSet<string>();
        try
        {
            var raw = files.ReadAll(StatePath);
            var state = raw is null ? new JsonObject { ["subcategories"] = new JsonObject(), ["command_line"] = null } : JsonNode.Parse(raw)!.AsObject();
            if (raw?.Length > 16384 || !JsonRead.HasExactly(state, "subcategories", "command_line") || state["subcategories"] is not JsonObject subcategories
                || subcategories.Any(item => !KnownGuids.Contains(item.Key))) throw new AgentException("agent_audit_state_invalid");
            foreach (var item in subcategories) ValidateSaved(item.Value, command: false);
            if (state["command_line"] is not null) ValidateSaved(state["command_line"], command: true);
            saved = subcategories;
            actual = api.Query(needed.Keys.Union(saved.Select(item => item.Key)).ToArray());
            ownership = scopedDc ? api.Ownership(needed.Keys.Union(saved.Select(item => item.Key)).ToArray()) : api.Ownership();
            if (scopedDc) policyNames = api.PolicyNames(needed.Keys.ToArray());
            if (ownership == "managed_by_gpo" && policyNames.Count > 0)
            {
                // Native scope resolution is complete: retain the block on each owned
                // setting while unrelated subcategories may still be configured.
                policyGuids.UnionWith(policyNames.Keys);
                ownership = "ok";
            }
            command = api.CommandLine;
            commandKnown = true;
            var wantCommand = policy.Control.ManageWindowsAudit && policy.Control.AuditProcessCommandLine && required.ContainsKey("processes");
            if ((wantCommand || state["command_line"] is not null) && api.CommandLineOwnership() is var commandOwner && commandOwner != "ok") ownership = commandOwner;
            management = policy.Control.ManageWindowsAudit ? "blocked" : "disabled";
            if (ownership == "ok" && api.IsSystem)
            {
                var hadPrevious = saved.Count > 0 || state["command_line"] is not null;
                var changes = new Dictionary<string, int>();
                var restoring = new List<string>();
                var conflict = false;
                foreach (var pair in saved)
                {
                    var spec = pair.Value!.AsObject();
                    var previous = spec["previous"]!.GetValue<int>();
                    var applied = spec["applied"]!.GetValue<int>();
                    var phase = spec["phase"]!.GetValue<string>();
                    var target = previous | (policy.Control.ManageWindowsAudit ? needed.GetValueOrDefault(pair.Key) : policy.FileAuditMasks.GetValueOrDefault(pair.Key));
                    var current = actual[pair.Key];
                    if (policyGuids.Contains(pair.Key) || phase == "conflict" || phase == "confirmed" && current != applied || current != previous && current != applied && !(phase == "restoring" && current == target))
                    {
                        spec["phase"] = "conflict";
                        conflict = true;
                        continue;
                    }
                    if (target != applied)
                    {
                        spec["phase"] = "restoring";
                        if (current != target) changes[pair.Key] = target;
                        if (target == previous) restoring.Add(pair.Key);
                    }
                }
                if (conflict && !scopedDc) { Save(state); ownership = "managed_by_gpo"; management = "blocked"; }
                else
                {
                    if (policy.Control.ManageWindowsAudit)
                        foreach (var pair in needed)
                        {
                            if (policyGuids.Contains(pair.Key) || saved[pair.Key]?["phase"]?.ToString() == "conflict") continue;
                            if (policy.FileAuditMasks.ContainsKey(pair.Key) && !policy.FileAuditManage && !required.Values.SelectMany(v => v).Any(v => v.Guid == pair.Key)) continue;
                            if (saved[pair.Key]?["phase"]?.GetValue<string>() == "restoring") continue;
                            var previous = saved[pair.Key]?["previous"]?.GetValue<int>() ?? actual[pair.Key];
                            var target = previous | pair.Value;
                            if (target != actual[pair.Key])
                            {
                                saved[pair.Key] = new JsonObject { ["previous"] = previous, ["applied"] = target, ["phase"] = "pending" };
                                changes[pair.Key] = target;
                            }
                        }
                    Save(state);
                    if (changes.Count > 0)
                    {
                        api.Set(changes);
                        actual = api.Query(needed.Keys.Union(saved.Select(item => item.Key)).ToArray());
                        if (changes.Any(pair => actual[pair.Key] != pair.Value))
                        {
                            foreach (var pair in changes)
                            {
                                bool confirmed = scopedDc && actual[pair.Key] == pair.Value;
                                saved[pair.Key]!["phase"] = confirmed ? "confirmed" : "conflict";
                                if (confirmed)
                                {
                                    saved[pair.Key]!["applied"] = pair.Value;
                                    saved[pair.Key]!["enabled_at"] = Iso8601.Format(now);
                                }
                            }
                            Save(state);
                            if (!scopedDc) ownership = "managed_by_gpo";
                            throw new AgentException("agent_audit_readback_failed");
                        }
                        foreach (var pair in changes)
                        {
                            saved[pair.Key]!["applied"] = pair.Value;
                            if (policy.AdDc is not null && Families["domain_controller"].Any(s => s.Guid == pair.Key)) saved[pair.Key]!["enabled_at"] = Iso8601.Format(now);
                        }
                    }
                    foreach (var guid in restoring) saved.Remove(guid);
                    foreach (var pair in saved.Where(p => p.Value?["phase"]?.ToString() != "conflict")) pair.Value!["phase"] = "confirmed";
                    Save(state);
                    var savedCommand = state["command_line"] as JsonObject;
                    if (savedCommand is not null && (savedCommand["phase"]!.GetValue<string>() == "conflict"
                        || savedCommand["phase"]!.GetValue<string>() == "confirmed" && command != savedCommand["applied"]!.GetValue<int>()
                        || command != savedCommand["previous"]?.GetValue<int>() && command != savedCommand["applied"]!.GetValue<int>()))
                    {
                        savedCommand["phase"] = "conflict";
                        Save(state);
                        ownership = "managed_by_gpo";
                        management = "blocked";
                    }
                    else
                    {
                        if (wantCommand && command != 1)
                        {
                            state["command_line"] = new JsonObject { ["previous"] = command, ["applied"] = 1, ["phase"] = "pending" };
                            Save(state);
                            api.CommandLine = 1;
                            command = api.CommandLine;
                            state["command_line"]!["phase"] = command == 1 ? "confirmed" : "conflict";
                            Save(state);
                            if (command != 1) throw new AgentException("agent_audit_readback_failed");
                        }
                        else if (!wantCommand && savedCommand is not null)
                        {
                            savedCommand["phase"] = "restoring";
                            Save(state);
                            api.CommandLine = savedCommand["previous"]?.GetValue<int>();
                            command = api.CommandLine;
                            if (command != savedCommand["previous"]?.GetValue<int>())
                            { savedCommand["phase"] = "conflict"; Save(state); throw new AgentException("agent_audit_readback_failed"); }
                            state["command_line"] = null;
                            Save(state);
                        }
                        management = conflict || policyGuids.Count > 0 ? "blocked" : policy.Control.ManageWindowsAudit ? "applied" : hadPrevious ? "restored" : "disabled";
                    }
                }
            }
            else if (saved.Count > 0 || state["command_line"] is not null) management = "blocked";
        }
        catch (Exception exception) when (exception is not OperationCanceledException) { management = ownership == "managed_by_gpo" || saved.Any(p => p.Value?["phase"]?.ToString() == "conflict") ? "blocked" : "unknown"; }
        var rootAudit = policy.AdDc is not null || files.ReadAll(RootStatePath) is not null ? ReconcileDomainRoot(policy, now) : null;
        var families = new JsonObject();
        foreach (var family in required)
        {
            var rows = new JsonArray();
            var missing = false;
            var unknown = false;
            foreach (var spec in family.Value)
            {
                var known = actual.TryGetValue(spec.Guid, out var mask);
                unknown |= !known;
                missing |= known && (mask & spec.Mask) != spec.Mask;
                var row = new JsonObject { ["subcategory"] = spec.Name, ["guid"] = spec.Guid, ["success"] = (spec.Mask & 1) != 0,
                    ["failure"] = (spec.Mask & 2) != 0, ["actual_success"] = known ? (mask & 1) != 0 : null, ["actual_failure"] = known ? (mask & 2) != 0 : null };
                if (family.Key == "domain_controller")
                {
                    var conflict = saved[spec.Guid]?["phase"]?.ToString() == "conflict";
                    row["state"] = conflict || policyGuids.Contains(spec.Guid) || ownership == "managed_by_gpo" ? "managed_by_gpo" : !known || ownership == "unknown" ? "unknown" : (mask & spec.Mask) == spec.Mask ? "ok" : "missing";
                    row["detections"] = new JsonArray((spec.Detections ?? []).Select(n => (JsonNode?)JsonValue.Create(n)).ToArray());
                    row["domain_changes"] = spec.DomainChanges;
                    row["enabled_at"] = row["state"]!.ToString() == "ok" ? saved[spec.Guid]?["enabled_at"]?.DeepClone() : null;
                    row["policy_name"] = policyNames.GetValueOrDefault(spec.Guid);
                }
                rows.Add(row);
            }
            if (family.Key == "domain_controller")
            {
                var root = rootAudit!;
                rows.Add(root);
                unknown |= root["actual_success"] is null;
                missing |= root["actual_success"]?.GetValue<bool>() == false;
                if (management == "applied" && root["state"]!.ToString() != "ok") management = "blocked";
            }
            string[] channels = family.Key == "protection" ? [WorkstationPolicy.Channels[1], WorkstationPolicy.Channels[2], WorkstationPolicy.Channels[3]]
                : family.Key == "usb" ? [WorkstationPolicy.Channels[4], WorkstationPolicy.Channels[5]] : [];
            families[family.Key] = new JsonObject { ["state"] = ownership != "ok" ? ownership : family.Key == "domain_controller" && rows.Any(r => r?["state"]?.ToString() == "managed_by_gpo") ? "managed_by_gpo" : unknown ? "unknown" : missing ? "missing" : "ok",
                ["required"] = rows, ["non_security_channels"] = new JsonArray(channels.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray()) };
        }
        var report = new JsonObject { ["policy_revision"] = policy.Revision, ["management_state"] = management,
            ["command_line_enabled"] = commandKnown ? command == 1 : null, ["families"] = families };
        if (policy.AdDc is not null) report["checked_at"] = Iso8601.Format(now);
        if (required.ContainsKey("protection"))
        {
            report["powershell_logging"] = new JsonObject { ["channel_enabled"] = null, ["script_block_logging_enabled"] = null };
            try { report["powershell_logging"] = api.PowershellLogging(); }
            catch (Exception exception) when (exception is not OperationCanceledException) { }
        }
        return new JsonObject { ["windows_audit"] = report };
    }

    private JsonObject ReconcileDomainRoot(AgentPolicy policy, DateTimeOffset now)
    {
        var row = new JsonObject { ["subcategory"] = DomainRootRequirement.Name, ["guid"] = DomainRootRequirement.Guid,
            ["success"] = true, ["failure"] = false, ["actual_success"] = null, ["actual_failure"] = null,
            ["state"] = "unknown", ["detections"] = new JsonArray(), ["domain_changes"] = true, ["enabled_at"] = null, ["policy_name"] = null };
        var path = RootStatePath;
        void Persist(JsonObject value) => files.WriteAtomic(path, CanonicalJson.ToBytes(value));
        try
        {
            var current = api.ReadDomainRootAudit();
            if (current is null) return row;
            var raw = files.ReadAll(path);
            JsonObject? state = raw is null ? null : JsonNode.Parse(raw)!.AsObject();
            if (state is not null && (raw!.Length > 1024 * 1024
                || !JsonRead.HasExactly(state, "domain", "previous", "applied", "phase", "enabled_at")
                || new[] { "domain", "previous", "applied" }.Any(k => !JsonRead.TryString(state[k], out var text) || text.Length > 262144)
                || state["phase"]?.ToString() is not ("pending" or "confirmed" or "restoring" or "restored" or "conflict")
                || state["enabled_at"] is not null && !Iso8601.TryParseUtc(state["enabled_at"]?.ToString(), out _)))
                throw new AgentException("agent_audit_state_invalid");
            bool enable = policy.AdDc is not null && policy.Control.ManageWindowsAudit && policy.Control.ManageDomainRootSacl;
            if (state is not null)
            {
                var phase = state["phase"]!.ToString();
                var previous = state["previous"]!.ToString();
                var applied = state["applied"]!.ToString();
                // Never replace changes made by another administrator, even after a restart.
                if (current.Domain != state["domain"]!.ToString() || phase == "conflict"
                    || phase == "confirmed" && current.Sddl != applied
                    || phase == "restored" && current.Sddl != previous
                    || current.Sddl != previous && current.Sddl != applied)
                {
                    state["phase"] = "conflict";
                    Persist(state);
                }
                else if (api.IsSystem && (!enable || phase == "restoring") && phase != "restored")
                {
                    state["phase"] = "restoring"; Persist(state);
                    if (current.Sddl != previous) api.SetDomainRootAudit(current.Domain, current.Sddl, previous);
                    current = api.ReadDomainRootAudit() ?? throw new AgentException("agent_audit_readback_failed");
                    if (current.Domain != state["domain"]!.ToString() || current.Sddl != previous) throw new AgentException("agent_audit_readback_failed");
                    state["phase"] = "restored"; state["enabled_at"] = null; Persist(state);
                }
                else if (api.IsSystem && enable && phase == "pending")
                {
                    if (current.Sddl != applied) api.SetDomainRootAudit(current.Domain, current.Sddl, applied);
                    current = api.ReadDomainRootAudit() ?? throw new AgentException("agent_audit_readback_failed");
                    if (current.Sddl != applied || current.Domain != state["domain"]!.ToString() || !current.Configured) throw new AgentException("agent_audit_readback_failed");
                    state["phase"] = "confirmed"; state["enabled_at"] = Iso8601.Format(now); Persist(state);
                }
            }
            if (api.IsSystem && enable && !current.Configured && (state is null || state["phase"]!.ToString() == "restored"))
            {
                var applied = api.WithDomainRootAudit(current.Sddl);
                state = new JsonObject { ["domain"] = current.Domain, ["previous"] = current.Sddl, ["applied"] = applied,
                    ["phase"] = "pending", ["enabled_at"] = null };
                Persist(state);
                api.SetDomainRootAudit(current.Domain, current.Sddl, applied);
                current = api.ReadDomainRootAudit() ?? throw new AgentException("agent_audit_readback_failed");
                if (current.Domain != state["domain"]!.ToString() || current.Sddl != applied || !current.Configured) throw new AgentException("agent_audit_readback_failed");
                state["phase"] = "confirmed"; state["enabled_at"] = Iso8601.Format(now); Persist(state);
            }
            row["actual_success"] = current.Configured; row["actual_failure"] = false;
            row["state"] = current.Configured ? "ok" : state?["phase"]?.ToString() == "restored" ? "restored" : "missing";
            if (current.Configured && state?["phase"]?.ToString() == "confirmed") row["enabled_at"] = state["enabled_at"]?.DeepClone();
        }
        catch (Exception exception) when (exception is not OperationCanceledException) { }
        return row;
    }

    private static void ValidateSaved(JsonNode? node, bool command)
    {
        if (node is not JsonObject value || !JsonRead.HasExactly(value, value.ContainsKey("enabled_at") ? ["previous", "applied", "phase", "enabled_at"] : ["previous", "applied", "phase"])
            || value.ContainsKey("enabled_at") && (!JsonRead.TryString(value["enabled_at"], out var stamp) || !DateTimeOffset.TryParse(stamp, out _))
            || !JsonRead.TryString(value["phase"], out var phase) || phase is not ("pending" or "confirmed" or "restoring" or "conflict")) throw new AgentException("agent_audit_state_invalid");
        foreach (var key in new[] { "previous", "applied" })
            if (!(command && key == "previous" && value[key] is null) && (!JsonRead.TryInteger(value[key], out var mask) || mask < 0 || mask > (command ? 1 : 3)))
                throw new AgentException("agent_audit_state_invalid");
    }
}
