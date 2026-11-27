using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Agent.Windows;

public interface IFileAuditObject : IDisposable
{
    JsonObject Describe();
    string Plan(JsonArray aces);
    string ExpectedSacl(string value);
    void SetSacl(string value);
    IEnumerable<string> Children();
    bool InheritedFrom(string previous, string applied);
}
public interface IFileAuditApi
{
    string AuditOwnership => "unknown";
    string Preflight(JsonArray roots);
    string Preflight(JsonArray roots, bool describeReadErrors) => Preflight(roots);
    string CheckPreflight(JsonArray roots, bool describeReadErrors) => Preflight(roots, describeReadErrors);
    Dictionary<string,int> QueryMasks(IReadOnlyCollection<string> guids);
    IFileAuditObject Open(string path, string root);
    JsonObject Share(string name, string root);
    JsonObject LocalGroups(int limit, bool allowUnresolvedSid = false);
}
public sealed record FileAuditReconcileResult(JsonObject? Audit, JsonObject? Report);

/// <summary>Durable ownership and inventory. Every mutation has a saved intent and exact native readback.</summary>
public sealed class FileAuditManager(string directory, IDurableFiles files, IFileAuditApi api, Func<TimeSpan>? clock = null)
{
    private static readonly string AgentVersion = typeof(FileAuditManager).Assembly.GetName().Version!.ToString(3);
    private string StatePath => Path.Combine(directory,"state.json");
    private static string Hash(JsonNode value) => Convert.ToHexStringLower(SHA256.HashData(CanonicalJson.ToBytes(value)));
    private static string Text(JsonNode node,string name) => node[name]!.GetValue<string>();
    private static JsonObject Masks(IEnumerable<KeyValuePair<string,int>> values) => new(values.Select(x => new KeyValuePair<string,JsonNode?>(x.Key,JsonValue.Create(x.Value))));
    private void Save(JsonObject state)
    {
        var raw = CanonicalJson.ToBytes(state);
        if (raw.Length > 8*1024*1024) throw new AgentException("file_audit_state_limit");
        files.WriteAtomic(StatePath,raw);
    }
    private JsonObject Load()
    {
        try
        {
            try { if (files.Length(StatePath) > 8*1024*1024) throw new AgentException("file_audit_state_invalid"); }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
            var raw = files.ReadAll(StatePath);
            if (raw is null) return new JsonObject { ["masks"]=new JsonObject(),["objects"]=new JsonObject(),["commands"]=new JsonObject(),["active"]=null,
                ["walks"]=new JsonObject(),["pending_report"]=null,["scan_command"]=null,["completed_at"]=null };
            var s = JsonNode.Parse(raw)!.AsObject();
            if (!JsonRead.HasExactly(s,"masks","objects","commands","active","walks","pending_report","scan_command","completed_at")
                || s["masks"] is not JsonObject masks || s["objects"] is not JsonObject objects || s["commands"] is not JsonObject commands || s["walks"] is not JsonObject walks
                || objects.Count > 100000 || commands.Count > 4096) throw new FormatException();
            var allowed = new[] {"921d","9224","9244","922f","9215","9223"}.Select(x => $"0cce{x}-69ae-11d9-bed3-505054503030").ToHashSet();
            if (masks.Any(x => !allowed.Contains(x.Key) || !JsonRead.TryInteger(x.Value,out var n) || n < 1 || n > 3)) throw new FormatException();
            if (s["active"] is JsonArray active) FileAuditPolicy.Parse(new JsonObject { ["roots"]=active.DeepClone(),["source_kind"]=active.All(r => r!["share_name"]!.ToString() == "") ? "workstation" : "server" });
            var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (path,node) in objects)
            {
                FileAuditPolicy.LocalPath(path);
                if (!paths.Add(path) || node is not JsonObject o || !JsonRead.HasExactly(o,"root","object_id","previous","applied","phase")
                    || !FileAuditPolicy.InRoot(path,Text(o,"root")) || Text(o,"phase") is not ("pending" or "confirmed" or "restoring" or "conflict")
                    || new[] {"object_id","previous","applied"}.Any(k => !JsonRead.TryString(o[k],out var v) || v.Length > 65536)) throw new FormatException();
            }
            foreach (var (_,node) in walks)
            {
                var w = node!.AsObject();
                if (w["stack"] is not JsonArray stack || stack.Count > 100000 || !JsonRead.TryInteger(w["page"],out var page) || page < 0
                    || !JsonRead.TryInteger(w["gaps"],out var gaps) || gaps < 0 || w["done"] is not JsonValue done || !done.TryGetValue<bool>(out _)) throw new FormatException();
                if (!w.ContainsKey("sacl_missing")) w["sacl_missing"]=null;
                foreach (var item in stack)
                {
                    if (item is not JsonArray a || a.Count != 2 || !JsonRead.TryString(a[0],out var path) || !JsonRead.TryInteger(a[1],out var depth) || depth < 0 || depth > 64) throw new FormatException();
                    FileAuditPolicy.LocalPath(path);
                }
            }
            return s;
        }
        catch (Exception e) when (e is System.Text.Json.JsonException or InvalidOperationException or NullReferenceException or FormatException)
        { throw new AgentException("file_audit_state_invalid"); }
    }
    public void Acknowledge(JsonObject report)
    {
        var state = Load();
        if (JsonNode.DeepEquals(state["pending_report"],report)) { state["pending_report"]=null; Save(state); }
    }
    public FileAuditReconcileResult Reconcile(AgentPolicy policy, IWindowsAudit? audit, DateTimeOffset now, bool readDiagnostics = false)
    {
        var state = Load(); // Invalid ownership must also block shared policy writes.
        var parsed = policy.FileAuditRequest is null ? null : FileAuditPolicy.ParseRequest(policy.FileAuditRequest);
        Dictionary<string,int> OwnedMasks() => state["masks"]!.AsObject().ToDictionary(x => x.Key,x => x.Value!.GetValue<int>());
        JsonObject? Shared(bool manage = false) => audit?.Reconcile(policy with { FileAuditMasks=OwnedMasks(),FileAuditManage=manage },now);
        if (parsed is null) return new(Shared(),null);
        var config = FileAuditPolicy.Parse(parsed["config"]!.AsObject()); var cmd = parsed["command"]!.AsObject();
        var key = Text(cmd,"command_id"); var action = Text(cmd,"action");
        var walks = state["walks"]!.AsObject();
        var terminalVersion = walks.Select(walk => walk.Value?["terminal_check_version"]?.ToString())
            .FirstOrDefault(version => version is not null);
        bool sameCommand = state["scan_command"]?.ToString() == key;
        if (state["pending_report"] is JsonObject pending)
        {
            if (terminalVersion is null || sameCommand && terminalVersion == AgentVersion)
                return new(Shared(), (JsonObject)pending.DeepClone());
            // A new command or agent version supersedes a pending terminal check.
            // An apply or restore receipt still has to be delivered in order.
            state["pending_report"] = null;
        }
        var commands = state["commands"]!.AsObject(); var digest = Hash(parsed);
        if (commands[key] is not null && commands[key]!.ToString() != digest) throw new AgentException("file_audit_command_reused");
        if (!commands.ContainsKey(key) && commands.Count >= 4096) throw new AgentException("file_audit_command_limit");
        commands[key]=digest;
        if (sameCommand && terminalVersion == AgentVersion) return new(Shared(), null);
        if (!sameCommand || terminalVersion is not null || state["completed_at"] is not null && now - Iso8601.ParseUtc(state["completed_at"]!.ToString()) >= TimeSpan.FromDays(1))
        { state["scan_command"]=key; state["walks"]=new JsonObject(); state["completed_at"]=null; }
        if (state["completed_at"] is not null) return new(Shared(),null);
        Save(state);
        var selected = new JsonArray(config.Roots.Where(r => cmd["collection_scope_ids"]!.AsArray().Any(id => JsonNode.DeepEquals(id,r!["collection_scope_id"]))).Select(r => r!.DeepClone()).ToArray());
        var selectedConfig = FileAuditPolicy.Parse((JsonObject)config.Value.DeepClone()); selectedConfig.Value["roots"]=selected.DeepClone();
        var required = selectedConfig.RequiredMasks();
        var writable = false; var reason = "ok";
        bool describeReads = readDiagnostics && action == "check" && !config.Workstation && selected.Count == 1;
        FileAuditReadError? readError = null;
        string? preflightFailure = null;
        var stage = "audit_policy";
        JsonObject? applyLocalGroups = null;
        Exception? applyLocalGroupError = null;
        try
        {
            reason = action == "check" ? api.CheckPreflight(selected, describeReads) : api.Preflight(selected, describeReads);
            if (action == "check" && reason == "native_unavailable")
                preflightFailure = reason;
            else if (describeReads && reason is ("unknown" or "global_sacl_unknown"))
            {
                preflightFailure = reason;
                readError = new("audit_policy");
            }
            writable = action != "check" && policy.Control.ManageWindowsAudit && policy.Control.State == "active" && reason == "ok";
            if (writable && action == "apply")
            {
                // Shared can write audit masks even before receiving the file-audit apply flag.
                try { applyLocalGroups = api.LocalGroups(config.Number("inventory_objects"), allowUnresolvedSid: false); }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    applyLocalGroupError = e;
                    writable = false;
                }
            }
            if (writable)
            {
                // A shared ownership conflict must block restores too, before touching any file SACL.
                var shared = Shared();
                if (shared?["windows_audit"]?["management_state"]?.ToString() is "blocked" or "unknown")
                {
                    var effective = api.QueryMasks(required.Keys.ToArray());
                    if (api.AuditOwnership != "managed_by_gpo" || required.Any(p => !effective.TryGetValue(p.Key,out var mask) || (mask&p.Value) != p.Value))
                    { reason="policy_blocked"; writable=false; }
                }
            }
            if (writable)
                foreach (var root in selected.OfType<JsonObject>())
                {
                    stage = "share";
                    if (!InventoryShare(root)["complete"]!.GetValue<bool>()) throw new AgentException("file_audit_share_unavailable");
                    stage = "directory";
                    using var obj = api.Open(Text(root,"path"),Text(root,"path"));
                    stage = "acl";
                    if (Text(obj.Describe(),"object_type") != "directory") throw new AgentException("file_audit_root_invalid");
                }
            stage = "inventory";
            if (action == "apply" && state["active"] is not null && !JsonNode.DeepEquals(state["active"],selected)) { writable=false; reason="restore_required"; }
            if (writable && action == "apply") { state["active"]=selected.DeepClone(); state["masks"]=Masks(required); Save(state); }
            if (writable && action == "restore")
            {
                if (state["active"] is JsonArray active && !active.Select(r => Text(r!,"collection_scope_id")).Order().SequenceEqual(cmd["collection_scope_ids"]!.AsArray().Select(id => id!.ToString()).Order()))
                { writable=false; reason="restore_scope_mismatch"; }
                else
                {
                    reason = RestoreGuard(state,config);
                    if (reason != "ok") writable=false;
                    else Restore(state,config);
                    if (writable && state["objects"]!.AsObject().Count == 0) { state["masks"]=new JsonObject(); state["active"]=null; Save(state); }
                }
            }
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            reason = FileAuditNativeReadException.Reason(stage, e);
            writable = false;
            if (action == "check") preflightFailure = reason;
            if (describeReads) readError = FileAuditNativeReadException.Describe(stage, e);
        }
        var auditReport = applyLocalGroupError is null ? Shared(writable && action == "apply") : null;
        var report = new JsonObject { ["contract_id"]="sli.file-audit.audit-result.v1",["command_id"]=key,["policy_revision"]=cmd["policy_revision"]!.DeepClone(),
            ["action"]=action,["observed_at_utc"]=Iso8601.Format(now),["scopes"]=new JsonArray(),["snapshots"]=new JsonArray(),["ownership_remaining"]=true };
        stage = "audit_policy";
        JsonObject Failed(JsonNode id, string failure) => new()
        {
            ["collection_scope_id"] = id.DeepClone(), ["state"] = "failed", ["reason_code"] = failure,
            ["required_masks"] = new JsonObject(), ["actual_masks"] = new JsonObject()
        };
        try
        {
            if (applyLocalGroupError is not null)
            {
                stage = "local_groups";
                ExceptionDispatchInfo.Throw(applyLocalGroupError);
            }
            if (preflightFailure is not null) throw new AgentException("file_audit_check_read_failed");
            var actual = api.QueryMasks(required.Keys.Union(OwnedMasks().Keys).ToArray());
            stage = "inventory";
            var policyOk = OwnedMasks().All(x => (actual.GetValueOrDefault(x.Key) & x.Value) == x.Value);
            if (auditReport?["windows_audit"]?["management_state"]?.ToString() is "unknown" or "blocked"
                && !(api.AuditOwnership == "managed_by_gpo" && reason == "ok" && policyOk)) { writable=false; if (reason == "ok") reason="policy_blocked"; }
            foreach (var root in selected.OfType<JsonObject>())
            {
                var scopeId = Text(root,"collection_scope_id");
                if (state["walks"]![scopeId]?["done"]?.GetValue<bool>() == true) continue;
                JsonObject scope, snapshot;
                try
                {
                    (scope,snapshot) = Inventory(state,root,config,cmd,now,writable && action == "apply" && policyOk,
                        value => stage = value, applyLocalGroups);
                }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    scope = Failed(root["collection_scope_id"]!, FileAuditNativeReadException.Reason(stage, e));
                    if (describeReads) scope["read_error"] = FileAuditNativeReadException.Describe(stage, e).ToJson();
                    if (action == "check") state["walks"]![scopeId]!["done"] = true;
                    report["scopes"]!.AsArray().Add(scope);
                    break;
                }
                if (action == "check" && reason != "ok" || action != "check" && !writable)
                {
                    scope["state"]="blocked"; scope["reason_code"]=reason == "ok" ? "management_disabled" : reason;
                    if (action != "check") ResetWalk(state,root);
                }
                else if (action == "restore" && state["objects"]!.AsObject().Count > 0) { scope["state"]="partial"; scope["reason_code"]="restore_incomplete"; ResetWalk(state,root); }
                var rootConfig = (JsonObject)config.Value.DeepClone(); rootConfig["roots"]=new JsonArray(root.DeepClone());
                var masks = FileAuditPolicy.Parse(rootConfig).RequiredMasks(); scope["required_masks"]=Masks(masks);
                scope["actual_masks"]=new JsonObject(masks.Keys.Select(g => new KeyValuePair<string,JsonNode?>(g,actual.TryGetValue(g,out var n) ? JsonValue.Create(n) : null)));
                if (scope["state"]!.ToString() == "verified" && action != "restore" && masks.Any(x => (actual.GetValueOrDefault(x.Key) & x.Value) != x.Value)) { scope["state"]="partial"; scope["reason_code"]="policy_missing"; }
                report["scopes"]!.AsArray().Add(scope); report["snapshots"]!.AsArray().Add(snapshot); break;
            }
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            var failure = preflightFailure ?? FileAuditNativeReadException.Reason(stage, e);
            report["scopes"]=new JsonArray(cmd["collection_scope_ids"]!.AsArray().Select(id => (JsonNode?)Failed(id!, failure)).ToArray());
            report["snapshots"]=new JsonArray();
            if (describeReads)
                report["scopes"]![0]!["read_error"] = (readError ?? FileAuditNativeReadException.Describe(stage, e)).ToJson();
        }
        report["ownership_remaining"]=state["objects"]!.AsObject().Count > 0 || state["masks"]!.AsObject().Count > 0;
        state["pending_report"]=report.DeepClone();
        if (action == "check" && report["scopes"]!.AsArray().Count == cmd["collection_scope_ids"]!.AsArray().Count
            && report["scopes"]!.AsArray().All(scope => scope?["state"]?.ToString() == "failed"
                && scope["reason_code"]?.ToString() == "native_unavailable"))
        {
            foreach (var id in cmd["collection_scope_ids"]!.AsArray())
                state["walks"]![id!.ToString()] = new JsonObject {
                    ["stack"] = new JsonArray(), ["page"] = 0, ["gaps"] = 0, ["done"] = true, ["terminal_check_version"] = AgentVersion
                };
        }
        if (cmd["collection_scope_ids"]!.AsArray().All(id => state["walks"]![id!.ToString()]?["done"]?.GetValue<bool>() == true)) state["completed_at"]=Iso8601.Format(now);
        Save(state); return new(auditReport,report);
    }
    private static void ResetWalk(JsonObject state,JsonObject root)
    {
        var walk = state["walks"]![Text(root,"collection_scope_id")]!;
        walk["done"]=false; walk["stack"]=new JsonArray(new JsonArray(Text(root,"path"),0));
    }
    private JsonObject InventoryShare(JsonObject root) => Text(root,"share_name") == "" ? new JsonObject { ["name"]="",["path"]=root["path"]!.DeepClone(),["dacl"]="",["complete"]=true } : api.Share(Text(root,"share_name"),Text(root,"path"));
    private static string ObjectKey(JsonObject objects,string path) => objects.Select(x => x.Key).FirstOrDefault(k => k.Equals(path,StringComparison.OrdinalIgnoreCase)) ?? path;
    private (JsonObject Scope,JsonObject Snapshot) Inventory(JsonObject state,JsonObject root,FileAuditPolicy config,JsonObject cmd,DateTimeOffset now,bool apply,Action<string> setReadStage,JsonObject? cachedLocalGroups)
    {
        var timer = System.Diagnostics.Stopwatch.StartNew(); TimeSpan Clock() => clock?.Invoke() ?? timer.Elapsed;
        var deadline = Clock() + TimeSpan.FromSeconds(config.Number("wall_seconds"));
        var scopeId = Text(root,"collection_scope_id"); var rootPath = Text(root,"path"); var walks = state["walks"]!.AsObject();
        if (walks[scopeId] is null) walks[scopeId]=new JsonObject { ["stack"]=new JsonArray(new JsonArray(rootPath,0)),["page"]=0,["done"]=false,["gaps"]=0,["started"]=Iso8601.Format(now),["sacl_missing"]=0 };
        var walk = walks[scopeId]!.AsObject(); var stack = walk["stack"]!.AsArray(); var rows = new JsonArray(); var seen=0; var gaps=0;
        setReadStage("share");
        var share = InventoryShare(root);
        setReadStage("local_groups");
        string? inventoryFailure = null;
        JsonObject groups;
        try
        {
            groups = cachedLocalGroups ?? api.LocalGroups(config.Number("inventory_objects"), allowUnresolvedSid: Text(cmd, "action") == "check");
        }
        catch (Exception e) when (!apply && e is not OperationCanceledException)
        {
            inventoryFailure = FileAuditNativeReadException.Reason("local_groups", e);
            groups = new JsonObject { ["complete"] = false, ["groups"] = new JsonArray() };
        }
        setReadStage("inventory");
        var metadataIncomplete = !share["complete"]!.GetValue<bool>() || !groups["complete"]!.GetValue<bool>();
        var objects = state["objects"]!.AsObject();
        while (stack.Count > 0)
        {
            if (seen >= config.Number("inventory_objects") || Clock() >= deadline) { gaps++; break; }
            var item = stack[^1]!.AsArray(); var path = item[0]!.ToString(); var depth = item[1]!.GetValue<int>(); stack.RemoveAt(stack.Count-1); seen++;
            var objectKey = ObjectKey(objects,path);
            var objectStage = "directory";
            try
            {
                if (!FileAuditPolicy.InRoot(path,rootPath)) throw new AgentException("file_audit_scope_escape");
                setReadStage(objectStage);
                using var obj = api.Open(path,rootPath);
                objectStage = "acl";
                setReadStage(objectStage);
                var row = obj.Describe();
                if (depth == 0 && Text(row,"object_type") != "directory") throw new AgentException("file_audit_root_invalid");
                var protectedChild = path != rootPath && row["sacl_protected"]!.GetValue<bool>();
                var eligible = path == rootPath || root["sacl"]![Text(row,"object_type") == "directory" ? "inherit_directories" : "inherit_files"]!.GetValue<bool>();
                var aces = FileAuditPolicy.DesiredAces(root); var plan = eligible && !protectedChild ? obj.Plan(aces) : Text(row,"sacl");
                if (protectedChild) gaps++;
                var conflict=false;
                if (apply && eligible && !protectedChild)
                {
                    var saved = objects[objectKey] as JsonObject;
                    if (saved is not null)
                    {
                        if (Text(saved,"phase") is "pending" or "conflict" && Text(row,"object_id") == Text(saved,"object_id") && Text(row,"sacl") != Text(saved,"applied") && Text(row,"sacl") == obj.ExpectedSacl(Text(saved,"applied")))
                        { saved["applied"]=row["sacl"]!.DeepClone(); saved["phase"]="confirmed"; Save(state); }
                        var allowed = Text(saved,"phase") == "pending" ? new[] {Text(saved,"previous"),Text(saved,"applied")} : [Text(saved,"applied")];
                        if (Text(saved,"phase") is "conflict" or "restoring" || Text(row,"object_id") != Text(saved,"object_id") || !allowed.Contains(Text(row,"sacl")))
                        { saved["phase"]="conflict"; Save(state); gaps++; conflict=true; plan=Text(row,"sacl"); }
                    }
                    if (plan != Text(row,"sacl"))
                    {
                        if (objects.Count >= 100000 && saved is null) throw new AgentException("file_audit_state_limit");
                        objects[objectKey]=new JsonObject { ["root"]=saved?["root"]?.DeepClone() ?? JsonValue.Create(rootPath),["object_id"]=row["object_id"]!.DeepClone(),
                            ["previous"]=saved?["previous"]?.DeepClone() ?? row["sacl"]!.DeepClone(),["applied"]=plan,["phase"]="pending" };
                        Save(state); obj.SetSacl(plan); var after = obj.Describe();
                        if (Text(after,"sacl") != plan || Text(after,"owner_sid") != Text(row,"owner_sid") || Text(after,"dacl") != Text(row,"dacl") || Text(after,"object_id") != Text(row,"object_id"))
                        { objects[objectKey]!["phase"]="conflict"; Save(state); throw new AgentException("file_audit_readback_failed"); }
                        objects[objectKey]!["phase"]="confirmed"; Save(state); row=after;
                    }
                    else if (saved is not null && Text(saved,"phase") == "pending") { saved["phase"]="confirmed"; Save(state); }
                }
                var missing = eligible && !protectedChild && obj.Plan(aces) != Text(row,"sacl");
                var candidate = (JsonObject)row.DeepClone(); candidate["path"]=path; candidate["sacl_missing"]=missing;
                if (CanonicalJson.ToBytes(new JsonArray(rows.Select(r => r!.DeepClone()).Append(candidate.DeepClone()).ToArray())).Length > Math.Min(config.Number("max_bytes"),48*1024-16384))
                { if (rows.Count > 0) stack.Add(new JsonArray(path,depth)); else gaps++; break; }
                rows.Add(candidate); if (walk["sacl_missing"] is not null) walk["sacl_missing"]=walk["sacl_missing"]!.GetValue<int>() + (missing ? 1 : 0);
                objectStage = "directory";
                setReadStage(objectStage);
                if (Text(row,"object_type") == "directory" && !protectedChild && !conflict)
                    foreach (var name in obj.Children())
                    {
                        if (depth >= config.Number("inventory_depth") || stack.Count+seen >= config.Number("inventory_objects") || Clock() >= deadline) { gaps++; break; }
                        if (name.Length == 0 || name.IndexOfAny(['\\','/',':']) >= 0) throw new AgentException("file_audit_scope_escape");
                        var child = FileAuditPolicy.LocalPath(path.TrimEnd('\\')+"\\"+name); stack.Add(new JsonArray(child,depth+1));
                    }
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                if (depth == 0 && rows.Count == 0 && !apply)
                {
                    stack.Add(new JsonArray(path, depth));
                    throw;
                }
                inventoryFailure ??= FileAuditNativeReadException.Reason(objectStage, e);
                if (objects[objectKey]?["phase"]?.ToString() == "pending") { stack.Add(new JsonArray(path,depth)); break; }
                gaps++;
            }
        }
        setReadStage("inventory");
        walk["done"]=stack.Count == 0; walk["gaps"]=walk["gaps"]!.GetValue<int>()+gaps;
        var snapshot = new JsonObject { ["contract_id"]="sli.file-audit.inventory.v1",["collection_scope_id"]=scopeId,["policy_revision"]=cmd["policy_revision"]!.DeepClone(),
            ["observed_at_utc"]=Iso8601.Format(now),["scan_id"]=Uuid5(Text(cmd,"command_id")+scopeId+Text(walk,"started")),["page_number"]=walk["page"]!.DeepClone(),
            ["has_more"]=stack.Count > 0,["completeness"]=metadataIncomplete || gaps > 0 || stack.Count > 0 || walk["page"]!.GetValue<int>() > 0 ? "partial" : "complete",["unread_objects"]=gaps,
            ["share"]=share,["local_groups"]=groups,["objects"]=rows };
        var hash=Hash(snapshot); snapshot["snapshot_sha256"]=hash; snapshot["snapshot_id"]=Uuid5(Text(cmd,"command_id")+hash);
        walk["page"]=walk["page"]!.GetValue<int>()+1;
        if (CanonicalJson.ToBytes(snapshot).Length > 48*1024) throw new AgentException("file_audit_snapshot_limit");
        var missingAny = Text(cmd,"action") != "restore" && walk["sacl_missing"]?.GetValue<int>() > 0;
        var incomplete = metadataIncomplete || walk["gaps"]!.GetValue<int>() > 0 || stack.Count > 0 || Text(cmd,"action") != "restore" && walk["sacl_missing"] is null;
        return (new JsonObject { ["collection_scope_id"]=scopeId,["state"]=incomplete || missingAny ? "partial" : "verified",["reason_code"]=inventoryFailure ?? (incomplete ? "coverage_incomplete" : missingAny ? "sacl_missing" : "ok") },snapshot);
    }
    private string RestoreGuard(JsonObject state,FileAuditPolicy config)
    {
        var timer=System.Diagnostics.Stopwatch.StartNew(); var start=clock?.Invoke() ?? timer.Elapsed; var seen=0;
        var objects=state["objects"]!.AsObject(); if (objects.Count == 0) return "ok";
        foreach (var root in (state["active"] as JsonArray ?? []).OfType<JsonObject>())
        {
            var rootPath=Text(root,"path"); var stack=new Stack<(string Path,int Depth)>(); stack.Push((rootPath,0));
            while (stack.TryPop(out var item))
            {
                if (++seen > config.Number("inventory_objects") || (clock?.Invoke() ?? timer.Elapsed)-start >= TimeSpan.FromSeconds(config.Number("wall_seconds"))) return "restore_scan_incomplete";
                try
                {
                    using var obj=api.Open(item.Path,rootPath); var row=obj.Describe(); var saved=objects[ObjectKey(objects,item.Path)];
                    if (saved is not null)
                    {
                        var allowed=Text(saved,"phase") is "pending" or "restoring" ? new[] {Text(saved,"previous"),Text(saved,"applied")} : [Text(saved,"applied")];
                        if (Text(saved,"phase") == "conflict" || Text(row,"object_id") != Text(saved,"object_id") || !allowed.Contains(Text(row,"sacl"))) { saved["phase"]="conflict"; Save(state); return "restore_conflict"; }
                    }
                    else if (objects.Any(x => Text(x.Value!,"root").Equals(rootPath,StringComparison.OrdinalIgnoreCase) && obj.InheritedFrom(Text(x.Value!,"previous"),Text(x.Value!,"applied")))) return "inheritance_untracked";
                    if (Text(row,"object_type") == "directory" && (item.Path == rootPath || !row["sacl_protected"]!.GetValue<bool>()))
                        foreach (var child in obj.Children())
                        {
                            if (item.Depth >= config.Number("inventory_depth") || stack.Count+seen >= config.Number("inventory_objects")) return "restore_scan_incomplete";
                            var path=FileAuditPolicy.LocalPath(item.Path.TrimEnd('\\')+"\\"+child);
                            if (child.IndexOfAny(['\\','/',':']) >= 0 || !FileAuditPolicy.InRoot(path,rootPath)) return "restore_scan_incomplete";
                            stack.Push((path,item.Depth+1));
                        }
                }
                catch (Exception e) when (e is not OperationCanceledException) { return "restore_scan_incomplete"; }
            }
        }
        return "ok";
    }
    private void Restore(JsonObject state,FileAuditPolicy config)
    {
        var timer=System.Diagnostics.Stopwatch.StartNew(); var start=clock?.Invoke() ?? timer.Elapsed; var seen=0; var objects=state["objects"]!.AsObject();
        foreach (var pair in objects.OrderByDescending(x => x.Key.Length).ToArray())
        {
            if (++seen > config.Number("inventory_objects") || (clock?.Invoke() ?? timer.Elapsed)-start >= TimeSpan.FromSeconds(config.Number("wall_seconds"))) break;
            var saved=pair.Value!;
            try
            {
                using var obj=api.Open(pair.Key,Text(saved,"root")); var row=obj.Describe();
                if (Text(row,"object_id") != Text(saved,"object_id") || Text(saved,"phase") == "conflict" || Text(row,"sacl") != Text(saved,"applied") && !(Text(saved,"phase") is "pending" or "restoring" && Text(row,"sacl") == Text(saved,"previous")))
                { saved["phase"]="conflict"; Save(state); continue; }
                saved["phase"]="restoring"; Save(state); obj.SetSacl(Text(saved,"previous")); var after=obj.Describe();
                if (Text(after,"sacl") != Text(saved,"previous") || Text(after,"owner_sid") != Text(row,"owner_sid") || Text(after,"dacl") != Text(row,"dacl")) { saved["phase"]="conflict"; Save(state); continue; }
                objects.Remove(pair.Key); Save(state);
            }
            catch (Exception e) when (e is not OperationCanceledException) { }
        }
    }
    public static string Uuid5(string text)
    {
        var ns=Guid.Parse("6ba7b811-9dad-11d1-80b4-00c04fd430c8").ToByteArray(bigEndian:true);
        var bytes=SHA1.HashData(ns.Concat(Encoding.UTF8.GetBytes(text)).ToArray())[..16]; bytes[6]=(byte)((bytes[6]&15)|80); bytes[8]=(byte)((bytes[8]&63)|128);
        return new Guid(bytes,bigEndian:true).ToString();
    }
}
