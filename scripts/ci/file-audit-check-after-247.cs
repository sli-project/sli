using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Windows;

internal static class Program
{
    private static int Main(string[] args)
    {
        var installed = args[0];
        var evidence = args[3];
        var result = new JsonObject();
        AssemblyLoadContext.Default.Resolving += (context, name) =>
        {
            var path = Path.Combine(installed, name.Name + ".dll");
            return File.Exists(path) ? context.LoadFromAssemblyPath(path) : null;
        };
        int status;
        try
        {
            status = Check(args[1], args[2], installed, result);
        }
        catch (Exception error)
        {
            result["exception_type"] = error.GetType().Name;
            result["hresult"] = unchecked((uint)error.HResult);
            status = 1;
        }
        var pending = evidence + ".pending";
        File.WriteAllText(pending, result.ToJsonString());
        File.Move(pending, evidence);
        return status;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static int Check(string name, string root, string installed, JsonObject result)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var sid = identity.User?.Value;
        result["service_account_sid"] = sid;
        if (sid != "S-1-5-18" ||
            !string.Equals(Path.GetDirectoryName(typeof(NativeFileAuditApi).Assembly.Location), installed, StringComparison.OrdinalIgnoreCase))
            return 1;

        var api = new NativeFileAuditApi();
        result["stage"] = "global_file_sacl_baseline";
        var baseline = GlobalFileSaclSnapshot();
        result["global_file_sacl_before"] = baseline;
        if (!IsAbsent(baseline))
            return 1;
        var marker = Path.Combine(root, "synthetic.txt");
        result["stage"] = "catalog";
        var catalog = NativeFileAuditApi.ListLocalShares(CancellationToken.None);
        result["catalog_state"] = catalog.State.ToString();
        result["catalog_win32"] = catalog.NativeStatus is uint code ? JsonValue.Create(code) : null;
        var share = catalog.Shares.SingleOrDefault(s => s.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (catalog.State != LocalSmbCatalogState.Ready || share is null ||
            !share.Path.Equals(root, StringComparison.OrdinalIgnoreCase))
            return 1;
        result["own_share_found"] = true;

        result["stage"] = "share";
        var beforeShare = api.Share(name, root);
        result["share_read"] = beforeShare["complete"]!.GetValue<bool>();
        result["stage"] = "acl";
        JsonObject ReadAcl(string path)
        {
            using var item = api.Open(path, root);
            return item.Describe();
        }
        var beforeRootAcl = ReadAcl(root);
        var beforeMarkerAcl = ReadAcl(marker);
        result["acl_read"] = true;

        const string scopeId = "scope:installed-proof";
        var scope = new JsonObject
        {
            ["collection_scope_id"] = scopeId, ["share_name"] = name, ["path"] = root,
            ["important"] = false, ["sacl"] = new JsonObject
            {
                ["trustee_sids"] = new JsonArray("S-1-1-0"), ["inherit_files"] = true, ["inherit_directories"] = true
            }
        };
        var request = new JsonObject
        {
            ["config"] = new JsonObject { ["roots"] = new JsonArray(scope), ["source_kind"] = "server" },
            ["command"] = new JsonObject
            {
                ["contract_id"] = "sli.file-audit.audit-command.v1", ["command_id"] = "installed-read-only",
                ["action"] = "check", ["policy_revision"] = "1", ["collection_scope_ids"] = new JsonArray(scopeId)
            }
        };
        var policy = new AgentPolicy(1, new CollectionControl("active", 60, 32, 120, 10000000, false, false),
            new JsonArray(), null, null, null) { FileAuditRequest = request };
        var stateDirectory = Path.Combine(Path.GetDirectoryName(root)!, "probe-state");
        var manager = new FileAuditManager(stateDirectory, new PhysicalDurableFiles(), api);
        var config = FileAuditPolicy.Parse(request["config"]!.AsObject());
        var maskKeys = config.RequiredMasks().Keys.ToArray();
        result["stage"] = "audit_masks";
        var beforeMasks = api.QueryMasks(maskKeys);
        result["audit_masks_read"] = beforeMasks.Count;
        result["expected_audit_masks"] = maskKeys.Length;
        if (beforeMasks.Count != maskKeys.Length || maskKeys.Length == 0)
            return 1;

        result["stage"] = "check";
        var report = manager.Reconcile(policy, null, DateTimeOffset.UtcNow, readDiagnostics: true).Report!;
        var check = report["scopes"]!.AsArray().Single()!;
        result["check_state"] = check["state"]!.DeepClone();
        result["check_reason"] = check["reason_code"]!.DeepClone();
        result["read_error"] = check["read_error"]?.DeepClone();
        result["command_action"] = report["action"]?.DeepClone();
        result["ownership_remaining"] = report["ownership_remaining"]?.DeepClone();
        var snapshots = report["snapshots"]!.AsArray();
        var snapshot = snapshots.Count == 1 ? snapshots[0] as JsonObject : null;
        var rows = snapshot?["objects"] as JsonArray;
        JsonObject? FindRow(string path) => rows?.OfType<JsonObject>()
            .SingleOrDefault(row => string.Equals(row["path"]?.GetValue<string>(), path, StringComparison.OrdinalIgnoreCase));
        var rootRow = FindRow(root);
        var markerRow = FindRow(marker);
        bool SameMetadata(JsonObject row, JsonObject actual) =>
            new[] { "object_id", "object_type", "owner_sid", "dacl", "sacl", "sacl_protected" }
                .All(key => row.ContainsKey(key) && JsonNode.DeepEquals(row[key], actual[key]));
        bool rootRead = rootRow?["object_type"]?.GetValue<string>() == "directory" && SameMetadata(rootRow, beforeRootAcl);
        bool markerRead = markerRow?["object_type"]?.GetValue<string>() == "file" && SameMetadata(markerRow, beforeMarkerAcl);
        result["inventory_root_metadata_matches"] = rootRead;
        result["inventory_file_metadata_matches"] = markerRead;
        result["inventory_object_count"] = JsonValue.Create(rows?.Count);
        result["inventory_coverage"] = snapshot?["completeness"]?.DeepClone();
        result["inventory_unread_count"] = snapshot?["unread_objects"]?.DeepClone();
        result["inventory_has_more"] = snapshot?["has_more"]?.DeepClone();
        result["inventory_sacl_missing_count"] = JsonValue.Create(rows?.OfType<JsonObject>()
            .Count(row => row["sacl_missing"]?.GetValue<bool>() == true));
        result["required_masks_missing_count"] = config.RequiredMasks()
            .Count(mask => (beforeMasks.GetValueOrDefault(mask.Key) & mask.Value) != mask.Value);
        var inventoryShare = snapshot?["share"] as JsonObject;
        bool shareMatches = inventoryShare?["complete"]?.GetValue<bool>() == true
            && string.Equals(inventoryShare["name"]?.GetValue<string>(), name, StringComparison.OrdinalIgnoreCase)
            && string.Equals(inventoryShare["path"]?.GetValue<string>(), root, StringComparison.OrdinalIgnoreCase)
            && JsonNode.DeepEquals(beforeShare["dacl"], inventoryShare["dacl"]);
        result["inventory_share_matches"] = shareMatches;

        var localGroups = snapshot?["local_groups"] as JsonObject;
        var groupRows = localGroups?["groups"] as JsonArray;
        var adminGroup = groupRows?.OfType<JsonObject>()
            .SingleOrDefault(group => group["group_sid"]?.GetValue<string>() == "S-1-5-32-544");
        var memberSids = adminGroup?["member_sids"] as JsonArray;
        bool groupComplete = localGroups?["complete"]?.GetValue<bool>() == true;
        bool adminRead = memberSids is not null
            && memberSids.All(member => member is not null && new SecurityIdentifier(member.GetValue<string>()).BinaryLength > 0);
        result["inventory_local_groups_complete"] = groupComplete;
        result["inventory_local_group_count"] = JsonValue.Create(groupRows?.Count);
        result["inventory_builtin_administrators_read"] = adminRead;
        result["inventory_builtin_administrators_member_count"] = JsonValue.Create(memberSids?.Count);

        var afterRootAcl = ReadAcl(root);
        var afterMarkerAcl = ReadAcl(marker);
        bool SameAcl(JsonObject before, JsonObject after) =>
            JsonNode.DeepEquals(before["dacl"], after["dacl"]) && JsonNode.DeepEquals(before["sacl"], after["sacl"])
            && JsonNode.DeepEquals(before["sacl_protected"], after["sacl_protected"]);
        bool unchanged = SameAcl(beforeRootAcl, afterRootAcl) && SameAcl(beforeMarkerAcl, afterMarkerAcl)
            && JsonNode.DeepEquals(beforeShare["dacl"], api.Share(name, root)["dacl"]);
        result["acls_unchanged"] = unchanged;
        bool metadataUnchanged = SameMetadata(beforeRootAcl, afterRootAcl) && SameMetadata(beforeMarkerAcl, afterMarkerAcl);
        result["owners_and_object_ids_unchanged"] = metadataUnchanged;
        var afterMasks = api.QueryMasks(maskKeys);
        bool masksUnchanged = beforeMasks.Count == afterMasks.Count
            && beforeMasks.All(item => afterMasks.TryGetValue(item.Key, out var value) && item.Value == value);
        result["audit_masks_unchanged"] = masksUnchanged;
        var after = GlobalFileSaclSnapshot();
        result["global_file_sacl_after"] = after;
        var state = JsonNode.Parse(File.ReadAllText(Path.Combine(stateDirectory, "state.json")))!;
        bool noOwnership = state["active"] is null && state["objects"] is JsonObject { Count: 0 }
            && state["masks"] is JsonObject { Count: 0 } && report["ownership_remaining"]?.GetValue<bool>() == false;
        result["check_ownership_empty"] = noOwnership;
        bool listed = snapshot?["collection_scope_id"]?.GetValue<string>() == scopeId
            && snapshot?["completeness"]?.GetValue<string>() == "complete"
            && snapshot["has_more"]?.GetValue<bool>() == false && snapshot["unread_objects"]?.GetValue<int>() == 0
            && rows?.Count == 2 && rootRead && markerRead && shareMatches && groupComplete && adminRead;
        result["check_inventory_complete"] = listed;
        string? status = check["state"]?.ToString();
        string? reason = check["reason_code"]?.ToString();
        var saclsMissing = result["inventory_sacl_missing_count"]?.GetValue<int>() ?? -1;
        var masksMissing = result["required_masks_missing_count"]!.GetValue<int>();
        bool expected = (status, reason) switch
        {
            ("verified", "ok") => saclsMissing == 0 && masksMissing == 0,
            ("partial", "sacl_missing") => saclsMissing > 0,
            ("partial", "policy_missing") => saclsMissing == 0 && masksMissing > 0,
            _ => false
        };
        return unchanged && metadataUnchanged && masksUnchanged && noOwnership && IsAbsent(after) && listed && expected
            && check["read_error"] is null && result["share_read"]!.GetValue<bool>()
            && report["action"]?.ToString() == "check" ? 0 : 1;
    }

    private static JsonObject GlobalFileSaclSnapshot()
    {
        var windows = typeof(NativeFileAuditApi).Assembly;
        var privilegeType = windows.GetType("Sli.Agent.Windows.WindowsAuditApi+SecurityPrivilege", throwOnError: true)!;
        using var privilege = (IDisposable)Activator.CreateInstance(privilegeType, nonPublic: true)!;
        bool read = AuditQueryGlobalSacl("File", out var acl);
        int error = Marshal.GetLastPInvokeError();
        try
        {
            return new JsonObject
            {
                ["api_return"] = read, ["last_error"] = error,
                ["ace_count"] = read ? JsonValue.Create(acl == IntPtr.Zero ? 0 : (ushort)Marshal.ReadInt16(acl, 4)) : null
            };
        }
        finally
        {
            if (read && acl != IntPtr.Zero) LocalFree(acl);
        }
    }

    private static bool IsAbsent(JsonObject state) =>
        state["api_return"]!.GetValue<bool>() == false && state["last_error"]!.GetValue<int>() == 2;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditQueryGlobalSacl(string objectType, out IntPtr acl);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr value);
}
