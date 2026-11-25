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
        var manager = new FileAuditManager(Path.Combine(Path.GetDirectoryName(root)!, "probe-state"), new PhysicalDurableFiles(), api);
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
        var afterRootAcl = ReadAcl(root);
        var afterMarkerAcl = ReadAcl(marker);
        bool SameAcl(JsonObject before, JsonObject after) =>
            JsonNode.DeepEquals(before["dacl"], after["dacl"]) && JsonNode.DeepEquals(before["sacl"], after["sacl"]);
        bool unchanged = SameAcl(beforeRootAcl, afterRootAcl) && SameAcl(beforeMarkerAcl, afterMarkerAcl)
            && JsonNode.DeepEquals(beforeShare["dacl"], api.Share(name, root)["dacl"]);
        result["acls_unchanged"] = unchanged;
        var afterMasks = api.QueryMasks(maskKeys);
        bool masksUnchanged = beforeMasks.Count == afterMasks.Count
            && beforeMasks.All(item => afterMasks.TryGetValue(item.Key, out var value) && item.Value == value);
        result["audit_masks_unchanged"] = masksUnchanged;
        var after = GlobalFileSaclSnapshot();
        result["global_file_sacl_after"] = after;
        bool listed = report["snapshots"]!.AsArray().Any(snapshot =>
            snapshot!["collection_scope_id"]!.ToString() == scopeId
            && snapshot["share"]!["name"]!.ToString() == name && snapshot["share"]!["path"]!.ToString() == root
            && snapshot["completeness"]!.ToString() == "complete"
            && snapshot["objects"]!.AsArray().Any(row => row!["path"]!.ToString().Equals(root, StringComparison.OrdinalIgnoreCase))
            && snapshot["objects"]!.AsArray().Any(row => row!["path"]!.ToString().Equals(marker, StringComparison.OrdinalIgnoreCase)));
        result["check_inventory_complete"] = listed;
        string? status = check["state"]?.ToString();
        string? reason = check["reason_code"]?.ToString();
        bool expected = status == "verified" && reason == "ok" || status == "partial" && reason is ("sacl_missing" or "policy_missing");
        return unchanged && masksUnchanged && IsAbsent(after) && listed && expected
            && check["read_error"] is null && result["share_read"]!.GetValue<bool>()
            && report["action"]?.ToString() == "check" && report["ownership_remaining"]!.GetValue<bool>() == false ? 0 : 1;
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
