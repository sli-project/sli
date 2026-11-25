using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;
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
        JsonObject ReadAcl()
        {
            using var item = api.Open(marker, root);
            return item.Describe();
        }
        var beforeAcl = ReadAcl();
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
        result["stage"] = "check";
        var report = manager.Reconcile(policy, null, DateTimeOffset.UtcNow, readDiagnostics: true).Report!;
        var check = report["scopes"]!.AsArray().Single()!;
        result["check_state"] = check["state"]!.DeepClone();
        result["check_reason"] = check["reason_code"]!.DeepClone();
        result["read_error"] = check["read_error"]?.DeepClone();
        var afterAcl = ReadAcl();
        bool unchanged = JsonNode.DeepEquals(beforeAcl["dacl"], afterAcl["dacl"])
            && JsonNode.DeepEquals(beforeAcl["sacl"], afterAcl["sacl"])
            && JsonNode.DeepEquals(beforeShare["dacl"], api.Share(name, root)["dacl"])
            && report["ownership_remaining"]!.GetValue<bool>() == false;
        result["read_only"] = unchanged;
        bool listed = report["snapshots"]!.AsArray().Any(snapshot =>
            snapshot!["collection_scope_id"]!.ToString() == scopeId
            && snapshot["share"]!["name"]!.ToString() == name && snapshot["share"]!["path"]!.ToString() == root
            && snapshot["objects"]!.AsArray().Any(row => row!["path"]!.ToString().Equals(marker, StringComparison.OrdinalIgnoreCase)));
        result["check_inventory_contains_marker"] = listed;
        return unchanged && listed && check["read_error"] is null && result["share_read"]!.GetValue<bool>() ? 0 : 1;
    }
}
