using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol;
namespace Sli.Server.Agents.FileAudit;
public static class FileAuditCommand
{
    public static bool Valid(JsonObject command,JsonObject config)
    {
        if(!JsonRead.HasExactly(command,"contract_id","command_id","action","policy_revision","collection_scope_ids")
            || !JsonRead.TryString(command["contract_id"],out var contract) || contract!="sli.file-audit.audit-command.v1"
            || !JsonRead.TryString(command["command_id"],out var id) || !Regex.IsMatch(id,@"\A[a-zA-Z0-9_-]{1,128}\z")
            || !JsonRead.TryString(command["action"],out var action) || action is not ("check" or "apply" or "restore")
            || !JsonRead.TryString(command["policy_revision"],out var revision) || !JsonRead.TryString(config["policy_revision"],out var expected) || revision!=expected
            || command["collection_scope_ids"] is not JsonArray selected || selected.Count==0 || config["roots"] is not JsonArray roots) return false;
        var allowed=roots.OfType<JsonObject>().Select(x=>JsonRead.TryString(x["collection_scope_id"],out var s)?s:"").ToHashSet(StringComparer.Ordinal);
        var seen=new HashSet<string>(StringComparer.Ordinal);
        foreach(var item in selected) if(!JsonRead.TryString(item,out var scope) || !seen.Add(scope) || !allowed.Contains(scope)) return false;
        return true;
    }
}
