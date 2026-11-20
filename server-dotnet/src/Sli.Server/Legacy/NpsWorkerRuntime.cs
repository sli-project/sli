using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Radius;
using Sli.Server.Operations;
using Sli.Server.Semantic;

namespace Sli.Server.Legacy;

// The hidden NPS worker cannot acquire events or access its retired cursor.
public sealed class NpsWorkerRuntime
{
    public NpsWorkerRuntime(ISemanticDatabase database, LegacySettings settings, ILegacyAcquisition acquisition, OperationsFiles files, LegacyHeartbeat heartbeat) { }

    public Task<JsonObject> CompleteAsync(JsonObject dc, LegacyWork work, string worker, CancellationToken ct)
    {
        return Task.FromResult(new JsonObject { ["status"] = "disabled", ["reason"] = "module_disabled" });
    }

}
