using System.Text.Json.Nodes;

namespace Sli.Server.Semantic;

internal sealed partial class SemanticProduction
{
    internal static string? NpsClientAddress(string? text) => text is not null && Password.PasswordNative.StrictIp(text,out var address,out var zone) ? Password.PasswordNative.CanonicalAddress(address!) + (zone is null ? "" : "%" + zone) : null;
    private static async Task<int> ProcessNpsThreshold(ISemanticSession session, JsonObject scope, CancellationToken ct) => (int)(await RunNpsThreshold(session,scope,ct)).Number("jobs");
    private static Task<JsonObject> RunNpsThreshold(ISemanticSession session, JsonObject scope, CancellationToken ct, DetectorRule? rule = null, DateTimeOffset? time = null)
    {
        return Task.FromResult(new JsonObject { ["state"] = "disabled", ["reason"] = "module_disabled", ["rows"] = new JsonArray(), ["jobs"] = 0 });
    }
}
