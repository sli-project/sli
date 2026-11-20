using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

/// <summary>Server-issued data identity and committed cursors; never a certificate/key replacement.</summary>
public sealed record RuntimeHandoff(string SourceHostId, IReadOnlyDictionary<string, CapturedPosition> Cursors)
{
    public CapturedPosition? Position(string moduleId) => Cursors.GetValueOrDefault(moduleId);

    public static RuntimeHandoff? Parse(JsonNode? node)
    {
        if (node is null) return null;
        try
        {
            if (node is not JsonObject body || !JsonRead.HasExactly(body, "source_host_id", "cursors")
                || !JsonRead.TryString(body["source_host_id"], out var host) || !Guid.TryParseExact(host, "D", out _)
                || body["cursors"] is not JsonObject cursors || cursors.Count > 64) throw new FormatException();
            var result = new Dictionary<string, CapturedPosition>();
            foreach (var (module, value) in cursors)
            {
                if (module is not (AdDcModule.ModuleId or WorkstationsModule.ModuleId or FileAuditPolicy.ModuleId or NpsPolicy.Nps or NpsPolicy.Accounting)
                    || value is not JsonObject cursor || !JsonRead.TryString(cursor["generation"], out var generation)
                    || generation.Length is < 1 or > 512) throw new FormatException();
                result[module] = new CapturedPosition(generation, Cursor.FromJson(cursor["cursor_after"]));
            }
            return new(host, result);
        }
        catch (Exception ex) when (ex is FormatException or ProtocolException or InvalidOperationException)
        { throw new AgentException("agent_runtime_handoff_invalid"); }
    }
}
