using System.Text.Json;
using System.Text.Json.Nodes;
namespace Sli.Server.Agents.ClientControl;
internal static class AgentClientJson
{
    internal static JsonNode? FromElement(JsonElement value) => Sli.Server.Compatibility.PythonJson.FromElement(value);
}
