using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Ingress;

public static class PacketStorageJson
{
    public static string Serialize(JsonNode? value) => CanonicalJson.Serialize(value);
}
