using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol.Compatibility;

namespace Sli.Server.Storage.Direct;

internal sealed record DirectPacketBytes(byte[] Bytes, string Sha256)
{
    public int SizeBytes => Bytes.Length;
}

internal static class DirectPacketJsonl
{
    public static DirectPacketBytes Create(JsonArray rows)
    {
        var text = new StringBuilder();
        foreach (var row in rows)
        {
            if (row is not JsonObject) throw new InvalidDataException("agent_ad_dc_packet_invalid");
            text.Append(SourceJson.Serialize(row)).Append('\n');
        }
        byte[] bytes = new UTF8Encoding(false, true).GetBytes(text.ToString());
        return new DirectPacketBytes(bytes, Convert.ToHexStringLower(SHA256.HashData(bytes)));
    }
}
