using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Server.Storage.Direct;

internal sealed record DirectEntityModel(int Id, int TypeId, DirectEntity Source, long? DomainId, long? ServerId,
    DateTime FirstSeen, DateTime LastSeen, byte[] CoreHash, byte[] DetailsHash)
{
    internal static DirectEntityModel Create(int id, int typeId, DirectEntity source, long? domainId, long? serverId, DateTime first, DateTime last)
    {
        if (id <= 0 || typeId <= 0 || first.Kind != DateTimeKind.Utc || last.Kind != DateTimeKind.Utc) throw new InvalidDataException("storage_v2_entity_invalid");
        var fields = new JsonObject {
            ["id"] = id, ["entity_type_id"] = typeId, ["natural_key"] = source.NaturalKey,
            ["display_name"] = source.DisplayName, ["domain_id"] = domainId, ["server_id"] = serverId,
            ["first_seen_utc"] = Timestamp(first), ["last_seen_utc"] = Timestamp(last)
        };
        return new DirectEntityModel(id,typeId,source,domainId,serverId,first,last,Digest(fields),Digest(source.Attributes));
    }
    internal static byte[] Digest(JsonNode? node) => SHA256.HashData(new UTF8Encoding(false,true).GetBytes(CanonicalJson.Serialize(node, ensureAscii:false)));
    internal static string Timestamp(DateTime value)
    {
        if (value.Kind != DateTimeKind.Utc) throw new InvalidDataException("storage_v2_timestamp_invalid");
        long micros=value.Ticks % TimeSpan.TicksPerSecond / 10;
        return value.ToString("yyyy-MM-dd'T'HH:mm:ss",CultureInfo.InvariantCulture)
            +(micros==0?"":"."+micros.ToString("D6",CultureInfo.InvariantCulture))+"+00:00";
    }
}
