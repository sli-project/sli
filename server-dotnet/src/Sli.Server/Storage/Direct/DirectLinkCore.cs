using System.Text.Json.Nodes;

namespace Sli.Server.Storage.Direct;

internal static class DirectLinkCore
{
    internal static byte[] Hash(long eventId, int entityId, short roleId, int extractedFromId, DateTime createdAt,double confidence=1.0)
    {
        if (eventId <= 0 || entityId <= 0 || roleId < 0 || extractedFromId <= 0 || confidence < 0 || confidence > 1) throw new InvalidDataException("storage_v2_link_invalid");
        var values = new JsonObject {
            ["event_id"] = eventId, ["entity_id"] = entityId, ["role_id"] = roleId,
            ["confidence"] = confidence, ["extracted_from_id"] = extractedFromId,
            ["created_at"] = DirectEntityModel.Timestamp(createdAt),
        };
        return DirectEntityModel.Digest(values);
    }
}
