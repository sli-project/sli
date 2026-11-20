using System.Text.Json.Nodes;

namespace Sli.Server.Sources;

// Pure fixture ledger from plugin_contract_v1.py, not runtime evidence storage.
public sealed class EvidenceFirstLedger
{
    public long TransportCursor { get; private set; }
    public Dictionary<string, bool> Evidence { get; } = [];
    public HashSet<(string SubscriptionId, string EvidenceUid)> Outbox { get; } = [];
    public Dictionary<string, long> DeliveryPositions { get; } = [];

    public JsonObject Ingest(JsonObject fixture, JsonObject record, string? failAfter = null)
    {
        string uid = PluginContractV1.CanonicalHash(record);
        Evidence.TryAdd(uid, false);
        if (failAfter == "evidence_write") throw new InvalidOperationException("injected_after_evidence_write");
        Evidence[uid] = true;
        if (failAfter == "evidence_verify") throw new InvalidOperationException("injected_after_evidence_verify");
        var routes = PluginContractV1.RouteEvent(fixture, record);
        if (failAfter == "before_registry_transaction") throw new InvalidOperationException("injected_before_registry_transaction");
        long cursor = PluginContractV1.Number(record["cursor"]);
        foreach (string route in routes)
        {
            Outbox.Add((route, uid));
            DeliveryPositions.TryAdd(route, 0);
        }
        TransportCursor = Math.Max(TransportCursor, cursor);
        return new() { ["evidence_uid"] = uid, ["routes"] = new JsonArray(routes.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray()) };
    }

    public void Deliver(string subscriptionId, long position)
    {
        if (!DeliveryPositions.TryGetValue(subscriptionId, out long current)) throw new PluginContractException("unknown_subscription_delivery");
        DeliveryPositions[subscriptionId] = Math.Max(current, position);
    }
}
