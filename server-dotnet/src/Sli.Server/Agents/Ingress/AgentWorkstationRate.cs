using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Ingress;

internal static class AgentWorkstationRate
{
    public static async Task<bool> IsLimitedAsync(NpgsqlConnection db,NpgsqlTransaction tx,Guid agent,JsonArray rows,WorkstationPolicy policy,CancellationToken ct)
    {
        var limits=policy.Value["rate_limits"]!.AsObject();
        var counts=rows.OfType<JsonObject>().GroupBy(row=>row["event_id"]!.ToJsonString()).ToDictionary(g=>g.Key,g=>g.LongCount());
        foreach(var pair in limits)
            if (counts.GetValueOrDefault(pair.Key)>AsLong(pair.Value)) return true;
        if (!limits.Any(pair=>counts.GetValueOrDefault(pair.Key)>0)) return false;
        await using var command=new NpgsqlCommand("""
            select event->>'event_id' as event_id,count(*) as count
            from sli_agent_receipts r join sli_agent_packet_inbox i using(packet_id)
            cross join lateral jsonb_array_elements(i.event_rows) event
            where r.agent_id=@agent and r.module_id='sli.workstations'
              and r.received_at >= clock_timestamp() - (@seconds * interval '1 second')
            group by event->>'event_id'
            """,db,tx);
        command.Parameters.AddWithValue("agent",agent); command.Parameters.AddWithValue("seconds",policy.RateWindowSeconds);
        await using var reader=await command.ExecuteReaderAsync(ct);
        while(await reader.ReadAsync(ct))
        {
            if (reader.IsDBNull(0)) continue; string id=reader.GetString(0); long incoming=counts.GetValueOrDefault(id);
            if (incoming>0 && limits.ContainsKey(id) && reader.GetInt64(1)+incoming>AsLong(limits[id])) return true;
        }
        return false;
    }
    private static long AsLong(JsonNode? node)=>JsonRead.TryInteger(node,out var value) && value>=0 && value<=long.MaxValue ? (long)value : throw new AgentException("agent_workstations_config_invalid");
}
