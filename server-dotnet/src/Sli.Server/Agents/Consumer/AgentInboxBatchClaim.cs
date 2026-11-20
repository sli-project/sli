using System.Text.Json.Nodes;
using Npgsql;

namespace Sli.Server.Agents.Consumer;

public sealed partial class AgentWorkstationInboxConsumer
{
    // One claim transaction reserves a bounded round-robin page. The process
    // lock owns scheduling; per-packet transactions recheck terminal state and
    // perform the unchanged admission/attestation before importing anything.
    internal static async Task<List<Inbox>> ClaimBatchAsync(NpgsqlConnection db,NpgsqlTransaction tx,int limit,
        IEnumerable<(string Agent,string Module)> deferred,string[] skipped,StreamFairness fairness,CancellationToken ct)
    {
        const string sql="""
            with candidates as materialized (
                select packet_id,received_at,
                    row_number() over(partition by envelope->>'agent_id',envelope->>'module_id' order by received_at,packet_id)
                      + case when concat_ws(chr(31),envelope->>'agent_id',envelope->>'module_id')=any(@served) then 1 else 0 end as round
                from sli_agent_packet_inbox i
                where imported_at is null and module_disabled_at is null
                  and (@workstations or envelope->>'module_id' is distinct from 'sli.workstations')
                  and not exists(select 1 from sli_agent_packet_quarantine q where q.packet_id=i.packet_id)
                  and not exists(select 1 from sli_agents a where a.id::text=i.envelope->>'agent_id' and a.status in ('replaced','disabled'))
                  and not (concat_ws(chr(31),envelope->>'agent_id',envelope->>'module_id',envelope->>'source_instance_id',envelope->>'channel',envelope->>'module_version',packet->'header'->>'source')=any(@skipped))
                  and not exists(select 1 from unnest(@deferred_agents,@deferred_modules) d(agent_id,module_id)
                    where envelope->>'agent_id'=d.agent_id and envelope->>'module_id'=d.module_id)
                  and not exists(select 1 from unnest(@cur_keys,@cur_times,@cur_ids) c(k,t,id)
                    where c.k=concat_ws(chr(31),envelope->>'agent_id',envelope->>'module_id') and (i.received_at,i.packet_id)<=(c.t,c.id))
            )
            select i.packet_id,i.received_at,i.envelope::text,i.packet::text,i.event_rows::text
            from candidates c join sli_agent_packet_inbox i using(packet_id)
            order by c.round,c.received_at,c.packet_id limit @limit for update of i skip locked
            """;
        await using var command=new NpgsqlCommand(sql,db,tx);
        ClaimParameters(command,null,deferred,skipped,fairness);
        command.Parameters.AddWithValue("limit",limit);
        bool workstations=Environment.GetEnvironmentVariable("SLI_CORE_JOB_WORKSTATIONS_PROJECTION")=="1"
            &&await Workstations.WorkstationJobPlugin.EnabledAsync(db,ct);
        command.Parameters.AddWithValue("workstations",workstations);
        var rows=new List<Inbox>();
        await using var reader=await command.ExecuteReaderAsync(ct);
        while(await reader.ReadAsync(ct))rows.Add(new(reader.GetGuid(0),reader.GetDateTime(1),
            JsonNode.Parse(reader.GetString(2))!.AsObject(),JsonNode.Parse(reader.GetString(3))!.AsObject(),JsonNode.Parse(reader.GetString(4))!.AsArray()));
        return rows;
    }
    private static string BindingKey(Inbox row)=>string.Join('\u001f',row.Envelope["agent_id"]?.ToString()??"",row.Envelope["module_id"]?.ToString()??"",
        row.Envelope["source_instance_id"]?.ToString()??"",row.Envelope["channel"]?.ToString()??"",row.Envelope["module_version"]?.ToString()??"",row.Packet["header"]?["source"]?.ToString()??"");
}
