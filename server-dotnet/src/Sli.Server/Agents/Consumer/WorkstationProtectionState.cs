using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;

namespace Sli.Server.Agents.Consumer;

// Frozen workstation importer protection_state, including monotone update/replay checks.
internal static class WorkstationProtectionState
{
    private const string DefenderChannel="Microsoft-Windows-Windows Defender/Operational";
    private static readonly string[] Components=["antivirus_enabled","real_time_protection_enabled","behavior_monitor_enabled","ioav_protection_enabled","nis_enabled","tamper_protected"];
    internal sealed record Prepared(JsonObject State,DateTimeOffset ObservedAt);
    public static Prepared? Prepare(JsonObject packet)
    {
        var state=packet["context"]?["workstations"]?["protection_state"];
        if(state is null)return null;
        if(packet["header"]?["channel"]?.GetValue<string>()!=DefenderChannel || state is not JsonObject obj || !JsonRead.HasExactly(obj,"state","components")
            || !JsonRead.TryString(obj["state"],out var stateName)||stateName is not ("available" or "unavailable")
            || obj["components"] is not JsonObject components||!JsonRead.HasExactly(components,Components))throw new InvalidDataException("workstation_protection_state_invalid");
        foreach(var pair in components) {
            if(pair.Value is null)continue;
            if(stateName=="unavailable" || pair.Value is not JsonValue value || value.GetValueKind() is not (JsonValueKind.True or JsonValueKind.False)) throw new InvalidDataException("workstation_protection_state_invalid");
        }
        if(!JsonRead.TryString(packet["header"]?["observed_at_utc"],out var observed)||!PythonIsoDateTime.TryParse(observed.Replace("Z","+00:00",StringComparison.Ordinal),out var parsed)||!parsed.IsAware||!parsed.TryToUtc(out var utc)) throw new InvalidDataException("workstation_protection_timestamp_invalid");
        return new Prepared((JsonObject)obj.DeepClone(),utc);
    }
    public static async Task StoreAsync(NpgsqlConnection db,NpgsqlTransaction tx,string agent,long entity,long? ad,Prepared prepared,CancellationToken ct)
    {
        string id=Packets.Digest(new JsonArray(JsonValue.Create(agent),JsonValue.Create("protection_state"))),hash=Packets.Digest(prepared.State);
        const string sql="""
            insert into sli_plugin_workstations.protection_state(id,agent_key,entity_id,ad_computer_id,observed_at,state,state_sha256)
            values(@id,@agent,@entity,@ad,@observed,@state,@hash)
            on conflict(agent_key) do update set entity_id=excluded.entity_id,ad_computer_id=excluded.ad_computer_id,
                observed_at=excluded.observed_at,state=excluded.state,state_sha256=excluded.state_sha256
            where protection_state.observed_at<excluded.observed_at returning id
            """;
        await using var command=new NpgsqlCommand(sql,db,tx);command.Parameters.AddWithValue("id",id);command.Parameters.AddWithValue("agent",agent);command.Parameters.AddWithValue("entity",entity);
        command.Parameters.AddWithValue("ad",NpgsqlDbType.Bigint,ad is null?DBNull.Value:ad.Value);command.Parameters.AddWithValue("observed",prepared.ObservedAt);
        command.Parameters.AddWithValue("state",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(prepared.State));command.Parameters.AddWithValue("hash",hash);
        if(await command.ExecuteScalarAsync(ct) is not null)return;
        await using var check=new NpgsqlCommand("select observed_at,state_sha256 from sli_plugin_workstations.protection_state where agent_key=@agent",db,tx);check.Parameters.AddWithValue("agent",agent);
        await using var reader=await check.ExecuteReaderAsync(ct);if(!await reader.ReadAsync(ct))throw new InvalidDataException("workstation_protection_replay_conflict");
        var previous=reader.GetFieldValue<DateTimeOffset>(0);if(previous==prepared.ObservedAt && reader.GetString(1)!=hash)throw new InvalidDataException("workstation_protection_replay_conflict");
    }
}
