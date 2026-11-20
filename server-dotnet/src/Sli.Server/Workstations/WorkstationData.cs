using Sli.Server.Infrastructure;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;

namespace Sli.Server.Workstations;

internal static class Ws
{
    internal static string? Text(this JsonNode? n,string k) => n?[k] is JsonValue v && v.TryGetValue<string>(out var s)?s:null;
    internal static long Number(this JsonNode? n,string k) => long.TryParse(n?[k]?.ToString(),CultureInfo.InvariantCulture,out long x)?x:0;
    internal static string Hash(JsonNode? n)=>Sha(CanonicalJson.Serialize(n));
    internal static string Sha(string s)=>Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(s)));
    internal static bool IsHash(string? s)=>s is {Length:64}&&s.All(c=>c is >= 'a' and <= 'f' or >= '0' and <= '9');
    internal static DateTimeOffset Time(string? s)
    {
        if(s is null||!System.Text.RegularExpressions.Regex.IsMatch(s,@"(?:Z|[+-]\d{2}:\d{2})$"))throw new WorkstationException("workstation_protection_timestamp_invalid");
        return DateTimeOffset.Parse(s,CultureInfo.InvariantCulture).ToUniversalTime();
    }
    internal static string Stamp(DateTimeOffset s)=>s.ToUniversalTime().ToString(s.Ticks%TimeSpan.TicksPerSecond==0?"yyyy-MM-dd'T'HH:mm:sszzz":"yyyy-MM-dd'T'HH:mm:ss.ffffffzzz",CultureInfo.InvariantCulture);
    internal static JsonObject Quality(string status,string? reason=null)=>new(){["status"]=status,["reasons"]=reason is null?new JsonArray():new JsonArray(new JsonObject{["code"]=reason,["message_key"]="workstations.reasons."+reason,["params"]=new JsonObject()})};
    internal static JsonObject Count(long? value,string relation)=>new(){["value"]=value,["relation"]=relation};
    internal static NpgsqlCommand Command(NpgsqlConnection db,string sql,params object?[] args)
    {
        SqlArguments.Validate(args);
        var cmd=new NpgsqlCommand(sql,db){CommandTimeout=0};
        for(int i=0;i<args.Length;i++)
        {
            var value=args[i];
            cmd.Parameters.Add(value is JsonNode json?new NpgsqlParameter("p"+i,NpgsqlDbType.Jsonb){Value=json.ToJsonString()}:new NpgsqlParameter("p"+i,value??DBNull.Value));
        }
        return cmd;
    }
    internal static async Task<List<JsonObject>> Rows(NpgsqlConnection db,string sql,CancellationToken ct,params object?[] args)
    {
        SqlArguments.Validate(args);
        await using var cmd=Command(db,"select to_jsonb(ws_row)::text from ("+sql+") ws_row",args);
        return await Rows(cmd,ct);
    }
    internal static async Task<List<JsonObject>> Rows(NpgsqlCommand cmd,CancellationToken ct)
    {
        var result=new List<JsonObject>();
        await using var reader=await cmd.ExecuteReaderAsync(ct);
        while(await reader.ReadAsync(ct))result.Add(JsonNode.Parse(reader.GetString(0))!.AsObject());
        return result;
    }
    internal static async Task<object?> Scalar(NpgsqlConnection db,string sql,CancellationToken ct,params object?[] args)
    {SqlArguments.Validate(args);await using var cmd=Command(db,sql,args);return await cmd.ExecuteScalarAsync(ct);}
    internal static async Task<int> Exec(NpgsqlConnection db,string sql,CancellationToken ct,params object?[] args)
    {SqlArguments.Validate(args);await using var cmd=Command(db,sql,args);return await cmd.ExecuteNonQueryAsync(ct);}
    internal static JsonArray Array(IEnumerable<JsonObject> rows)=>new(rows.Select(r=>(JsonNode)r.DeepClone()).ToArray());
    internal static JsonObject Pick(JsonNode n,params string[] keys)=>new(keys.Select(k=>new KeyValuePair<string,JsonNode?>(k,n[k]?.DeepClone())));
    internal static void NormalizeTransport(JsonObject row){row["observed_at"]=Stamp(Time(row.Text("observed_at")));}
    // Table/columns are compiled constants of reviewed evaluators, never request or source keys.
    internal static async Task Insert(NpgsqlConnection db,string table,JsonObject row,string conflict,CancellationToken ct)
    {
        var columns=row.Select(p=>p.Key).ToArray();
        var slots=columns.Select((k,i)=>"@p"+i+(row[k] is JsonObject or JsonArray?"::jsonb":"")).ToArray();
        await using var cmd=new NpgsqlCommand($"insert into sli_plugin_workstations.{table} ({string.Join(',',columns)}) values ({string.Join(',',slots)}) {conflict}",db);
        for(int i=0;i<columns.Length;i++)
        {
            string k=columns[i];var n=row[k];
            if(n is JsonObject or JsonArray)cmd.Parameters.AddWithValue("p"+i,NpgsqlDbType.Jsonb,n.ToJsonString());
            else if(k.EndsWith("_at",StringComparison.Ordinal)||k=="as_of_utc")cmd.Parameters.AddWithValue("p"+i,NpgsqlDbType.TimestampTz,n is null?DBNull.Value:Time(n.ToString()));
            else if(n is null)cmd.Parameters.AddWithValue("p"+i,DBNull.Value);
            else if(n.GetValueKind()==JsonValueKind.Number)cmd.Parameters.AddWithValue("p"+i,n.GetValue<int>());
            else if(n.GetValueKind() is JsonValueKind.True or JsonValueKind.False)cmd.Parameters.AddWithValue("p"+i,n.GetValue<bool>());
            else cmd.Parameters.AddWithValue("p"+i,n.GetValue<string>());
        }
        await cmd.ExecuteNonQueryAsync(ct);
    }
}
public sealed class WorkstationException(string code,int status=400):Exception(code)
{public int Status {get;}=status;}
