using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;

namespace Sli.Server.Storage.Direct;

internal static partial class Direct4624Writes
{
    // Turn the existing fixed column/parameter mapping into a typed PostgreSQL
    // rowset. No values or identifiers from the source are interpolated into SQL.
    internal static async Task WriteBatchAsync(NpgsqlConnection db,NpgsqlTransaction tx,
        IReadOnlyList<NpgsqlCommand> commands,string table,CancellationToken ct)
    {
        if(commands.Count==0)return;
        string failure=table switch {
            "entities_v2"=>"storage_v2_entity_conflict", "entity_details_v2"=>"storage_v2_entity_details_conflict",
            _=>throw new ArgumentOutOfRangeException(nameof(table))
        };
        string sql=commands[0].CommandText;
        int columnsStart=sql.IndexOf('('),columnsEnd=sql.IndexOf(')',columnsStart);
        string columns=sql[(columnsStart+1)..columnsEnd];
        int valuesStart=sql.IndexOf("values(",StringComparison.Ordinal),valuesEnd=sql.IndexOf(')',valuesStart);
        var names=columns.Split(',').Select(x=>x.Trim()).ToArray();
        var parameters=sql[(valuesStart+7)..valuesEnd].Split(',').Select(x=>x.Trim().TrimStart('@')).ToArray();
        var rows=new JsonArray();
        foreach(var command in commands) {
            var row=new JsonObject();
            for(int i=0;i<names.Length;i++) {
                var parameter=command.Parameters[parameters[i]];object value=parameter.Value!;
                row[names[i]]=value is DBNull?null:value is byte[] bytes?JsonValue.Create("\\x"+Convert.ToHexStringLower(bytes)):
                    parameter.NpgsqlDbType==NpgsqlDbType.Jsonb?JsonNode.Parse((string)value):JsonSerializer.SerializeToNode(value);
            }
            rows.Add(row);
        }
        string selection=string.Join(',',names.Select(x=>"w."+x));
        string batchSql=sql[..valuesStart]+$"select {selection} from jsonb_populate_recordset(null::{table},@rows) w "+sql[(valuesEnd+1)..];
        await using(var write=new NpgsqlCommand(batchSql,db,tx)) {
            write.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,rows.ToJsonString());
            int count=0;
            await using(var reader=await write.ExecuteReaderAsync(ct)) while(await reader.ReadAsync(ct))count++;
            if(count!=commands.Count)throw new InvalidOperationException(failure);
        }
    }
}
