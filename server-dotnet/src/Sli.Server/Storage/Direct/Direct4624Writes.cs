using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol.Compatibility;

namespace Sli.Server.Storage.Direct;

internal static partial class Direct4624Writes
{
    internal static NpgsqlCommand EntityCommand(NpgsqlConnection db,NpgsqlTransaction tx,DirectEntityModel entity)
    {
        var command = new NpgsqlCommand("""
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,server_id,first_seen_utc,last_seen_utc,source_core_sha256)
            values(@id,@type,@key,@name,@domain,@server,@first,@last,@hash)
            on conflict(id) do update set entity_type_id=excluded.entity_type_id,natural_key=excluded.natural_key,
               display_name=excluded.display_name,domain_id=excluded.domain_id,server_id=excluded.server_id,
               first_seen_utc=excluded.first_seen_utc,last_seen_utc=excluded.last_seen_utc,source_core_sha256=excluded.source_core_sha256
            where entities_v2.entity_type_id=excluded.entity_type_id and entities_v2.natural_key=excluded.natural_key returning id
            """, db, tx);
            command.Parameters.AddWithValue("id",entity.Id); command.Parameters.AddWithValue("type",entity.TypeId);
            command.Parameters.AddWithValue("key",entity.Source.NaturalKey); command.Parameters.AddWithValue("name",entity.Source.DisplayName);
            command.Parameters.AddWithValue("domain",NpgsqlDbType.Bigint,(object?)entity.DomainId ?? DBNull.Value);
            command.Parameters.AddWithValue("server",NpgsqlDbType.Bigint,(object?)entity.ServerId ?? DBNull.Value);
            command.Parameters.AddWithValue("first",entity.FirstSeen); command.Parameters.AddWithValue("last",entity.LastSeen);
            command.Parameters.AddWithValue("hash",entity.CoreHash);
        return command;
    }
    internal static NpgsqlCommand EntityDetailsCommand(NpgsqlConnection db,NpgsqlTransaction tx,DirectEntityModel entity)
    {
        var details = new NpgsqlCommand("""
            insert into entity_details_v2(entity_id,attributes_json,source_details_sha256) values(@id,@data,@hash)
            on conflict(entity_id) do update set attributes_json=excluded.attributes_json,source_details_sha256=excluded.source_details_sha256 returning entity_id
            """, db, tx);
        details.Parameters.AddWithValue("id", entity.Id);
        details.Parameters.AddWithValue("data", NpgsqlDbType.Jsonb, SourceJson.Serialize(entity.Source.Attributes));
        details.Parameters.AddWithValue("hash", entity.DetailsHash);
        return details;
    }
}
