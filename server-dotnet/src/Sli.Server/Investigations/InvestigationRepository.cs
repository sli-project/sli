using Npgsql;
using NpgsqlTypes;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Infrastructure;

namespace Sli.Server.Investigations;

public sealed class InvestigationRepository(IPostgresConnectionFactory connections) : IInvestigationRepository
{
    public async Task<IReadOnlyList<IReadOnlyList<AccessResource>>> ResourceGroupsAsync(InvestigationIdentity identity, CancellationToken ct)
    {
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        long id = await CaseId(connection, transaction, identity, false, ct);
        var groups = new List<IReadOnlyList<AccessResource>>();
        await using (var command = new NpgsqlCommand("""
            select linked.event_db_id, source.server_id, source.domain_id, source.channel
            from investigation_events linked
            left join lateral (
                select core.server_id, server.domain_id, channel.value as channel
                from storage_v2_event_identity_allocations core
                join servers server on server.id=core.server_id
                join storage_v2_channel channel on channel.id=core.channel_id
                where core.id=linked.event_db_id
            ) source on true
            where linked.investigation_id=@id order by linked.event_db_id
            """, connection, transaction))
        {
            command.Parameters.AddWithValue("id", id);
            await using var reader = await command.ExecuteReaderAsync(ct);
            var seen = new HashSet<long>();
            while (await reader.ReadAsync(ct))
            {
                if (!seen.Add(reader.GetInt64(0))) continue;
                var group = new List<AccessResource>();
                if (!reader.IsDBNull(1)) group.Add(new("server", reader.GetInt64(1)));
                if (!reader.IsDBNull(2)) group.Add(new("domain", reader.GetInt64(2)));
                if (!reader.IsDBNull(3) && reader.GetString(3).Length > 0) group.Add(new("channel", Value: reader.GetString(3)));
                groups.Add(group); // Missing linked events remain empty and deny access.
            }
        }
        await using (var command = new NpgsqlCommand("""
            select source_domain_id from investigation_evidence_refs where investigation_id=@id
            order by source_domain_id,reference_id
            """, connection, transaction))
        {
            command.Parameters.AddWithValue("id", id);
            await using var reader = await command.ExecuteReaderAsync(ct);
            var seen = new HashSet<long>();
            while (await reader.ReadAsync(ct))
                if (seen.Add(reader.GetInt64(0))) groups.Add([new AccessResource("domain", reader.GetInt64(0))]);
        }
        await transaction.CommitAsync(ct);
        return groups;
    }

    public async Task<InvestigationNote> AddNoteAsync(InvestigationIdentity identity, string body, string actor, CancellationToken ct)
    {
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        // Preserve _case_row's full read dependencies before any mutation. A
        // failed evidence/notes read must roll back rather than fabricate success.
        long id = await CaseId(connection, transaction, identity, true, ct);
        foreach (string sql in new[]
        {
            "select event_db_id, relation_status, added_by, added_at from investigation_events where investigation_id=@id order by added_at desc limit 500",
            "select evidence_kind,source_domain_id,reference_id,relation_status,added_by,added_at from investigation_evidence_refs where investigation_id=@id order by added_at desc,evidence_kind,reference_id limit 500",
            "select id, body, created_by, created_at from investigation_notes where investigation_id=@id order by created_at desc limit 100"
        })
        {
            await using var read = new NpgsqlCommand(sql, connection, transaction);
            read.Parameters.AddWithValue("id", id);
            await using var reader = await read.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct)) { }
        }
        InvestigationNote note;
        await using (var insert = new NpgsqlCommand("""
            insert into investigation_notes(investigation_id, body, created_by)
            values (@id,@body,@actor) returning id,body,created_by,created_at
            """, connection, transaction))
        {
            insert.Parameters.AddWithValue("id", id);
            insert.Parameters.AddWithValue("body", body);
            insert.Parameters.AddWithValue("actor", actor);
            await using var reader = await insert.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct)) throw new InvalidOperationException("Investigation note insert returned no row");
            note = new(reader.GetInt64(0), reader.GetString(1), reader.IsDBNull(2) ? null : reader.GetString(2),
                AssignmentAudit.Stamp(new DateTimeOffset(reader.GetDateTime(3))));
        }
        await using (var update = new NpgsqlCommand("update investigations set updated_at=now() where id=@id", connection, transaction))
        { update.Parameters.AddWithValue("id", id); await update.ExecuteNonQueryAsync(ct); }
        await using (var audit = new NpgsqlCommand("insert into investigation_audit(investigation_id,action,actor) values (@id,'note_added',@actor)", connection, transaction))
        { audit.Parameters.AddWithValue("id", id); audit.Parameters.AddWithValue("actor", actor); await audit.ExecuteNonQueryAsync(ct); }
        await transaction.CommitAsync(ct);
        return note;
    }

    private static async Task<long> CaseId(NpgsqlConnection connection, NpgsqlTransaction transaction, InvestigationIdentity identity, bool full, CancellationToken ct)
    {
        string fields = full ? "id,public_id,title,status,owner,created_by,created_at,updated_at,closed_at" : "id";
        await using var command = new NpgsqlCommand($"select {fields} from investigations where {identity.Column}=@identity", connection, transaction);
        if (identity.Id is { } id) command.Parameters.AddWithValue("identity", NpgsqlDbType.Numeric, id);
        else command.Parameters.AddWithValue("identity", NpgsqlDbType.Uuid, identity.PublicId!.Value);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) throw new InvestigationException("not_found", $"Investigation {identity.Display} was not found", 404);
        return reader.GetInt64(0);
    }
}
