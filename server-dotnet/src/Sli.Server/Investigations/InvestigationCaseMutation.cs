using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Infrastructure;

namespace Sli.Server.Investigations;

public sealed record InvestigationCaseMutationInput(string Operation, string? Value)
{
    public static InvestigationCaseMutationInput Parse(string operation, JsonElement payload)
    {
        var item = payload.ValueKind == JsonValueKind.Object && payload.TryGetProperty(operation, out var value) ? value : default;
        var text = AssignmentValidation.Strip(AuthJsonBody.Truthy(item) ? InvestigationPythonString.String(item) : "");
        if (operation == "owner") return new(operation, string.Concat(text.EnumerateRunes().Take(200).Select(r => r.ToString())) is { Length: > 0 } owner ? owner : null);
        if (operation != "status") throw new InvalidOperationException("Unknown mutation");
        text = text.ToLowerInvariant();
        if (text is not ("new" or "active" or "review" or "confirmed" or "closed"))
            throw new InvestigationException("invalid_status", "Unsupported investigation status");
        return new(operation, text);
    }
    public void CheckTransition(string current)
    {
        if (Operation != "status" || current == Value) return;
        bool allowed = current switch
        {
            "new" => Value is "active" or "closed",
            "active" => Value is "review" or "confirmed" or "closed",
            "review" => Value is "active" or "confirmed" or "closed",
            "confirmed" => Value is "active" or "closed",
            "closed" => Value is "active",
            _ => false
        };
        if (!allowed) throw new InvestigationException("conflict", $"Transition {current} -> {Value} is not allowed", 409);
    }
}

public sealed record InvestigationCaseMutationResult(JsonObject Case, bool Replay);
public interface IInvestigationCaseMutationRepository
{
    Task<InvestigationCaseMutationResult> ApplyAsync(InvestigationIdentity identity, InvestigationCaseMutationInput input, string actor, CancellationToken ct);
}

public sealed class InvestigationCaseMutationRepository(IPostgresConnectionFactory connections) : IInvestigationCaseMutationRepository
{
    public async Task<InvestigationCaseMutationResult> ApplyAsync(InvestigationIdentity identity, InvestigationCaseMutationInput input, string actor, CancellationToken ct)
    {
        await using var connection = await connections.OpenAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(ct);
        return await InvestigationCaseMutation.ExecuteAsync(new SqlTransaction(connection, tx), identity, input, actor, ct);
    }
    private sealed class SqlTransaction(NpgsqlConnection connection, NpgsqlTransaction tx) : IInvestigationCaseTransaction
    {
        public Task<JsonObject> ReadAsync(InvestigationIdentity identity, CancellationToken ct) => ReadCase(connection, tx, identity, ct);
        public async Task WriteAsync(long id, InvestigationCaseMutationInput input, string? old, string actor, CancellationToken ct)
        {
            string update = input.Operation == "status"
                ? "update investigations set status=@value,updated_at=now(),closed_at=case when @value='closed' then now() else null end where id=@id"
                : "update investigations set owner=@value,updated_at=now() where id=@id";
            await using (var cmd = new NpgsqlCommand(update, connection, tx))
            {
                cmd.Parameters.AddWithValue("id", id);
                cmd.Parameters.AddWithValue("value", NpgsqlDbType.Text, (object?)input.Value ?? DBNull.Value);
                await cmd.ExecuteNonQueryAsync(ct);
            }
            string audit = input.Operation == "status"
                ? "insert into investigation_audit(investigation_id,action,actor,payload) values (@id,'status_changed',@actor,jsonb_build_object('old_status',@old::text,'new_status',@value::text))"
                : "insert into investigation_audit(investigation_id,action,actor,payload) values (@id,'owner_changed',@actor,jsonb_build_object('old_owner',@old::text,'new_owner',@value::text))";
            await using var auditCmd = new NpgsqlCommand(audit, connection, tx);
            auditCmd.Parameters.AddWithValue("id", id); auditCmd.Parameters.AddWithValue("actor", actor);
            auditCmd.Parameters.AddWithValue("old", NpgsqlDbType.Text, (object?)old ?? DBNull.Value);
            auditCmd.Parameters.AddWithValue("value", NpgsqlDbType.Text, (object?)input.Value ?? DBNull.Value);
            await auditCmd.ExecuteNonQueryAsync(ct);
        }
        public Task CommitAsync(CancellationToken ct) => tx.CommitAsync(ct);
    }
    internal static async Task<JsonObject> ReadCase(NpgsqlConnection connection, NpgsqlTransaction tx, InvestigationIdentity identity, CancellationToken ct)
    {
        JsonObject result;
        await using (var cmd = new NpgsqlCommand($"select row_to_json(c)::text from (select id,public_id,title,status,owner,created_by,created_at,updated_at,closed_at from investigations where {identity.Column}=@identity) c", connection, tx))
        {
            if (identity.Id is { } id) cmd.Parameters.AddWithValue("identity", NpgsqlDbType.Numeric, id);
            else cmd.Parameters.AddWithValue("identity", NpgsqlDbType.Uuid, identity.PublicId!.Value);
            var row = (string?)await cmd.ExecuteScalarAsync(ct);
            if (row is null) throw new InvestigationException("not_found", $"Investigation {identity.Display} was not found", 404);
            result = JsonNode.Parse(row)!.AsObject();
        }
        long caseId = result["id"]!.GetValue<long>();
        foreach (var (name, sql) in new[] {
            ("events", "select event_db_id,relation_status,added_by,added_at from investigation_events where investigation_id=@id order by added_at desc limit 500"),
            ("evidence_refs", "select evidence_kind,source_domain_id,reference_id,relation_status,added_by,added_at from investigation_evidence_refs where investigation_id=@id order by added_at desc,evidence_kind,reference_id limit 500"),
            ("notes", "select id,body,created_by,created_at from investigation_notes where investigation_id=@id order by created_at desc limit 100") })
        {
            var rows = new JsonArray();
            await using var cmd = new NpgsqlCommand("select row_to_json(t)::text from (" + sql + ") t", connection, tx);
            cmd.Parameters.AddWithValue("id", caseId);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct)) rows.Add(JsonNode.Parse(reader.GetString(0)));
            result[name] = rows;
        }
        return result;
    }
}

public interface IInvestigationCaseTransaction
{
    Task<JsonObject> ReadAsync(InvestigationIdentity identity, CancellationToken ct);
    Task WriteAsync(long id, InvestigationCaseMutationInput input, string? old, string actor, CancellationToken ct);
    Task CommitAsync(CancellationToken ct);
}

public static class InvestigationCaseMutation
{
    public static async Task<InvestigationCaseMutationResult> ExecuteAsync(IInvestigationCaseTransaction tx, InvestigationIdentity identity, InvestigationCaseMutationInput input, string actor, CancellationToken ct)
    {
        var current = await tx.ReadAsync(identity, ct);
        long id = current["id"]!.GetValue<long>();
        string? old = current[input.Operation]?.GetValue<string>();
        if (old == input.Value) { await tx.CommitAsync(ct); return new(current, true); }
        input.CheckTransition(old ?? "None");
        await tx.WriteAsync(id, input, old, actor, ct);
        var updated = await tx.ReadAsync(new(id, null), ct);
        await tx.CommitAsync(ct);
        return new(updated, false);
    }
}
