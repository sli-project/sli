using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Infrastructure;

namespace Sli.Server.Access.Administration;

public sealed class AssignmentPackageWriter(IPostgresConnectionFactory connections)
{
    public async Task<JsonElement> CreateAsync(JsonElement payload, AssignmentActor? actor, string? remoteAddress, CancellationToken ct)
    {
        var values = AssignmentValidation.Parse(payload, true);
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        long packageId; string packageName;
        await using (var lookup = new NpgsqlCommand("select id,name from access_packages where package_key=@key", connection, transaction))
        {
            lookup.Parameters.AddWithValue("key", values.Key); await using var reader = await lookup.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct)) throw AssignmentValidation.Error("access_package_not_found");
            packageId = reader.GetInt64(0); packageName = reader.GetString(1);
        }
        await ReportAssignmentWriter.EnsureSubjectAsync(transaction, values, ct);
        await using var write = new NpgsqlCommand("""
            with changed as (
                insert into access_subject_packages(subject_type,subject_id,package_id,effect,valid_from,valid_until,business_reason,approved_by,source_type,created_by)
                values(@subject,@subject_id,@package,@effect,@from,@until,@reason,@approved,@source,@actor)
                on conflict(subject_type,subject_id,package_id,effect,source_type) do update set
                    valid_from=excluded.valid_from,valid_until=excluded.valid_until,business_reason=excluded.business_reason,
                    approved_by=excluded.approved_by,created_by=excluded.created_by,created_at=now()
                returning id,subject_type,subject_id,package_id,effect,valid_from,valid_until,business_reason,approved_by,source_type,created_at
            ) select to_jsonb(changed) from changed
            """, connection, transaction);
        ReportAssignmentWriter.Bind(write, values, actor); write.Parameters.AddWithValue("package", packageId);
        var raw = AssignmentAudit.Row((string)(await write.ExecuteScalarAsync(ct))!);
        var result = JsonNode.Parse(raw.GetRawText())!.AsObject(); result["package_key"] = values.Key; result["package_name"] = packageName;
        await AssignmentAudit.AppendAsync(transaction, actor, values, raw.Get("id").GetInt64(), true, remoteAddress, ct);
        await transaction.CommitAsync(ct);
        return JsonSerializer.SerializeToElement(result);
    }
}
