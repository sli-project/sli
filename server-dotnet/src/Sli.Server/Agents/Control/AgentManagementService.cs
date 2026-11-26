using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Hosting;

namespace Sli.Server.Agents.Control;

public sealed partial class AgentManagementService(IAgentControlAudit audit, AgentCertificateRejections? rejections = null)
{
    public async Task<JsonElement> CreateTokenAsync(NpgsqlConnection db, NpgsqlTransaction tx, JsonElement payload, string actor, CancellationToken ct)
    {
        Guid host = AgentControlJson.Id(AgentControlJson.Get(payload, "host_id"));
        Guid? replacement = payload.TryGetProperty("replacement_for", out var rawReplacement) ? AgentControlJson.Id(rawReplacement) : null;
        if (replacement is not null)
        {
            await using var read = new NpgsqlCommand("select id from sli_agents where id=@id and status='active' for update", db, tx);
            read.Parameters.AddWithValue("id", replacement.Value); if (await read.ExecuteScalarAsync(ct) is null) throw new AgentControlException("agent_not_found", 404);
        }
        var instanceValue = AgentControlJson.Get(payload, "instance_name"); string? instance = AgentControlJson.String(instanceValue);
        if (instanceValue.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Null) && !AgentControlJson.Matches(instance, @"\A[a-z0-9][a-z0-9_-]{0,47}\z")) throw new AgentControlException("invalid_agent_instance_name");
        string? fp = AgentControlJson.String(AgentControlJson.Get(payload, "key_fingerprint"));
        var ttlValue = AgentControlJson.Get(payload, "ttl_seconds");
        var nameValue = AgentControlJson.Get(payload, "registration_host_name"); string? name = AgentControlJson.ReportedName(nameValue);
        if (nameValue.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Null) && name is null) throw new AgentControlException("invalid_agent_registration_name");
        if (!AgentControlJson.Matches(fp, @"\A[0-9a-f]{64}\z")) throw new AgentControlException("invalid_key_fingerprint");
        long ttl = 900;
        if (ttlValue.ValueKind != JsonValueKind.Undefined && (ttlValue.ValueKind != JsonValueKind.Number || !ttlValue.TryGetInt64(out ttl) || ttl is < 60 or > 3600)) throw new AgentControlException("invalid_enrollment_ttl");
        string token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        string digest = Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(token))); Guid id = Guid.NewGuid();
        var now = AgentControlJson.Now(); var expires = now.AddSeconds(ttl);
        await using var insert = new NpgsqlCommand("insert into sli_agent_enrollment_tokens(id,token_hash,host_id,key_fingerprint,created_at,expires_at,instance_name,replacement_for) values(@id,@hash,@host,@fp,@now,@expires,@instance,@replacement)", db, tx);
        insert.Parameters.AddWithValue("id", id); insert.Parameters.AddWithValue("hash", digest); insert.Parameters.AddWithValue("host", host); insert.Parameters.AddWithValue("fp", fp!);
        insert.Parameters.AddWithValue("now", now); insert.Parameters.AddWithValue("expires", expires);
        insert.Parameters.AddWithValue("instance", NpgsqlDbType.Text, (object?)instance ?? DBNull.Value); insert.Parameters.AddWithValue("replacement", NpgsqlDbType.Uuid, (object?)replacement ?? DBNull.Value); await insert.ExecuteNonQueryAsync(ct);
        var details = new Dictionary<string, object?> { ["ttl_seconds"] = ttl, ["instance_name"] = instance };
        if (replacement is not null) details["replacement_for"] = replacement.Value.ToString(); if (name is not null) details["registration_host_name"] = name;
        await audit.AppendAsync(db, tx, "token_create", actor, id.ToString(), details, ct);
        return JsonSerializer.SerializeToElement(new { id, token, host_id = host, expires_at = AgentControlJson.Stamp(expires, true), instance_name = instance });
    }

    public async Task<JsonElement> ListTokensAsync(NpgsqlConnection db, NpgsqlTransaction tx, string actor, CancellationToken ct)
    {
        var items = await RowsAsync(db, tx, "select id,host_id,key_fingerprint,created_at,expires_at,used_at,revoked_at,instance_name from sli_agent_enrollment_tokens order by created_at desc,id limit 100", ct);
        await audit.AppendAsync(db, tx, "token_list", actor, "tokens", new { }, ct); return JsonSerializer.SerializeToElement(new { items });
    }

    public async Task<JsonElement> RevokeTokenAsync(NpgsqlConnection db, NpgsqlTransaction tx, JsonElement payload, string actor, CancellationToken ct)
    {
        Guid id = AgentControlJson.Id(AgentControlJson.Get(payload, "id"));
        await using var update = new NpgsqlCommand("update sli_agent_enrollment_tokens set revoked_at=coalesce(revoked_at,clock_timestamp()) where id=@id returning id", db, tx);
        update.Parameters.AddWithValue("id", id); if (await update.ExecuteScalarAsync(ct) is null) throw new AgentControlException("enrollment_token_not_found", 404);
        await audit.AppendAsync(db, tx, "token_revoke", actor, id.ToString(), new { }, ct); return JsonSerializer.SerializeToElement(new { status = "revoked" });
    }

    public async Task<JsonElement> RevokeAsync(NpgsqlConnection db, NpgsqlTransaction tx, JsonElement payload, string actor, bool disable, CancellationToken ct)
    {
        Guid id = AgentControlJson.Id(AgentControlJson.Get(payload, "agent_id")); string? serial = AgentControlJson.String(AgentControlJson.Get(payload, "serial"));
        if (!disable && !AgentControlJson.Matches(serial, @"\A[0-9a-f]{1,40}\z")) throw new AgentControlException("invalid_agent_serial");
        await using (var read = new NpgsqlCommand("select id from sli_agents where id=@id for update", db, tx))
        { read.Parameters.AddWithValue("id", id); if (await read.ExecuteScalarAsync(ct) is null) throw new AgentControlException("agent_not_found", 404); }
        await LockImportAsync(db,tx,id,ct);
        await using (var gate = new NpgsqlCommand("select pg_advisory_xact_lock(hashtext('sli-agent-revocations'))", db, tx)) await gate.ExecuteNonQueryAsync(ct);
        if (disable)
        {
            await using var status = new NpgsqlCommand("update sli_agents set status='disabled' where id=@id", db, tx); status.Parameters.AddWithValue("id", id); await status.ExecuteNonQueryAsync(ct);
        }
        var revoked = new List<string>();
        await using (var update = new NpgsqlCommand(disable
            ? "update sli_agent_certificates set revoked_at=clock_timestamp() where agent_id=@id and revoked_at is null returning serial"
            : "update sli_agent_certificates set revoked_at=coalesce(revoked_at,clock_timestamp()) where agent_id=@id and serial=@serial returning serial", db, tx))
        {
            update.Parameters.AddWithValue("id", id); if (!disable) update.Parameters.AddWithValue("serial", serial!);
            await using var reader = await update.ExecuteReaderAsync(ct); while (await reader.ReadAsync(ct)) revoked.Add(reader.GetString(0));
        }
        if (!disable && revoked.Count == 0) throw new AgentControlException("agent_certificate_not_found", 404);
        foreach (string value in revoked) await audit.AppendAsync(db, tx, "revoke", actor, id.ToString(), new { serial = value }, ct);
        if (disable) await audit.AppendAsync(db, tx, "disable", actor, id.ToString(), new { }, ct);
        return JsonSerializer.SerializeToElement(new { status = disable ? "disabled" : "revoked" });
    }

    // Always take the agent row lock first. Imports retain this advisory lock
    // across their short read/finalization transactions and the hot write.
    internal static async Task LockImportAsync(NpgsqlConnection db,NpgsqlTransaction tx,Guid id,CancellationToken ct,bool session=false)
    {
        await using var command=new NpgsqlCommand(session
            ? "select pg_advisory_lock(hashtextextended(@key,0))"
            : "select pg_advisory_xact_lock(hashtextextended(@key,0))",db,tx);
        command.Parameters.AddWithValue("key","sli-agent-import:"+id.ToString("D")); await command.ExecuteNonQueryAsync(ct);
    }
    internal static async Task UnlockImportAsync(NpgsqlConnection db,Guid id,bool required=true)
    {
        await using var command=new NpgsqlCommand("select pg_advisory_unlock(hashtextextended(@key,0))",db) { CommandTimeout=0 };
        command.Parameters.AddWithValue("key","sli-agent-import:"+id.ToString("D"));
        if(await command.ExecuteScalarAsync(CancellationToken.None) is not true && required)throw new InvalidOperationException("agent_import_lock_lost");
    }
}
