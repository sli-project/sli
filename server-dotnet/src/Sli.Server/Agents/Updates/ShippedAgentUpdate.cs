using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;

namespace Sli.Server.Agents.Updates;

internal static class ShippedAgentUpdate
{
    internal const string Actor = "native:shipped-agent";
    private const int BatchSize = 100;

    // The native release is already verified by the installer. Only bytes from
    // that release are eligible for the MSI channel. Admin uploads still use the
    // signed ZIP verifier.
    internal static async Task RegisterAsync(NpgsqlConnection db, string directory, IAgentControlAudit audit, CancellationToken ct)
    {
        string path = Path.Combine(directory, "SliAgent.msi");
        byte[]? archive = null;
        string? hash = null, version = null;
        try
        {
            if (File.Exists(path) || File.Exists(path + ".json"))
            {
                await using var file = File.OpenRead(path);
                if (file.Length is < 1 or > 268435456)
                    throw new InvalidDataException();
                archive = new byte[(int)file.Length];
                await file.ReadExactlyAsync(archive, ct);
                if (file.ReadByte() != -1)
                    throw new InvalidDataException();
                hash = Convert.ToHexStringLower(SHA256.HashData(archive));
                version = await AgentConsolePackage.ReadVersionAsync(path, hash, ct);
                if (version.Length == 0)
                    throw new InvalidDataException();
            }
        }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or JsonException)
        {
            throw new AgentControlException("agent_package_verification_failed");
        }

        await using var tx = await db.BeginTransactionAsync(ct);
        await AgentClientControlService.LockUpdateWavesAsync(db, tx, ct);
        if (archive is null)
        {
            await using var clear = new NpgsqlCommand("""
                update platform_settings set value='',updated_at=now(),updated_by=@actor
                where key='agents.shipped_update' and value<>''
                """, db, tx);
            clear.Parameters.AddWithValue("actor", Actor);
            await clear.ExecuteNonQueryAsync(ct);
            await tx.CommitAsync(ct);
            return;
        }

        await using (var add = new NpgsqlCommand("""
            insert into sli_agent_update_packages(sha256,version,manifest,archive)
            values(@hash,@version,@manifest,@archive) on conflict(sha256) do nothing
            """, db, tx))
        {
            add.Parameters.AddWithValue("hash", hash!);
            add.Parameters.AddWithValue("version", version!);
            add.Parameters.AddWithValue("archive", archive);
            add.Parameters.AddWithValue("manifest", NpgsqlDbType.Jsonb,
                JsonSerializer.Serialize(new { component = "agent", package_id = "sli.agent", format = "msi", version, sha256 = hash }));
            if (await add.ExecuteNonQueryAsync(ct) != 0)
                await audit.AppendAsync(db, tx, "update_upload", Actor, hash!, new { version, format = "msi" }, ct);
        }
        await using var wave = new NpgsqlCommand("""
            insert into sli_agent_update_waves(id,package_sha256,version,batch_size,error_threshold,created_by)
            select @id,sha256,version,@size,1000,@actor from sli_agent_update_packages
            where sha256=@hash and version=@version and manifest->>'format'='msi'
                and not exists(select 1 from sli_agent_update_waves where package_sha256=@hash and created_by=@actor)
            returning id
            """, db, tx);
        wave.Parameters.AddWithValue("id", Guid.NewGuid());
        wave.Parameters.AddWithValue("hash", hash!);
        wave.Parameters.AddWithValue("version", version!);
        wave.Parameters.AddWithValue("size", BatchSize);
        wave.Parameters.AddWithValue("actor", Actor);
        if (await wave.ExecuteScalarAsync(ct) is Guid id)
            await audit.AppendAsync(db, tx, "update_wave_create", Actor, id.ToString("D"), new { sha256 = hash, version }, ct);
        else
        {
            await using var registered = new NpgsqlCommand("""
                select 1 from sli_agent_update_waves where package_sha256=@hash and version=@version and created_by=@actor
                """, db, tx);
            registered.Parameters.AddWithValue("hash", hash!);
            registered.Parameters.AddWithValue("version", version!);
            registered.Parameters.AddWithValue("actor", Actor);
            if (await registered.ExecuteScalarAsync(ct) is null)
                throw new AgentControlException("agent_package_verification_failed");
        }

        await using var select = new NpgsqlCommand("""
            insert into platform_settings(key,value,updated_by)
            values('agents.automatic_update','automatic',@actor) on conflict(key) do nothing;
            insert into platform_settings(key,value,updated_by)
            values('agents.shipped_update',@hash,@actor) on conflict(key) do update
            set value=excluded.value,updated_by=excluded.updated_by,updated_at=now()
            where platform_settings.value is distinct from excluded.value
            """, db, tx);
        select.Parameters.AddWithValue("hash", hash!);
        select.Parameters.AddWithValue("actor", Actor);
        await select.ExecuteNonQueryAsync(ct);
        await tx.CommitAsync(ct);
    }

    internal static async Task<JsonObject?> OfferAsync(NpgsqlConnection db, NpgsqlTransaction tx, JsonObject agent,
        AgentIdentity identity, IAgentControlAudit audit, CancellationToken ct)
    {
        string? reported = AgentUpdateInput.Text(agent["rights_probe"]?["agent_version"]);
        string? hash, version, current, format;
        Guid? wave;
        int batch;
        // An explicit NULL package is the administrator's opt-out. Manual
        // waves also take precedence, including their queued members.
        await using (var read = new NpgsqlCommand("""
            select coalesce(p.sha256,w.package_sha256),coalesce(p.version,w.version),
                coalesce(p.manifest->>'format',case when w.id is not null then 'msi' end),
                w.id,w.current_batch,
                coalesce(@reported,(select r.version from sli_agent_update_results r
                    where r.agent_id=@agent order by r.observed_at desc limit 1),
                    (select a.details->>'agent_version' from sli_agent_audit a
                    where a.target=@target and a.action='issue' order by a.id desc limit 1))
            from (select @agent as id) a
            left join sli_agent_update_policy manual on manual.agent_id=a.id
            left join sli_agent_update_packages p on p.sha256=manual.package_sha256
            left join sli_agent_update_waves w on w.created_by=@actor and w.status='running'
                and w.package_sha256=(select value from platform_settings where key='agents.shipped_update')
                and exists(select 1 from platform_settings where key='agents.automatic_update' and value='automatic')
                and manual.agent_id is null
                and not exists(select 1 from sli_agent_update_wave_members m where m.agent_id=a.id and m.reserved)
            """, db, tx))
        {
            read.Parameters.AddWithValue("agent", identity.Id);
            read.Parameters.AddWithValue("target", identity.Id.ToString("D"));
            read.Parameters.AddWithValue("actor", Actor);
            read.Parameters.AddWithValue("reported", NpgsqlDbType.Text, (object?)reported ?? DBNull.Value);
            await using var row = await read.ExecuteReaderAsync(ct);
            if (!await row.ReadAsync(ct) || row.IsDBNull(0))
                return null;
            hash = row.GetString(0);
            version = row.GetString(1);
            format = row.IsDBNull(2) ? null : row.GetString(2);
            wave = row.IsDBNull(3) ? null : row.GetGuid(3);
            batch = row.IsDBNull(4) ? 0 : row.GetInt32(4);
            current = row.IsDBNull(5) ? null : row.GetString(5);
        }
        var offer = new JsonObject { ["sha256"] = hash, ["version"] = version };
        if (format != "msi")
            return offer;
        if (Version.TryParse(current, out var installed) && installed >= Version.Parse(version))
            return null;
        offer["format"] = "msi";
        if (wave is null)
            return offer;

        await using var assign = new NpgsqlCommand("""
            with assigned as (
                insert into sli_agent_update_wave_members(wave_id,agent_id,package_sha256,batch_number,state,reserved,issued_at)
                select @wave,@agent,@hash,
                    case when count(*)>=@size then least(@batch+1,1000) else greatest(@batch,1) end,
                    'pending',false,clock_timestamp()
                from sli_agent_update_wave_members where wave_id=@wave and batch_number=@batch
                on conflict(agent_id,package_sha256) do nothing returning batch_number
            )
            update sli_agent_update_waves set current_batch=assigned.batch_number from assigned
            where id=@wave returning current_batch
            """, db, tx);
        assign.Parameters.AddWithValue("wave", wave.Value);
        assign.Parameters.AddWithValue("agent", identity.Id);
        assign.Parameters.AddWithValue("hash", hash);
        assign.Parameters.AddWithValue("batch", batch);
        assign.Parameters.AddWithValue("size", BatchSize);
        if (await assign.ExecuteScalarAsync(ct) is int issued)
            await audit.AppendAsync(db, tx, "update_assign", Actor, identity.Id.ToString("D"),
                new { sha256 = hash, wave_id = wave.Value.ToString("D"), batch = issued }, ct);
        else
        {
            await using var member = new NpgsqlCommand("""
                select state from sli_agent_update_wave_members where wave_id=@wave and agent_id=@agent
                """, db, tx);
            member.Parameters.AddWithValue("wave", wave.Value);
            member.Parameters.AddWithValue("agent", identity.Id);
            if (await member.ExecuteScalarAsync(ct) is not ("pending" or "failed"))
                return null;
        }
        return offer;
    }
}
