using System.Text.Json;
using System.Security.Cryptography;
using Npgsql;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Agents;

internal sealed class AgentLifecycleFixture(AgentControlFixture control, SyntheticDatabase database, string ownerCookie) : IAsyncDisposable
{
    internal AgentControlFixture Control => control;
    internal string OwnerCookie => ownerCookie;
    internal static async Task<AgentLifecycleFixture> OpenAsync(CancellationToken ct)
    {
        string path = Environment.GetEnvironmentVariable("SLI_LIFECYCLE_OWNER_PROFILE") ?? throw new InvalidOperationException("Exact owned synthetic owner profile required");
        byte[] bytes = await File.ReadAllBytesAsync(path, ct);
        Assert.Equal(Environment.GetEnvironmentVariable("SLI_LIFECYCLE_OWNER_SHA256"), Convert.ToHexStringLower(SHA256.HashData(bytes)));
        using var profile = JsonDocument.Parse(bytes); Assert.Equal("a3fcc413-8980-4cd8-ba5d-ebe374f7b864", profile.RootElement.GetProperty("run_id").GetString());
        long ownerId = profile.RootElement.GetProperty("user_id").GetInt64(); Assert.True(ownerId >= 1000000);
        var database = await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(), ct);
        var control = await AgentControlFixture.OpenAsync(ct);
        var f = new AgentLifecycleFixture(control, database, profile.RootElement.GetProperty("cookie").GetString()!);
        await using var db = await database.OpenConnectionAsync(ct);
        await using (var proof = new NpgsqlCommand("select current_user,exists(select 1 from access_platform_owners where user_id=@id and owner_key=@key),has_table_privilege(current_user,'sli_agent_removals','INSERT'),has_table_privilege(current_user,'access_platform_owners','INSERT')", db))
        {
            proof.Parameters.AddWithValue("id", ownerId); proof.Parameters.AddWithValue("key", profile.RootElement.GetProperty("owner_key").GetString()!);
            await using var reader = await proof.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct)); Assert.Equal("adlog_user", reader.GetString(0)); Assert.True(reader.GetBoolean(1)); Assert.True(reader.GetBoolean(2));
            await AgentControlFixture.RecordAsync(control.Marker + "-owner-profile-proof", new { current_user = reader.GetString(0), owner_profile_id = ownerId, own_platform_owner = reader.GetBoolean(1), removal_insert = reader.GetBoolean(2), owner_table_insert = reader.GetBoolean(3) });
        }
        await using var seed = new NpgsqlCommand("update sli_agents set rights_probe=rights_probe-'pending' where id=any(@ids)", db);
        seed.Parameters.AddWithValue("ids", new[] { control.Agent, control.OtherAgent }); Assert.Equal(2, await seed.ExecuteNonQueryAsync(ct));
        return f;
    }
    internal async Task<JsonElement> StateAsync(CancellationToken ct)
    {
        await using var db = await database.OpenConnectionAsync(ct);
        await using var query = new NpgsqlCommand("""
            select jsonb_build_object('current_user',current_user,'agents',coalesce(jsonb_agg(r order by r.id),'[]'::jsonb)) from (
                select a.id,a.status,a.policy_revision,a.rights_probe,
                    (select count(*) from sli_agent_certificates c where c.agent_id=a.id and revoked_at is null) as active_certificates,
                    (select jsonb_build_object('operation_id',operation_id,'command_id',command_id,'state',state) from sli_agent_removals m where m.agent_id=a.id) as removal,
                    (select coalesce(jsonb_agg(jsonb_build_object('action',action,'actor',actor,'details',details) order by id),'[]'::jsonb) from sli_agent_audit where target=a.id::text) as audits
                from sli_agents a where id=any(@ids)
            ) r
            """, db);
        query.Parameters.AddWithValue("ids", new[] { control.Agent, control.OtherAgent, control.ExpiredAgent });
        using var doc = JsonDocument.Parse((string)(await query.ExecuteScalarAsync(ct))!); return doc.RootElement.Clone();
    }
    public async ValueTask DisposeAsync() { await control.DisposeAsync(); await database.DisposeAsync(); }
}
