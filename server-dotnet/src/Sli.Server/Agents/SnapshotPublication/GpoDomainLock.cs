using Npgsql;

namespace Sli.Server.Agents.SnapshotPublication;

// Source GPO importer requires an existing exact SID/FQDN binding before context import.
internal static class GpoDomainLock
{
    public static async Task<long> AcquireAsync(NpgsqlConnection db,NpgsqlTransaction tx,string sid,string dns,CancellationToken ct)
    {
        await using (var cmd=new NpgsqlCommand("select pg_advisory_xact_lock(hashtext('sli_agent_ad_snapshot'),hashtext(@sid))",db,tx))
        { cmd.Parameters.AddWithValue("sid",sid); await cmd.ExecuteNonQueryAsync(ct); }
        long domain;
        await using (var cmd=new NpgsqlCommand("select id from domains where domain_sid=@sid and lower(fqdn)=@dns for update",db,tx))
        {
            cmd.Parameters.AddWithValue("sid",sid); cmd.Parameters.AddWithValue("dns",dns);
            var result=await cmd.ExecuteScalarAsync(ct); if(result is null) throw new Sli.Agent.Protocol.ProtocolException("agent_gpo_domain_not_bound");
            domain=Convert.ToInt64(result);
        }
        await using (var cmd=new NpgsqlCommand("select id from domains where lower(fqdn)=lower(@dns) order by id",db,tx))
        {
            cmd.Parameters.AddWithValue("dns",dns); var count=0; long found=0; await using var reader=await cmd.ExecuteReaderAsync(ct);
            while(await reader.ReadAsync(ct)){ count++; found=Convert.ToInt64(reader.GetValue(0)); }
            if(count!=1 || found!=domain) throw new InvalidDataException("agent_gpo_domain_scope_invalid");
        }
        return domain;
    }
}
