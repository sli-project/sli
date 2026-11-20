using System.Net;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Legacy;

namespace Sli.Server.Sources;

public sealed class PostgresCollectionBlocks(IPostgresConnectionFactory connections) : ICollectionBlockStore
{
    public async Task<string?> ActiveAsync(CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct);
        await using var command = new NpgsqlCommand("select reason_code from runtime_collection_blocks where singleton_id=1 and active",db) { CommandTimeout=0 };
        return await command.ExecuteScalarAsync(ct) as string;
    }
    public async Task ActivateAsync(CollectionFailure failure,string server,string worker,CancellationToken ct)
    {
        if (!failure.Blocked || CollectionFailurePolicy.Classify(failure.Code).Code != failure.Code) throw new InvalidOperationException("collection_failure_invalid");
        await using var db = await connections.OpenAsync(ct);
        await using var command = new NpgsqlCommand("""
            insert into runtime_collection_blocks(singleton_id,active,reason_code,retry_policy,operator_action,source_worker_id,source_server,evidence_json)
            values(1,true,@code,'operator_recovery_required',@action,@worker,@server,jsonb_build_object('failure_code',@code::text,'failure_scope','worker_identity','collector_backend','dotnet'))
            on conflict(singleton_id) do update set active=true,reason_code=excluded.reason_code,retry_policy=excluded.retry_policy,
                operator_action=excluded.operator_action,source_worker_id=excluded.source_worker_id,source_server=excluded.source_server,
                source_job_id=null,evidence_json=excluded.evidence_json,observed_count=runtime_collection_blocks.observed_count+1,
                last_seen_at=now(),cleared_at=null,cleared_by=null,updated_at=now()
            """,db) { CommandTimeout=0 };
        command.Parameters.AddWithValue("code",failure.Code!); command.Parameters.AddWithValue("action",failure.OperatorAction!);
        command.Parameters.AddWithValue("worker",worker); command.Parameters.AddWithValue("server",server);
        await command.ExecuteNonQueryAsync(ct);
    }
    public async Task ClearAsync(string server,string actor,CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct);
        await using var command = new NpgsqlCommand("""
            update runtime_collection_blocks set active=false,last_probe_at=now(),last_probe_result='success',
                cleared_at=now(),cleared_by=@actor,updated_at=now(),
                evidence_json=evidence_json || jsonb_build_object('successful_probe_server',@server::text)
            where singleton_id=1 and active
            """,db) { CommandTimeout=0 };
        command.Parameters.AddWithValue("actor",actor); command.Parameters.AddWithValue("server",server);
        await command.ExecuteNonQueryAsync(ct);
    }
}

public static class CollectionRuntime
{
    public static async Task<WindowsCollection> CreateAsync(IPostgresConnectionFactory connections,LegacySettings settings,CancellationToken ct)
    {
        if (settings.Disabled) throw new InvalidOperationException("legacy_collection_disabled");
        if (settings.AcquisitionDisabled) throw new InvalidOperationException("acquisition_disabled");
        // Reuse the same configured PostgreSQL targets as the legacy worker.
        var targets = new List<AdSourceTarget>(); var ips = new Dictionary<string,string?>(StringComparer.OrdinalIgnoreCase);
        await using (var db = await connections.OpenAsync(ct)) {
            await using var command = new NpgsqlCommand("select hostname,connect_address,host(owner_confirmed_ip) from domain_controller_targets where enabled order by lower(hostname)",db) { CommandTimeout=0 };
            await using var rows = await command.ExecuteReaderAsync(ct);
            while (await rows.ReadAsync(ct)) {
                string hostname=rows.GetString(0),address=rows.GetString(1);
                targets.Add(new(hostname,address)); ips.Add(hostname,rows.IsDBNull(2) ? null : rows.GetString(2));
            }
        }
        string Resolve(string hostname) {
            var target = targets.Single(x => string.Equals(x.Hostname,hostname,StringComparison.OrdinalIgnoreCase));
            if (ips[hostname] is { } expected && !Dns.GetHostAddresses(target.ConnectAddress).Any(x => x.ToString() == expected)) throw new FormatException();
            return target.ConnectAddress;
        }
        var events = new WindowsEventLog(); var store = new WindowsCredentialStore(settings.DataDirectory);
        return new(new(() => targets,Resolve,store.Load,events,settings.Get),events,new PostgresCollectionBlocks(connections),WindowsCredentialStore.CurrentIdentity,settings.Get);
    }
}
