using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;
using Sli.Server.Storage.Direct;
using Sli.Server.Storage.Lifecycle;

namespace Sli.Server.Legacy;

public sealed record LegacyPostClaim(string DurableId, long SourceId, string[] Servers, string Worker, int Attempt);
public sealed class LegacyLeaseLost() : Exception("post_collection_lease_lost");

public interface ILegacyPostStore
{
    Task QueueAsync(string durableId, int sourceId, string[] servers, CancellationToken ct);
    Task RecoverAsync(CancellationToken ct);
    Task<IReadOnlyList<LegacyPostClaim>> ClaimAsync(string worker, int limit, CancellationToken ct);
    Task HeartbeatAsync(LegacyPostClaim claim, string phase, CancellationToken ct);
    Task FindingsAsync(LegacyPostClaim claim, JsonObject result, string? errorId, CancellationToken ct);
    Task FinishAsync(LegacyPostClaim claim, string? reportPath, string? errorId, CancellationToken ct);
    Task FenceAsync(LegacyPostClaim claim, Func<Task> publish, CancellationToken ct);
}

public sealed class LegacyPostStore(IPostgresConnectionFactory connections) : ILegacyPostStore
{
    internal static int RetentionDays(Func<string, string?> get) =>
        Math.Max(1, LifecyclePolicy.ReadOperationalRetention(get).Days);

    internal static async Task<int> CleanupAsync(NpgsqlConnection db, int days, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            delete from post_collection_jobs
            where status in ('completed','failed') and finished_at < now() - (@days * interval '1 day')
            """, db);
        command.Parameters.AddWithValue("days", Math.Max(1, days));
        return await command.ExecuteNonQueryAsync(ct);
    }

    public async Task QueueAsync(string durableId, int sourceId, string[] servers, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct);
        await using var command = new NpgsqlCommand("""
            insert into post_collection_jobs(durable_job_id,source_job_id,status,phase,findings_status,servers_json,queued_at,updated_at)
            values(@id,@source,'queued','queued','queued',@servers,now(),now())
            on conflict(durable_job_id) do update set updated_at=post_collection_jobs.updated_at
            """, db);
        command.Parameters.AddWithValue("id", durableId); command.Parameters.AddWithValue("source", sourceId);
        command.Parameters.AddWithValue("servers", NpgsqlDbType.Jsonb, JsonSerializer.Serialize(servers));
        await command.ExecuteNonQueryAsync(ct);
    }
    public async Task RecoverAsync(CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        // Validate before recovery changes durable work, not only when the
        // eventual report or findings producer opens its own session.
        if (await DirectRuntimeAuthorization.LoadAsync(db, tx, DateTime.UtcNow, ct) is null)
            throw new InvalidOperationException("storage_v2_admission_required");
        await using var command = new NpgsqlCommand("""
            update post_collection_jobs set status='queued',started_at=null,worker_id=null,worker_lease_until=null,
              error_message='requeued_after_expired_worker_lease',updated_at=now()
            where status='running' and durable_job_id not like 'legacy-%' and attempt_count<max_attempts
              and (worker_lease_until is null or worker_lease_until<=now());
            update post_collection_jobs set status='failed',phase='failed',finished_at=now(),worker_lease_until=null,
              error_message=coalesce(error_message,'post_collection_attempts_exhausted'),updated_at=now()
            where status in ('queued','running') and durable_job_id not like 'legacy-%' and attempt_count>=max_attempts
              and (status='queued' or worker_lease_until is null or worker_lease_until<=now())
            """, db, tx);
        await command.ExecuteNonQueryAsync(ct); await tx.CommitAsync(ct);
    }
    public async Task<IReadOnlyList<LegacyPostClaim>> ClaimAsync(string worker, int limit, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        if (await DirectRuntimeAuthorization.LoadAsync(db, tx, DateTime.UtcNow, ct) is null)
            throw new InvalidOperationException("storage_v2_admission_required");
        await using var command = new NpgsqlCommand("""
            with candidates as (
              select id from post_collection_jobs where status='queued' and durable_job_id not like 'legacy-%'
                and attempt_count<max_attempts order by queued_at,id for update skip locked limit @limit)
            update post_collection_jobs p set status='running',started_at=coalesce(p.started_at,now()),worker_id=@worker,
              heartbeat_at=now(),worker_lease_until=now()+interval '3600 seconds',attempt_count=p.attempt_count+1,
              phase=case when p.phase='queued' then 'findings_queued' else p.phase end,updated_at=now()
            from candidates c where p.id=c.id returning p.durable_job_id,p.source_job_id,p.servers_json::text,p.attempt_count
            """, db, tx);
        command.Parameters.AddWithValue("worker", worker); command.Parameters.AddWithValue("limit", Math.Clamp(limit, 1, 10));
        var claims = new List<LegacyPostClaim>();
        await using (var reader = await command.ExecuteReaderAsync(ct))
            while (await reader.ReadAsync(ct)) claims.Add(new(reader.GetString(0), reader.GetInt64(1),
                JsonSerializer.Deserialize<string[]>(reader.GetString(2)) ?? [], worker, reader.GetInt32(3)));
        await tx.CommitAsync(ct);
        return claims;
    }
    private static void Bind(NpgsqlCommand command, LegacyPostClaim claim)
    {
        command.Parameters.AddWithValue("id", claim.DurableId); command.Parameters.AddWithValue("worker", claim.Worker);
        command.Parameters.AddWithValue("attempt", claim.Attempt);
    }
    private const string Owned = " where durable_job_id=@id and worker_id=@worker and attempt_count=@attempt and status='running' and worker_lease_until>clock_timestamp()";
    public async Task HeartbeatAsync(LegacyPostClaim claim, string phase, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct);
        await using var command = new NpgsqlCommand("update post_collection_jobs set heartbeat_at=now(),worker_lease_until=now()+interval '3600 seconds',phase=@phase,updated_at=now()" + Owned, db);
        Bind(command, claim); command.Parameters.AddWithValue("phase", phase);
        if (await command.ExecuteNonQueryAsync(ct) != 1) throw new LegacyLeaseLost();
    }
    public async Task FindingsAsync(LegacyPostClaim claim, JsonObject result, string? errorId, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct);
        await using var command = new NpgsqlCommand("""
            update post_collection_jobs set findings_status=@status,findings_result_json=@result,
              findings_error_id=@error,findings_finished_at=now(),phase='report_queued',heartbeat_at=now(),updated_at=now()
            """ + Owned, db);
        Bind(command, claim); command.Parameters.AddWithValue("status", errorId is null ? "completed" : "failed");
        command.Parameters.AddWithValue("result", NpgsqlDbType.Jsonb, result.ToJsonString());
        command.Parameters.AddWithValue("error", NpgsqlDbType.Text, (object?)errorId ?? DBNull.Value);
        if (await command.ExecuteNonQueryAsync(ct) != 1) throw new LegacyLeaseLost();
    }
    public async Task FinishAsync(LegacyPostClaim claim, string? reportPath, string? errorId, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct);
        await using var command = new NpgsqlCommand("""
            update post_collection_jobs set status=@status,phase=@status,finished_at=now(),worker_lease_until=null,
              report_path=coalesce(@path,report_path),error_id=@error,error_message=@error,updated_at=now()
            """ + Owned, db);
        Bind(command, claim); command.Parameters.AddWithValue("status", errorId is null ? "completed" : "failed");
        command.Parameters.AddWithValue("path", NpgsqlDbType.Text, (object?)reportPath ?? DBNull.Value);
        command.Parameters.AddWithValue("error", NpgsqlDbType.Text, (object?)errorId ?? DBNull.Value);
        if (await command.ExecuteNonQueryAsync(ct) != 1) throw new LegacyLeaseLost();
    }
    public async Task FenceAsync(LegacyPostClaim claim, Func<Task> publish, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        await using (var command = new NpgsqlCommand("select worker_lease_until from post_collection_jobs where durable_job_id=@id and worker_id=@worker and attempt_count=@attempt and status='running' for update", db, tx)) {
            Bind(command, claim);
            object? until = await command.ExecuteScalarAsync(ct);
            if (until is not DateTime lease) throw new LegacyLeaseLost();
            // clock_timestamp after FOR UPDATE is essential: lock wait may have
            // outlived the lease; transaction-start now() would accept a stale owner.
            await using var live = new NpgsqlCommand("select @until>clock_timestamp()", db, tx);
            live.Parameters.AddWithValue("until", lease);
            if (await live.ExecuteScalarAsync(ct) is not true) throw new LegacyLeaseLost();
        }
        await publish(); await tx.CommitAsync(ct);
    }
}
