using System.CommandLine;
using System.Text.Json;
using Npgsql;
using NpgsqlTypes;

namespace Sli.Server.Agents.SnapshotPublication;

// One-shot profile with bounded pages. It does not start the HTTP listener or other worker roles.
public static class GpoWorkerCommand
{
    public static async Task<int> RunAsync(string[] args,string module="sli.gpo-snapshot")
    {
        var once = new Option<bool>("--once");
        var after = new Option<Guid?>("--after");
        var root = new RootCommand("Publish pending GPO snapshot cycles in bounded batches.");
        root.Options.Add(once); root.Options.Add(after);
        root.SetAction(async (parse, ct) =>
        {
            if (!parse.GetValue(once)) { Console.Error.WriteLine("gpo_worker_once_required"); return 2; }
            if (!GpoWorkerConfiguration.TryCreate(Environment.GetEnvironmentVariable, ReadBoundedFile, out var dsn))
            { Console.Error.WriteLine("server_configuration_invalid"); return 1; }
            try
            {
                var result = await RunOnceAsync(dsn!, parse.GetValue(after), module, ct);
                if (result.ExitCode == 0) Console.Out.WriteLine(JsonSerializer.Serialize(new { scanned = result.Scanned, failed = result.Failed, next_after = result.NextAfter }));
                return result.ExitCode;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return 130; }
            catch (Exception) { Console.Error.WriteLine("agent_snapshot_import_unavailable"); return 1; }
        });
        var parsed = root.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null });
        return await parsed.InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false });
    }

    internal static byte[] ReadBoundedFile(string path)
    {
        using var stream = File.OpenRead(path);
        byte[] buffer = new byte[65537]; int count = 0, read;
        while (count < buffer.Length && (read = stream.Read(buffer, count, buffer.Length - count)) != 0) count += read;
        if (count > 65536) throw new ArgumentException();
        return buffer[..count];
    }

    internal sealed record BatchResult(int ExitCode, int Scanned, int Failed, Guid? NextAfter);

    internal static async Task<BatchResult> RunOnceAsync(string connectionString, Guid? after, string module, CancellationToken ct, DateTimeOffset? due = null)
    {
        await using var db = new NpgsqlConnection(connectionString);
        await db.OpenAsync(ct);
        await using (var role = new NpgsqlCommand("set role adlog_context_worker", db)) await role.ExecuteNonQueryAsync(ct);
        await using (var limits = new NpgsqlCommand("set statement_timeout=300000; set lock_timeout=10000", db)) await limits.ExecuteNonQueryAsync(ct);
        await using var acquire = new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))", db);
        if (await acquire.ExecuteScalarAsync(ct) is not true) return new(9, 0, 0, null);
        try
        {
            int scanned = 0, failed = 0;
            Guid? nextAfter = null;
            // Advance past deferred cycles as the Python snapshot consumer does.
            // Both the one-shot worker and the AD calendar visit every due page.
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                var cycles = new List<Guid>();
                await using (var select = new NpgsqlCommand("""
                    select cycle_id from sli_agent_snapshot_cycles
                    where module_id=@module and (transport_state='pending' or publication_state='pending')
                      and (@due is null or slot_start_utc::timestamptz<=@due)
                      and (@after is null or (slot_start_utc::timestamptz,cycle_id) >
                        (select slot_start_utc::timestamptz,cycle_id from sli_agent_snapshot_cycles where cycle_id=@after))
                    order by slot_start_utc::timestamptz,cycle_id limit 4
                    """, db))
                {
                    select.Parameters.AddWithValue("after", NpgsqlDbType.Uuid, after is null ? DBNull.Value : after.Value);
                    select.Parameters.AddWithValue("module",module);
                    select.Parameters.AddWithValue("due", NpgsqlDbType.TimestampTz, due is null ? DBNull.Value : due.Value.ToUniversalTime());
                    await using var reader = await select.ExecuteReaderAsync(ct);
                    while (await reader.ReadAsync(ct)) cycles.Add(reader.GetGuid(0));
                }
                foreach (var cycle in cycles)
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        var publication=module=="sli.ad-snapshot" ? await Sli.Server.Ad.AdSnapshotPublisher.ProcessAsync(db,cycle,ct) : await GpoSnapshotPublisher.ProcessAsync(db,cycle,ct);
                        if(publication.PublicationState=="pending" && publication.PendingReason is not null) failed++;
                    }
                    catch (Exception error) when (error is not OperationCanceledException and not NpgsqlException and not IOException)
                    { failed++; }
                }
                scanned += cycles.Count;
                if (cycles.Count > 0) after = nextAfter = cycles[^1];
                if (cycles.Count < 4) return new(0, scanned, failed, nextAfter);
            }
        }
        finally
        {
            await using var release = new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_post_collection_process'))", db);
            await release.ExecuteScalarAsync(CancellationToken.None);
        }
    }
}
