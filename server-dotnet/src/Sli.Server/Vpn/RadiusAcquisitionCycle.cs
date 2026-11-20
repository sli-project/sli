using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Agents.Radius;
using Sli.Server.Operations;

namespace Sli.Server.Vpn;

internal sealed record RadiusAcquisitionSource(string SourceId, string SourceName, string Subscription, string Directory,
    string Timezone, int Offset, string EvidenceRoot, string DataRoot)
{
    public override string ToString() => nameof(RadiusAcquisitionSource);

    internal static RadiusAcquisitionSource Load(IConfiguration configuration)
    {
        var files = new OperationsFiles(configuration);
        string path = Environment.GetEnvironmentVariable("ADLOG_RADIUS_COLLECTION_ROUTES_PATH") ?? Path.Combine(files.Root, "config", "stage10_radius_collection_routes_v1.json");
        using var route = JsonDocument.Parse(Sli.Server.Agents.SnapshotPublication.GpoWorkerCommand.ReadBoundedFile(path));
        string[] keys = ["ADLOG_RADIUS_SOURCE_NAME", "ADLOG_RADIUS_SOURCE_INSTANCE_ID", "ADLOG_RADIUS_ACCOUNTING_SHARE_UNC"];
        var env = keys.Where(k => Environment.GetEnvironmentVariable(k) is not null).ToDictionary(k => k, Environment.GetEnvironmentVariable);
        string name = RadiusCollectionRoute.Validate(route.RootElement, env);
        string source = env.GetValueOrDefault("ADLOG_RADIUS_SOURCE_INSTANCE_ID")?.Trim() is { Length: > 0 } id ? id :
            env.ContainsKey("ADLOG_RADIUS_SOURCE_NAME") ? name : route.RootElement.GetProperty("source_instance_id").GetString()!;
        var accounting = route.RootElement.GetProperty("accounting_route");
        string? share = env.ContainsKey("ADLOG_RADIUS_ACCOUNTING_SHARE_UNC") ? env["ADLOG_RADIUS_ACCOUNTING_SHARE_UNC"] : accounting.GetProperty("share_unc").GetString();
        if (string.IsNullOrWhiteSpace(share)) throw new InvalidOperationException("radius_dedicated_read_only_share_not_configured");
        using var manual = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(files.Root, "config", "stage9_radius_manual_control_v1.json")));
        string subscription = $"vpn-radius-session-observations-{name.Split('.')[0]}-v1";
        if (manual.RootElement.GetProperty("contract_id").GetString() != "sli.radius-accounting-manual-control.v1" || string.IsNullOrWhiteSpace(subscription))
            throw new InvalidOperationException("manual_control_contract_invalid");
        var timezone = accounting.GetProperty("timezone_descriptor");
        return new(source, name, subscription, share.Trim(), timezone.GetProperty("timezone_id").GetString()!, timezone.GetProperty("utc_offset_minutes").GetInt32(),
            @"C:\SLI", files.DataRoot);
    }
}

internal static class RadiusAcquisitionCycle
{
    internal const string WorkerRole = "adlog_radius_accounting_worker";
    internal const string StateSql = """
        select c.source_instance_id,c.stream_id,c.transport_binding,c.cursor_epoch,c.file_generation,c.byte_offset,
               c.last_record_sha256,c.revision,s.desired_activation source_activation,sub.desired_activation subscription_activation,
               c.previous_generation_last_record_sha256
        from acquisition_consumer_subscriptions sub join acquisition_stream_cursors c
          on c.source_instance_id=sub.source_instance_id and c.stream_id=sub.stream_id and c.transport_binding=sub.transport_binding
        join acquisition_source_instances s on s.source_instance_id=c.source_instance_id where sub.subscription_id=$1
        """;

    // One source read per invocation, like run_acquisition_cycle. Batch sizes are
    // the existing parser/wire contract; they never bound the host's lifetime.
    internal static async Task<JsonObject> RunAsync(NpgsqlConnection db, RadiusAcquisitionSource source,
        Func<RadiusCursor, bool, RadiusTailBatch> read, Func<JsonObject, Task> progress, CancellationToken ct)
    {
        await RadiusJobs.Execute(db, "set role adlog_radius_accounting_worker", ct);
        Guid lease = Guid.NewGuid(); string holder = $"radius-acquisition:{Environment.ProcessId}:{Guid.NewGuid():N}";
        var admitted = (await RadiusJobs.Rows(db, "select lease_uid,component_id,admission_mode,expires_at_utc from acquire_plugin_component_lease_v1($1,'sli.remote-access','radius-acquisition','source_contact',$2)", ct, lease, holder)).SingleOrDefault();
        if (admitted is null || admitted.Text("lease_uid") != lease.ToString("D") || admitted.Text("component_id") != "radius-acquisition" || admitted.Text("admission_mode") != "open" || admitted.At("expires_at_utc") is null)
            throw new InvalidOperationException("component_lease_result_invalid");
        string outcome = "failed";
        try {
            var state = (await RadiusJobs.Rows(db, StateSql, ct, source.Subscription)).SingleOrDefault() ?? throw new InvalidOperationException("subscription_not_found");
            if (state.Text("source_activation") != "manual_enabled" || state.Text("subscription_activation") != "manual_enabled") throw new InvalidOperationException("subscription_not_manually_enabled");
            var cursor = new RadiusCursor(state.Text("source_instance_id"), state.Text("stream_id"), state.Text("transport_binding"), state.Text("file_generation"), state.Number("byte_offset"), state["last_record_sha256"]?.GetValue<string>());
            if (cursor.SourceId != source.SourceId) throw new InvalidOperationException("radius_source_binding_changed");
            long revision = state.Number("revision");
            Guid epoch = Guid.Parse(state.Text("cursor_epoch"));
            await progress(new JsonObject { ["status"] = "running", ["cursor_revision_before"] = revision, ["cursor_revision_after"] = revision });
            ct.ThrowIfCancellationRequested();
            var tail = read(cursor, cursor.LastRecordSha256 is not null && cursor.LastRecordSha256 != state["previous_generation_last_record_sha256"]?.GetValue<string>());
            bool rotation = tail.FileGeneration != cursor.FileGeneration;
            ValidateTail(cursor, tail);
            bool moved = tail.EndOffset > tail.StartOffset || rotation;
            int observations = 0;
            if (tail.Records.Count > 0 || moved) {
                await using var tx = await db.BeginTransactionAsync(ct);
                if (tail.Records.Count == 0)
                    await RadiusAccountingImporter.LockAndAdvance(db, tx, source.Subscription, cursor, epoch, revision, tail.FileGeneration, tail.EndOffset, cursor.LastRecordSha256, rotation, ct);
                else
                    observations = await RadiusAccountingImporter.CommitRecordsAsync(db, tx, new(source.EvidenceRoot, source.SourceName), source.Subscription,
                        cursor, epoch, revision, tail.FileGeneration, tail.StartOffset, tail.EndOffset, rotation, tail.Records.ToArray(), source.Timezone, source.Offset, DateTimeOffset.UtcNow, ct);
                await tx.CommitAsync(ct);
            }
            outcome = "completed";
            return new JsonObject { ["status"] = moved ? "committed" : "no_new_complete_records", ["records"] = tail.Records.Count,
                ["evidence_rows"] = tail.Records.Count, ["observation_rows"] = observations, ["outbox_rows"] = observations,
                ["cursor_revision_before"] = revision, ["cursor_revision_after"] = moved ? revision + 1 : revision };
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { outcome = "cancelled"; throw; }
        finally {
            if (await RadiusJobs.Scalar(db, "select release_plugin_component_lease_v1($1,$2,$3)", CancellationToken.None, lease, holder, outcome) is not true)
                throw new InvalidOperationException("component_lease_release_invalid");
        }
    }

    internal static void ValidateTail(RadiusCursor cursor, RadiusTailBatch tail)
    {
        bool rotation = tail.FileGeneration != cursor.FileGeneration;
        if (tail.StartOffset != (rotation ? 0 : cursor.ByteOffset) || tail.EndOffset < tail.StartOffset || tail.PreviousGenerationEof != rotation ||
            tail.PhysicalLines < 0 || tail.PhysicalLines > 1000 || tail.BytesRead < 0 || tail.BytesRead > RadiusTailSource.MaximumReadBytes ||
            tail.PartialTrailingBytes < 0 || tail.PartialTrailingBytes > tail.BytesRead || tail.EndOffset - tail.StartOffset > tail.BytesRead - tail.PartialTrailingBytes ||
            tail.Records.Count > tail.PhysicalLines || tail.Records.Count > 0 && tail.EndOffset == tail.StartOffset ||
            tail.EndOffset > tail.StartOffset && tail.PhysicalLines == 0)
            throw new InvalidOperationException("collection_packet_local_tail_mismatch");
    }
}
