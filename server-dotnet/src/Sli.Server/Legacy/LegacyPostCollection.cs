using System.Text.Json.Nodes;

namespace Sli.Server.Legacy;

public sealed record LegacyPostResult(int Claimed, int Completed, int Failed);
public sealed class LegacyPostCollection(ILegacyPostStore store, ILegacyAnalysis analysis, LegacySettings settings,
    ILogger<LegacyPostCollection> logger, LegacyJobStore? jobs = null, LegacyHeartbeat? heartbeat = null,
    ILegacyFindings? producer = null, ILegacyStorageSnapshot? snapshots = null)
{
    internal Func<TimeSpan, CancellationToken, Task> Delay { get; init; } = Task.Delay;

    public async Task<LegacyPostResult> RunOnceAsync(string worker, int limit, CancellationToken ct,
        Func<JsonObject, CancellationToken, Task>? progress = null)
    {
        if (settings.Disabled) return new(0, 0, 0);
        await store.RecoverAsync(ct);
        // Claim just before execution, not a batch whose later leases can expire
        // while the first long report is still running.
        int claimed = 0, completed = 0, failed = 0;
        for (int index = 0; index < Math.Clamp(limit, 1, 10); index++) {
            ct.ThrowIfCancellationRequested();
            var claims = await store.ClaimAsync(worker, 1, ct);
            if (claims.Count == 0) break;
            var claim = claims[0]; claimed++;
            int? localId = jobs?.FindDurable(claim.DurableId);
            if (jobs is not null && localId is null) {
                var restored = jobs.Create("post_collection_worker",new(claim.Servers,0,0));
                localId = restored["id"]!.GetValue<int>();
                jobs.Update(localId.Value,j => { j["durable_id"] = claim.DurableId; j["status"] = "completed";
                    j["collection_status"] = "completed"; j["trace_id"] = "resume-" + claim.DurableId; });
            }
            void Update(Action<JsonObject> update) { if (localId is {} id) jobs!.Update(id,update); }
            Update(j => { j["phase"] = "findings_running"; j["analysis_status"] = "running"; j["findings_status"] = "running";
                j["report_status"] = "queued"; j["analysis_started_at"] = DateTimeOffset.UtcNow.ToString("O"); });
            using var leaseStop = CancellationTokenSource.CreateLinkedTokenSource(ct);
            string phase = "findings_running";
            async Task Monitor(CancellationToken token) {
                var current = new JsonObject { ["durable_job_id"] = claim.DurableId, ["job_id"] = localId,
                    ["phase"] = Volatile.Read(ref phase), ["claim_attempt"] = claim.Attempt };
                try {
                    if (progress is not null) await progress(current, token);
                    else if (heartbeat is not null) await heartbeat.WriteAsync("post_collection", claim.Worker, "running",
                        current["phase"]!.GetValue<string>(), 30, new() { ["durable_job_id"] = claim.DurableId, ["job_id"] = claim.SourceId, ["active_job"] = current }, token);
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                catch { logger.LogWarning("post_collection_monitor_heartbeat_failed"); }
            }
            Task pulse = PulseAsync(claim, leaseStop, ct, () => Volatile.Read(ref phase), Monitor);
            try {
                await HeartbeatAsync(claim, "findings_running", leaseStop.Token);
                await Monitor(leaseStop.Token);
                string? warning = null;
                var findings = new JsonObject { ["status"] = "skipped", ["reason"] = "legacy_event_id_verdict_producer_disabled",
                    ["verdict_owner"] = "semantic_scenarios", ["created_findings"] = 0, ["updated_findings"] = 0, ["evidence_added"] = 0 };
                if (settings.Enabled("ADLOG_LEGACY_FINDINGS_ENABLED")) {
                    try {
                        findings = await (producer ?? throw new InvalidOperationException("legacy_findings_not_registered")).RefreshAsync(leaseStop.Token);
                    }
                    catch (OperationCanceledException) when (leaseStop.IsCancellationRequested) { throw; }
                    catch {
                        warning = "legacy_findings_refresh_failed_" + Guid.NewGuid().ToString("N");
                        findings = new JsonObject { ["status"] = "failed", ["error_id"] = warning };
                        logger.LogWarning("legacy_findings_refresh_failed {ErrorId}", warning);
                    }
                }
                await store.FindingsAsync(claim, findings, warning, leaseStop.Token);
                Update(j => { j["findings_status"] = warning is null ? "completed" : "failed"; j["findings_result"] = findings.DeepClone();
                    j["findings_error_id"] = warning; j["phase"] = "report_running"; j["report_status"] = "running"; });
                Volatile.Write(ref phase, "report_running");
                await HeartbeatAsync(claim, phase, leaseStop.Token);
                await Monitor(leaseStop.Token);
                var report = await analysis.RenderAsync(claim.SourceId, claim.Servers, leaseStop.Token);
                string directory = Path.Combine(settings.DataDirectory, "reports");
                await LegacyReportPublication.PublishAsync(report, directory,
                    (publish, token) => store.FenceAsync(claim, publish, token), leaseStop.Token);
                await store.FinishAsync(claim, Path.Combine(directory, report.Url.Split('/')[^1]), null, leaseStop.Token);
                Update(j => { j["phase"] = "done"; j["analysis_status"] = warning is null ? "completed" : "completed_with_findings_warning";
                    j["report_status"] = "completed"; j["analysis_report_url"] = report.Url;
                    j["analysis_finished_at"] = DateTimeOffset.UtcNow.ToString("O");
                    j["message"] = warning is null ? "Сбор завершен; Findings и отчет готовы." : "Сбор и отчет завершены; Findings refresh завершился ошибкой."; });
                completed++;
                // The durable job is now completed: renewing its running lease
                // would falsely report lease loss during the storage snapshot.
                leaseStop.Cancel();
                await pulse;
                // Snapshot failures never change the completed collection/report outcome.
                if (snapshots is not null) {
                    Volatile.Write(ref phase, "storage_snapshot");
                    await Monitor(ct);
                    try { await snapshots.RecordAsync(claim,ct); }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                    catch { logger.LogWarning("post_collection_storage_snapshot_failed"); }
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (LegacyLeaseLost) {
                failed++; logger.LogWarning("post_collection_lease_lost");
                Update(j => { j["analysis_status"] = "lease_lost"; j["report_status"] = "lease_lost"; j["analysis_error_id"] = "post_collection_lease_lost"; });
            }
            catch (Exception) {
                failed++;
                // No SQL bind data, source payload or exceptions enter logs.
                string errorId = "post_collection_failed_" + Guid.NewGuid().ToString("N");
                try { await store.FinishAsync(claim, null, errorId, ct); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (LegacyLeaseLost) { }
                catch { logger.LogWarning("post_collection_failure_status_write_failed {ErrorId}", errorId); }
                Update(j => { j["phase"] = "done"; j["analysis_status"] = "failed"; j["report_status"] = "failed";
                    if (j["findings_status"]?.GetValue<string>() is "queued" or "running") j["findings_status"] = "failed";
                    if (j["findings_status"]?.GetValue<string>() == "failed" && j["findings_error_id"] is null) j["findings_error_id"] = errorId;
                    j["analysis_error_id"] = errorId; j["analysis_finished_at"] = DateTimeOffset.UtcNow.ToString("O"); });
                logger.LogWarning("post_collection_failed {ErrorId}", errorId);
            }
            finally {
                leaseStop.Cancel();
                try { await pulse; } catch (OperationCanceledException) when (leaseStop.IsCancellationRequested) { }
            }
        }
        return new(claimed, completed, failed);
    }
    private async Task PulseAsync(LegacyPostClaim claim, CancellationTokenSource leaseStop, CancellationToken stopping,
        Func<string> phase, Func<CancellationToken, Task> monitor)
    {
        try {
            while (true) {
                await Delay(TimeSpan.FromSeconds(30), leaseStop.Token);
                await HeartbeatAsync(claim, phase(), leaseStop.Token);
                await monitor(leaseStop.Token);
            }
        }
        catch (OperationCanceledException) when (leaseStop.IsCancellationRequested) { }
        catch {
            // An explicitly lost lease stops work; transient heartbeat errors
            // are handled below and publication still checks ownership in FenceAsync.
            if (!stopping.IsCancellationRequested) logger.LogWarning("post_collection_heartbeat_failed");
            leaseStop.Cancel();
        }
    }

    private async Task HeartbeatAsync(LegacyPostClaim claim, string phase, CancellationToken ct)
    {
        try { await store.HeartbeatAsync(claim, phase, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (LegacyLeaseLost) { throw; }
        catch { logger.LogWarning("post_collection_heartbeat_failed"); }
    }
}
