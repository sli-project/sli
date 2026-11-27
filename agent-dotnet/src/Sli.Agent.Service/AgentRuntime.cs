using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Windows;

namespace Sli.Agent.Service;

public sealed record CycleStatus(string? ErrorCode, bool CollectionActive, int Captured, int Pending, bool DeliveryFailed)
{
    public string? ErrorDetail { get; init; }
    public IReadOnlyDictionary<string, SnapshotFailure>? SnapshotFailures { get; init; }
    public FileAuditCatalogDiagnostic? FileAuditCatalog { get; init; }
}

/// <summary>Revisioned check-in fails closed. Drain acknowledges paused only after durable delivery.</summary>
public sealed class AgentRuntime(IOptions<AgentOptions> options, TimeProvider clock,
    Func<AgentIdentity?, AgentHttpClient>? transportFactory = null, IEventLogSource? eventSource = null, IWindowsAudit? audit = null,
    IDirectorySnapshotReader? snapshotReader = null, IFileAuditEventSource? fileEventSource = null, IFileAuditApi? fileAuditApi = null,
    Action<string,string>? filePathCheck = null, Func<string,bool>? fileAccountCheck = null,
    INpsEventSource? npsEventSource = null, IRadiusTailSource? radiusSource = null, Func<JsonObject>? protectionReader = null,
    Func<CancellationToken, LocalSmbCatalog>? localShareReader = null) : IDisposable
{
    private readonly AgentOptions _options = options.Value;
    private readonly IDurableFiles _files = CreateFiles();
    private readonly EventCatalog _catalog = EventCatalog.Load();
    private readonly Queue<DateTimeOffset> _attempts = new();
    private FilePacketQueue? _queue;
    private AgentHttpClient? _http;
    private AgentIdentity? _identity;
    private MsiAgentUpdate? _updates;
    private DateTimeOffset? _lastCapture;
    private string? _lastCapturePolicy;
    private string? _dcCatchUpChannel;
    private IWindowsAudit? _audit = audit;
    private SnapshotCapture? _snapshots;
    private FileAuditManager? _fileAudit;
    private readonly FileAuditReportDelivery _fileAuditReport = new(clock);
    private readonly FileAuditCatalogWorker? _fileAuditCatalog = localShareReader is not null ? new(localShareReader, clock)
        : OperatingSystem.IsWindows() ? new(NativeFileAuditApi.ListLocalShares, clock) : null;
    private DateTimeOffset? _lastFileCapture;
    private string? _lastFilePolicy;
    private readonly Dictionary<string, (DateTimeOffset At, string Policy)> _lastNpsCapture = new();
    public int IntervalSeconds { get; private set; } = 60;
    public bool ContinueImmediately { get; private set; }

    public static IDurableFiles CreateFiles() => new PhysicalDurableFiles(OperatingSystem.IsWindows() ? new WindowsDirectorySecurity(includeAdministrators: true) : null);
    public static HostIdentityStore CreateIdentityStore(AgentOptions options) => new(options.StateDir, CreateFiles(),
        OperatingSystem.IsWindows() ? new DpapiKeyProtector() : new RestrictedFileKeyProtector());

    public async Task<CycleStatus> RunCycleAsync(CancellationToken cancellationToken)
    {
        ContinueImmediately = false;
        string? error = null;
        SnapshotFailure? snapshotFailure = null;
        TransportException? transportError = null;
        var captured = 0;
        var failed = false;
        var active = false;
        try
        {
            if (!Path.IsPathFullyQualified(_options.StateDir)) return new("agent_state_path_invalid", false, 0, 0, true);
            if (!Uri.TryCreate(_options.ServerUrl, UriKind.Absolute, out var server) || server.Scheme != "https" || server.UserInfo.Length > 0
                || server.AbsolutePath != "/" || server.Query.Length > 0 || server.Fragment.Length > 0) return Finish("agent_config_invalid", false, 0, true);
            _queue ??= new FilePacketQueue(Path.Combine(_options.StateDir, "queue"), _files, _options.SpoolMaxBytes, _options.SpoolMaxAgeSeconds);
            var store = CreateIdentityStore(_options);
            AgentIdentity? identity;
            try
            {
                store.Prepare(_options.HostId);
                identity = store.Load();
            }
            catch (AgentException exception) when (exception.Code == "agent_identity_invalid")
            { return Finish("agent_identity_missing_reenroll_required", false, 0, true); }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            { return Finish("agent_identity_missing_reenroll_required", false, 0, true); }
            if (identity is null)
            {
                var raw = ReadBootstrap();
                if (raw is null) return Finish("agent_not_enrolled", false, 0, false);
                var input = EnrollmentInput.Parse(raw, clock.GetUtcNow());
                using var bootstrapHttp = NewHttp(null);
                var enrollment = new Enrollment(store, bootstrapHttp, clock,
                    hasFileShares: string.IsNullOrEmpty(_options.CaCertificate) ? null : HasFileShares);
                identity = input.ComputerEntityId is { } entity
                    ? await enrollment.EnrollGroupAsync(input.Token, entity, cancellationToken, _options.InstanceName).ConfigureAwait(false)
                    : await enrollment.EnrollAsync(input.Token, cancellationToken, _options.InstanceName).ConfigureAwait(false);
                if (identity is null) return Finish("agent_enrollment_pending", false, 0, false);
            }
            // Enrollment has already durably saved the identity. A locked bootstrap file must
            // be retried for cleanup, never prevent creation of the mTLS client and check-in.
            try { ClearBootstrap(); }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            { error = "agent_bootstrap_cleanup_failed"; }
            Use(identity);
            if (_identity!.Certificate.NotAfter.ToUniversalTime() <= clock.GetUtcNow()) throw new AgentException("agent_certificate_expired");
            var enrolled = new Enrollment(store, _http!, clock);
            try
            {
                if (await enrolled.RenewIfDueAsync(_identity, cancellationToken).ConfigureAwait(false)) Use(store.Load()!);
            }
            catch (AgentException exception) when (exception.Code != "agent_certificate_expired")
            {
                transportError = exception as TransportException;
                error = transportError is not null || IssuedCertificate.IsValidationError(exception.Code) ? exception.Code : "agent_renewal_pending";
            }
            var assignment = await _http!.GetIdentityAsync(_fileAuditCatalog is not null, cancellationToken).ConfigureAwait(false);
            if (assignment["agent_removal"] is not null) throw new AgentException("agent_removal_requires_admin");
            _updates ??= new MsiAgentUpdate(_options.StateDir, _files, clock);
            try
            {
                await _updates.CheckAsync(assignment["agent_update"] as JsonObject, _http, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is AgentException or IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
            {
                error ??= exception is AgentException update ? update.Code : "agent_update_stage_failed";
            }
            var policy = AgentPolicy.Parse(assignment, _identity.AgentId, _catalog);
            bool fileAuditReadDiagnostics = assignment[FileAuditReadError.Capability] is JsonValue fileAuditFeature
                && fileAuditFeature.TryGetValue<bool>(out var supported) && supported;
            _fileAuditCatalog?.Tick(assignment["file_audit_catalog_request"], _http!, fileAuditReadDiagnostics, cancellationToken);
            var sourceHostId = policy.Handoff?.SourceHostId ?? store.ReadHostId();
            CapturedPosition? Position(string module) => _queue.Captured(module) ?? policy.Handoff?.Position(module);
            IntervalSeconds = policy.Control.IntervalSeconds;
            _queue.MaxBytes = policy.Control.SpoolMaxBytes;
            var state = policy.Control.State;
            _snapshots ??= new SnapshotCapture(Path.Combine(_options.StateDir, "snapshots"), _files, snapshotReader ?? new DirectorySnapshotReader(), clock);
            if (state != "active") _snapshots.Cancel(clearFailures: true);
            var source = eventSource ?? (OperatingSystem.IsWindows() ? new EventLogBookmarkSource(_catalog, filterSecurity: policy.AdDc is not null) : null);
            if (OperatingSystem.IsWindows()) _audit ??= new NativeWindowsAudit(Path.Combine(_options.StateDir, "audit"), _files);
            var fileDirectory = Path.Combine(_options.StateDir,"file-audit");
            if (_fileAudit is null && (policy.FileAuditRequest is not null || _files.ReadAll(Path.Combine(fileDirectory,"state.json")) is not null))
            {
                var api = fileAuditApi;
                if (api is null && OperatingSystem.IsWindows()) api = new NativeFileAuditApi();
                if (api is null) throw new AgentException("file_audit_native_unavailable");
                _fileAudit = new FileAuditManager(fileDirectory,_files,api);
            }
            if (_fileAudit is not null) _fileAuditReport.Observe(_fileAudit);
            var fileResult = _fileAudit?.Reconcile(policy,_audit,clock.GetUtcNow(),fileAuditReadDiagnostics);
            var auditReport = fileResult?.Audit ?? (_fileAudit is null ? _audit?.Reconcile(policy, clock.GetUtcNow()) : null);
            var rights = ProbeRights(policy, source, store.ReadHostId());
            if (state != "drain")
            {
                var report = policy.Report(state, rights);
                if (assignment["dc_identity_required"] is JsonValue required && required.TryGetValue<bool>(out bool requested) && requested)
                    report["dc_identity"] = enrolled.ReadDcIdentity();
                await _http.PostAsync("/api/v1/agent/policy-report", report, cancellationToken).ConfigureAwait(false);
            }
            // A DC audit command result must not wait for the event backlog.
            if (policy.AdDc is not null && auditReport is not null)
                await _http.PostAsync("/api/v1/agent/windows-audit-report", auditReport, cancellationToken).ConfigureAwait(false);
            if (state != "paused")
            {
                var now = clock.GetUtcNow();
                while (_attempts.TryPeek(out var attempted) && now - attempted >= TimeSpan.FromMinutes(1)) _attempts.Dequeue();
                var result = await new PacketDelivery(_queue, _http, _identity.Signer).DeliverOnceAsync(limit: Math.Max(0, policy.Control.RateLimitPerMinute - _attempts.Count), cancellationToken: cancellationToken).ConfigureAwait(false);
                for (var i = 0; i < result.Attempted; i++) _attempts.Enqueue(now);
                failed = !result.Success;
                if (result.TransportFailure is { } deliveryError)
                {
                    transportError = deliveryError;
                    error = deliveryError.Code;
                }
                if(result.DisabledModules.Count>0) {
                    foreach(var item in assignment["assigned_modules"]!.AsArray().OfType<JsonObject>())
                        if(result.DisabledModules.Contains(item["module_id"]!.GetValue<string>())) item["enabled"]=false;
                    policy=AgentPolicy.Parse(assignment,_identity.AgentId,_catalog);
                }
            }
            if (state == "drain" && _queue.Pending().Count == 0)
                await _http.PostAsync("/api/v1/agent/policy-report", policy.Report("paused", rights), cancellationToken).ConfigureAwait(false);
            if (policy.AdDc is null && auditReport is not null) await _http.PostAsync("/api/v1/agent/windows-audit-report", auditReport, cancellationToken).ConfigureAwait(false);
            if (fileResult?.Report is { } fileReport)
                _fileAuditReport.Start(fileReport, _http, fileAuditReadDiagnostics, cancellationToken);
            var eventActive = state == "active" && source is not null && (policy.AdDc is not null || policy.Workstations is not null);
            active = eventActive || state == "active" && (policy.Snapshots.Count > 0 || policy.FileAudit is not null || policy.NpsModules.Count > 0);
            var capturePolicy = CanonicalJson.Serialize(new JsonObject { ["dc"] = policy.AdDc?.DeepClone(), ["ws"] = policy.Workstations?.DeepClone() });
            if (eventActive && (_lastCapture is null || _lastCapturePolicy != capturePolicy || policy.AdDc is not null && _dcCatchUpChannel is not null
                || clock.GetUtcNow() - _lastCapture >= TimeSpan.FromSeconds(IntervalSeconds)))
            {
                var hostId = sourceHostId;
                var moduleId = policy.AdDc is not null ? AdDcModule.ModuleId : WorkstationsModule.ModuleId;
                var dc = policy.AdDc is not null ? new AdDcModule(hostId, AdDcConfig.Parse(policy.AdDc, _catalog), source!, _catalog) : null;
                var ws = policy.Workstations is not null ? new WorkstationsModule(hostId, WorkstationPolicy.Parse(policy.Workstations), source!,
                    protectionReader ?? (OperatingSystem.IsWindows() ? DefenderProtectionReader.Read : null)) : null;
                var deadline = Stopwatch.StartNew();
                if (_lastCapturePolicy != capturePolicy) _dcCatchUpChannel = null;
                var channel = dc is not null && _lastCapturePolicy == capturePolicy ? _dcCatchUpChannel : null;
                var budget = Math.Min(16, policy.Control.BatchSize) - _queue.Pending().Count(packet => packet.Envelope.ModuleId == moduleId);
                try
                {
                    // DC catch-up yields for check-in after a bounded number of packets, never after elapsed time.
                    for (var step = 0; step < budget && (dc is not null || deadline.Elapsed < CaptureRunner.WallBudget); step++)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var result = dc?.Collect(Position(moduleId), clock.GetUtcNow(), channel) ?? ws!.Collect(Position(moduleId), clock.GetUtcNow(), channel);
                        if (result.Sample is null)
                        {
                            if (dc is not null) _dcCatchUpChannel = null;
                            break;
                        }
                        _queue.Capture(_identity.Signer, _identity.AgentId, result.Sample, clock.GetUtcNow());
                        captured++;
                        channel = result.CatchUpChannel;
                        if (dc is not null) _dcCatchUpChannel = channel;
                        if (channel is null) break;
                    }
                }
                catch (QueueFullException exception) { error = exception.Code; }
                _lastCapture = clock.GetUtcNow();
                _lastCapturePolicy = capturePolicy;
            }
            if (state == "active")
            {
                foreach (var (moduleId, npsPolicy) in policy.NpsModules)
                {
                    var signature = CanonicalJson.Serialize(npsPolicy.Value);
                    if (_lastNpsCapture.TryGetValue(moduleId, out var last) && last.Policy == signature && clock.GetUtcNow() - last.At < TimeSpan.FromSeconds(IntervalSeconds)) continue;
                    var npsSource = npsEventSource;
                    var accountingSource = radiusSource;
                    if (OperatingSystem.IsWindows())
                    {
                        if (moduleId == NpsPolicy.Nps) npsSource ??= new NpsEventSource();
                        else accountingSource ??= new RadiusTailSource(new RadiusFileSystem());
                    }
                    var npsModule = moduleId == NpsPolicy.Nps ? new NpsModule(sourceHostId, npsPolicy, npsSource ?? throw new AgentException("agent_nps_native_unavailable")) : null;
                    var accountingModule = moduleId == NpsPolicy.Accounting ? new RadiusAccountingModule(sourceHostId, npsPolicy, accountingSource ?? throw new AgentException("agent_radius_native_unavailable")) : null;
                    var budget = Math.Min(16, policy.Control.BatchSize) - _queue.Pending().Count(p => p.Envelope.ModuleId == moduleId);
                    var deadline = Stopwatch.StartNew();
                    try
                    {
                        for (var step = 0; step < budget && deadline.Elapsed < CaptureRunner.WallBudget; step++)
                        {
                            cancellationToken.ThrowIfCancellationRequested();
                            // The NPS importer requires the payload observation and signed envelope to name the same instant.
                            var observed = clock.GetUtcNow();
                            var sample = npsModule?.Collect(Position(moduleId), observed) ?? accountingModule!.Collect(Position(moduleId), observed);
                            _queue.Capture(_identity.Signer, _identity.AgentId, sample, observed); captured++;
                            if (npsModule is not null && sample.Payload["context"]!["tail_drained"]!.GetValue<bool>() || sample.CursorBefore == sample.CursorAfter) break;
                            if (accountingModule is not null && sample.Payload["records"]!.AsArray().Count == 0 && sample.Payload["context"]!["empty_progress_v1"] is null) break;
                        }
                        _lastNpsCapture[moduleId] = (clock.GetUtcNow(), signature);
                    }
                    catch (AgentException exception) { error = exception.Code; }
                }
                if (policy.FileAudit is { } filePolicy)
                {
                    bool permissionsOnly = !filePolicy.Workstation && !policy.FileAuditActivity;
                    var signature = CanonicalJson.Serialize(filePolicy.Value) + ":" + permissionsOnly;
                    if (_lastFileCapture is null || signature != _lastFilePolicy || clock.GetUtcNow()-_lastFileCapture >= TimeSpan.FromSeconds(IntervalSeconds))
                    {
                        IFileAuditEventSource? fileSource=fileEventSource;
                        Action<string,string>? pathCheck=filePathCheck;
                        Func<string,bool>? accountCheck=fileAccountCheck;
                        Func<string,string,string?>? pathKind = null;
                        if (OperatingSystem.IsWindows())
                        {
                            fileSource ??= new FileAuditEventSource();
                            if (pathCheck is null)
                            {
                                var nativeFileAudit = new NativeFileAuditApi();
                                pathCheck = nativeFileAudit.CheckPath;
                                if (policy.FileAuditActivity) pathKind = nativeFileAudit.CheckPathKind;
                            }
                            accountCheck ??= new FileAuditAccounts().IsUser;
                        }
                        if (fileSource is null || pathCheck is null) throw new AgentException("file_audit_native_unavailable");
                        var module=new FileAuditModule(sourceHostId,filePolicy,fileSource,pathCheck,accountCheck,
                            permissionsOnly:permissionsOnly,pathKind:pathKind);
                        var budget=Math.Min(16,policy.Control.BatchSize)-_queue.Pending().Count(p => p.Envelope.ModuleId == FileAuditModule.ModuleId);
                        var deadline=Stopwatch.StartNew();
                        var savedLimit=_queue.MaxBytes; _queue.MaxBytes=Math.Min(savedLimit,filePolicy.Number("spool_bytes"));
                        bool catchUp = policy.FileAuditActivity;
                        try
                        {
                            for (var step=0; step<budget && deadline.Elapsed < TimeSpan.FromSeconds(filePolicy.Number("wall_seconds")); step++)
                            {
                                cancellationToken.ThrowIfCancellationRequested();
                                var position=Position(FileAuditModule.ModuleId); var sample=module.Collect(position,clock.GetUtcNow());
                                _queue.Capture(_identity.Signer,_identity.AgentId,sample,clock.GetUtcNow()); captured++;
                                if (sample.CursorAfter == sample.CursorBefore || position is not null && sample.Generation != position.Generation || sample.Payload["context"]?["read_error"] is not null
                                    || sample.Payload["records"]!.AsArray().Count == 0 && sample.FilteredCount == 0 && !(sample.LostCount > 0))
                                {
                                    catchUp = false;
                                    break;
                                }
                            }
                            _lastFileCapture=catchUp ? null : clock.GetUtcNow(); _lastFilePolicy=signature;
                        }
                        catch (QueueFullException exception) { error=exception.Code; }
                        finally { _queue.MaxBytes=savedLimit; }
                    }
                }
                try
                {
                    var snapshotResult = _snapshots.Tick(policy.Snapshots, _queue, _identity.Signer, _identity.AgentId, clock.GetUtcNow(), policy.Control.BatchSize, cancellationToken);
                    captured += snapshotResult.Captured;
                    if (error is null && snapshotResult.Failure is { } failure)
                    {
                        snapshotFailure = failure;
                        error = failure.Code;
                    }
                    if (_snapshots.Busy) IntervalSeconds = Math.Min(IntervalSeconds, 1);
                }
                catch (QueueFullException exception) { error = exception.Code; }
            }
            // A new check-in still authorizes every burst. Failed delivery and the owner's rate limit
            // retain normal backoff; a healthy DC backlog or newly captured packet needs no idle poll.
            ContinueImmediately = state == "active" && (policy.AdDc is not null || policy.FileAuditActivity)
                && error is null && !failed
                && _attempts.Count < policy.Control.RateLimitPerMinute
                && (policy.AdDc is not null && _dcCatchUpChannel is not null
                    || _queue.Pending().Any(packet => policy.AdDc is not null && packet.Envelope.ModuleId == AdDcModule.ModuleId
                        || policy.FileAuditActivity && packet.Envelope.ModuleId == FileAuditModule.ModuleId));
        }
        catch (Exception exception) when (exception is AgentException or ProtocolException)
        {
            _snapshots?.Cancel();
            transportError = exception as TransportException;
            error = exception is AgentException agent ? agent.Code : ((ProtocolException)exception).Code;
            if (error is "agent_bootstrap_expired" or "agent_bootstrap_rejected") error = "agent_identity_missing_reenroll_required";
            failed = true;
            active = false;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        { error = "agent_cycle_failed"; transportError = null; failed = true; active = false; }
        if (transportError is not null && (error is null || error == transportError.Code || transportError.Code == "agent_bootstrap_rejected"))
            return Finish(error ?? transportError.Code, active, captured, failed, transportError.Detail);
        return Finish(error ?? (failed ? "agent_delivery_pending" : null), active, captured, failed,
            snapshotFailure?.Code == error ? snapshotFailure?.Detail : null);
    }

    private string ProbeRights(AgentPolicy policy, IEventLogSource? source, string hostId)
    {
        if (policy.RightsProbeRequest is null || source is null) return "unavailable";
        // Event Log access does not prove LDAP/SYSVOL access under the service identity.
        if (policy.Snapshots.Count > 0 || policy.FileAudit is not null || policy.NpsModules.Count > 0) return "unavailable";
        try
        {
            IEnumerable<string> channels = policy.Workstations is not null ? Enumerable.Range(0, WorkstationPolicy.Channels.Length)
                .Where(WorkstationPolicy.Parse(policy.Workstations).ChannelEnabled).Select(i => WorkstationPolicy.Channels[i])
                : policy.AdDc is not null ? AdDcConfig.Parse(policy.AdDc, _catalog).Channels.Where(pair => pair.Value).Select(pair => pair.Key) : [];
            foreach (var channel in channels) source.Read(channel, ChannelProgress.Start(hostId), 1);
            return "allowed";
        }
        catch (EventLogReadException exception) { return exception.Diagnostic?.WinError == 5 ? "denied" : "unavailable"; }
    }

    private string? ReadBootstrap()
    {
        if (_options.TokenFile is { Length: > 0 } path)
        {
            if (!File.Exists(path)) return null;
            if (new FileInfo(path).Length > 8192 || new FileInfo(path).LinkTarget is not null) throw new AgentException("agent_bootstrap_invalid");
            var raw = File.ReadAllText(path);
            if (!raw.TrimStart().StartsWith('{') && clock.GetUtcNow() - File.GetLastWriteTimeUtc(path) > TimeSpan.FromHours(1)) throw new AgentException("agent_bootstrap_expired");
            return raw;
        }
        var savedPath = Path.Combine(_options.StateDir, "bootstrap.json");
        // A fresh token explicitly supplied by a reinstall replaces a retained expired bootstrap.
        var registryToken = OperatingSystem.IsWindows() ? MsiConfiguration.ReadToken() : null;
        var saved = registryToken is null ? _files.ReadAll(savedPath) : null;
        IKeyProtector protector = OperatingSystem.IsWindows() ? new DpapiKeyProtector() : new RestrictedFileKeyProtector();
        if (registryToken is not null)
        {
            // Validate before retaining anything; remove the MSI's transient registry token only after durable protection.
            EnrollmentInput.Parse(registryToken, clock.GetUtcNow());
            var bytes = Encoding.UTF8.GetBytes(registryToken);
            try
            {
                saved = CanonicalJson.ToBytes(new JsonObject { ["protection"] = protector.Name, ["data"] = Convert.ToBase64String(protector.Protect(bytes)),
                    ["created_at"] = Iso8601.Format(clock.GetUtcNow()) });
                _files.WriteAtomic(savedPath, saved);
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
            if (OperatingSystem.IsWindows()) MsiConfiguration.ClearToken();
        }
        if (saved is null) return null;
        if (saved.Length > 32768) throw new AgentException("agent_bootstrap_invalid");
        var body = JsonNode.Parse(saved)!.AsObject();
        if (body["protection"]?.GetValue<string>() != protector.Name || !Iso8601.TryParseUtc(body["created_at"]?.GetValue<string>(), out var created)) throw new AgentException("agent_bootstrap_invalid");
        var clear = protector.Unprotect(Convert.FromBase64String(body["data"]!.GetValue<string>()));
        try
        {
            var token = Encoding.UTF8.GetString(clear);
            var input = EnrollmentInput.Parse(token, clock.GetUtcNow());
            bool packaged = !string.IsNullOrEmpty(_options.CaCertificate) && input.ComputerEntityId is null;
            if (!packaged && clock.GetUtcNow() - created > TimeSpan.FromSeconds(input.ComputerEntityId is null ? 3600 : 604800))
                throw new AgentException("agent_bootstrap_expired");
            return token;
        }
        finally { CryptographicOperations.ZeroMemory(clear); }
    }

    private void ClearBootstrap()
    {
        if (_options.TokenFile is { Length: > 0 } path && File.Exists(path)) File.Delete(path);
        _files.Delete(Path.Combine(_options.StateDir, "bootstrap.json"));
        if (OperatingSystem.IsWindows()) MsiConfiguration.ClearToken();
    }

    private bool HasFileShares(CancellationToken ct)
    {
        var catalog = localShareReader?.Invoke(ct) ?? (OperatingSystem.IsWindows() ? NativeFileAuditApi.ListLocalShares(ct) : null);
        return catalog is { State: LocalSmbCatalogState.Ready, Shares.Count: > 0 };
    }

    private AgentHttpClient NewHttp(AgentIdentity? identity)
    {
        if (transportFactory is not null) return transportFactory(identity);
        var roots = new X509Certificate2Collection();
        if (!string.IsNullOrEmpty(_options.CaBundle)) roots.ImportFromPemFile(_options.CaBundle);
        if (!string.IsNullOrEmpty(_options.CaCertificate))
        {
            if (string.IsNullOrEmpty(_options.CaFingerprint)) throw new AgentException("agent_config_invalid");
            try { roots.Add(X509CertificateLoader.LoadCertificate(Convert.FromBase64String(_options.CaCertificate))); }
            catch (Exception error) when (error is FormatException or CryptographicException) { throw new AgentException("agent_config_invalid"); }
        }
        return new AgentHttpClient(AgentHttp.Create(new Uri(_options.ServerUrl), identity?.Certificate, roots, _options.CaFingerprint),
            clientCertificateConfigured: identity is not null);
    }

    private void Use(AgentIdentity identity)
    {
        if (_identity?.Certificate.Thumbprint == identity.Certificate.Thumbprint && _http is not null) { identity.Dispose(); return; }
        AgentHttpClient next;
        try { next = NewHttp(identity); }
        catch { identity.Dispose(); throw; }
        _fileAuditCatalog?.Cancel();
        _fileAuditReport.Cancel();
        _http?.Dispose();
        _identity?.Dispose();
        _identity = identity;
        _http = next;
    }

    private CycleStatus Finish(string? error, bool active, int captured, bool failed, string? detail = null)
    {
        var pending = _queue?.Pending().Count ?? 0;
        var observed = Iso8601.Format(clock.GetUtcNow());
        var snapshotFailures = _snapshots?.Failures.ToDictionary();
        var catalogDiagnostic = _fileAuditCatalog?.Diagnostic;
        foreach (var name in new[] { "last-cycle.json", "status.json" })
        {
            try
            {
                var status = new JsonObject
                { ["observed_at_utc"] = observed, ["collection_active"] = active, ["error_code"] = error, ["pending_packets"] = pending };
                if (name == "status.json" && detail is not null) status["error_detail"] = detail;
                if (_fileAuditReport.Error is { } fileReportError) status["file_audit_report_error"] = fileReportError;
                if (catalogDiagnostic is { } catalog)
                    status["file_audit_catalog"] = new JsonObject
                    {
                        ["enumeration_error"] = catalog.EnumerationError, ["native_status"] = catalog.NativeStatus,
                        ["report_error"] = catalog.ReportError, ["http_status"] = catalog.HttpStatus
                    };
                if (name == "status.json" && snapshotFailures is { Count: > 0 })
                    status["snapshot_errors"] = new JsonObject(snapshotFailures.Select(item => KeyValuePair.Create(item.Key,
                        (JsonNode?)new JsonObject { ["error_code"] = item.Value.Code, ["error_detail"] = item.Value.Detail })));
                _files.WriteAtomic(Path.Combine(_options.StateDir, name), CanonicalJson.ToBytes(status));
            }
            catch (Exception exception) when (exception is AgentException or IOException or UnauthorizedAccessException)
            { error ??= "agent_cycle_status_write_failed"; failed = true; }
        }
        if (error is not null || failed) ContinueImmediately = false;
        return new(error, active, captured, pending, failed)
        { ErrorDetail = detail, SnapshotFailures = snapshotFailures, FileAuditCatalog = catalogDiagnostic };
    }

    public void Dispose()
    {
        _snapshots?.Dispose();
        _fileAuditCatalog?.Dispose();
        _fileAuditReport.Dispose();
        _http?.Dispose();
        _identity?.Dispose();
        _queue?.Dispose();
    }
}
