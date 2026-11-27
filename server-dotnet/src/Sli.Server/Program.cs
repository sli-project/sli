using Microsoft.AspNetCore.Http.Features;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Access.Requests;
using Sli.Server.Agents;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Groups;
using Sli.Server.Agents.Deployment;
using Sli.Server.Agents.FileAudit;
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.Radius;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Agents.Updates;
using Sli.Server.Auth;
using Sli.Server.Auth.Administration;
using Sli.Server.Auth.Administration.ApiKeys;
using Sli.Server.Auth.Commands;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Auth.Recovery;
using Sli.Server.Auth.ReportKeys;
using Sli.Server.Domains;
using Sli.Server.Entities.State;
using Sli.Server.Entities;
using Sli.Server.Hosting;
using Sli.Server.Infrastructure;
using Sli.Server.Notifications;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic.Risk;
using Sli.Server.Reports;
using Sli.Server.Legacy;
using Sli.Server.Semantic;

if (args.Length > 0 && args[0] == "agent-command")
{
    Environment.ExitCode = await AgentCommandConsole.RunAsync(args[1..]);
    return;
}
if (args.Length > 0 && args[0] == "existing-postgres-bootstrap")
{
    Environment.ExitCode = await Sli.Server.InstallationSetup.PostgresBootstrapCommand.RunAsync(args[1..]);
    return;
}
if (args.Length > 0 && args[0] == "radius-session-reconciliation")
{
    Environment.ExitCode = await Sli.Server.Vpn.RadiusReconciliationCommand.RunAsync(args[1..]);
    return;
}
if (args.Length > 0 && args[0] == "collection-block-control")
{
    Environment.ExitCode = await Sli.Server.Sources.CollectionBlockCommand.RunAsync(args[1..]);
    return;
}
if (args.Length > 0 && args[0] == "ad-source-credentials")
{
    var files = new Sli.Server.Operations.OperationsFiles(new ConfigurationBuilder().Build());
    Environment.ExitCode = await new Sli.Server.Sources.AdSourceCredentialCommand(
        new Sli.Server.Sources.AdSourceCredentials(files.DataRoot), new AuthConsoleIO()).RunAsync(args[1..]);
    return;
}
if (args.Length > 0 && args[0] == "eventlog-collector")
{
    Environment.ExitCode = await NpsEventLogCommand.RunAsync(args[1..]);
    return;
}
if (args.Length > 0 && args[0] == "plugin-update-runtime")
{
    Environment.ExitCode = await Sli.Server.Plugins.PluginRuntimeCommand.RunAsync(args[1..]);
    return;
}
if (args.Length > 0 && args[0] == "operations-storage-snapshot")
{
    Environment.ExitCode = await Sli.Server.Operations.OperationsWorkerObservation.RunAsync("operations_storage_snapshot", () => Sli.Server.Operations.OperationsStorageSnapshotCommand.RunAsync(args[1..]));
    return;
}
if (args.Length > 0 && args[0] == "ad-context-live-canary")
{
    Environment.ExitCode = await Sli.Server.Ad.AdContextLiveCanaryCommand.RunAsync(args[1..]);
    return;
}
if (args.Length > 0 && args[0] == "core-job-executor")
{
    Environment.ExitCode = await Sli.Server.Jobs.CoreJobCommand.RunAsync(args[1..]);
    return;
}
if (args.Length > 0 && args[0] == "notification-setup")
{
    Environment.ExitCode = await NotificationSetupCommand.RunAsync(args[1..]);
    return;
}
if (args.Length > 0 && args[0] == "storage-lifecycle-worker")
{
    Environment.ExitCode = await Sli.Server.Storage.Lifecycle.StorageLifecycleCommand.RunAsync(args[1..]);
    return;
}
if (args.Length > 0 && args[0] is "collection-worker" or "legacy-post-collection-worker" or "semantic-worker")
{
    Environment.ExitCode = await LegacyWorkerCommand.RunAsync(args[0], args[1..]);
    return;
}
if (args.Length > 0 && args[0] is "account-watch-worker" or "account-decoy-worker" or "file-decoy-worker" or "file-ransom-worker" or "nps-threshold-worker")
{
    Environment.ExitCode = await DetectorCommand.RunAsync(args[0][..^7], args[1..]);
    return;
}
if (args.Length > 0 && args[0] == "semantic-retained-facts")
{
    Environment.ExitCode = await RetainedFactsCommand.RunAsync(args[1..]);
    return;
}
if (args.Length > 0 && args[0] == "semantic-dispatch-partition-recovery")
{
    Environment.ExitCode = await SemanticDispatchRecoveryCommand.RunAsync(args[1..]);
    return;
}
if (args.Length > 0 && args[0] == "semantic-production-control")
{
    Environment.ExitCode = await SemanticProductionControlCommand.RunAsync(args[1..]);
    return;
}
if (args.Length > 0 && args[0] == "sigma-history-test")
{
    Environment.ExitCode = await SigmaHistoryTestCommand.RunAsync(args[1..]);
    return;
}

if (args.Length > 0 && args[0] == "semantic-production-worker")
{
    Environment.ExitCode = await Sli.Server.Operations.OperationsWorkerObservation.RunAsync("semantic", () => SemanticProductionCommand.RunAsync(args[1..]));
    return;
}
if (args.Length > 0 && args[0] == "semantic-quarantine-replay")
{
    Environment.ExitCode = await SemanticQuarantineReplayCommand.RunAsync(args[1..]);
    return;
}
if (args.Length > 0 && args[0] == "smtp-delivery-worker")
{
    Environment.ExitCode = await Sli.Server.Operations.OperationsWorkerObservation.RunAsync("smtp_delivery", () => Sli.Server.Notifications.SmtpWorkerCommand.RunAsync(args[1..]));
    return;
}
if (args.Length > 0 && args[0] == "report-producer")
{
    Environment.ExitCode = await Sli.Server.Notifications.ReportProducerCommand.RunAsync(args[1..]);
    return;
}
if (args.Length > 0 && args[0] == "notification-delivery-worker")
{
    Environment.ExitCode = await Sli.Server.Operations.OperationsWorkerObservation.RunAsync("notification_delivery", () => Sli.Server.Notifications.NotificationDeliveryCommand.RunAsync(args[1..]));
    return;
}
if (args.Length > 0 && args[0] == "telegram-delivery-worker")
{
    Environment.ExitCode = await Sli.Server.Operations.OperationsWorkerObservation.RunAsync("telegram_delivery", () => Sli.Server.Notifications.TelegramWorkerCommand.RunAsync(args[1..]));
    return;
}
if (args.Length > 0 && args[0] == "password-producer")
{
    Environment.ExitCode = await Sli.Server.Operations.OperationsWorkerObservation.RunAsync("password_producer", () => PasswordProducerCommand.RunAsync(args[1..]));
    return;
}
if (args.Length > 0 && args[0] == "password-risk-consumer")
{
    Environment.ExitCode = await Sli.Server.Operations.OperationsWorkerObservation.RunAsync("password_risk", () => PasswordRiskCommand.RunAsync(args[1..]));
    return;
}
if (args.Length > 0 && args[0] == "entity-state-worker")
{
    Environment.ExitCode = await Sli.Server.Operations.OperationsWorkerObservation.RunAsync("entity_state", () => EntityStateWorkerCommand.RunAsync(args[1..]));
    return;
}
if (args.Length > 0 && args[0] == "what-where-when-projection-worker")
{
    Environment.ExitCode = await Sli.Server.Operations.OperationsWorkerObservation.RunAsync("what_where_when_projection", () => WhatWhereWhenCommand.RunAsync(args[1..]));
    return;
}
if (args.Length > 0 && args[0] == "post-collection-worker")
{
    Environment.ExitCode = await Sli.Server.Operations.OperationsWorkerObservation.RunAsync("post_collection", () => AgentImportCommand.RunAsync(args[1..]));
    return;
}
if (args.Length > 0 && args[0] == "agent-import-worker")
{
    Environment.ExitCode = await Sli.Server.Operations.OperationsWorkerObservation.RunAsync("agent_import", () => AgentImportCommand.RunAsync(args[1..]));
    return;
}
if (args.Length > 0 && args[0] == "radius-accounting-worker")
{
    Environment.ExitCode = await Sli.Server.Operations.OperationsWorkerObservation.RunAsync("radius_accounting", () => RadiusWorkerCommand.RunAsync(args[1..]));
    return;
}
if (args.Length > 0 && args[0] == "gpo-snapshot-worker")
{
    Environment.ExitCode = await Sli.Server.Operations.OperationsWorkerObservation.RunAsync("gpo_snapshot", () => GpoWorkerCommand.RunAsync(args[1..]));
    return;
}
if (args.Length > 0 && args[0] == "ad-snapshot-manifest-coordinator-worker")
{
    Environment.ExitCode = await Sli.Server.Operations.OperationsWorkerObservation.RunAsync("ad_snapshot_manifest_coordinator", () => AdCoordinatorCommand.RunAsync(args[1..]));
    return;
}
if (args.Length > 0 && args[0] == "radius-acquisition")
{
    Environment.ExitCode = args.Contains("--cycle-child")
        ? await Sli.Server.Vpn.RadiusAcquisitionHost.RunAsync(args[1..])
        : await Sli.Server.Operations.OperationsWorkerObservation.RunAsync("plugin_radius_acquisition", () => Sli.Server.Vpn.RadiusAcquisitionHost.RunAsync(args[1..]));
    return;
}
if (args.Length > 0 && args[0] == "radius-session-observation")
{
    Environment.ExitCode = args.Contains("--cycle-child", StringComparer.Ordinal) ? await Sli.Server.Vpn.RadiusObservationHost.RunAsync(args[1..]) : await Sli.Server.Operations.OperationsWorkerObservation.RunAsync("plugin_radius_session_observation", () => Sli.Server.Vpn.RadiusObservationHost.RunAsync(args[1..]));
    return;
}
if (args.Length > 0 && args[0] == "ad-snapshot-worker")
{
    Environment.ExitCode = await GpoWorkerCommand.RunAsync(args[1..], "sli.ad-snapshot");
    return;
}
bool recoveryCommand = args.Length > 0 && args[0] == "owner-recovery";
bool authCommand = args.Length > 0 && args[0] is "create-user" or "create-api-key" or "revoke-api-key" or "issue-report-key";
if (authCommand && AuthConsole.TryHandleNonMutation(args, out int authExitCode))
{
    Environment.ExitCode = authExitCode;
    return;
}
if (recoveryCommand)
{
    if (OwnerRecoveryConsole.TryHandleNonIssuance(args, out int exitCode))
    {
        Environment.ExitCode = exitCode;
        return;
    }
    try { new OwnerRecoveryTerminal().RequireRootInteractiveTerminal(); }
    catch (UnauthorizedAccessException error) when (error.Message is "host_root_required" or "terminal_required")
    {
        Console.Error.WriteLine(error.Message);
        Environment.ExitCode = 1;
        return;
    }
}
try
{
var builder = WebApplication.CreateBuilder(recoveryCommand || authCommand ? [] : args);
// Host/Kestrel log startup exceptions before Run throws. Until listening,
// emit only the safe setting/error code below, not framework exception text.
int startupCompleted=0;
builder.Services.PostConfigure<LoggerFilterOptions>(options=>
{
    bool StartupFilter(string? provider,string? category,LogLevel level)=>Volatile.Read(ref startupCompleted)!=0 || level<LogLevel.Error;
    var rules=options.Rules.ToArray();
    options.Rules.Clear();
    options.Rules.Add(new LoggerFilterRule(null,null,options.MinLevel,StartupFilter));
    // Preserve each configured category/provider threshold and filter.
    foreach(var rule in rules)
        options.Rules.Add(new LoggerFilterRule(rule.ProviderName,rule.CategoryName,rule.LogLevel,
            (provider,category,level)=>StartupFilter(provider,category,level) && (rule.Filter?.Invoke(provider,category,level) ?? true)));
});
try { builder.Configuration.AddInstalledEnvironment(); IngressHosting.ValidateAdmissionSettings(builder.Configuration); }
catch (ServerConfigurationException error)
{
    Console.Error.WriteLine(error.Message);
    Environment.ExitCode = 1;
    return;
}
AgentTlsTrust? listenerTrust = null;
if (!recoveryCommand && !authCommand && !AgentTlsTrust.TryLoad(builder.Configuration, out listenerTrust))
{
    Console.Error.WriteLine("server_configuration_invalid:Sli:AgentMtlsCaFile:invalid");
    Environment.ExitCode = 1;
    return;
}
builder.Services.AddSingleton<IPostgresConnectionFactory, PostgresConnectionFactory>();
builder.Services.AddEntityReads();
builder.Services.AddSingleton<ReportRuleCatalog>();
builder.Services.AddSingleton<IReportCatalogProvider>(services => services.GetRequiredService<ReportRuleCatalog>());
builder.Services.AddSingleton<IReportRuleCatalog>(services => services.GetRequiredService<ReportRuleCatalog>());
builder.Services.AddScoped<IPrincipalAuthenticator, PrincipalAuthenticator>();
builder.Services.AddSingleton<TransportGate>();
builder.Services.AddScoped<IDomainAccessService, DomainAccessService>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddSingleton<SessionAccessFactsCache>();
builder.Services.AddScoped<DomainRepository>();
builder.Services.AddScoped<IDomainRepository>(services => services.GetRequiredService<DomainRepository>());
builder.Services.AddScoped<IHomeSummaryAccess, HomeSummaryAccess>();
builder.Services.AddScoped<IHomeSummaryRepository, HomeSummaryRepository>();
builder.Services.AddScoped<HomeSummaryReaders>();
builder.Services.AddScoped<HomeSummaryService>();
builder.Services.AddAuthLifecycle();
builder.Services.AddNotificationAdministration();
builder.Services.AddSingleton<Sli.Server.Operations.BackupSettingsClient>();
builder.Services.AddAuthLoginSecurity();
builder.Services.AddAccessReadAdministration();
builder.Services.AddAdHardening();
builder.Services.AddScoped<Sli.Server.Workspace.IWorkspaceRows, Sli.Server.Workspace.PostgresWorkspaceRows>();
Sli.Server.Workspace.WorkspaceCompatibilityEndpoints.AddWorkspaceCompatibility(builder.Services);
builder.Services.AddSliIngress(builder.Configuration, listenerTrust);
builder.Services.AddOwnerRecovery();
builder.Services.AddUserAdministration();
builder.Services.AddAccessWrites();
builder.Services.AddApiKeyAdministration();
builder.Services.AddAuthConsole();
builder.Services.AddAccessRequests();
Sli.Server.InstallationSetup.InstallationEndpoints.AddInstallation(builder.Services);
Sli.Server.Reporting.V2.ReportV2Endpoints.AddReportV2Engine(builder.Services);
builder.Services.AddReportKeyServices();
Sli.Server.Reporting.ReportStudioEndpoints.AddReportStudio(builder.Services);
Sli.Server.Compatibility.LegacyHttpEndpoints.AddLegacyHttp(builder.Services);
builder.Services.AddAgentEnrollment();
builder.Services.AddAgentPacketIngress();
builder.Services.AddAgentControl();
builder.Services.AddAgentLifecycleControl();
builder.Services.AddAgentRecoveryControl();
builder.Services.AddAgentClientControl();
Sli.Server.Agents.Diagnostics.AgentDiagnosticsEndpoints.AddAgentDiagnostics(builder.Services);
builder.Services.AddAgentUpdates();
builder.Services.AddAgentUpdateAdministration();
builder.Services.AddAgentGroups();
builder.Services.AddAgentDeployment();
builder.Services.AddAgentTemplates();
builder.Services.AddFileAuditControl();
Sli.Server.Investigations.InvestigationEndpoints.AddInvestigationNotes(builder.Services);
Sli.Server.Investigations.InvestigationListEndpoints.AddInvestigationList(builder.Services);
Sli.Server.Investigations.InvestigationDetailEndpoints.AddInvestigationDetail(builder.Services);
Sli.Server.Investigations.InvestigationEventEndpoints.AddInvestigationEvents(builder.Services);
Sli.Server.Investigations.InvestigationCreateEndpoints.AddInvestigationCreate(builder.Services);
Sli.Server.Investigations.InvestigationLinksEndpoints.AddInvestigationLinks(builder.Services);
Sli.Server.Investigations.InvestigationWorkspaceEndpoints.AddInvestigationWorkspace(builder.Services);
Sli.Server.Problems.ProblemEndpoints.AddProblemLifecycle(builder.Services);
Sli.Server.Storage.EventReports.EventReadEndpoints.AddEventReads(builder.Services);
Sli.Server.Ad.AdReportEndpoints.AddAdReports(builder.Services);
Sli.Server.Ad.AdV2Endpoints.AddAdV2(builder.Services);
Sli.Server.Operations.OperationsEndpoints.AddOperations(builder.Services);
Sli.Server.Notifications.ReportScheduleEndpoints.AddReportSchedules(builder.Services);
Sli.Server.Gpo.GpoEndpoints.AddGpoReports(builder.Services);
Sli.Server.Vpn.VpnEndpoints.AddVpn(builder.Services);
Sli.Server.Workstations.WorkstationEndpoints.AddWorkstationReports(builder.Services);
builder.Services.AddLegacyJobs();
builder.Services.AddSemantic();

var app = builder.Build();
app.Lifetime.ApplicationStarted.Register(()=>Volatile.Write(ref startupCompleted,1));
if (authCommand)
{
    try
    {
        await using var scope = app.Services.CreateAsyncScope();
        Environment.ExitCode = await scope.ServiceProvider.GetRequiredService<AuthConsole>()
            .RunAsync(args, CancellationToken.None);
    }
    catch (ReportKeyPublicationException)
    {
        Console.Error.WriteLine("report_key_publication_failed");
        Environment.ExitCode = 1;
    }
    catch (Exception)
    {
        Console.Error.WriteLine("auth_command_failed");
        Environment.ExitCode = 1;
    }
    await app.DisposeAsync();
    return;
}
// Dispatch local recovery before validating HTTP-only settings.
if (recoveryCommand)
{
    try
    {
        await using var scope = app.Services.CreateAsyncScope();
        Environment.ExitCode = await scope.ServiceProvider.GetRequiredService<IOwnerRecoveryConsole>()
            .RunAsync(args, CancellationToken.None);
    }
    catch (Exception)
    {
        Console.Error.WriteLine("owner_recovery_issue_failed");
        Environment.ExitCode = 1;
    }
    await app.DisposeAsync();
    return;
}
try
{
    if (listenerTrust is not null) _ = app.Services.GetRequiredService<AgentTlsTrust>();
    _ = app.Services.GetRequiredService<AuthRequestPolicy>();
    _ = app.Services.GetRequiredService<TransportGate>();
    _ = app.Services.GetRequiredService<DynamicRequestAdmission>();
    IngressHosting.ValidateBindSecurity(app.Configuration);
}
catch (Exception error) when (error is InvalidOperationException or ArgumentException or FormatException)
{
    Console.Error.WriteLine(error is ServerConfigurationException ? error.Message : "server_configuration_invalid:Kestrel:Endpoints:invalid");
    Environment.ExitCode = 1;
    await app.DisposeAsync();
    return;
}
app.Use(async (context, next) =>
{
    context.Response.OnStarting(() => { DomainHttp.ApplyHeaders(context); return Task.CompletedTask; });
    try { await next(context); }
    catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { }
    catch (Exception error)
    {
        if (context.Response.HasStarted) throw;
        string route = context.Request.Path.Value switch
        {
            "/api/auth/login" => "/api/auth/login",
            "/api/auth/me" => "/api/auth/me",
            "/api/auth/logout" => "/api/auth/logout",
            "/api/auth/change-initial-password" => "/api/auth/change-initial-password",
            _ => "other"
        };
        await DomainHttp.WriteUnexpectedAsync(context, app.Logger, error, context.RequestAborted, route);
    }
});
app.UseRateLimiter();
app.UseSliDynamicAdmission();
app.UseReportKeyRequestGate();
app.UseInitialPasswordGate();
app.UseReadRoleRequestGate();
app.MapAuthEndpoints();
Sli.Server.Reporting.SliV4FixtureEndpoints.MapSliV4Fixture(app);
app.MapEntityReads();
app.MapNotificationAdministration();
app.MapAccessReadEndpoints();
app.MapAdHardening();
Sli.Server.Workspace.WorkspaceEndpoints.MapWorkspaceEndpoints(app);
Sli.Server.Workspace.WorkspaceCompatibilityEndpoints.MapWorkspaceCompatibility(app);
app.MapUserAdministrationEndpoints();
app.MapAccessWriteEndpoints();
app.MapApiKeyAdministrationEndpoints();
app.MapAccessRequestEndpoints();
Sli.Server.InstallationSetup.InstallationEndpoints.MapInstallation(app);
Sli.Server.Reporting.ReportStudioEndpoints.MapReportStudio(app);
Sli.Server.Reporting.V2.ReportV2Endpoints.MapReportV2Engine(app);
app.MapAgentEnrollmentEndpoints();
app.MapAgentPacketEndpoints();
app.MapAgentControlEndpoints();
app.MapAgentLifecycleControlEndpoints();
app.MapAgentRecoveryControlEndpoints();
app.MapAgentClientControlEndpoints();
Sli.Server.Agents.Diagnostics.AgentDiagnosticsEndpoints.MapAgentDiagnosticsEndpoints(app);
app.MapAgentUpdateEndpoints();
app.MapAgentUpdateAdministrationEndpoints();
app.MapAgentGroupEndpoints();
app.MapAgentDeploymentEndpoints();
app.MapAgentTemplateEndpoints();
app.MapFileAuditControlEndpoints();
Sli.Server.Investigations.InvestigationEndpoints.MapInvestigationNoteEndpoints(app);
Sli.Server.Investigations.InvestigationListEndpoints.MapInvestigationList(app);
Sli.Server.Investigations.InvestigationDetailEndpoints.MapInvestigationDetail(app);
Sli.Server.Investigations.InvestigationEventEndpoints.MapInvestigationEvents(app);
Sli.Server.Investigations.InvestigationCreateEndpoints.MapInvestigationCreate(app);
Sli.Server.Investigations.InvestigationLinksEndpoints.MapInvestigationLinks(app);
Sli.Server.Investigations.InvestigationWorkspaceEndpoints.MapInvestigationWorkspace(app);
Sli.Server.Problems.ProblemEndpoints.MapProblemLifecycle(app);
Sli.Server.Storage.EventReports.EventReadEndpoints.MapEventReads(app);
Sli.Server.Ad.AdReportEndpoints.MapAdReports(app);
Sli.Server.Ad.AdV2Endpoints.MapAdV2(app);
Sli.Server.Operations.OperationsEndpoints.MapOperations(app);
Sli.Server.Operations.BackupSettingsEndpoints.MapBackupSettings(app);
Sli.Server.Notifications.ReportScheduleEndpoints.MapReportSchedules(app);
Sli.Server.Gpo.GpoEndpoints.MapGpoReports(app);
Sli.Server.Vpn.VpnEndpoints.MapVpn(app);
Sli.Server.Workstations.WorkstationEndpoints.MapWorkstationReports(app);
app.MapSliStaticAssets();
app.MapHomeSummary();
Sli.Server.Compatibility.LegacyHttpEndpoints.MapLegacyHttp(app);
app.MapSemantic();
app.MapLegacyJobs();
app.MapSliHealth();
app.Map("/api/v1/domains", async context =>
{
    CancellationToken ct = context.RequestAborted;
    string rawTarget = context.Features.Get<IHttpRequestFeature>()?.RawTarget ?? "";
    int question = rawTarget.IndexOf('?');
    string rawPath = question < 0 ? rawTarget : rawTarget[..question];
    if (!HttpMethods.IsGet(context.Request.Method) || rawPath != "/api/v1/domains")
    {
        await DomainHttp.WriteAsync(context, new { error = "not_implemented" }, StatusCodes.Status501NotImplemented, ct);
        return;
    }

    try
    {
        AuthenticationFailure? transportFailure = context.RequestServices.GetRequiredService<TransportGate>().CheckTransport(context);
        if (transportFailure is not null)
        {
            await DomainHttp.WriteFailureAsync(context, transportFailure, ct);
            return;
        }
        AuthenticationResult authentication = await context.RequestServices.GetRequiredService<IPrincipalAuthenticator>()
            .AuthenticateAsync(context, ct);
        if (!authentication.Succeeded)
        {
            await DomainHttp.WriteFailureAsync(context, authentication.Failure ?? new(401, "authentication_required"), ct);
            return;
        }
        Principal principal = authentication.Principal!;
        AuthenticationFailure? roleFailure = TransportGate.CheckViewerRole(principal);
        if (roleFailure is not null)
        {
            await DomainHttp.WriteFailureAsync(context, roleFailure, ct);
            return;
        }
        if (DomainQuery.HasParameters(context.Request.QueryString.Value))
        {
            await DomainHttp.WriteAsync(context, new { error = "domain_parameters_invalid" }, StatusCodes.Status400BadRequest, ct);
            return;
        }
        DomainAccessDecision access = await context.RequestServices.GetRequiredService<IDomainAccessService>()
            .EvaluateAsync(principal, ct);
        if (!access.CapabilityAllowed)
        {
            await DomainHttp.WriteAsync(context, new { error = "workspace_view_required" },
                StatusCodes.Status403Forbidden, ct);
            return;
        }
        IReadOnlyList<DomainItem> domains = await context.RequestServices.GetRequiredService<IDomainRepository>()
            .ReadAsync(access.Grant, ct);
        await DomainHttp.WriteAsync(context, new DomainResponse(domains), StatusCodes.Status200OK, ct);
    }
    catch (DomainScopeCompositionException)
    {
        await DomainHttp.WriteAsync(context, new { error = "domain_parameters_invalid" }, StatusCodes.Status400BadRequest, ct);
    }
    catch (PostgresException error) when (error.SqlState == "57014")
    {
        await DomainHttp.WriteAsync(context, new { error = "report_read_timeout", state = "unavailable" },
            StatusCodes.Status503ServiceUnavailable, ct);
    }
    catch (OperationCanceledException) when (ct.IsCancellationRequested)
    {
        // The client has disconnected; do not attempt another response.
    }
    catch (Exception error)
    {
        if (context.Response.HasStarted) throw;
        await DomainHttp.WriteUnexpectedAsync(context, app.Logger, error, ct);
    }
});
app.MapFallback("{**path}", async context =>
{
    if (context.Request.Path == "/api/auth/bootstrap")
    {
        await DomainHttp.WriteAsync(context, new { error = "not_found" }, StatusCodes.Status404NotFound, context.RequestAborted);
        return;
    }
    bool api=context.Request.Path.StartsWithSegments("/api");
    if(context.RequestServices.GetRequiredService<AuthRequestPolicy>().AuthRequired)
    {
        var auth=await context.RequestServices.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context,context.RequestAborted);
        if(!auth.Succeeded)
        {
            if(api) await DomainHttp.WriteFailureAsync(context,auth.Failure??new(401,"authentication_required"),context.RequestAborted);
            else context.Response.Redirect("/login"+QueryString.Create("next",context.Request.Path.ToUriComponent()+context.Request.QueryString));
            return;
        }
        if(api && TransportGate.CheckViewerRole(auth.Principal!) is {} role)
        { await DomainHttp.WriteFailureAsync(context,role,context.RequestAborted); return; }
    }
    if(api && context.RequestServices.GetRequiredService<TransportGate>().CheckTransport(context) is {} transport)
    { await DomainHttp.WriteFailureAsync(context,transport,context.RequestAborted); return; }
    if (api)
        await DomainHttp.WriteAsync(context, new { error = "not_ported", route = context.Request.Path.Value },
            StatusCodes.Status501NotImplemented, context.RequestAborted);
    else
        await DomainHttp.WriteAsync(context, new { error = "not_found" }, StatusCodes.Status404NotFound, context.RequestAborted);
});
if (app.Configuration["SLI_DEPLOYMENT_MODE"] == "native")
    await app.Services.GetRequiredService<AgentInstallPackages>().PrepareOnStartupAsync(
        app.Services.GetRequiredService<IPostgresConnectionFactory>(), app.Lifetime.ApplicationStopping);

// Native configure starts this API after database migration. A candidate tested
// behind the upgrade fence must not publish its MSI before the durable commit.
if (app.Configuration["SLI_DEPLOYMENT_MODE"] == "native" &&
    app.Configuration["SLI_NATIVE_UPGRADE_TESTING"] != "1")
{
    try
    {
        await using var scope = app.Services.CreateAsyncScope();
        await using var db = await scope.ServiceProvider.GetRequiredService<IPostgresConnectionFactory>()
            .OpenAsync(app.Lifetime.ApplicationStopping);
        await ShippedAgentUpdate.RegisterAsync(db, "/opt/sli/current/agent",
            scope.ServiceProvider.GetRequiredService<IAgentControlAudit>(), app.Lifetime.ApplicationStopping);
    }
    catch (Exception error)
    {
        Console.Error.WriteLine(error is AgentControlException { Message: "agent_package_verification_failed" }
            ? error.Message : "shipped_agent_update_registration_failed");
        Environment.ExitCode = 1;
        await app.DisposeAsync();
        return;
    }
}
app.Run();
}
catch(ServerConfigurationException error)
{
    Console.Error.WriteLine(error.Message);
    Environment.ExitCode=1;
}
catch(Exception)
{
    Console.Error.WriteLine("server_startup_failed");
    Environment.ExitCode=1;
}

public partial class Program { }
