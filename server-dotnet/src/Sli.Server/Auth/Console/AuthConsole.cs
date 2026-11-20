using System.CommandLine;
using System.CommandLine.Help;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Auth.Administration;
using Sli.Server.Auth.Administration.ApiKeys;
using Sli.Server.Auth.ReportKeys;
using System.Text.Json;

namespace Sli.Server.Auth.Commands;

public sealed class ReportKeyPublicationException() : Exception("report_key_publication_failed");

public sealed class AuthConsole(Func<IUserAdministration> users, Func<IApiKeyAdministration> keys, IAuthConsoleIO io,
    Func<IReportKeyAdministration>? reportKeys = null)
{
    private static readonly UserAdministrationActor LocalActor = new("session", null, null!);
    private static readonly ParserConfiguration Parser = new() { ResponseFileTokenReplacer = null };

    private static InvocationConfiguration Invocation(IAuthConsoleIO channels) => new()
    {
        Output = channels.Output, Error = channels.Error, EnableDefaultExceptionHandler = false
    };

    // Generic-host wiring calls this before resolving DB services. No user argument values are echoed on error.
    public static bool TryHandleNonMutation(string[] args, out int exitCode)
    {
        var channels = new AuthConsoleIO();
        var result = Commands(null).Parse(args, Parser);
        if (result.Action is HelpAction) { exitCode = result.Invoke(Invocation(channels)); return true; }
        if (result.Errors.Count != 0) { channels.Error.WriteLine("Invalid command arguments. Use --help."); exitCode = 2; return true; }
        exitCode = 0;
        return false;
    }

    public async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        var result = Commands(this).Parse(args, Parser);
        if (result.Action is not HelpAction && result.Errors.Count != 0)
        { io.Error.WriteLine("Invalid command arguments. Use --help."); return 2; }
        try { return await result.InvokeAsync(Invocation(io), ct); }
        catch (OperationCanceledException) { return 130; }
        catch (ReportKeyPublicationException) { throw; }
        catch (UserAdministrationException error) { io.Error.WriteLine(error.Message); return 1; }
        catch (ApiKeyAdministrationException error) { io.Error.WriteLine(error.Message); return 1; }
        catch (InvalidOperationException error) when (error.Message == "password_terminal_required")
        { io.Error.WriteLine("password_terminal_required"); return 1; }
        // Driver/crypto exceptions can contain credentials or SQL parameters.
        catch (Exception) { io.Error.WriteLine("auth_command_failed"); return 1; }
    }

    private static RootCommand Commands(AuthConsole? owner)
    {
        var root = new RootCommand("Manage Security Log Intelligence local authentication.");
        root.Directives.Clear();
        foreach (var option in root.Options.Where(option => option.Name == "--version").ToArray()) root.Options.Remove(option);
        var createUser = new Command("create-user", "Create a local user; password is requested privately.");
        var username = new Option<string>("--username") { Required = true };
        var userRole = new Option<string>("--role") { DefaultValueFactory = _ => "admin" };
        userRole.AcceptOnlyFromAmong("viewer", "operator", "admin");
        createUser.Options.Add(username); createUser.Options.Add(userRole);
        createUser.SetAction((parse, ct) => owner?.CreateUserAsync(parse.GetValue(username)!, parse.GetValue(userRole)!, ct) ?? Task.FromResult(0));
        var createKey = new Command("create-api-key", "Issue an ordinary API key; its secret is shown once.");
        var label = new Option<string>("--label") { Required = true };
        var keyRole = new Option<string>("--role") { DefaultValueFactory = _ => "viewer" };
        keyRole.AcceptOnlyFromAmong("viewer", "operator", "admin");
        createKey.Options.Add(label); createKey.Options.Add(keyRole);
        createKey.SetAction((parse, ct) => owner?.CreateKeyAsync(parse.GetValue(label)!, parse.GetValue(keyRole)!, ct) ?? Task.FromResult(0));
        var revokeKey = new Command("revoke-api-key", "Revoke an ordinary API key by id.");
        var id = new Option<string>("--id") { Required = true };
        id.Validators.Add(result =>
        {
            if (!ApiKeyAdministrationEndpoints.TryId(result.GetValueOrDefault<string>() ?? "", out _))
                result.AddError("invalid_api_key_id");
        });
        revokeKey.Options.Add(id);
        revokeKey.SetAction((parse, ct) => owner?.RevokeKeyAsync(parse.GetValue(id)!, ct) ?? Task.FromResult(0));
        var report = new Command("issue-report-key", "Issue an expiring report-only key to a protected pipe.");
        var reportLabel = new Option<string>("--label") { Required = true };
        var domain = new Option<long>("--domain-id") { Required = true };
        var hours = new Option<int>("--hours") { DefaultValueFactory = _ => 24 };
        var fileAgents = new Option<string[]>("--file-agent-id") { DefaultValueFactory = _ => [] };
        var stations = new Option<string[]>("--workstation-agent-id") { DefaultValueFactory = _ => [] };
        var stationsOnly = new Option<bool>("--workstations-only");
        report.Options.Add(reportLabel); report.Options.Add(domain); report.Options.Add(hours); report.Options.Add(fileAgents); report.Options.Add(stations); report.Options.Add(stationsOnly);
        report.SetAction((parse, ct) => owner?.IssueReportAsync(new(parse.GetValue(reportLabel)!, parse.GetValue(domain), parse.GetValue(hours),
            parse.GetValue(fileAgents) ?? [], parse.GetValue(stations) ?? [], parse.GetValue(stationsOnly)), ct) ?? Task.FromResult(0));
        root.Subcommands.Add(createUser); root.Subcommands.Add(createKey); root.Subcommands.Add(revokeKey); root.Subcommands.Add(report);
        return root;
    }

    private async Task<int> CreateUserAsync(string username, string role, CancellationToken ct)
    {
        if (!io.CanPromptPassword) { io.Error.WriteLine("password_terminal_required"); return 1; }
        string password = await io.ReadPasswordAsync("Password (at least 12 characters): ", ct);
        string confirmation = await io.ReadPasswordAsync("Repeat password: ", ct);
        if (password != confirmation) { io.Error.WriteLine("Passwords do not match."); return 1; }
        var item = await users().CreateAsync(new(username, password, role), LocalActor, ct);
        io.Output.WriteLine($"Created user id={item.GetProperty("id").GetInt64()} username={item.GetProperty("username").GetString()} role={item.GetProperty("role").GetString()}");
        return 0;
    }

    private async Task<int> CreateKeyAsync(string label, string role, CancellationToken ct)
    {
        var issued = await keys().IssueAsync(new(label, role), LocalActor, ct);
        io.Output.WriteLine($"Created API key id={issued.Item.GetProperty("id").GetInt64()} label={issued.Item.GetProperty("label").GetString()} role={issued.Item.GetProperty("role").GetString()}");
        io.Output.WriteLine("Copy this key now; it cannot be shown again:");
        io.Output.WriteLine(issued.Token); // Explicit one-time operator output, never a diagnostic/log.
        return 0;
    }

    private async Task<int> RevokeKeyAsync(string text, CancellationToken ct)
    {
        if (!ApiKeyAdministrationEndpoints.TryId(text, out var id)) { io.Error.WriteLine("invalid_api_key_id"); return 2; }
        if (await keys().RevokeAsync(id, LocalActor, ct)) { io.Output.WriteLine($"Revoked API key id={id}"); return 0; }
        io.Output.WriteLine($"Active API key id={id} was not found.");
        return 1;
    }

    private async Task<int> IssueReportAsync(IssueReportKeyCommand command, CancellationToken ct)
    {
        if (!io.IsOutputRedirected) { io.Error.WriteLine("report_key_requires_protected_output_pipe"); return 1; }
        ReportKeyIssueResult issued;
        try { issued = await (reportKeys ?? throw new InvalidOperationException())().IssueAsync(command, ct); }
        catch (OperationCanceledException) { throw; }
        catch (Exception) { io.Error.WriteLine("report_key_issue_failed"); return 1; }
        try
        {
            io.Error.WriteLine(JsonSerializer.Serialize(new { id = issued.Id, expires_at = ReportKeyTime.Format(issued.ExpiresAt), domain_id = issued.DomainId }));
            io.Output.Write(issued.Token);
        }
        catch (Exception) { throw new ReportKeyPublicationException(); }
        return 0;
    }
}

public static class AuthConsoleServices
{
    public static IServiceCollection AddAuthConsole(this IServiceCollection services)
    {
        services.TryAddSingleton<IAuthConsoleIO, AuthConsoleIO>();
        services.AddScoped(provider => new AuthConsole(() => provider.GetRequiredService<IUserAdministration>(),
            () => provider.GetRequiredService<IApiKeyAdministration>(), provider.GetRequiredService<IAuthConsoleIO>(),
            () => provider.GetRequiredService<IReportKeyAdministration>()));
        return services;
    }
}
