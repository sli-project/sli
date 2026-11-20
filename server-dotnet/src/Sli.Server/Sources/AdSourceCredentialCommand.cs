using System.CommandLine;
using System.CommandLine.Help;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Server.Auth.Commands;

namespace Sli.Server.Sources;

internal sealed class AdSourceCredentialCommand(AdSourceCredentials store, IAuthConsoleIO io, Action? pause = null)
{
    internal async Task<int> RunAsync(string[] args, CancellationToken ct = default)
    {
        var root = new RootCommand("Provision or check local CurrentUser DPAPI credentials without contacting AD.");
        root.Directives.Clear();
        var provision = new Command("provision");
        var check = new Command("check");
        var usernames = new Dictionary<Command, Option<string?>>();
        var profiles = new Dictionary<Command, Option<string>>();
        var pauses = new Dictionary<Command, Option<bool>>();
        foreach (var command in new[] { provision, check })
        {
            var username = new Option<string?>("--username") { Required = command == provision };
            var profile = new Option<string>("--profile") { DefaultValueFactory = _ => "ad" };
            profile.AcceptOnlyFromAmong("ad", "vpn");
            var wait = new Option<bool>("--pause");
            command.Options.Add(username); command.Options.Add(profile); command.Options.Add(wait);
            usernames[command] = username; profiles[command] = profile; pauses[command] = wait;
            root.Subcommands.Add(command);
        }
        var replace = new Option<bool>("--replace");
        var single = new Option<bool>("--single-entry");
        provision.Options.Add(replace); provision.Options.Add(single);
        var parsed = root.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null });
        if (parsed.Action is HelpAction)
            return await parsed.InvokeAsync(new InvocationConfiguration { Output = io.Output, Error = io.Error }, ct);
        var selected = parsed.CommandResult.Command;
        if (parsed.Errors.Count != 0 || !usernames.ContainsKey(selected))
        { io.Error.WriteLine("Invalid arguments. Use --help; passwords are accepted only in the local hidden prompt."); return 2; }
        try
        {
            if (!OperatingSystem.IsWindows()) return Error("windows_dpapi_required");
            string? username = parsed.GetValue(usernames[selected]);
            string profile = parsed.GetValue(profiles[selected])!;
            if (username is not null) AdSourceCredentials.ValidateUsername(username);
            if (selected == check)
            {
                var status = store.Status(username, profile: profile); Print(status);
                return Ready(status) && status["account_matches"]?.GetValue<bool>() != false ? 0 : 1;
            }
            bool overwrite = parsed.GetValue(replace);
            if (store.Status(profile: profile)["status"]!.GetValue<string>() != "missing" && !overwrite)
                return Error("credential_already_exists");
            if (!io.CanPromptPassword) return Error("interactive_console_required");
            io.Output.WriteLine($"SLI: save the {profile} profile password for this local Windows user.");
            io.Output.WriteLine($"Domain account: {username}");
            io.Output.WriteLine("No domain connection, collector start or service change will be performed.");
            string password = await io.ReadPasswordAsync("Password (hidden): ", ct);
            if (password.Length == 0) return Error("empty_password");
            string confirmation = parsed.GetValue(single) ? password : await io.ReadPasswordAsync("Repeat password (hidden): ", ct);
            byte[] left = Encoding.UTF8.GetBytes(password), right = Encoding.UTF8.GetBytes(confirmation);
            bool matched;
            try { matched = CryptographicOperations.FixedTimeEquals(left, right); }
            finally { CryptographicOperations.ZeroMemory(left); CryptographicOperations.ZeroMemory(right); }
            if (!matched) return Error("password_confirmation_mismatch");
            store.Store(username, password, replace: overwrite, profile: profile);
            password = confirmation = "";
            var result = store.Status(username, profile: profile); Print(result);
            return Ready(result) && result["account_matches"]?.GetValue<bool>() == true ? 0 : 1;
        }
        catch (AdCredentialStoreException e) { return Error(e.Message); }
        catch (Exception e) when (e is OperationCanceledException or EndOfStreamException) { return Error("cancelled"); }
        catch (InvalidOperationException) { return Error("secure_console_required"); }
        catch { return Error("credential_operation_failed"); }
        finally
        {
            if (parsed.GetValue(pauses[selected]) && io.CanPromptPassword)
                try { (pause ?? (() => { io.Output.Write("Press Enter to close. "); Console.ReadLine(); }))(); }
                catch { /* Retain the already determined outcome; never prompt for the secret again. */ }
        }
    }

    private static bool Ready(JsonObject result) => result["status"]?.GetValue<string>() == "ready";
    private int Error(string code) { Print(new() { ["status"] = "error", ["error_code"] = code }); return 1; }
    private void Print(JsonObject result)
    {
        string[] allowed = ["status", "dpapi_scope", "owner_matches", "account_matches", "error_code", "path", "stored", "replaced"];
        io.Output.WriteLine(new JsonObject(result.Where(p => allowed.Contains(p.Key)).Select(p => KeyValuePair.Create(p.Key, p.Value?.DeepClone()))).ToJsonString());
    }
}
