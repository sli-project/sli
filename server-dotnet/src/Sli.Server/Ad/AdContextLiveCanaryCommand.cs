using System.CommandLine;
using Sli.Agent.Protocol;

namespace Sli.Server.Ad;

public static class AdContextLiveCanaryCommand
{
    public static Task<int> RunAsync(string[] args) => RunAsync(args, Console.Out, Console.Error);
    internal static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter error, CancellationToken ct = default)
    {
        var root = new RootCommand("Validate or execute one owner-approved read-only AD Context collection.");
        Option<string> Required(string name) { var option = new Option<string>("--" + name) { Required = true }; root.Options.Add(option); return option; }
        Option<T> Optional<T>(string name, T fallback) { var option = new Option<T>("--" + name) { DefaultValueFactory = _ => fallback }; root.Options.Add(option); return option; }
        var server = Required("directory-server"); var domain = Required("domain"); var search = Required("search-base");
        var account = Required("expected-account"); var before = Required("not-before-utc"); var after = Required("not-after-utc");
        var sections = Optional<string[]>("section", []); var groups = Optional<string[]>("group-sid", []); var vpn = Optional<string[]>("vpn-group-sid", []);
        var timeout = Optional("timeout-seconds", 120); var records = Optional("max-records", 2000); var bytes = Optional("max-bundle-bytes", 2 * 1024 * 1024);
        var accounts = Optional("max-directory-accounts", 2000); var users = Optional<int?>("max-directory-users", null); var computers = Optional<int?>("max-directory-computers", null);
        var members = Optional("max-vpn-members", 500); var gpos = Optional("max-gpos", 72);
        var project = Optional("project-root", Directory.GetCurrentDirectory()); var destination = Optional<string?>("output-root", null);
        var execute = Optional("execute", false); var validateOnly = Optional("validate-only", false);
        var confirmation = Optional("confirmation", ""); var approval = Optional("approved-request-sha256", "");
        root.SetAction(async (parse, token) =>
        {
            try
            {
                AdContextCommand.Require(!(parse.GetValue(execute) && parse.GetValue(validateOnly)), "execute and validate-only are mutually exclusive");
                var request = new AdContextCanaryRequest {
                    DirectoryServer = parse.GetValue(server)!, Domain = parse.GetValue(domain)!, SearchBase = parse.GetValue(search)!,
                    ExpectedAccount = parse.GetValue(account)!, NotBeforeUtc = parse.GetValue(before)!, NotAfterUtc = parse.GetValue(after)!,
                    Sections = parse.GetValue(sections)!, PrivilegedGroups = parse.GetValue(groups)!, VpnGroups = parse.GetValue(vpn)!,
                    TimeoutSeconds = parse.GetValue(timeout), MaxRecords = parse.GetValue(records), MaxBundleBytes = parse.GetValue(bytes),
                    MaxDirectoryAccounts = parse.GetValue(accounts), MaxDirectoryUsers = parse.GetValue(users), MaxDirectoryComputers = parse.GetValue(computers),
                    MaxVpnMembers = parse.GetValue(members), MaxGpos = parse.GetValue(gpos), OutputRoot = parse.GetValue(destination),
                    Execute = parse.GetValue(execute), Confirmation = parse.GetValue(confirmation)!, ApprovedRequestSha256 = parse.GetValue(approval)!
                };
                var result = await new AdContextLiveCanary(Path.GetFullPath(parse.GetValue(project)!)).RunAsync(request, token);
                await output.WriteLineAsync(CanonicalJson.Serialize(result, false));
                return 0;
            }
            catch (Exception e) when (e is ArgumentException or UnauthorizedAccessException or InvalidOperationException or FormatException or PlatformNotSupportedException)
            {
                await error.WriteLineAsync(CanonicalJson.Serialize(new System.Text.Json.Nodes.JsonObject { ["status"] = "failed", ["error_type"] = e.GetType().Name, ["error"] = e.Message }, false));
                return 1;
            }
        });
        return await root.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null }).InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false, Output = output, Error = error }, ct);
    }
}
