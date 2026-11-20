using System.CommandLine;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Consumer;
using Sli.Server.Legacy;

namespace Sli.Server.Sources;

public static class CollectionBlockCommand
{
    public const string Confirmation = "SLI-RECHECK-WINDOWS-CONTEXT";
    public static Task<int> RunAsync(string[] args) => RunCoreAsync(args,async ct => {
        var builder = Host.CreateApplicationBuilder(Array.Empty<string>());
        if (!AgentImportCommand.TryCreateFactory(builder.Configuration,out var connections)) throw new InvalidOperationException("server_configuration_invalid");
        return await CollectionRuntime.CreateAsync(connections!,new LegacySettings(builder.Configuration),ct);
    },Console.Out,CancellationToken.None);
    internal static async Task<int> RunCoreAsync(string[] args,Func<CancellationToken,Task<WindowsCollection>> create,TextWriter output,CancellationToken ct)
    {
        var server = new Option<string>("--probe-server"); var mode = new Option<string?>("--ad-source-credential-mode");
        var confirm = new Option<string?>("--confirm");
        var root = new RootCommand("Verify the collection owner and Event Log access before clearing a durable block.");
        root.Options.Add(server);root.Options.Add(mode);root.Options.Add(confirm);
        root.SetAction(async (parse,token) => {
            JsonObject result;
            if (string.IsNullOrEmpty(parse.GetValue(server)) || parse.GetValue(confirm) != Confirmation)
                result = new() { ["status"]="failed", ["failure_code"]="ad_source_recovery_confirmation_required" };
            else {
                try {
                    // Reject unknown mode before opening a store, querying PG or printing raw input.
                    string? explicitMode = parse.GetValue(mode);
                    if (explicitMode is not null) AdSourceAuth.ValidateMode(explicitMode);
                    var collection = await create(token);
                    result = await collection.RecoverAsync(parse.GetValue(server)!,explicitMode,Environment.UserName,token);
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                catch (CollectionSourceException e) { result = new() { ["status"]="failed", ["failure_code"]=e.Code }; }
                catch { result = new() { ["status"]="failed", ["failure_code"]="collection_recovery_unavailable" }; }
            }
            await output.WriteLineAsync(result.ToJsonString());
            return result["status"]!.GetValue<string>() == "ok" ? 0 : 2;
        });
        var parsed = root.Parse(args,new ParserConfiguration { ResponseFileTokenReplacer=null });
        // System.CommandLine diagnostics include the supplied value: do not emit them.
        if (parsed.Errors.Count > 0) { await output.WriteLineAsync("{\"status\":\"failed\",\"failure_code\":\"collection_recovery_arguments_invalid\"}");return 2; }
        return await parsed.InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler=false },ct);
    }
}
