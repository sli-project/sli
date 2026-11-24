using Sli.Agent.Core;
using Npgsql;

namespace Sli.Server.Agents.Radius;

// The same root-managed systemd route credential is delivered to API and
// post-collection. Only the latter receives credentials for the worker role.
internal sealed record RadiusAccountingMode(string SourceName, string SourceId, string Subscription, string TransportBinding,
    string EndpointIdentity,string TimezoneId,int UtcOffsetMinutes)
{
    internal const string EnabledSetting = "SLI_RADIUS_ACCOUNTING_IMPORT_ENABLED";
    internal const string RouteCredential = "radius-agent-route";
    internal const string ConfigRootSetting = "SLI_RADIUS_ACCOUNTING_CONFIG_ROOT";
    internal static readonly string[] Settings = [EnabledSetting,"CREDENTIALS_DIRECTORY",ConfigRootSetting];

    internal static RadiusAccountingMode? FromEnvironment() =>
        Load(Settings.ToDictionary(key => key,Environment.GetEnvironmentVariable));

    internal static RadiusAccountingMode? Effective()
    {
        try { return FromEnvironment(); }
        catch (Exception e) when (e is ArgumentException or IOException or UnauthorizedAccessException) { return null; }
    }

    internal async Task<bool> RegisteredAsync(NpgsqlConnection db,NpgsqlTransaction tx,bool active,CancellationToken ct)
    {
        await using var exists = new NpgsqlCommand("select to_regprocedure('public.radius_accounting_source_ready406(text,text,text,text,boolean)') is not null",db,tx);
        if (await exists.ExecuteScalarAsync(ct) is not true) return false;
        await using var command = new NpgsqlCommand("select public.radius_accounting_source_ready406(@source,@subscription,@binding,@endpoint,@active)",db,tx);
        command.Parameters.AddWithValue("source",SourceId);
        command.Parameters.AddWithValue("subscription",Subscription);
        command.Parameters.AddWithValue("binding",TransportBinding);
        command.Parameters.AddWithValue("endpoint",EndpointIdentity);
        command.Parameters.AddWithValue("active",active);
        return await command.ExecuteScalarAsync(ct) is true;
    }

    internal static RadiusAccountingMode? Load(IReadOnlyDictionary<string,string?> settings)
    {
        if (!settings.TryGetValue(EnabledSetting,out var enabled) || enabled != "1") return null;
        if (!settings.TryGetValue("CREDENTIALS_DIRECTORY",out var directory) || directory is null ||
            !Path.IsPathFullyQualified(directory))
            throw new ArgumentException("agent_radius_mode_invalid");
        var routePath = Path.Combine(directory,RouteCredential);
        var env = new Dictionary<string,string?> { ["ADLOG_RADIUS_COLLECTION_ROUTES_PATH"] = routePath };
        var info = new FileInfo(routePath);
        if (!info.Exists || info.Length is < 1 or > 65_536 ||
            info.Attributes.HasFlag(FileAttributes.ReparsePoint))
            throw new ArgumentException("agent_radius_mode_invalid");
        var root = settings.GetValueOrDefault(ConfigRootSetting) ?? Path.Combine(PostCollectionConfigRoot(),"config");
        if (!Path.IsPathFullyQualified(root)) throw new ArgumentException("agent_radius_mode_invalid");
        var route = RadiusCollectionRoute.Load(root,env);
        if (route["accounting_ready"]?.GetValue<bool>() != true)
            throw new ArgumentException("agent_radius_mode_invalid");
        var registration = RadiusSourceContracts.LoadRegistration(root,env);
        return new(route["source_name"]!.GetValue<string>(),route["source_instance_id"]!.GetValue<string>(),
            registration["subscription"]!["subscription_id"]!.GetValue<string>(),
            registration["stream"]!["transport_binding"]!.GetValue<string>(),
            registration["source"]!["endpoint_identity"]!.GetValue<string>(),
            route["timezone_id"]!.GetValue<string>(),route["utc_offset_minutes"]!.GetValue<int>());
    }

    private static string PostCollectionConfigRoot()
    {
        foreach (var start in new[] { Environment.CurrentDirectory,AppContext.BaseDirectory })
            for (var dir = new DirectoryInfo(start); dir is not null; dir = dir.Parent)
                if (File.Exists(Path.Combine(dir.FullName,"config","stage9_radius_registration_v1.json")))
                    return dir.FullName;
        throw new ArgumentException("agent_radius_mode_invalid");
    }

    internal bool Matches(NpsPolicy policy) =>
        policy.ModuleId == NpsPolicy.Accounting && policy.SourceId == SourceId &&
        policy.Text("subscription_id") == Subscription &&
        policy.Text("source_timezone_id") == TimezoneId &&
        policy.Value["source_utc_offset_minutes"]?.GetValue<int>() == UtcOffsetMinutes &&
        RadiusCursor.Parse(policy.Value["initial_cursor"]).TransportBinding == TransportBinding;
}
