using Npgsql;

namespace Sli.Server.Agents.Radius;

// Select the source from the validated server-owned route snapshot.
public sealed record RadiusWorkerConfiguration(bool Enabled, string? WorkerDsn, RadiusImportBinding? Binding)
{
    public override string ToString()=>nameof(RadiusWorkerConfiguration);
    public static RadiusWorkerConfiguration FromEnvironment()
    {
        string[] keys=["SLI_NPS_AGENT_IMPORT_ENABLED","SLI_NPS_AGENT_WORKER_DSN","SLI_NPS_AGENT_WORKER_DSN_FILE","SLI_NPS_AGENT_WORKER_PASSWORD","SLI_NPS_AGENT_WORKER_PASSWORD_FILE","SLI_PLUGIN_RUNTIME_DIR","SLI_PLUGIN_LOCK_DIR","ADLOG_RADIUS_COLLECTION_ROUTES_PATH","ADLOG_RADIUS_SOURCE_NAME","ADLOG_RADIUS_SOURCE_INSTANCE_ID","ADLOG_RADIUS_OWNER_CONFIRMED_IP","ADLOG_RADIUS_ACCOUNTING_SHARE_UNC","ADLOG_DATA_DIR","SLI_DATA_DIR"];
        return Parse(keys.Select(key=>(Key:key,Value:Environment.GetEnvironmentVariable(key))).Where(item=>item.Value is not null).ToDictionary(item=>item.Key,item=>item.Value));
    }
    private static string RepositoryRoot()
    {
        foreach(string start in new[]{Environment.CurrentDirectory,AppContext.BaseDirectory})
            for(var current=new DirectoryInfo(Path.GetFullPath(start));current is not null;current=current.Parent)
                if(File.Exists(Path.Combine(current.FullName,"config","stage10_radius_collection_routes_v1.json"))) return current.FullName;
        return Path.GetFullPath(Environment.CurrentDirectory);
    }
    public static RadiusWorkerConfiguration Parse(IReadOnlyDictionary<string,string?> values)
    {
        string? Get(string key) => values.TryGetValue(key,out var value) ? value : null;
        string? Secret(string key)
        {
            string? value=Get(key), path=Get(key+"_FILE");
            if(path is null) return string.IsNullOrEmpty(value)?null:value;
            if(!string.IsNullOrEmpty(value) || path.Length==0) throw new ArgumentException("agent_nps_import_config_invalid");
            try
            {
                using var input=File.OpenRead(path);
                byte[] buffer=new byte[65537];int count=0,read;
                while(count<buffer.Length && (read=input.Read(buffer,count,buffer.Length-count))>0) count+=read;
                if(count>65536) throw new ArgumentException();
                value=new System.Text.UTF8Encoding(false,true).GetString(buffer,0,count).TrimEnd('\r','\n');
                if(value.Length==0 || value.Contains('\0')) throw new ArgumentException();
                return value;
            }
            catch(Exception e) when(e is IOException or UnauthorizedAccessException or ArgumentException)
            { throw new ArgumentException("agent_nps_import_config_invalid"); }
        }
        string enabled=Get("SLI_NPS_AGENT_IMPORT_ENABLED") ?? "0";
        if(enabled=="0") return new(false,null,null);
        if(enabled!="1") throw new ArgumentException("agent_nps_import_config_invalid");
        string? dsn=Secret("SLI_NPS_AGENT_WORKER_DSN"),password=Secret("SLI_NPS_AGENT_WORKER_PASSWORD");
        if(string.IsNullOrWhiteSpace(dsn)) throw new ArgumentException("agent_nps_import_config_invalid");
        string repository=RepositoryRoot();
        string? configured=Get("ADLOG_DATA_DIR"),fallback=Get("SLI_DATA_DIR");
        configured=configured is null?null:Sli.Server.Compatibility.PythonText.Strip(configured);
        fallback=fallback is null?null:Sli.Server.Compatibility.PythonText.Strip(fallback);
        string defaultData=Path.Combine(Directory.GetParent(repository)?.FullName ?? repository,"sli_data");
        if(!Directory.Exists(defaultData)) defaultData=Path.Combine(repository,"data");
        string rawRoot=!string.IsNullOrEmpty(configured)?configured:!string.IsNullOrEmpty(fallback)?fallback:defaultData;
        if(rawRoot=="~" || rawRoot.StartsWith("~/",StringComparison.Ordinal) || rawRoot.StartsWith("~\\",StringComparison.Ordinal))
            rawRoot=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),rawRoot.Length==1?"":rawRoot[2..]);
        string root=Path.IsPathFullyQualified(rawRoot)?rawRoot:Path.GetFullPath(rawRoot,repository);
        string source;
        try { source=RadiusCollectionRoute.Load(Path.Combine(repository,"config"),values)["source_name"]!.GetValue<string>(); }
        catch(Exception e) when(e is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or ArgumentException)
        { throw new ArgumentException("agent_nps_import_config_invalid"); }
        var builder=new NpgsqlConnectionStringBuilder();
        Dictionary<string,string>? parts=null;
        if(dsn.StartsWith("postgresql://",StringComparison.Ordinal) || dsn.StartsWith("postgres://",StringComparison.Ordinal))
        {
            if(System.Text.RegularExpressions.Regex.IsMatch(dsn,@"%(?![0-9A-Fa-f]{2})") || !Uri.TryCreate(dsn,UriKind.Absolute,out var uri) || uri.Fragment.Length>0 || uri.Host.Contains(',')) throw new ArgumentException("agent_nps_import_config_invalid");
            parts=new(StringComparer.Ordinal);
            string[] user=uri.UserInfo.Split(':',2);
            if(user[0].Length>0) parts["user"]=Uri.UnescapeDataString(user[0]);
            if(user.Length==2) parts["password"]=Uri.UnescapeDataString(user[1]);
            if(uri.Host.Length>0) parts["host"]=uri.Host;
            if(!uri.IsDefaultPort && uri.Port>0) parts["port"]=uri.Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
            string database=uri.AbsolutePath.TrimStart('/');
            if(database.Contains('/')) throw new ArgumentException("agent_nps_import_config_invalid");
            if(database.Length>0) parts["dbname"]=Uri.UnescapeDataString(database);
            foreach(string pair in uri.Query.TrimStart('?').Split('&',StringSplitOptions.RemoveEmptyEntries))
            {
                var kv=pair.Split('=',2);if(kv.Length!=2) throw new ArgumentException("agent_nps_import_config_invalid");
                parts[Uri.UnescapeDataString(kv[0])]=Uri.UnescapeDataString(kv[1]);
            }
        }
        else if(dsn.Contains(';')) builder.ConnectionString=dsn;
        else parts=Sli.Server.Compatibility.LibpqKeywordDsn.Parse(dsn);
        if(parts is not null) foreach(var (key,value) in parts)
            switch(key)
            {
                case "host":builder.Host=value;break;
                case "port":builder.Port=int.Parse(value,System.Globalization.CultureInfo.InvariantCulture);break;
                case "dbname":builder.Database=value;break;
                case "user":builder.Username=value;break;
                case "password":builder.Password=value;break;
                case "connect_timeout":builder.Timeout=int.Parse(value,System.Globalization.CultureInfo.InvariantCulture);break;
                case "application_name":builder.ApplicationName=value;break;
                case "sslmode":builder.SslMode=value switch { "disable"=>SslMode.Disable,"prefer"=>SslMode.Prefer,"require"=>SslMode.Require,"verify-ca"=>SslMode.VerifyCA,"verify-full"=>SslMode.VerifyFull,_=>throw new ArgumentException("agent_nps_import_config_invalid") };break;
                default:throw new ArgumentException("agent_nps_import_config_invalid");
            }
        if(string.IsNullOrWhiteSpace(builder.Host) || string.IsNullOrWhiteSpace(builder.Username) || string.IsNullOrWhiteSpace(builder.Database)) throw new ArgumentException("agent_nps_import_config_invalid");
        if(builder.Multiplexing) throw new ArgumentException("agent_nps_import_config_invalid");
        if(password is not null)
        {
            if(!string.IsNullOrEmpty(builder.Password)) throw new ArgumentException("agent_nps_import_config_invalid");
            builder.Password=password;
        }
        builder.Multiplexing=false;builder.Pooling=false;
        return new(true,builder.ConnectionString,new(root,source.Trim()));
    }
}

public static class RadiusWorkerCommand
{
    public static async Task<int> RunAsync(string[] args,CancellationToken cancellationToken=default)
    {
        if(args.Length!=1 || args[0]!="--once") { Console.Error.WriteLine("agent_nps_import_config_invalid"); return 1; }
        try
        {
            var config=RadiusWorkerConfiguration.FromEnvironment();
            if(config.Enabled) await RadiusAccountingImporter.RunOnceFromDsnAsync(config.WorkerDsn!,config.Binding!,16,cancellationToken);
            return 0;
        }
        catch(OperationCanceledException) when(cancellationToken.IsCancellationRequested) { throw; }
        catch(Exception) { Console.Error.WriteLine("agent_radius_import_failed"); return 1; }
    }
}
