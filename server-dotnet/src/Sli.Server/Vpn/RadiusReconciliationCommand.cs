using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;

namespace Sli.Server.Vpn;

public static class RadiusReconciliationCommand
{
    internal static string OutputPath(string root, string path)
    {
        string allowed=Path.GetFullPath(Path.Combine(root,"artifacts","g11a3"))+Path.DirectorySeparatorChar;
        string output=Path.GetFullPath(path);
        if (!output.StartsWith(allowed,OperatingSystem.IsWindows()?StringComparison.OrdinalIgnoreCase:StringComparison.Ordinal))
            throw new RadiusReconciliationException("production_reconciliation_output_path_invalid");
        for (var parent=new DirectoryInfo(Path.GetDirectoryName(output)!);parent is not null;parent=parent.Parent)
            if (parent.Exists && parent.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new RadiusReconciliationException("production_reconciliation_output_path_invalid");
        return output;
    }
    internal static void ExclusiveWrite(string path, JsonObject payload)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        try
        {
            using var file=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None);
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path,UnixFileMode.UserRead|UnixFileMode.UserWrite);
            file.Write(JsonSerializer.SerializeToUtf8Bytes(payload,new JsonSerializerOptions { WriteIndented=true }));
            file.Flush(flushToDisk:true);
            Sli.Server.Agents.Radius.RadiusEvidenceStore.SyncDirectory(Path.GetDirectoryName(path)!);
        }
        catch (IOException) when(File.Exists(path))
        { throw new RadiusReconciliationException("production_reconciliation_output_already_exists"); }
    }
    internal static string PrepareOutput(string root, string path, JsonObject plan)
    {
        path=OutputPath(root,path); string reservation=Guid.NewGuid().ToString("N");
        ExclusiveWrite(path,new JsonObject { ["status"]="apply_started",["reservation_id"]=reservation,
            ["plan_sha256"]=RadiusReconciliationControl.Digest(plan),["mutation_state"]="not_started_or_unknown",["production_database_changed"]="unknown" });
        return reservation;
    }
    internal static void FinalizeOutput(string path, JsonObject payload, string reservation)
    {
        JsonObject reserved;
        if (!File.Exists(path)) throw new RadiusReconciliationException("production_reconciliation_apply_evidence_missing");
        try { reserved=JsonNode.Parse(File.ReadAllBytes(path))!.AsObject(); }
        catch (Exception e) when(e is IOException or JsonException or InvalidOperationException or NullReferenceException)
        { throw new RadiusReconciliationException("production_reconciliation_apply_evidence_invalid"); }
        if (RadiusReconciliationControl.Text(reserved,"status")!="apply_started" || RadiusReconciliationControl.Text(reserved,"reservation_id")!=reservation)
            throw new RadiusReconciliationException("production_reconciliation_apply_evidence_not_reserved");
        var finalized=(JsonObject)payload.DeepClone();finalized["plan_sha256"]=reserved["plan_sha256"]!.DeepClone();finalized["reservation_id"]=reservation;
        string temp=Path.Combine(Path.GetDirectoryName(path)!,"."+Path.GetFileName(path)+"."+reservation+".tmp");
        ExclusiveWrite(temp,finalized);
        File.Move(temp,path,true);
        Sli.Server.Agents.Radius.RadiusEvidenceStore.SyncDirectory(Path.GetDirectoryName(path)!);
    }
    internal static Dictionary<string,string> Parse(string[] args)
    {
        var options=new Dictionary<string,string>(StringComparer.Ordinal);
        string[] allowed=["--action","--plan","--output","--disposable-acceptance","--confirmation","--root","--evidence-root"];
        for(int i=0;i<args.Length;i+=2)
            if (i+1==args.Length || !allowed.Contains(args[i]) || !options.TryAdd(args[i],args[i+1]))
                throw new RadiusReconciliationException("production_apply_without_plan_binding");
        string action=options.GetValueOrDefault("--action","plan");
        if (action is not ("plan" or "apply") || (action=="apply" &&
            (options.GetValueOrDefault("--confirmation")!=RadiusReconciliationControl.Confirmation || !options.ContainsKey("--plan") || !options.ContainsKey("--output"))))
            throw new RadiusReconciliationException("production_apply_without_plan_binding");
        return options;
    }
    public static async Task<int> RunAsync(string[] args)
    {
        try
        {
            var options=Parse(args); string root=Path.GetFullPath(options.GetValueOrDefault("--root",Environment.CurrentDirectory));
            string evidenceRoot=Path.GetFullPath(options.GetValueOrDefault("--evidence-root",OperatingSystem.IsWindows()?@"C:\SLI":"/var/lib/sli"));
            string acceptance=options.GetValueOrDefault("--disposable-acceptance",Path.Combine(root,"artifacts","stage10","evidence","radius-session-reconciliation80-disposable-pg18.json"));
            string action=options.GetValueOrDefault("--action","plan"); JsonObject? plan=null; string? reservation=null;
            if(action=="apply")
            {
                plan=JsonNode.Parse(File.ReadAllBytes(options["--plan"]))!.AsObject();
                reservation=PrepareOutput(root,options["--output"],plan);
            }
            JsonObject result;
            try
            {
                string dsn=Environment.GetEnvironmentVariable("SLI_RADIUS_RECONCILIATION_DSN") ?? throw new RadiusReconciliationException("protected_postgres_credentials_required");
                var builder=new NpgsqlConnectionStringBuilder(dsn) { CommandTimeout=0,Pooling=false,Multiplexing=false };
                await using var db=new NpgsqlConnection(builder.ConnectionString);await db.OpenAsync();
                await using var transaction=await db.BeginTransactionAsync();
                if(action=="plan") { await using var readOnly=new NpgsqlCommand("set transaction read only",db,transaction);await readOnly.ExecuteNonQueryAsync(); }
                async Task<List<JsonObject>> Query(string sql,object?[] values)
                {
                    await using var cmd=new NpgsqlCommand(sql,db,transaction) { CommandTimeout=0 };
                    foreach(var value in values) cmd.Parameters.Add(value is null
                        ? new NpgsqlParameter { NpgsqlDbType=NpgsqlTypes.NpgsqlDbType.Unknown,Value=DBNull.Value }
                        : PostgresVpnStore.Parameter(value));
                    var rows=new List<JsonObject>();await using var reader=await cmd.ExecuteReaderAsync();
                    do
                    {
                        while(await reader.ReadAsync())
                        {
                            var row=new JsonObject();for(int i=0;i<reader.FieldCount;i++) row[reader.GetName(i)]=reader.IsDBNull(i)?null:JsonSerializer.SerializeToNode(reader.GetValue(i));rows.Add(row);
                        }
                    } while(await reader.NextResultAsync());
                    return rows;
                }
                var control=new RadiusReconciliationControl(Query,root,evidenceRoot,message=>Console.Error.WriteLine(message));
                result=action=="apply"?await control.ApplyAsync(plan!,acceptance):await control.BuildPlanAsync(acceptance);
                if(action=="apply") await transaction.CommitAsync(); else await transaction.RollbackAsync();
            }
            catch(Exception e) when(reservation is not null)
            {
                FinalizeOutput(options["--output"],new JsonObject { ["status"]="failed",["failure_code"]=e is RadiusReconciliationException?e.Message:"production_reconciliation_apply_failed",
                    ["mutation_state"]="unknown_after_apply_exception",["production_database_changed"]="unknown",["source_contacted"]=false,
                    ["queue_or_lease_changed"]=false,["runtime_enabled"]=false,["autostart_enabled"]=false },reservation);
                throw;
            }
            if(reservation is not null) FinalizeOutput(options["--output"],result,reservation);
            else if(options.TryGetValue("--output",out var output)) ExclusiveWrite(OutputPath(root,output),result);
            Console.WriteLine(result.ToJsonString());return 0;
        }
        catch(Exception e)
        {
            Console.Error.WriteLine(e is RadiusReconciliationException?e.Message:"production_reconciliation_control_failed");return 1;
        }
    }
}
