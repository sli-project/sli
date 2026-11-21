using System.Globalization;
using System.Text;
using Npgsql;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Hosting;

namespace Sli.Server.Agents.Consumer;

// A private source worker pool; never share sessions with the application/owner login.
public sealed class DirectAdDcRuntime : IAsyncDisposable
{
    internal NpgsqlDataSource Worker { get; }
    internal string CatalogPath { get; }
    internal DirectAdDcRuntime(NpgsqlDataSource worker,string catalogPath) { Worker=worker; CatalogPath=catalogPath; }
    public static DirectAdDcRuntime? TryCreate(IConfiguration config) => TryCreate(config, out _);

    internal static DirectAdDcRuntime? TryCreate(IConfiguration config, out string? issue)
    {
        string? catalog = config["Sli:EventCatalogPath"];
        if (string.IsNullOrWhiteSpace(catalog) || !Path.IsPathFullyQualified(catalog) || !File.Exists(catalog))
        {
            issue = AdDcProjectionFailure.CatalogUnavailable;
            return null;
        }

        string? GetSetting(string name) => config[name] is { } value && name.EndsWith("_FILE", StringComparison.Ordinal)
            ? InstalledConfiguration.CredentialPath(config, value, name) : config[name];
        var runtime = TryCreate(GetSetting, ReadBounded, catalog);
        issue = runtime is null ? AdDcProjectionFailure.ConnectionUnconfigured : null;
        return runtime;
    }
    internal static DirectAdDcRuntime? TryCreate(Func<string,string?> get,Func<string,byte[]> read,string? catalog)
    {
        if (string.IsNullOrWhiteSpace(catalog) || !Path.IsPathFullyQualified(catalog)) return null;
        if (!GpoWorkerConfiguration.TryCreateNamed(get,read,"ADLOG_STORAGE_V2_WORKER_DSN","ADLOG_STORAGE_V2_WORKER_PASSWORD","adlog_storage_import",0,out var dsn)) return null;
        try {
            int ReadInt(string name,int fallback) => int.TryParse(get(name),NumberStyles.Integer,CultureInfo.InvariantCulture,out int value) ? value : fallback;
            int connect=Math.Max(1,ReadInt("ADLOG_PG_CONNECT_TIMEOUT_SECONDS",3));
            // Each storage operation still enters and checks SET LOCAL ROLE. Reset all
            // session state on return; physical opens retain the admission check below.
            var b=new NpgsqlConnectionStringBuilder(dsn) { Pooling=true, NoResetOnClose=false, Multiplexing=false, Timeout=connect, CommandTimeout=0 };
            b.Options=(b.Options ?? "").Trim()+" -c statement_timeout=0 -c lock_timeout=0";
            var source = new NpgsqlDataSourceBuilder(b.ConnectionString);
            source.UsePhysicalConnectionInitializer(_ => throw new NotSupportedException("storage_worker_requires_async_open"), InitializeWorkerAsync);
            return new DirectAdDcRuntime(source.Build(),catalog);
        } catch(Exception e) when(e is ArgumentException or FormatException or OverflowException) { return null; }
    }
    internal static async Task InitializeWorkerAsync(NpgsqlConnection db)
    {
        // Activate and verify the session role before exposing any worker connection.
        // SET ROLE survives the commit and later rollbacks, unlike SET LOCAL ROLE.
        await using var tx = await db.BeginTransactionAsync();
        await using (var role = new NpgsqlCommand("set role adlog_storage_worker", db, tx) { CommandTimeout = 0 })
            await role.ExecuteNonQueryAsync();
        await using (var check = new NpgsqlCommand("select current_user as role", db, tx) { CommandTimeout = 0 })
            if ((string?)await check.ExecuteScalarAsync() != "adlog_storage_worker")
                throw new InvalidOperationException("storage_v2_worker_role_required");
        await tx.CommitAsync();
    }
    private static byte[] ReadBounded(string path)
    {
        using var stream=File.OpenRead(path);byte[] b=new byte[65537];int count=0,n;
        while(count<b.Length && (n=stream.Read(b,count,b.Length-count))!=0)count+=n;
        if(count>65536)throw new ArgumentException();return b[..count];
    }
    public ValueTask DisposeAsync()=>Worker.DisposeAsync();
}
