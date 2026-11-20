using System.Globalization;
using System.Text;
using Npgsql;
using Sli.Server.Agents.SnapshotPublication;

namespace Sli.Server.Entities.State;

// Source worker DSN/password profile; no administrator fallback or pooling.
public sealed class EntityStateWorkerRuntime : IAsyncDisposable
{
    internal NpgsqlDataSource DataSource {get;}
    private EntityStateWorkerRuntime(NpgsqlDataSource source)=>DataSource=source;
    public static EntityStateWorkerRuntime? TryCreate()=>TryCreate(Environment.GetEnvironmentVariable,ReadBounded);
    internal static EntityStateWorkerRuntime? TryCreate(Func<string,string?> get,Func<string,byte[]> read)
    {
        if(!GpoWorkerConfiguration.TryCreateNamed(get,read,"ADLOG_STORAGE_V2_WORKER_DSN","ADLOG_STORAGE_V2_WORKER_PASSWORD","adlog_entity_state_projector",900,out var dsn))return null;
        try {
            int ReadInt(string key,int fallback)=>int.TryParse(get(key),NumberStyles.Integer,CultureInfo.InvariantCulture,out int value)?value:fallback;
            int connect=Math.Max(1,ReadInt("ADLOG_PG_CONNECT_TIMEOUT_SECONDS",3));
            int statement=Math.Max(1000,ReadInt("ADLOG_PG_STATEMENT_TIMEOUT_MS",900000));
            int locked=Math.Max(100,Math.Min(ReadInt("ADLOG_PG_LOCK_TIMEOUT_MS",3000),statement));
            var builder=new NpgsqlConnectionStringBuilder(dsn) {Pooling=false,Multiplexing=false,Timeout=connect,CommandTimeout=checked((statement+999)/1000)};
            builder.Options=(builder.Options??"").Trim()+$" -c statement_timeout={statement} -c lock_timeout={locked}";
            return new(new NpgsqlDataSourceBuilder(builder.ConnectionString).Build());
        } catch(Exception e) when(e is ArgumentException or FormatException or OverflowException){return null;}
    }
    private static byte[] ReadBounded(string path)
    {
        using var file=File.OpenRead(path);byte[] bytes=new byte[65537];int count=0,n;
        while(count<bytes.Length && (n=file.Read(bytes,count,bytes.Length-count))!=0)count+=n;
        if(count>65536)throw new ArgumentException();return bytes[..count];
    }
    public ValueTask DisposeAsync()=>DataSource.DisposeAsync();
}
