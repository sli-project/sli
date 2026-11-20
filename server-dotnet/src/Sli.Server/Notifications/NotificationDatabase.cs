using Npgsql;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Infrastructure;
namespace Sli.Server.Notifications;
public sealed class NotificationDatabase : IPostgresConnectionFactory,IAsyncDisposable
{
    private readonly NpgsqlDataSource source;
    private NotificationDatabase(string dsn) => source=new NpgsqlDataSourceBuilder(dsn).Build();
    public static NotificationDatabase? TryCreate()
    {
        static byte[] Read(string p){using var f=File.OpenRead(p);var b=new byte[65537];int n=0,k;while(n<b.Length && (k=f.Read(b,n,b.Length-n))>0)n+=k;if(n>65536)throw new FormatException();return b[..n];}
        if(!GpoWorkerConfiguration.TryCreateNamed(Environment.GetEnvironmentVariable,Read,"ADLOG_PG_DSN","ADLOG_PG_PASSWORD","adlog_notification_worker",30,out var dsn))return null;
        try{return new(dsn!);}catch{return null;}
    }
    public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
    {
        var db=await source.OpenConnectionAsync(ct);
        try {
            await using(var role=new NpgsqlCommand("set role adlog_notification_worker",db))await role.ExecuteNonQueryAsync(ct);
            await using var check=new NpgsqlCommand("""
                with recursive granted_roles(role_oid,role_name) as (
                  select r.oid,r.rolname from pg_roles l join pg_auth_members m on m.member=l.oid join pg_roles r on r.oid=m.roleid where l.rolname=session_user
                  union select r.oid,r.rolname from granted_roles p join pg_auth_members m on m.member=p.role_oid join pg_roles r on r.oid=m.roleid)
                select current_user='adlog_notification_worker'
                  and not(a.rolsuper or a.rolcreatedb or a.rolcreaterole or a.rolreplication or a.rolbypassrls or l.rolsuper or l.rolcreatedb or l.rolcreaterole or l.rolreplication or l.rolbypassrls)
                  and not exists(select 1 from granted_roles where role_name<>'adlog_notification_worker')
                  and not exists(select 1 from pg_class where relowner=l.oid)
                  and not exists(select 1 from pg_namespace where nspowner=l.oid)
                  and not exists(select 1 from pg_class c cross join lateral aclexplode(c.relacl) acl where acl.grantee=l.oid)
                  and not exists(select 1 from pg_namespace n cross join lateral aclexplode(n.nspacl) acl where acl.grantee=l.oid)
                  and not exists(select 1 from pg_proc p cross join lateral aclexplode(p.proacl) acl where acl.grantee=l.oid)
                from pg_roles a cross join pg_roles l where a.rolname=current_user and l.rolname=session_user
                """,db);
            if(await check.ExecuteScalarAsync(ct) is not true)throw new InvalidOperationException("notification_worker_privilege_invalid");
            return db;
        }catch{await db.DisposeAsync();throw;}
    }
    public ValueTask DisposeAsync()=>source.DisposeAsync();
}
