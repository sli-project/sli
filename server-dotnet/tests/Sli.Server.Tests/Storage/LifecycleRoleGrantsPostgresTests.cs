using Npgsql;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Replaces Installed_roles_copy_without_delete_credentials_and_purge_only_verified_unheld_rows
// (its AssertPrivileges part): the rights boundary of the storage lifecycle roles.
public sealed class LifecycleRoleGrantsPostgresTests
{
    // DELETE the remaining lifecycle cycle needs: InboxRetention, ReceiptRetention,
    // SemanticOutboxRetention, FileAuditRetention (access_snapshots) and
    // FileAuditObservationRetention (observations).
    static readonly string[] Needed = [
        "public.sli_agent_packet_inbox", "public.sli_agent_receipts", "public.semantic_processing_outbox",
        "sli_plugin_file_audit.access_snapshots", "sli_plugin_file_audit.observations" ];

    static async Task<object?> Scalar(NpgsqlConnection db, string sql, CancellationToken ct)
    { await using var c = new NpgsqlCommand(sql, db); return await c.ExecuteScalarAsync(ct); }

    [Fact]
    public async Task Lifecycle_roles_cannot_alter_schema_and_only_the_delete_role_deletes_only_what_the_cycle_needs()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        Assert.Equal(false, await Scalar(admin, """
            select exists(select 1 from pg_roles where rolname in ('sli_storage_lifecycle_login','sli_storage_lifecycle_delete_login',
              'adlog_storage_lifecycle_worker','adlog_storage_lifecycle_delete','adlog_storage_lifecycle_guard')
              and (rolsuper or rolcreatedb or rolcreaterole or rolreplication or rolbypassrls or rolinherit))
            """, ct));
        foreach (string role in new[] { "adlog_storage_lifecycle_worker", "adlog_storage_lifecycle_delete" })
            Assert.Equal(false, await Scalar(admin, $"""
                select has_schema_privilege('{role}','public','CREATE') or has_schema_privilege('{role}','sli_plugin_file_audit','CREATE')
                  or pg_has_role('{role}','adlog_storage_owner','MEMBER') or pg_has_role('{role}','adlog_storage_worker','MEMBER')
                  or pg_has_role('{role}','adlog_storage_lifecycle_guard','MEMBER')
                  or exists(select 1 from pg_class c join pg_namespace n on n.oid=c.relnamespace
                     where n.nspname in ('public','sli_plugin_file_audit') and c.relkind in ('r','p')
                     and has_table_privilege('{role}',c.oid,'TRUNCATE,TRIGGER,REFERENCES'))
                """, ct));
        Assert.Equal(false, await Scalar(admin, """
            select exists(select 1 from pg_class c join pg_namespace n on n.oid=c.relnamespace
              where n.nspname in ('public','sli_plugin_file_audit') and c.relkind in ('r','p')
                and has_table_privilege('adlog_storage_lifecycle_worker',c.oid,'DELETE'))
              or pg_has_role('sli_storage_lifecycle_login','adlog_storage_lifecycle_delete','MEMBER')
            """, ct));
        var granted = new List<string>();
        await using (var cmd = new NpgsqlCommand("""
            select n.nspname||'.'||c.relname from pg_class c join pg_namespace n on n.oid=c.relnamespace
            where n.nspname in ('public','sli_plugin_file_audit') and c.relkind in ('r','p')
              and has_table_privilege('adlog_storage_lifecycle_delete',c.oid,'DELETE') order by 1
            """, admin))
        await using (var rd = await cmd.ExecuteReaderAsync(ct)) while (await rd.ReadAsync(ct)) granted.Add(rd.GetString(0));
        Assert.Empty(granted.Except(Needed));
    }
}
