using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;

namespace Sli.Server.Access;

public interface IAccessFactsRepository
{
    Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct);
    Task<AccessFacts> LoadAsync(Principal principal, bool includeReadProjection, CancellationToken ct) => LoadAsync(principal, ct);
}

public sealed class AccessFactsRepository(IPostgresConnectionFactory connections, SessionAccessFactsCache? sessionCache = null, IHttpContextAccessor? http = null) : IAccessFactsRepository
{
    private readonly Dictionary<Principal, Task<AccessFacts>> requestFacts = new();
    public async Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct)
        => await LoadAsync(principal, false, ct);

    public async Task<AccessFacts> LoadAsync(Principal principal, bool includeReadProjection, CancellationToken ct)
    {
        if (sessionCache is not null && http?.HttpContext is {} context && principal.Type == "session")
        {
            if (!requestFacts.TryGetValue(principal, out var task))
            {
                task = sessionCache.LoadAsync(principal, PrincipalAuthenticator.SessionTokenFromCookie(context.Request.Headers.Cookie.ToString()), () => LoadCoreAsync(principal, true, ct), ct);
                requestFacts.Add(principal, task);
            }
            return await task;
        }
        return await LoadCoreAsync(principal, includeReadProjection, ct);
    }
    private async Task<AccessFacts> LoadCoreAsync(Principal principal, bool includeReadProjection, CancellationToken ct)
    {
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using (var readOnly = new NpgsqlCommand("set transaction read only", connection, transaction))
            await readOnly.ExecuteNonQueryAsync(ct);
        // Python evaluates one UTC time before its fact queries, rather than per assignment.
        var now = DateTime.UtcNow;
        var userId = principal.UserId;
        var role = principal.RestrictedReportKey ? "report_reader" : principal.Role;
        var groups = new List<long>();
        var memberships = new List<JsonElement>();
        async Task<List<JsonElement>> Read(string sql, long[]? packageIds = null)
        {
            await using var command = new NpgsqlCommand("select to_jsonb(f) from (" + sql + ") f", connection, transaction);
            command.Parameters.AddWithValue("user", NpgsqlDbType.Bigint, (object?)userId ?? DBNull.Value);
            command.Parameters.AddWithValue("role", NpgsqlDbType.Text, role);
            command.Parameters.AddWithValue("now", NpgsqlDbType.TimestampTz, now);
            command.Parameters.AddWithValue("groups", NpgsqlDbType.Array | NpgsqlDbType.Bigint, groups.ToArray());
            command.Parameters.AddWithValue("packages", NpgsqlDbType.Array | NpgsqlDbType.Bigint, packageIds ?? []);
            var rows = new List<JsonElement>();
            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                using var json = JsonDocument.Parse(reader.GetString(0));
                rows.Add(json.RootElement.Clone());
            }
            return rows;
        }
        bool owner = false;
        if (userId.HasValue && !principal.RestrictedReportKey)
        {
            var owners = await Read("select exists(select 1 from access_platform_owners where user_id=@user) as is_owner");
            owner = owners[0].Get("is_owner").GetBoolean();
            memberships = await Read("""
                select g.id,g.group_key,g.name,m.valid_from,m.valid_until,m.source from access_group_members m join access_groups g on g.id=m.group_id
                where m.user_id=@user and g.is_active=true
                  and (m.valid_from is null or m.valid_from<=@now)
                  and (m.valid_until is null or m.valid_until>@now) order by g.group_key
                """);
            groups.AddRange(memberships.Select(row => row.Get("id").GetInt64()));
        }
        var packages = await Read("""
            select p.id,p.package_key,p.name,'role'::text as source_kind,@role::text as source_key,'allow'::text as effect,
              null::timestamptz as valid_from,null::timestamptz as valid_until
            from access_role_packages rp join access_packages p on p.id=rp.package_id
            where rp.coarse_role=@role order by p.package_key
            """);
        if (userId.HasValue && !principal.RestrictedReportKey)
            packages.AddRange(await Read("""
                select p.id,p.package_key,p.name,sp.source_type as source_kind,
                  (sp.subject_type||':'||sp.subject_id::text) as source_key,sp.effect,sp.valid_from,sp.valid_until
                from access_subject_packages sp join access_packages p on p.id=sp.package_id
                where ((sp.subject_type='user' and sp.subject_id=@user)
                    or (sp.subject_type='group' and sp.subject_id=any(@groups)))
                  and (sp.valid_from is null or sp.valid_from<=@now)
                  and (sp.valid_until is null or sp.valid_until>@now) order by p.package_key,sp.effect desc
                """));
        if (owner) packages.AddRange(await Read("""
            select id,package_key,name,'platform_owner'::text as source_kind,'owner:primary'::text as source_key,'allow'::text as effect,
              null::timestamptz as valid_from,null::timestamptz as valid_until
            from access_packages order by package_key
            """));
        var packageIds = packages.Select(row => row.Get("id").GetInt64()).Distinct().Order().ToArray();
        var packageCapabilities = await Read("""
            select c.capability_key,p.package_key from access_package_capabilities pc
            join access_capabilities c on c.id=pc.capability_id join access_packages p on p.id=pc.package_id
            where pc.package_id=any(@packages) order by c.capability_key,p.package_key
            """, packageIds);
        var direct = userId.HasValue ? await Read("""
            select c.capability_key,a.effect,a.scope_json,a.subject_type,a.subject_id,a.source_type,a.valid_from,a.valid_until from access_capability_assignments a
            join access_capabilities c on c.id=a.capability_id
            where ((a.subject_type='user' and a.subject_id=@user) or (a.subject_type='group' and a.subject_id=any(@groups)))
              and (a.valid_from is null or a.valid_from<=@now) and (a.valid_until is null or a.valid_until>@now)
            order by c.capability_key,a.effect desc
            """) : [];
        var all = owner ? await Read("select capability_key from access_capabilities order by capability_key") : [];
        var packageReports = await Read("""
            select pr.report_key,pr.field_categories,pr.allowed_actions,pr.scope_json,p.package_key
            from access_package_reports pr join access_packages p on p.id=pr.package_id where pr.package_id=any(@packages)
            """, packageIds);
        var assignments = userId.HasValue ? await Read("""
            select report_key,effect,field_categories,allowed_actions,scope_json,subject_type,subject_id,source_type,valid_from,valid_until,business_reason from access_report_assignments
            where ((subject_type='user' and subject_id=@user) or (subject_type='group' and subject_id=any(@groups)))
              and (valid_from is null or valid_from<=@now) and (valid_until is null or valid_until>@now)
            order by report_key,effect desc,id
            """) : [];
        var definitions = await Read("""
            select distinct on (r.report_key) r.report_key,r.version,r.definition_json,r.discoverable,
                r.name,r.owner_name,r.purpose,r.sensitivity,r.status,r.requestable,r.request_profile_json,
                d.dataset_key,d.version as dataset_version,d.fields_json,d.actions_json,d.status as dataset_status
            from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id
            where r.status='published' order by r.report_key,r.version desc
            """);
        var requests = includeReadProjection && userId.HasValue ? await Read("""
            select distinct on (report_key) id,report_key,status,created_at,updated_at,decision_reason
            from report_access_requests_v4 where requester_user_id=@user order by report_key,created_at desc,id desc
            """) : [];
        var preferences = includeReadProjection && userId.HasValue ? await Read("""
            select report_key,pinned,view_json,updated_at from user_report_preferences where user_id=@user
            """) : [];
        await transaction.CommitAsync(ct);
        return new(owner, role, packages, packageCapabilities, direct, all, packageReports, assignments, definitions)
            { Groups = memberships, Requests = requests, Preferences = preferences, EvaluatedAt = now };
    }
}
