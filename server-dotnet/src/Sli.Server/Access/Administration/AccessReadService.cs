using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;

namespace Sli.Server.Access.Administration;

public sealed record AccessReadEvaluation(AccessFacts Facts, CapabilityDecisionSet Capabilities, AccessDecision Reports);

public sealed class AccessReadService(IPostgresConnectionFactory connections)
{
    public async Task<AccessReadEvaluation> LoadAsync(Principal principal, CancellationToken ct)
    {
        var facts = await new AccessFactsRepository(connections).LoadAsync(principal, true, ct);
        var capabilities = new CapabilityComposer().Compose(facts);
        return new(facts, capabilities, new ReportEligibility().Compose(facts, capabilities));
    }

    public async Task<Principal?> FindUserAsync(long id, CancellationToken ct)
    {
        await using var connection = await connections.OpenAsync(ct);
        await using var command = new NpgsqlCommand("select id,username,role from auth_users where id=@id and is_active=true", connection);
        command.Parameters.AddWithValue("id", id);
        await using var reader = await command.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? new("session", reader.GetInt64(0), reader.GetString(2), Username: reader.GetString(1)) : null;
    }

    public async Task<object> GetSubjectsAsync(string accountType, CancellationToken ct)
    {
        await using var connection = await connections.OpenAsync(ct);
        var users = await ReadAsync(connection, """
            select u.id,u.username,u.role,u.is_active,u.last_login_at,
              (u.is_service or exists(select 1 from auth_api_keys k where k.report_subject_id=u.id)) as is_service
            from auth_users u where (@service::boolean is null or
              (u.is_service or exists(select 1 from auth_api_keys k where k.report_subject_id=u.id))=@service)
            order by lower(u.username),u.id limit 500
            """, ct, new NpgsqlParameter("service", NpgsqlDbType.Boolean) { Value = accountType == "all" ? DBNull.Value : accountType == "service" });
        var groups = await ReadAsync(connection, "select id,group_key,name,description,is_active from access_groups order by name,id limit 500", ct);
        var packages = await ReadAsync(connection, """
            select p.package_key,p.name,p.description,
              coalesce(array_agg(distinct c.capability_key) filter(where c.capability_key is not null),'{}') as capabilities,
              coalesce(array_agg(distinct pr.report_key) filter(where pr.report_key is not null),'{}') as reports
            from access_packages p left join access_package_capabilities pc on pc.package_id=p.id
            left join access_capabilities c on c.id=pc.capability_id left join access_package_reports pr on pr.package_id=p.id
            group by p.id,p.package_key,p.name,p.description order by p.name
            """, ct);
        var assignments = await ReadAsync(connection, """
            select id,subject_type,subject_id,report_key,effect,scope_json,field_categories,allowed_actions,
              valid_from,valid_until,source_type,business_reason,approved_by,created_at
            from access_report_assignments order by created_at desc,id desc limit 200
            """, ct);
        var packageAssignments = await ReadAsync(connection, """
            select sp.id,sp.subject_type,sp.subject_id,p.package_key,p.name as package_name,sp.effect,
              sp.valid_from,sp.valid_until,sp.business_reason,sp.approved_by,sp.source_type,sp.created_at
            from access_subject_packages sp join access_packages p on p.id=sp.package_id
            order by sp.created_at desc,sp.id desc limit 200
            """, ct);
        return new { users, groups, packages, assignments, package_assignments = packageAssignments, limits = new { subjects = 500, assignments = 200 } };
    }

    public async Task<object> GetAuditAsync(int limit, CancellationToken ct, bool collapse = false)
    {
        limit = Math.Clamp(limit, 1, 500);
        await using var connection = await connections.OpenAsync(ct);
        const string recent = """
            select id,actor_type,actor_id,action,subject_type,subject_id,target_type,target_key,reason,outcome,
              details_json,remote_address,created_at from access_audit_v4 order by created_at desc,id desc limit @limit
            """;
        string sql = collapse ? "with recent as (" + recent + """
            ), grouped as (
              select r.*,row_number() over series as position,
                case when count(*) over series>1 then jsonb_agg(to_jsonb(r)) over series end as occurrences
              from recent r
              window series as (partition by actor_type,actor_id,action,subject_type,subject_id,target_type,target_key,
                reason,outcome,remote_address,
                case when action<>'notification_channel_update' then details_json end,
                case when subject_id is null and target_key is null then id end
                order by created_at desc,id desc rows between unbounded preceding and unbounded following)
            )
            select id,actor_type,actor_id,action,subject_type,subject_id,target_type,target_key,reason,outcome,
              details_json,remote_address,created_at,occurrences from grouped where position=1 order by created_at desc,id desc
            """ : recent;
        var items = await ReadAsync(connection, sql, ct, new NpgsqlParameter("limit", limit));
        return new { items, limit, total_count = "not_calculated" };
    }

    public async Task<object> GetGrantOptionsAsync(CancellationToken ct)
    {
        await using var connection = await connections.OpenAsync(ct);
        var rows = await ReadAsync(connection, """
            select distinct on(r.report_key) r.report_key,r.version,r.name,r.purpose,r.sensitivity,r.definition_json,
              d.dataset_key,d.fields_json,d.actions_json from report_registry_v4 r
            join report_datasets_v4 d on d.id=r.dataset_id where r.status='published' order by r.report_key,r.version desc
            """, ct);
        var items = rows.Select(row =>
        {
            var definition = row.Get("definition_json").Object();
            var defined = definition.Get("field_categories").Strings();
            var labels = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var field in row.Get("fields_json").Items())
            {
                string category = field.Text("category");
                if (defined.Contains(category) && !labels.ContainsKey(category))
                    labels[category] = field.Text("category_label") is { Length: > 0 } label ? label : category;
            }
            var actions = row.Get("actions_json").Strings(); actions.IntersectWith(definition.Get("actions").Strings());
            string dataset = row.Text("dataset_key");
            var scopes = new List<string> { "all" };
            if (dataset is "entities.v2" or "ad.audit.snapshot" or "ad.accounts.privileged" or "ad.accounts.vpn" or "ad.gpo.governance" or "events.v2") scopes.AddRange(["server", "domain"]);
            if (dataset == "events.v2") scopes.Add("channel");
            if (dataset is "ad.gpo.reference.v2" or "security.problems" or "security.events.atomic" or "ad.accounts.users.reference.v2" or "ad.assets.computers.v6") scopes.Add("domain");
            return new { report_key = row.Text("report_key"), version = row.Get("version").GetInt64(), name = row.Text("name"),
                purpose = row.Text("purpose"), sensitivity = row.Text("sensitivity"), dataset_key = dataset,
                field_categories = labels.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => new { key = p.Key, label = p.Value }).ToArray(),
                allowed_actions = actions.Order(StringComparer.Ordinal).ToArray(), required_capabilities = definition.Get("required_capabilities").Strings().Order(StringComparer.Ordinal).ToArray(), scope_kinds = scopes };
        }).ToArray();
        return new { api_version = "v4", items, limits = new { reports = items.Length } };
    }

    private static async Task<List<JsonElement>> ReadAsync(NpgsqlConnection connection, string sql, CancellationToken ct, params NpgsqlParameter[] parameters)
    {
        await using var command = new NpgsqlCommand("select to_jsonb(r) from (" + sql + ") r", connection);
        command.Parameters.AddRange(parameters);
        var rows = new List<JsonElement>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            using var json = JsonDocument.Parse(reader.GetString(0));
            rows.Add(json.RootElement.Clone());
        }
        return rows;
    }
}
