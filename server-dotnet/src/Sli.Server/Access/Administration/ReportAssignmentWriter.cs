using System.Numerics;
using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;

namespace Sli.Server.Access.Administration;

public sealed class ReportAssignmentWriter(IPostgresConnectionFactory connections, IReportCatalogProvider? catalog = null) : IReportAssignmentWriter
{
    private readonly IReportCatalogProvider catalog = catalog ?? new ReportRuleCatalog();
    public async Task<ReportAssignmentResult> CreateAsync(ReportAssignmentCommand command, AssignmentActor? actor, string? remoteAddress, CancellationToken ct)
    {
        var values = AssignmentValidation.Parse(command.Payload, false);
        var captured = values.ScopeKind == "scope" ? catalog.Capture() : null;
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        JsonElement registered;
        await using (var read = new NpgsqlCommand("""
            select to_jsonb(r) from (
                select r.definition_json,d.dataset_key,d.fields_json,d.actions_json
                from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id
                where r.report_key=@key and r.status='published' order by r.version desc limit 1
            ) r
            """, connection, transaction))
        {
            read.Parameters.AddWithValue("key", values.Key);
            if (await read.ExecuteScalarAsync(ct) is not string json) throw AssignmentValidation.Error("report_not_found");
            using var parsed = JsonDocument.Parse(json); registered = parsed.RootElement.Clone();
        }
        await EnsureSubjectAsync(transaction, values, ct);
        var supported = SupportedScopes(registered.Text("dataset_key"));
        if (captured is not null && catalog.Recheck(captured).SupportsGenericScope(values.Key)) supported.Add("scope");
        if (!supported.Contains(values.ScopeKind)) throw AssignmentValidation.Error("scope_not_supported_by_dataset");
        await ValidateTargetsAsync(transaction, values.ScopeKind, values.Scope, ct);
        var definition = registered.Get("definition_json").Object();
        var fields = registered.Get("fields_json").Items().Select(f => f.Text("category")).Where(f => f.Length > 0).ToHashSet();
        fields.IntersectWith(definition.Get("field_categories").Strings());
        var actions = registered.Get("actions_json").Strings(); actions.IntersectWith(definition.Get("actions").Strings());
        string[] selectedFields = values.Fields, selectedActions = values.Actions;
        if (values.Effect == "allow")
        {
            if (selectedFields.Length == 0) selectedFields = fields.Order(StringComparer.Ordinal).ToArray();
            if (selectedFields.Any(f => !fields.Contains(f))) throw AssignmentValidation.Error("unknown_report_field_category");
            if (selectedActions.Any(a => !actions.Contains(a))) throw AssignmentValidation.Error("unknown_report_action");
            if (!selectedActions.Contains("view")) throw AssignmentValidation.Error("report_view_action_required");
        }
        else { selectedFields = []; selectedActions = []; }
        await using var insert = new NpgsqlCommand("""
            with inserted as (
                insert into access_report_assignments(subject_type,subject_id,report_key,effect,scope_json,field_categories,allowed_actions,valid_from,valid_until,source_type,business_reason,approved_by,created_by)
                values(@subject,@subject_id,@key,@effect,@scope::jsonb,@fields,@actions,@from,@until,@source,@reason,@approved,@actor)
                returning id,subject_type,subject_id,report_key,effect,scope_json,field_categories,allowed_actions,valid_from,valid_until,source_type,business_reason,approved_by,created_at
            ) select to_jsonb(inserted) from inserted
            """, connection, transaction);
        Bind(insert, values, actor);
        insert.Parameters.AddWithValue("scope", values.Scope.GetRawText()); insert.Parameters.AddWithValue("fields", selectedFields);
        insert.Parameters.AddWithValue("actions", selectedActions);
        var result = AssignmentAudit.Row((string)(await insert.ExecuteScalarAsync(ct))!);
        await AssignmentAudit.AppendAsync(transaction, actor, values, result.Get("id").GetInt64(), false, remoteAddress, ct);
        if (captured is not null && !catalog.Recheck(captured).SupportsGenericScope(values.Key))
            throw AssignmentValidation.Error("scope_not_supported_by_dataset");
        await transaction.CommitAsync(ct);
        return new(result);
    }

    internal static void Bind(NpgsqlCommand command, AssignmentValues values, AssignmentActor? actor)
    {
        command.Parameters.AddWithValue("subject", values.SubjectType); command.Parameters.AddWithValue("subject_id", (long)values.SubjectId);
        command.Parameters.AddWithValue("key", values.Key); command.Parameters.AddWithValue("effect", values.Effect);
        command.Parameters.AddWithValue("from", NpgsqlDbType.TimestampTz, (object?)values.ValidFrom ?? DBNull.Value);
        command.Parameters.AddWithValue("until", NpgsqlDbType.TimestampTz, (object?)values.ValidUntil ?? DBNull.Value);
        command.Parameters.AddWithValue("source", values.SourceType); command.Parameters.AddWithValue("reason", values.Reason);
        command.Parameters.AddWithValue("approved", NpgsqlDbType.Text, (object?)values.ApprovedBy ?? DBNull.Value);
        command.Parameters.AddWithValue("actor", NpgsqlDbType.Bigint, (object?)actor?.Id ?? DBNull.Value);
    }

    internal static async Task EnsureSubjectAsync(NpgsqlTransaction transaction, AssignmentValues values, CancellationToken ct)
    {
        if (values.SubjectId > long.MaxValue) throw AssignmentValidation.Error("access_subject_not_found");
        string table = values.SubjectType == "user" ? "auth_users" : "access_groups";
        await using var check = new NpgsqlCommand("select 1 from " + table + " where id=@id and is_active=true", transaction.Connection, transaction);
        check.Parameters.AddWithValue("id", (long)values.SubjectId);
        if (await check.ExecuteScalarAsync(ct) is null) throw AssignmentValidation.Error("access_subject_not_found");
    }

    private static HashSet<string> SupportedScopes(string dataset)
    {
        var result = new HashSet<string>(StringComparer.Ordinal) { "all" };
        if (dataset is "entities.v2" or "ad.audit.snapshot" or "ad.accounts.privileged" or "ad.accounts.vpn" or "ad.gpo.governance" or "events.v2") result.UnionWith(["server", "domain"]);
        if (dataset == "events.v2") result.Add("channel");
        if (dataset is "ad.gpo.reference.v2" or "security.problems" or "security.events.atomic" or "ad.accounts.users.reference.v2" or "ad.assets.computers.v6") result.Add("domain");
        return result;
    }

    internal static async Task ValidateTargetsAsync(NpgsqlTransaction transaction, string kind, JsonElement scope, CancellationToken ct)
    {
        if (kind == "all") return;
        if (kind == "scope")
        {
            foreach (var clause in scope.Get("clauses").Items())
            {
                var plugins = clause.Get("plugin_ids").Items().Select(v => v.GetString()!).ToArray();
                var sources = clause.Get("source_instance_ids").Items().Select(v => v.GetString()!).ToArray();
                var devices = clause.Get("device_ids").Items().Select(v => v.GetString()!).ToArray();
                if (plugins.SequenceEqual(["sli.file-audit"]) && sources.Length > 0 && !clause.Get("entity_ids").Items().Any() && !clause.Get("collection_scope_ids").Items().Any())
                {
                    await using var agents = new NpgsqlCommand("""
                        select id::text,host_id::text from sli_agents where status='active' and host_id::text=any(@sources)
                        and exists(select 1 from jsonb_array_elements(assigned_modules) m where m->>'module_id'='sli.file-audit' and m->>'enabled'='true')
                        """, transaction.Connection, transaction);
                    agents.Parameters.AddWithValue("sources", sources);
                    var foundSources = new HashSet<string>(); var foundDevices = new HashSet<string>();
                    await using (var reader = await agents.ExecuteReaderAsync(ct)) while (await reader.ReadAsync(ct)) { foundDevices.Add(reader.GetString(0)); foundSources.Add(reader.GetString(1)); }
                    if (!foundSources.SetEquals(sources) || devices.Length > 0 && !foundDevices.SetEquals(devices)) throw AssignmentValidation.Error("report_scope_target_not_found");
                    continue;
                }
                foreach ((string dimension, string[] values) in new[] { ("plugin_id", plugins), ("source_instance_id", sources) })
                    if (values.Length > 0) await MatchStringsAsync(transaction, "select distinct " + dimension + " from core_entity_scope_resources where " + dimension + "=any(@values)", values, ct);
                var entities = clause.Get("entity_ids").Items().Select(AssignmentValidation.Integer).ToArray();
                if (entities.Length > 0) await MatchIdsAsync(transaction, "entities_v2", entities, ct);
                if (devices.Length > 0) await MatchStringsAsync(transaction, "select e.natural_key from entities_v2 e join storage_v2_entity_type t on t.id=e.entity_type_id where e.natural_key=any(@values) and t.value in ('device','ad_computer','asset','workstation')", devices, ct);
                foreach (var collection in clause.Get("collection_scope_ids").Items())
                {
                    string text = collection.GetString()!;
                    if (!System.Text.RegularExpressions.Regex.IsMatch(text, @"\Aad-domain:[1-9][0-9]*\z")) throw AssignmentValidation.Error("report_scope_target_not_found");
                    await MatchIdsAsync(transaction, "domains", [BigInteger.Parse(text[10..])], ct);
                }
            }
            return;
        }
        if (kind is "domain" or "server")
            await MatchIdsAsync(transaction, kind == "domain" ? "domains" : "servers", scope.Get("ids").Items().Select(AssignmentValidation.Integer).Distinct().Order().ToArray(), ct);
        else await MatchStringsAsync(transaction, "select value from storage_v2_channel where value=any(@values)", scope.Get("values").Items().Select(AssignmentValidation.String).Where(v => v.Length > 0).Distinct().ToArray(), ct);
    }

    private static async Task MatchIdsAsync(NpgsqlTransaction transaction, string table, BigInteger[] values, CancellationToken ct)
    {
        if (values.Any(v => v < long.MinValue || v > long.MaxValue)) throw AssignmentValidation.Error("report_scope_target_not_found");
        await using var command = new NpgsqlCommand("select id from " + table + " where id=any(@values)", transaction.Connection, transaction);
        var wanted = values.Select(v => (long)v).ToHashSet(); command.Parameters.AddWithValue("values", wanted.ToArray());
        var found = new HashSet<long>(); await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) found.Add(reader.GetInt64(0));
        if (wanted.Count == 0 || !found.SetEquals(wanted)) throw AssignmentValidation.Error("report_scope_target_not_found");
    }

    private static async Task MatchStringsAsync(NpgsqlTransaction transaction, string sql, string[] values, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(sql, transaction.Connection, transaction); command.Parameters.AddWithValue("values", values);
        var found = new HashSet<string>(); await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) found.Add(reader.GetString(0));
        if (values.Length == 0 || !found.SetEquals(values)) throw AssignmentValidation.Error("report_scope_target_not_found");
    }
}
