using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static Sli.Server.Reporting.ReportJson;
using static Sli.Server.Reporting.ReportStudioService;

namespace Sli.Server.Reporting;

internal static class ReportSummaries
{
    internal static async Task<JsonObject?> ReadAsync(IReportSession db, string dataset, string where, object?[] scope, IReadOnlySet<string> categories,
        long days, string filteredWhere, IReadOnlyList<object?> filterValues, CancellationToken ct)
    {
        string name = dataset switch { "ad.audit.snapshot" => "_ad_snapshot_summary", "ad.accounts.privileged" => "_privileged_account_summary", "ad.accounts.vpn" => "_vpn_account_summary", "ad.gpo.governance" => "_gpo_governance_summary", _ => "" };
        if (dataset == "security.problems")
        {
            var aggregate = First(await db.QueryAsync(ReportRunner.Template("_execute_definition_4", filteredWhere, "", days), filterValues, ct));
            return new() { ["kind"] = "security_problems", ["aggregate_scope"] = "effective_report_scope", ["total_items"] = aggregate.Number("total_items"), ["latest_observed_at_utc"] = aggregate["latest_observed_at_utc"]?.DeepClone() };
        }
        if (name.Length == 0) return null;
        var summary = (ReportDatasetCatalog.Data["summary_bases"]![name] as JsonObject)!.Copy();
        string[] sections = dataset switch { "ad.audit.snapshot" => ["directory_accounts", "privileged_membership", "vpn_membership", "gpo_governance"], "ad.accounts.privileged" => ["privileged_membership", "directory_accounts"], "ad.accounts.vpn" => ["vpn_membership", "directory_accounts", "privileged_membership"], _ => ["gpo_governance"] };
        string alias = dataset is "ad.accounts.privileged" or "ad.accounts.vpn" ? "source_entity" : "entity";
        summary["collection"] = await CoverageAsync(db, sections, where.Replace(alias + ".", "run."), scope, ct);
        async Task<IReadOnlyList<JsonObject>> Read(string suffix, string? currentContext = null)
        {
            string sql = ReportRunner.Template(name + suffix, where, "", days);
            if (currentContext is not null) sql = sql.Replace("{current_context}", currentContext);
            return await db.QueryAsync(sql, scope, ct);
        }
        void Copy(JsonObject row, params string[] fields) { foreach (string field in fields) summary[field] = row[field]?.DeepClone() ?? (field.EndsWith("_utc") ? null : JsonValue.Create(0)); }
        if (dataset == "ad.audit.snapshot")
        {
            const string currentContext = "exists(select 1 from ad_context_entity_versions version where version.entity_id=entity.id and version.valid_to_utc is null and version.source_section='directory_accounts')";
            if (categories.Contains("identity_basic"))
            {
                var total = First(await Read("_0", currentContext)); summary["total_objects"] = total.Number("total_objects");
                summary["by_entity_type"] = Nodes((await Read("_1", currentContext)).Select(r => new JsonObject { ["entity_type"] = r.Text("entity_type", "unknown"), ["count"] = r.Number("object_count") }));
            }
            if (categories.Contains("security"))
            {
                Copy(First(await Read("_2", currentContext)), "without_observation_count", "latest_observed_at_utc");
                var row = First(await Read("_3"));
                var account = new JsonObject(); foreach (string field in new[] { "observed_users", "disabled_users", "inactive_users", "password_never_expires_users", "locked_users" }) account[field] = row.Number(field);
                var computer = new JsonObject(); foreach (string field in new[] { "observed_computers", "disabled_computers", "inactive_computers", "computers_with_operating_system" }) computer[field] = row.Number(field);
                computer["operating_system_distribution"] = row["operating_system_distribution"]?.DeepClone() ?? new JsonArray();
                summary["account_controls"] = account; summary["computer_controls"] = computer;
            }
        }
        else
        {
            var row = First(await Read("_0"));
            if (dataset == "ad.accounts.privileged")
            {
                if (categories.Contains("identity_basic")) Copy(row, "unique_subjects");
                if (categories.Contains("privilege")) Copy(row, "total_relations", "unique_target_groups");
                if (categories.Contains("security")) Copy(row, "latest_observed_at_utc", "disabled_subjects", "inactive_subjects");
            }
            if (dataset == "ad.accounts.vpn")
            {
                summary["inactive_threshold_days"] = days;
                if (categories.Contains("identity_basic")) Copy(row, "total_users");
                if (categories.Contains("privilege")) Copy(row, "privileged_overlap_users");
                if (categories.Contains("security")) Copy(row, "enabled_users", "active_users", "disabled_users", "unknown_account_state_users", "inactive_users", "unknown_activity_users", "password_never_expires_users", "latest_observed_at_utc");
            }
            if (dataset == "ad.gpo.governance")
            {
                if (categories.Contains("identity_basic"))
                {
                    Copy(row, "total_gpo", "missing_owner_count");
                    summary["owner_observation_state"] = row.Number("total_gpo") > 0 && row.Number("missing_owner_count") == row.Number("total_gpo") ? "not_collected" : row.Number("missing_owner_count") > 0 ? "partial" : "observed";
                }
                if (categories.Contains("security"))
                {
                    Copy(row, "unlinked_policy_count", "disabled_policy_count", "partially_enabled_policy_count", "executable_component_policy_count", "executable_component_total_count", "setting_policy_count", "setting_total_count", "sensitive_value_policy_count", "manual_review_count", "latest_observed_at_utc");
                    summary["executable_component_risk_qualified"] = false; summary["manual_review_basis"] = new JsonArray("link_count_zero", "application_state_disabled");
                }
            }
        }
        return summary;
    }

    private static async Task<JsonObject> CoverageAsync(IReportSession db, string[] names, string where, object?[] scope, CancellationToken ct)
    {
        bool notApplicable = where.Contains("run.server_id", StringComparison.Ordinal);
        IReadOnlyList<JsonObject> rows = [];
        if (!notApplicable)
        {
            string predicate = where.Length > 0 ? " and " + where[7..] : "";
            predicate = Regex.Replace(predicate, "@p([0-9]+)", m => "@p" + (int.Parse(m.Groups[1].Value) + 1));
            string sql = ReportDatasetCatalog.Data["queries"].Text("_context_section_coverage_0").Replace("{scope_predicate}", predicate).Replace("?", "@p0");
            rows = await db.QueryAsync(sql, new object?[] { names }.Concat(scope).ToArray(), ct);
        }
        var result = new JsonObject();
        foreach (string name in names)
        {
            var row = rows.FirstOrDefault(r => r.Text("section_name") == name) ?? new JsonObject();
            long domains = row.Number("domain_count");
            string state = notApplicable ? "scope_not_applicable" : domains == 0 ? "not_collected" : row.Number("failed_domain_count") == domains ? "failed"
                : row.Number("skipped_domain_count") == domains ? "skipped" : row.Number("complete_domain_count") == domains ? "complete" : "partial";
            var item = new JsonObject { ["state"] = state, ["latest_observed_at_utc"] = row["latest_observed_at_utc"]?.DeepClone() };
            foreach (string field in new[] { "domain_count", "complete_domain_count", "partial_domain_count", "failed_domain_count", "skipped_domain_count" }) item[field] = row.Number(field);
            result[name] = item;
        }
        return result;
    }
}
