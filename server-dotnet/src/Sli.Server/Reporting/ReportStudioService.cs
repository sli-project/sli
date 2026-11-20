using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Access;
using Sli.Server.Auth;
using static Sli.Server.Reporting.ReportJson;

namespace Sli.Server.Reporting;

public sealed record ReportCaller(Principal Principal, AccessFacts Facts, CapabilityDecisionSet Capabilities, JsonObject Access)
{
    public IReadOnlySet<string> Caps => Capabilities.Capabilities;
}

public sealed class ReportStudioService(IReportDatabase database, IReportRuleCatalog catalog)
{
    private bool CodeDefined(string key) => catalog.Rules.Any(r => r.RegistryKey == key);
    internal static void Publisher(ReportCaller caller)
    {
        Require(caller.Caps.Contains("reports.publish"), "reports_publish_required", 403);
        Require(caller.Caps.Contains("reports.design"), "report_design_capability_required", 403);
    }
    internal static string Key(string value)
    {
        string key = value.Trim();
        Require(Regex.IsMatch(key, "\\A[a-z0-9][a-z0-9_.-]{2,79}\\z"), "invalid_report_key");
        return key;
    }
    private string LifecycleKey(string value) { string key = Key(value); Require(!CodeDefined(key), "report_is_code_defined"); return key; }
    internal static JsonObject First(IReadOnlyList<JsonObject> rows) => rows.FirstOrDefault() ?? new JsonObject();
    internal static Task<IReadOnlyList<JsonObject>> Query(IReportSession session, string sql, CancellationToken ct, params object?[] values)
    {
        Sli.Server.Infrastructure.SqlArguments.Validate(values);
        return session.QueryAsync(sql, values, ct);
    }

    public async Task<JsonObject> DatasetsAsync(ReportCaller caller, CancellationToken ct)
    {
        Require(caller.Caps.Contains("reports.design"), "reports_design_required", 403);
        await using var db = await database.OpenAsync(false, ct);
        var rows = await Query(db, "select dataset_key,version,name,object_type,fields_json,filters_json,actions_json from report_datasets_v4 where status='published' order by name,version desc", ct);
        foreach (var row in rows)
        {
            string key = row.Text("dataset_key"); row["executable"] = ReportBuilder.Executable.Contains(key);
            row["executable_filter_keys"] = Nodes((ReportDatasetCatalog.Data["RUNTIME_FILTER_FIELDS"]?[key] as JsonObject ?? []).Select(p => p.Key).Order(StringComparer.Ordinal));
            row["executable_sort_keys"] = Nodes((ReportDatasetCatalog.Data["RUNTIME_SORT_FIELDS"]?[key] as JsonObject ?? []).Select(p => p.Key).Order(StringComparer.Ordinal));
        }
        return new() { ["api_version"] = "v4", ["items"] = Nodes(rows), ["arbitrary_sql_allowed"] = false };
    }
    public async Task<JsonObject> DefinitionsAsync(ReportCaller caller, int limit, CancellationToken ct)
    {
        Require(caller.Caps.Contains("reports.design") || caller.Caps.Contains("reports.publish"), "reports_design_required", 403);
        limit = Math.Clamp(limit, 1, 500);
        await using var db = await database.OpenAsync(false, ct);
        var rows = await Query(db, """
            select r.report_key,r.version,r.name,r.owner_name,r.purpose,r.sensitivity,r.status,
              r.published_at,r.created_at,d.dataset_key,d.version as dataset_version,r.discoverable,r.requestable,
              (select count(*) from access_report_assignments a where a.report_key=r.report_key) as assignment_count,
              (select count(*) from access_package_reports pr where pr.report_key=r.report_key) as package_count
            from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id
            order by r.created_at desc,r.id desc limit @p0
            """, ct, limit);
        foreach (var row in rows) row["code_defined"] = CodeDefined(row.Text("report_key"));
        return new() { ["api_version"] = "v4", ["items"] = Nodes(rows), ["limit"] = limit, ["total_count"] = "not_calculated" };
    }
    public async Task<JsonObject> DetailAsync(ReportCaller caller, string key, CancellationToken ct)
    {
        Require(caller.Caps.Contains("reports.design") || caller.Caps.Contains("reports.publish"), "reports_design_required", 403);
        key = key.Trim();
        await using var db = await database.OpenAsync(false, ct);
        var rows = await Query(db, """
            select r.report_key,r.version,r.name,r.owner_name,r.purpose,r.sensitivity,r.status,r.definition_json,
              r.discoverable,r.requestable,r.published_at,r.created_by,d.dataset_key
            from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id
            where r.report_key=@p0 order by r.version desc
            """, ct, key);
        Require(rows.Count > 0, "report_not_found", 404);
        var counts = await CountsAsync(db, key, ct);
        return new() { ["api_version"] = "v4", ["report_key"] = key, ["code_defined"] = CodeDefined(key), ["versions"] = Nodes(rows),
            ["assignment_count"] = counts.Number("assignment_count"), ["package_count"] = counts.Number("package_count") };
    }
    private static async Task<JsonObject> CountsAsync(IReportSession db, string key, CancellationToken ct) => First(await Query(db, """
        select (select count(*) from access_report_assignments where report_key=@p0) as assignment_count,
               (select count(*) from access_package_reports where report_key=@p0) as package_count
        """, ct, key));

    public async Task<JsonObject> PreviewAsync(ReportCaller caller, JsonObject payload, CancellationToken ct)
    {
        Require(caller.Caps.Contains("reports.design"), "reports_design_required", 403);
        await using var db = await database.OpenAsync(false, ct);
        var preview = await PreviewAsync(db, caller, payload, ct);
        if (payload.Flag("with_rows"))
            await new ReportRunner(database).SampleAsync(preview, caller, ct);
        return preview;
    }
    internal static async Task<JsonObject> PreviewAsync(IReportSession db, ReportCaller caller, JsonObject payload, CancellationToken ct)
    {
        Require(!ReportBuilder.Unsafe(payload), "arbitrary_sql_or_unsafe_definition_rejected");
        string rawVersion = payload.Text("dataset_version", "1");
        var parsedVersion = Integer(rawVersion);
        Require(parsedVersion >= long.MinValue && parsedVersion <= long.MaxValue, "unknown_dataset");
        long version = (long)parsedVersion;
        if (version == 0) version = 1;
        var dataset = First(await Query(db, "select dataset_key,version,name,object_type,fields_json,filters_json,actions_json from report_datasets_v4 where dataset_key=@p0 and version=@p1 and status='published'", ct, payload.Text("dataset_key").Trim(), version));
        return ReportBuilder.Preview(payload, dataset, caller.Caps);
    }

    public async Task<JsonObject> PublishAsync(ReportCaller caller, JsonObject payload, string? address, CancellationToken ct)
    {
        Publisher(caller);
        await using var db = await database.OpenAsync(true, ct);
        var preview = await PreviewAsync(db, caller, payload, ct);
        string key = payload.Text("report_key").Trim(), name = payload.Text("name").Trim(), purpose = payload.Text("purpose").Trim(), owner = payload.Text("owner").Trim();
        string status = payload.Text("status", "draft").Trim().ToLowerInvariant(), sensitivity = payload.Text("sensitivity", "restricted").Trim().ToLowerInvariant();
        Require(Regex.IsMatch(key, "\\A[a-z0-9][a-z0-9_.-]{2,79}\\z") && name.Length > 0 && purpose.Length > 0 && owner.Length > 0
            && status is "draft" or "published" && sensitivity is "internal" or "restricted" or "confidential", "invalid_report_definition");
        await LockAsync(db, key, ct);
        var previous = await PublishedAsync(db, key, ct);
        var dataset = First(await Query(db, "select id from report_datasets_v4 where dataset_key=@p0 and version=@p1", ct, preview["dataset"].Text("key"), preview["dataset"].Number("version")));
        Require(dataset.Count > 0, "unknown_dataset");
        long version = First(await Query(db, "select coalesce(max(version),0)+1 as version from report_registry_v4 where report_key=@p0", ct, key)).Number("version", 1);
        var definition = Definition(preview, key);
        var discoverable = payload.ContainsKey("discoverable") ? payload["discoverable"] : previous["discoverable"] ?? JsonValue.Create(false)!;
        var requestable = payload.ContainsKey("requestable") ? payload["requestable"] : previous["requestable"] ?? JsonValue.Create(false)!;
        ValidateVisibility(discoverable, requestable);
        Require(!payload.ContainsKey("request_profile") || payload["request_profile"] is JsonObject, "invalid_report_request_profile");
        var profile = RequestProfile(payload["request_profile"] ?? previous["request_profile_json"] ?? new JsonObject(), preview);
        if (status == "published") await CheckSecurityAsync(db, key, previous, preview["dataset"].Text("key"), definition, ct);
        if (status == "published" && previous.Count > 0) await RetirePublishedAsync(db, key, ct);
        var result = First(await Query(db, """
            insert into report_registry_v4(report_key,version,name,owner_name,purpose,dataset_id,definition_json,sensitivity,status,published_at,created_by,discoverable,requestable,request_profile_json)
            values(@p0,@p1,@p2,@p3,@p4,@p5,@p6::jsonb,@p7,@p8,case when @p8='published' then now() else null end,@p9::bigint,@p10,@p11,@p12::jsonb)
            returning report_key,version,name,owner_name,purpose,sensitivity,status,published_at,created_at,discoverable,requestable,request_profile_json
            """, ct, key, version, name, owner, purpose, dataset.Number("id"), definition.ToJsonString(), sensitivity, status,
            caller.Principal.Type == "local" ? null : caller.Principal.Id.ToString(System.Globalization.CultureInfo.InvariantCulture), discoverable!.GetValue<bool>(), requestable!.GetValue<bool>(), profile.ToJsonString()));
        await AuditAsync(db, caller, status == "published" ? "report_published" : "report_draft_created", key, purpose,
            new JsonObject { ["version"] = version, ["dataset"] = preview["dataset"]!.DeepClone() }, address, ct);
        await db.CommitAsync(ct);
        return result;
    }

    internal static JsonObject Definition(JsonObject preview, string key) => new()
    {
        ["columns"] = Nodes(preview.Array("fields").Select(f => f.Text("key"))), ["filters"] = preview["filters"]!.DeepClone(), ["sort"] = preview["sort"]!.DeepClone(),
        ["actions"] = preview["actions"]!.DeepClone(), ["required_capabilities"] = preview["required_capabilities"]!.DeepClone(),
        ["field_categories"] = preview["required_field_categories"]!.DeepClone(), ["target_path"] = "/reports/" + key,
        ["export_policy"] = preview.Strings("actions").Contains("export") ? "controlled" : "disabled", ["dashboard_metrics"] = preview["dashboard_metrics"]!.DeepClone()
    };
    private static JsonObject RequestProfile(JsonNode raw, JsonObject preview)
    {
        Require(raw is JsonObject, "invalid_report_request_profile");
        string dataset = preview["dataset"].Text("key");
        string[] scopes = Sorted(raw["scope_kinds"] is null ? ["all"] : raw.Strings("scope_kinds"));
        string[] fields = Sorted(raw["field_categories"] is null ? preview.Strings("required_field_categories") : raw.Strings("field_categories"));
        string[] actions = Sorted(raw["allowed_actions"] is null ? ["view"] : raw.Strings("allowed_actions"));
        string[] supported = dataset == "events.v2" ? ["all", "server", "domain", "channel"] : dataset == "security.problems" ? ["all"] : ["all", "server", "domain"];
        var parsedDays = Integer(raw.Text("max_duration_days", "90"));
        Require(parsedDays >= long.MinValue && parsedDays <= long.MaxValue, "invalid_report_request_profile");
        long days = (long)parsedDays; if (days == 0) days = 90;
        Require(scopes.Length > 0 && !scopes.Except(supported).Any() && !fields.Except(preview.Strings("required_field_categories")).Any()
            && !actions.Except(preview.Strings("actions")).Any() && actions.Contains("view") && days is >= 1 and <= 365, "invalid_report_request_profile");
        return new() { ["scope_kinds"] = Nodes(scopes), ["field_categories"] = Nodes(fields), ["allowed_actions"] = Nodes(actions), ["max_duration_days"] = days };
    }
    private static void ValidateVisibility(JsonNode? discoverable, JsonNode? requestable)
    {
        Require(discoverable is JsonValue d && d.TryGetValue<bool>(out _) && requestable is JsonValue r && r.TryGetValue<bool>(out _), "invalid_report_discovery_policy");
        Require(!requestable!.GetValue<bool>() || discoverable!.GetValue<bool>(), "requestable_report_must_be_discoverable");
    }
    private static Task<IReadOnlyList<JsonObject>> LockAsync(IReportSession db, string key, CancellationToken ct) => Query(db, "select pg_advisory_xact_lock(hashtext(@p0))", ct, key);
    private static async Task<JsonObject> PublishedAsync(IReportSession db, string key, CancellationToken ct) => First(await Query(db, """
        select r.version,r.definition_json,r.discoverable,r.requestable,r.request_profile_json,d.dataset_key
        from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id
        where r.report_key=@p0 and r.status='published' order by r.version desc limit 1 for update of r
        """, ct, key));
    private static Task<IReadOnlyList<JsonObject>> RetirePublishedAsync(IReportSession db, string key, CancellationToken ct) => Query(db, "update report_registry_v4 set status='retired' where report_key=@p0 and status='published'", ct, key);
    private static async Task CheckSecurityAsync(IReportSession db, string key, JsonObject previous, string dataset, JsonObject definition, CancellationToken ct)
    {
        var counts = await CountsAsync(db, key, ct);
        if (counts.Number("assignment_count") + counts.Number("package_count") == 0) return;
        if (previous.Count == 0) previous = First(await Query(db, """
            select r.version,r.definition_json,d.dataset_key from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id
            where r.report_key=@p0 and r.status='retired' and r.published_at is not null
            order by r.published_at desc,r.version desc,r.id desc limit 1 for update of r
            """, ct, key));
        Require(previous.Count > 0 && previous.Text("dataset_key") == dataset
            && !ReportBuilder.SecurityExpands(previous["definition_json"] as JsonObject ?? [], definition), "report_security_reapproval_required");
    }

    public async Task<JsonObject> LifecycleAsync(ReportCaller caller, string reportKey, string action, string? versionText, JsonObject payload, string? address, CancellationToken ct)
    {
        Publisher(caller); string key = LifecycleKey(reportKey);
        long version = 0;
        if (action == "publish") Require(long.TryParse(versionText, out version), "invalid_report_version");
        if (action == "visibility") ValidateVisibility(payload["discoverable"], payload["requestable"]);
        await using var db = await database.OpenAsync(true, ct);
        await LockAsync(db, key, ct);
        JsonObject result, details;
        if (action == "publish")
        {
            var draft = First(await Query(db, """
                select r.id,r.status,r.definition_json,d.dataset_key,d.version as dataset_version
                from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id
                where r.report_key=@p0 and r.version=@p1 for update of r
                """, ct, key, version));
            Require(draft.Count > 0, "report_version_not_found", 404);
            Require(draft.Text("status") == "draft", "report_version_not_draft");
            var definition = draft["definition_json"] as JsonObject ?? new();
            var previewPayload = definition.Copy(); previewPayload["fields"] = definition["columns"]?.DeepClone();
            previewPayload["dataset_key"] = draft.Text("dataset_key"); previewPayload["dataset_version"] = draft.Number("dataset_version");
            _ = await PreviewAsync(db, caller, previewPayload, ct);
            var previous = await PublishedAsync(db, key, ct);
            await CheckSecurityAsync(db, key, previous, draft.Text("dataset_key"), definition, ct);
            await RetirePublishedAsync(db, key, ct);
            result = First(await Query(db, "update report_registry_v4 set status='published',published_at=now() where report_key=@p0 and version=@p1 returning report_key,version,name,status,published_at,discoverable,requestable", ct, key, version));
            details = new() { ["version"] = version, ["retired_version"] = previous["version"]?.DeepClone() };
        }
        else if (action == "retire")
        {
            result = First(await Query(db, "update report_registry_v4 set status='retired' where report_key=@p0 and status='published' returning report_key,version,name,status", ct, key));
            Require(result.Count > 0, "report_not_published", 404); details = new() { ["version"] = result["version"]?.DeepClone() };
        }
        else
        {
            result = First(await Query(db, "update report_registry_v4 set discoverable=@p1,requestable=@p2 where report_key=@p0 and status='published' returning report_key,version,status,discoverable,requestable", ct, key, payload.Flag("discoverable"), payload.Flag("requestable")));
            Require(result.Count > 0, "report_not_published", 404); details = new() { ["version"] = result["version"]?.DeepClone(), ["discoverable"] = payload.Flag("discoverable"), ["requestable"] = payload.Flag("requestable") };
        }
        await AuditAsync(db, caller, action switch { "publish" => "report_version_promoted", "retire" => "report_retired", _ => "report_visibility_changed" }, key, null, details, address, ct);
        await db.CommitAsync(ct); return result;
    }

    internal static async Task AuditAsync(IReportSession db, ReportCaller caller, string action, string key, string? reason, JsonObject details, string? address, CancellationToken ct)
    {
        var row = First(await Query(db, """
            insert into access_audit_v4(actor_type,actor_id,action,subject_type,subject_id,target_type,target_key,reason,outcome,details_json,remote_address)
            values(@p0,@p1::bigint,@p2,null,null,'report',@p3,@p4,'ok',@p5::jsonb,@p6) returning id,created_at
            """, ct, caller.Principal.Type, caller.Principal.Type == "local" ? null : caller.Principal.Id.ToString(System.Globalization.CultureInfo.InvariantCulture), action, key, reason, details.ToJsonString(), address));
        Require(row.Number("id") > 0, "administrative_activity_access_audit_id_invalid");
        if (!Sli.Server.Access.Administration.AdministrativeActivityProducer.SupportsAccess(action)) return;
        var activity = Sli.Server.Access.Administration.AdministrativeActivityProducer.ProjectAccess(
            row.Number("id"), DateTimeOffset.Parse(row.Text("created_at"), System.Globalization.CultureInfo.InvariantCulture).UtcDateTime,
            caller.Principal.Type, caller.Principal.Type == "local" ? null : caller.Principal.Id,
            action, null, null, "report", key, "ok", address);
        await Sli.Server.Access.Administration.AdministrativeActivityProducer.MirrorAsync(db, activity,
            Sli.Server.Access.Administration.AssignmentAudit.RuntimeWriteEnabled(), ct);
    }

    public async Task<JsonObject> SummaryAsync(ReportCaller caller, string reportKey, CancellationToken ct)
    {
        Require(caller.Caps.Contains("reports.assign") || caller.Caps.Contains("access.manage"), "reports_assign_required", 403);
        string key = Key(reportKey);
        await using var db = await database.OpenAsync(false, ct);
        var published = First(await Query(db, "select version,discoverable,requestable from report_registry_v4 where report_key=@p0 and status='published' order by version desc limit 1", ct, key));
        if (published.Count == 0) Require((await Query(db, "select 1 as n from report_registry_v4 where report_key=@p0 limit 1", ct, key)).Count > 0, "report_not_found", 404);
        var assignments = await Query(db, """
            select a.subject_type,a.subject_id,a.effect,a.source_type,a.valid_until,a.allowed_actions as actions,a.field_categories,
              coalesce(case when a.subject_type='user' then u.username else g.name end,'') as subject_name
            from access_report_assignments a left join auth_users u on a.subject_type='user' and u.id=a.subject_id
            left join access_groups g on a.subject_type='group' and g.id=a.subject_id
            where a.report_key=@p0 order by a.created_at desc,a.id desc limit 200
            """, ct, key);
        var packages = await Query(db, "select p.package_key,p.name from access_package_reports pr join access_packages p on p.id=pr.package_id where pr.report_key=@p0 order by p.name,p.package_key", ct, key);
        var pending = First(await Query(db, "select count(*) as n from report_access_requests_v4 where report_key=@p0 and status in ('submitted','reviewing')", ct, key));
        return new() { ["api_version"] = "v4", ["report_key"] = key, ["published_version"] = published["version"]?.DeepClone(), ["discoverable"] = published.Flag("discoverable"), ["requestable"] = published.Flag("requestable"),
            ["assignments"] = Nodes(assignments), ["packages"] = Nodes(packages), ["pending_requests"] = pending.Number("n") };
    }

    public static JsonObject Trace(ReportCaller caller, string reportKey)
    {
        string key = Key(reportKey);
        var report = caller.Access.Array("reports").OfType<JsonObject>().FirstOrDefault(r => r.Text("report_key") == key);
        Require(report is not null, "report_not_found", 404);
        var grants = new JsonArray(); bool allowed = report!.Flag("allowed");
        if (allowed) foreach (var grant in report.Array("grants").OfType<JsonObject>())
        {
            string type = grant.Text("source_type", "assignment"), source = grant.Text("source");
            source = type == "platform_owner" ? "owner:primary" : type == "package" ? source : source.StartsWith("user:") ? "current_subject"
                : source.StartsWith("group:") ? "group:" + (caller.Access.Array("groups").OfType<JsonObject>().FirstOrDefault(g => g.Text("id") == source[6..]).Text("key", "assigned")) : type;
            var item = grant.Copy(); item["source"] = source; item["source_type"] = type;
            item["valid_from"] ??= null; item["valid_until"] ??= null; grants.Add(item);
        }
        bool incomplete = allowed && grants.Count == 0; allowed &= !incomplete;
        return new() { ["api_version"] = "v4", ["evaluated_at_utc"] = caller.Access["evaluated_at_utc"]?.DeepClone(),
            ["subject"] = new JsonObject { ["username"] = caller.Access["subject"].Text("username", "current_subject"), ["coarse_role"] = caller.Access["subject"].Text("coarse_role", "viewer") },
            ["report"] = new JsonObject { ["report_key"] = key, ["name"] = report.Text("name", key), ["version"] = report.Number("version") },
            ["decision"] = allowed ? "allowed" : "denied", ["explanation"] = incomplete ? "Сервер не вернул атомарную разрешающую ветвь; доступ этим ответом не подтверждён" : report.Text("explanation", "Решение сервера не содержит пояснения"),
            ["platform_owner"] = caller.Facts.IsOwner, ["owner_policy"] = new JsonObject { ["full_product_access"] = caller.Facts.IsOwner, ["surveyed_system_write_access"] = false },
            ["exact_deny"] = caller.Access["explicit_denies"].Strings("reports").Contains(key), ["ignored_deny"] = caller.Access["ignored_denies"].Strings("reports").Contains(key),
            ["missing_capabilities"] = report["missing_capabilities"]?.DeepClone() ?? new JsonArray(), ["assignment_version_state"] = report.Text("assignment_version_state", "not_assigned"), ["grants"] = allowed ? grants : new JsonArray() };
    }
}
