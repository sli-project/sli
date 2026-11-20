using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.Registry;
using Sli.Server.Auth.Lifecycle.Security;

namespace Sli.Server.Semantic;

internal sealed record SemanticEvent(long Source, string Type, DateTimeOffset At, JsonObject Roles, JsonObject Facts, JsonObject Quality, string Sha)
{
    internal const string Normalizer = "windows.named-eventdata", Version = "1.4+identity-1.0";
    internal Guid Id(string? version = null) => AuthAudit.Uuid5($"adlog:normalized:{Source}:1:{Normalizer}:{version ?? Version}:{Sha}");
    internal static SemanticEvent Read(JsonNode row) => new(row.Number("source_event_id"), row.Text("semantic_type")!, SigmaProjection.At(row, "occurred_at_utc"), row["roles_json"]!.DeepClone().AsObject(), row["facts_json"]!.DeepClone().AsObject(), row["quality_json"]!.DeepClone().AsObject(), row.Text("semantic_sha256")!);
}

internal static class SemanticNormalization
{
    internal sealed record ShadowResult(SemanticEvent? Normalized, IReadOnlyList<SemanticAction> Actions, string? SkippedReason = null);
    internal static ShadowResult ProcessShadow(JsonObject source, SemanticRuntimeSettings settings)
    {
        if (!settings.Normalization) return new(null, [], "semantic_normalization_disabled");
        var normalized = Normalize(source);
        return new(normalized, settings.Assembly ? SemanticAssembly.Assemble([normalized]) : []);
    }

    internal sealed record EventIdentity(string Source, string Stream, string EventKey, string Provider, string Type, string Noise, string CatalogVersion);
    internal static IReadOnlyList<EventIdentity> IdentitiesForTypes(IReadOnlyCollection<string> types)
    {
        using var stream = typeof(SemanticNormalization).Assembly.GetManifestResourceStream("Sli.Server.Semantic.Risk.event_catalog.json")!;
        string version = JsonNode.Parse(stream)!.Text("version")!;
        var identities = new List<EventIdentity>();
        foreach (var entry in Catalog.OfType<JsonObject>().Where(x => x.Text("source") == "sli.windows.ad-dc"))
        {
            if (!int.TryParse(entry.Text("event_key"), out int id)) continue;
            // Probe the same projection used for real events; the catalogue does not duplicate its type mapping.
            var projection = Normalize(new JsonObject { ["id"] = 1, ["server_id"] = 1, ["event_id"] = id,
                ["channel"] = entry["stream"].Copy(), ["provider_name"] = entry["provider_name"].Copy(),
                ["time_created_utc"] = SemanticJson.Stamp(DateTimeOffset.UnixEpoch), ["event_data_json"] = new JsonObject() });
            if (types.Contains(projection.Type)) identities.Add(new("sli.windows.ad-dc", entry.Text("stream")!, entry.Text("event_key")!, entry.Text("provider_name")!, projection.Type, entry.Text("noise_class")!, version));
        }
        return identities;
    }
    internal static readonly JsonArray Catalog = ReadCatalog();
    private static JsonArray ReadCatalog()
    {
        using var stream = typeof(SemanticNormalization).Assembly.GetManifestResourceStream("Sli.Server.Semantic.Risk.event_catalog.json")!;
        return JsonNode.Parse(stream)!["entries"]!.AsArray();
    }
    internal static IReadOnlySet<(string Stream, string Provider, long Event)> MembershipEventIdentities() => Catalog
        .OfType<JsonObject>().Where(e => e["source"]?.ToString() == "sli.windows.ad-dc" && e["event_key"]?.ToString() is "4728" or "4732" or "4756")
        .Select(e => (e["stream"]!.ToString(), e["provider_name"]!.ToString(), long.Parse(e["event_key"]!.ToString(), CultureInfo.InvariantCulture))).ToHashSet();

    internal static SemanticEvent Normalize(JsonObject source) => Project(source, sourceOwned: false);
    // Like the Python AD source-pack projection, independent of registry admission.
    internal static SemanticEvent ProjectSource(JsonObject source) => Project(source, sourceOwned: true);
    // Windows source-pack compatibility entry point shares the AD report vocabulary.
    internal static SemanticEvent ProjectWindows(JsonObject source) => ProjectSource(source);
    // Pure evaluator retained by windows_task_correlation_audit.py after V1 retirement.
    internal static JsonObject EvaluateTaskCorrelation(JsonArray eventRows, JsonArray pairRows)
    {
        var byEvent = new Dictionary<long, JsonNode>();
        foreach (var row in eventRows) byEvent[row.Number("event_id")] = row!;
        var byPair = new Dictionary<(long, long), JsonNode>();
        foreach (var row in pairRows) byPair[(row.Number("opener"), row.Number("closer"))] = row!;
        long[] expected = [100, 102, 200, 201];
        bool ready = byEvent.Keys.ToHashSet().SetEquals(expected) && expected.All(id =>
            byEvent[id].Number("total") > 0 && byEvent[id].Number("nonempty") == byEvent[id].Number("total")
            && byEvent[id].Number("uuid_shaped") == byEvent[id].Number("total"));
        bool OneToOne(long opener, long closer)
        {
            if (!ready || !byPair.TryGetValue((opener, closer), out var pair)) return false;
            return byEvent[opener].Number("distinct_ids") == byEvent[opener].Number("total")
                && byEvent[closer].Number("distinct_ids") == byEvent[closer].Number("total")
                && pair.Number("shared_ids") == byEvent[closer].Number("distinct_ids");
        }
        return new JsonObject
        {
            ["status"] = ready ? "ok" : "gaps_found", ["normalization_ready"] = ready,
            ["safe_pair_candidates"] = new JsonObject { ["100_to_102_by_correlation_id"] = OneToOne(100, 102), ["200_to_201_by_correlation_id"] = OneToOne(200, 201) },
            ["event_metrics"] = eventRows.DeepClone(), ["pair_metrics"] = pairRows.DeepClone(), ["raw_identifiers_in_report"] = false
        };
    }
    // Compact source-field filters used by the Windows source-pack contract.
    internal static IReadOnlyList<(string Role, string PrimaryField, string? FallbackField, string Value)>? CoreRoleFilters(
        string semanticType, IReadOnlyList<string> joinRoles, IReadOnlyDictionary<string, string> triggerRoles)
    {
        if (semanticType is not ("authentication.session.created" or "authentication.explicit_credentials.used" or "authentication.privileged_session.created")) return null;
        var filters = new List<(string, string, string?, string)>();
        foreach (string role in joinRoles)
        {
            if (role == "source_host") continue;
            string raw = triggerRoles.GetValueOrDefault(role)?.Trim() ?? "";
            if (raw.Length == 0) return null;
            (string? primary, string? fallback) = role switch
            {
                "affected_entity" when semanticType != "authentication.privileged_session.created" => ("target_user_sid", "target_user_name"),
                "actor" when semanticType != "authentication.session.created" => ("subject_user_sid", "subject_user_name"),
                "session_principal" => ("logon_id", null), "source_ip" => ("ip_address", null), _ => (null, null)
            };
            if (primary is null) return null;
            string value = raw; int separator = raw.IndexOf(':');
            if (role == "session_principal")
            {
                if (separator < 0 || separator == raw.Length - 1) return null;
                value = raw[(separator + 1)..];
            }
            else if (separator >= 0 && raw[..separator] is "sid" or "guid" or "upn" or "sam" or "name")
                value = raw[..separator] is "sid" or "sam" ? raw[(raw.LastIndexOf(':') + 1)..] : raw[(separator + 1)..];
            filters.Add((role, primary, fallback, value));
        }
        return filters;
    }
    private static SemanticEvent Project(JsonObject source, bool sourceOwned)
    {
        int id = (int)source.Number("event_id"); long eventId = source.Number("id");
        string channel = source.Text("channel")!, provider = source.Text("provider_name") ?? "", host = source["source_host_id"]?.ToString() ?? source["server_id"]!.ToString(), identityHost = source.Text("computer") ?? host;
        var data = source["event_data_json"] is JsonObject obj ? obj : JsonNode.Parse(source.Text("event_data_json") ?? "{}")!.AsObject();
        if (id is 6272 or 6273 && channel.Trim().Equals("Security", StringComparison.OrdinalIgnoreCase) && provider.Trim().Equals("Microsoft-Windows-Security-Auditing", StringComparison.OrdinalIgnoreCase)) return Nps(source, data);
        var values = data.ToDictionary(x => x.Key, x => x.Value?.ToString());
        string? Text(params string[] keys) => keys.Select(k => values.GetValueOrDefault(k)?.Trim()).FirstOrDefault(x => !string.IsNullOrEmpty(x));
        var basis = WorkstationLogonProjection.Build(id, channel, provider, values, identityHost, null);
        // Native source-host IDs, rather than DNS spellings, bind AD/DC semantic roles.
        var roles = basis.Roles; roles["source_host"] = host;
        var identities = basis.Quality["identity_roles"]!.AsObject();
        string? logon = id == 4624 ? Text("TargetLogonId", "LogonId") : id == 4672 ? Text("SubjectLogonId", "LogonId") : Text("SubjectLogonId", "TargetLogonId", "LogonId");
        roles.Remove("session_principal"); identities.Remove("session_principal");
        if (logon is not null)
        {
            string key = host + ":" + UnicodeCaseFold.Fold(logon); roles["session_principal"] = key;
            identities["session_principal"] = new JsonObject { ["key"] = key, ["state"] = "resolved", ["step"] = "source_scoped_session", ["provisional"] = false, ["confidence"] = 1.0, ["reason"] = null, ["aliases"] = new JsonArray(), ["rule"] = "source-host-plus-logon-id/v1" };
        }
        string semantic = "event.unknown";
        var facts = new JsonObject { ["windows_event_id"] = id, ["channel"] = channel, ["provider"] = string.IsNullOrEmpty(provider) ? null : provider, ["correlation_id"] = source["correlation_id"].Copy() };
        var quality = basis.Quality; quality.Remove("ad_enrichment"); quality.Remove("coverage"); quality.Remove("relation_account_identity");
        bool descriptor = Catalog.Any(x => x.Text("source") == "sli.windows.ad-dc" && x?["event_key"]?.ToString() == id.ToString(CultureInfo.InvariantCulture) && string.Equals(x.Text("stream"), channel, StringComparison.OrdinalIgnoreCase) && string.Equals(x.Text("provider_name"), provider, StringComparison.OrdinalIgnoreCase));
        // The AD source pack also owns report events absent from the legacy catalog.
        // Match its complete descriptor (event, channel and provider) before mapping.
        descriptor |= sourceOwned && Sli.Server.Ad.AdSecurity.Family(id) is not null
            && channel.Trim().Equals("Security", StringComparison.OrdinalIgnoreCase)
            && provider.Trim() == (id == 1102 ? "Microsoft-Windows-Eventlog" : "Microsoft-Windows-Security-Auditing");
        void Put(string key, params string[] names) { if (Text(names) is { } text) facts[key] = text; }
        void Result(string? code)
        {
            facts["result_code_state"] = code is null ? "unknown" : "observed";
            facts["result"] = code is null ? "unknown" : new[] { "0", "0x0", "0x00000000", "00000000" }.Contains(code.ToLowerInvariant()) ? "success" : "failure";
            if (code is not null) facts["result_code"] = code;
        }
        if (descriptor)
        {
            semantic = id switch
            {
                4608 => "system.boot.boundary", 4688 => "process.started.fragment", 4689 => "process.ended.fragment", 4624 => "authentication.session.created", 4634 => "authentication.session.ended", 4647 => "authentication.logout.requested", 4625 => "authentication.session.failed",
                4720 => "directory.account.created", 4722 => "directory.account.enabled", 4725 => "directory.account.disabled", 4726 => "directory.account.deleted", 4738 => "directory.account.changed", 4781 => "directory.account.renamed",
                4740 => "authentication.account.locked", 4767 => "authentication.account.unlocked", 4672 => "authentication.privileged_session.created", 4648 => "authentication.explicit_credentials.used",
                4768 => "authentication.kerberos.tgt.requested", 4769 => "authentication.kerberos.service_ticket.requested", 4770 => "authentication.kerberos.service_ticket.renewed", 4771 => "authentication.kerberos.preauthentication.failed", 4773 => "authentication.kerberos.service_ticket.failed", 4776 => "authentication.credentials.validated",
                4719 => "audit.policy.changed", 4728 or 4732 or 4756 => "group.member.added", 4729 or 4733 or 4757 => "group.member.removed", 4727 or 4731 or 4754 => "directory.group.created", 4730 or 4734 or 4755 => "directory.group.deleted", 4737 or 4735 or 4758 => "directory.group.changed", 4764 => "directory.group.type_changed",
                5136 => "directory.attribute.changed.fragment", 4697 or 7045 => "service.installed.fragment", 4698 or 106 => "scheduled_task.created.fragment", 4699 => "scheduled_task.deleted.fragment", 4700 => "scheduled_task.enabled.fragment", 4701 => "scheduled_task.disabled.fragment", 4702 => "scheduled_task.updated.fragment",
                4103 => "powershell.module.fragment", 4104 => "powershell.script_block.fragment", 1102 or 104 => "eventlog.cleared.fragment", _ => "event.unknown"
            };
            if (id is 4624 or 4634) Put("logon_type", "LogonType");
            if (id == 4647) facts["lifecycle_role"] = "supplemental_logout_only";
            if (id == 4625)
            {
                string? code = Text("Status") ?? Text("SubStatus"); if (Text("SubStatus") is { } sub && WorkstationLogonProjection.PositiveHexStatus(sub)) code = sub;
                if (code is not null) facts["failure_status"] = code; Result(code);
            }
            if (id is 4723 or 4724)
            {
                string? outcome = AuditOutcome(source.Text("keywords")); string? code = Text("Status", "ResultCode");
                facts["result"] = outcome ?? "unknown"; facts["audit_outcome_state"] = outcome is null ? "unknown" : "observed"; if (outcome is not null) facts["audit_outcome"] = outcome;
                facts["result_code_state"] = code is null ? "unknown" : "observed"; if (code is not null) facts["result_code"] = code;
                semantic = id == 4723 ? outcome == "success" ? "account.password.changed.succeeded" : "account.password.change.attempted" : outcome == "success" ? "account.password.reset.succeeded" : "account.password.reset.attempted";
            }
            if (id == 4781) { Put("account_name_before", "OldTargetUserName", "OldAccountName"); Put("account_name_after", "NewTargetUserName", "NewAccountName"); }
            if (id == 4740) Put("caller_computer", "CallerComputerName", "CallerComputer");
            if (id == 4672) { Put("privileges", "PrivilegeList"); facts["security_assertion"] = "privileged_session_observed_not_privilege_escalation"; }
            if (id == 4648) facts["security_assertion"] = "explicit_credentials_observed_no_high_risk_by_default";
            if (id is 4768 or 4769 or 4770 or 4771 or 4773 or 4776) Result(id is 4771 or 4773 ? Text("FailureCode", "Status", "ResultCode", "ErrorCode") : Text("Status", "ResultCode", "FailureCode", "ErrorCode"));
            if (id is 4769 or 4770 or 4773) Put("service_name", "ServiceName"); if (id == 4776) Put("workstation", "Workstation", "WorkstationName");
            if (id == 4719) foreach (var (key, name) in new[] { ("audit_category_id", "CategoryId"), ("audit_subcategory_id", "SubcategoryId"), ("audit_subcategory_guid", "SubcategoryGuid"), ("audit_policy_changes", "AuditPolicyChanges"), ("subject_logon_id", "SubjectLogonId") }) Put(key, name);
            if (semantic.StartsWith("group.member.", StringComparison.Ordinal) || semantic.StartsWith("directory.group.", StringComparison.Ordinal))
            {
                facts["change"] = semantic.Split('.')[^1]; facts["group_scope"] = id is 4727 or 4728 or 4729 or 4730 or 4737 ? "global" : id is 4731 or 4732 or 4733 or 4734 or 4735 ? "local" : "universal";
                Put("group", "TargetSid", "TargetUserName", "GroupName"); if (facts.Text("group") is { } group) roles["container_entity"] = group;
                if (semantic.StartsWith("group.member.", StringComparison.Ordinal)) { Put("member", "MemberSid", "MemberName"); if (facts.Text("member") is { } member) roles["target_entity"] = member; }
            }
            if (id == 5136)
            {
                Put("object", "ObjectGUID", "ObjectDN"); Put("attribute", "AttributeLDAPDisplayName"); facts["operation"] = (Text("OperationType", "Operation") ?? "").ToLowerInvariant(); facts["operation_correlation_id"] = Text("OpCorrelationID", "CorrelationId", "CorrelationID") ?? source.Text("correlation_id");
                if (facts.Text("object") is { } entity) roles["target_entity"] = entity;
                if (Text("AttributeValue") is { } value) facts[facts.Text("operation")!.Contains("delete") ? "removed_values" : facts.Text("operation")!.Contains("add") ? "added_values" : "observed_values"] = new JsonArray(value);
            }
            if (id is 4697 or 7045)
            {
                Put("service_name", "ServiceName"); Put("service_file", "ServiceFileName", "ImagePath"); Put("service_account", "ServiceAccount", "AccountName"); Put("service_start_type", "ServiceStartType"); if (facts.Text("service_name") is { } service) roles["target_entity"] = service;
            }
            if (id is 4698 or 4699 or 4700 or 4701 or 4702 or 106)
            {
                Put("task_name", "TaskName", "TaskNamePath"); if (facts.Text("task_name") is { } task) roles["target_entity"] = task;
                if (id == 106) { Put("task_instance_id", "TaskInstanceId", "InstanceId"); Put("task_user_context", "UserContext", "UserName"); }
                else { facts["task_change"] = semantic.Split('.')[1]; string? content = Text("TaskContentNew", "TaskContent"); if (content is not null && Encoding.UTF8.GetByteCount(content) <= 8192) facts["task_content"] = content; }
            }
            if (id is 4688 or 4689 or 4697 or 4698 or 4699 or 4700 or 4701 or 4702)
            {
                foreach (var (key, name, max) in new[] { ("process_user_sid", "SubjectUserSid", 512), ("process_user_name", "SubjectUserName", 512), ("process_user_domain", "SubjectDomainName", 512), ("process_logon_id", "SubjectLogonId", 128) }) { string? value = Text(name); if (value is not null && value != "-" && Encoding.UTF8.GetByteCount(value) <= max) facts[key] = value; }
                string? pid = WorkstationLogonProjection.ProcessId(Text(id == 4688 ? "NewProcessId" : id == 4689 ? "ProcessId" : "ClientProcessId")); if (pid is not null) facts[id is 4688 or 4689 ? "process_id" : "native_process_id"] = pid;
                if (id is 4688 or 4689)
                {
                    string? rawPid = Text(id == 4688 ? "NewProcessId" : "ProcessId"); quality["process_id_state"] = rawPid is null or "-" ? "unknown_missing" : pid is null ? "unknown_invalid" : "exact";
                    string? name = Text(id == 4688 ? "NewProcessName" : "ProcessName"); if (name is not null && name != "-" && Encoding.UTF8.GetByteCount(name) <= 512) facts["process_name"] = name;
                    if (id == 4688)
                    {
                        string? parent = WorkstationLogonProjection.ProcessId(Text("CreatorProcessId")); if (parent is not null) facts["process_parent_id"] = parent;
                        quality["process_parent_id_state"] = Text("CreatorProcessId") is null or "-" ? "unknown_missing" : parent is null ? "unknown_invalid" : "exact";
                        string? command = Text("CommandLine"); quality["process_command_line_state"] = command is null or "-" ? "unknown_missing" : Encoding.UTF8.GetByteCount(command) > 4096 ? "unknown_over_limit" : "exact";
                        if (quality.Text("process_command_line_state") == "exact") facts["process_command_line"] = command;
                    }
                }
            }
            if (id is 4103 or 4104)
            {
                string? pid = WorkstationLogonProjection.ProcessId(Text("SystemExecutionProcessId")); if (pid is not null) facts["native_process_id"] = pid;
                foreach (var (key, names, max) in new[] { ("powershell_user_name", new[] { "User", "ConnectedUser" }, 512), (id == 4103 ? "powershell_command_name" : "powershell_script_block_text", new[] { id == 4103 ? "CommandName" : "ScriptBlockText" }, id == 4103 ? 512 : 2048) }) { string? value = Text(names); if (value is not null && Encoding.UTF8.GetByteCount(value) <= max) facts[key] = value; }
            }
            if (semantic == "eventlog.cleared.fragment") facts["cleared_log"] = Text("Channel", "LogName", "ChannelName") ?? (id == 1102 ? "Security" : null);
            if (ObservedChange(id, data) is { } observedChange) facts["observed_change"] = observedChange;
            string? Exact(string field) { string? sid = Text(field); return sid is not null && Regex.IsMatch(sid, @"\AS-1-5-21-\d+-\d+-\d+-\d+\z", RegexOptions.IgnoreCase) ? sid.ToUpperInvariant() : null; }
            if (id is 4624 or 4720 or 4724 or 4740 or 4767)
            {
                string field = id == 4624 ? "TargetUserSid" : "TargetSid"; string? sid = Exact(field); quality["relation_account_identity"] = new JsonObject { ["state"] = sid is null ? "not_exact" : "exact", ["sid_field"] = field }; if (sid is not null) facts["relation_account_sid"] = sid;
            }
            if (id is 4728 or 4729 or 4732 or 4733 or 4756 or 4757)
            {
                string? member = Exact("MemberSid"), group = Exact("TargetSid"); quality["relation_membership_identity"] = new JsonObject { ["state"] = member is not null && group is not null ? "exact" : "not_exact", ["member_sid_field"] = "MemberSid", ["group_sid_field"] = "TargetSid" };
                if (member is not null && group is not null) { facts["relation_member_sid"] = member; facts["relation_group_sid"] = group; }
            }
        }
        else
        {
            roles = new JsonObject { ["source_host"] = host }; quality = new JsonObject { ["event_data_encoding"] = "named", ["catalog_independent"] = false, ["raw_event_mutated"] = false, ["missing_actor_sid"] = true, ["unresolved_actor"] = false, ["unresolved_target"] = false, ["missing_source_ip"] = true, ["unknown_event_mapping"] = true, ["semantic_mapping_status"] = "source_pack_or_provider_unresolved" };
        }
        if (descriptor) { quality["unknown_event_mapping"] = semantic == "event.unknown"; quality["semantic_mapping_status"] = id == 4772 ? "defined_but_not_emitted" : semantic == "event.unknown" ? "accepted_descriptor_without_semantic_projection" : "mapped"; quality["defined_but_not_emitted"] = id == 4772; }
        foreach (var (key, value) in new[] { ("domain_id", source["domain_id"]), ("source_host_id", source["source_host_id"] ?? source["server_id"]), ("host", JsonValue.Create(identityHost)), ("event_record_id", source["event_record_id"]), ("source_event_sha256", source["source_event_sha256"] ?? source["normalized_hash"]), ("source_facts_sha256", source["source_facts_sha256"]) }) if (value is not null) facts[key] = value.Copy();
        foreach (string key in facts.Where(p => p.Value is null).Select(p => p.Key).ToArray()) facts.Remove(key);
        quality["identity_resolution_version"] = "1.0";
        var material = new JsonObject { ["source_event_id"] = eventId, ["semantic_type"] = semantic, ["roles"] = roles.Copy(), ["facts"] = facts.Copy(), ["identity_resolution_version"] = "1.0" };
        return new(eventId, semantic, SigmaProjection.At(source, "time_created_utc"), roles, facts, quality, SemanticJson.Hash(material));
    }
    internal static string? AuditOutcome(string? keywords)
    {
        string value = keywords?.Trim().ToLowerInvariant() ?? ""; if (value.Contains("auditsuccess") || value.Replace(" ", "").Contains("auditsuccess") || new[] { "9007199254740992", "0x20000000000000", "0x8020000000000000", "-9214364837600034816" }.Contains(value)) return "success";
        if (value.Replace(" ", "").Contains("auditfailure") || new[] { "4503599627370496", "0x10000000000000", "0x8010000000000000", "-9218868437227405312" }.Contains(value)) return "failure"; return null;
    }
    private static SemanticEvent Nps(JsonObject source, JsonObject data)
    {
        long eventId = source.Number("id"); int id = (int)source.Number("event_id"); string host = source["source_host_id"]?.ToString() ?? source["server_id"]!.ToString();
        string? Text(int limit, params string[] names) => names.Select(k => data[k]?.ToString().Trim()).Where(x => !string.IsNullOrEmpty(x)).Select(x => string.Concat(x!.EnumerateRunes().Take(limit).Select(r => r.ToString()))).FirstOrDefault();
        var values = data.ToDictionary(x => x.Key, x => x.Value?.ToString()); values["SubjectUserName"] = Text(512, "SubjectUserName", "FullyQualifiedSubjectUserName");
        var identity = WorkstationLogonProjection.Resolve(values, "Subject", source.Text("computer") ?? host); var roles = new JsonObject { ["source_host"] = host }; var identities = new JsonObject();
        if (identity.Key.Length > 0) { roles["affected_entity"] = identity.Key; identities["affected_entity"] = new JsonObject { ["key"] = identity.Key, ["state"] = identity.State, ["step"] = identity.Step, ["provisional"] = identity.State == "provisional", ["confidence"] = identity.Confidence, ["reason"] = identity.Reason, ["aliases"] = new JsonArray(identity.Aliases.Select(x => JsonValue.Create(x)).ToArray()), ["rule"] = "identity-ladder/v1" }; }
        string? session = Text(256, "AccountSessionIdentifier"), ip = Text(128, "CallingStationID"); if (session is not null) roles["session_principal"] = host + ":nps:" + UnicodeCaseFold.Fold(session); if (ip is not null) roles["source_ip"] = ip;
        var facts = new JsonObject { ["windows_event_id"] = id, ["channel"] = source["channel"].Copy(), ["provider"] = source["provider_name"].Copy(), ["correlation_id"] = source.Text("correlation_id") ?? session, ["decision"] = id == 6272 ? "allowed" : "denied", ["authentication_type"] = Text(512, "AuthenticationType"), ["authentication_provider"] = Text(512, "AuthenticationProvider"), ["network_policy"] = Text(512, "NetworkPolicyName"), ["nas_identifier"] = Text(512, "NASIdentifier"), ["reason_code"] = Text(128, "ReasonCode"), ["session_evidence"] = "nps_decision_only_accounting_required", ["domain_id"] = source["domain_id"].Copy(), ["source_host_id"] = source["source_host_id"].Copy() ?? source["server_id"].Copy(), ["host"] = source.Text("computer") ?? host, ["event_record_id"] = source["event_record_id"].Copy(), ["source_event_sha256"] = source["source_event_sha256"].Copy() ?? source["normalized_hash"].Copy(), ["source_facts_sha256"] = source["source_facts_sha256"].Copy() };
        foreach (string key in facts.Where(x => x.Value is null).Select(x => x.Key).ToArray()) facts.Remove(key);
        var quality = new JsonObject { ["event_data_encoding"] = "named", ["catalog_independent"] = false, ["raw_event_mutated"] = false, ["missing_actor_sid"] = Text(512, "SubjectUserSid") is null, ["unresolved_actor"] = false, ["unresolved_target"] = identity.Key.Length > 0 && identity.State == "unresolved", ["missing_source_ip"] = ip is null, ["unknown_event_mapping"] = false, ["identity_roles"] = identities, ["provisional_identity_roles"] = identity.State == "provisional" && identity.Key.Length > 0 ? new JsonArray("affected_entity") : new JsonArray(), ["unresolved_identity_roles"] = identity.State == "unresolved" && identity.Key.Length > 0 ? new JsonArray("affected_entity") : new JsonArray(), ["semantic_mapping_status"] = "mapped_nps_decision", ["vpn_session_confirmed"] = false, ["identity_resolution_version"] = "1.0" };
        string type = id == 6272 ? "remote_access.authentication.allowed" : "remote_access.authentication.denied"; string hash = SemanticJson.Hash(new JsonObject { ["source_event_id"] = eventId, ["semantic_type"] = type, ["roles"] = roles.Copy(), ["facts"] = facts.Copy(), ["identity_resolution_version"] = "1.0" }); return new(eventId, type, SigmaProjection.At(source, "time_created_utc"), roles, facts, quality, hash);
    }
    private static JsonObject? ObservedChange(int id, JsonObject data)
    {
        string? kind = id switch { 4738 => "attributes_changed", 4728 or 4732 or 4756 => "member_added", 4729 or 4733 or 4757 => "member_removed", 4727 or 4731 or 4754 => "group_created", 4730 or 4734 or 4755 => "group_deleted", 4737 or 4735 or 4758 => "group_changed", 4764 => "group_type_changed", 4719 => "audit_policy_changed", 1102 => "security_log_cleared", _ => null };
        if (kind is not ("attributes_changed" or "group_changed" or "group_type_changed" or "audit_policy_changed" or "security_log_cleared")) return null;
        string? Text(params string[] names) => names.Select(k => data[k]?.ToString().Trim()).Where(x => !string.IsNullOrEmpty(x) && x != "-").Select(x => string.Concat(x!.EnumerateRunes().Take(512).Select(r => r.ToString()))).FirstOrDefault();
        var result = new JsonObject { ["state"] = "observed", ["kind"] = kind }; var values = new JsonObject(); string? missing = null;
        if (kind is "attributes_changed" or "group_changed")
        {
            var fields = kind == "attributes_changed" ? new[] { ("DisplayName", "changed_display_name", "display_name"), ("SamAccountName", "changed_sam_account_name", "sam_account_name"), ("UserPrincipalName", "changed_user_principal_name", "user_principal_name"), ("HomeDirectory", "changed_home_directory", "home_directory"), ("HomePath", "changed_home_path", "home_path"), ("ScriptPath", "changed_script_path", "script_path"), ("ProfilePath", "changed_profile_path", "profile_path"), ("UserWorkstations", "changed_user_workstations", "user_workstations"), ("PasswordLastSet", "changed_password_last_set", "password_last_set"), ("AccountExpires", "changed_account_expires", "account_expires"), ("PrimaryGroupId", "changed_primary_group_id", "primary_group_id"), ("AllowedToDelegateTo", "changed_allowed_to_delegate_to", "allowed_to_delegate_to"), ("UserAccountControl", "changed_user_account_control", "user_account_control"), ("OldUacValue", "old_user_account_control", "old_user_account_control"), ("NewUacValue", "new_user_account_control", "new_user_account_control") } : new[] { ("Description", "changed_description", "description"), ("DisplayName", "changed_display_name", "display_name"), ("SamAccountName", "changed_sam_account_name", "sam_account_name"), ("GroupType", "changed_group_type", "group_type") };
            foreach (var (native, alias, key) in fields) if (Text(native, alias) is { } value) values[key] = value;
            if (values.Count > 0) result["attributes"] = values; else missing = kind == "attributes_changed" ? "account_attributes_not_present" : "group_change_attributes_not_present";
        }
        else if (kind is "group_type_changed" or "audit_policy_changed")
        {
            var fields = kind == "group_type_changed" ? new[] { ("OldGroupType", "old_group_type", "old_group_type"), ("NewGroupType", "new_group_type", "new_group_type") } : new[] { ("CategoryId", "audit_category_id", "category_id"), ("SubcategoryId", "audit_subcategory_id", "subcategory_id"), ("SubcategoryGuid", "audit_subcategory_guid", "subcategory_guid"), ("AuditPolicyChanges", "audit_policy_changes", "observed_value") };
            foreach (var (native, alias, key) in fields) if (Text(native, alias) is { } value) values[key] = value;
            if (values.Count > 0) foreach (var pair in values) result[pair.Key] = pair.Value.Copy(); else missing = kind == "group_type_changed" ? "group_type_values_not_present" : "audit_policy_fields_not_present";
        }
        else if (kind == "security_log_cleared" && Text("Channel", "LogName", "cleared_log") is { } cleared) result["observed_value"] = cleared;
        if (missing is not null) { result["state"] = "partial"; result["detail"] = new JsonObject { ["state"] = "unknown", ["reason"] = missing }; }
        return result;
    }
}
