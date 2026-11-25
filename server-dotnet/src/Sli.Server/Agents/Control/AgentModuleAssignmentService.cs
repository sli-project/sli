using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Sli.Server.Agents.Registry;
using PythonJsonCompatibility = Sli.Server.Compatibility.PythonJson;

namespace Sli.Server.Agents.Control;

// Source policies.assign_module; transaction is owned by caller.
internal sealed class AgentModuleAssignmentService(IAgentControlAudit audit)
{
    internal async Task<JsonElement> AssignAsync(NpgsqlConnection db,NpgsqlTransaction tx,JsonElement body,string actor,CancellationToken ct)
    {
        if (body.ValueKind==JsonValueKind.Object && body.TryGetProperty("password_detection_domain",out _)) return await PasswordDomainAsync(db,tx,body,actor,ct);
        if (body.ValueKind!=JsonValueKind.Object || body.EnumerateObject().Any(p=>p.Name is not ("agent_id" or "module_id" or "enabled" or "config" or "expected_revision"))
            || !body.TryGetProperty("module_id",out var moduleValue) || AgentControlJson.String(moduleValue) is not string module || module is not (SnapshotPolicy.Ad or SnapshotPolicy.Gpo or "sli.workstations" or "sli.windows.ad-dc" or "sli.windows.ad-dc-history" or "sli.file-audit" or NpsPolicy.Nps or NpsPolicy.Accounting)
            || !body.TryGetProperty("enabled",out var flag) || flag.ValueKind is not (JsonValueKind.True or JsonValueKind.False)
            || (body.TryGetProperty("config",out var settings) && settings.ValueKind!=JsonValueKind.Object)
            || (module is SnapshotPolicy.Ad or SnapshotPolicy.Gpo && settings.ValueKind!=JsonValueKind.Object))
            throw new AgentControlException("invalid_agent_module_assignment");
        if (module=="sli.file-audit") throw new AgentControlException("module_disabled",503);
        Guid id=AgentControlJson.Id(AgentControlJson.Get(body,"agent_id"));
        bool workstation=module==WorkstationsModule.ModuleId && await WorkstationJournalAdmission.AvailableAsync(db,tx,ct);
        if (flag.GetBoolean() && !(workstation ? await WorkstationJournalAdmission.PluginEnabledAsync(db,tx,ct)
            : await AgentPolicyAssignments.ModuleEnabledAsync(db,tx,module,ct)))
            throw new AgentControlException("module_disabled",503);
        bool snapshot=module is SnapshotPolicy.Ad or SnapshotPolicy.Gpo;
        JsonObject agent;
        await using (var read=new NpgsqlCommand("select to_jsonb(a) from sli_agents a where id=@id for update",db,tx))
        {
            read.Parameters.AddWithValue("id",id);
            if (await read.ExecuteScalarAsync(ct) is not string raw) throw new AgentControlException("agent_not_found",404);
            agent=JsonNode.Parse(raw)!.AsObject();
        }
        await AgentManagementService.LockImportAsync(db,tx,id,ct);
        if (agent["status"]!.GetValue<string>()!="active") throw new AgentControlException("agent_disabled",409);
        long current=agent["policy_revision"]!.GetValue<long>();
        long expected=current;
        if (body.TryGetProperty("expected_revision",out var e) && (e.ValueKind!=JsonValueKind.Number || !e.TryGetInt64(out expected)))
            throw new AgentControlException("agent_policy_revision_conflict",409);
        long revision=AgentModuleAssignmentRules.NextRevision(current,expected);
        var oldModules=agent["assigned_modules"]!.AsArray(); var modules=new JsonArray();
        foreach (var item in oldModules)
            if (!(item is JsonValue value && value.TryGetValue<string>(out var text) && text==module)
                && !(item is JsonObject obj && obj["module_id"] is JsonValue key && key.TryGetValue<string>(out var name) && name==module)) modules.Add(item?.DeepClone());
        JsonObject config;
        string? plugin=module switch { "sli.file-audit"=>"sli.file-audit", NpsPolicy.Nps or NpsPolicy.Accounting=>"sli.remote-access", "sli.windows.ad-dc" or "sli.windows.ad-dc-history"=>"sli.ad", _=>null };
        using (var guard=plugin is null ? null : AgentAssignmentPluginAdmission.Enter(plugin,Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"),Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR")))
        try
        {
            var input=ReadConfig(settings,revision);
            bool useWorkstationBaseline = flag.GetBoolean() && oldModules.Count == modules.Count;
            if (module == WorkstationsModule.ModuleId && flag.GetBoolean() && input.Count == 1)
            {
                var previous = oldModules.OfType<JsonObject>()
                    .FirstOrDefault(item => item["module_id"]?.ToString() == module)?["config"] as JsonObject;
                if (previous is not null && previous.Any(entry => entry.Key != "policy_revision"))
                {
                    useWorkstationBaseline = workstation && await HasUnchangedWorkstationEnrollmentAsync(db, tx, id, previous, ct);
                    if (!useWorkstationBaseline)
                    {
                        var nextRevision = input["policy_revision"]!.DeepClone();
                        input = previous.DeepClone().AsObject();
                        input["policy_revision"] = nextRevision;
                    }
                }
                else if (workstation) useWorkstationBaseline = true;
            }
            config=module switch {
                SnapshotPolicy.Ad or SnapshotPolicy.Gpo => SnapshotIngressPolicy.Parse(module,input).Config,
                "sli.workstations" => AgentModuleAssignmentRules.NormalizeWorkstation(input,
                    useCollectionBaseline: useWorkstationBaseline),
                "sli.windows.ad-dc" or "sli.windows.ad-dc-history" => AgentModuleAssignmentRules.NormalizeAd(input,module=="sli.windows.ad-dc-history"),
                "sli.file-audit" => AgentFileAuditPolicy.Parse(input).Value,
                NpsPolicy.Nps or NpsPolicy.Accounting => AgentModuleAssignmentRules.NormalizeNps(module,input).Value,
                _ => throw new InvalidOperationException()
            };
        }
        catch (Exception ex) when (ex is AgentException or ProtocolException or InvalidOperationException or ArgumentException or FormatException or OverflowException)
        { throw new AgentControlException("invalid_agent_module_config"); }
        if (workstation && flag.GetBoolean() && !WorkstationJournalAdmission.SupportsConfig(config))
            throw new AgentControlException("workstation_journal_profile_unsupported")
                { AllowedEventIds = WorkstationJournalAdmission.EventIds };
        if (module == NpsPolicy.Accounting && flag.GetBoolean())
        {
            var policy=NpsPolicy.Parse(module,config);
            if (!await AgentPolicyAssignments.AccountingSourceEnabledAsync(db,tx,policy,policy,ct))
                throw new AgentControlException("agent_source_not_bound",409);
        }
        if (snapshot) await AgentSnapshotAssignment.ValidateAsync(db,tx,id,module,config,flag.GetBoolean(),ct);
        modules.Add(new JsonObject { ["module_id"]=module,["enabled"]=flag.GetBoolean(),["config"]=config.DeepClone() });
        if (modules.Count>64) throw new AgentControlException("agent_module_limit");
        var check=CheckIn(agent,modules,revision);
        if (CanonicalJson.Length(check)>60*1024-1024) throw new AgentControlException("agent_policy_size_limit");
        if (!snapshot) AgentModuleAssignmentRules.ValidateChannelOwnership(modules);
        var control=AgentControlJson.Element(agent["collection_policy"]!);
        await AgentPolicyStore.SnapshotAsync(db,tx,id,current,AgentControlJson.Element(oldModules),control,ct);
        await AgentPolicyStore.SnapshotAsync(db,tx,id,revision,AgentControlJson.Element(modules),control,ct);
        if (snapshot) await AgentSnapshotAssignment.PublishAsync(db,tx,id,module,config,flag.GetBoolean(),ct);
        await using (var update=new NpgsqlCommand("update sli_agents set assigned_modules=@modules::jsonb,policy_revision=@revision where id=@id",db,tx))
        { update.Parameters.AddWithValue("modules",modules.ToJsonString());update.Parameters.AddWithValue("revision",revision);update.Parameters.AddWithValue("id",id);await update.ExecuteNonQueryAsync(ct); }
        if(workstation && !await WorkstationJournalAdmission.SetAsync(db,tx,id,flag.GetBoolean(),ct))
            throw new AgentControlException("agent_source_not_bound",409);
        if (module=="sli.windows.ad-dc") await ReconcilePasswordDomainAsync(db,tx,id,ct);
        if (module=="sli.file-audit")
        {
            var match=System.Text.RegularExpressions.Regex.Match(actor,@"\A(session|api_key):([1-9][0-9]{0,18})\z");
            if (!match.Success || !long.TryParse(match.Groups[2].Value,out long actorId)) throw new AgentControlException("file_audit_request_denied",403);
            using var guard=AgentAssignmentPluginAdmission.Enter("sli.file-audit",Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"),Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR"));
            await using var retain=new NpgsqlCommand("select sli_plugin_file_audit.retain_assignment_policy(@agent,@type,@actor)",db,tx);
            retain.Parameters.AddWithValue("agent",id);retain.Parameters.AddWithValue("type",match.Groups[1].Value);retain.Parameters.AddWithValue("actor",actorId);
            await retain.ExecuteNonQueryAsync(ct);
        }
        string hash=Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(PythonJson(config))));
        var details=new JsonObject { ["module_id"]=module,["enabled"]=flag.GetBoolean(),["policy_sha256"]=hash,["revision"]=revision };
        if(workstation && flag.GetBoolean() && await WorkstationJournalAdmission.ReadAsync(db,tx,id,null,null,ct) is { } scope)
        {
            details["server_id"]=scope.ServerId;
            details["source"]=scope.Computer;
            details["domain_id"]=scope.DomainId;
            details["source_instance_id"]=(agent["source_host_id"] ?? agent["host_id"])?.DeepClone();
        }
        if (!snapshot)
        {
            if (module is "sli.workstations" or NpsPolicy.Nps or NpsPolicy.Accounting) details["families"]=config["families"]!.DeepClone();
            else if (module=="sli.file-audit") details["channels"]=new JsonArray("Security");
            else details["channels"]=config["channels"]!.DeepClone();
            details["changed_fields"]=ChangedFields(settings);
        }
        await audit.AppendAsync(db,tx,"module_assign",actor,id.ToString(),details,ct);
        return JsonSerializer.SerializeToElement(new { agent_id=id,assigned_modules=modules,policy_revision=revision });
    }
    private static async Task<bool> HasUnchangedWorkstationEnrollmentAsync(NpgsqlConnection db, NpgsqlTransaction tx,
        Guid agent, JsonObject previous, CancellationToken ct)
    {
        var initial = AgentEnrollmentService.DefaultWorkstationConfig();
        // Check-in may advance the revision while keeping the enrollment settings.
        initial["policy_revision"] = previous["policy_revision"]?.DeepClone();
        if (!JsonNode.DeepEquals(previous, initial)) return false;

        await using var command = new NpgsqlCommand("""
            select actor like 'enrollment:%'
            from sli_agent_audit
            where target=@agent and action='module_assign' and details->>'module_id'='sli.workstations'
            order by id desc limit 1
            """, db, tx);
        command.Parameters.AddWithValue("agent", agent.ToString("D"));
        return await command.ExecuteScalarAsync(ct) is true;
    }

    internal static async Task ReconcilePasswordDomainAsync(NpgsqlConnection db,NpgsqlTransaction tx,Guid agent,CancellationToken ct)
    {
        await using var query=new NpgsqlCommand("select public.reconcile_password_detection_domain371(@agent)",db,tx);
        query.Parameters.AddWithValue("agent",agent);
        await query.ExecuteScalarAsync(ct);
    }
    internal static JsonObject ReadConfig(JsonElement settings,long revision)
    {
        var input=settings.ValueKind==JsonValueKind.Object ? PythonJsonCompatibility.FromElement(settings)!.AsObject() : new JsonObject();
        input["policy_revision"]=revision.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return input;
    }
    internal static JsonArray ChangedFields(JsonElement settings) => new(
        (settings.ValueKind==JsonValueKind.Object ? settings.EnumerateObject().Select(x=>x.Name).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal) : Enumerable.Empty<string>())
            .Select(x=>(JsonNode?)JsonValue.Create(x)).ToArray());
    private static async Task<JsonElement> PasswordDomainAsync(NpgsqlConnection db,NpgsqlTransaction tx,JsonElement body,string actor,CancellationToken ct)
    {
        if (!body.EnumerateObject().Select(x=>x.Name).ToHashSet().SetEquals(["agent_id","module_id","expected_revision","password_detection_domain"])
            || AgentControlJson.String(body.GetProperty("module_id"))!="sli.windows.ad-dc"
            || body.GetProperty("expected_revision").ValueKind!=JsonValueKind.Number || !body.GetProperty("expected_revision").TryGetInt64(out long revision)
            || revision<1 || revision>9007199254740991 || body.GetProperty("password_detection_domain") is not { ValueKind:JsonValueKind.Object } metadata
            || !metadata.EnumerateObject().Select(x=>x.Name).ToHashSet().SetEquals(["fqdn","expected_domain_id"])
            || AgentControlJson.String(metadata.GetProperty("fqdn")) is not string name)
            throw new AgentControlException("invalid_password_domain_metadata");
        var expected=metadata.GetProperty("expected_domain_id"); long domainId=0;
        if (expected.ValueKind!=JsonValueKind.Null && (expected.ValueKind!=JsonValueKind.Number || !expected.TryGetInt64(out domainId) || domainId<1))
            throw new AgentControlException("invalid_password_domain_metadata");
        Guid agent=AgentControlJson.Id(body.GetProperty("agent_id"));string fqdn=AgentModuleAssignmentRules.NormalizeDomain(name);
        try
        {
            await using var query=new NpgsqlCommand("select public.provision_password_detection_domain_v2(@agent,@revision,@domain,@fqdn,@actor)::text",db,tx);
            query.Parameters.AddWithValue("agent",agent);query.Parameters.AddWithValue("revision",revision);
            query.Parameters.AddWithValue("domain",NpgsqlTypes.NpgsqlDbType.Bigint,expected.ValueKind==JsonValueKind.Null ? DBNull.Value : domainId);
            query.Parameters.AddWithValue("fqdn",fqdn);query.Parameters.AddWithValue("actor",actor);
            var result=JsonNode.Parse((string)(await query.ExecuteScalarAsync(ct))!)!;
            return JsonSerializer.SerializeToElement(new { agent_id=agent,policy_revision=revision,password_detection_domain=result });
        }
        catch(PostgresException ex) when (ex.SqlState is "40001" or "55000" or "22023")
        { throw ex.SqlState switch { "40001"=>new AgentControlException("password_domain_conflict",409),"55000"=>new AgentControlException("password_domain_immutable",409),_=>new AgentControlException("invalid_password_domain_metadata") }; }
    }
    internal static JsonObject CheckIn(JsonObject agent,JsonArray modules,long revision)
    {
        var control=JsonNode.Parse(AgentPolicyStore.NormalizeCollectionPolicy(AgentControlJson.Element(agent["collection_policy"]!)).GetRawText())!.AsObject();
        if (!control["manage_windows_audit"]!.GetValue<bool>()) { control.Remove("manage_windows_audit");control.Remove("audit_process_command_line"); }
        var result=new JsonObject { ["agent_id"]=agent["id"]!.DeepClone(),["assigned_modules"]=modules.DeepClone(),["policy_revision"]=revision,
            ["rights_probe_request"]=agent["rights_probe"]?["pending"]?.DeepClone(),["collection_policy"]=control,
            ["eventlog_diagnostics_supported"]=true,["delivery_diagnostics_supported"]=true };
        if (agent["source_host_id"] is not null) result["runtime_handoff"]=new JsonObject { ["source_host_id"]=agent["source_host_id"]!.DeepClone(),["cursors"]=agent["runtime_resume"]?.DeepClone() ?? new JsonObject() };
        if (agent["file_audit"]?["request"] is JsonNode request) result["file_audit"]=request.DeepClone();
        return result;
    }
    private static string PythonJson(JsonNode node)
    {
        string compact=CanonicalJson.Serialize(node);var result=new StringBuilder();bool quoted=false,escape=false;
        foreach(char c in compact)
        {
            result.Append(c);
            if (quoted) { if (escape) escape=false; else if (c=='\\') escape=true; else if (c=='"') quoted=false; }
            else if (c=='"') quoted=true; else if (c is ':' or ',') result.Append(' ');
        }
        return result.ToString();
    }
}

