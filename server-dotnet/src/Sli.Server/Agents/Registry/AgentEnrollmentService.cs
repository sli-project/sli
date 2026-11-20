using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using NpgsqlTypes;
using Npgsql;
using Sli.Server.Agents.Certificates;
using Sli.Agent.Core;
using Sli.Server.Ad;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Ingress;
using Sli.Server.Hosting;

namespace Sli.Server.Agents.Registry;

public sealed partial class AgentEnrollmentService(AgentIssuingCa ca, IAgentIdentityService identity, IConfiguration? configuration = null)
{
    public async Task<JsonObject> EnrollAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        JsonObject body, CancellationToken ct)
    {
        string? token = StringValue(body, "token");
        if (token is null || !Regex.IsMatch(token, "^[A-Za-z0-9_-]{43}\\z", RegexOptions.CultureInvariant)) throw RejectToken();
        var digest = Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(token)));
        await AdvisoryAsync(connection,transaction,"sli-agent-registration-reconcile",ct);
        await LockGroupApprovalAsync(connection, transaction, digest, ct);
        Guid tokenId, hostId;
        string keyFingerprint;
        string? instance;
        Guid? replacement;
        await using (var q = new NpgsqlCommand("select id,host_id,key_fingerprint,instance_name,replacement_for,used_at,revoked_at,expires_at from sli_agent_enrollment_tokens where token_hash=@hash for update", connection, transaction))
        {
            q.Parameters.AddWithValue("hash", digest);
            await using var reader = await q.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct) || !reader.IsDBNull(5) || !reader.IsDBNull(6) || reader.GetFieldValue<DateTime>(7) <= DateTime.UtcNow) throw RejectToken();
            tokenId = reader.GetGuid(0); hostId = reader.GetGuid(1); keyFingerprint = reader.GetString(2);
            instance = reader.IsDBNull(3) ? null : reader.GetString(3);
            replacement = reader.IsDBNull(4) ? null : reader.GetGuid(4);
        }
        ValidateInstance(instance);
        var requestedInstance = StringValue(body, "instance_name");
        if (body["instance_name"] is not null && requestedInstance is null) throw new AgentCertificateException("invalid_agent_instance_name");
        ValidateInstance(requestedInstance);
        if (requestedInstance != instance) throw new AgentCertificateException("agent_instance_name_mismatch");
        var csr = AgentCertificateAuthority.ParseCsr(StringValue(body, "csr_pem"), hostId);
        var received = SHA256.HashData(csr.PublicKey.ExportSubjectPublicKeyInfo());
        if (!CryptographicOperations.FixedTimeEquals(received, Convert.FromHexString(keyFingerprint))) throw new AgentCertificateException("agent_csr_key_mismatch");
        var hostName = HostName(StringValue(body, "reported_hostname"));
        string? versionText=StringValue(body,"agent_version"); Version? agentVersion=null;
        if(body.ContainsKey("agent_version") && (versionText is null || versionText.Length>32 || !Version.TryParse(versionText,out agentVersion) || agentVersion.Build<0 || agentVersion.Revision>=0))
            throw new AgentCertificateException("invalid_agent_module_config");
        string? approved;
        await using (var q = new NpgsqlCommand("select details->>'registration_host_name' from sli_agent_audit where target=@id and action='token_create' order by id desc limit 1", connection, transaction))
        { q.Parameters.AddWithValue("id", tokenId.ToString()); approved = await q.ExecuteScalarAsync(ct) as string; }
        var role = body.ContainsKey("machine_role") ? StringValue(body, "machine_role") : "workstation";
        if (role is not ("workstation" or "domain_controller")) throw new AgentCertificateException("invalid_agent_module_config");
        var dc=role=="domain_controller" && hostName is not null ? await ResolveDcAsync(connection,transaction,hostName,ct) : null;
        if(dc is {} configuredDc && configuredDc.Name.Length>128)throw new AgentCertificateException("invalid_agent_module_config");
        if (approved is not null && !string.Equals(approved,hostName,StringComparison.OrdinalIgnoreCase))
        {
            var approvedDc=dc is not null ? await ResolveDcAsync(connection,transaction,approved,ct) : null;
            if(approvedDc is null || approvedDc.Value.Server!=dc!.Value.Server) throw new AgentCertificateException("agent_registration_name_mismatch");
        }
        if (hostName is not null) await AdvisoryAsync(connection, transaction, $"sli-agent-registration:{ca.RootFingerprint}:{hostName.ToLowerInvariant()}:{instance ?? ""}", ct);
        if(dc is not null) await AdvisoryAsync(connection,transaction,$"sli-agent-dc:{ca.RootFingerprint}:{dc.Value.Server}",ct);
        await AdvisoryAsync(connection, transaction, "sli-agent-host:" + hostId, ct);
        Guid? duplicate=null;
        await using (var q = new NpgsqlCommand(instance is null ? "select id from sli_agents where host_id=@host order by id limit 1" : "select id from sli_agents where host_id=@host and (instance_name=@instance or key_fingerprint=@key) order by id limit 1", connection, transaction))
        {
            q.Parameters.AddWithValue("host", hostId);
            if (instance is not null) { q.Parameters.AddWithValue("instance", instance); q.Parameters.AddWithValue("key", keyFingerprint); }
            duplicate=await q.ExecuteScalarAsync(ct) as Guid?;
        }
        if(duplicate is {} duplicateId)
        {
            if(dc is {} requested && await ResolveDcAsync(connection,transaction,"",ct,duplicateId) is {} existing && requested.Server!=existing.Server)
            {
                await using var conflict=new NpgsqlCommand("update sli_agents set rights_probe=jsonb_set(rights_probe,'{identity_conflict}',@details::jsonb) where id=@id",connection,transaction);
                conflict.Parameters.AddWithValue("id",duplicateId);
                conflict.Parameters.AddWithValue("details",new JsonObject { ["computer"]=existing.Name,["other_computer"]=requested.Name,["observed_at"]=DateTimeOffset.UtcNow.ToString("O") }.ToJsonString());
                await conflict.ExecuteNonQueryAsync(ct);
                // The endpoint commits this observation, then returns a refusal.
                // No token, certificate, assignment or agent is issued.
                return new JsonObject { ["error"]="agent_identity_computer_conflict" };
            }
            throw new AgentCertificateException("agent_host_already_enrolled",409);
        }
        await using (var q = new NpgsqlCommand("select expires_at > clock_timestamp() from sli_agent_enrollment_tokens where id=@id", connection, transaction))
        { q.Parameters.AddWithValue("id", tokenId); if ((bool)(await q.ExecuteScalarAsync(ct) ?? false) == false) throw RejectToken(); }
        var agentId = Guid.NewGuid();
        using var cert = ca.Issue(csr, agentId, hostId);
        int rate = role == "domain_controller" ? AdDcConfig.DefaultRateLimitPerMinute : 120;
        var control = "{\"state\":\"" + (replacement is null ? "active" : "drain") + "\",\"interval_seconds\":60,\"batch_size\":32,\"rate_limit_per_minute\":" + rate + ",\"spool_max_bytes\":67108864,\"manage_windows_audit\":true,\"audit_process_command_line\":false}";
        await using (var q = new NpgsqlCommand("insert into sli_agents(id,host_id,key_fingerprint,instance_name,registration_host_name,collection_policy,last_seen) values(@id,@host,@key,@instance,@name,@control::jsonb,clock_timestamp())", connection, transaction))
        {
            q.Parameters.AddWithValue("id", agentId); q.Parameters.AddWithValue("host", hostId); q.Parameters.AddWithValue("key", keyFingerprint);
            q.Parameters.Add("instance", NpgsqlDbType.Text).Value = (object?)instance ?? DBNull.Value;
            q.Parameters.Add("name", NpgsqlDbType.Text).Value = (object?)hostName ?? DBNull.Value;
            q.Parameters.AddWithValue("control", control); await q.ExecuteNonQueryAsync(ct);
        }
        Guid? newer=null;
        if (approved is not null && replacement is null)
            newer=await ReplaceRegistrationAsync(connection,transaction,agentId,hostName!,instance,tokenId,ct,dc?.Server,agentVersion);
        if (replacement is null && !await CopyTemplateAsync(connection, transaction, tokenId, agentId, ct))
            await AssignDefaultAsync(connection, transaction, tokenId, agentId, hostId,dc?.Name ?? hostName, role!, control, ct,approved is not null ? dc?.Server : null);
        var serial = await StoreCertificateAsync(connection, transaction, agentId, cert, ct);
        if(newer is not null)await RetireRegistrationAsync(connection,transaction,agentId,newer.Value,"enrollment:"+tokenId,true,ct);
        await using (var q = new NpgsqlCommand("update sli_agent_enrollment_tokens set used_at=clock_timestamp(),enrolled_agent_id=@agent where id=@id; insert into sli_agent_group_members(agent_id,group_id) select @agent,t.group_id from sli_agent_group_approval_links a join sli_agent_group_requests r on r.id=a.request_id join sli_agent_group_tokens t on t.id=r.token_id where a.enrollment_token_id=@id", connection, transaction))
        { q.Parameters.AddWithValue("agent", agentId); q.Parameters.AddWithValue("id", tokenId); await q.ExecuteNonQueryAsync(ct); }
        await AuditAsync(connection, transaction, "issue", "enrollment:" + tokenId, agentId.ToString(), new JsonObject { ["serial"] = serial, ["registration_ca_sha256"] = ca.RootFingerprint,["agent_version"]=versionText,["server_id"]=dc?.Server }, ct);
        if(approved is not null && dc is {} recoveredDc && replacement is null && newer is null)
        {
            var recoveries=new List<(Guid Id,string Source)>();
            await using(var query=new NpgsqlCommand("""
                select a.id,b.source_name from sli_agents a join sli_agent_module_bindings b on b.agent_id=a.id
                where a.status='replaced' and b.module_id='sli.windows.ad-dc'
                    and a.rights_probe->>'certificate_reissue_required'='true' order by a.id
                """,connection,transaction))
            await using(var rows=await query.ExecuteReaderAsync(ct))
                while(await rows.ReadAsync(ct))recoveries.Add((rows.GetGuid(0),rows.GetString(1)));
            foreach(var recovery in recoveries)
                if((await ResolveDcAsync(connection,transaction,recovery.Source,ct,recovery.Id))?.Server==recoveredDc.Server)
                {
                    await using var clear=new NpgsqlCommand("update sli_agents set rights_probe=rights_probe-'certificate_reissue_required' where id=@id",connection,transaction);
                    clear.Parameters.AddWithValue("id",recovery.Id); await clear.ExecuteNonQueryAsync(ct);
                }
        }
        await AgentModuleAssignmentService.ReconcilePasswordDomainAsync(connection,transaction,agentId,ct);
        return CertificateResponse(cert, agentId, serial);
    }

    private static async Task LockGroupApprovalAsync(NpgsqlConnection c, NpgsqlTransaction t, string digest, CancellationToken ct)
    {
        Guid groupId; long computer; string? instance;
        await using (var q = new NpgsqlCommand("select r.token_id,r.computer_entity_id,r.instance_name from sli_agent_group_approval_links a join sli_agent_group_requests r on r.id=a.request_id join sli_agent_enrollment_tokens e on e.id=a.enrollment_token_id where e.token_hash=@hash", c, t))
        {
            q.Parameters.AddWithValue("hash", digest); await using var reader=await q.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct)) return;
            groupId=reader.GetGuid(0); computer=reader.GetInt64(1); instance=reader.IsDBNull(2)?null:reader.GetString(2);
        }
        long domain; long[] ous, selected;
        await using (var q = new NpgsqlCommand("select domain_id,ou_entity_ids,computer_entity_ids,revoked_at,expires_at from sli_agent_group_tokens where id=@id for update", c, t))
        {
            q.Parameters.AddWithValue("id", groupId); await using var reader=await q.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct) || !reader.IsDBNull(3) || reader.GetFieldValue<DateTime>(4)<=DateTime.UtcNow) throw RejectToken();
            domain=reader.GetInt64(0); ous=reader.GetFieldValue<long[]>(1); selected=reader.GetFieldValue<long[]>(2);
        }
        var dn=await DirectoryDnAsync(c,t,computer,domain,false,ct);
        if (selected.Length>0 && !selected.Contains(computer)) throw new AgentCertificateException("invalid_group_enrollment_scope");
        if (ous.Length>0)
        {
            bool matches=false;
            foreach (var ou in ous)
            {
                var suffix=await DirectoryDnAsync(c,t,ou,domain,true,ct);
                if (dn.Length>suffix.Length && dn.TakeLast(suffix.Length).SequenceEqual(suffix)) { matches=true; break; }
            }
            if (!matches) throw new AgentCertificateException("invalid_group_enrollment_scope");
        }
        await AdvisoryAsync(c,t,$"sli-agent-computer:{computer}:{instance ?? ""}",ct);
        await using var duplicate=new NpgsqlCommand("select issued.target from sli_agent_audit issued join sli_agent_group_approval_links a on issued.actor='enrollment:' || a.enrollment_token_id::text join sli_agent_group_requests r on r.id=a.request_id where issued.action='issue' and r.computer_entity_id=@computer and r.instance_name is not distinct from @instance limit 1",c,t);
        duplicate.Parameters.AddWithValue("computer",computer); duplicate.Parameters.Add("instance",NpgsqlDbType.Text).Value=(object?)instance??DBNull.Value;
        if (await duplicate.ExecuteScalarAsync(ct) is not null) throw RejectToken();
    }
    private static async Task<string[]> DirectoryDnAsync(NpgsqlConnection c,NpgsqlTransaction t,long entity,long domain,bool ou,CancellationToken ct)
    {
        try { return (await Groups.AgentGroupDirectory.ResolveAsync(c,t,entity,domain,ou,ct)).Dn; }
        catch (Control.AgentControlException) { throw new AgentCertificateException("invalid_group_enrollment_scope"); }
    }
    public static string[] ParseDirectoryDn(string? raw, bool ou)
    {
        if (string.IsNullOrEmpty(raw)) throw new FormatException();
        var count = 0;
        foreach (var rune in raw.EnumerateRunes())
            if (++count > 2048) throw new FormatException();
        var parts=new List<string>(); var current=new System.Text.StringBuilder(); bool escaped=false;
        foreach (char ch in raw)
        {
            if (ch==',' && !escaped) { parts.Add(UnicodeCaseFold.TrimAndFold(current.ToString())); current.Clear(); continue; }
            current.Append(ch); escaped=ch=='\\' && !escaped;
        }
        if (escaped) throw new FormatException(); parts.Add(UnicodeCaseFold.TrimAndFold(current.ToString()));
        if (parts.Any(p => !p.Contains('=') || p[(p.IndexOf('=')+1)..].Length==0) || (ou && !parts[0].StartsWith("ou=",StringComparison.Ordinal))) throw new FormatException();
        return parts.ToArray();
    }
    private static async Task<bool> CopyTemplateAsync(NpgsqlConnection c,NpgsqlTransaction t,Guid token,Guid agent,CancellationToken ct)
    {
        Guid id; long version; string modules,control,hash;
        await using (var q=new NpgsqlCommand("select t.id,t.version,t.assigned_modules,t.collection_policy,t.policy_sha256 from sli_agent_onboarding_copies c join sli_agent_policy_templates t on t.id=c.template_id and t.version=c.template_version where c.enrollment_token_id=@token",c,t))
        {
            q.Parameters.AddWithValue("token",token); await using var reader=await q.ExecuteReaderAsync(ct); if (!await reader.ReadAsync(ct)) return false;
            id=reader.GetGuid(0); version=reader.GetInt64(1); modules=reader.GetString(2); control=reader.GetString(3); hash=reader.GetString(4);
        }
        await using (var q=new NpgsqlCommand("update sli_agents set assigned_modules=@modules::jsonb,collection_policy=@control::jsonb,template_id=@id,template_version=@version,template_sha256=@hash where id=@agent; insert into sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy) values(@agent,1,@modules::jsonb,@control::jsonb)",c,t))
        { q.Parameters.AddWithValue("modules",modules); q.Parameters.AddWithValue("control",control); q.Parameters.AddWithValue("id",id); q.Parameters.AddWithValue("version",version); q.Parameters.AddWithValue("hash",hash); q.Parameters.AddWithValue("agent",agent); await q.ExecuteNonQueryAsync(ct); }
        await AuditAsync(c,t,"template_copy","enrollment:"+token,agent.ToString(),new JsonObject { ["result"]="copied",["revision"]=1,["template_id"]=id.ToString(),["template_version"]=version,["policy_sha256"]=hash },ct);
        return true;
    }
    internal static string CollectionProfile(IConfiguration? configuration)
    {
        var profile=configuration?["Sli:CollectionProfile"] ?? configuration?["SLI_COLLECTION_PROFILE"] ?? "beta";
        return profile is "beta" or "full" ? profile : throw new ServerConfigurationException("Sli:CollectionProfile");
    }
    internal static JsonArray DefaultModules(IConfiguration? configuration,string role,Guid host,string? hostName,JsonObject? domain)
    {
        var beta=CollectionProfile(configuration)=="beta";
        if(beta && role=="workstation") return new JsonArray();
        string module; JsonObject config;
        if (role=="workstation")
        {
            module="sli.workstations";
            config=JsonNode.Parse("{\"policy_revision\":\"2\",\"allow_event_ids\":null,\"deny_event_ids\":[],\"allow_process_paths\":[],\"deny_process_paths\":[],\"rate_limits\":{\"4104\":10},\"rate_window_seconds\":60,\"batch_size\":32,\"channel_generations\":{},\"protected_services\":[],\"families\":{\"logons\":true,\"processes\":true,\"usb\":true,\"local_admins\":true,\"protection\":true},\"family_filters\":{}}")!.AsObject();
        }
        else
        {
            module="sli.windows.ad-dc"; var name=hostName is { Length: <=128 } ? hostName : host.ToString();
            config=new JsonObject { ["policy_revision"]="2",["batch_size"]=32,["channel_generations"]=new JsonObject(),["initial_read_hours"]=24,["source_name"]=name,["connect_address"]=name,["channels"]=new JsonObject { ["Security"]=true,["System"]=true,["Directory Service"]=true },["allow_event_ids"]=null };
            if(beta) config["allow_event_ids"]=new JsonArray(BetaEventIds().Select(id=>(JsonNode?)JsonValue.Create(id)).ToArray());
        }
        var modules=new JsonArray(new JsonObject { ["module_id"]=module,["enabled"]=true,["config"]=config.DeepClone() });
        if(beta && role=="domain_controller" && domain is not null)
            foreach(var snapshot in new[] { SnapshotPolicy.Ad,SnapshotPolicy.Gpo })
            {
                var input=new JsonObject { ["source_instance_id"]=host.ToString(),["domain_sid"]=domain["domain_sid"]!.DeepClone(),["domain_dns"]=domain["fqdn"]!.DeepClone(),["scope"]="domain",["policy_revision"]="2" };
                if(snapshot==SnapshotPolicy.Ad) input["families"]=new JsonArray(SnapshotPolicy.AdFamilies.Where(f=>f!="ad_vpn_membership").Select(f=>(JsonNode?)JsonValue.Create(f)).ToArray());
                var snapshotConfig=SnapshotIngressPolicy.Parse(snapshot,input).Config;
                modules.Add(new JsonObject { ["module_id"]=snapshot,["enabled"]=true,["config"]=snapshotConfig });
            }
        return modules;
    }
    internal static int[] BetaEventIds()
    {
        var catalog=EventCatalog.Load();
        return catalog.Channels.SelectMany(catalog.EventIds)
            .Distinct().Order().ToArray();
    }
    private async Task AssignDefaultAsync(NpgsqlConnection c,NpgsqlTransaction t,Guid token,Guid agent,Guid host,string? hostName,string role,string control,CancellationToken ct,long? approvedServer)
    {
        JsonObject? domain=null;
        if(CollectionProfile(configuration)=="beta" && role=="domain_controller")
        {
            // Only owner-approved enrollment scope may authorize snapshots.
            // reported_hostname and machine_role alone are not an AD scope.
            await using var read=new NpgsqlCommand("""
                select distinct d.domain_sid,lower(d.fqdn) from domains d
                where d.domain_sid is not null and (
                    exists(select 1 from sli_agent_group_approval_links a
                        join sli_agent_group_requests r on r.id=a.request_id
                        join sli_agent_group_tokens g on g.id=r.token_id
                        where a.enrollment_token_id=@token and g.domain_id=d.id)
                    or exists(select 1 from sli_agent_audit a join servers s
                        on s.id=@server
                        where a.target=@token::text and a.action='token_create'
                        and s.domain_id=d.id and s.role='domain_controller' and s.is_active))
                order by d.domain_sid,lower(d.fqdn) limit 2
                """,c,t);
            read.Parameters.AddWithValue("token",token);
            read.Parameters.Add("server",NpgsqlDbType.Bigint).Value=(object?)approvedServer ?? DBNull.Value;
            await using var reader=await read.ExecuteReaderAsync(ct);
            if(await reader.ReadAsync(ct))
            {
                domain=new JsonObject { ["domain_sid"]=reader.GetString(0),["fqdn"]=reader.GetString(1) };
                if(await reader.ReadAsync(ct)) domain=null;
            }
        }
        var modules=DefaultModules(configuration,role,host,hostName,domain);
        if(modules.Count==0) return;
        foreach(var item in modules.OfType<JsonObject>().Where(m=>m["module_id"]!.GetValue<string>() is SnapshotPolicy.Ad or SnapshotPolicy.Gpo).ToArray())
        {
            var module=item["module_id"]!.GetValue<string>(); var config=item["config"]!.AsObject();
            try { await AgentSnapshotAssignment.ValidateAsync(c,t,agent,module,config,true,ct); }
            catch(AgentControlException error) when(error.Message=="agent_snapshot_collector_conflict")
            { modules.Remove(item); continue; }
            await AgentSnapshotAssignment.PublishAsync(c,t,agent,module,config,true,ct);
        }
        await using (var q=new NpgsqlCommand("insert into sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy) values(@id,1,'[]'::jsonb,@control::jsonb),(@id,2,@modules::jsonb,@control::jsonb) on conflict(agent_id,revision) do nothing; update sli_agents set assigned_modules=@modules::jsonb,policy_revision=2 where id=@id",c,t))
        { q.Parameters.AddWithValue("id",agent); q.Parameters.AddWithValue("control",control); q.Parameters.AddWithValue("modules",modules.ToJsonString()); await q.ExecuteNonQueryAsync(ct); }
        foreach(var item in modules.OfType<JsonObject>())
        {
            var module=item["module_id"]!.GetValue<string>(); var config=item["config"]!.AsObject();
            var configHash=Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(PythonJson(config))));
            var details=new JsonObject { ["module_id"]=module,["enabled"]=true,["policy_sha256"]=configHash,["revision"]=2,["changed_fields"]=module=="sli.windows.ad-dc"?new JsonArray("connect_address","source_name"):new JsonArray() };
            foreach(var key in new[] { "families","channels" }) if(config[key] is not null) details[key]=config[key]!.DeepClone();
            await AuditAsync(c,t,"module_assign","enrollment:"+token,agent.ToString(),details,ct);
        }
    }
    private static string PythonJson(JsonNode? value)
    {
        if (value is JsonObject o) return "{"+string.Join(", ",o.OrderBy(p=>p.Key,StringComparer.Ordinal).Select(p=>System.Text.Json.JsonSerializer.Serialize(p.Key)+": "+PythonJson(p.Value)))+"}";
        if (value is JsonArray a) return "["+string.Join(", ",a.Select(PythonJson))+"]";
        return value?.ToJsonString() ?? "null";
    }
    internal static async Task<(long Server,string Name,long Domain,long? Site)?> ResolveDcAsync(NpgsqlConnection c,NpgsqlTransaction t,string name,CancellationToken ct,Guid? agent=null)
    {
        await using var query=new NpgsqlCommand("""
            select id,hostname,domain_id,site_id from servers where role='domain_controller' and is_active and coalesce(
                id::text=(select details->>'server_id' from sli_agent_audit where target=@agent and action='issue' order by id desc limit 1), (
                lower(@name) in (lower(hostname),lower(fqdn))
                or strpos(@name,'.')=0 and lower(@name)=split_part(lower(coalesce(nullif(fqdn,''),hostname)),'.',1)
                or strpos(coalesce(nullif(fqdn,''),hostname),'.')=0 and lower(hostname)=split_part(lower(@name),'.',1)))
            order by id limit 2
            """,c,t);
        query.Parameters.AddWithValue("name",name);
        query.Parameters.Add("agent",NpgsqlDbType.Text).Value=(object?)agent?.ToString() ?? DBNull.Value;
        await using var reader=await query.ExecuteReaderAsync(ct);
        if(!await reader.ReadAsync(ct))return null;
        var result=(reader.GetInt64(0),reader.GetString(1),reader.GetInt64(2),reader.IsDBNull(3)?(long?)null:reader.GetInt64(3));
        return await reader.ReadAsync(ct) ? null : result;
    }
    private async Task<Guid?> ReplaceRegistrationAsync(NpgsqlConnection c,NpgsqlTransaction t,Guid agent,string hostName,string? instance,Guid token,CancellationToken ct,long? server=null,Version? version=null)
    {
        var others=new List<(Guid Id,Version? Version,bool Live,bool DotNet,DateTime? Packet)>();
        await using (var q=new NpgsqlCommand("""
            select a.id,coalesce(a.rights_probe->>'agent_version',
                (select version from sli_agent_update_results v where v.agent_id=a.id order by observed_at desc limit 1),
                (select details->>'agent_version' from sli_agent_audit v where v.target=a.id::text and action='issue' order by id desc limit 1)),
                a.last_seen,coalesce((a.collection_policy->>'interval_seconds')::bigint,60),
                coalesce((a.rights_probe->>'runtime_handoff_supported')::boolean,false)
                    or a.rights_probe->>'agent_version' is not null
                    or exists(select 1 from sli_agent_audit v where v.target=a.id::text and v.action='issue' and v.details->>'agent_version' is not null),
                (select max(t) from (select max(received_at) t from sli_agent_receipts where agent_id=a.id
                    union all select max(received_at) from sli_agent_stream_receipts where agent_id=a.id) p)
            from sli_agents a where a.id<>@id and a.status='active' and
            """ + " " +
            (server is null ? "lower(a.registration_host_name)=lower(@name) and a.instance_name is not distinct from @instance" : "exists(select 1 from sli_agent_module_bindings b where b.agent_id=a.id and b.module_id='sli.windows.ad-dc')") +
            " and exists(select 1 from sli_agent_audit issued where issued.target=a.id::text and issued.action='issue' and issued.details->>'registration_ca_sha256'=@scope) order by a.id for update of a",c,t))
        {
            q.Parameters.AddWithValue("id",agent); q.Parameters.AddWithValue("name",hostName); q.Parameters.Add("instance",NpgsqlDbType.Text).Value=(object?)instance??DBNull.Value; q.Parameters.AddWithValue("scope",ca.RootFingerprint);
            await using var reader=await q.ExecuteReaderAsync(ct); while(await reader.ReadAsync(ct)) others.Add((reader.GetGuid(0),!reader.IsDBNull(1) && Version.TryParse(reader.GetString(1),out var prior) ? prior : null,RecentContact(reader.IsDBNull(2)?null:reader.GetDateTime(2),reader.GetInt64(3),DateTime.UtcNow),reader.GetBoolean(4),reader.IsDBNull(5)?null:reader.GetDateTime(5)));
        }
        var matching=new List<(Guid Id,Version? Version,bool Live,bool DotNet,DateTime? Packet)>();
        foreach (var candidate in others)
        {
            var id=candidate.Id;
            if(server is not null)
            {
                string? source;
                await using(var binding=new NpgsqlCommand("select source_name from sli_agent_module_bindings where agent_id=@id and module_id='sli.windows.ad-dc'",c,t))
                { binding.Parameters.AddWithValue("id",id); source=await binding.ExecuteScalarAsync(ct) as string; }
                if(source is null || (await ResolveDcAsync(c,t,source,ct,id))?.Server!=server)continue;
            }
            matching.Add(candidate);
        }
        // This enrollment is a current authenticated contact. A stale higher version
        // must not prevent reinstalling the computer. Only equal generations compare versions.
        var newer=server is not null ? matching.Where(a=>a.Live && (a.DotNet && version is null || a.DotNet==(version is not null) && (a.Version>version || a.Version==version && a.Packet is not null)))
            .OrderByDescending(a=>a.DotNet).ThenByDescending(a=>a.Version).ThenByDescending(a=>a.Packet).FirstOrDefault() : default;
        if(newer.Id!=Guid.Empty)return newer.Id;
        foreach(var prior in matching)
            await RetireRegistrationAsync(c,t,prior.Id,agent,"enrollment:"+token,server is not null,ct);
        return null;
    }
    private static async Task RetireRegistrationAsync(NpgsqlConnection c,NpgsqlTransaction t,Guid id,Guid agent,string actor,bool dc,CancellationToken ct)
    {
            await Sli.Server.Agents.Control.AgentManagementService.LockImportAsync(c,t,id,ct);
            await using (var update=new NpgsqlCommand("update sli_agents set status=@status where id=@id",c,t)) { update.Parameters.AddWithValue("id",id); update.Parameters.AddWithValue("status",dc ? "replaced" : "disabled"); await update.ExecuteNonQueryAsync(ct); }
            await using(var snapshots=new NpgsqlCommand("update sli_agent_snapshot_bindings set enabled=false where agent_id=@id",c,t))
            { snapshots.Parameters.AddWithValue("id",id); await snapshots.ExecuteNonQueryAsync(ct); }
            await AuditAsync(c,t,"disable",actor,id.ToString(),new JsonObject { ["reason"]="registration_replaced",["replaced_by"]=agent.ToString(),["tail_import"]=false },ct);
    }
    private static string? StringValue(JsonObject body, string key)
    {
        try { return body[key]?.GetValue<string>(); } catch (InvalidOperationException) { return null; }
    }
    private static AgentCertificateException RejectToken() => new("enrollment_token_rejected", 401);
    private static void ValidateInstance(string? name)
    {
        if (name is not null && !Regex.IsMatch(name, "^[a-z0-9][a-z0-9_-]{0,47}\\z", RegexOptions.CultureInvariant)) throw new AgentCertificateException("invalid_agent_instance_name");
    }
    private static string? HostName(string? value)
    {
        if (value is null || value.Length is < 1 or > 253 || Guid.TryParse(value, out _) ||
            value.Equals("localhost", StringComparison.OrdinalIgnoreCase) || value.Equals("localhost.localdomain", StringComparison.OrdinalIgnoreCase) || value.Equals("unknown", StringComparison.OrdinalIgnoreCase) ||
            Regex.IsMatch(value, "^[0-9]+(?:\\.[0-9]+){3}\\z", RegexOptions.CultureInvariant) ||
            value.Split('.').Any(label => !Regex.IsMatch(label, "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\z", RegexOptions.CultureInvariant))) return null;
        return value;
    }
    private static async Task AdvisoryAsync(NpgsqlConnection c, NpgsqlTransaction t, string value, CancellationToken ct)
    { await using var q = new NpgsqlCommand("select pg_advisory_xact_lock(hashtext(@value))", c, t); q.Parameters.AddWithValue("value", value); await q.ExecuteNonQueryAsync(ct); }
    private static async Task AuditAsync(NpgsqlConnection c, NpgsqlTransaction t, string action, string actor, string target, JsonObject details, CancellationToken ct)
    {
        await using var q = new NpgsqlCommand("insert into sli_agent_audit(action,actor,target,details) values(@action,@actor,@target,@details::jsonb)", c, t);
        q.Parameters.AddWithValue("action", action); q.Parameters.AddWithValue("actor", actor); q.Parameters.AddWithValue("target", target); q.Parameters.AddWithValue("details", details.ToJsonString()); await q.ExecuteNonQueryAsync(ct);
    }
    private static async Task<string> StoreCertificateAsync(NpgsqlConnection c, NpgsqlTransaction t, Guid agent, X509Certificate2 cert, CancellationToken ct)
    {
        var bytes=cert.GetSerialNumber(); Array.Reverse(bytes); var serial=Convert.ToHexStringLower(bytes).TrimStart('0'); if (serial.Length == 0) serial="0";
        await using var q = new NpgsqlCommand("insert into sli_agent_certificates(agent_id,serial,fingerprint,not_before,not_after) values(@id,@serial,@fp,@before,@after)", c, t);
        q.Parameters.AddWithValue("id", agent); q.Parameters.AddWithValue("serial", serial); q.Parameters.AddWithValue("fp", Convert.ToHexStringLower(SHA256.HashData(cert.RawData)));
        q.Parameters.AddWithValue("before", cert.NotBefore.ToUniversalTime()); q.Parameters.AddWithValue("after", cert.NotAfter.ToUniversalTime()); await q.ExecuteNonQueryAsync(ct); return serial;
    }
    private JsonObject CertificateResponse(X509Certificate2 cert, Guid agent, string serial) => new() {
        ["agent_id"] = agent.ToString(), ["serial"] = serial, ["certificate_pem"] = cert.ExportCertificatePem() + "\n", ["ca_chain_pem"] = ca.ChainPem(),
        ["expires_at"] = new DateTimeOffset(cert.NotAfter.ToUniversalTime()).ToString("yyyy-MM-dd'T'HH:mm:sszzz", System.Globalization.CultureInfo.InvariantCulture)
    };
    public async Task<JsonObject> RenewAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        X509Certificate2 certificate, JsonObject body, CancellationToken cancellationToken)
    {
        var agent = await identity.AuthenticateAsync(connection, transaction, certificate, true, cancellationToken);
        string? pem;
        try { pem = body["csr_pem"]?.GetValue<string>(); }
        catch (InvalidOperationException) { throw new AgentCertificateException("invalid_agent_csr"); }
        var csr = AgentCertificateAuthority.ParseCsr(pem, agent.HostId);
        using var issued = ca.Issue(csr, agent.Id, agent.HostId);
        var serialBytes = issued.GetSerialNumber();
        Array.Reverse(serialBytes);
        var serial = Convert.ToHexString(serialBytes).TrimStart('0').ToLowerInvariant();
        if (serial.Length == 0) serial = "0";
        var fingerprint = Convert.ToHexString(SHA256.HashData(issued.RawData)).ToLowerInvariant();
        var keyFingerprint = Convert.ToHexString(SHA256.HashData(csr.PublicKey.ExportSubjectPublicKeyInfo())).ToLowerInvariant();
        await using var insert = new NpgsqlCommand("insert into sli_agent_certificates(agent_id,serial,fingerprint,not_before,not_after) values(@agent,@serial,@fingerprint,@before,@after)", connection, transaction);
        insert.Parameters.AddWithValue("agent", agent.Id);
        insert.Parameters.AddWithValue("serial", serial);
        insert.Parameters.AddWithValue("fingerprint", fingerprint);
        insert.Parameters.AddWithValue("before", issued.NotBefore.ToUniversalTime());
        insert.Parameters.AddWithValue("after", issued.NotAfter.ToUniversalTime());
        await insert.ExecuteNonQueryAsync(cancellationToken);
        await using var update = new NpgsqlCommand("update sli_agents set key_fingerprint=@fingerprint where id=@agent", connection, transaction);
        update.Parameters.AddWithValue("fingerprint", keyFingerprint);
        update.Parameters.AddWithValue("agent", agent.Id);
        await update.ExecuteNonQueryAsync(cancellationToken);
        await using var audit = new NpgsqlCommand("insert into sli_agent_audit(action,actor,target,details) values('renew',@actor,@target,jsonb_build_object('serial',@serial::text))", connection, transaction);
        audit.Parameters.AddWithValue("actor", "agent:" + agent.Id);
        audit.Parameters.AddWithValue("target", agent.Id.ToString());
        audit.Parameters.AddWithValue("serial", serial);
        await audit.ExecuteNonQueryAsync(cancellationToken);
        return new JsonObject {
            ["agent_id"] = agent.Id.ToString(), ["serial"] = serial,
            ["certificate_pem"] = issued.ExportCertificatePem() + "\n", ["ca_chain_pem"] = ca.ChainPem(),
            ["expires_at"] = new DateTimeOffset(issued.NotAfter.ToUniversalTime()).ToString("yyyy-MM-dd'T'HH:mm:sszzz", System.Globalization.CultureInfo.InvariantCulture)
        };
    }
}
