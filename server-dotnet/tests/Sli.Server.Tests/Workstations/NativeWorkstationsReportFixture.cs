using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Agents.Control;
using Sli.Server.Tests.Ad;

namespace Sli.Server.Tests.Workstations;

// Synthetic current bindings and canonical stored events in the caller's owned
// disposable database. The acceptance test exercises the real runtime reader.
internal static class NativeWorkstationsReportFixture
{
    internal const int Count = 205;
    internal const long ExactEvent = 9141701;
    internal static readonly Guid Agent = new("41700000-0000-4000-8000-000000000001");
    internal static readonly Guid Source = new("41800000-0000-4000-8000-000000000001");
    internal const string Host = "WS-WORKSPACE-001.example.test";

    internal static async Task<JsonObject> SeedAsync(NpgsqlConnection owner, CancellationToken ct)
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var repeatWindow = now.AddSeconds(-(now.ToUnixTimeSeconds() % 600)).AddMinutes(-10);
        var first = new DateTimeOffset(now.UtcDateTime.Date.AddDays(-20).AddHours(10), TimeSpan.Zero);
        var last = first.AddMinutes(4);
        var policy = AgentModuleAssignmentRules.NormalizeWorkstation(new JsonObject { ["policy_revision"] = "1" }, true);
        async Task Execute(string sql, params (string Name, object Value)[] values)
        {
            await using var command = new NpgsqlCommand(sql, owner);
            foreach (var (name, value) in values)
                if (value is JsonNode json) command.Parameters.AddWithValue(name, NpgsqlDbType.Jsonb, json.ToJsonString());
                else command.Parameters.AddWithValue(name, value);
            await command.ExecuteNonQueryAsync(ct);
        }
        await using var domainQuery = new NpgsqlCommand("select id from public.domains where fqdn='example.test'", owner);
        long domain = Convert.ToInt64(await domainQuery.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture);
        if (domain <= 0) throw new InvalidOperationException("The workstation fixture requires the migrated example.test domain.");
        await Execute("""
            update plugin_installations_v1 set desired_activation='enabled_manual',component_runtime='running'
                where plugin_id='sli.workstations';
            insert into servers(domain_id,hostname,fqdn,role,os_name,os_version)
                select @domain,'WS-WORKSPACE-'||lpad(n::text,3,'0')||'.example.test',
                    'WS-WORKSPACE-'||lpad(n::text,3,'0')||'.example.test','workstation','Windows 11','23H2'
                from generate_series(1,@count) n;
            insert into sli_agents(id,host_id,key_fingerprint,registration_host_name,last_seen,policy_revision,applied_policy_revision,assigned_modules)
                select ('41700000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
                    ('41800000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
                    encode(sha256(convert_to('workstation-workspace-fixture-'||n,'UTF8')),'hex'),
                    'WS-WORKSPACE-'||lpad(n::text,3,'0')||'.example.test',@now-interval '5 minutes',
                    case when n=1 then 2 else 1 end,1,
                    jsonb_build_array(jsonb_build_object('module_id','sli.workstations','enabled',true,'config',@policy::jsonb))
                from generate_series(1,@count) n;
            select public.set_workstation_journal_grant412(id,true) from sli_agents where id::text like '41700000-0000-4000-8000-%';
            update sli_agents set rights_probe='{"windows_product_type":"WinNT","windows_product":{"name":"Windows 11 Pro","version":"10.0.26100"}}'
                where id=@agent;
            """, ("domain", domain), ("count", Count), ("now", now.UtcDateTime), ("policy", policy), ("agent", Agent));
        await using (var bindings = new NpgsqlCommand("""
            select count(*) from sli_agents a
            cross join lateral public.workstation_journal_scope412(a.id,null,null) binding
            where a.id::text like '41700000-0000-4000-8000-%'
            """, owner))
            if (Convert.ToInt64(await bindings.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture) != Count)
                throw new InvalidOperationException("The workstation fixture must create all current authoritative bindings.");
        await using var serverQuery = new NpgsqlCommand("select id from servers where domain_id=@domain and hostname=@host", owner);
        serverQuery.Parameters.AddWithValue("domain", domain); serverQuery.Parameters.AddWithValue("host", Host);
        long server = Convert.ToInt64(await serverQuery.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture);
        JsonObject Method(string channel, string provider, string source) => new()
        {
            ["$server_id"] = server, ["$channel"] = channel, ["$provider"] = provider,
            ["$origin"] = new JsonObject { ["plugin_id"] = "sli.workstations", ["agent_id"] = Agent.ToString("D"),
                ["source_instance_id"] = source, ["source_generation"] = source }
        };
        var security = Method("Security", "Microsoft-Windows-Security-Auditing", Source.ToString("D"));
        var failedLogon = (JsonObject)security.DeepClone();
        failedLogon["$principals"] = new JsonObject
        {
            ["TargetUserName"] = "user", ["TargetDomainName"] = "EXAMPLE",
            ["SubjectUserName"] = "operator", ["SubjectDomainName"] = "EXAMPLE"
        };
        var service = Method("System", "Service Control Manager", Source.ToString("D"));
        var other = Method("System", "Service Control Manager", "41800000-0000-4000-8000-000000999999");
        const string sid = "S-1-5-21-100000001-200000002-300000003-1001";
        const string directorySid = "S-1-5-21-100000001-200000002-300000003-1002";
        var process = (JsonObject)security.DeepClone();
        process["$principals"] = new JsonObject
        {
            ["TargetUserSid"] = "S-1-0-0", ["TargetUserName"] = "-", ["TargetDomainName"] = "-",
            ["SubjectUserSid"] = sid, ["SubjectUserName"] = "user", ["SubjectDomainName"] = "WS-WORKSPACE-001"
        };
        var processFields = new JsonObject
        {
            ["NewProcessName"] = @"C:\Tools\editor.exe", ["ParentProcessName"] = @"C:\Windows\explorer.exe",
            ["CommandLine"] = "editor.exe draft.txt"
        };
        var directoryProcess = (JsonObject)security.DeepClone();
        directoryProcess["$principals"] = new JsonObject
        {
            ["TargetUserSid"] = directorySid, ["SubjectUserSid"] = sid,
            ["SubjectUserName"] = "user", ["SubjectDomainName"] = "WS-WORKSPACE-001"
        };
        var run = await NewLogonPairsNativeFixture.StoreRunAsync(owner, domain, now, ct);
        await Execute("""
            insert into ad_context_sections(run_id,section_name,status,record_count) values(@run,'directory_accounts','complete',1);
            insert into storage_v2_entity_type(value) values('ad_user') on conflict do nothing;
            insert into entities_v2(entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
                select id,'workstation-fixture-directory-user','Fixture directory user',@domain,sha256('fixture'::bytea)
                from storage_v2_entity_type where value='ad_user';
            insert into ad_context_entity_aliases(entity_id,domain_id,alias_type,alias_value,normalized_value,first_seen_utc,last_seen_utc,source_run_id)
                select id,domain_id,'object_sid',@sid,lower(@sid),@now,@now,@run
                from entities_v2 where natural_key='workstation-fixture-directory-user';
            insert into ad_context_entity_versions(entity_id,source_section,valid_from_utc,last_observed_at_utc,content_sha256,attributes_json,source_run_id)
                select id,'directory_accounts',@now,@now,sha256('fixture-account'::bytea),
                    '{"identity":{"kind":"ad_user"},"attributes":{"sam_account_name":"directory-user"}}',@run
                from entities_v2 where natural_key='workstation-fixture-directory-user';
            """, ("run", run), ("domain", domain), ("sid", directorySid), ("now", now.UtcDateTime));
        var otherSecurity = Method("Security", "Microsoft-Windows-Security-Auditing", "41800000-0000-4000-8000-000000999999");
        // Seed retained individual facts. Direct event_hot inserts deliberately
        // lose caller-supplied origins in the admission trigger; the existing
        // signed-packet integration test covers the actual hot ingestion path.
        await Execute("""
            select create_event_storage_partitions((@now-interval '1 day')::date,@now::date);
            select create_event_storage_partitions(@first::date,@first::date);
            insert into event_cold_facts(event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields)
                values(@event,@now-interval '5 minutes',7045,@domain,'EXAMPLE\\operator',null,null,@host,@service,'{}',
                    '{"ServiceName":"Workspace service","ImagePath":"C:\\Program Files\\Workspace\\service.exe"}'),
                    (@event+1,@repeat_window+interval '1 minute',4625,@domain,'EXAMPLE\\operator','EXAMPLE\\user','192.0.2.41',@host,@failed_logon,'{"Status":"0xc000006d"}','{"LogonType":"3"}'),
                    (@event+2,@repeat_window+interval '2 minutes',4625,@domain,'EXAMPLE\\operator','EXAMPLE\\user','192.0.2.41',@host,@failed_logon,'{"Status":"0xc000006d"}','{"LogonType":"3"}'),
                    (@event+3,@now-interval '2 minutes',7045,@domain,'OTHER-SOURCE',null,null,@host,@other,'{}','{}'),
                    (@event+4,@repeat_window+interval '4 minutes 1 second',4688,@domain,@sid,null,null,@host,@process,'{}',@process_fields),
                    (@event+5,@repeat_window+interval '4 minutes 12 seconds',4688,@domain,@sid,null,null,@host,@process,'{}',@process_fields),
                    (@event+6,@repeat_window+interval '5 minutes 1 second',4688,@domain,@sid,null,null,@host,@process,'{}',@process_fields),
                    (@event+7,@repeat_window+interval '4 minutes 20 seconds',4688,@domain,@sid,null,null,@host,@process,'{}',@process_fields-'CommandLine'),
                    (@event+8,@repeat_window+interval '6 minutes',6416,@domain,null,null,null,@host,@security,'{}',
                        '{"ClassName":"DiskDrive","ClassId":"fixture-class-id","DeviceDescription":"Example USB drive"}'),
                    (@event+9,@repeat_window+interval '7 minutes',4688,@domain,@sid,@directory_sid,null,@host,@directory_process,'{}',@process_fields);
            insert into event_cold_daily(day,grouping_key,event_kind,domain_id,actor,target,source,computer,method,outcome,event_count,first_seen_utc,last_seen_utc)
                values(@first::date,sha256(convert_to('workstation-workspace-daily','UTF8')),4624,@domain,
                    'EXAMPLE\\operator','EXAMPLE\\user','192.0.2.41',@host,@security,'{"LogonType":"10"}',37,@first,@last),
                    (@first::date,sha256(convert_to('workstation-workspace-service-logon','UTF8')),4624,@domain,
                    'EXAMPLE\\operator','EXAMPLE\\user',null,@host,@security,'{"LogonType":"5"}',1,@first,@last+interval '5 minutes'),
                    (@first::date,sha256(convert_to('workstation-workspace-other-logon','UTF8')),4624,@domain,
                    'OTHER-SOURCE',null,null,@host,@other_security,'{"LogonType":"11"}',1,@first,@last+interval '10 minutes');
            """, ("event", ExactEvent), ("now", now.UtcDateTime), ("first", first.UtcDateTime), ("last", last.UtcDateTime),
            ("domain", domain), ("host", Host), ("service", service), ("security", security), ("other", other),
            ("repeat_window", repeatWindow.UtcDateTime), ("failed_logon", failedLogon), ("process", process),
            ("sid", sid), ("process_fields", processFields), ("other_security", otherSecurity),
            ("directory_sid", directorySid), ("directory_process", directoryProcess));
        return new JsonObject
        {
            ["station_id"] = Agent.ToString("D"), ["agent_id"] = Agent.ToString("D"),
            ["source_instance_id"] = Source.ToString("D"), ["host_name"] = Host, ["domain_id"] = domain,
            ["server_id"] = server, ["fixture_count"] = Count, ["search"] = "WS-WORKSPACE-",
            ["from_utc"] = first.AddDays(-1).ToString("O", CultureInfo.InvariantCulture),
            ["to_utc"] = now.AddSeconds(1).ToString("O", CultureInfo.InvariantCulture),
            ["exact_event_id"] = ExactEvent, ["repeat_event_id"] = ExactEvent + 2, ["repeat_count"] = 2,
            ["group_day"] = first.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            ["group_summary_key"] = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
                first.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + ":" +
                Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("workstation-workspace-daily")))))),
            ["group_count"] = 37, ["event_count"] = 46, ["group_first_seen_utc"] = first.ToString("O", CultureInfo.InvariantCulture),
            ["group_last_seen_utc"] = last.ToString("O", CultureInfo.InvariantCulture)
        };
    }
}
