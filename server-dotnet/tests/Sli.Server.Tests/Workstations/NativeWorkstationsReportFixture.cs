using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Agents.Control;

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
            """, ("domain", domain), ("count", Count), ("now", now.UtcDateTime), ("policy", policy));
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
        var service = Method("System", "Service Control Manager", Source.ToString("D"));
        var other = Method("System", "Service Control Manager", "41800000-0000-4000-8000-000000999999");
        await Execute("""
            select create_event_storage_partitions((@now-interval '1 day')::date,@now::date);
            select create_event_storage_partitions(@first::date,@first::date);
            insert into event_hot(event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields)
                values(@event,@now-interval '5 minutes',7045,@domain,'EXAMPLE\\operator',null,null,@host,@service,'{}',
                    '{"ServiceName":"Workspace service","ImagePath":"C:\\Program Files\\Workspace\\service.exe"}'),
                    (@event+1,@now-interval '10 minutes',4625,@domain,'EXAMPLE\\operator','EXAMPLE\\user','192.0.2.41',@host,@security,'{"Status":"0xc000006d"}','{}'),
                    (@event+2,@now-interval '9 minutes',4625,@domain,'EXAMPLE\\operator','EXAMPLE\\user','192.0.2.41',@host,@security,'{"Status":"0xc000006d"}','{}'),
                    (@event+3,@now-interval '2 minutes',7045,@domain,'OTHER-SOURCE',null,null,@host,@other,'{}','{}');
            insert into event_cold_daily(day,grouping_key,event_kind,domain_id,actor,target,source,computer,method,outcome,event_count,first_seen_utc,last_seen_utc)
                values(@first::date,sha256(convert_to('workstation-workspace-daily','UTF8')),4624,@domain,
                    'EXAMPLE\\operator','EXAMPLE\\user','192.0.2.41',@host,@security,'{}',37,@first,@last);
            """, ("event", ExactEvent), ("now", now.UtcDateTime), ("first", first.UtcDateTime), ("last", last.UtcDateTime),
            ("domain", domain), ("host", Host), ("service", service), ("security", security), ("other", other));
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
            ["group_count"] = 37, ["event_count"] = 40, ["group_first_seen_utc"] = first.ToString("O", CultureInfo.InvariantCulture),
            ["group_last_seen_utc"] = last.ToString("O", CultureInfo.InvariantCulture)
        };
    }
}
