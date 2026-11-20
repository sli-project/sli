using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Infrastructure;
using Sli.Server.Storage.Archive;
using Sli.Server.Storage.EventReports;
using Sli.Server.Storage.History;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed partial class LifecycleRolePostgresTests
{
    internal static async Task SeedSnapshots(NpgsqlConnection db, CancellationToken ct)
    {
        await PostCollectionPostgres.Sql(db, """
            update domains set domain_sid='S-1-5-21-100000001-200000002-300000003' where fqdn='example.test';
            """, ct);
        for (int n = 1; n <= 128; n++) {
        var payload = new JsonObject { ["metadata"] = new JsonObject { ["collection_status"] = "complete", ["domain"] = "example.test" },
            ["users"] = new JsonArray(new JsonObject { ["objectGuid"] = "00000000-0000-4000-8000-000000000001", ["displayName"] = "Synthetic " + n,
                ["description"] = n % 2 == 0 ? new JsonArray(null, n, "synthetic", "synthetic") : null,
                ["manager"] = new JsonObject { ["id"] = n },
                ["sourceStates"] = new JsonObject { ["directory"] = new JsonObject { ["status"] = "observed" } },
                ["memberships"] = new JsonObject { ["status"] = "observed", ["direct"] = new JsonArray("synthetic-group", "synthetic-group", null, n) } }),
            ["groups"] = new JsonArray(new JsonObject { ["id"] = "synthetic-group", ["parentGroupIds"] = new JsonArray(null, 7, 7) }) };
        await using var snapshots = new NpgsqlCommand("""
            insert into users_report_v2_snapshots(snapshot_id,domain_id,contract_id,scope_json,scope_sha256,bucket_start_utc,captured_at_utc,
              source_observed_at_utc,source_state,user_count,payload_json,payload_sha256)
            select @n,id,'sli.users-report.v2','{}',sha256('{}'::bytea),date_trunc('day',now()-interval '160 days')+@n*interval '1 day',now(),now(),'complete',1,
              cast(@payload as jsonb),@hash from domains where fqdn='example.test';
            insert into ad_snapshot_manifests(manifest_id,domain_id,domain_sid,domain_dns,slot_start_utc,assembled_at_utc,contract_version,coverage_state,manifest_sha256)
            select @id,id,'S-1-5-21-100000001-200000002-300000003',fqdn,
              date_trunc('day',now()-interval '160 days')+@n*interval '1 day',now(),'sli.ad-snapshot-manifest/1.0','partial',sha256('synthetic'::bytea) from domains where fqdn='example.test';
            insert into ad_snapshot_manifest_sources(manifest_id,family,contract_id,source_id,observed_at_utc,source_state,payload_sha256)
            values(@id,'users_v2','sli.users-report.v2',cast(@n as text),now(),'complete',@hash);
            """, db);
        snapshots.Parameters.AddWithValue("payload", LifecycleJson.Canonical(payload)); snapshots.Parameters.AddWithValue("hash", Convert.FromHexString(LifecycleJson.Hash(payload)));
        snapshots.Parameters.AddWithValue("n", n); snapshots.Parameters.AddWithValue("id", Guid.Parse($"00000000-0000-4000-8000-{n:000000000000}"));
        await snapshots.ExecuteNonQueryAsync(ct);
        if (n >= 127) await SeedComputers(db, n, ct);
        }
        await SeedGpo(db, ct);
    }
    static async Task SeedComputers(NpgsqlConnection db, int n, CancellationToken ct)
    {
        Guid id = Guid.Parse($"00000000-0000-4000-8003-{n:000000000000}");
        var payload = new JsonObject { ["schema_version"] = "2.0", ["metadata"] = new JsonObject {
            ["snapshot_id"] = id.ToString("D"), ["collection_status"] = "complete", ["object_count"] = 1, ["domain"] = "example.test" },
            ["objects"] = new JsonArray(new JsonObject { ["objectGuid"] = "00000000-0000-4000-8000-000000000903", ["osVersion"] = n,
                ["spns"] = new JsonArray(null, "synthetic", "synthetic", n) }) };
        await using var command = new NpgsqlCommand("""
            insert into computers_v6_source_snapshots(domain_id,snapshot_uuid,source_started_at_utc,source_completed_at_utc,captured_at_utc,query_dc,
              collector_version,collector_sha256,collection_status,base_inventory_status,object_count,source_options_json,payload_json,payload_sha256,collector_exit_code)
            select id,@source,now(),now(),now(),'synthetic.example.test','synthetic',decode('caf0ee7e590e133a4e834bb31997e5253a5e707e347e677158260ab7085154d5','hex'),
              'complete','observed',1,'{"server":"synthetic.example.test","search_base":null,"skip_dns":true,"collect_ad_site":false,"collect_exact_last_logon":false}',
              cast(@payload as jsonb),@hash,0 from domains where fqdn='example.test';
            insert into ad_snapshot_manifest_sources(manifest_id,family,contract_id,source_id,observed_at_utc,source_state,payload_sha256)
            values(@manifest,'computers_v6','sli.ad-computers.snapshot/2.0',cast(@source as text),now(),'complete',@hash);
            """, db);
        command.Parameters.AddWithValue("source", id); command.Parameters.AddWithValue("manifest", Guid.Parse($"00000000-0000-4000-8000-{n:000000000000}"));
        command.Parameters.AddWithValue("payload", LifecycleJson.Canonical(payload)); command.Parameters.AddWithValue("hash", Convert.FromHexString(LifecycleJson.Hash(payload)));
        await command.ExecuteNonQueryAsync(ct);
    }
    static async Task SeedGpo(NpgsqlConnection db, CancellationToken ct)
    {
        await PostCollectionPostgres.Sql(db, """
            insert into sli_agents(id,host_id,key_fingerprint) values('00000000-0000-4000-8000-000000000900','00000000-0000-4000-8000-000000000901',repeat('a',64));
            insert into sli_agent_snapshot_bindings(agent_id,module_id,config) values('00000000-0000-4000-8000-000000000900','sli.gpo-snapshot','{"domain_sid":"S-1-5-21-100000001-200000002-300000003"}');
            """, ct);
        for (int n = 1; n <= 3; n++) {
            var payload = JsonNode.Parse("""
                {"schema_version":"sli.ad-gpo.snapshot/1.0","metadata":{"collection_status":"complete","domain":"example.test"},
                 "gpos":[{"id":"00000000-0000-4000-8000-000000000902","display_name":"Synthetic","computer":{"enabled":true,"directory_version":1,"sysvol_version":1}}],
                 "scopes":[],"links":[],"settings":[],"permissions":[],"wmi_filters":[],"source_states":{"gpo_list":{"status":"observed"}}}
                """)!.AsObject();
            payload["gpos"]![0]!["display_name"] = "Synthetic " + n;
            payload["gpos"]![0]!["versions"] = new JsonArray(null, n, n);
            await using var command = new NpgsqlCommand("""
                insert into ad_context_runs(run_id,source_pack_id,source_pack_version,domain_id,mode,observed_at_utc,bundle_sha256,status)
                select @run,'sli.gpo','1',id,'full',now(),@hash,'completed' from domains where fqdn='example.test';
                insert into gpo_report_v2_source_snapshots(domain_id,source_run_id,schema_version,collector_version,collection_status,source_started_at_utc,source_completed_at_utc,
                  source_observed_at_utc,gpo_count,scope_count,link_count,setting_count,permission_count,wmi_filter_count,payload_json,payload_sha256)
                select id,@run,'sli.ad-gpo.snapshot/1.0','synthetic','complete',now(),now(),now(),1,0,0,0,0,0,cast(@payload as jsonb),@hash from domains where fqdn='example.test';
                insert into sli_agent_snapshot_cycles(cycle_id,agent_id,module_id,slot_start_utc,domain_sid,policy,transport_state,completed_at,publication_state,published_at,gpo_source_run_id)
                values(@cycle,'00000000-0000-4000-8000-000000000900','sli.gpo-snapshot',@slot,'S-1-5-21-100000001-200000002-300000003',
                  '{"source_instance_id":"synthetic","domain_sid":"S-1-5-21-100000001-200000002-300000003","domain_dns":"example.test","scope":{}}','complete',now(),'published',now(),@run);
                """, db);
            command.Parameters.AddWithValue("payload", LifecycleJson.Canonical(payload)); command.Parameters.AddWithValue("hash", Convert.FromHexString(LifecycleJson.Hash(payload)));
            command.Parameters.AddWithValue("run", Guid.Parse($"00000000-0000-4000-8001-{n:000000000000}"));
            command.Parameters.AddWithValue("cycle", Guid.Parse($"00000000-0000-4000-8002-{n:000000000000}"));
            command.Parameters.AddWithValue("slot", $"2026-10-0{n}T00:00:00+00:00");
            await command.ExecuteNonQueryAsync(ct);
            if (n <= 2) {
                await using var member = new NpgsqlCommand("""
                    insert into ad_snapshot_manifest_sources(manifest_id,family,contract_id,source_id,observed_at_utc,source_state,payload_sha256)
                    values(@manifest,'gpo_v2','sli.ad-gpo.snapshot/1.0',cast(@source as text),now(),'complete',@hash)
                    """, db);
                member.Parameters.AddWithValue("manifest", Guid.Parse($"00000000-0000-4000-8000-{n + 126:000000000000}"));
                member.Parameters.AddWithValue("source", Guid.Parse($"00000000-0000-4000-8001-{n:000000000000}"));
                member.Parameters.AddWithValue("hash", Convert.FromHexString(LifecycleJson.Hash(payload)));
                await member.ExecuteNonQueryAsync(ct);
            }
        }
    }
}
