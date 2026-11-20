using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Ad;
using HomeComputerSource = Sli.Server.Domains.HomeComputerSource;
using Sli.Server.Tests.Agents;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Tests.Ad;

// Port of tests/reporting/new_logon_pairs_native_fixture.py. Test data only;
// the caller cannot supply a DSN or a connection to an installed database.
internal static class NewLogonPairsNativeFixture
{
    internal static readonly string[] ContextTables = ["servers", "ad_context_runs", "entities_v2", "users_report_v2_snapshots", "computers_v6_source_snapshots"];
    internal sealed record Seed(long DomainId, long[] ServerIds, Dictionary<string, string> ComputerGuids);

    internal static JsonObject SyntheticSnapshot(DateTimeOffset observed, int population)
    {
        using var stream = typeof(NewLogonPairsNativeFixture).Assembly.GetManifestResourceStream("Sli.Server.Tests.Domains.home-computer-source.json")!;
        var snapshot = JsonNode.Parse(stream)!.AsObject();
        var template = snapshot["objects"]![0]!.DeepClone();
        string stamp = Iso(observed);
        var metadata = snapshot["metadata"]!;
        metadata["snapshot_id"] = Guid.NewGuid().ToString(); metadata["label"] = "T002 synthetic native CI";
        metadata["started_at"] = stamp; metadata["completed_at"] = stamp; metadata["object_count"] = population;
        foreach (var source in metadata["sources"]!.AsArray()) source!["counts"] = new JsonObject { [source.Text("status")!] = population };
        var objects = new JsonArray();
        for (int i = 0; i < population; i++)
        {
            var item = template.DeepClone().AsObject();
            string guid = Guid.Parse((i + 1).ToString("x32", CultureInfo.InvariantCulture)).ToString(), name = $"PC-{i}", dns = $"pc-{i}.example.test";
            // Documentation-only address space; no captured AD identities.
            string address = $"192.0.2.{i % 250 + 1}";
            item["id"] = guid; item["objectGuid"] = guid; item["name"] = name; item["dnsHostName"] = dns;
            item["deviceType"] = "workstation"; item["osName"] = "Windows 11 Pro"; item["osVersion"] = "10.0 (26100)";
            item["osBuild"] = "26100"; item["osFamily"] = "Windows 11"; item["ipv4s"] = new JsonArray(address); item["ou"] = "Workstations";
            item["distinguishedName"] = $"CN={name},OU=Workstations,DC=example,DC=test"; item["canonicalName"] = $"example.test/Workstations/{name}";
            item["description"] = "Synthetic native CI workstation"; item["location"] = "Synthetic";
            item["sid"] = $"S-1-5-21-100000001-200000002-300000003-{20000 + i}"; item["spns"] = new JsonArray($"HOST/{dns}");
            item["roleHint"] = "Workstation"; item["roleEvidence"] = "Synthetic Windows client OS";
            item["collectedAt"] = stamp; item["lastLogonTimestamp"] = stamp; item["exactLastLogon"] = stamp;
            item["classification"] = Obj(new { status = "observed", value = "workstation", rule_id = "device-classification/os-workstation-v1", evidence = new[] { "OperatingSystem is Windows client" } });
            foreach (var source in item["sources"]!.AsObject()) if (source.Value!["observed_at"] is not null) source.Value["observed_at"] = stamp;
            item["sources"]!["dns"]!["value"] = Obj(new { ipv4 = new[] { address }, ipv6 = System.Array.Empty<string>() });
            item["sources"]!["os"]!["value"] = Obj(new { name = "Windows 11 Pro", version = "10.0 (26100)", service_pack = "" });
            foreach (string key in new[] { "last_logon_timestamp", "exact_last_logon" }) item["sources"]![key]!["value"] = stamp;
            objects.Add(item);
        }
        snapshot["objects"] = objects;
        if (!HomeComputerSource.Valid(snapshot)) throw new InvalidOperationException("native fixture source contract invalid");
        return snapshot;
    }

    internal static async Task<Seed> SeedAsync(PostCollectionPostgres pg, DateTimeOffset observed, int population, CancellationToken ct)
    {
        if (population is < 2 or > 5000) throw new ArgumentOutOfRangeException(nameof(population));
        observed = observed.ToUniversalTime();
        // OpenAsync verifies this freshly started cluster's random ownership marker.
        await using var db = await pg.OpenAsync(ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        var baseline = await ReadAsync(db, "select id from domains where lower(fqdn)='example.test'", ct);
        if (baseline.Count != 1) throw new InvalidOperationException("native fixture requires migrated example.test baseline");
        long domain = baseline[0].Int("id");
        foreach (string table in ContextTables)
            if ((await ReadAsync(db, $"select 1 from {table} where domain_id=$1 limit 1", ct, domain)).Count != 0)
                throw new InvalidOperationException($"native fixture requires empty example.test {table}");

        var servers = new List<long>();
        for (int i = 1; i <= 2; i++)
            servers.Add((await ReadAsync(db, "insert into servers(domain_id,hostname,fqdn,role) values($1,$2,$3,'domain_controller') returning id", ct, domain, $"DC-{i}", $"dc-{i}.example.test"))[0].Int("id"));
        var users = Obj(new { users = Enumerable.Range(0, population).Select(i => new { samAccountName = $"synthetic-user-{i}" }) });
        await StoreUsersAsync(db, domain, observed, users, population, ct);
        Guid run = await StoreRunAsync(db, domain, observed, ct);
        await ExecuteAsync(db, "insert into ad_context_sections(run_id,section_name,status,record_count) values($1,'directory_accounts','complete',$2)", ct, run, population);
        await ExecuteAsync(db, "insert into storage_v2_entity_type(value) values('ad_computer') on conflict do nothing", ct);
        var snapshot = SyntheticSnapshot(observed, population);
        var guids = new Dictionary<string, string>();
        foreach (var item in snapshot["objects"]!.AsArray())
        {
            string guid = item.Text("objectGuid")!;
            guids[item.Text("name")!] = guid;
            var attrs = Obj(new { identity = new { object_guid = guid, object_sid = item.Text("sid") }, object_guid = guid, enabled = true,
                dns_host_name = item.Text("dnsHostName"), operating_system = item.Text("osName"), operating_system_version = item.Text("osVersion"),
                distinguished_name = item.Text("distinguishedName"), canonical_name = item.Text("canonicalName"), ip_addresses = item!["ipv4s"], last_logon_utc = Iso(observed) });
            long entity = (await ReadAsync(db, """
                insert into entities_v2(entity_type_id,natural_key,display_name,domain_id,first_seen_utc,last_seen_utc,source_core_sha256)
                select id,$1,$2,$3,$4,$5,decode($6,'hex') from storage_v2_entity_type where value='ad_computer' returning id
                """, ct, $"ad_computer:{guid}", item.Text("name"), domain, observed.AddDays(-31), observed, AdJobPlugin.Digest(attrs)))[0].Int("id");
            await ExecuteAsync(db, """
                insert into ad_context_entity_versions(entity_id,source_section,valid_from_utc,last_observed_at_utc,content_sha256,attributes_json,source_run_id)
                values($1,'directory_accounts',$2,$2,decode($3,'hex'),$4,$5)
                """, ct, entity, observed, AdJobPlugin.Digest(attrs), attrs, run);
            // The .NET retained-source reader resolves identities through these aliases.
            await ExecuteAsync(db, """
                insert into ad_context_entity_aliases(entity_id,domain_id,alias_type,alias_value,normalized_value,first_seen_utc,last_seen_utc,source_run_id)
                values($1,$2,'object_guid',$3,$3,$4,$4,$5)
                """, ct, entity, domain, guid, observed, run);
        }
        await StoreComputersAsync(db, domain, observed, snapshot, ct);
        await tx.CommitAsync(ct);
        return new(domain, servers.ToArray(), guids);
    }

    internal static async Task<Guid> StoreRunAsync(NpgsqlConnection db, long domain, DateTimeOffset observed, CancellationToken ct)
    {
        Guid run = Guid.NewGuid();
        await ExecuteAsync(db, """
            insert into ad_context_runs(run_id,source_pack_id,source_pack_version,domain_id,mode,observed_at_utc,bundle_sha256,status,completed_at)
            values($1,'t002-synthetic-native','1',$2,'full',$3,decode($4,'hex'),'completed',$3)
            """, ct, run, domain, observed, AdJobPlugin.Digest(new JsonObject()));
        return run;
    }

    internal static Task StoreUsersAsync(NpgsqlConnection db, long domain, DateTimeOffset observed, JsonObject payload, int population, CancellationToken ct) =>
        ExecuteAsync(db, """
            insert into users_report_v2_snapshots(domain_id,contract_id,schema_version,scope_json,scope_sha256,bucket_start_utc,captured_at_utc,source_observed_at_utc,source_state,user_count,payload_json,payload_sha256)
            values($1,'sli.users-report.v2',1,'{}'::jsonb,decode($2,'hex'),date_trunc('hour',$3::timestamptz),$3,$3,'complete',$4,$5,decode($6,'hex'))
            """, ct, domain, AdJobPlugin.Digest(new JsonObject()), observed, population, payload, AdJobPlugin.Digest(payload));

    internal static Task StoreComputersAsync(NpgsqlConnection db, long domain, DateTimeOffset observed, JsonObject snapshot, CancellationToken ct) =>
        ExecuteAsync(db, """
            insert into computers_v6_source_snapshots(domain_id,snapshot_uuid,schema_version,source_started_at_utc,source_completed_at_utc,captured_at_utc,
                query_dc,search_base,collector_version,collector_sha256,collection_status,base_inventory_status,object_count,source_options_json,payload_json,payload_sha256,collector_exit_code)
            values($1,$2,'2.0',$3,$3,$3,$4,null,$5,decode('caf0ee7e590e133a4e834bb31997e5253a5e707e347e677158260ab7085154d5','hex'),
                'complete','observed',$6,$7,$8,decode($9,'hex'),0)
            """, ct, domain, Guid.Parse(snapshot["metadata"].Text("snapshot_id")!), observed, snapshot["metadata"].Text("query_dc"), snapshot["metadata"].Text("collector_version"),
            snapshot["objects"]!.AsArray().Count, Obj(new { server = "dc-1.example.test", search_base = (string?)null, skip_dns = false, collect_ad_site = true, collect_exact_last_logon = true }), snapshot, AdJobPlugin.Digest(snapshot));

    internal static async Task ExecuteAsync(NpgsqlConnection db, string sql, CancellationToken ct, params object?[] args)
    {
        await using var command = new NpgsqlCommand(sql, db);
        foreach (object? arg in args)
            command.Parameters.Add(arg is JsonNode node ? new() { NpgsqlDbType = NpgsqlDbType.Jsonb, Value = node.ToJsonString() } : new() { Value = arg ?? DBNull.Value });
        await command.ExecuteNonQueryAsync(ct);
    }
}
