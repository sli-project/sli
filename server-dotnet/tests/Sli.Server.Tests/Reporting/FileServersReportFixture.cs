using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Server.Reporting.V2;

namespace Sli.Server.Tests.Reporting;

// Retained synthetic evidence shared by the read-contract and browser scenarios.
// The caller owns an isolated SqlPostgresFixture connection. No collector is enabled.
internal static class FileServersReportFixture
{
    internal static readonly Guid Agent = new("41600000-0000-4000-8000-000000000001");
    internal static readonly Guid Source = new("41600000-0000-4000-8000-000000000002");
    internal static readonly Guid Before = new("41600000-0000-4000-8000-000000000003");
    internal static readonly Guid Current = new("41600000-0000-4000-8000-000000000004");
    internal const string Scope = "file-servers-fixture";
    internal const string RootPath = @"C:\Shares\Finance";
    internal const string ObjectId = "00000001:0000000000000042";
    internal const string Subject = "S-1-5-21-100000001-200000002-300000003-1199";
    internal const long EventId = 9141601;

    internal static async Task<JsonObject> SeedAsync(NpgsqlConnection owner, CancellationToken ct)
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var first = new DateTimeOffset(now.Year, now.Month, now.Day, now.Hour, now.Minute, 10, TimeSpan.Zero).AddMinutes(-15);
        var last = first.AddSeconds(20);
        await using var domainQuery = new NpgsqlCommand("select id from public.domains where fqdn='example.test'", owner);
        long domain = Convert.ToInt64(await domainQuery.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture);
        if (domain <= 0) throw new InvalidOperationException("File server fixture requires the migrated example.test domain.");
        var root = new JsonObject
        {
            ["collection_scope_id"] = Scope, ["path"] = RootPath, ["share_name"] = "Finance",
            ["important"] = true
        };
        var aces = Enumerable.Range(0, 126)
            .Select(n => $"(A;;FR;;;S-1-5-21-100000001-200000002-300000003-{2000 + n})").ToArray();
        aces[0] = $"(D;;0x00000002;;;{Subject})";
        aces[1] = "(A;CIIO;FR;;;BA)";
        aces[2] = $"(A;ID;0x021f01ff;;;{Subject})";
        var oldAcl = "D:" + string.Concat(aces);
        aces[4] = "(A;;FW;;;S-1-5-21-100000001-200000002-300000003-2004)";
        var newAcl = "D:" + string.Concat(aces);

        async Task Execute(string sql, params (string Name, object Value)[] values)
        {
            await using var command = new NpgsqlCommand(sql, owner);
            foreach (var (name, value) in values)
                if (value is JsonNode json) command.Parameters.AddWithValue(name, NpgsqlDbType.Jsonb, json.ToJsonString());
                else command.Parameters.AddWithValue(name, value);
            await command.ExecuteNonQueryAsync(ct);
        }
        await Execute("""
            insert into public.sli_agents(id,host_id,key_fingerprint,registration_host_name,last_seen)
            values(@agent,@source,repeat('4',64),'FS-01.example.test',@now);
            """, ("agent", Agent), ("source", Source), ("now", now.UtcDateTime));

        foreach (var (id, revision, observed, dacl) in new[]
        {
            (Before, 1, now.AddHours(-2), oldAcl), (Current, 2, now.AddMinutes(-30), newAcl)
        })
        {
            var policy = new JsonObject
            {
                ["source_name"] = "FS-01.example.test", ["source_kind"] = "server",
                ["policy_revision"] = revision.ToString(CultureInfo.InvariantCulture),
                ["roots"] = new JsonArray(root.DeepClone())
            };
            var snapshot = new JsonObject
            {
                ["contract_id"] = "sli.file-audit.inventory.v1", ["collection_scope_id"] = Scope,
                ["policy_revision"] = revision.ToString(CultureInfo.InvariantCulture),
                ["observed_at_utc"] = observed.ToString("O", CultureInfo.InvariantCulture),
                ["scan_id"] = id.ToString("D"), ["page_number"] = 0, ["has_more"] = false,
                ["completeness"] = "complete", ["unread_objects"] = 0,
                ["share"] = new JsonObject { ["name"] = "Finance", ["path"] = RootPath, ["dacl"] = "D:(A;;FR;;;AU)", ["complete"] = true },
                ["local_groups"] = new JsonObject { ["complete"] = true, ["groups"] = new JsonArray() },
                ["objects"] = new JsonArray(
                    new JsonObject { ["path"] = RootPath, ["object_type"] = "directory", ["object_id"] = ObjectId,
                        ["owner_sid"] = Subject, ["dacl"] = dacl, ["sacl"] = "S:(AU;SAFA;FR;;;WD)",
                        ["sacl_protected"] = false, ["sacl_missing"] = false },
                    new JsonObject { ["path"] = RootPath + @"\Budgets", ["object_type"] = "directory",
                        ["object_id"] = "00000001:0000000000000043", ["owner_sid"] = Subject,
                        ["dacl"] = "D:(A;ID;FR;;;AU)", ["sacl"] = "S:", ["sacl_protected"] = false, ["sacl_missing"] = false })
            };
            await Execute("""
                insert into sli_plugin_file_audit.policy_revisions(agent_id,source_instance_id,revision,authored_at,actor_kind,actor_id,policy,policy_sha256)
                values(@agent,@source,@revision,@observed,'session',1,@policy,@policy_hash);
                insert into sli_plugin_file_audit.access_snapshots(snapshot_id,agent_id,source_instance_id,collection_scope_id,
                    observed_at,contract_version,completeness,snapshot_sha256,snapshot,unread_objects)
                values(@snapshot,@agent,@source,@scope,@observed,1,'complete',@snapshot_hash,@document,0);
                """, ("agent", Agent), ("source", Source.ToString("D")), ("revision", revision),
                ("observed", observed.UtcDateTime), ("policy", policy), ("policy_hash", Packets.Digest(policy)),
                ("snapshot", id), ("scope", Scope), ("snapshot_hash", Packets.Digest(snapshot)), ("document", snapshot));
        }
        var method = new JsonObject
        {
            ["$channel"] = "Security", ["$provider"] = "Microsoft-Windows-Security-Auditing", ["operation"] = "permissions",
            ["$origin"] = new JsonObject { ["plugin_id"] = "sli.file-audit", ["agent_id"] = Agent.ToString("D"),
                ["source_instance_id"] = Source.ToString("D"), ["collection_scope_id"] = Scope, ["source_generation"] = Source.ToString("D") }
        };
        var fields = new JsonObject
        {
            ["path"] = RootPath, ["operation"] = "permissions",
            ["aggregate"] = new JsonObject { ["count"] = 7, ["first_seen_utc"] = first.ToString("O", CultureInfo.InvariantCulture),
                ["last_seen_utc"] = last.ToString("O", CultureInfo.InvariantCulture) }
        };
        await Execute("""
            select public.create_event_storage_partitions((@first-interval '1 day')::date,@last::date);
            insert into public.event_cold_facts(event_id,time_created_utc,event_kind,domain_id,actor,computer,method,outcome,fields,source_sha256,event_record_id)
            values(@event,@first,4670,@domain,@actor,'FS-01.example.test',@method,'{"outcome":"success"}',@fields,decode(repeat('a',64),'hex'),41607);
            """, ("first", first.UtcDateTime), ("last", last.UtcDateTime), ("event", EventId),
            ("domain", domain), ("actor", Subject), ("method", method), ("fields", fields));
        return new JsonObject
        {
            ["agent_id"] = Agent.ToString("D"), ["source_instance_id"] = Source.ToString("D"),
            ["collection_scope_id"] = Scope, ["share_key"] = FileAuditReportReader.ShareKey(new JsonObject
                { ["agent_id"] = Agent.ToString("D"), ["source_instance_id"] = Source.ToString("D"), ["collection_scope_id"] = Scope }),
            ["source_name"] = "FS-01.example.test", ["share_name"] = "Finance", ["path"] = RootPath,
            ["object_id"] = ObjectId, ["domain_id"] = domain, ["before_snapshot_id"] = Before.ToString("D"),
            ["snapshot_id"] = Current.ToString("D"), ["from_utc"] = now.AddDays(-1).ToString("O", CultureInfo.InvariantCulture),
            ["to_utc"] = now.AddSeconds(1).ToString("O", CultureInfo.InvariantCulture),
            ["first_seen_utc"] = first.ToString("O", CultureInfo.InvariantCulture), ["last_seen_utc"] = last.ToString("O", CultureInfo.InvariantCulture),
            ["event_count"] = 7, ["group_count"] = 1, ["acl_count"] = 126
        };
    }
}
