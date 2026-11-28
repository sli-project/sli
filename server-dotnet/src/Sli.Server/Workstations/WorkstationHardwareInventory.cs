using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Sli.Server.Reporting.V2;

namespace Sli.Server.Workstations;

internal static class WorkstationHardwareInventory
{
    internal const string Latest = "public.workstation_hardware_latest465";
    private const string Changes = "public.workstation_hardware_changes465";
    internal const string ModelSql = "(select i.inventory#>>'{computer,0,model}' from " + Latest
        + " i where i.server_id=p.server_id and i.domain_id=p.domain_id and i.source_id::text=p.source_instance_id)";

    internal static async Task<bool> AvailableAsync(NpgsqlConnection db, NpgsqlTransaction tx, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("select to_regclass('" + Latest + "') is not null", db, tx);
        return await command.ExecuteScalarAsync(ct) is true;
    }

    internal static JsonObject Validate(Envelope envelope, JsonObject packet, WorkstationPolicy policy, Guid host)
    {
        CollectionPacket.Validate(packet);
        var header = packet["header"]!.AsObject();
        var records = packet["records"]!.AsArray();
        var hostId = host.ToString("D");
        if (!WorkstationHardware.IsPacket(envelope, packet)
            || envelope.Channel != "workstations" || envelope.PayloadContract != CollectionPacket.Contract
            || envelope.ModuleVersion != WorkstationsModule.ModuleVersion || envelope.PolicyRevision != policy.Revision
            || envelope.SourceInstanceId != hostId || envelope.Generation != hostId
            || Ws.Text(header, "source") != hostId || Ws.Text(header, "generation") != hostId
            || Ws.Text(header, "observed_at_utc") != envelope.ObservedAtUtc
            || envelope.CursorBefore.Strategy != "bookmark" || envelope.CursorBefore != envelope.CursorAfter
            || envelope.ContinuityState is not ("not_proven" or "gap") || envelope.FilteredCount != 0 || envelope.LostCount is not null
            || header["cursor"] is not JsonObject { Count: 0 } || packet["context"] is not JsonObject { Count: 0 }
            || Ws.Text(packet["continuity"]!.AsObject(), "status") != "not_proven"
            || records.Count != 1 || records[0] is not JsonObject record || Ws.Text(record, "format") != "snapshot_json"
            || record["payload"] is not JsonObject inventory || !WorkstationHardware.IsValid(inventory))
            throw new ProtocolException("agent_workstations_packet_invalid");
        return inventory;
    }

    internal static JsonArray Diff(JsonObject before, JsonObject after)
    {
        var changes = new JsonArray();
        foreach (var (section, value) in after)
        {
            if (value is not JsonArray newRows || before[section] is not JsonArray oldRows) continue;
            var oldById = oldRows.Cast<JsonObject>().ToDictionary(row => Ws.Text(row, "id")!, StringComparer.Ordinal);
            var newById = newRows.Cast<JsonObject>().ToDictionary(row => Ws.Text(row, "id")!, StringComparer.Ordinal);
            foreach (var id in oldById.Keys.Union(newById.Keys).Order(StringComparer.Ordinal))
            {
                var old = oldById.GetValueOrDefault(id);
                var current = newById.GetValueOrDefault(id);
                var component = current ?? old!;
                var name = ComponentName(component);
                void Add(string kind, string? field, JsonNode? from, JsonNode? to, string? severity) => changes.Add(new JsonObject
                {
                    ["section"] = section, ["component_id"] = id, ["component"] = name,
                    ["kind"] = kind, ["field"] = field, ["before"] = from?.DeepClone(), ["after"] = to?.DeepClone(),
                    ["severity"] = severity,
                });
                if (old is null || current is null)
                {
                    var label = JsonValue.Create(name);
                    Add(old is null ? "added" : "removed", null, old is null ? null : label, current is null ? null : label,
                        section == "disk" ? "medium" : section is "network" or "memory_module" ? "low" : null);
                    continue;
                }
                foreach (var (field, now) in current)
                {
                    var was = old[field];
                    // Missing values establish neither a transition nor a removal.
                    if (field is "id" or "disk_id" or "partition" or "system" || was is null || now is null || JsonNode.DeepEquals(was, now)) continue;
                    bool version = field is "version" or "tpm_version";
                    bool replacement = field is "serial" or "model" or "mac";
                    string? severity = (section, field) switch
                    {
                        ("security", "secure_boot" or "tpm_enabled") when now.GetValue<bool>() == false => "medium",
                        ("volume", "bitlocker") when Ws.Text(current, "bitlocker") == "off"
                            && Ws.Text(old, "bitlocker") == "on" && current["system"]?.GetValue<bool>() == true
                            && old["system"]?.GetValue<bool>() == true => "medium",
                        ("bios", "version") or ("memory", _) or ("memory_module", _) or ("network", _) => "low",
                        _ => null,
                    };
                    Add(version ? "version_changed" : replacement ? "replaced" : "changed", field, was, now, severity);
                }
            }
        }
        return changes;
    }

    private static string? ComponentName(JsonObject row) => Ws.Text(row, "model") ?? Ws.Text(row, "name")
        ?? Ws.Text(row, "mount") ?? Ws.Text(row, "slot") ?? Ws.Text(row, "serial");

    internal static async Task StoreAsync(NpgsqlConnection db, NpgsqlTransaction tx, WorkstationJournalScope scope,
        Guid source, Guid packetId, DateTimeOffset observedAt, JsonObject inventory, CancellationToken ct)
    {
        await using (var fence = new NpgsqlCommand("select pg_advisory_xact_lock(hashtextextended('workstation-hardware:'||@server::text,0))", db, tx))
        {
            fence.Parameters.AddWithValue("server", scope.ServerId);
            await fence.ExecuteNonQueryAsync(ct);
        }
        var digest = Packets.Digest(inventory);
        JsonObject? before = null;
        await using (var read = new NpgsqlCommand("select digest,inventory::text from " + Latest
            + " where server_id=@server and domain_id=@domain and source_id=@source", db, tx))
        {
            BindStation(read, scope.ServerId, scope.DomainId, source);
            await using var rows = await read.ExecuteReaderAsync(ct);
            if (await rows.ReadAsync(ct))
            {
                if (rows.GetString(0) == digest) return;
                before = JsonNode.Parse(rows.GetString(1))!.AsObject();
            }
        }
        if (before is not null)
        {
            var changes = Diff(before, inventory);
            if (changes.Count > 0)
            {
                await using var write = new NpgsqlCommand("insert into " + Changes + " (server_id,domain_id,source_id,observed_at,packet_id,ordinal,change) "
                    + "select @server,@domain,@source,@observed,@packet,(n-1)::integer,item from jsonb_array_elements(@changes) with ordinality as x(item,n)", db, tx);
                BindStation(write, scope.ServerId, scope.DomainId, source);
                write.Parameters.AddWithValue("observed", observedAt.UtcDateTime);
                write.Parameters.AddWithValue("packet", packetId);
                write.Parameters.AddWithValue("changes", NpgsqlDbType.Jsonb, changes.ToJsonString());
                await write.ExecuteNonQueryAsync(ct);
            }
        }
        await using var replace = new NpgsqlCommand("insert into " + Latest + " (server_id,domain_id,source_id,observed_at,digest,inventory) "
            + "values(@server,@domain,@source,@observed,@digest,@inventory) on conflict(server_id) do update "
            + "set domain_id=excluded.domain_id,source_id=excluded.source_id,observed_at=excluded.observed_at,digest=excluded.digest,inventory=excluded.inventory", db, tx);
        BindStation(replace, scope.ServerId, scope.DomainId, source);
        replace.Parameters.AddWithValue("observed", observedAt.UtcDateTime);
        replace.Parameters.AddWithValue("digest", digest);
        replace.Parameters.AddWithValue("inventory", NpgsqlDbType.Jsonb, inventory.ToJsonString());
        await replace.ExecuteNonQueryAsync(ct);
    }

    internal static async Task<JsonObject?> ReadAsync(NpgsqlConnection db, NpgsqlTransaction tx, ReportQueryContext context,
        JsonObject station, CancellationToken ct)
    {
        if (Ws.Number(station, "server_id") is not (> 0 and var server) || Ws.Number(station, "domain_id") is not (> 0 and var domain)
            || !Guid.TryParse(Ws.Text(station, "source_instance_id"), out var source)) return null;
        var sql = """
            select jsonb_build_object('inventory',i.inventory,'observed_at',i.observed_at,
                'changes',coalesce((select jsonb_agg(c.change || jsonb_build_object('id',c.packet_id::text||':'||c.ordinal,'time',c.observed_at)
                    order by c.observed_at desc,c.packet_id,c.ordinal)
                from public.workstation_hardware_changes465 c
                where c.server_id=i.server_id and c.domain_id=i.domain_id and c.source_id=i.source_id
                    and c.observed_at>=@from and c.observed_at<@to),'[]'::jsonb))::text
            from public.workstation_hardware_latest465 i
            where i.server_id=@server and i.domain_id=@domain and i.source_id=@source
            """;
        await using var command = new NpgsqlCommand(sql, db, tx);
        BindStation(command, server, domain, source);
        command.Parameters.AddWithValue("from", Iso8601.ParseUtc(context.Params["period"]!["from_utc"]!.GetValue<string>()).UtcDateTime);
        command.Parameters.AddWithValue("to", Iso8601.ParseUtc(context.Params["period"]!["to_utc"]!.GetValue<string>()).UtcDateTime);
        return await command.ExecuteScalarAsync(ct) is string result ? JsonNode.Parse(result)!.AsObject() : null;
    }

    private static void BindStation(NpgsqlCommand command, long server, long domain, Guid source)
    {
        command.Parameters.AddWithValue("server", server);
        command.Parameters.AddWithValue("domain", domain);
        command.Parameters.AddWithValue("source", source);
    }
}
