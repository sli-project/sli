using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Gpo.SnapshotModel;

namespace Sli.Server.Agents.SnapshotPublication;

// Caller owns publication transaction. The GPO row is only one part of context import.
internal static class GpoSnapshotStore
{
    public static async Task StoreAndVerifyAsync(NpgsqlConnection db,NpgsqlTransaction tx,long domainId,Guid run,JsonObject snapshot,bool insert,CancellationToken ct)
    {
        var redacted=GpoSnapshotDocument.Redact(JsonSerializer.SerializeToElement(snapshot));
        byte[] canonical=GpoSnapshotDocument.CanonicalUtf8(redacted),hash=GpoSnapshotDocument.CanonicalSha256(redacted);
        if (insert) await using (var cmd=new NpgsqlCommand("""
            insert into gpo_report_v2_source_snapshots(domain_id,source_run_id,schema_version,collector_version,collection_status,
            source_started_at_utc,source_completed_at_utc,source_observed_at_utc,import_status,gpo_count,scope_count,link_count,setting_count,
            permission_count,wmi_filter_count,payload_json,payload_sha256)
            values(@domain,@run,@schema,@collector,@status,@started::timestamptz,@completed::timestamptz,@observed,'completed',@gpos,@scopes,@links,@settings,@permissions,@wmi,@payload,@hash)
            on conflict(domain_id,source_run_id) do nothing
            """,db,tx))
        {
            cmd.Parameters.AddWithValue("domain",domainId); cmd.Parameters.AddWithValue("run",run);
            cmd.Parameters.AddWithValue("schema",snapshot["schema_version"]!.GetValue<string>()); cmd.Parameters.AddWithValue("collector",snapshot["collector_version"]!.GetValue<string>());
            cmd.Parameters.AddWithValue("status",snapshot["collection_status"]!.GetValue<string>());
            cmd.Parameters.AddWithValue("started",NpgsqlDbType.Text,snapshot["started_at"]!.GetValue<string>());
            cmd.Parameters.AddWithValue("completed",NpgsqlDbType.Text,snapshot["completed_at"]!.GetValue<string>());
            if (!Sli.Agent.Protocol.Compatibility.PythonIsoDateTime.TryParse(snapshot["observed_at"]!.GetValue<string>(),out var parsed) || !parsed.TryToUtc(out var time)) throw new InvalidDataException("agent_gpo_observation_invalid");
            cmd.Parameters.AddWithValue("observed",time);
            foreach(var (name,key) in new[] { ("gpos","gpos"),("scopes","scopes"),("links","links"),("settings","settings"),("permissions","permissions"),("wmi","wmi_filters") }) cmd.Parameters.AddWithValue(name,snapshot[key]!.AsArray().Count);
            cmd.Parameters.AddWithValue("payload",NpgsqlDbType.Jsonb,System.Text.Encoding.UTF8.GetString(canonical)); cmd.Parameters.AddWithValue("hash",hash);
            await cmd.ExecuteNonQueryAsync(ct);
        }
        await using var read=new NpgsqlCommand("select payload_sha256 from gpo_report_v2_source_snapshots where domain_id=@domain and source_run_id=@run and import_status='completed'",db,tx);
        read.Parameters.AddWithValue("domain",domainId); read.Parameters.AddWithValue("run",run);
        if (await read.ExecuteScalarAsync(ct) is not byte[] actual || !actual.AsSpan().SequenceEqual(hash)) throw new InvalidDataException("agent_gpo_import_readback_invalid");
    }
}
