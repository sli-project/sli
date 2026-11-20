using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Server.Storage.Direct;

internal static class Direct4624Core
{
    internal static byte[] SourceHash(long eventId, long rawId, long serverId, long domainId, long? siteId,
        long logSourceId, DateTime normalizedAt, JsonObject row, Direct4624Projection projection,string? sourceTimestamp=null)
    {
        if (normalizedAt.Kind != DateTimeKind.Utc) throw new InvalidDataException("storage_v2_timestamp_invalid");
        var micros = normalizedAt.Ticks % TimeSpan.TicksPerSecond / 10;
        var time = normalizedAt.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
            + (micros == 0 ? "" : "." + micros.ToString("D6", CultureInfo.InvariantCulture)) + "+00:00";
        var source = new JsonObject {
            ["id"] = eventId, ["raw_log_file_id"] = rawId, ["server_id"] = serverId,
            ["domain_id"] = domainId, ["site_id"] = siteId, ["log_source_id"] = logSourceId,
            ["event_record_id"] = row["record_id"]!.DeepClone(), ["event_id"] = row["event_id"]!.DeepClone(),
            ["version"] = row["version"]?.DeepClone(), ["level"] = row["level"]?.DeepClone(),
            ["task"] = row["task"]?.DeepClone(), ["opcode"] = row["opcode"]?.DeepClone(),
            ["keywords"] = row["keywords"]?.DeepClone(), ["provider_name"] = row["provider_name"]!.DeepClone(),
            ["channel"] = row["channel"]!.DeepClone(), ["computer"] = DirectNpsArchiveRows.Computer(row),
            ["time_created_utc"] = row["time_created"]!.DeepClone(),
            ["subject_user_sid"] = Pick(projection,"SubjectUserSid"), ["subject_user_name"] = DirectNpsArchiveRows.SubjectName(projection), ["subject_domain_name"] = Pick(projection,"SubjectDomainName"),
            ["target_user_sid"] = Pick(projection,"TargetUserSid","TargetSid"), ["target_user_name"] = Pick(projection,"TargetUserName","NewTargetUserName","TargetAccount"), ["target_domain_name"] = Pick(projection,"TargetDomainName"),
            ["ip_address"] = Pick(projection,"IpAddress","ClientAddress","SourceAddress"), ["workstation_name"] = Pick(projection,"WorkstationName","Workstation"), ["logon_id"] = Pick(projection,"LogonId","TargetLogonId","SubjectLogonId"),
            ["correlation_id"] = NpsCorrelation(projection), ["normalized_at"] = sourceTimestamp ?? time, ["normalized_hash"] = projection.IdentityHash,
        };
        return SHA256.HashData(new UTF8Encoding(false, true).GetBytes(CanonicalJson.Serialize(source, ensureAscii: false)));
    }
    internal static string? NpsCorrelation(Direct4624Projection projection)
    {
        if(projection.Normalizer=="event_catalog" && projection.Channel=="Microsoft-Windows-TaskScheduler/Operational") {
            string? key=projection.EventKind switch {100 or 102=>"InstanceId",200 or 201=>"TaskInstanceId",_=>null};
            return key is not null && Guid.TryParse(projection.Data.GetValueOrDefault(key),out var id)?id.ToString("D"):null;
        }
        if (projection.Normalizer!="radius_event_catalog") return null;
        var value=projection.Data.GetValueOrDefault("AccountSessionIdentifier");
        if(value is null) return null;
        value=Sli.Server.Compatibility.PythonText.Strip(value);
        return value.Length==0 ? null : string.Concat(value.EnumerateRunes().Take(256).Select(r=>r.ToString()));
    }
    private static string? Pick(Direct4624Projection projection, params string[] keys) => keys.Select(k => projection.Data.GetValueOrDefault(k)).FirstOrDefault(v => !string.IsNullOrEmpty(v));
}
