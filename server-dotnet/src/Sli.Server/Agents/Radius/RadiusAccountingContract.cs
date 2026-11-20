using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Sli.Agent.Core;
using Sli.Server.Agents.Registry;
using Sli.Server.Compatibility;

namespace Sli.Server.Agents.Radius;

internal sealed record RadiusParsedRecord(
    int PacketType, string? AccountingStatus, string RecordDate, string RecordTime,
    string? AccountSessionId, string? NasIdentifier, string? NasIpAddress,
    string? UserName, string? DistinguishedName, string? ClassAttribute, string CanonicalRecordSha256)
{
    public string AdapterContractId => RadiusAccountingContract.AdapterContractId;
    public bool IsAccountingRequest => PacketType == 4;
    public bool IsAccountingControlEvent => IsAccountingRequest && AccountingStatus is "accounting_on" or "accounting_off";
    public string? NasIdentity => NasIdentifier ?? NasIpAddress;
    public override string ToString() => nameof(RadiusParsedRecord);
}

internal sealed record RadiusClassIdentityBinding(
    string SourceInstanceId, string CanonicalRecordSha256, string ClassAttribute,
    string PrincipalObservation, string? ExactPrincipalKey)
{
    public string AdapterContractId => RadiusAccountingContract.AdapterContractId;
    public bool IdentityLookupReady => true;
    public bool ExactIdentityReady => ExactPrincipalKey is not null;
    public override string ToString() => nameof(RadiusClassIdentityBinding);
}

internal sealed record RadiusSessionObservation(
    string SourceInstanceId, string LifecycleEvent, string CanonicalRecordSha256,
    string AccountSessionId, string NasIdentity, string? PrincipalObservation, string? ExactPrincipalKey,
    DateTimeOffset? ObservedAtUtc, string? TimestampBasis, string? SessionIdentityKey)
{
    public string AdapterContractId => RadiusAccountingContract.AdapterContractId;
    public bool SessionConfirmedByAccounting => true;
    public bool SessionIdentityReady => SessionIdentityKey is not null;
    public bool TimestampReady => ObservedAtUtc is not null;
    public override string ToString() => nameof(RadiusSessionObservation);
}

// Pure record contract shared by the importer and source parity tests.
// Source: sli_collect/radius_accounting.py. Identity and timezone are never inferred.
internal static class RadiusAccountingContract
{
    public const string AdapterContractId = "radius-accounting-database-compatible-v1";
    private static string? Text(string? value)
    {
        string text = value is null ? "" : PythonText.Strip(value);
        return text.Length == 0 ? null : text;
    }
    private static string Source(string source)
    {
        var value = Text(source) ?? "";
        if (!Regex.IsMatch(value, @"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\z")) throw new ArgumentException("source_instance_id_invalid");
        return value;
    }
    private static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(new UTF8Encoding(false, true).GetBytes(value)));

    public static RadiusParsedRecord Parse(string line)
    {
        var f = RadiusAccountingRecord.ParseFields(line);
        PythonInt.TryParse(Text(f[4]), out var packet);
        string? status = Text(f[31]) switch { "1" => "start", "2" => "stop", "3" => "interim_update", "7" => "accounting_on", "8" => "accounting_off", _ => null };
        return new((int)packet, status, Text(f[2]) ?? "", Text(f[3]) ?? "", Text(f[35]), Text(f[11]), Text(f[12]), Text(f[5]), Text(f[6]), Text(f[26]), Hash(line));
    }

    public static RadiusClassIdentityBinding? BuildClassIdentityBinding(RadiusParsedRecord record, string sourceInstanceId, string? exactPrincipalKey = null)
    {
        if (record.PacketType != 2) return null;
        string source = Source(sourceInstanceId);
        string classValue = record.ClassAttribute ?? throw new ArgumentException("access_accept_class_required");
        string principalObservation = Text(record.DistinguishedName) ?? throw new ArgumentException("access_accept_distinguished_name_required");
        return new(source, record.CanonicalRecordSha256, classValue, principalObservation, Text(exactPrincipalKey));
    }

    public static RadiusSessionObservation? BuildSessionObservation(
        RadiusParsedRecord record, string sourceInstanceId, string? exactPrincipalKey = null,
        RadiusClassIdentityBinding? classIdentityBinding = null, string? sourceTimezoneId = null, int? sourceUtcOffsetMinutes = null)
    {
        if (!record.IsAccountingRequest || record.IsAccountingControlEvent) return null;
        string source = Source(sourceInstanceId);
        string session = Text(record.AccountSessionId) ?? throw new ArgumentException("account_session_id_required");
        string nas = Text(record.NasIdentity) ?? throw new ArgumentException("nas_identity_required");
        if (record.AccountingStatus is not ("start" or "interim_update" or "stop")) throw new ArgumentException("accounting_status_required");
        string? principal = Text(exactPrincipalKey), principalObservation = record.DistinguishedName ?? record.UserName;
        if (classIdentityBinding is not null)
        {
            if (principal is not null) throw new ArgumentException("principal_sources_are_mutually_exclusive");
            if (classIdentityBinding.SourceInstanceId != source) throw new ArgumentException("class_binding_source_mismatch");
            if (record.ClassAttribute is null || record.ClassAttribute != classIdentityBinding.ClassAttribute) throw new ArgumentException("class_binding_mismatch");
            principal = classIdentityBinding.ExactPrincipalKey;
            principalObservation = classIdentityBinding.PrincipalObservation;
        }
        DateTimeOffset? observed = null;
        string? basis = null;
        if (sourceUtcOffsetMinutes is not null || Text(sourceTimezoneId) is not null)
        {
            if (sourceUtcOffsetMinutes is null || Text(sourceTimezoneId) is null) throw new ArgumentException("source_timezone_context_incomplete");
            int offset = sourceUtcOffsetMinutes.Value;
            if (offset is < -840 or > 840) throw new ArgumentException("source_timezone_offset_invalid");
            if (!DateTime.TryParseExact(record.RecordDate + " " + record.RecordTime, ["M/d/yyyy H:m:s", "MM/dd/yyyy HH:mm:ss"], CultureInfo.InvariantCulture, DateTimeStyles.None, out var local)) throw new ArgumentException("record_local_timestamp_invalid");
            observed = new DateTimeOffset(DateTime.SpecifyKind(local.AddMinutes(-offset), DateTimeKind.Utc));
            basis = "record_date_time_plus_observed_source_timezone";
        }
        return new(source, record.AccountingStatus, record.CanonicalRecordSha256, session, nas, principalObservation, principal,
            observed, basis, principal is null ? null : SessionKey(source, nas, session, principal));
    }

    private static string JsonString(string value)
    {
        var result = new StringBuilder("\"");
        foreach (char c in value)
        {
            switch (c)
            {
                case '"': result.Append("\\\""); break;
                case '\\': result.Append("\\\\"); break;
                case '\b': result.Append("\\b"); break;
                case '\f': result.Append("\\f"); break;
                case '\n': result.Append("\\n"); break;
                case '\r': result.Append("\\r"); break;
                case '\t': result.Append("\\t"); break;
                default: if (c < 32) result.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture)); else result.Append(c); break;
            }
        }
        return result.Append('"').ToString();
    }
    private static string SessionKey(string source, string nas, string session, string principal)
    {
        string json = "{\"account_session_id\":" + JsonString(session) + ",\"exact_principal_key\":" + JsonString(principal) + ",\"nas_identity\":" + JsonString(UnicodeCaseFold.Fold(nas)) + ",\"source_instance_id\":" + JsonString(UnicodeCaseFold.Fold(source)) + "}";
        return "radius-session:" + Hash(json);
    }
}
