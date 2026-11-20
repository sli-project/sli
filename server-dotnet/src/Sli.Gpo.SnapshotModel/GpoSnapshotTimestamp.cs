using Sli.Agent.Protocol.Compatibility;
namespace Sli.Gpo.SnapshotModel;
// Source validates awareness after Python datetime.fromisoformat(value.replace("Z", "+00:00")).
internal static class GpoSnapshotTimestamp
{
    public static bool IsAware(string value) => value is not null && PythonIsoDateTime.TryParse(value.Replace("Z", "+00:00", StringComparison.Ordinal),out var parsed) && parsed.IsAware;
}
