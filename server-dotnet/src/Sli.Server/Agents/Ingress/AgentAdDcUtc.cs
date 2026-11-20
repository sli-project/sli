using Sli.Agent.Protocol.Compatibility;

namespace Sli.Server.Agents.Ingress;

// datetime.fromisoformat(s.replace("Z", "+00:00")) with UTC offset zero, as used in AD/DC cursors.
internal static class AgentAdDcUtc
{
    public static DateTimeOffset Parse(string text) => PythonIsoDateTime.TryParseUtc(text,out var result) ? result : throw new ArgumentException();
}
