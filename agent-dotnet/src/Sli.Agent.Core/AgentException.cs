namespace Sli.Agent.Core;

/// <summary>An agent-side failure with a fixed code (the same codes the Python agent uses). Never carries data.</summary>
public class AgentException(string code) : Exception(code)
{
    public string Code { get; } = code;
}

/// <summary>A source read failed. The detail is an allowlisted diagnostic, never exception text or event content.</summary>
public sealed class EventLogReadException(EventLogDiagnostic? diagnostic = null, string code = "agent_ad_dc_read_failed")
    : AgentException(code)
{
    public EventLogDiagnostic? Diagnostic { get; } = diagnostic;
}

/// <summary>Mirrors <c>sli_collect/eventlog_diagnostics.py</c>: classes, numbers and stages only.</summary>
public sealed record EventLogDiagnostic(string ExceptionClass, int? WinError, int? HResult, string Channel, long? RecordId, bool BookmarkPresent, string Stage);

public sealed class QueueFullException(string code) : AgentException(code);
