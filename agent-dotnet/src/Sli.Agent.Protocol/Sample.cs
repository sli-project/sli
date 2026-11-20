using System.Text.Json.Nodes;

namespace Sli.Agent.Protocol;

/// <summary>One bounded capture of a module: the data and the cursors that frame it (<c>sli_agent/modules.py: Sample</c>).</summary>
public sealed record Sample(
    string ModuleId,
    string SourceInstanceId,
    string Channel,
    string Generation,
    Cursor CursorBefore,
    Cursor CursorAfter,
    JsonObject Payload,
    string ModuleVersion = "1.0.0",
    string PolicyRevision = "1",
    string ContinuityState = "not_proven",
    long FilteredCount = 0,
    long? LostCount = null);
