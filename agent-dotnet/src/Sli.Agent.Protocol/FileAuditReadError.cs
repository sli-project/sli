using System.Text.Json.Nodes;

namespace Sli.Agent.Protocol;

/// <summary>Bounded diagnostic metadata for read-only file audit checks.</summary>
public sealed record FileAuditReadError(string Stage, string? CodeKind = null, uint? Code = null)
{
    public const string Capability = "file_audit_read_diagnostics";

    public JsonObject ToJson() => Code is uint code && code != 0
        ? new JsonObject { ["stage"] = Stage, ["code_kind"] = CodeKind, ["code"] = code }
        : new JsonObject { ["stage"] = Stage };

    public static bool Valid(JsonNode? value) =>
        value is JsonObject error
        && JsonRead.TryString(error["stage"], out var stage)
        && stage is ("audit_policy" or "share" or "directory" or "acl" or "local_groups" or "inventory")
        && (JsonRead.HasExactly(error, "stage")
            || JsonRead.HasExactly(error, "stage", "code_kind", "code")
                && JsonRead.TryString(error["code_kind"], out var kind) && kind is ("win32" or "hresult")
                && JsonRead.TryInteger(error["code"], out var code) && code > 0 && code <= uint.MaxValue);
}
