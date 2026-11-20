using System.Text.Json.Nodes;

namespace Sli.Server.Semantic;

public sealed record SemanticRuntimeSettings(bool Normalization, bool Assembly, bool DirectoryState, bool Correlation, bool Risk, bool Findings)
{
    public const string FactsMode = "facts-v1", InvestigationMode = "investigation-v1", FindingsMode = "findings-v1";
    public static bool Enabled(string? value) => value?.Trim().ToLowerInvariant() is "1" or "true" or "yes" or "on";
    public static SemanticRuntimeSettings Read(Func<string, string?> get)
    {
        bool n = Enabled(get("ADLOG_SEMANTIC_NORMALIZATION_ENABLED")), a = n && Enabled(get("ADLOG_SEMANTIC_ASSEMBLY_ENABLED"));
        bool c = a && Enabled(get("ADLOG_SEMANTIC_CORRELATION_ENABLED")), r = c && Enabled(get("ADLOG_SEMANTIC_RISK_ENGINE_ENABLED"));
        return new(n, a, a && Enabled(get("ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED")), c, r, r && Enabled(get("ADLOG_SEMANTIC_FINDING_CREATION_ENABLED")));
    }
    public static string Mode(Func<string, string?> get)
    {
        if (!Enabled(get("ADLOG_SEMANTIC_PRODUCTION_ENABLED"))) throw new InvalidOperationException("semantic production admission is required");
        string mode = get("ADLOG_SEMANTIC_RUNTIME_MODE")?.Trim() ?? "";
        if (mode == "") return FindingsMode;
        if (mode is not (FactsMode or InvestigationMode or FindingsMode)) throw new InvalidOperationException("semantic runtime mode is unsupported");
        return mode;
    }
    public void Validate(string mode, Func<string, string?> get)
    {
        if (mode is not (FactsMode or InvestigationMode or FindingsMode)) throw new InvalidOperationException("semantic runtime mode is unsupported");
        if (!Normalization || !Assembly || DirectoryState || (mode == FactsMode ? Correlation || Risk || Findings :
            mode == InvestigationMode ? !Correlation || Risk || Findings : !Correlation || !Risk || !Findings))
            throw new InvalidOperationException("semantic feature chain differs from admitted mode");
        if (mode == FactsMode && new[] { "DIRECTORY_STATE", "CORRELATION", "RISK_ENGINE", "FINDING_CREATION" }
            .Any(stage => Enabled(get("ADLOG_SEMANTIC_" + stage + "_ENABLED")))) throw new InvalidOperationException("facts mode forbids raw downstream flags");
    }
    public JsonObject Document => new() { ["normalization"] = Normalization, ["assembly"] = Assembly, ["directory_state"] = DirectoryState,
        ["correlation"] = Correlation, ["risk_engine"] = Risk, ["finding_creation"] = Findings };
}
