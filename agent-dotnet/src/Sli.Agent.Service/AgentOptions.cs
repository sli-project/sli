using System.Text.Json.Nodes;

namespace Sli.Agent.Service;

/// <summary>
/// Local connection and bootstrap settings. Only the current server policy authorizes collection.
/// </summary>
public sealed class AgentOptions
{
    public const string Section = "Agent";

    public string ServerUrl { get; set; } = string.Empty;

    public string CaBundle { get; set; } = string.Empty;

    public string? CaFingerprint { get; set; }
    public string? CaCertificate { get; set; }
    public string? TokenFile { get; set; }
    public string? HostId { get; set; }
    public string? InstanceName { get; set; }

    public string StateDir { get; set; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SLI", "AgentNet", "state");

    public bool CollectionEnabled { get; set; }

    public int IntervalSeconds { get; set; } = 60;

    public long SpoolMaxBytes { get; set; } = 64L * 1024 * 1024;

    public long SpoolMaxAgeSeconds { get; set; } = 7 * 86400;

    public int RateLimitPerMinute { get; set; } = 120;

    /// <summary>The module configuration exactly as the server would assign it (see PROTOCOL.md, section 3.2).</summary>
    public JsonObject? AdDc { get; set; }
}
