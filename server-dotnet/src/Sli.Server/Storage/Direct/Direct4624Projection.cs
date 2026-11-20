using System.Text.Json.Nodes;
using System.Xml.Linq;
using Sli.Agent.Core;
using Sli.Agent.Protocol.Compatibility;

namespace Sli.Server.Storage.Direct;

internal sealed record DirectEntity(string Type, string NaturalKey, string DisplayName, string Role,
    bool DomainScoped, bool ServerScoped, JsonObject Attributes, double Confidence=1.0);
internal sealed record Direct4624Projection(string IdentityHash, int EventKind, string? LogonType, IReadOnlyList<DirectEntity> Entities, IReadOnlyDictionary<string,string> Data)
{
    internal string? Keywords {get;init;}
    internal string? MessageText {get;init;}
    internal string? CatalogInitiator {get;init;}
    internal string Channel {get;init;}="Security";
    internal string Provider {get;init;}="Microsoft-Windows-Security-Auditing";
    internal string Normalizer {get;init;}="event_catalog";
    internal string Noise {get;init;}="not_classified";
    internal string NoiseVersion {get;init;}="catalog-unavailable";
    internal static bool IsFileAudit(int kind)=>kind is 4656 or 4659 or 4660 or 4663 or 4670 or 4907 or 5140 or 5142 or 5143 or 5144 or 5145 or 5168 or 4658 or 4664;
    internal static Direct4624Projection Create(JsonObject row)
    {
        var identity = DirectEventIdentity.Hash(row);
        var source = row["computer_name"]!.GetValue<string>();
        int kind=row["event_id"]!.GetValue<int>();
        // The configured collector source and native XML Computer can differ.
        // Hash() has already verified the complete row against its native XML.
        source=Sli.Server.Compatibility.PythonText.Strip(source);
        if (source.Length == 0)
            throw new InvalidDataException("storage_v2_event_profile_pending");
        string channel=row["channel"]!.GetValue<string>(),provider=row["provider_name"]?.GetValue<string>()??"";
        var profile=DirectNativeEvent.Profile(channel,provider,kind);
        var items = DirectNativeEvent.Data(row).Where(x=>x.Value is not null).ToDictionary(x=>x.Key,x=>x.Value is JsonValue v && v.TryGetValue<string>(out var text)?text:x.Value!.ToJsonString(),StringComparer.Ordinal);
        string? logonType=items.GetValueOrDefault("LogonType");
        // event_facts_for_event.pick: missing values are null, strings are
        // stripped and limited in Unicode code points, never rejected globally.
        if(logonType is not null)logonType=string.Concat(Sli.Server.Compatibility.PythonText.Strip(logonType).EnumerateRunes().Take(64).Select(r=>r.ToString()));
        if(logonType=="")logonType=null;
        var lowered = UnicodeLower.Lower(source);
        var asset = new DirectEntity("asset", "server:" + lowered, source, "recorder", true, true,
            new JsonObject { ["role_hint"] = "event_recorder", ["risk_tier"] = lowered.StartsWith("dc", StringComparison.Ordinal) || lowered.Contains("domain controller", StringComparison.Ordinal) ? "critical" : "normal" });
        var channelEntity = new DirectEntity("log_source", "log:"+UnicodeLower.Lower(channel), channel, "context", false, false,
            new JsonObject { ["provider_name"] = provider.Length==0?null:provider, ["risk_tier"] = "normal" });
        var providerEntity = new DirectEntity("event_provider", "provider:"+UnicodeLower.Lower(provider), provider, "context", false, false,
            new JsonObject { ["risk_tier"] = "normal" });
        var entities = new List<DirectEntity> {asset, channelEntity, providerEntity};
        entities.AddRange(DirectNpsEntities.Extract(items,source,profile.Normalizer=="event_catalog"?kind:0,channel,DirectNativeEvent.Initiator(row,items)));
        return new Direct4624Projection(identity, kind, logonType, entities, items){Keywords=row["keywords"]?.GetValue<string>(),MessageText=row["message"]?.GetValue<string>(),Channel=channel,Provider=provider,Normalizer=profile.Normalizer,Noise=profile.Noise,NoiseVersion=profile.Version,CatalogInitiator=DirectNativeEvent.Initiator(row,items)};
    }
}
