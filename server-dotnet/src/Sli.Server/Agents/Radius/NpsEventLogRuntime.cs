using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Compatibility;

namespace Sli.Server.Agents.Radius;

public sealed record NpsEventLogAdmission(
    string? EventIdsJson, string? StartTimeUtc, string? EndTimeUtc,
    string RequestedBackend, string Server, string? ConnectAddress,
    IReadOnlyList<string> Channels, bool Archive, bool UseRecordIdCursor,
    string AdaptiveStateMode, bool CollectMessage, string AdSourceCredentialMode,
    bool AllowSourceContact);

public sealed record NpsEventLogSelection(IReadOnlyList<int> EventIds, string StartTimeUtc, string EndTimeUtc);

// server/source_packs/nps_eventlog_runtime.py: pure admission before credentials or RPC.
// The loader supplies the validated Radius collection-route summary, as in Python.
public static class NpsEventLogRuntime
{
    private static readonly Regex Fqdn = new(
        @"\A(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\z",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static string ResolveEndpoint(string? server, string? connectAddress, Func<JsonObject> routeLoader)
    {
        var route = routeLoader();
        string Text(string key) => route[key] is JsonValue v && v.TryGetValue<string>(out var s) ? PythonText.Strip(s) : "";
        string registered = Text("source_name");
        if (!Fqdn.IsMatch(registered) || !registered.Equals(Text("source_instance_id"), StringComparison.OrdinalIgnoreCase)
            || Text("owner_confirmed_ip").Length == 0 || route["event_log_ready"] is not JsonValue ready
            || !ready.TryGetValue<bool>(out var isReady) || !isReady
            || route["event_log_adapter"] is not JsonValue adapter
            || !adapter.TryGetValue<string>(out var adapterId) || adapterId != "windows-eventlog-pywin32")
            throw new InvalidOperationException("nps_eventlog_registered_route_required");

        string requested = PythonText.Strip(server ?? ""), connect = PythonText.Strip(connectAddress ?? server ?? "");
        if (!Fqdn.IsMatch(requested) || !Fqdn.IsMatch(connect)
            || !requested.Equals(registered, StringComparison.OrdinalIgnoreCase)
            || !connect.Equals(registered, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("nps_eventlog_endpoint_invalid");
        return registered;
    }

    public static NpsEventLogSelection Validate(NpsEventLogAdmission input, Func<JsonObject> routeLoader)
    {
        int[] ids;
        try
        {
            using var doc = JsonDocument.Parse(input.EventIdsJson ?? "null");
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Array || root.GetArrayLength() != 2
                || root.EnumerateArray().Any(x => x.ValueKind != JsonValueKind.Number || !x.TryGetInt32(out _)))
                throw new ArgumentException("continuous_nps_event_ids_mismatch");
            ids = root.EnumerateArray().Select(x => x.GetInt32()).ToArray();
        }
        catch (JsonException) { throw new ArgumentException("continuous_nps_event_ids_mismatch"); }
        if (!ids.SequenceEqual(new[] { 6272, 6273 })) throw new ArgumentException("continuous_nps_event_ids_mismatch");
        if (!PythonIsoDateTime.TryParseUtc(input.StartTimeUtc, out var start)
            || !PythonIsoDateTime.TryParseUtc(input.EndTimeUtc, out var end))
            throw new ArgumentException("bounded Event Log timestamps must be explicit UTC");
        if (start >= end) throw new ArgumentException("bounded Event Log start/end UTC range must be increasing");
        // "python" identifies the registered pywin32 collector backend, not the server runtime.
        if (input.RequestedBackend != "python") throw new ArgumentException("continuous_nps_python_backend_required");
        if (!input.Channels.SequenceEqual(new[] { "Security" })) throw new ArgumentException("continuous_nps_security_channel_required");
        if (!input.Archive || !input.UseRecordIdCursor) throw new ArgumentException("continuous_nps_cursor_archive_required");
        if (input.AdaptiveStateMode != "observe") throw new ArgumentException("continuous_nps_adaptive_state_required");
        if (input.CollectMessage) throw new ArgumentException("continuous_nps_message_collection_forbidden");
        // Q500: no event-count ceilings or execution timeouts; explicit recovery windows stay intact.
        if (input.AdSourceCredentialMode != "dpapi_current_user") throw new ArgumentException("continuous_nps_dpapi_required");
        if (!input.AllowSourceContact) throw new ArgumentException("continuous_nps_source_contact_not_allowed");
        ResolveEndpoint(input.Server, input.ConnectAddress, routeLoader);
        return new(ids, Format(start), Format(end));
    }

    private static string Format(DateTimeOffset value) => value.ToString(
        value.Ticks % TimeSpan.TicksPerSecond == 0 ? "yyyy-MM-dd'T'HH:mm:sszzz" : "yyyy-MM-dd'T'HH:mm:ss.ffffffzzz",
        CultureInfo.InvariantCulture);
}
