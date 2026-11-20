using System.Text.Json.Nodes;
using Sli.Server.Agents.Radius;
using Xunit;

namespace Sli.Server.Tests.Agents;

// Vectors: tests/sources/test_nps_eventlog_runtime.py.
public sealed class NpsEventLogRuntimeTests
{
    private static JsonObject Route() => new()
    {
        ["source_name"] = "radius01.example.test", ["source_instance_id"] = "radius01.example.test",
        ["owner_confirmed_ip"] = "198.51.100.23", ["event_log_ready"] = true,
        ["event_log_adapter"] = "windows-eventlog-pywin32"
    };

    private static NpsEventLogAdmission Admission() => new(
        "[6272,6273]", "2026-09-09T00:00:00Z", "2026-09-09T01:00:00Z",
        "python", "radius01.example.test", "radius01.example.test", ["Security"],
        true, true, "observe", false, "dpapi_current_user", true);

    [Fact]
    public void AcceptsExactFencedContract()
    {
        int loads = 0;
        var selection = NpsEventLogRuntime.Validate(Admission(), () => { loads++; return Route(); });
        Assert.Equal(new[] { 6272, 6273 }, selection.EventIds);
        Assert.Equal("2026-09-09T00:00:00+00:00", selection.StartTimeUtc);
        Assert.Equal("2026-09-09T01:00:00+00:00", selection.EndTimeUtc);
        Assert.Equal(1, loads);
    }

    [Theory]
    [InlineData("ids-missing", "continuous_nps_event_ids_mismatch")]
    [InlineData("ids-reversed", "continuous_nps_event_ids_mismatch")]
    [InlineData("empty-window", "bounded Event Log start/end UTC range must be increasing")]
    [InlineData("backend", "continuous_nps_python_backend_required")]
    [InlineData("server", "nps_eventlog_endpoint_invalid")]
    [InlineData("connect", "nps_eventlog_endpoint_invalid")]
    [InlineData("channels", "continuous_nps_security_channel_required")]
    [InlineData("archive", "continuous_nps_cursor_archive_required")]
    [InlineData("cursor", "continuous_nps_cursor_archive_required")]
    [InlineData("adaptive", "continuous_nps_adaptive_state_required")]
    [InlineData("message", "continuous_nps_message_collection_forbidden")]
    [InlineData("credentials", "continuous_nps_dpapi_required")]
    [InlineData("contact", "continuous_nps_source_contact_not_allowed")]
    [InlineData("route", "nps_eventlog_registered_route_required")]
    public void RejectsEveryApplicableContractDrift(string vector, string code)
    {
        var input = Admission();
        input = vector switch
        {
            "ids-missing" => input with { EventIdsJson = "[6272]" },
            "ids-reversed" => input with { EventIdsJson = "[6273,6272]" },
            "empty-window" => input with { StartTimeUtc = input.EndTimeUtc },
            "backend" => input with { RequestedBackend = "powershell" },
            "server" => input with { Server = "other.example.test" },
            "connect" => input with { ConnectAddress = "other.example.test" },
            "channels" => input with { Channels = ["Security", "System"] },
            "archive" => input with { Archive = false },
            "cursor" => input with { UseRecordIdCursor = false },
            "adaptive" => input with { AdaptiveStateMode = "update" },
            "message" => input with { CollectMessage = true },
            "credentials" => input with { AdSourceCredentialMode = "process" },
            "contact" => input with { AllowSourceContact = false },
            "route" => input,
            _ => throw new ArgumentException(vector)
        };
        int loads = 0;
        var error = Assert.ThrowsAny<Exception>(() => NpsEventLogRuntime.Validate(input, () =>
        {
            loads++;
            var route = Route();
            if (vector == "route") route["event_log_ready"] = false;
            return route;
        }));
        Assert.Equal(code, error.Message);
        Assert.Equal(vector is "server" or "connect" or "route" ? 1 : 0, loads);
    }

    [Fact]
    public void KeepsLongExplicitRecoveryWindow()
    {
        var selection = NpsEventLogRuntime.Validate(Admission() with { StartTimeUtc = "2026-08-01T00:00:00Z" }, Route);
        Assert.Equal("2026-08-01T00:00:00+00:00", selection.StartTimeUtc);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("not-json")]
    [InlineData("{\"id\":6272}")]
    [InlineData("[6272.0,6273]")]
    [InlineData("[true,6273]")]
    [InlineData("[6272,6272]")]
    public void RejectsMalformedOrNonIntegerSelectors(string? ids)
    {
        Assert.Throws<ArgumentException>(() => NpsEventLogRuntime.Validate(Admission() with { EventIdsJson = ids }, Route));
    }

    [Fact]
    public void NormalizesExplicitUtcWithPythonMicrosecondPrecision()
    {
        var selection = NpsEventLogRuntime.Validate(Admission() with { StartTimeUtc = "2026-09-09T00:00:00.123456Z" }, Route);
        Assert.Equal("2026-09-09T00:00:00.123456+00:00", selection.StartTimeUtc);
        Assert.Equal("radius01.example.test", NpsEventLogRuntime.ResolveEndpoint("radius01.example.test", null, Route));
    }

    [Theory]
    [InlineData("radius01.example.test", "radius01.example.test")]
    [InlineData("RADIUS01.EXAMPLE.TEST", "RADIUS01.EXAMPLE.TEST")]
    public void AdmitsOnlyRegisteredFqdn(string server, string connect)
    {
        Assert.Equal("radius01.example.test", NpsEventLogRuntime.ResolveEndpoint(server, connect, Route));
    }

    [Theory]
    [InlineData("198.51.100.23", "198.51.100.23")]
    [InlineData("radius01.example.test", "198.51.100.23")]
    [InlineData("radius01.example.test.", "radius01.example.test.")]
    [InlineData("other.example.test", "other.example.test")]
    public void RejectsEndpointBeforeCallerCanLoadCredentials(string server, string connect)
    {
        bool credentialsRequested = false;
        var error = Assert.Throws<InvalidOperationException>(() =>
        {
            NpsEventLogRuntime.ResolveEndpoint(server, connect, Route);
            credentialsRequested = true;
        });
        Assert.Equal("nps_eventlog_endpoint_invalid", error.Message);
        Assert.False(credentialsRequested);
    }

    [Theory]
    [InlineData("source_name", "198.51.100.23")]
    [InlineData("source_instance_id", "other.example.test")]
    [InlineData("owner_confirmed_ip", "")]
    [InlineData("event_log_adapter", "windows-eventlog-powershell")]
    public void RequiresRegisteredRouteIdentityAndAdapter(string field, string value)
    {
        var route = Route(); route[field] = value;
        Assert.Equal("nps_eventlog_registered_route_required", Assert.Throws<InvalidOperationException>(() =>
            NpsEventLogRuntime.ResolveEndpoint("radius01.example.test", null, () => route)).Message);
    }

    [Theory]
    [InlineData("2026-09-09T00:00:00", "2026-09-09T01:00:00Z")]
    [InlineData("2026-09-09T00:00:00+07:00", "2026-09-09T01:00:00Z")]
    [InlineData("2026-09-09T02:00:00Z", "2026-09-09T01:00:00Z")]
    public void RejectsNonUtcAndReversedWindows(string start, string end)
    {
        Assert.Throws<ArgumentException>(() => NpsEventLogRuntime.Validate(Admission() with { StartTimeUtc = start, EndTimeUtc = end }, Route));
    }
}
