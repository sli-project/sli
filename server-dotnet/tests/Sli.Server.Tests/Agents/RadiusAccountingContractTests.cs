using System.Security.Cryptography;
using System.Text;
using Sli.Agent.Core;
using Sli.Server.Agents.Radius;
using Xunit;

namespace Sli.Server.Tests.Agents;

// Vectors from tests/sources/test_radius_accounting_contract.py.
public sealed class RadiusAccountingContractTests
{
    private const string Source = "radius-radius01-1";
    private const string Principal = "sid:S-1-5-21-100000001-200000002-300000003-1101";
    private static string Line(string service = "IAS", string packet = "4", string status = "1",
        string session = "opaque-session-001", string nas = "VPN-GW-01", string nasIp = "192.0.2.1", string classValue = "opaque-class-001")
    {
        var fields = Enumerable.Repeat("", 66).ToArray();
        fields[0] = "NPS01"; fields[1] = service; fields[2] = "07/30/2026"; fields[3] = "09:30:00";
        fields[4] = packet; fields[5] = "EXAMPLE\\sample.user"; fields[6] = "example.test/Users/sample.user";
        fields[11] = nas; fields[12] = nasIp; fields[26] = classValue; fields[31] = status; fields[35] = session;
        return string.Join(',', fields);
    }

    [Theory]
    [InlineData("IAS")]
    [InlineData("RAS")]
    public void ParserAcceptsExactReviewedShapeAndKeepsDiagnosticsPrivate(string service)
    {
        string line = Line(service: service);
        var record = RadiusAccountingContract.Parse(line);
        Assert.Equal("radius-accounting-database-compatible-v1", record.AdapterContractId);
        Assert.Equal(4, record.PacketType);
        Assert.Equal("start", record.AccountingStatus);
        Assert.True(record.IsAccountingRequest);
        Assert.Equal("VPN-GW-01", record.NasIdentity);
        Assert.Equal(64, record.CanonicalRecordSha256.Length);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(line))), record.CanonicalRecordSha256);
        AssertPrivate(record);
    }

    [Theory]
    [InlineData("1", "start")]
    [InlineData("2", "stop")]
    [InlineData("3", "interim_update")]
    public void LifecycleRequiresNeitherInventedIdentityNorInferredTimezone(string status, string expected)
    {
        var record = RadiusAccountingContract.Parse(Line(status: status));
        var observation = RadiusAccountingContract.BuildSessionObservation(record, Source);
        Assert.NotNull(observation);
        Assert.Equal(expected, record.AccountingStatus);
        Assert.Equal(expected, observation.LifecycleEvent);
        Assert.True(observation.SessionConfirmedByAccounting);
        Assert.False(observation.SessionIdentityReady);
        Assert.Null(observation.SessionIdentityKey);
        Assert.Null(observation.ExactPrincipalKey);
        Assert.False(observation.TimestampReady);
        Assert.Null(observation.ObservedAtUtc);
        Assert.Null(observation.TimestampBasis);
        AssertPrivate(observation);
    }

    [Theory]
    [InlineData("7", "accounting_on")]
    [InlineData("8", "accounting_off")]
    public void ControlStatusesAreNamedNonSessionEvents(string status, string expected)
    {
        var record = RadiusAccountingContract.Parse(Line(status: status, session: ""));
        Assert.Equal(expected, record.AccountingStatus);
        Assert.True(record.IsAccountingControlEvent);
        Assert.Null(RadiusAccountingContract.BuildSessionObservation(record, Source));
    }

    [Theory]
    [InlineData("1")]
    [InlineData("2")]
    [InlineData("3")]
    public void AccessPacketsNeverCreateAccountingLifecycle(string packet)
    {
        var record = RadiusAccountingContract.Parse(Line(packet: packet, status: ""));
        Assert.False(record.IsAccountingRequest);
        Assert.Null(RadiusAccountingContract.BuildSessionObservation(record, Source));
    }

    [Fact]
    public void ExactPrincipalMustBeSuppliedBeforeSessionIdentityExists()
    {
        var record = RadiusAccountingContract.Parse(Line());
        var unresolved = RadiusAccountingContract.BuildSessionObservation(record, Source)!;
        var resolved = RadiusAccountingContract.BuildSessionObservation(record, Source, Principal)!;
        Assert.Null(unresolved.SessionIdentityKey);
        Assert.True(resolved.SessionIdentityReady);
        Assert.StartsWith("radius-session:", resolved.SessionIdentityKey);
        Assert.Equal(Principal, resolved.ExactPrincipalKey);
    }

    [Fact]
    public void AccessAcceptClassLookupNeedsExternalResolutionAndCanSupplyAccountingIdentity()
    {
        var accept = RadiusAccountingContract.Parse(Line(packet: "2", status: ""));
        var unresolved = RadiusAccountingContract.BuildClassIdentityBinding(accept, Source)!;
        var resolved = RadiusAccountingContract.BuildClassIdentityBinding(accept, Source, Principal)!;
        Assert.True(unresolved.IdentityLookupReady);
        Assert.False(unresolved.ExactIdentityReady);
        Assert.Null(unresolved.ExactPrincipalKey);
        Assert.True(resolved.ExactIdentityReady);
        AssertPrivate(resolved);
        var accounting = RadiusAccountingContract.Parse(Line());
        var observation = RadiusAccountingContract.BuildSessionObservation(accounting, Source, classIdentityBinding: resolved)!;
        Assert.True(observation.SessionIdentityReady);
        Assert.Equal(Principal, observation.ExactPrincipalKey);
        Assert.Equal(RadiusAccountingContract.BuildSessionObservation(accounting, Source, Principal)!.SessionIdentityKey, observation.SessionIdentityKey);
        Assert.False(RadiusAccountingContract.BuildSessionObservation(accounting, Source, classIdentityBinding: unresolved)!.SessionIdentityReady);
    }

    [Fact]
    public void MismatchedClassBindingFailsClosedEvenWhenUnresolved()
    {
        var accept = RadiusAccountingContract.Parse(Line(packet: "2", status: "", classValue: "class-a"));
        var binding = RadiusAccountingContract.BuildClassIdentityBinding(accept, Source)!;
        var accounting = RadiusAccountingContract.Parse(Line(classValue: "class-b"));
        Assert.Equal("class_binding_mismatch", Assert.Throws<ArgumentException>(() =>
            RadiusAccountingContract.BuildSessionObservation(accounting, Source, classIdentityBinding: binding)).Message);
    }

    [Fact]
    public void BindingRejectsDifferentSourceAndCompetingPrincipal()
    {
        var binding = RadiusAccountingContract.BuildClassIdentityBinding(RadiusAccountingContract.Parse(Line(packet: "2", status: "")), Source, Principal)!;
        var accounting = RadiusAccountingContract.Parse(Line());
        Assert.Equal("class_binding_source_mismatch", Assert.Throws<ArgumentException>(() =>
            RadiusAccountingContract.BuildSessionObservation(accounting, "radius-radius01-2", classIdentityBinding: binding)).Message);
        Assert.Equal("principal_sources_are_mutually_exclusive", Assert.Throws<ArgumentException>(() =>
            RadiusAccountingContract.BuildSessionObservation(accounting, Source, Principal, binding)).Message);
    }

    [Fact]
    public void ExplicitSourceTimezoneMakesTimestampReady()
    {
        var observation = RadiusAccountingContract.BuildSessionObservation(RadiusAccountingContract.Parse(Line()), Source,
            sourceTimezoneId: "N. Central Asia Standard Time", sourceUtcOffsetMinutes: 420)!;
        Assert.True(observation.TimestampReady);
        Assert.Equal(new DateTimeOffset(2026, 7, 30, 2, 30, 0, TimeSpan.Zero), observation.ObservedAtUtc);
        Assert.Equal("record_date_time_plus_observed_source_timezone", observation.TimestampBasis);
    }

    [Fact]
    public void SessionKeyUsesSourcePrincipalOpaqueSessionAndNas()
    {
        string Key(string source = Source, string principal = Principal, string? line = null) =>
            RadiusAccountingContract.BuildSessionObservation(RadiusAccountingContract.Parse(line ?? Line()), source, principal)!.SessionIdentityKey!;
        string baseline = Key();
        Assert.Equal(baseline, Key());
        Assert.NotEqual(baseline, Key(source: "radius-radius01-2"));
        Assert.NotEqual(baseline, Key(principal: "sid:S-1-5-21-100000001-200000002-300000003-1102"));
        Assert.NotEqual(baseline, Key(line: Line(session: "opaque-session-002")));
        Assert.NotEqual(baseline, Key(line: Line(nas: "VPN-GW-02")));
        Assert.Equal(baseline, Key(source: "RADIUS-RADIUS01-1", line: Line(nas: "vpn-gw-01")));
        Assert.NotEqual(baseline, Key(line: Line(session: "OPAQUE-SESSION-001")));
    }

    [Theory]
    [InlineData("", "record_required")]
    [InlineData("a,b,c", "database_compatible_shape_required")]
    [InlineData("", "accounting_status_unsupported_or_missing", true)]
    [InlineData("9", "accounting_status_unsupported_or_missing", true)]
    public void ParserFailsClosedWithExactErrorCodes(string input, string code, bool isStatus = false)
    {
        Assert.Equal(code, Assert.Throws<AgentException>(() => RadiusAccountingContract.Parse(isStatus ? Line(status: input) : input)).Code);
    }

    [Theory]
    [InlineData("", "VPN-GW-01", "192.0.2.1", "account_session_id_required")]
    [InlineData("opaque-session-001", "", "", "nas_identity_required")]
    public void SessionScopeErrorsHaveExactCodes(string session, string nas, string nasIp, string code)
    {
        var record = RadiusAccountingContract.Parse(Line(session: session, nas: nas, nasIp: nasIp));
        Assert.Equal(code, Assert.Throws<ArgumentException>(() => RadiusAccountingContract.BuildSessionObservation(record, Source)).Message);
    }

    private static void AssertPrivate(object value)
    {
        Assert.DoesNotContain("opaque-session-001", value.ToString());
        Assert.DoesNotContain("sample.user", value.ToString());
        Assert.DoesNotContain("opaque-class-001", value.ToString());
        Assert.DoesNotContain(Principal, value.ToString());
    }
}
