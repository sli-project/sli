using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Consumer;
using Sli.Server.Storage.Direct;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AdDcProjectionFailureTests
{
    [Fact]
    public void Repeated_reasons_log_at_most_once_per_minute_and_count_suppressed_failures()
    {
        var clock = new ManualClock();
        var failures = new AdDcProjectionFailure(clock);
        JsonObject Diagnostic(string reason) => new() { ["code"] = AdDcProjectionFailure.Code, ["reason"] = reason };

        var first = Diagnostic(AdDcProjectionFailure.AuthorizationMissing);
        Assert.True(failures.CountAndAllow(first));
        Assert.Equal(1L, (long?)first["occurrences"]);
        clock.Advance(TimeSpan.FromSeconds(59));
        Assert.False(failures.CountAndAllow(Diagnostic(AdDcProjectionFailure.AuthorizationMissing)));
        Assert.False(failures.CountAndAllow(Diagnostic(AdDcProjectionFailure.AuthorizationMissing)));
        Assert.True(failures.CountAndAllow(Diagnostic(AdDcProjectionFailure.AccessDenied)));
        clock.Advance(TimeSpan.FromSeconds(1));
        var next = Diagnostic(AdDcProjectionFailure.AuthorizationMissing);
        Assert.True(failures.CountAndAllow(next));
        Assert.Equal(3L, (long?)next["occurrences"]);
        Assert.False(failures.CountAndAllow(Diagnostic(AdDcProjectionFailure.AccessDenied)));
    }

    private sealed class ManualClock : TimeProvider
    {
        private long timestamp;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => timestamp;
        internal void Advance(TimeSpan elapsed) => timestamp += elapsed.Ticks;
    }

    [Theory]
    [InlineData("agent_inbox_marker_conflict",false)]
    [InlineData("short_event_summary_conflict",true)]
    [InlineData("short_event_attestation_failed",true)]
    [InlineData("operation_failed",false)]
    public void Short_store_failures_keep_their_safe_reason_and_only_deterministic_refusals_are_permanent(string reason,bool permanent)
    {
        var error=new InvalidOperationException(reason);
        var diagnostic=AdDcProjectionFailure.Describe(error,AdDcProjectionStep.HotEvents);
        Assert.Equal(reason,(string?)diagnostic["reason"]);
        Assert.Equal(permanent,AdDcProjectionFailure.IsPermanent(error));
        Assert.False(AdDcProjectionFailure.IsPermanent(new IOException(reason)));
    }

    [Fact]
    public void Python_agent_packet_with_native_system_metadata_can_be_projected()
    {
        string path = Path.Combine(PostCollectionPostgres.Repository(), "server-dotnet/tests/Sli.Server.Tests/Agents/ad-dc-history-vectors.json");
        var packet = JsonNode.Parse(File.ReadAllText(path))![0]!["sample"]!["payload"]!;
        var row = packet["records"]![0]!["payload"]!.DeepClone();
        var projection = Assert.Single(DirectAdDcPacket.PrepareBatch(new JsonArray(row))).Projection;
        Assert.Equal(4624, projection.EventKind);
        Assert.Null(projection.LogonType);
        Assert.Contains(projection.Entities, entity => entity.NaturalKey == "name:fixture-account");
    }

    [Fact]
    public void Native_large_and_unicode_packets_match_frozen_Python_identity_entities_and_facts()
    {
        string path = Path.Combine(PostCollectionPostgres.Repository(), "server-dotnet/tests/Sli.Server.Tests/Agents/ad-dc-projection-source.json");
        foreach (var vector in JsonNode.Parse(File.ReadAllText(path))!.AsArray()) {
            var row = vector!["packet"]!["records"]![0]!["payload"]!.DeepClone();
            var projection = Assert.Single(DirectAdDcPacket.PrepareBatch(new JsonArray(row))).Projection;
            Assert.Equal((string?)vector["hash"], projection.IdentityHash);
            Assert.Equal(vector["entities"]!.AsArray().Count, projection.Entities.Count);
            for (int index=0; index<projection.Entities.Count; index++) {
                var entity=projection.Entities[index]; var expected=vector["entities"]![index]!;
                Assert.Equal((string?)expected["entity_type"],entity.Type);
                Assert.Equal((string?)expected["natural_key"],entity.NaturalKey);
                Assert.Equal((string?)expected["display_name"],entity.DisplayName);
                Assert.Equal((string?)expected["link_role"],entity.Role);
                Assert.Equal((double)expected["confidence"]!,entity.Confidence);
                Assert.Equal((bool)expected["domain_scoped"]!,entity.DomainScoped);
                Assert.Equal((bool)expected["server_scoped"]!,entity.ServerScoped);
                Assert.True(JsonNode.DeepEquals(expected["attributes"],entity.Attributes), (string?)vector["name"]);
            }
            Assert.True(JsonNode.DeepEquals(vector["facts"],Direct4624Facts.Document(42,projection)), (string?)vector["name"]);
        }
    }

    [Theory]
    [InlineData("54000","dictionaries")]
    [InlineData("22001","dictionaries")]
    public void Oversized_database_fields_are_diagnosed_without_their_values(string state,string expectedStep)
    {
        var error=new PostgresException(new string('x',4096),"ERROR","ERROR",state,detail:"private-field");
        var diagnostic=AdDcProjectionFailure.Describe(error,AdDcProjectionStep.Dictionaries);
        Assert.Equal(state,(string?)diagnostic["sql_state"]);
        Assert.Equal(expectedStep,(string?)diagnostic["step"]);
        Assert.DoesNotContain("private",diagnostic.ToJsonString());
        Assert.True(diagnostic.ToJsonString().Length<512);
    }

    [Fact]
    public void Database_failure_reports_only_metadata_even_through_wrappers()
    {
        var error = new PostgresException("private-message", "ERROR", "ERROR", "23505",
            detail: "private-row", hint: "private-hint", where: "private-sql",
            schemaName: "private-schema", tableName: "private-table", columnName: "private-column",
            constraintName: "storage_v2_event_identity_allocations_pkey");
        var diagnostic = AdDcProjectionFailure.Describe(new InvalidOperationException("private-wrapper", error), AdDcProjectionStep.Publication);
        Assert.Equal("agent_ad_dc_projection_failed", (string?)diagnostic["code"]);
        Assert.Equal("InvalidOperationException", (string?)diagnostic["exception_type"]);
        Assert.Equal("23505", (string?)diagnostic["sql_state"]);
        Assert.Equal("storage_v2_event_identity_allocations_pkey", (string?)diagnostic["constraint"]);
        Assert.Equal("publication", (string?)diagnostic["step"]);
        Assert.DoesNotContain("private", diagnostic.ToJsonString());
    }

    [Fact]
    public void Untrusted_constraint_and_exception_values_are_never_written()
    {
        var error = new PostgresException("private", "ERROR", "ERROR", "23514", constraintName: "private\nforged-log");
        var diagnostic = AdDcProjectionFailure.Describe(error, AdDcProjectionStep.PrepareBatch);
        Assert.Equal("unrecognized", (string?)diagnostic["constraint"]);
        Assert.DoesNotContain("private", diagnostic.ToJsonString());
        diagnostic = AdDcProjectionFailure.Describe(new InvalidDataException("private-value"), AdDcProjectionStep.PrepareBatch);
        Assert.Null(diagnostic["sql_state"]);
        Assert.Equal("operation_failed", (string?)diagnostic["reason"]);
        diagnostic = AdDcProjectionFailure.Describe(new InvalidDataException("storage_v2_event_profile_pending"), AdDcProjectionStep.PrepareBatch);
        Assert.Equal("storage_v2_event_profile_pending", (string?)diagnostic["reason"]);
    }

    [Fact]
    public void Representation_conflicts_and_native_tampering_remain_fail_closed()
    {
        string? Describe(Exception error)=>(string?)AdDcProjectionFailure.Describe(error,AdDcProjectionStep.EventReservation)["reason"];
        Assert.Contains("published_source_event_hash_mismatch",Describe(new DirectSourceConflict(true)));
        Assert.Contains("event_representation_pending",Describe(new InvalidOperationException("event_representation_pending")));
        var fixture=JsonNode.Parse(File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(),
            "server-dotnet/tests/Sli.Server.Tests/Agents/ad-dc-history-vectors.json")))!;
        string xml=(string)fixture[0]!["sample"]!["payload"]!["records"]![0]!["payload"]!["xml"]!;
        var row=Sli.Agent.Core.EventXml.Parse(xml.Replace("<EventID>4624</EventID>","<EventID>6274</EventID>"),"fixture-dc","fixture-endpoint","Security");
        Assert.Single(DirectAdDcPacket.PrepareBatch(new JsonArray(row.DeepClone())));
        row["event_id"]=4624; // The signed native XML still says 6274.
        Assert.Throws<InvalidDataException>(()=>DirectAdDcPacket.PrepareBatch(new JsonArray(row)));
    }
}
