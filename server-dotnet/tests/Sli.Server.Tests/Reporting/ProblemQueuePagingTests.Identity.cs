using System.Text.Json.Nodes;
using Sli.Server.Problems;
using Sli.Server.Reporting.V2;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed partial class ProblemQueuePagingTests
{
    [Theory]
    [InlineData("users_v2", "displayName")]
    [InlineData("computers_v6", "name")]
    public async Task QueueNamesComeFromCurrentDomainSnapshotWithoutHistoricalWitness(string family, string field)
    {
        const string sid = "S-1-5-21-100000001-200000002-300000003-1101";
        JsonObject Finding(long domain) => new() {
            ["id"] = domain, ["entities"] = new JsonArray(new JsonObject { ["display_name"] = "sid:fixture-dc:" + sid }),
            ["evidence"] = new JsonArray(new JsonObject { ["identity_domain_min"] = domain, ["identity_domain_max"] = domain })
        };
        var rows = new JsonArray(Finding(7), Finding(8));
        await ProblemRepository.AttachQueueNames(rows, (requestedFamily, _, _) => Task.FromResult(requestedFamily == family
            ? new List<JsonObject> { new() { ["domain_id"] = 7, ["snapshot"] = new JsonObject {
                [family == "users_v2" ? "users" : "objects"] = new JsonArray(new JsonObject { ["sid"] = sid, [field] = "fixture-name" }) } } }
            : new List<JsonObject>()), TestContext.Current.CancellationToken);
        var result = SecurityProblemsReader.Render(Context(), new() { ["items"] = rows });
        Assert.Equal("fixture-name", result["items"]![0]!["entity_text"]!.ToString());
        Assert.Equal("Неизвестная учётная запись", result["items"]![1]!["entity_text"]!.ToString());
    }

    [Theory]
    [InlineData("ru", "Неизвестная учётная запись")]
    [InlineData("en", "Unknown account")]
    public void QueueObjectsUseDirectoryNamesAndKeepIdentifiersInDetails(string locale, string unknown)
    {
        const string sid = "S-1-5-21-100000001-200000002-300000003-1101";
        JsonObject Finding(bool named) => new() {
            ["id"] = 7, ["actor"] = sid, ["target"] = sid,
            ["entities"] = new JsonArray(new JsonObject { ["display_name"] = "42", ["entity_role"] = "source_host" },
                new JsonObject { ["display_name"] = sid, ["entity_role"] = "target" }),
            ["_queue_names"] = named ? new JsonObject { [sid] = "fixture-admin" } : new JsonObject()
        };
        foreach (bool named in new[] { true, false }) {
            var raw = new JsonObject { ["items"] = new JsonArray(Finding(named)) };
            var row = SecurityProblemsReader.Render(Context() with { Language = locale }, raw)["items"]![0]!;
            Assert.Equal(named ? "fixture-admin" : unknown, row["entity_text"]!.ToString());
            Assert.Contains(sid, row["entity_identifiers"]!.ToString());
            var hidden = SecurityProblemsReader.Render(Context(identity: false), raw)["items"]![0]!;
            Assert.Null(hidden["entity_text"]);
        }
    }
}
