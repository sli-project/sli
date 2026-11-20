using System.Text.Json.Nodes;
using Sli.Server.Operations;
using Sli.Server.SourcePacks.Examples;
using Xunit;

namespace Sli.Server.Tests.Events;

// Vectors from tests/events/test_example_linux_auth_pack.py and its auth.log fixture.
public sealed class ExampleLinuxAuthPackTests
{
    private static string[] Lines()
    {
        using var stream = typeof(ExampleLinuxAuthPackTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Events.linux-auth.log.txt")!;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries);
    }

    private static JsonObject[] Events() => Lines().Select(line => LinuxAuthPack.ParseLine(line, 2026))
        .OfType<JsonObject>().ToArray();

    [Fact]
    public void Example_manifest_and_catalog_own_only_linux_auth_and_are_not_product_packs()
    {
        var pack = LinuxAuthPack.Manifest();
        Assert.Equal(2, pack["schema_version"]!.GetValue<int>());
        Assert.Equal("example.linux-auth", pack["pack_id"]!.GetValue<string>());
        Assert.Equal("example-linux-auth-v1", pack["normalizer"]!.GetValue<string>());
        Assert.Equal(new[] { "linux:auth" }, pack["channels"]!.AsArray().Select(n => n!.GetValue<string>()));
        Assert.Equal(new[] { "authentication", "privilege_use" }, pack["capabilities"]!.AsArray().Select(n => n!.GetValue<string>()));
        Assert.DoesNotContain(new OperationsCatalog().Packs(), p => p!["pack_id"]!.GetValue<string>() == "example.linux-auth");
        var catalog = LinuxAuthPack.Catalog();
        Assert.Equal(2, catalog["schema_version"]!.GetValue<int>());
        var entries = catalog["entries"]!.AsArray().OfType<JsonObject>().ToArray();
        Assert.Equal(new[] { 100, 101, 110, 120, 121 }, entries.Select(e => e["event_id"]!.GetValue<int>()).Order());
        foreach (var entry in entries)
        {
            Assert.Equal("example.linux-auth", entry["source"]!.GetValue<string>());
            Assert.Equal("linux:auth", entry["stream"]!.GetValue<string>());
            Assert.Equal("linux:auth", entry["channel"]!.GetValue<string>());
            int id = entry["event_id"]!.GetValue<int>();
            Assert.Equal(id.ToString(System.Globalization.CultureInfo.InvariantCulture), entry["event_key"]!.GetValue<string>());
            Assert.Equal(id == 110 ? "sudo" : "sshd", entry["provider_name"]!.GetValue<string>());
            Assert.Equal(id is 101 or 110 ? "medium" : "low", entry["severity"]!.GetValue<string>());
            Assert.Equal(id is 101 or 110 ? "medium" : "low", entry["base_risk"]!.GetValue<string>());
            Assert.Equal("technical", entry["purpose_tier"]!.GetValue<string>());
            Assert.Equal("context", entry["noise_class"]!.GetValue<string>());
            Assert.Equal(id == 110 ? "privilege_management" : "authentication", entry["category"]!.GetValue<string>());
            Assert.Equal(LinuxAuthPack.EventLabel(id, "ru"), entry["title"]!.GetValue<string>());
            Assert.False(string.IsNullOrWhiteSpace(entry["why"]!.GetValue<string>()));
            Assert.False(string.IsNullOrWhiteSpace(entry["fix"]!.GetValue<string>()));
        }
    }

    [Fact]
    public void Optional_handlers_default_to_no_rules_families_or_state()
    {
        Assert.Empty(LinuxAuthPack.FindingRules());
        Assert.Empty(LinuxAuthPack.EventIdsForSearchFamily("authentication"));
        Assert.Null(LinuxAuthPack.StateSemantics("linux:auth", 100));
    }

    [Fact]
    public void Fixture_parses_exactly_the_nine_understood_events()
    {
        Assert.Equal(15, Lines().Length);
        var events = Events();
        Assert.Equal(new[] { 100, 120, 110, 101, 101, 100, 100, 121, 121 }, events.Select(e => e["event_id"]!.GetValue<int>()));
        var first = events[0];
        Assert.Equal("alice", first["user"]!.GetValue<string>());
        Assert.Equal("192.0.2.10", first["source_ip"]!.GetValue<string>());
        Assert.Equal("publickey", first["auth_method"]!.GetValue<string>());
        Assert.Equal("web01.example.test", first["host"]!.GetValue<string>());
        Assert.Equal("sshd", first["program"]!.GetValue<string>());
        Assert.Equal("1201", first["pid"]!.GetValue<string>());
        Assert.Equal(new DateTimeOffset(2026, 9, 30, 10, 15, 1, TimeSpan.Zero), first["time"]!.GetValue<DateTimeOffset>());
        Assert.Equal("/usr/bin/apt update", events[2]["command"]!.GetValue<string>());
        Assert.Equal("alice", events[2]["user"]!.GetValue<string>());
        Assert.Null(events[2]["pid"]);
        Assert.Equal("admin", events[4]["user"]!.GetValue<string>());
        Assert.Equal(1, events[6]["time"]!.GetValue<DateTimeOffset>().Day);
        // No guessing cron/sudo PAM sessions, preauth closure, garbage, kernel or Feb 30.
        foreach (int index in new[] { 3, 8, 10, 11, 12, 13 }) Assert.Null(LinuxAuthPack.ParseLine(Lines()[index], 2026));
        Assert.Null(LinuxAuthPack.ParseLine("", 2026));
        Assert.Null(LinuxAuthPack.ParseLine("Feb 30 10:34:00 h sshd[1]: Accepted password for a from 192.0.2.1 port 1", 2026));
    }

    [Fact]
    public void Caller_timezone_is_converted_to_utc()
    {
        const string line = "Sep 30 10:00:00 h.example.test sshd[1]: Accepted password for alice from 192.0.2.1 port 22 ssh2";
        var zone = TimeZoneInfo.CreateCustomTimeZone("example-plus-three", TimeSpan.FromHours(3), "example", "example");
        var actual = LinuxAuthPack.ParseLine(line, 2026, zone)!;
        Assert.Equal(new DateTimeOffset(2026, 9, 30, 7, 0, 0, TimeSpan.Zero), actual["time"]!.GetValue<DateTimeOffset>());
        Assert.Equal(TimeSpan.Zero, actual["time"]!.GetValue<DateTimeOffset>().Offset);
    }

    [Fact]
    public void Facts_and_entity_semantics_follow_the_event_model_for_every_fixture_event()
    {
        string[] keys = ["process_name", "process_id", "target_server_name", "service_name", "task_name", "task_action", "task_author", "run_as", "logon_type", "result_code", "object_name", "share_name", "message_sample"];
        foreach (var ev in Events())
        {
            int id = ev["event_id"]!.GetValue<int>();
            var facts = LinuxAuthPack.EventFacts(ev, ev);
            Assert.Equal(keys.Order(), facts.Select(p => p.Key).Order());
            foreach (var (fact, field) in new[] { ("process_name", "program"), ("process_id", "pid"), ("target_server_name", "host"), ("logon_type", "auth_method"), ("object_name", "command") })
                Assert.True(JsonNode.DeepEquals(ev[field], facts[fact]), fact);
            Assert.Equal(id == 100 ? "success" : id == 101 ? "failure" : null, facts["result_code"]?.GetValue<string>());
            foreach (string key in new[] { "service_name", "task_name", "task_action", "task_author", "run_as", "share_name", "message_sample" }) Assert.Null(facts[key]);
            Assert.Equal(default, LinuxAuthPack.EntitySemantics("linux:auth", id));
            Assert.False(string.IsNullOrWhiteSpace(LinuxAuthPack.EventLabel(id, "ru")));
            Assert.NotEqual(LinuxAuthPack.EventLabel(id, "en"), LinuxAuthPack.EventLabel(id, "ru"));
            Assert.True(JsonNode.DeepEquals(facts, LinuxAuthPack.EventFacts(ev)));
        }
        Assert.Empty(LinuxAuthPack.EventFacts(new JsonObject { ["event_id"] = 4624 }, new JsonObject()));
        Assert.Null(LinuxAuthPack.EventLabel(4624, "ru"));
    }

    [Theory]
    [InlineData(100, "sshd: вход принят", "sshd: login accepted")]
    [InlineData(101, "sshd: вход отклонён", "sshd: login failed")]
    [InlineData(110, "sudo: выполнена команда", "sudo: command run")]
    [InlineData(120, "Сессия открыта", "Session opened")]
    [InlineData(121, "Сессия закрыта", "Session closed")]
    public void Labels_match_the_reference_and_default_to_russian(int id, string ru, string en)
    {
        Assert.Equal(ru, LinuxAuthPack.EventLabel(id, "ru"));
        Assert.Equal(en, LinuxAuthPack.EventLabel(id, "EN"));
        Assert.Equal(ru, LinuxAuthPack.EventLabel(id, "unknown"));
    }
}
