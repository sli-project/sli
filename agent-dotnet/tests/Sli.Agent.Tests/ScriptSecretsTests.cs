using System.Text.Json.Nodes;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class ScriptSecretsTests
{
    public static IEnumerable<object[]> Vectors() => Support.Vectors.Load("script-secrets.json").AsArray()
        .Select(v => new object[] { v!["name"]!.GetValue<string>() });

    private sealed class Source(string xml) : IEventLogSource
    {
        public SourceBatch Read(string channel, ChannelProgress progress, int limit) => new([new(xml, "bookmark-1")]);
    }

    [Theory]
    [MemberData(nameof(Vectors))]
    public void SharedVectorsAreMaskedBeforeSigning(string name)
    {
        var v = Support.Vectors.Load("script-secrets.json").AsArray().Single(v => v!["name"]!.GetValue<string>() == name)!;
        string Expand(string value)
        {
            foreach (var (placeholder, parts) in v["substitutions"]?.AsObject() ?? new JsonObject())
                value = value.Replace(placeholder, string.Concat(parts!.AsArray().Select(p => p!.GetValue<string>())), StringComparison.Ordinal);
            foreach (var (placeholder, parts) in v["repetitions"]?.AsObject() ?? new JsonObject())
                value = value.Replace(placeholder, string.Concat(Enumerable.Repeat(parts![0]!.GetValue<string>(), parts[1]!.GetValue<int>())), StringComparison.Ordinal);
            return value;
        }
        var script = Expand(v["script"]!.GetValue<string>());
        var expected = Expand(v["expected"]!.GetValue<string>());
        var count = v["count"]!.GetValue<int>();
        Assert.Equal((expected, count, v["truncated"]!.GetValue<bool>()), ScriptSecrets.Mask(script));
        Assert.Equal((expected, 0, false), ScriptSecrets.Mask(expected));
        if (v["max_ms"] is not null)
        {
            for (var i = 0; i < 3; i++)
            {
                var timer = Stopwatch.StartNew();
                var result = ScriptSecrets.Mask(script);
                timer.Stop();
                Assert.True(timer.Elapsed.TotalMilliseconds < v["max_ms"]!.GetValue<int>(), name + ": " + timer.Elapsed.TotalMilliseconds);
                Assert.Equal((expected, count, v["truncated"]!.GetValue<bool>()), result);
            }
        }
        XNamespace ns = EventXml.Namespace;
        var channel = WorkstationPolicy.Channels[6];
        var root = new XElement(ns + "Event",
            new XElement(ns + "System", new XElement(ns + "Provider", new XAttribute("Name", "Microsoft-Windows-PowerShell")),
                new XElement(ns + "EventID", 4104), new XElement(ns + "EventRecordID", 1), new XElement(ns + "Channel", channel)),
            new XElement(ns + "EventData", new XElement(ns + "Data", new XAttribute("Name", "ScriptBlockText"), script)));
        var sample = new WorkstationsModule(Helpers.HostId, WorkstationPolicy.Parse(new()), new Source(root.ToString()))
            .Collect(null, Helpers.Now, channel).Sample!;
        var row = sample.Payload["records"]![0]!["payload"]!;
        var data = EventXml.ParseBounded(row["xml"]!.GetValue<string>()).Descendants(ns + "Data")
            .ToDictionary(e => e.Attribute("Name")!.Value, e => e.Value);
        var actual = data["ScriptBlockText"];
        if (v["detection"] is not null) Assert.Contains(v["detection"]!.GetValue<string>(), actual, StringComparison.Ordinal);
        Assert.StartsWith(actual, expected, StringComparison.Ordinal);
        Assert.Equal(actual.Length == 0 ? null : actual, row["properties"]![0]?.GetValue<string>());
        Assert.Equal(count, row["secrets_masked"]!.GetValue<int>());
        Assert.Equal(count.ToString(System.Globalization.CultureInfo.InvariantCulture), data.GetValueOrDefault("SecretsMasked", "0"));
        Assert.Equal(v["truncated"]!.GetValue<bool>(), data.GetValueOrDefault("ScriptBlockTextTruncated") == "true");
        using var key = Helpers.NewKey();
        var packet = Packets.Make(Helpers.Signer(key), Helpers.AgentId, 1, sample, Helpers.Now);
        Assert.Equal(packet.Envelope.PacketId, PacketVerifier.Verify(packet.ToJson(), key).PacketId);
        if (count > 0) Assert.DoesNotContain(script, packet.ToJson().ToJsonString(new() { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
        foreach (var secret in v["secrets"]!.AsArray())
            Assert.DoesNotContain(Expand(secret!.GetValue<string>()), packet.ToJson().ToJsonString(new() { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
        var forged = packet.ToJson();
        forged["payload"]!["records"]![0]!["payload"]!["properties"]![0] = "changed";
        Assert.Throws<ProtocolException>(() => PacketVerifier.Verify(forged, key));
    }

    [Fact]
    public void RegexTimeoutPreservesSignedEventAndFailureMarker()
    {
        var script = new string('x', 8192);
        var raw = Encoding.UTF8.GetBytes(script);
        var expected = ScriptSecrets.MaskFailed + " bytes=8192 sha256=" + Convert.ToHexStringLower(SHA256.HashData(raw));
        var patterns = ((string Kind, string Mode, Regex Pattern)[])typeof(ScriptSecrets)
            .GetField("Patterns", BindingFlags.Static | BindingFlags.NonPublic)!.GetValue(null)!;
        var original = patterns[0];
        // Inject a real regex timeout without changing any production timeout.
        var timeout = new Regex("(x+)+y", RegexOptions.None, TimeSpan.FromTicks(1));
        Assert.Throws<RegexMatchTimeoutException>(() => timeout.IsMatch(script));
        try
        {
            patterns[0] = ("token", "value", timeout);
            Assert.Equal((expected, 1, true), ScriptSecrets.Mask(script));
            XNamespace ns = EventXml.Namespace;
            var channel = WorkstationPolicy.Channels[6];
            var root = new XElement(ns + "Event",
                new XElement(ns + "System", new XElement(ns + "Provider", new XAttribute("Name", "Microsoft-Windows-PowerShell")),
                    new XElement(ns + "EventID", 4104), new XElement(ns + "EventRecordID", 1), new XElement(ns + "Channel", channel)),
                new XElement(ns + "EventData", new XElement(ns + "Data", new XAttribute("Name", "ScriptBlockText"), script)));
            var collection = new WorkstationsModule(Helpers.HostId, WorkstationPolicy.Parse(new()), new Source(root.ToString()))
                .Collect(null, Helpers.Now, channel);
            var sample = collection.Sample!;
            var row = sample.Payload["records"]![0]!["payload"]!;
            Assert.Equal(4104, row["event_id"]!.GetValue<int>());
            Assert.Equal(expected, row["properties"]![0]!.GetValue<string>());
            Assert.Equal(1, row["secrets_masked"]!.GetValue<int>());
            var data = EventXml.ParseBounded(row["xml"]!.GetValue<string>()).Descendants(ns + "Data")
                .ToDictionary(e => e.Attribute("Name")!.Value, e => e.Value);
            Assert.Equal(expected, data["ScriptBlockText"]);
            Assert.Equal("true", data["ScriptMaskingFailed"]);
            Assert.Equal("true", data["ScriptBlockTextTruncated"]);
            using var key = Helpers.NewKey();
            var packet = Packets.Make(Helpers.Signer(key), Helpers.AgentId, 1, sample, Helpers.Now);
            Assert.Equal(packet.Envelope.PacketId, PacketVerifier.Verify(packet.ToJson(), key).PacketId);
            Assert.DoesNotContain(script, packet.ToJson().ToJsonString());
        }
        finally { patterns[0] = original; }
        Assert.Equal((expected, 0, false), ScriptSecrets.Mask(expected));
    }
}
