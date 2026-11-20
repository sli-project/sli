using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class SnapshotIngressTests
{
    private static JsonObject Config() => new()
    {
        ["source_instance_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        ["domain_sid"] = "S-1-5-21-1-2-3", ["domain_dns"] = "example.test", ["scope"] = "domain"
    };

    [Fact]
    public void ServerPolicyAcceptsSourceUnicodeCodepoints()
    {
        var input = Config(); input["scope"] = string.Concat(Enumerable.Repeat("😀",300));
        var policy = Sli.Server.Agents.Ingress.SnapshotIngressPolicy.Parse(SnapshotPolicy.Gpo,input);
        Assert.Equal(300, policy.Config["scope"]!.GetValue<string>().EnumerateRunes().Count());
    }

    [Fact]
    public void ServerPolicyAcceptsSourceDecimalRevision()
    {
        var input = Config(); input["policy_revision"] = "١";
        var policy = Sli.Server.Agents.Ingress.SnapshotIngressPolicy.Parse(SnapshotPolicy.Gpo,input);
        Assert.Equal("١", policy.Revision);
    }
    private static (Sli.Agent.Protocol.Envelope Envelope, JsonObject Payload, SnapshotPolicy Policy) Chunk(string module)
    {
        var config = Config(); config["policy_revision"] = "1";
        var policy = Sli.Server.Agents.Ingress.SnapshotIngressPolicy.Parse(module, config);
        var family = policy.Families[0];
        var payload = new JsonObject
        {
            ["contract"] = module + ".chunk.v1", ["cycle_id"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            ["family"] = family, ["slot_start_utc"] = "2026-10-07T11:00:00+00:00", ["chunk_index"] = 0, ["chunk_count"] = 1,
            ["cycle_families"] = policy.Config["families"]!.DeepClone(), ["total_objects"] = 0, ["total_bytes"] = 0,
            ["family_sha256"] = new string('a', 64), ["records"] = new JsonArray(new JsonObject { ["data_b64"] = "" }),
            ["domain_sid"] = policy.Config["domain_sid"]!.DeepClone(), ["domain_dns"] = policy.Config["domain_dns"]!.DeepClone(), ["scope"] = policy.Config["scope"]!.DeepClone()
        };
        var envelope = new Sli.Agent.Protocol.Envelope("cccccccc-cccc-4ccc-8ccc-cccccccccccc", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", policy.SourceId,
            module,"1.0.0", "1", "snapshot", policy.SourceId, 1, Sli.Agent.Protocol.Cursor.Start("snapshot"),
            SnapshotStream.MakeCursor(payload), module + ".chunk.v1", new string('a',64),1,0,"2026-10-07T11:00:01+00:00","complete",0,0);
        return (envelope,payload,policy);
    }

    [Theory]
    [InlineData(SnapshotPolicy.Ad)]
    [InlineData(SnapshotPolicy.Gpo)]
    public void SnapshotSourceValidChunksAndNegativeControls(string module)
    {
        var (envelope,payload,policy) = Chunk(module);
        Sli.Server.Agents.Ingress.SnapshotChunkValidator.Validate(envelope,payload,policy);
        var gap=envelope with { ContinuityState="gap" };
        Sli.Server.Agents.Ingress.SnapshotChunkValidator.Validate(gap,payload,policy,transportGap:true);
        Assert.Throws<ProtocolException>(()=>Sli.Server.Agents.Ingress.SnapshotChunkValidator.Validate(gap,payload,policy));
        payload["records"]![0]!["data_b64"] = "AA==";
        Assert.Equal("agent_snapshot_chunk_invalid", Assert.Throws<Sli.Agent.Protocol.ProtocolException>(() => Sli.Server.Agents.Ingress.SnapshotChunkValidator.Validate(envelope,payload,policy)).Code);
    }
    [Fact]
    public void DecimalDigitCoverageMatchesPinnedPythonUnicode()
    {
        string path = Environment.GetEnvironmentVariable("SLI_SNAPSHOT_DECIMAL_VECTORS") ?? throw new InvalidOperationException("source decimal vectors required");
        using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(path));
        Assert.Equal("16.0.0", doc.RootElement.GetProperty("unicode_version").GetString());
        var expected = doc.RootElement.GetProperty("digits").EnumerateArray().Select(v => v[0].GetInt32()).ToHashSet();
        for (int code = 0; code <= 0x10ffff; code++)
            if (System.Text.Rune.TryCreate(code, out var rune) && System.Text.Rune.GetUnicodeCategory(rune) == System.Globalization.UnicodeCategory.DecimalDigitNumber)
                Assert.Contains(code, expected);
        foreach (var vector in doc.RootElement.GetProperty("digits").EnumerateArray())
        {
            string text = char.ConvertFromUtf32(vector[0].GetInt32());
            Assert.Equal(vector[1].GetInt32(), System.Globalization.CharUnicodeInfo.GetDecimalDigitValue(text, 0));
        }
        var invalidSid = Config(); invalidSid["domain_sid"] = "S-١-5-21-1-2-3";
        Assert.Equal("agent_snapshot_policy_invalid", Assert.Throws<AgentException>(() => SnapshotIngressPolicy.Parse(SnapshotPolicy.Gpo,invalidSid)).Code);
        var invalid = Config(); invalid["policy_revision"] = "²";
        Assert.Equal("agent_snapshot_policy_invalid", Assert.Throws<AgentException>(() => Sli.Server.Agents.Ingress.SnapshotIngressPolicy.Parse(SnapshotPolicy.Gpo,invalid)).Code);
    }
    [Theory]
    [InlineData("S-1-5-21-١-٢-٣")]
    [InlineData("S-1-5-21-𝟙-𝟚-𝟛")]
    public void ServerPolicyPreservesUnicodeDecimalSid(string sid)
    {
        var input = Config(); input["domain_sid"] = sid;
        var policy = Sli.Server.Agents.Ingress.SnapshotIngressPolicy.Parse(SnapshotPolicy.Gpo,input);
        Assert.Equal(sid,policy.Config["domain_sid"]!.GetValue<string>());
    }
    [Fact]
    public void ChunkBoundaryAndCrossFamilyCursorFollowSource()
    {
        var (envelope,payload,policy) = Chunk(SnapshotPolicy.Gpo);
        payload["total_bytes"] = 32769; payload["chunk_count"] = 2;
        payload["records"]![0]!["data_b64"] = Convert.ToBase64String(new byte[32768]);
        envelope = envelope with { CursorAfter = SnapshotStream.MakeCursor(payload) };
        SnapshotChunkValidator.Validate(envelope,payload,policy);
        var prior = envelope.CursorAfter;
        payload["chunk_index"] = 1; payload["records"]![0]!["data_b64"] = "AA==";
        envelope = envelope with { CursorBefore = prior, CursorAfter = SnapshotStream.MakeCursor(payload) };
        SnapshotChunkValidator.Validate(envelope,payload,policy);
        var last = envelope.CursorAfter;
        payload["family"] = policy.Families[1]; payload["chunk_index"] = 0; payload["chunk_count"] = 1; payload["total_bytes"] = 0;
        payload["records"]![0]!["data_b64"] = "";
        envelope = envelope with { CursorBefore = last, CursorAfter = SnapshotStream.MakeCursor(payload) };
        SnapshotChunkValidator.Validate(envelope,payload,policy);
        payload["records"]![0]!["data_b64"] = " ";
        Assert.Equal("agent_snapshot_chunk_invalid",Assert.Throws<ProtocolException>(() => SnapshotChunkValidator.Validate(envelope,payload,policy)).Code);
    }

    [Fact]
    public void SnapshotSlotRejectsSubsecondAndMalformedCycle()
    {
        var (envelope,payload,policy) = Chunk(SnapshotPolicy.Gpo);
        payload["slot_start_utc"] = "2026-10-07T11:00:00.000001+00:00";
        Assert.Equal("agent_snapshot_chunk_invalid",Assert.Throws<ProtocolException>(() => SnapshotChunkValidator.Validate(envelope,payload,policy)).Code);
        payload["slot_start_utc"] = "2026-10-07T11:00:00+00:00";
        payload["cycle_id"] = null;
        Assert.Equal("agent_snapshot_chunk_invalid",Assert.Throws<ProtocolException>(() => SnapshotChunkValidator.Validate(envelope,payload,policy)).Code);
    }
    [Fact]
    public void SourceSnapshotChunkVectorsMatch()
    {
        string path = Environment.GetEnvironmentVariable("SLI_SNAPSHOT_CHUNK_VECTORS") ?? throw new InvalidOperationException("source chunk vectors required");
        var rows = JsonNode.Parse(File.ReadAllText(path))!.AsArray();
        Assert.Equal(10,rows.Count);
        foreach (var item in rows)
        {
            var row = item!.AsObject();
            var envelope = Envelope.Parse(row["envelope"]);
            var payload = row["payload"]!.AsObject();
            var policy = SnapshotIngressPolicy.Parse(envelope.ModuleId,row["config"]!.AsObject());
            bool actual;
            try { SnapshotChunkValidator.Validate(envelope,payload,policy); actual=true; }
            catch (ProtocolException error) { Assert.Equal("agent_snapshot_chunk_invalid",error.Code); actual=false; }
            Assert.True(actual == row["valid"]!.GetValue<bool>(),row["name"]!.GetValue<string>());
        }
    }
}
