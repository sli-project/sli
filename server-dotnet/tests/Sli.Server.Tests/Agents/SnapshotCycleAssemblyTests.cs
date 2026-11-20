using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Sli.Server.Agents.SnapshotPublication;
using Xunit;
namespace Sli.Server.Tests.Agents;
public sealed class SnapshotCycleAssemblyTests
{
    [Fact]
    public void ValidatesBothFamiliesAndRejectsTamperedPayload()
    {
        var config = new JsonObject { ["source_instance_id"]="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ["domain_sid"]="S-1-5-21-1-2-3", ["domain_dns"]="example.test", ["scope"]="domain" };
        var policy = SnapshotIngressPolicy.Parse(SnapshotPolicy.Gpo, config);
        var rows = new List<SnapshotCycleRow>(); Cursor before = Cursor.Start("snapshot");
        foreach (string family in policy.Families)
        {
            byte[] fragment = Encoding.UTF8.GetBytes(family == "gpo_v2" ? "{\"gpos\":[]}" : "{\"records\":[]}");
            var payload = new JsonObject { ["contract"]="sli.gpo-snapshot.chunk.v1", ["cycle_id"]="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ["family"]=family, ["slot_start_utc"]="2026-10-07T11:00:00+00:00", ["chunk_index"]=0, ["chunk_count"]=1, ["cycle_families"]=policy.Config["families"]!.DeepClone(), ["total_objects"]=0, ["total_bytes"]=fragment.Length, ["family_sha256"]=Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(fragment)), ["records"]=new JsonArray(new JsonObject {["data_b64"]=Convert.ToBase64String(fragment)}), ["domain_sid"]=policy.Config["domain_sid"]!.DeepClone(), ["domain_dns"]=policy.Config["domain_dns"]!.DeepClone(), ["scope"]=policy.Config["scope"]!.DeepClone() };
            var after=SnapshotStream.MakeCursor(payload);
            var e=new Envelope(Guid.NewGuid().ToString(),"dddddddd-dddd-4ddd-8ddd-dddddddddddd",policy.SourceId,SnapshotPolicy.Gpo,"1.0.0",policy.Revision,"snapshot",policy.SourceId,rows.Count+1,before,after,"sli.gpo-snapshot.chunk.v1",Packets.Digest(payload),1,CanonicalJson.Length(payload),"2026-10-07T11:00:01+00:00","complete",0,0);
            rows.Add(new(e.ToJson(),payload,Packets.Digest(e.ToJson()))); before=after;
        }
        var assembled=SnapshotCycleAssembly.ValidateAndAssemble("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","dddddddd-dddd-4ddd-8ddd-dddddddddddd","2026-10-07T11:00:00+00:00",policy,rows);
        Assert.NotNull(assembled); Assert.Equal(2,assembled.Count);
        var transport = new SnapshotTransport(Guid.Parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),"S-1-5-21-1-2-3",policy.Config,assembled,rows,true);
        Assert.Equal(2,SnapshotFamilyDecoder.Decode(transport).Count);
        var corrupted = new Dictionary<string, byte[]>(assembled) { ["gpo_v2"] = Encoding.UTF8.GetBytes("{") };
        Assert.Throws<ProtocolException>(()=>SnapshotFamilyDecoder.Decode(transport with { Families=corrupted }));
        Assert.Null(SnapshotCycleAssembly.ValidateAndAssemble("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","dddddddd-dddd-4ddd-8ddd-dddddddddddd","2026-10-07T11:00:00+00:00",policy,rows.Take(1).ToList()));
        rows[1].Payload["family_sha256"]=new string('0',64);
        var e2 = Envelope.Parse(rows[1].Envelope) with { PayloadSha256=Packets.Digest(rows[1].Payload) };
        rows[1]=new(e2.ToJson(),rows[1].Payload,Packets.Digest(e2.ToJson()));
        Assert.Throws<ProtocolException>(()=>SnapshotCycleAssembly.ValidateAndAssemble("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","dddddddd-dddd-4ddd-8ddd-dddddddddddd","2026-10-07T11:00:00+00:00",policy,rows));
    }
}
