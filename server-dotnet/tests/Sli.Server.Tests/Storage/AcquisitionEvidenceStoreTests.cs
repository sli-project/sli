using System.Security.Cryptography;
using System.Text;
using Sli.Agent.Core;
using Sli.Server.Agents.Radius;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Parity: tests/storage/test_acquisition_evidence_store.py.
public sealed class AcquisitionEvidenceStoreTests : IDisposable
{
    private const string Source = "radius-fixture-1";
    private const string Generation = "in-20260730";
    private const string Binding = "nps-database-compatible-log";
    private static readonly Guid Epoch = Guid.Parse("00000000-0000-4000-8000-000000000042");
    private readonly string root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "sli-acquisition-evidence-" + Guid.NewGuid().ToString("N")));

    private static string Hash(string record) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(record)));

    private static string Line(string packet, string status = "")
    {
        var fields = Enumerable.Repeat("", 66).ToArray();
        fields[0] = "NPS01"; fields[1] = "IAS"; fields[2] = "07/30/2026"; fields[3] = "15:00:00";
        fields[4] = packet; fields[6] = "example.test/Users/sample.user"; fields[11] = "VPN-GW-01";
        fields[26] = "opaque-class"; fields[31] = status; fields[35] = "opaque-session";
        return string.Join(',', fields);
    }

    private RadiusEvidence Publish(string record, int maximumObjectBytes = 65536) => RadiusEvidenceStore.PublishCanonicalRecord(
        root, Source, "radius-accounting", Binding, Epoch, Generation, 100, 0, record, Hash(record), maximumObjectBytes);

    private static Task<RadiusPlan> Plan(string[] records) => RadiusPlanner.ProjectAsync(
        records, Source, "N. Central Asia Standard Time", 420, new DateTimeOffset(2026, 7, 30, 8, 0, 0, TimeSpan.Zero), [],
        _ => Task.FromResult<string?>("sid:S-1-5-21-100000001-200000002-300000003-1101"));

    private IReadOnlyList<RadiusEvidence> PublishBatch(RadiusPlan plan, string[] records) => RadiusEvidenceStore.PublishBatch(
        root, new RadiusCursor(Source, "radius-accounting", Binding, Generation, 0, null), Epoch, Generation, plan, records);

    private string ObjectPath(RadiusEvidence evidence) => Path.Combine(root, "published", "acquisition-radius",
        evidence.Id.ToString("N")[..2], evidence.Id.ToString("N") + ".record");

    [Fact]
    public void PublicationIsDeterministicVerifiedAndPayloadSafe()
    {
        string record = Line("4", "1"), digest = Hash(record);
        var before = DateTimeOffset.UtcNow;
        var first = Publish(record);
        var second = Publish(record);

        Assert.Equal(first.Id, second.Id);
        Assert.Equal(first.Reference, second.Reference);
        Assert.Equal(digest, first.Hash);
        Assert.Equal(digest, second.Hash);
        Assert.Equal(Encoding.UTF8.GetByteCount(record), second.Size);
        Assert.InRange(second.VerifiedAt, before, DateTimeOffset.UtcNow);
        Assert.Equal(record, RadiusEvidenceStore.ReadVerified(root, second));
        Assert.DoesNotContain(record, first.ToString());
        Assert.Single(Directory.EnumerateFiles(Path.Combine(root, "published"), "*.record", SearchOption.AllDirectories));
    }

    [Fact]
    public void IdentityConflictKeepsOriginalBytesAndReturnsClosedCode()
    {
        string record = Line("4", "1");
        var first = Publish(record);
        var error = Assert.Throws<IOException>(() => Publish(Line("4", "2")));
        Assert.Equal("evidence_identity_conflict", error.Message);
        Assert.Equal(record, RadiusEvidenceStore.ReadVerified(root, first));
    }

    [Fact]
    public void ReadbackUsesCoreIdentityAndRejectsExternalReference()
    {
        string record = Line("2");
        var publication = Publish(record);
        // Unlike Python's object_path, .NET metadata has no caller-controlled path.
        var forged = publication with { Reference = Path.Combine(Path.GetDirectoryName(root)!, "outside-sensitive-file") };
        var error = Assert.Throws<ArgumentException>(() => RadiusEvidenceStore.ReadVerified(root, forged));
        Assert.Equal("evidence_reference_invalid", error.Message);
        Assert.Equal(record, RadiusEvidenceStore.ReadVerified(root, publication));
    }

    [Theory]
    [InlineData(64, 40)]
    [InlineData(65536, 32769)]
    public void OversizeUtf8LeavesNoPartialObject(int maximum, int characters)
    {
        string record = new('я', characters);
        var error = Assert.Throws<ArgumentException>(() => Publish(record, maximum));
        Assert.Equal("evidence_object_too_large", error.Message);
        Assert.False(Directory.Exists(root));
    }

    [Fact]
    public void Utf8ObjectAtExactByteBoundaryIsAccepted()
    {
        string record = new('я', 32);
        var publication = Publish(record, 64);
        Assert.Equal(64, publication.Size);
        Assert.Equal(record, RadiusEvidenceStore.ReadVerified(root, publication, 64));
    }

    [Fact]
    public async Task RadiusBridgeProducesExactPostgresManifestInputs()
    {
        string[] records = [Line("2"), Line("4", "1")];
        var plan = await Plan(records);
        var before = DateTimeOffset.UtcNow;
        var evidence = PublishBatch(plan, records);

        Assert.Equal(new[] {
            "0d176fef68a82662f7a6d292f06a75fecd27ce0045c93eb39b38c26bd7599a96",
            "d8667391d01db0e50fb06f5234a73651fef311a207a088caa2a264b54163366b"
        }, plan.EvidenceHashes);
        Assert.Equal(plan.EvidenceHashes, evidence.Select(item => item.Hash));
        // Python uuid5 vectors include cursor epoch, current offset and batch ordinal.
        Assert.Equal(new[] { Guid.Parse("cc918424-0014-582e-85d3-22b325fc6f22"), Guid.Parse("7a9905e3-2c3e-5278-ba60-7db2e5d084db") }, evidence.Select(item => item.Id));
        for (int i = 0; i < records.Length; i++)
        {
            var item = evidence[i];
            Assert.Equal("evidence:acquisition.radius." + item.Id.ToString("N"), item.Reference);
            Assert.Equal(Hash(records[i]), item.Hash); // Used for both manifest SHA-256 columns.
            Assert.Equal(Encoding.UTF8.GetByteCount(records[i]), item.Size);
            Assert.InRange(item.VerifiedAt, before, DateTimeOffset.UtcNow);
            Assert.Equal(records[i], RadiusEvidenceStore.ReadVerified(root, item));
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    public async Task RadiusBridgeRejectsMissingOrExtraRecordsBeforePublication(int count)
    {
        string record = Line("4", "1");
        var plan = await Plan([record]);
        var error = Assert.Throws<ArgumentException>(() => PublishBatch(plan, Enumerable.Repeat(record, count).ToArray()));
        Assert.Equal("evidence_record_count_mismatch", error.Message);
        Assert.False(Directory.Exists(root));
    }

    [Fact]
    public async Task RadiusBridgeRejectsRecordBytesThatDisagreeWithPlan()
    {
        var plan = await Plan([Line("4", "1")]);
        var error = Assert.Throws<ArgumentException>(() => PublishBatch(plan, [Line("4", "2")]));
        Assert.Equal("canonical_record_sha256_mismatch", error.Message);
        Assert.False(Directory.Exists(root));
    }

    [Fact]
    public async Task RadiusBridgeRejectsEmptyBatch()
    {
        var plan = await Plan([]);
        var error = Assert.Throws<ArgumentException>(() => PublishBatch(plan, []));
        Assert.Equal("evidence_batch_empty", error.Message);
        Assert.False(Directory.Exists(root));
    }

    [Theory]
    [InlineData("bytes")]
    [InlineData("size")]
    [InlineData("hash")]
    [InlineData("missing")]
    public void ReadbackRejectsChangedObjectOrManifest(string change)
    {
        var publication = Publish(Line("4", "1"));
        switch (change)
        {
            case "bytes": File.WriteAllText(ObjectPath(publication), Line("4", "2"), new UTF8Encoding(false)); break;
            case "size": publication = publication with { Size = publication.Size + 1 }; break;
            case "hash": publication = publication with { Hash = new string('0', 64) }; break;
            case "missing": File.Delete(ObjectPath(publication)); break;
        }
        var error = Assert.Throws<IOException>(() => RadiusEvidenceStore.ReadVerified(root, publication));
        Assert.Equal("evidence_readback_failed", error.Message);
    }

    public void Dispose()
    {
        string absolute = Path.GetFullPath(root);
        Assert.StartsWith(Path.GetFullPath(Path.GetTempPath()), absolute, StringComparison.OrdinalIgnoreCase);
        Assert.StartsWith("sli-acquisition-evidence-", Path.GetFileName(absolute), StringComparison.Ordinal);
        if (Directory.Exists(absolute)) Directory.Delete(absolute, true);
    }
}
