using System.Text;
using Sli.Server.Agents.Radius;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class RadiusAccountingCursorBootstrapTests
{
    private const string Source = "radius.radius01.example.test";
    private const string FileName = "IN260730.log";
    private const string FirstHash = "638f50b93273bd643fccfcb86f351ddbd6d19a1ad592da13e772358ceadf20f9";
    private const string SecondHash = "c11c171d2b0a08d38dac05356836af2b5cabb653565ba3446f18c1c93f8b6e3f";

    private static string Line(string status = "1")
    {
        var fields = new string[66];
        fields[0] = "NPS01";
        fields[1] = "IAS";
        fields[2] = "07/30/2026";
        fields[3] = "15:00:00";
        fields[4] = "4";
        fields[11] = "VPN-GW-01";
        fields[31] = status;
        fields[35] = "opaque-session";
        return string.Join(',', fields);
    }

    private static RadiusCursorAnchor Derive(byte[] bytes, long start = 0, long creation = 100) =>
        RadiusCursorBootstrap.DeriveCursorAnchor(Source, FileName, creation, bytes, start, start + bytes.Length);

    [Fact]
    public void AnchorStopsAfterLastCompleteRecordAndHashesCanonicalText()
    {
        string partial = Line("3")[..40];
        var anchor = Derive(Encoding.UTF8.GetBytes(Line() + "\r\n" + Line("2") + "\r\n" + partial), creation: 1_722_331_200_000_000_000);
        Assert.Equal(236L, anchor.ByteOffset);
        Assert.Equal(40L, anchor.BoundaryLagBytes);
        Assert.Equal(SecondHash, anchor.LastRecordSha256);
        Assert.Equal("gen-c8a39e0fb449d9744e634d9b9981ee2b", anchor.FileGeneration);
    }

    [Fact]
    public void GenerationIsStableForSameFileAndChangesForNewCreation()
    {
        var bytes = Encoding.UTF8.GetBytes(Line() + "\r\n");
        var first = Derive(bytes);
        var repeated = Derive(bytes);
        var replacement = Derive(bytes, creation: 101);
        Assert.Equal("gen-d9f03c5a13db0d103e1d216aca417343", first.FileGeneration);
        Assert.Equal(first.FileGeneration, repeated.FileGeneration);
        Assert.Equal("gen-a978c4fb93545e48c9429deb4d83e7ac", replacement.FileGeneration);
        Assert.NotEqual(first.FileGeneration, replacement.FileGeneration);
    }

    [Fact]
    public void TruncatedTailDiscardsFirstPartialSegment()
    {
        var bytes = Encoding.UTF8.GetBytes("partial-prefix\n" + Line() + "\n" + Line("2") + "\n");
        var anchor = Derive(bytes, start: 500);
        Assert.Equal(749L, anchor.ByteOffset);
        Assert.Equal(0L, anchor.BoundaryLagBytes);
        Assert.Equal(SecondHash, anchor.LastRecordSha256);
    }

    [Fact]
    public void NoCompleteRecordFailsClosed()
    {
        var error = Assert.Throws<RadiusCursorBootstrapError>(() => Derive("partial"u8.ToArray()));
        Assert.Equal("bootstrap_complete_record_required", error.Code);
        Assert.Equal(error.Code, error.Message);
    }

    [Fact]
    public void BomIsExcludedFromCanonicalHashAndMultibytePartialTailCountsBytes()
    {
        var anchor = Derive(Encoding.UTF8.GetBytes("\uFEFF" + Line() + "\r\nхвост😀"));
        Assert.Equal(121L, anchor.ByteOffset);
        Assert.Equal(14L, anchor.BoundaryLagBytes);
        Assert.Equal(FirstHash, anchor.LastRecordSha256);
    }

    [Fact]
    public void BlankLinesAdvanceBoundaryWithoutChangingLastRecordHash()
    {
        var anchor = Derive(Encoding.UTF8.GetBytes(Line() + "\n \t\r\n\n"));
        Assert.Equal(122L, anchor.ByteOffset);
        Assert.Equal(0L, anchor.BoundaryLagBytes);
        Assert.Equal(FirstHash, anchor.LastRecordSha256);
    }

    [Fact]
    public void GenerationNormalizesSourceAndFileCaseButIncludesTheirIdentity()
    {
        var bytes = Encoding.UTF8.GetBytes(Line() + "\n");
        var anchor = RadiusCursorBootstrap.DeriveCursorAnchor(" RADIUS.RADIUS01.EXAMPLE.TEST ", "in260730.LOG", 100, bytes, 0, bytes.Length);
        Assert.Equal("gen-d9f03c5a13db0d103e1d216aca417343", anchor.FileGeneration);
        Assert.NotEqual(anchor.FileGeneration, RadiusCursorBootstrap.DeriveCursorAnchor("other.example.test", FileName, 100, bytes, 0, bytes.Length).FileGeneration);
        Assert.NotEqual(anchor.FileGeneration, RadiusCursorBootstrap.DeriveCursorAnchor(Source, "IN260731.log", 100, bytes, 0, bytes.Length).FileGeneration);
    }

    [Theory]
    [InlineData("", 0, "bootstrap_complete_record_required")]
    [InlineData(" \t\r\n", 0, "bootstrap_complete_record_required")]
    [InlineData("partial-prefix\n", 500, "bootstrap_bounded_tail_too_small")]
    [InlineData("partial-prefix\n \t\n", 500, "bootstrap_complete_record_required")]
    [InlineData("bad-record\n", 0, "bootstrap_last_record_invalid")]
    public void InvalidTailFailsClosed(string tail, long start, string code)
    {
        Assert.Equal(code, Assert.Throws<RadiusCursorBootstrapError>(() => Derive(Encoding.UTF8.GetBytes(tail), start)).Code);
    }

    [Fact]
    public void InvalidLastRecordDoesNotFallBackToEarlierValidRecord()
    {
        var bytes = Encoding.UTF8.GetBytes(Line() + "\n" + Line("9") + "\n");
        Assert.Equal("bootstrap_last_record_invalid", Assert.Throws<RadiusCursorBootstrapError>(() => Derive(bytes)).Code);
    }

    [Fact]
    public void InvalidUtf8InLastRecordIsRejected()
    {
        byte[] bytes = [0xff, 0x0a];
        Assert.Equal("bootstrap_record_encoding_invalid", Assert.Throws<RadiusCursorBootstrapError>(() => Derive(bytes)).Code);
    }

    [Theory]
    [InlineData("", FileName, 100, 0, 0, "bootstrap_source_instance_invalid")]
    [InlineData("bad/source", FileName, 100, 0, 0, "bootstrap_source_instance_invalid")]
    [InlineData(Source, "", 100, 0, 0, "bootstrap_file_basename_invalid")]
    [InlineData(Source, ".", 100, 0, 0, "bootstrap_file_basename_invalid")]
    [InlineData(Source, "dir/IN260730.log", 100, 0, 0, "bootstrap_file_basename_invalid")]
    [InlineData(Source, "dir\\IN260730.log", 100, 0, 0, "bootstrap_file_basename_invalid")]
    [InlineData(Source, FileName, 0, 0, 0, "bootstrap_creation_time_invalid")]
    [InlineData(Source, FileName, -1, 0, 0, "bootstrap_creation_time_invalid")]
    [InlineData(Source, FileName, 100, -1, 0, "bootstrap_tail_range_invalid")]
    [InlineData(Source, FileName, 100, 1, 0, "bootstrap_tail_range_invalid")]
    [InlineData(Source, FileName, 100, 0, 1, "bootstrap_tail_range_invalid")]
    public void InvalidMetadataIsRejectedBeforeReadingRecords(string source, string name, long creation, long start, long size, string code)
    {
        Assert.Equal(code, Assert.Throws<RadiusCursorBootstrapError>(() =>
            RadiusCursorBootstrap.DeriveCursorAnchor(source, name, creation, [], start, size)).Code);
    }
}
