using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class RadiusTailTests
{
    private static RadiusCursor Cursor(RadiusMemoryFiles files, long offset = 0) => new("synthetic-radius", "radius-accounting", "synthetic-tail",
        RadiusTailSource.DeriveGeneration("synthetic-radius", files.Files[0].Name, files.Files[0].CreationTimeNs), offset, null);
    private static string Line() => JsonNode.Parse(NpsTests.Scenario("radius-blank-progress")["steps"]![1]!["payload_canonical"]!.GetValue<string>())!["records"]![0]!["payload"]!.GetValue<string>();

    [Theory]
    [InlineData("replace", "tail_file_replaced_during_open")]
    [InlineData("truncate", "tail_file_truncated_during_open")]
    [InlineData("reparse-open", "tail_reparse_point_forbidden")]
    [InlineData("reparse-inventory", "tail_reparse_point_forbidden")]
    [InlineData("inventory", "tail_inventory_failed")]
    [InlineData("read", "tail_file_read_failed")]
    public void SourceChangesAndIoErrorsAreClosedCodesWithoutProgress(string fault, string expected)
    {
        var files = new RadiusMemoryFiles(Encoding.UTF8.GetBytes(Line() + "\n"));
        var cursor = Cursor(files);
        if (fault == "reparse-inventory") files.Files[0] = files.Files[0] with { ReparsePoint = true };
        if (fault == "inventory") files.InventoryFails = true;
        files.OnOpen = file => fault switch
        {
            "replace" => file with { FileId = "replacement" },
            "truncate" => file with { Size = 1 },
            "reparse-open" => file with { ReparsePoint = true },
            "read" => throw new IOException("password=private-path"),
            _ => file,
        };
        var exception = Assert.Throws<AgentException>(() => new RadiusTailSource(files).Read("private-directory", cursor, 32, true));
        Assert.Equal(expected, exception.Code); Assert.DoesNotContain("private", exception.ToString());
    }

    [Fact]
    public void ReadAndPhysicalLineBudgetsIncludeBlanksAndNeverConsumePartialBytes()
    {
        var bytes = Enumerable.Repeat((byte)' ', RadiusTailSource.MaximumReadBytes - 1).Concat(new byte[] { 10 }).Concat(Encoding.UTF8.GetBytes(Line() + "\n")).ToArray();
        var files = new RadiusMemoryFiles(bytes);
        var cursor = Cursor(files);
        var tail = new RadiusTailSource(files).Read("synthetic", cursor, 1, true);
        Assert.Empty(tail.Records); Assert.Equal(1, tail.PhysicalLines); Assert.Equal(RadiusTailSource.MaximumReadBytes, tail.EndOffset);
        Assert.Equal(RadiusTailSource.MaximumReadBytes, files.ReadBytes);
        var next = new RadiusTailSource(files).Read("synthetic", cursor with { ByteOffset = tail.EndOffset }, 1, false);
        Assert.Equal(Line(), Assert.Single(next.Records));
        var partial = new RadiusMemoryFiles(Encoding.UTF8.GetBytes("partial"));
        var unchanged = new RadiusTailSource(partial).Read("synthetic", Cursor(partial), 1, false);
        Assert.Equal(0, unchanged.EndOffset); Assert.Equal(7, unchanged.PartialTrailingBytes);
    }

    [Fact]
    public void CandidateLimitAndNameFilterBoundTheInventory()
    {
        var files = new RadiusMemoryFiles(new JsonArray());
        files.Files.Add(new("ignored", "passwords.txt", 1, 1, 0, "d", "1", true));
        Assert.Equal("tail_accounting_file_not_observed", Assert.Throws<AgentException>(() => new RadiusTailSource(files).Read("synthetic",
            new("synthetic-radius", "radius-accounting", "synthetic-tail", "missing", 0, null), 32, false)).Code);
        files.Files.Clear();
        for (var i = 0; i < 21; i++) files.Files.Add(new("IN" + i + ".log", "IN" + i + ".log", i, i, 0, "d", i.ToString()));
        Assert.Equal("tail_candidate_limit_exceeded", Assert.Throws<AgentException>(() => new RadiusTailSource(files).Read("synthetic", Cursor(files), 32, false)).Code);
        Assert.Equal(0, files.OpenCount);
    }

    [Fact]
    public void EmptyRotationHistoricalHashCannotRecoverUntilARealRecordAnchorsTheGeneration()
    {
        var scenario = NpsTests.Scenario("radius-empty-rotations");
        var first = scenario["steps"]![0]!.AsObject();
        var policy = NpsPolicy.Parse(NpsPolicy.Accounting, first["config"]!.AsObject());
        var source = new RadiusTailSource(new RadiusMemoryFiles(first["files"]!.AsArray()));
        var sample = new RadiusAccountingModule(Helpers.HostId, policy, source).Collect(null, Helpers.Now);
        Assert.False(JsonNode.Parse(sample.CursorAfter.Token)!["exact_boundary_recovery"]!.GetValue<bool>());
        var second = new RadiusAccountingModule(Helpers.HostId, policy, source).Collect(new(sample.Generation, sample.CursorAfter), Helpers.Now);
        Assert.False(JsonNode.Parse(second.CursorAfter.Token)!["exact_boundary_recovery"]!.GetValue<bool>());
        var third = new RadiusAccountingModule(Helpers.HostId, policy, source).Collect(new(second.Generation, second.CursorAfter), Helpers.Now);
        Assert.True(JsonNode.Parse(third.CursorAfter.Token)!["exact_boundary_recovery"]!.GetValue<bool>());
    }

    [Theory]
    [InlineData("User-Password,shared-secret", "database_compatible_shape_required")]
    [InlineData("\"unterminated", "invalid_csv")]
    [InlineData("\"closed\"bad", "invalid_csv")]
    [InlineData("a\nb", "single_text_record_required")]
    [InlineData("a\0b", "single_text_record_required")]
    public void AccountingRejectsExtendedSecretFormatsMalformedCsvAndMultilineRecords(string line, string expected)
        => Assert.Equal(expected, Assert.Throws<AgentException>(() => RadiusAccountingRecord.Validate(line)).Code);
}
