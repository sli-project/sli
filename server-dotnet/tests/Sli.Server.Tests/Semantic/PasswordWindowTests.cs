using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordWindowTests
{
    [Theory]
    [InlineData("candidate_count","10001","CountBound")]
    [InlineData("read_from","\"2025-12-31T23:50:11Z\"","ReadFrom")]
    [InlineData("read_from","\"2025-12-31T23:20:09Z\"","ReadFrom")]
    [InlineData("finalizable_through","\"2026-01-01T00:00:11Z\"","FinalizableThrough")]
    public void Window_failure_log_names_the_failed_check_without_event_values(string field,string value,string check)
    {
        var document=JsonNode.Parse("""
            {"version":"sli.password.v2.window.1","read_from":"2025-12-31T23:50:10Z",
             "read_to":"2026-01-01T00:02:10Z","finalizable_through":"2026-01-01T00:00:10Z",
             "candidate_count":0,"native_checked_count":0,"unverifiable_count":0,"oversized_count":0,
             "truncated":false,"native_checks_complete":true,"error_code":null}
            """)!.AsObject();
        document[field]=JsonNode.Parse(value);
        var error=Assert.Throws<PasswordFailure>(()=>PasswordProducer.ValidateWindow(document,DateTimeOffset.UtcNow,true));
        var diagnostics=new DetectionDiagnostics();diagnostics.Add(error);var lines=new List<string>();
        diagnostics.Write("password_producer",lines.Add);var line=Assert.Single(lines);
        Assert.StartsWith("password_producer_source_failed:",line);
        var detail=JsonNode.Parse(line[(line.IndexOf(':')+1)..])!;
        Assert.Equal(check,detail["window_check"]?.GetValue<string>());
        Assert.DoesNotContain("2026-01-01",line);Assert.DoesNotContain("2025-12-31",line);
    }
}
