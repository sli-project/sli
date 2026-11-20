using System.Diagnostics;
using System.Net.Http;
using System.Text.Json.Nodes;

namespace Sli.Server.Reporting;

public sealed record HtmlPageSpec(string PageId, string Url, int SlowMs = 3000, int[]? ExpectedStatus = null);

// Read-only HTTP audit, like reporting.html_audit with browser_mode=off.
// SlowMs classifies observations; it never cancels an active request.
public static class HtmlAudit
{
    public static async Task<JsonObject> RunAsync(HttpClient client, Uri baseUrl, IEnumerable<HtmlPageSpec> specs, CancellationToken ct)
    {
        if (!baseUrl.IsLoopback || baseUrl.Scheme is not ("http" or "https"))
            throw new ArgumentException("HTML audit requires a loopback HTTP target", nameof(baseUrl));
        var pages = new JsonArray();
        foreach (var spec in specs)
        {
            var url = new Uri(baseUrl, spec.Url);
            if (url.Scheme != baseUrl.Scheme || url.Authority != baseUrl.Authority)
                throw new ArgumentException("HTML audit page must belong to the audit target", nameof(specs));
            var first = await ReadAsync(client, url, ct);
            var attempts = new JsonArray(Metadata(first));
            var response = first;
            if (Timeout(first) || Duration(first) > spec.SlowMs)
            {
                var second = await ReadAsync(client, url, ct);
                attempts.Add(Metadata(second));
                if ((string?)second["status"] == "ok") response = second;
            }
            var functional = new JsonArray(); var performance = new JsonArray();
            if (attempts.Any(a => Timeout(a!))) performance.Add("http_timeout");
            if (attempts.Any(a => Duration(a!) > spec.SlowMs)) performance.Add("slow_http_response");
            if (attempts.Count > 1 && (string?)response["status"] == "ok") performance.Add("recovered_on_isolated_retry");
            int? status = (int?)response["status_code"];
            if ((string?)response["status"] == "failed" && !Timeout(response)) functional.Add("network_error");
            if ((string?)response["status"] != "failed" && !(spec.ExpectedStatus ?? [200]).Contains(status ?? 0)) functional.Add($"unexpected_status:{status}");
            string html = (string?)response["body"] ?? "";
            if (status == 200 && !((string?)response["content_type"] ?? "").Contains("text/html", StringComparison.OrdinalIgnoreCase)) functional.Add("unexpected_content_type");
            if (status == 200 && !html.Contains("<html", StringComparison.OrdinalIgnoreCase)) functional.Add("missing_html_element");
            if (html.Length > 0 && html.Count(c => !char.IsWhiteSpace(c)) < 80) functional.Add("empty_page");
            pages.Add(new JsonObject { ["page_id"] = spec.PageId, ["url"] = spec.Url, ["http"] = Metadata(response), ["http_attempts"] = attempts,
                ["retried"] = attempts.Count > 1, ["functional_findings"] = functional, ["performance_findings"] = performance,
                ["status"] = functional.Count > 0 ? "failed" : performance.Count > 0 ? "warning" : "ok" });
        }
        int failed = pages.Count(p => (string?)p!["status"] == "failed");
        int warnings = pages.Count(p => (string?)p!["status"] == "warning");
        return new() { ["package_type"] = "HTML_AUDIT_2", ["status"] = failed > 0 ? "failed" : warnings > 0 ? "warning" : "ok", ["pages"] = pages,
            ["summary"] = new JsonObject { ["pages_tested"] = pages.Count, ["functional_failures"] = failed, ["performance_findings"] = pages.Count(p => p!["performance_findings"]!.AsArray().Count > 0) } };
    }

    static long Duration(JsonNode response) => (long?)response["duration_ms"] ?? 0;
    static bool Timeout(JsonNode response) => (bool?)response["timed_out"] ?? false;
    static JsonObject Metadata(JsonObject response)
    {
        var result = (JsonObject)response.DeepClone(); result.Remove("body"); return result;
    }
    static async Task<JsonObject> ReadAsync(HttpClient client, Uri url, CancellationToken ct)
    {
        var timer = Stopwatch.StartNew();
        try
        {
            using var response = await client.GetAsync(url, ct);
            string body = await response.Content.ReadAsStringAsync(ct);
            return new() { ["status"] = "ok", ["status_code"] = (int)response.StatusCode, ["body"] = body,
                ["content_type"] = response.Content.Headers.ContentType?.ToString(), ["duration_ms"] = timer.ElapsedMilliseconds };
        }
        catch (Exception e) when (!ct.IsCancellationRequested && e is HttpRequestException or TimeoutException or OperationCanceledException)
        {
            bool timedOut = e is TimeoutException or OperationCanceledException || e.InnerException is TimeoutException;
            return new() { ["status"] = "failed", ["status_code"] = null, ["duration_ms"] = timer.ElapsedMilliseconds, ["timed_out"] = timedOut, ["error_type"] = e.GetType().Name };
        }
    }
}
