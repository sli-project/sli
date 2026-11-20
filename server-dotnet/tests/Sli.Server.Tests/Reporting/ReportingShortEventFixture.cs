using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sli.Server.Tests.Reporting;

internal static class ReportingShortEventFixture
{
    internal static JsonObject Stored(JsonNode row)
    {
        string? Text(string key) => row[key]?.ToString();
        var data = new Dictionary<string,string>();
        foreach (var (key,native) in new[] { ("target_user_sid","TargetUserSid"),("target_user_name","TargetUserName"),
            ("subject_user_sid","SubjectUserSid"),("subject_user_name","SubjectUserName"),("ip_address","IpAddress"),
            ("workstation_name","WorkstationName"),("logon_type","LogonType"),("result_code","Status"),
            ("service_name","ServiceName"),("service_file","ServiceFileName"),("service_account","ServiceAccount"),
            ("service_start_type","ServiceStartType"),("task_name","TaskName"),("task_content","TaskContent") })
            data[native] = Text(key) ?? "";
        foreach (var (key,native) in new[] { ("process_user_sid","SubjectUserSid"),("process_user_name","SubjectUserName"),
            ("process_user_domain","SubjectDomainName") }) if (Text(key) is {} value) data[native] = value;
        if (row["facts_json"]?["caller_computer"] is {} caller) data["CallerComputerName"] = caller.ToString();
        if (row["facts_json"]?["failure_status"] is {} failure) data["SubStatus"] = failure.ToString();
        if (row["facts_json"]?["result_code"] is {} result) data["Status"] = result.ToString();
        int code = int.Parse(Text("event_id")!,CultureInfo.InvariantCulture);
        if (code == 7045) foreach (var (oldKey,newKey) in new[] { ("ServiceFileName","ImagePath"),("ServiceAccount","AccountName"),("ServiceStartType","StartType") }) data[newKey] = data[oldKey];
        var compact = SecurityChainsShortReadsPostgresTests.Row(long.Parse(Text("event_db_id")!,CultureInfo.InvariantCulture),code,0,
            start:DateTimeOffset.Parse(Text("time_created_utc")!,CultureInfo.InvariantCulture),
            domain:long.Parse(Text("domain_id") ?? "7",CultureInfo.InvariantCulture),extra:data);
        return new JsonObject { ["id"] = compact.EventId,["event_id"] = compact.Kind,["domain_id"] = compact.DomainId,
            ["server_id"] = row["server_id"]?.DeepClone() ?? JsonValue.Create(11),["dc"] = row["dc"]?.DeepClone(),
            ["time_created_utc"] = Text("time_created_utc"),["actor"] = compact.Actor,["target"] = compact.Target,
            ["source"] = compact.Source,["computer"] = Text("source") ?? compact.Computer,
            ["channel"] = code == 7045 ? "System" : "Security",["provider_name"] = code == 7045 ? "Service Control Manager" : "Microsoft-Windows-Security-Auditing",
            ["method"] = JsonNode.Parse(compact.Method),["outcome"] = JsonNode.Parse(compact.Outcome),
            ["fields"] = JsonSerializer.SerializeToNode(compact.Fields) };
    }
}
