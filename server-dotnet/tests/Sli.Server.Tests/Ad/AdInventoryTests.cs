using System.Text.Json.Nodes;
using Sli.Server.Ad;
using Xunit;

namespace Sli.Server.Tests.Ad;

public sealed class AdInventoryTests
{
    [Fact] public void User_rows_match_frozen_python_including_unknowns_and_security_evidence()
    {
        using var stream=typeof(AdInventoryTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Ad.inventory-reference.json")!;
        foreach(var vector in JsonNode.Parse(stream)!.AsArray())
        {
            // The frozen generator supplies this policy explicitly, independently of platform defaults.
            var actual=AdInventoryRows.User((JsonObject)vector!["user"]!.DeepClone(),vector["observed"]!.ToString(),new JsonObject{["password_age"]=90,["inactivity"]=90});
            Assert.True(JsonNode.DeepEquals(vector["row"],actual),Difference(vector["row"],actual));
        }
    }
    static string Difference(JsonNode? a,JsonNode? b,string path="")
    {
        if(JsonNode.DeepEquals(a,b))return "";
        if(a is JsonObject first&&b is JsonObject second)foreach(string key in first.Select(p=>p.Key).Union(second.Select(p=>p.Key))){string diff=Difference(first[key],second[key],path+"."+key);if(diff.Length>0)return diff;}
        if(a is JsonArray x&&b is JsonArray y&&x.Count==y.Count)for(int i=0;i<x.Count;i++){string diff=Difference(x[i],y[i],path+"["+i+"]");if(diff.Length>0)return diff;}
        return path+" expected "+a+" actual "+b;
    }
    [Fact] public void User_snapshot_changes_match_python_and_do_not_invent_actors()
    {
        using var stream=typeof(AdInventoryTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Ad.changes-reference.json")!;
        foreach(var vector in JsonNode.Parse(stream)!.AsArray())
        {
            var actual=System.Text.Json.JsonSerializer.SerializeToNode(AdSnapshotChanges.CompareUsers(vector!["current"]!.AsObject(),vector["previous"]!.AsObject()));
            Assert.True(JsonNode.DeepEquals(vector["rows"],actual),Difference(vector["rows"],actual));
        }
    }
    [Fact] public void Naive_agent_timestamps_are_rejected()
    {
        using var stream=typeof(AdInventoryTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Ad.snapshot-reference.json")!;
        var bundle=JsonNode.Parse(stream)!["families"]!["ad_context_base"]!.AsObject();bundle["observed_at_utc"]="2026-11-01T00:00:00";
        Assert.Throws<FormatException>(()=>AdContextBundle.Normalize(bundle));
    }
    [Fact] public void Infrastructure_controls_preserve_observations_without_basis()
    {
        using var stream=typeof(AdInventoryTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Ad.control-reference.json")!;
        var reference=JsonNode.Parse(stream)!;
        var actual=AdInfrastructure.Compose(reference["entities"]!.AsArray().OfType<JsonObject>().ToArray(),new());
        Assert.NotEmpty(actual);
        foreach (var row in actual)
        {
            Assert.False(row.ContainsKey("basis"));
            Assert.False(row["presentation_messages"]!.AsObject().ContainsKey("basis"));
            var expected=reference["rows"]!.AsArray().Single(r=>r!["row_id"]!.ToString()==row["row_id"]!.ToString());
            foreach (string field in new[] { "actual_value", "object_context", "observed_at_utc" })
                Assert.True(JsonNode.DeepEquals(expected![field],row[field]),field);
        }
    }
    [Fact] public void Infrastructure_csv_omits_basis_and_preserves_values_and_escaping()
    {
        var rows=new JsonArray(new JsonObject {
            ["label"]="=1+1", ["entity_name"]="dc.example.test", ["entity_type"]="domain_controller",
            ["object_context"]=new JsonObject(), ["actual_value"]="passed", ["expected_condition"]="passed",
            ["qualification"]="passed", ["basis"]="removed basis", ["authority"]="collector_diagnostic",
            ["source_section"]="domain_health", ["observed_at_utc"]="2026-11-01T12:00:00Z"
        });
        var csv=AdInfrastructure.CsvControls(rows);
        Assert.DoesNotContain("Основание",csv);
        Assert.DoesNotContain("removed basis",csv);
        Assert.Equal("Параметр;Объект;Тип объекта;Контекст;Фактическое значение;Ожидаемое условие;Результат;Источник правила;Секция;Наблюдалось\r\n"
            + "'=1+1;dc.example.test;domain_controller;{};passed;passed;passed;collector_diagnostic;domain_health;2026-11-01T12:00:00Z\r\n",csv);
    }

    [Fact] public void Password_parameters_compare_collected_values_with_the_report_conditions()
    {
        var entity = new JsonObject {
            ["entity_id"] = 7L, ["entity_type"] = "password_policy", ["domain_name"] = "example.test",
            ["source_section"] = "domain_posture", ["observed_at_utc"] = "2026-11-22T01:45:00Z",
            ["record"] = """{"attributes":{"password_min_length":16,"lockout_threshold":0,"lockout_duration":"00:30:00","password_properties":4,"password_min_age":null}}"""
        };
        var rows = AdInfrastructure.Compose([entity], new());
        Assert.Equal("passed", rows.Single(row => AdJson.Text(row, "control_id") == "password.minimum_length")["qualification"]!.ToString());
        Assert.Equal("failed", rows.Single(row => AdJson.Text(row, "control_id") == "password.lockout_threshold")["qualification"]!.ToString());
        Assert.Equal("passed", rows.Single(row => AdJson.Text(row, "control_id") == "password.lockout_duration")["qualification"]!.ToString());
        Assert.Equal("failed", rows.Single(row => AdJson.Text(row, "control_id") == "password.properties")["qualification"]!.ToString());
        Assert.DoesNotContain(rows, row => AdJson.Text(row, "control_id") == "password.minimum_age" && AdJson.Text(row, "qualification") == "passed");
    }
    [Fact] public void Cursor_interoperates_with_python_and_rejects_another_domain_or_filter()
    {
        using var stream=typeof(AdInventoryTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Ad.control-reference.json")!;
        var reference=JsonNode.Parse(stream)!;var context=reference["cursor_context"]!.AsObject();string token=reference["cursor"]!.ToString();
        Assert.True(JsonNode.DeepEquals(reference["cursor_position"],AdCursors.Read(token,context)));
        // JSON property order in the envelope is immaterial to the shared decoder.
        Assert.True(JsonNode.DeepEquals(reference["cursor_position"],AdCursors.Read(AdCursors.Encode(context,reference["cursor_position"]!.AsObject()),context)));
        context["domain"]=8;Assert.Throws<AdInputException>(()=>AdCursors.Read(token,context));context["domain"]=7;context["q"]="другой";Assert.Throws<AdInputException>(()=>AdCursors.Read(token,context));
    }
    [Fact] public void User_checks_preserve_three_valued_results_from_python()
    {
        using var stream=typeof(AdInventoryTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Ad.control-reference.json")!;
        foreach(var vector in JsonNode.Parse(stream)!["checks"]!.AsArray())
        {
            var actual=System.Text.Json.JsonSerializer.SerializeToNode(AdReviewChecks.Evaluate(true,(JsonObject)vector!["user"]!.DeepClone(),DateTimeOffset.Parse(vector["at"]!.ToString()),vector["previous"]!.AsObject(),true));
            Assert.True(JsonNode.DeepEquals(vector["result"],actual),Difference(vector["result"],actual));
        }
    }
    [Fact] public void Result_states_and_source_failure_details_match_python()
    {
        using var stream=typeof(AdInventoryTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Ad.control-reference.json")!;
        foreach(var vector in JsonNode.Parse(stream)!["results"]!.AsArray())
        {
            var actual=AdV2Store.Result("ad.users.v2","ok",coverage:(JsonObject)vector!["coverage"]!.DeepClone());AdV2Result.Finish(actual);
            Assert.True(JsonNode.DeepEquals(vector["result"],actual),Difference(vector["result"],actual));
        }
    }
    [Fact] public void Spn_collisions_are_comparable_only_inside_the_same_domain_and_collection()
    {
        using var stream=typeof(AdInventoryTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Ad.control-reference.json")!;var reference=JsonNode.Parse(stream)!;
        var inputs=reference["spn_inputs"]!.AsArray().OfType<JsonObject>().ToArray();var now=DateTimeOffset.Parse("2026-11-01T12:00:00Z");
        var actual=System.Text.Json.JsonSerializer.SerializeToNode(AdInfrastructureExtras.SpnRows(inputs,new(),now,out int identity,out int spn,out bool truncated));
        Assert.True(JsonNode.DeepEquals(reference["spn_result"]!["items"],actual),Difference(reference["spn_result"]!["items"],actual));Assert.Equal(0,identity);Assert.Equal(0,spn);Assert.False(truncated);
        inputs[1]["domain_id"]=8;Assert.Empty(AdInfrastructureExtras.SpnRows(inputs,new(),now,out _,out _,out _));inputs[1]["domain_id"]=7;inputs[1]["run_id"]="00000000-0000-0000-0000-000000000002";Assert.Empty(AdInfrastructureExtras.SpnRows(inputs,new(),now,out _,out _,out _));
    }
    [Fact] public void Csv_preserves_lists_state_labels_and_neutralizes_formulas()
    {
        var columns=JsonNode.Parse("[{\"key\":\"name\",\"label\":\"Имя\"},{\"key\":\"groups\",\"label\":\"Группы\"},{\"key\":\"state\",\"label\":\"Состояние\",\"labels\":{\"unknown\":\"Нет данных\"}}]")!.AsArray();
        var rows=JsonNode.Parse("[{\"name\":\"=1+1\",\"groups\":[\"one\",\"two\"],\"state\":\"unknown\"}]")!.AsArray();Assert.Equal("Имя,Группы,Состояние\r\n'=1+1,\"one, two\",Нет данных\r\n",AdV2Endpoints.Csv(columns,rows));
    }
    [Theory][InlineData("0")][InlineData("01")][InlineData("+1")][InlineData(" 1")][InlineData("9223372036854775808")]
    public void Domain_parser_rejects_noncanonical_ids(string value)
    {
        var context=new Microsoft.AspNetCore.Http.DefaultHttpContext();context.Request.QueryString=new("?domain_id="+Uri.EscapeDataString(value));
        Assert.Equal("domain_scope_invalid",Assert.Throws<AdInputException>(()=>AdV2Endpoints.Parse(context.Request,"ad.users.v2","view",[1])).Message);
    }
}
