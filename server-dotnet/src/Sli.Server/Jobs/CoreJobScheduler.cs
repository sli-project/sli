using System.Globalization;
using System.Text.Json.Nodes;

namespace Sli.Server.Jobs;

public delegate (JsonObject Pinned, string Partition) CoreJobSourcePin(JsonObject handler, JsonObject source, string generation);

public static class CoreJobScheduler
{
    public static string? Slot(JsonObject schedule, DateTimeOffset now, string? inputGeneration = null)
    {
        if (schedule.Text("trigger") == "input_available") return inputGeneration;
        if (schedule.Text("trigger") == "interval") return Math.Floor((decimal)now.ToUnixTimeSeconds() / schedule["interval_seconds"]!.GetValue<long>()).ToString(CultureInfo.InvariantCulture);
        var local = TimeZoneInfo.ConvertTime(now, TimeZoneInfo.FindSystemTimeZoneById(schedule.Text("timezone")));
        string time = local.ToString("HH:mm", CultureInfo.InvariantCulture);
        return schedule["calendar"]!["local_times"]!.AsArray().Any(t => t!.GetValue<string>() == time) ? local.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + ":" + time : null;
    }
    public static IEnumerable<JsonObject> Create(CoreJobRegistry registry, string profile, JsonObject source, DateTimeOffset now, CoreJobSourcePin? provider = null)
    {
        foreach (var manifest in registry.Manifests)
        {
            if ((source["plugin_id"]?.GetValue<string>() ?? "sli.remote-access") != manifest.Text("plugin_id")) continue;
            foreach (var schedule in manifest["schedules"]!.AsArray().OfType<JsonObject>())
            {
                var handler = registry.Handlers.Single(h => h.Text("plugin_id") == manifest.Text("plugin_id") && h.Text("manifest_sha256") == CoreJobJson.Digest(manifest) && h.Text("handler_id") == schedule.Text("handler_id"));
                if (handler.Text("resource_profile") != profile || handler.Text("handler_id") == "radius-acquisition") continue;
                string? generation = Slot(schedule, now, source["manifest_id"]?.GetValue<string>());
                if (generation is null) continue;
                var pinned = new JsonObject
                {
                    ["generation"] = generation, ["input_range"] = source["delivery_ids"]?.DeepClone() ?? new JsonArray(),
                    ["policy_revision"] = source["revision"]?.DeepClone(), ["continuation"] = null,
                    ["subscription_id"] = source["subscription_id"]?.DeepClone(), ["delivery_ids"] = source["delivery_ids"]?.DeepClone() ?? new JsonArray()
                };
                string partition = handler.Text("handler_id");
                if (provider is not null) (pinned, partition) = provider(handler, source, generation);
                var spec = CoreJobJson.Pick(handler, "plugin_id", "plugin_version", "manifest_sha256", "handler_id", "handler_version", "input_contract", "result_contract", "resource_profile", "rights_profile", "budget", "max_attempts");
                spec["contract_id"] = "sli.core-job.v1"; spec["job_type"] = handler["kind"]!.DeepClone();
                spec["input_ref"] = $"schedule:{schedule.Text("schedule_id")}:{generation}";
                spec["input_sha256"] = CoreJobJson.Digest(pinned); spec["pinned_input"] = pinned;
                spec["source_instance_id"] = source["source_instance_id"]!.DeepClone(); spec["partition_key"] = partition;
                spec["access_scope"] = source["access_scope"]!.DeepClone(); spec["priority"] = "normal"; spec["continuation"] = null;
                spec["available_at_utc"] = now.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffffzzz", CultureInfo.InvariantCulture);
                spec["deadline_at_utc"] = now.AddSeconds(300).ToString("yyyy-MM-dd'T'HH:mm:ss.ffffffzzz", CultureInfo.InvariantCulture);
                spec["max_inflight_per_source"] = schedule["max_inflight_per_source"]!.DeepClone();
                spec["schedule_key"] = CoreJobJson.Digest(new JsonArray(manifest.Text("plugin_id"), schedule.Text("schedule_id"), source.Text("source_instance_id"), generation));
                spec["idempotency_key"] = CoreJobQueue.IdempotencyKey(spec, pinned);
                yield return spec;
            }
        }
    }
}
