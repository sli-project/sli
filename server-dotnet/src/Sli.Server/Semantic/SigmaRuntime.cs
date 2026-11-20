using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Npgsql;
using Sli.Agent.Core;

namespace Sli.Server.Semantic;

internal sealed record SigmaEvent(int Id, string Channel, string Computer, DateTimeOffset At, JsonObject Fields, HashSet<string> Unavailable)
{
    internal static SigmaEvent Map(string xml)
    {
        try { return MapCore(xml); }
        catch (Exception e) when (e is FormatException or OverflowException or System.Xml.XmlException or EventXmlException)
        { throw new InvalidDataException("sigma_event_mapping_invalid"); }
    }
    private static SigmaEvent MapCore(string xml)
    {
        var root = EventXml.ParseBounded(xml); XNamespace ns = EventXml.Namespace;
        XElement? One(XElement parent, string name, bool required = true) { var nodes = parent.Elements(ns + name).ToArray(); if (nodes.Length > 1 || required && nodes.Length == 0) throw new InvalidDataException("sigma_event_structure_invalid"); return nodes.FirstOrDefault(); }
        string Text(XElement? node) => node is not null && !node.HasElements && node.Attribute(XName.Get("nil", "http://www.w3.org/2001/XMLSchema-instance")) is null ? node.Value : throw new InvalidDataException("sigma_event_structure_invalid");
        var system = One(root, "System")!; string channel = Text(One(system, "Channel")), provider = One(system, "Provider")?.Attribute("Name")?.Value ?? "";
        int id = int.Parse(Text(One(system, "EventID")), CultureInfo.InvariantCulture), version = int.Parse(Text(One(system, "Version")), CultureInfo.InvariantCulture);
        int[] versions = (channel, provider, id) switch
        {
            ("Security", "Microsoft-Windows-Eventlog", 1102) => [0],
            ("Security", "Microsoft-Windows-Security-Auditing", 4624 or 4688) => [0, 1, 2],
            ("Security", "Microsoft-Windows-Security-Auditing", 4698 or 4702) => [0, 1],
            ("Security", "Microsoft-Windows-Security-Auditing", 4768 or 4769) => [0, 2],
            ("Security", "Microsoft-Windows-Security-Auditing", 4625 or 4697 or 4719 or 4720 or 4732 or 4776 or 4781) => [0],
            ("System", "Service Control Manager", 7045 or 7036 or 7040) => [0],
            ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4104) => [1], _ => []
        };
        if (!versions.Contains(version)) throw new InvalidDataException("sigma_event_schema_unsupported");
        string? guid = One(system, "Provider")?.Attribute("Guid")?.Value;
        if (guid is not null)
        {
            string expected = provider switch { "Microsoft-Windows-Security-Auditing" => "54849625-5478-4994-a5ba-3e3b0328c30d", "Microsoft-Windows-Eventlog" => "fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148", "Service Control Manager" => "555908d1-a6d7-4695-8e1e-26931d2012f4", _ => "a0c1853b-5c40-4b15-8766-3cf1c58f985a" };
            if (!Guid.TryParse(guid, out var parsed) || parsed.ToString() != expected) throw new InvalidDataException("sigma_event_provider_invalid"); guid = parsed.ToString();
        }
        string computer = Text(One(system, "Computer")), stamp = One(system, "TimeCreated")!.Attribute("SystemTime")?.Value ?? "";
        if (string.IsNullOrWhiteSpace(computer) || !Regex.IsMatch(stamp, @"\A[0-9]{4}(-[0-9]{2}){2}T[0-9]{2}(:[0-9]{2}){2}(\.[0-9]{1,9})?Z\z")) throw new InvalidDataException("sigma_event_header_invalid");
        ulong record = ulong.Parse(Text(One(system, "EventRecordID")), CultureInfo.InvariantCulture); if (record == 0) throw new InvalidDataException("sigma_event_header_invalid");
        var fields = new JsonObject(); var unavailable = new HashSet<string>(); var data = One(root, "EventData", false); var user = One(root, "UserData", false);
        if (data is not null && user is not null) throw new InvalidDataException("sigma_event_payload_ambiguous");
        var entries = new List<(string Name, string Value)>();
        if (user is not null)
        {
            XNamespace log = "http://manifests.microsoft.com/win/2004/08/windows/eventlog";
            if (id != 1102 || user.Elements().Count() != 1 || user.Elements().Single().Name != log + "LogFileCleared") throw new InvalidDataException("sigma_event_userdata_unsupported");
            foreach (var leaf in user.Elements().Single().Elements()) { if (leaf.Name.Namespace != log) throw new InvalidDataException("sigma_event_userdata_unsupported"); entries.Add((leaf.Name.LocalName, Text(leaf))); }
        }
        else if (data is not null)
        {
            if (data.Elements().Any(x => x.Name != ns + "Data" && x.Name != ns + "Binary")) throw new InvalidDataException("sigma_event_structure_invalid");
            var values = data.Elements(ns + "Data").ToArray(); var names = values.Select(x => x.Attribute("Name")?.Value).ToArray();
            if (names.Any(x => x is not null) && names.Any(x => x is null)) throw new InvalidDataException("sigma_event_payload_ambiguous");
            if (values.Length > 0 && names.All(x => x is null)) { if (channel != "System" || provider != "Service Control Manager" || id != 7045 || version != 0 || values.Length != 5) throw new InvalidDataException("sigma_event_positional_unsupported"); names = ["ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName"]; fields["Data"] = new JsonArray(values.Select(x => JsonValue.Create(Text(x))).ToArray()); }
            entries.AddRange(values.Select((x, index) => (names[index]!, Text(x))));
        }
        var seen = new HashSet<string>(); HashSet<string> reserved = ["eventid", "provider_name", "provider_guid", "channel", "computer", "version", "eventrecordid", "timecreated", "processid", "threadid", "data", "message", "message_text", "renderedmessage", "rendered_message"];
        foreach (var entry in entries) { if (string.IsNullOrWhiteSpace(entry.Name) || entry.Name.Trim() != entry.Name || !seen.Add(entry.Name)) throw new InvalidDataException("sigma_event_payload_ambiguous"); if (!reserved.Contains(entry.Name.ToLowerInvariant()) || id == 4688 && entry.Name == "ProcessId") fields[entry.Name] = entry.Value; }
        if (id == 4688)
        {
            string[] unsupported = ["OriginalFileName", "Description", "Product", "Company", "FileVersion", "Hashes", "CurrentDirectory", "ParentCommandLine", "ParentUser", "ProcessGuid", "ParentProcessGuid"];
            foreach (string name in unsupported.Concat(["Image", "ParentImage", "User", "UserSid", "LogonId", "LogonIdNumeric", "IntegrityLevel", "ParentProcessId", "CreatorProcessId", "NativeProcessId"])) fields.Remove(name);
            unavailable.UnionWith(unsupported);
            bool Present(string key) => fields.Text(key) is { Length: > 0 } value && value.Trim().Length > 0 && value != "-";
            void Alias(string dest, string native) { if (Present(native)) fields[dest] = fields[native].Copy(); else unavailable.Add(dest); }
            ulong? Hex(string? value, int bits) => value is not null && Regex.IsMatch(value, @"\A0[xX][0-9a-fA-F]{1,16}\z") && ulong.TryParse(value[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong n) && (bits == 64 || n <= uint.MaxValue) ? n : null;
            Alias("Image", "NewProcessName"); string? creator = fields.Text("ProcessId"); fields.Remove("ProcessId"); if (creator is not null) fields["CreatorProcessId"] = creator;
            foreach (var (dest, value) in new[] { ("ProcessId", fields.Text("NewProcessId")), ("ParentProcessId", creator) }) { if (Hex(value, 32) is { } number) fields[dest] = number; else unavailable.Add(dest); }
            if (version < 1) { fields.Remove("CommandLine"); unavailable.Add("CommandLine"); } else if (!Present("CommandLine")) unavailable.Add("CommandLine");
            if (version < 2) unavailable.UnionWith(["ParentImage", "IntegrityLevel"]);
            else { Alias("ParentImage", "ParentProcessName"); var levels = new Dictionary<string, string> { ["S-1-16-0"] = "Untrusted", ["S-1-16-4096"] = "Low", ["S-1-16-8192"] = "Medium", ["S-1-16-8448"] = "MediumPlus", ["S-1-16-12288"] = "High", ["S-1-16-16384"] = "System", ["S-1-16-20480"] = "ProtectedProcess" }; if (levels.TryGetValue(fields.Text("MandatoryLabel") ?? "", out string? level)) fields["IntegrityLevel"] = level; else unavailable.Add("IntegrityLevel"); }
            bool nullTarget = fields.Text("TargetUserSid") is null or "" or "-" or "S-1-0-0" && new[] { "TargetUserName", "TargetDomainName", "TargetLogonId" }.All(x => fields.Text(x) is null or "" or "-" or "0x0"); string prefix = version == 2 && !nullTarget ? "Target" : "Subject";
            string? sid = fields.Text(prefix + "UserSid");
            if (sid is null || !Regex.IsMatch(sid, @"\AS-1-[0-9]{1,15}(?:-[0-9]{1,10}){1,15}\z") || sid == "S-1-0-0") unavailable.UnionWith(["User", "UserSid", "LogonId", "LogonIdNumeric"]);
            else { Alias("UserSid", prefix + "UserSid"); if (Present(prefix + "UserName") && Present(prefix + "DomainName")) fields["User"] = fields.Text(prefix + "DomainName") + "\\" + fields.Text(prefix + "UserName"); else unavailable.Add("User"); if (Hex(fields.Text(prefix + "LogonId"), 64) is { } number) { Alias("LogonId", prefix + "LogonId"); fields["LogonIdNumeric"] = number; } else unavailable.UnionWith(["LogonId", "LogonIdNumeric"]); }
        }
        fields["EventID"] = id; fields["Version"] = version; fields["Provider_Name"] = provider; fields["Channel"] = channel; fields["Computer"] = computer; fields["EventRecordID"] = record; fields["TimeCreated"] = stamp; if (guid is not null) fields["Provider_Guid"] = guid;
        var execution = One(system, "Execution", false); if (execution is not null) foreach (var (native, name) in new[] { ("ProcessID", id == 4688 ? "NativeProcessId" : "ProcessId"), ("ThreadID", "ThreadId") }) if (execution.Attribute(native) is { } value) fields[name] = uint.Parse(value.Value, CultureInfo.InvariantCulture);
        return new(id, channel, computer, SemanticQuery.Time(stamp, "UTC", "sigma_event_header_invalid"), fields, unavailable);
    }
}

internal sealed partial class SemanticProduction
{
    private static async Task<JsonObject> ProcessSigma(NpgsqlConnection db, CancellationToken ct)
    {
        JsonArray policies;
        await using (var tx = await db.BeginTransactionAsync(ct)) { policies = await new SemanticSession(db, tx).QueryAsync("select p.policy_id,p.policy_version from semantic_risk_policies p join semantic_policy_admission a using(policy_id,policy_version) where p.source_kind='detection_match' and a.enabled and semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)='enabled' order by p.policy_id,p.policy_version limit 25", ct); await tx.CommitAsync(ct); }
        int jobs = 0, failed = 0;
        foreach (var policy in policies)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                await using var tx = await db.BeginTransactionAsync(ct); var session = new SemanticSession(db, tx); string policyId = policy.Text("policy_id")!; int version = (int)policy.Number("policy_version");
                var revision = (await session.QueryAsync("select public.read_admitted_sigma_revision($1,$2) as revision", ct, policyId, version))[0]?["revision"];
                if (revision is null) { await tx.CommitAsync(ct); continue; }
                var pin = revision["execution"]!.AsObject(); var rule = SigmaRule.Compile(revision.Text("raw_yaml")!, revision.Text("license"));
                if (!SigmaProjection.ValidPin(pin, rule.Id) || pin.Text("rule_sha256") != rule.Sha || pin.Text("compiler_version") != SigmaRule.CompilerVersion || pin.Text("mapping_version") != SigmaRule.MappingVersion || pin.Text("overlay_sha256") != Password.PasswordJson.Hash(new JsonObject())) throw new InvalidDataException("sigma_live_revision_mismatch");
                await session.QueryAsync("insert into semantic_sigma_live_cursors(policy_id,policy_version,last_event_id) values($1,$2,0) on conflict do nothing", ct, policyId, version);
                var cursor = (await session.QueryAsync("select last_event_id from semantic_sigma_live_cursors where policy_id=$1 and policy_version=$2 for update", ct, policyId, version))[0]!;
                if (!(await session.QueryAsync("select to_regprocedure('public.read_admitted_sigma_events(jsonb,bigint)') is not null as ready", ct))[0]!["ready"]!.GetValue<bool>()) { await tx.CommitAsync(ct); continue; }
                var rows = await session.QueryAsync("select * from public.read_admitted_sigma_events($1::jsonb,$2)", ct, pin["scope"], cursor.Number("last_event_id")); int added = 0;
                foreach (var row in rows)
                {
                    SigmaEvent ev; try { ev = SigmaEvent.Map(row.Text("source_xml")!); } catch (InvalidDataException) { continue; }
                    if (rule.Match(ev.Fields, ev.Unavailable) != "matched") continue;
                    var reference = new JsonObject { ["storage_kind"] = "core_event", ["native_id"] = row.Number("source_event_id").ToString(CultureInfo.InvariantCulture), ["sha256"] = row!["sha256"].Copy(), ["scope"] = pin["scope"].Copy() };
                    await VerifyNative(session, new JsonArray(reference.Copy()), ct);
                    var document = new JsonObject { ["rule_id"] = rule.Id, ["rule_sha256"] = rule.Sha, ["manifest_sha256"] = pin["manifest_sha256"].Copy(), ["compiler_version"] = SigmaRule.CompilerVersion, ["mapping_version"] = SigmaRule.MappingVersion, ["overlay_sha256"] = pin["overlay_sha256"].Copy(), ["evidence"] = reference.Copy(), ["entity_key"] = Password.PasswordJson.Hash(new JsonArray(pin["scope"].Text("source_instance_id"), ev.Computer)), ["occurred_at_utc"] = SemanticJson.Stamp(ev.At), ["evaluation_mode"] = "enabled", ["conclusion_state"] = "observed", ["quality"] = "good", ["suppressed"] = false };
                    string id = Password.PasswordJson.Hash(document); var scope = pin["scope"]!; string evidenceKey = Password.PasswordJson.Hash(new JsonArray(scope["installation_id"].Copy(), scope["plugin_id"].Copy(), scope["source_instance_id"].Copy(), scope["source_generation"].Copy(), scope["collection_scope_id"].Copy(), reference["storage_kind"].Copy(), reference["native_id"].Copy(), reference["sha256"].Copy()));
                    await session.QueryAsync("insert into semantic_detection_matches(match_id,rule_id,evaluation_mode,occurred_at_utc,evidence_key,document_json) values($1,$2,'enabled',$3,$4,$5) on conflict(match_id) do nothing", ct, id, rule.Id, ev.At, evidenceKey, document);
                    var stored = (await session.QueryAsync("select document_json from semantic_detection_matches where match_id=$1", ct, id)).Single()!; if (!JsonNode.DeepEquals(stored["document_json"], document)) throw new InvalidDataException("sigma_input_replay_conflict"); added += await EnqueueRiskSource(session, "detection_match", id, ct);
                }
                if (rows.Count > 0) await session.QueryAsync("update semantic_sigma_live_cursors set last_event_id=$1 where policy_id=$2 and policy_version=$3", ct, rows[^1].Number("source_event_id"), policyId, version);
                await tx.CommitAsync(ct); jobs += added;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch { failed++; }
        }
        return new JsonObject { ["policies"] = policies.Count, ["jobs"] = jobs, ["failed"] = failed };
    }
}
