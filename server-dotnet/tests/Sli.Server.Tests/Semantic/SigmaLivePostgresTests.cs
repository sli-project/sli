using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Problems;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

[Collection("Semantic producer environment")]
public sealed class SigmaLivePostgresTests
{
    private static readonly Guid HiddenUser = new("7b449a5e-1db5-4dd0-a2dc-4e3a67282538");
    private static readonly Guid SuspiciousService = new("1d61f71d-59d2-479e-9562-4ff5f4ead16b");

    [Fact]
    public async Task Starter_rules_follow_admitted_events_and_publish_once_per_subject()
    {
        var ct = TestContext.Current.CancellationToken;
        var migrations = MigrationDirectory.Read().Where(item => item.Version <= 433).ToArray();
        string migration = migrations.Single(item => item.Version == 433).Path;
        string starter = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(migration)!, "../sigma/starter"));
        var yaml = Directory.GetFiles(starter, "*.yml").Select(File.ReadAllText)
            .Select(raw => SigmaRule.Compile(raw, "DRL-1.1")).ToDictionary(rule => rule.Id);
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, migrations.Last(item => item.Version < 433).Version);
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        await using var api = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await api.OpenAsync(ct);

        async Task<JsonArray> Rules()
        {
            await using var tx = await api.BeginTransactionAsync(ct);
            return await new SemanticSession(api, tx).QueryAsync("select * from public.sigma_live_list433()", ct);
        }
        var installed = await Rules();
        Assert.Equal(yaml.Count, installed.Count);
        Assert.All(installed, row => Assert.Equal(yaml[row.Text("rule_id")!].Document.Text("title"), row.Text("title")));
        await using (var tx = await worker.BeginTransactionAsync(ct))
        {
            var revisions = await new SemanticSession(worker, tx).QueryAsync("select * from public.sigma_starter433()", ct);
            Assert.All(revisions, row => Assert.Equal(yaml[row.Text("rule_id")!].Sha, row.Text("raw_sha256")));
        }

        await PostCollectionPostgres.Sql(owner, """
            update public.plugin_installations_v1 set desired_activation='enabled_manual',component_runtime='running'
            where plugin_id='sli.sigma'
            """, ct);
        var dc = (Guid.NewGuid(), Guid.NewGuid(), 940001L, 1L);
        const string host = "sigma-dc.example.test";
        await ShortEventAdmissionPostgresTests.RegisterDcAsync(owner, dc.Item1, dc.Item2, dc.Item3, dc.Item4,
            host, "Security", ct, "System", completePolicy: true);
        await using (var bind = new NpgsqlCommand("""
            insert into log_sources(name) values('Security') on conflict do nothing;
            insert into finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
                source_instance_id,source_generation,collection_scope_id,storage_kind,log_source_id,agent_id)
            select oid,rolname,installation_id,'sli.windows.ad-dc',@source,@source,'','core_event',
                (select id from log_sources where name='Security'),@agent
            from pg_roles cross join semantic_default_installation where rolname='sli_semantic_login'
            """, owner))
        {
            bind.Parameters.AddWithValue("source", dc.Item2.ToString());
            bind.Parameters.AddWithValue("agent", dc.Item1);
            await bind.ExecuteNonQueryAsync(ct);
        }
        async Task Add(int record, int kind, string channel, string account, bool suspiciousService = false)
        {
            var fields = suspiciousService ? new Dictionary<string, string> {
                ["ImagePath"] = @"C:\Temp\fixture.exe", ["AccountName"] = account } : null;
            var rows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: [kind],
                registered: dc, packetId: Guid.NewGuid(), sequence: record, firstRecordId: record,
                hostName: host, eventChannel: channel, nativeAccounts: [account], nativeFields: fields, nativeVersion: 0);
            await ShortEventAdmissionPostgresTests.WriteAsync(fixture, rows, ct);
        }
        var production = new SemanticProduction(runtime, new(true, true, false, true, false, false),
            SemanticRuntimeSettings.FindingsMode, 16);
        await Add(30, 4720, "Security", "fixture-user$");
        await Add(40, 7045, "System", "fixture-service", suspiciousService: true);
        await Add(50, 4720, "Security", "ordinary-user");
        var first = await SemanticProduction.ProcessSigma(worker, ct);
        Assert.Equal(3, first.Number("events"));
        Assert.Equal(2, first.Number("jobs"));
        var risk = await production.ProcessRisk(worker, ct);
        if (risk.Number("published") != 2)
        {
            await using var diagnostics = await owner.BeginTransactionAsync(ct);
            var jobs = await new SemanticSession(owner, diagnostics).QueryAsync("""
                select evaluation_status,last_error_code,last_error_detail from public.semantic_risk_evaluation_jobs
                where policy_id like 'default:sigma:%' order by policy_id
                """, ct);
            var errors = (await fixture.Pg.DiagnosticsAsync(ct)).Split('\n')
                .Where(line => line.Contains("ERROR:", StringComparison.Ordinal)).TakeLast(6);
            Assert.Fail($"Expected two publications. Risk cycle {risk.ToJsonString()}, jobs {jobs.ToJsonString()}"
                + Environment.NewLine + string.Join(Environment.NewLine, errors));
        }
        await using (var tx = await owner.BeginTransactionAsync(ct))
        {
            var problems = await new SemanticSession(owner, tx).QueryAsync("""
                select rule_code,title,source,target,summary from public.findings_active where rule_code like 'semantic.sigma.%' order by title
                """, ct);
            Assert.Collection(problems,
                user => {
                    Assert.Equal(yaml[HiddenUser.ToString()].Document.Text("title"), user.Text("title"));
                    Assert.Equal(user.Text("title"), ProblemPresentation.RuleMessage(user!.AsObject(), "title", "en").Text("text"));
                    Assert.Equal(host, user.Text("source"));
                    Assert.Equal(@"example.test\fixture-user$", user.Text("target"));
                },
                service => {
                    Assert.Equal(yaml[SuspiciousService.ToString()].Document.Text("title"), service.Text("title"));
                    Assert.Equal(host, service.Text("source"));
                    Assert.Equal("fixture-service", service.Text("target"));
                });
        }
        Assert.Equal(0, (await SemanticProduction.ProcessSigma(worker, ct)).Number("events"));
        Assert.Equal(0, (await production.ProcessRisk(worker, ct)).Number("published"));

        async Task<long> Repeats(Guid rule)
        {
            await using var query = new NpgsqlCommand("""
                select coalesce(max(repeat_count),0) from public.findings_active where rule_code=@rule
                """, owner);
            query.Parameters.AddWithValue("rule", "semantic.sigma." + rule);
            return (long)(await query.ExecuteScalarAsync(ct))!;
        }
        await Add(45, 4720, "Security", "fixture-user$");
        Assert.Equal(0, (await SemanticProduction.ProcessSigma(worker, ct)).Number("jobs"));
        Assert.Equal(1L, await Repeats(HiddenUser));

        await using (var disable = new NpgsqlCommand("select public.sigma_live_toggle433(@rule,false,'fixture-admin')", api))
        {
            disable.Parameters.AddWithValue("rule", HiddenUser);
            Assert.Equal(true, await disable.ExecuteScalarAsync(ct));
        }
        // A lower native ID can commit after the prior page; it must still be consumed.
        await Add(20, 4720, "Security", "after-disable$");
        var disabled = await SemanticProduction.ProcessSigma(worker, ct);
        Assert.Equal(1, disabled.Number("events"));
        Assert.Equal(0, disabled.Number("jobs"));
        Assert.Equal(0, (await production.ProcessRisk(worker, ct)).Number("published"));
        var readback = Assert.Single(await Rules(), row => row.Text("rule_id") == HiddenUser.ToString());
        Assert.False(readback.Flag("enabled"));
        Assert.Equal(2, readback.Number("matches_24h"));

        await PostCollectionPostgres.Sql(owner, "update public.sigma_live_hits433 set hour=hour-interval '2 hours'", ct);
        for (int index = 0; index <= SemanticProduction.SigmaHourlyMatchLimit; index++)
            await Add(100 + index, 7045, "System", "fixture-volume-" + index, suspiciousService: true);
        var volume = await SemanticProduction.ProcessSigma(worker, ct);
        Assert.Equal(SemanticProduction.SigmaHourlyMatchLimit + 1, volume.Number("events"));
        Assert.Equal(1, volume.Number("jobs"));
        Assert.Equal(1, (await production.ProcessRisk(worker, ct)).Number("published"));
        Assert.Equal(SemanticProduction.SigmaHourlyMatchLimit, await Repeats(SuspiciousService));
        await PostCollectionPostgres.Sql(owner, """
            update public.sigma_live_hits433 set hour=hour-interval '1 hour'
            where hour=date_trunc('hour',clock_timestamp(),'UTC')
            """, ct);
        Assert.Equal(0, (await SemanticProduction.ProcessSigma(worker, ct)).Number("jobs"));
        Assert.Equal(0, (await production.ProcessRisk(worker, ct)).Number("published"));
        Assert.Equal(SemanticProduction.SigmaHourlyMatchLimit + 2,
            Assert.Single(await Rules(), row => row.Text("rule_id") == SuspiciousService.ToString()).Number("matches_24h"));

        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        var reinstalled = await Rules();
        Assert.Equal(yaml.Count, reinstalled.Count);
        Assert.False(Assert.Single(reinstalled, row => row.Text("rule_id") == HiddenUser.ToString()).Flag("enabled"));
    }
}
