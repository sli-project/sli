using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.InstallationSetup;
using Sli.Server.Tests.Agents;
using Xunit;
using InstallationCluster = Sli.Server.InstallationSetup.BootstrapCluster;

namespace Sli.Server.Tests.Access;

// Input/output vectors from tests/access/test_existing_postgres_bootstrap.py.
public sealed class ExistingPostgresBootstrapTests : IDisposable
{
    private readonly string temporary = Path.Combine(Path.GetTempPath(), "sli-bootstrap-vectors-" + Guid.NewGuid().ToString("N"));
    private const string Sid = "S-1-5-21-100000001-200000002-300000003-1000";
    private const string OtherSid = "S-1-5-21-100000001-200000002-300000003-1001";
    private const string AdminPassword = "synthetic-admin";
    private const string OwnerPassword = "synthetic-owner-password";
    private static readonly Dictionary<string, string> Source = new() { ["SYSTEMROOT"] = "C:/Windows", ["TEMP"] = Path.GetTempPath() };
    private static string Root => PostCollectionPostgres.Repository();
    public ExistingPostgresBootstrapTests() => Directory.CreateDirectory(temporary);
    private string FileAt(string name, string text) { string path = Path.Combine(temporary, name); File.WriteAllText(path, text, new UTF8Encoding(false)); return path; }
    private InstallationCluster Cluster => new(180006, Path.Combine(temporary, "pgdata"), "127.0.0.1", 55433, false, false);
    private static void Error(string code, Action action) => Assert.Equal(code, Assert.Throws<BootstrapException>(action).Message);
    private static async Task ErrorAsync(string code, Func<Task> action) => Assert.Equal(code, (await Assert.ThrowsAsync<BootstrapException>(action)).Message);
    private static Task<object?[][]> Rows(params object?[][] rows) => Task.FromResult(rows);

    [Fact]
    public void Forward_inventory_reads_real_files_and_ignores_both_rollback_forms()
    {
        FileAt("009_storage.sql", "insert into schema_migrations(version, name) values (9,'storage');\n");
        FileAt("011_reports.sql", "insert into public.schema_migrations(version,name) values(11,'reports');\n");
        FileAt("009_storage.rollback.sql", "rollback;"); FileAt("011_reports_rollback.sql", "rollback;");
        FileAt("notes.txt", "not a migration");
        var inventory = PostgresBootstrap.ForwardInventory(temporary);
        Assert.Equal([(9,"storage","009_storage.sql"),(11,"reports","011_reports.sql")], inventory.Select(m => (m.Version,m.Name,Path.GetFileName(m.Path))));
        foreach (var item in inventory) Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(item.Path))), item.Sha256);
    }

    [Theory]
    [InlineData("select 1;", "migration_marker_missing")]
    [InlineData("insert into schema_migrations(version,name) values(10,'storage');", "migration_marker_mismatch")]
    public void Invalid_migration_marker_fails_closed(string sql, string code)
    {
        FileAt("009_storage.sql", sql); Error(code, () => PostgresBootstrap.ForwardInventory(temporary));
    }

    [Fact]
    public void Duplicate_migration_versions_are_rejected()
    {
        FileAt("009_storage.sql", "insert into schema_migrations(version,name) values(9,'storage');");
        FileAt("009_duplicate.sql", "insert into schema_migrations(version,name) values(9,'duplicate');");
        Error("migration_version_duplicate", () => PostgresBootstrap.ForwardInventory(temporary));
    }

    [Fact]
    public void Repository_inventory_pins_source_markers_without_inventing_numeric_gaps()
    {
        var inventory = PostgresBootstrap.ForwardInventory(Path.Combine(Root, "config/postgres_migrations"));
        Assert.Equal(inventory.Length, inventory.Select(m => m.Version).Distinct().Count()); Assert.Equal(9, inventory[0].Version);
        Assert.DoesNotContain(inventory, m => m.Version is 13 or 95);
        string[] names = "organization_neutral_radius_access plugin_state semantic_governance core_job_queue core_identity_scope agent_registry agent_packets ad_gpo_core_jobs workstation_security agent_workstation_dispatch ad_dc_agent finding_risk_acceptance agent_policy_revisions agent_instances ad_snapshot_change_history registered_plugin_activation agent_updates plugin_core_drain_handoff agent_collection_control agent_snapshot_stream agent_windows_audit agent_ad_snapshot_import nps_agent_import agent_gpo_snapshot_import agent_group_enrollment workstation_history agent_removal agent_onboarding installed_release report_api_key ad_state_privilege_category bundled_ad_gpo_defaults file_audit_contracts agent_update_waves file_audit_management file_audit_collection file_audit_rules agent_group_deployment agent_snapshot_publication_health agent_semantic_source file_audit_reports workstation_retention_jobs file_audit_retention agent_deployment_scope ad_snapshot_history_composition agent_msi_update_result".Split(' ');
        Assert.Equal(names.Select((name, i) => (151+i,name)), inventory.Where(m => m.Version is >=151 and <=196).Select(m => (m.Version,m.Name)));
        foreach (var (version, name) in new (int,string)[] {
            (296,"agent_runtime_switch"),(297,"agent_stream_import_health"),(299,"login_account_throttle"),(300,"owner_recovery"),
            (301,"identity_attack_rules"),(302,"attack_precursors"),(303,"evsearch_fact_publication"),(304,"nps_agent_row_lock"),
            (305,"agent_group_approval_delivery"),(306,"password_policy_reconciliation"),(307,"security_candidate_sid_lookup"),
            (308,"semantic_review_row_lock"),(309,"semantic_source_lookup"),(310,"semantic_discovery_streams"),(311,"semantic_inbox_admission"),
            (312,"semantic_workstation_discovery"),(313,"agent_collection_stream_index"),(314,"semantic_runtime_readers"),(315,"semantic_bounded_readers"),
            (316,"semantic_t109_source_candidates"),(317,"semantic_event_candidates"),(318,"semantic_pending_candidates"),(319,"storage_lifecycle_roles"),
            (320,"semantic_import_summary"),(321,"storage_lifecycle_evidence") }) {
            var migration = Assert.Single(inventory, m => m.Version == version); Assert.Equal(name, migration.Name);
            Assert.Equal($"{version:000}_{name}.sql", Path.GetFileName(migration.Path));
        }
        foreach (string suffix in new[] { ".sql", ".rollback.sql" }) {
            string roles = File.ReadAllText(Path.Combine(Root, "config/postgres_migrations/319_storage_lifecycle_roles" + suffix));
            Assert.Contains("version=318 and name='semantic_pending_candidates'", roles);
            string evidence = File.ReadAllText(Path.Combine(Root, "config/postgres_migrations/321_storage_lifecycle_evidence" + suffix));
            Assert.Contains("version=320 and name='semantic_import_summary'", evidence);
            Assert.Contains("pg_has_role(session_user,'adlog_storage_owner','MEMBER')", evidence);
            Assert.Contains("set local role adlog_storage_owner", evidence);
        }
    }

    [Fact]
    public void Base_inventory_and_replay_baseline_have_only_declared_versions_one_through_eight()
    {
        var markers = PostgresBootstrap.BaseMarkers(Path.Combine(Root, "config/postgres_schema.sql"));
        Assert.Equal(new[] { "initial_postgres_schema", "stage_4_1_persistent_findings", "stage_4_3_ai_api_prompt_runs", "stage_4_4_ai_report_pipeline",
            "db_0_1_postgres_readiness", "findings_pg1_incremental_pipeline", "storage_lifecycle2_measurement_and_backup_rehearsal", "ops_stability1_runtime_contracts" }
            .Select((name,i)=>(i+1,name)), markers);
        string baseline = Path.Combine(Root,"config/postgres_schema_v8.sql");
        Assert.Equal(markers, PostgresBootstrap.BaseMarkers(baseline));
        string sql = File.ReadAllText(baseline).ToLowerInvariant(); Assert.DoesNotContain("ad_snapshot_manifests",sql); Assert.DoesNotContain("raw_batch_lifecycle",sql);
    }

    [Fact]
    public void Plan_binds_exact_cluster_state_and_migration_hashes_without_credentials()
    {
        FileAt("009_storage.sql", "insert into schema_migrations(version,name) values(9,'storage');\n");
        var inventory = PostgresBootstrap.ForwardInventory(temporary);
        var plan = PostgresBootstrap.BuildPlan("sli_local", Cluster.DataDirectory, Cluster, new('1',64), new('2',64), inventory);
        Assert.Equal("bootstrap_existing_postgresql_18",plan["operation"]!.GetValue<string>());
        Assert.Equal("sli_local",plan["database"]!.GetValue<string>());
        Assert.Equal(180006,plan["cluster"]!["server_version_num"]!.GetValue<int>());
        Assert.Equal(Cluster.DataDirectory,plan["cluster"]!["data_directory"]!.GetValue<string>());
        Assert.True(JsonNode.DeepEquals(new JsonArray(new JsonObject { ["version"]=9,["name"]="storage",["path"]="009_storage.sql",["sha256"]=inventory[0].Sha256 }),plan["migrations"]));
        Assert.DoesNotContain("password",PostgresBootstrap.Canonical(plan),StringComparison.OrdinalIgnoreCase);
        string hash = PostgresBootstrap.Confirmation(plan); Assert.Matches("^[0-9a-f]{64}$",hash);
        plan["cluster"]!["server_port"]=55434; Assert.NotEqual(hash,PostgresBootstrap.Confirmation(plan));
        plan["cluster"]!["server_port"]=55433; plan["migrations"]![0]!["sha256"]=new string('3',64); Assert.NotEqual(hash,PostgresBootstrap.Confirmation(plan));
    }

    [Fact]
    public void Confirmation_matches_frozen_Python_canonical_bytes()
    {
        var plan = new JsonObject { ["z"]="D:\\тест\\a&<+😀",["a"]=new JsonArray(true,1,null,"\n\t\"\\") };
        const string canonical = "{\"a\":[true,1,null,\"\\n\\t\\\"\\\\\"],\"z\":\"D:\\\\\\u0442\\u0435\\u0441\\u0442\\\\a&<+\\ud83d\\ude00\"}";
        Assert.Equal(canonical,PostgresBootstrap.Canonical(plan));
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))),PostgresBootstrap.Confirmation(plan));
    }

    [Theory]
    [InlineData("version","postgresql_18_required")]
    [InlineData("address","loopback_required")]
    [InlineData("port","cluster_identity_mismatch")]
    [InlineData("directory","cluster_identity_mismatch")]
    [InlineData("database","target_database_exists")]
    [InlineData("role","runtime_role_exists")]
    [InlineData("user","postgres_admin_required")]
    [InlineData("superuser","postgres_admin_required")]
    public void New_target_rejects_wrong_cluster_or_existing_state(string change,string code)
    {
        var snapshot=change switch {
            "version"=>Cluster with {ServerVersionNum=170009},"address"=>Cluster with {ServerAddress="192.0.2.10"},
            "port"=>Cluster with {ServerPort=5432},"directory"=>Cluster with {DataDirectory=Path.Combine(temporary,"other")},
            "database"=>Cluster with {DatabaseExists=true},"role"=>Cluster with {RuntimeRoleExists=true},
            "user"=>Cluster with {CurrentUser="adlog_user"},_=>Cluster with {AdminIsSuperuser=false} };
        Error(code,()=>PostgresBootstrap.ValidateCluster(snapshot,Cluster.DataDirectory,55433));
    }

    [Theory]
    [InlineData("127.0.0.1")][InlineData("127.0.0.1/32")][InlineData("::1")][InlineData("::1/128")]
    [InlineData("::ffff:127.0.0.1")][InlineData("::ffff:127.0.0.1/128")]
    public void Equivalent_loopback_server_addresses_are_accepted(string address) =>
        PostgresBootstrap.ValidateCluster(Cluster with {ServerAddress=address},Cluster.DataDirectory,55433);

    [Fact]
    public async Task Cluster_snapshot_is_server_readback_with_bound_target_parameters()
    {
        var snapshot=await PostgresBootstrap.ReadClusterAsync((sql,args)=> {
            Assert.Contains("current_setting('server_version_num')",sql); Assert.Equal(new object[]{"sli_local","adlog_user"},args);
            return Rows([180006,Cluster.DataDirectory,"127.0.0.1",55433,false,false,"postgres",true]);
        },"sli_local");
        Assert.Equal(Cluster,snapshot);
    }

    [Fact]
    public async Task Psql_disables_startup_files_and_password_prompts_and_discards_captured_output()
    {
        string sql=FileAt("009_storage.sql","select 1;"),psql=Path.Combine(temporary,"psql.exe");
        int calls=0;
        var result=await PostgresBootstrap.RunFileAsync(psql,"127.0.0.1",55433,"postgres","sli_local",sql,"synthetic-admin-secret",start=> {
            calls++; Assert.Equal(new[]{"-X","--host","127.0.0.1","--port","55433","--username","postgres","--dbname","sli_local","--no-password","--set","ON_ERROR_STOP=1","--file",sql},start.ArgumentList);
            Assert.DoesNotContain("synthetic-admin-secret",string.Join(' ',start.ArgumentList)); Assert.True(start.RedirectStandardInput);
            Assert.Equal("synthetic-admin-secret",start.Environment["PGPASSWORD"]);
            return Task.FromResult(new BootstrapProcessResult(0,"sensitive migration output"));
        },Source);
        Assert.Equal(1,calls); Assert.Equal("{\"status\":\"ok\"}",PostgresBootstrap.Canonical(result));
        await ErrorAsync("migration_apply_failed",()=>PostgresBootstrap.RunFileAsync(psql,"127.0.0.1",55433,"postgres","sli_local",sql,AdminPassword,
            _=>Task.FromResult(new BootstrapProcessResult(1,"synthetic-admin-secret")),Source));
    }

    [Fact]
    public void Child_environment_keeps_only_validated_domain_and_no_inherited_cluster_options()
    {
        var environment=PostgresBootstrap.ChildEnvironment(Path.Combine(temporary,"psql.exe"),"synthetic-password",new Dictionary<string,string> {
            ["ADLOG_REPORT_DOMAIN_FQDN"]=" Corp.Example.TEST ",["PGOPTIONS"]="-c role=other",["PGSERVICE"]="other",["PGHOST"]="192.0.2.9",["SECRET"]="synthetic" });
        Assert.Equal("-c sli.report_domain_fqdn=corp.example.test",environment["PGOPTIONS"]);
        Assert.Equal(new[]{"PATH","PGOPTIONS","PGPASSWORD"},environment.Keys.Order(StringComparer.Ordinal));
        Error("source_domain_config_invalid",()=>PostgresBootstrap.ChildEnvironment(Path.Combine(temporary,"psql.exe"),"",new Dictionary<string,string>{["ADLOG_REPORT_DOMAIN_FQDN"]="example.test -c role=other"}));
    }

    [Theory][InlineData(0)][InlineData(1)]
    public async Task Windows_checkout_line_endings_preserve_reviewed_function_hashes_and_leave_source_untouched(int exitCode)
    {
        const string content="select 1;\r\nselect 2;\r\n";
        string path=FileAt("009_storage.sql",content),executed="";
        async Task Run() => await PostgresBootstrap.RunFileAsync(Path.Combine(temporary,"psql.exe"),"127.0.0.1",55433,"postgres","sli_local",path,AdminPassword,start=> {
            executed=start.ArgumentList[^1];Assert.NotEqual(path,executed);Assert.Equal("select 1;\nselect 2;\n",File.ReadAllText(executed));
            return Task.FromResult(new BootstrapProcessResult(exitCode,""));
        },Source);
        if(exitCode==0)await Run();else await ErrorAsync("migration_apply_failed",Run);
        Assert.Equal(content,File.ReadAllText(path));Assert.False(File.Exists(executed));
    }

    [Fact]
    public void Exact_ledger_rejects_missing_extra_and_renamed_markers()
    {
        (int,string)[] expected=[(1,"base"),(9,"storage"),(11,"reports")];
        PostgresBootstrap.VerifyLedger(expected,expected);
        foreach(var actual in new (int,string)[][] {
            [(1,"base"),(11,"reports")],[(1,"base"),(9,"wrong"),(11,"reports")],[(1,"base"),(9,"storage"),(10,"invented"),(11,"reports")] })
            Error("migration_ledger_mismatch",()=>PostgresBootstrap.VerifyLedger(actual,expected));
    }

    [Fact]
    public void Controller_inventory_requires_one_configured_source_domain()
    {
        string path=FileAt("controllers.json","{\"domain_controllers\":[{\"connect_address\":\"DC1.example.test\"},{\"connect_address\":\"dc2.example.test\"}]}");
        Assert.Equal("example.test",PostgresBootstrap.SourceDomain(path));
        File.WriteAllText(path,"{\"domain_controllers\":[{\"connect_address\":\"dc1.example.test\"},{\"connect_address\":\"dc2.other.example.test\"}]}");
        Error("source_domain_ambiguous",()=>PostgresBootstrap.SourceDomain(path));
    }

    [Fact]
    public async Task Source_domain_is_seeded_with_parameters_before_domain_bound_migrations()
    {
        var calls=new List<(string Sql,object[] Parameters)>();
        await PostgresBootstrap.SeedDomainAsync((sql,args)=> { calls.Add((sql,args)); return Rows([sql.Contains("public.forests")?7L:sql.Contains("insert into public.domains")?11L:1L]); },"example.test");
        Assert.Equal(new object[]{"example.test"},calls[0].Parameters); Assert.Equal(new object[]{7L,"example.test"},calls[1].Parameters);
        Assert.All(calls,c=>Assert.DoesNotContain("example.test",c.Sql));
    }

    [Fact]
    public async Task Schema_sequence_preserves_owners_cutover_owner_creation_and_hardened_boundary()
    {
        var definitions=new (int Version,string Name,string Prefix)[]{(9,"storage","set local role adlog_storage_owner;"),(11,"routing","set local role adlog_storage_owner;"),
            (12,"cutover","set local role adlog_storage_owner;"),(14,"auth",""),(17,"application","create table application_owned(id bigint);"),
            (19,"elevated","select pg_has_role(session_user,'adlog_storage_owner','MEMBER'); set local role adlog_storage_owner;"),
            (20,"casefold_search_indexes","create index concurrently if not exists idx_app on events(id);"),(37,"owner",""),(89,"hardened","")};
        foreach(var m in definitions) FileAt($"{m.Version:000}_{m.Name}.sql",m.Prefix+$" insert into schema_migrations(version,name) values({m.Version},'{m.Name}');\n");
        string schema=FileAt("postgres_schema.sql","select 1;"),roles=FileAt("storage_v2_roles.sql","select 2;"),psql=Path.Combine(temporary,"psql.exe");
        var commands=new List<ProcessStartInfo>(); var admin=new List<(string Sql,object[] Args)>(); var events=new List<string>();
        await PostgresBootstrap.ApplySequenceAsync(schema,roles,PostgresBootstrap.ForwardInventory(temporary),psql,"127.0.0.1",55433,"sli_local",AdminPassword,"synthetic-runtime",OwnerPassword,
            (sql,args)=> { admin.Add((sql,args)); events.Add(sql); return Rows([sql.Contains("public.forests")?7L:sql.Contains("insert into public.domains")?11L:1L]); },"example.test",
            start=>{commands.Add(start);events.Add(Path.GetFileName(start.ArgumentList[^1]));return Task.FromResult(new BootstrapProcessResult(0,""));},Source);
        Assert.Equal(new[]{"postgres_schema.sql","storage_v2_roles.sql"}.Concat(definitions.Select(m=>$"{m.Version:000}_{m.Name}.sql")),commands.Select(c=>Path.GetFileName(c.ArgumentList[^1])));
        Assert.Equal(new[]{"adlog_user","postgres","postgres","postgres","postgres","adlog_user","adlog_user","postgres","postgres","adlog_user","postgres"},commands.Select(c=>c.ArgumentList[c.ArgumentList.IndexOf("--username")+1]));
        Assert.Equal(PostgresBootstrap.PgcryptoSql,admin[0].Sql);Assert.Equal(PostgresBootstrap.GrantSchemaSql,admin[1].Sql);
        Assert.True(events.IndexOf("postgres_schema.sql")<events.FindIndex(e=>e.Contains("insert into public.forests")));
        Assert.True(events.FindIndex(e=>e.Contains("insert into public.domains"))<events.IndexOf("storage_v2_roles.sql"));
        Assert.True(events.IndexOf(PostgresBootstrap.EmptyV2RouteSql)<events.IndexOf("012_cutover.sql"));
        Assert.True(events.IndexOf(PostgresBootstrap.RevokeSchemaSql)<events.IndexOf("089_hardened.sql"));
        var owner=Assert.Single(admin,c=>c.Sql.Contains("insert into public.auth_users"));
        Assert.True(events.IndexOf("014_auth.sql")<events.IndexOf(owner.Sql)); Assert.Equal("platform-owner",owner.Args[0]); Assert.Equal("admin",owner.Args[2]);
        Assert.StartsWith("$argon2id$",(string)owner.Args[1]); Assert.True(new PasswordCodec().Verify((string)owner.Args[1],OwnerPassword).Valid);
        Assert.All(commands,c=> { string user=c.ArgumentList[c.ArgumentList.IndexOf("--username")+1]; Assert.Equal(user=="postgres"?AdminPassword:"synthetic-runtime",c.Environment["PGPASSWORD"]);
            Assert.DoesNotContain(AdminPassword,string.Join(' ',c.ArgumentList)); Assert.DoesNotContain("synthetic-runtime",string.Join(' ',c.ArgumentList)); });
    }

    [Fact]
    public async Task Owner_creation_hashes_and_parameterizes_password_and_rejects_short_values()
    {
        var calls=new List<(string Sql,object[] Args)>();
        BootstrapExecute execute=(sql,args)=>{calls.Add((sql,args));return Rows();};
        await PostgresBootstrap.CreateOwnerAsync(execute,OwnerPassword);
        var call=Assert.Single(calls); Assert.DoesNotContain(OwnerPassword,call.Sql); Assert.Equal("platform-owner",call.Args[0]); Assert.Equal("admin",call.Args[2]);
        Assert.True(new PasswordCodec().Verify((string)call.Args[1],OwnerPassword).Valid);
        await ErrorAsync("platform_owner_password_invalid",()=>PostgresBootstrap.CreateOwnerAsync(execute,"too-short")); Assert.Single(calls);
    }

    [Fact]
    public async Task Target_creation_parameterizes_secret_and_never_makes_runtime_database_owner()
    {
        var calls=new List<(string Sql,object[] Args)>();
        await PostgresBootstrap.CreateTargetAsync((sql,args)=>{calls.Add((sql,args));return Rows();},"sli_local","synthetic-runtime-secret");
        string text=string.Join('\n',calls.Select(c=>c.Sql)); Assert.DoesNotContain("synthetic-runtime-secret",text);
        Assert.Contains(calls,c=>c.Args.SequenceEqual(new object[]{"synthetic-runtime-secret"}));
        Assert.Contains("CREATE DATABASE \"sli_local\" OWNER \"postgres\"",text); Assert.DoesNotContain("OWNER \"adlog_user\"",text);
        Assert.Contains("NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS",text);
    }

    [Theory][InlineData(false)][InlineData(true)]
    public void Credentials_round_trip_in_exact_envelope_without_plaintext_and_refuse_replace_or_wrong_identity(bool owner)
    {
        string path=Path.Combine(temporary,owner?"platform-owner.dpapi.json":"postgres-admin.dpapi.json"),password=owner?OwnerPassword:"synthetic-admin-secret";
        var inputs=new List<string>();
        PostgresBootstrapCredentials.WriteCredential(path,password,Sid,value=>{inputs.Add(value);return "sealed-payload";},owner);
        Assert.Equal(new[]{password},inputs); string serialized=File.ReadAllText(path);Assert.DoesNotContain(password,serialized);
        var expected=new JsonObject { ["credential_version"]=1,["identity_sid"]=Sid,["kind"]=owner?"sli-platform-owner":"postgresql-administrator",
            ["payload"]="sealed-payload",["protection"]="windows-dpapi-current-user",["purpose"]=owner?"sli-platform-owner-password-v1":"sli-existing-postgres-admin-v1",["role"]=owner?"platform-owner":"postgres" };
        Assert.True(JsonNode.DeepEquals(expected,JsonNode.Parse(serialized)));
        Assert.Equal(password,PostgresBootstrapCredentials.ReadCredential(path,Sid,value=>value=="sealed-payload"?password:"wrong",owner));
        string prefix=owner?"platform_owner_credential":"admin_credential";
        Error(prefix+"_exists",()=>PostgresBootstrapCredentials.WriteCredential(path,"second-synthetic-password",Sid,_=>"second",owner));
        Error(prefix+"_owner_mismatch",()=>PostgresBootstrapCredentials.ReadCredential(path,OtherSid,_=>throw new InvalidOperationException("must not decrypt"),owner));
        expected["purpose"]="wrong"; File.WriteAllText(path,PostgresBootstrap.Canonical(expected));
        Error(prefix+"_invalid",()=>PostgresBootstrapCredentials.ReadCredential(path,Sid,_=>password,owner));
    }

    [Theory][InlineData(false)][InlineData(true)]
    public void Runtime_candidate_is_inactive_sealed_and_accepts_precreated_empty_directory(bool precreated)
    {
        string directory=Path.Combine(temporary,"profile"); if(precreated)Directory.CreateDirectory(directory);
        var inputs=new List<string>();
        string path=PostgresBootstrapCredentials.WriteRuntimeCandidate(directory,"sli_local","127.0.0.1",55433,"synthetic-runtime-secret",Sid,value=>{inputs.Add(value);return "synthetic-dpapi-payload";});
        Assert.Equal(new[]{"postgresql://adlog_user:synthetic-runtime-secret@127.0.0.1:55433/sli_local"},inputs);
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["active"]=false,["candidate_version"]=1,["identity_sid"]=Sid,["kind"]="runtime",
            ["payload"]="synthetic-dpapi-payload",["protection"]="windows-dpapi-current-user",["role"]="adlog_user" },JsonNode.Parse(File.ReadAllText(path))));
        Assert.Equal(directory,Path.GetDirectoryName(path)); Assert.DoesNotContain("synthetic-runtime-secret",File.ReadAllText(path));
        Error("profile_target_exists",()=>PostgresBootstrapCredentials.WriteRuntimeCandidate(directory,"sli_local","127.0.0.1",55433,"synthetic-runtime-secret",Sid,_=>"sealed"));
    }

    [Fact]
    public void Actual_CurrentUser_DPAPI_and_private_directory_enforce_the_production_boundary()
    {
        if(!OperatingSystem.IsWindows()) {
            Error("windows_dpapi_required",()=>PostgresBootstrapCredentials.Protect(AdminPassword,PostgresBootstrapCredentials.AdminPurpose));return;
        }
        foreach(string purpose in new[]{PostgresBootstrapCredentials.AdminPurpose,PostgresBootstrapCredentials.OwnerPurpose,PostgresBootstrapCredentials.RuntimePurpose}) {
            string sealedValue=PostgresBootstrapCredentials.Protect(OwnerPassword,purpose);
            Assert.NotEqual(OwnerPassword,sealedValue);Assert.Equal(OwnerPassword,PostgresBootstrapCredentials.Unprotect(sealedValue,purpose));
        }
        string sid=PostgresBootstrapCredentials.IdentitySid(),directory=Path.Combine(temporary,"private");
        PostgresBootstrapCredentials.CreatePrivateDirectory(directory,sid);Assert.True(PostgresBootstrapCredentials.VerifyPrivateDirectory(directory,sid));
        Assert.False(PostgresBootstrapCredentials.VerifyPrivateDirectory(directory,OtherSid));
    }

    private string[] Args(params string[] extra) => new[]{"--app-root",temporary,"--bin-dir",temporary,"--data-dir",temporary,"--database","sli_local"}.Concat(extra).ToArray();
    private sealed class Services : PostgresBootstrapServices
    {
        public readonly List<string> Events=[];
        public JsonObject Plan = new(){["operation"]="bootstrap_existing_postgresql_18",["database"]="sli_local"};
        public Exception? PlanFailure, ValidationFailure;
        public override string ReadHiddenPassword(string prompt) { Events.Add(prompt.Contains("platform-owner")?"prompt-owner":"prompt-admin");return prompt.Contains("platform-owner")?OwnerPassword:AdminPassword; }
        public override string LoadPassword(string root,bool owner) { Events.Add(owner?"load-owner":"load-admin");return owner?OwnerPassword:AdminPassword; }
        public override void SavePassword(string root,string password,bool owner) { Assert.Equal(owner?OwnerPassword:AdminPassword,password);Events.Add(owner?"save-owner":"save-admin"); }
        public override Task ValidateCredentialsAsync(BootstrapOptions opts,string password) { Assert.Equal(AdminPassword,password);Events.Add("validate"); if(ValidationFailure is not null)throw ValidationFailure;return Task.CompletedTask; }
        public override Task<JsonObject> PreparePlanAsync(BootstrapOptions opts,string password) { Assert.Equal(AdminPassword,password);Events.Add("plan"); if(PlanFailure is not null)throw PlanFailure;return Task.FromResult(Plan.DeepClone().AsObject()); }
        public override Task<string> ApplyAsync(BootstrapOptions opts,string password,string ownerPassword,JsonObject plan,string confirmation) {
            Assert.Equal(AdminPassword,password);Assert.Equal(OwnerPassword,ownerPassword);Assert.True(JsonNode.DeepEquals(Plan,plan));Assert.Equal(PostgresBootstrap.Confirmation(Plan),confirmation);Events.Add("apply");return Task.FromResult("synthetic-receipt.json"); }
    }
    private static void NoSecrets(string output) { Assert.DoesNotContain(AdminPassword,output);Assert.DoesNotContain(OwnerPassword,output);Assert.DoesNotContain("Traceback",output); }

    [Theory][InlineData(false)][InlineData(true)]
    public async Task Plan_reads_hidden_or_stdin_password_once_and_prints_only_sanitized_envelope(bool stdin)
    {
        var services=new Services();using var output=new StringWriter();using var error=new StringWriter();string status=Path.Combine(temporary,"status.json");
        var args=Args("--status-file",status).Concat(stdin?new[]{"--admin-password-stdin"}:[]).ToArray();
        int code=await PostgresBootstrapCommand.RunAsync(args,services,new StringReader(AdminPassword+"\n"),output,error);
        Assert.Equal(0,code);Assert.Equal(stdin?new[]{"plan"}:new[]{"prompt-admin","plan"},services.Events);Assert.Equal("",error.ToString());NoSecrets(output.ToString());
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["confirmation_sha256"]=PostgresBootstrap.Confirmation(services.Plan),["mode"]="plan",["plan"]=services.Plan.DeepClone() },JsonNode.Parse(output.ToString())));
        Assert.Equal("planned",JsonNode.Parse(File.ReadAllText(status))!["status"]!.GetValue<string>());
    }

    [Theory][InlineData("hidden")][InlineData("stdin")][InlineData("saved")]
    public async Task Apply_reuses_exact_live_plan_and_single_secret_reads(string mode)
    {
        var services=new Services();using var output=new StringWriter();using var error=new StringWriter();
        string[] flags=mode switch {"stdin"=>["--admin-password-stdin","--platform-owner-password-stdin"],"saved"=>["--use-saved-admin-password","--use-saved-platform-owner-password"],_=>[]};
        int code=await PostgresBootstrapCommand.RunAsync(Args("--apply-after-plan").Concat(flags).ToArray(),services,new StringReader(AdminPassword+"\n"+OwnerPassword+"\n"),output,error);
        Assert.Equal(0,code);Assert.Equal(mode switch {"stdin"=>new[]{"plan","apply"},"saved"=>["load-admin","load-owner","plan","apply"],_=>["prompt-admin","prompt-owner","plan","apply"]},services.Events);
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["confirmation_sha256"]=PostgresBootstrap.Confirmation(services.Plan),["mode"]="apply",["receipt"]="synthetic-receipt.json",["status"]="complete" },JsonNode.Parse(output.ToString())));
        NoSecrets(output.ToString()+error);Assert.Equal("",error.ToString());
    }

    [Theory][InlineData(false)][InlineData(true)]
    public async Task Explicit_apply_checks_confirmation_before_any_mutation(bool match)
    {
        var services=new Services();using var output=new StringWriter();using var error=new StringWriter();
        string confirmation=match?PostgresBootstrap.Confirmation(services.Plan):new('0',64);
        int code=await PostgresBootstrapCommand.RunAsync(Args("--apply","--confirm-plan",confirmation),services,new StringReader(""),output,error);
        Assert.Equal(match?0:2,code);Assert.Equal(match,services.Events.Contains("apply"));NoSecrets(output.ToString()+error);
        if(!match)Assert.Equal("confirmation_mismatch",JsonNode.Parse(error.ToString())!["code"]!.GetValue<string>());
    }

    [Theory][InlineData("success")][InlineData("plan-fails")][InlineData("authentication-fails")]
    public async Task Credentials_are_sealed_after_authentication_and_before_plan_failure_or_apply(string mode)
    {
        var services=new Services {PlanFailure=mode=="plan-fails"?new BootstrapException("target_database_exists"):null,
            ValidationFailure=mode=="authentication-fails"?new BootstrapException("postgres_admin_connection_failed"):null};
        using var output=new StringWriter();using var error=new StringWriter();
        int code=await PostgresBootstrapCommand.RunAsync(Args("--apply-after-plan","--admin-password-stdin","--save-admin-password","--platform-owner-password-stdin","--save-platform-owner-password"),
            services,new StringReader(AdminPassword+"\n"+OwnerPassword+"\n"),output,error);
        Assert.Equal(mode=="success"?0:2,code);
        Assert.Equal(mode switch {"success"=>new[]{"validate","save-admin","save-owner","plan","apply"},"plan-fails"=>["validate","save-admin","save-owner","plan"],_=>["validate"]},services.Events);
        NoSecrets(output.ToString()+error);
        if(mode!="success") Assert.Equal(mode=="plan-fails"?"target_database_exists":"postgres_admin_connection_failed",JsonNode.Parse(error.ToString())!["code"]!.GetValue<string>());
    }

    [Theory][InlineData(false)][InlineData(true)]
    public async Task Failure_status_and_stderr_contain_only_safe_codes(bool unknown)
    {
        var services=new Services {PlanFailure=unknown?new IOException("synthetic-admin password=synthetic-owner-password"):new BootstrapException("postgres_admin_connection_failed")};
        using var output=new StringWriter();using var error=new StringWriter();string status=Path.Combine(temporary,"status.json");
        int code=await PostgresBootstrapCommand.RunAsync(Args("--status-file",status),services,new StringReader(""),output,error);
        Assert.Equal(2,code);Assert.Equal("",output.ToString());NoSecrets(error.ToString()+File.ReadAllText(status));
        Assert.True(JsonNode.DeepEquals(new JsonObject{["status"]="error",["code"]=unknown?"internal_error":"postgres_admin_connection_failed"},JsonNode.Parse(File.ReadAllText(status))));
    }

    [Theory]
    [InlineData("--apply","confirmation_required")]
    [InlineData("--apply-after-plan --apply","invalid_arguments")]
    [InlineData("--admin-password synthetic-admin","invalid_arguments")]
    [InlineData("--use-saved-admin-password --admin-password-stdin","invalid_arguments")]
    [InlineData("--use-saved-platform-owner-password --save-platform-owner-password","invalid_arguments")]
    [InlineData("--database other","invalid_database")]
    [InlineData("--host 192.0.2.10","loopback_required")]
    [InlineData("--port 0","invalid_port")]
    public async Task Invalid_arguments_never_read_credentials_or_start_runtime(string flags,string expected)
    {
        var services=new Services();using var output=new StringWriter();using var error=new StringWriter();
        int code=await PostgresBootstrapCommand.RunAsync(Args(flags.Split(' ')),services,new StringReader(""),output,error);
        Assert.Equal(2,code);Assert.Empty(services.Events);Assert.Equal("",output.ToString());NoSecrets(error.ToString());
        Assert.Equal(expected,JsonNode.Parse(error.ToString())!["code"]!.GetValue<string>());
    }

    [Theory][InlineData(false)][InlineData(true)]
    public void Invalid_or_oversized_owner_password_never_creates_a_credential(bool oversized)
    {
        string path=Path.Combine(temporary,"owner.json"),password=oversized?new('x',4097):"synthetic\0owner-password";
        Error("platform_owner_password_invalid",()=>PostgresBootstrapCredentials.WriteCredential(path,password,Sid,_=>throw new InvalidOperationException("must not seal"),true));
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task Direct_command_fails_safely_before_any_connection_when_required_files_are_missing()
    {
        string status=Path.Combine(temporary,"status.json"),host=Environment.GetEnvironmentVariable("DOTNET_HOST_PATH")??"dotnet";
        var start=new ProcessStartInfo(host){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,WorkingDirectory=temporary};
        start.ArgumentList.Add(typeof(PostgresBootstrap).Assembly.Location);start.ArgumentList.Add("existing-postgres-bootstrap");
        foreach(string arg in Args("--admin-password-stdin","--status-file",status))start.ArgumentList.Add(arg);
        using var process=Process.Start(start)!;await process.StandardInput.WriteLineAsync(AdminPassword);process.StandardInput.Close();
        var stdout=process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);var stderr=process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);await process.WaitForExitAsync(TestContext.Current.CancellationToken);
        Assert.Equal(2,process.ExitCode);Assert.Equal("",await stdout);NoSecrets(await stderr);
        Assert.True(JsonNode.DeepEquals(new JsonObject{["status"]="error",["code"]="required_path_missing"},JsonNode.Parse(File.ReadAllText(status))));
    }

    [Fact]
    public async Task Full_PostgreSQL18_chain_uses_owned_cluster_exact_ledger_and_real_roles()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var pg=new PostCollectionPostgres(canonicalSchema:true);await pg.StartAsync(ct);
        var settings=new NpgsqlConnectionStringBuilder(pg.ConnectionString);
        var opts=new BootstrapOptions(Root,"",Path.Combine(pg.Root,"data"),"sli_local",settings.Host!,settings.Port);
        await using var admin=await PostgresBootstrap.ConnectAsync(opts,"postgres","");
        var snapshot=await PostgresBootstrap.ReadClusterAsync((sql,args)=>PostgresBootstrap.ExecuteAsync(admin,sql,args),opts.Database);
        PostgresBootstrap.ValidateCluster(snapshot,opts.DataDirectory,opts.Port);
        await PostgresBootstrap.CreateTargetAsync((sql,args)=>PostgresBootstrap.ExecuteAsync(admin,sql,args),opts.Database,"synthetic-runtime-password");
        string binary=OperatingSystem.IsWindows()?"psql.exe":"psql";
        string psql=Path.Combine(pg.BinaryDirectory,binary);
        var migrations=PostgresBootstrap.ForwardInventory(Path.Combine(Root,"config/postgres_migrations"));
        var plan=PostgresBootstrap.BuildPlan(opts.Database,snapshot.DataDirectory,snapshot,new('1',64),new('2',64),migrations);
        plan["paths"]=new JsonObject{["app_root"]=Root,["psql"]=psql};
        plan["source_identity"]=new JsonObject{["domain_fqdn"]="example.test"};
        plan["base_markers"]=new JsonArray(PostgresBootstrap.BaseMarkers(Path.Combine(Root,"config/postgres_schema.sql"))
            .Select(m=>(JsonNode)new JsonObject{["version"]=m.Version,["name"]=m.Name}).ToArray());
        try { await PostgresBootstrap.ApplyDatabaseAsync(opts,plan,"","synthetic-runtime-password",OwnerPassword); }
        catch(BootstrapException) {
            // Only our disposable cluster's fixed error messages; never dump SQL,
            // connection settings, captured psql output, or parameter details.
            string log=await pg.DiagnosticsAsync(ct);
            Assert.Fail(string.Join('\n',Regex.Matches(log,@"(?m)^.*(?:ERROR:|ОШИБКА:).*$").Select(m=>m.Value)));
        }
        await using var target=await PostgresBootstrap.ConnectAsync(opts,opts.Database,"");
        await PostgresBootstrap.VerifyTargetAsync((sql,args)=>PostgresBootstrap.ExecuteAsync(target,sql,args),plan);
        var owner=await PostgresBootstrap.ExecuteAsync(target,"select username,password_hash,role from auth_users where username='platform-owner'");
        Assert.Equal("admin",Assert.Single(owner)[2]);Assert.True(new PasswordCodec().Verify((string)owner[0][1]!,OwnerPassword).Valid);
        var runtimeSettings=new NpgsqlConnectionStringBuilder(settings.ConnectionString){Username="adlog_user",Password="synthetic-runtime-password",Database=opts.Database};
        await using var runtime=new NpgsqlConnection(runtimeSettings.ConnectionString);await runtime.OpenAsync(ct);
        await using var denied=new NpgsqlCommand("create table public.synthetic_forbidden(id bigint)",runtime);
        var failure=await Assert.ThrowsAsync<PostgresException>(()=>denied.ExecuteNonQueryAsync(ct));Assert.Equal("42501",failure.SqlState);
    }

    public void Dispose() => Directory.Delete(temporary,true);
}
