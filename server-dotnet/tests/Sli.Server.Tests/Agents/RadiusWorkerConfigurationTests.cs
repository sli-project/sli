using Sli.Server.Agents.Radius;
using Sli.Server.Agents.Control;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class RadiusWorkerConfigurationTests
{
    [Fact]
    public void StartupSetsServerTimeoutsBeforeWorkerRoleAndOverridesDsnOptions()
    {
        var value=RadiusAccountingImporter.WorkerConnectionString("Host=localhost;Database=sli;Username=worker;Options=-c lock_timeout=99");
        var parsed=new Npgsql.NpgsqlConnectionStringBuilder(value);
        Assert.Equal("-c statement_timeout=30000 -c lock_timeout=2000",parsed.Options);
        Assert.False(parsed.Pooling);Assert.False(parsed.Multiplexing);
        Assert.Equal(5,parsed.Timeout);Assert.Equal(30,parsed.CommandTimeout);
    }
    [Fact]
    public void RemoteAccessUsesReviewedBundledAdmissionAndFences()
    {
        using(var lease=AgentAssignmentPluginAdmission.Enter("sli.remote-access",null,null)) { }
        string root=Path.Combine(Path.GetTempPath(),"radius-fence-"+Guid.NewGuid().ToString("N"));
        string plugin=Path.Combine(root,"sli.remote-access");Directory.CreateDirectory(plugin);
        try {
            File.WriteAllText(Path.Combine(plugin,"draining.json"),"{}");
            Assert.Equal("plugin_update_draining",Assert.Throws<InvalidOperationException>(()=>AgentAssignmentPluginAdmission.Enter("sli.remote-access",root,null)).Message);
            File.Delete(Path.Combine(plugin,"draining.json"));File.WriteAllText(Path.Combine(plugin,"active.json"),"{}");
            Assert.Equal("plugin_generation_unavailable",Assert.Throws<InvalidOperationException>(()=>AgentAssignmentPluginAdmission.Enter("sli.remote-access",root,null)).Message);
        } finally { Directory.Delete(root,true); }
    }
    [Fact]
    public void DisabledSourceDoesNotRequireSecretsOrStartAConnection()
    {
        var config = RadiusWorkerConfiguration.Parse(new Dictionary<string,string?>());
        Assert.False(config.Enabled);
    }

    [Fact]
    public void EnabledWorkerRequiresDedicatedBindingAndRejectsMultiplexing()
    {
        string route=Path.Combine(Path.GetTempPath(),"radius-route-"+Guid.NewGuid().ToString("N")+".json");
        File.WriteAllText(route,RadiusCollectionRouteTests.Route);
        try {
        var values = new Dictionary<string,string?> {
            ["SLI_NPS_AGENT_IMPORT_ENABLED"]="1",
            ["SLI_NPS_AGENT_WORKER_DSN"]="Host=localhost;Database=sli_oracle;Username=worker;Multiplexing=true",
            ["ADLOG_RADIUS_COLLECTION_ROUTES_PATH"]=route,
            ["ADLOG_DATA_DIR"]=Path.GetFullPath(Path.GetTempPath())
        };
        Assert.Throws<ArgumentException>(() => RadiusWorkerConfiguration.Parse(values));
        values["SLI_NPS_AGENT_WORKER_DSN"]="Host=localhost;Database=sli_oracle;Username=worker";
        var config=RadiusWorkerConfiguration.Parse(values);
        Assert.True(config.Enabled);
        Assert.Equal("nps.example.test",config.Binding!.SourceName);
        Assert.False(new Npgsql.NpgsqlConnectionStringBuilder(config.WorkerDsn).Multiplexing);
        values["ADLOG_RADIUS_SOURCE_NAME"]=" ";
        Assert.Throws<ArgumentException>(() => RadiusWorkerConfiguration.Parse(values));
        } finally { File.Delete(route); }
    }

    [Fact]
    public void DedicatedDsnAndSeparatePasswordCanBeReadFromFiles()
    {
        string dir=Path.Combine(Path.GetTempPath(),"radius-config-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string dsn=Path.Combine(dir,"dsn"),password=Path.Combine(dir,"password"),route=Path.Combine(dir,"route.json");
            File.WriteAllText(route,RadiusCollectionRouteTests.Route);
            File.WriteAllText(dsn,"host=localhost dbname=sli_oracle user='worker name' sslmode=disable\n");
            File.WriteAllText(password," test password \r\n");
            var values=new Dictionary<string,string?> {
                ["SLI_NPS_AGENT_IMPORT_ENABLED"]="1",["SLI_NPS_AGENT_WORKER_DSN_FILE"]=dsn,
                ["SLI_NPS_AGENT_WORKER_PASSWORD_FILE"]=password,["ADLOG_RADIUS_COLLECTION_ROUTES_PATH"]=route,
                ["ADLOG_DATA_DIR"]=dir
            };
            var config=RadiusWorkerConfiguration.Parse(values);
            Assert.Equal(" test password ",new Npgsql.NpgsqlConnectionStringBuilder(config.WorkerDsn).Password);
            Assert.Equal("worker name",new Npgsql.NpgsqlConnectionStringBuilder(config.WorkerDsn).Username);
            values["SLI_NPS_AGENT_WORKER_DSN"]="Host=other";
            Assert.Throws<ArgumentException>(()=>RadiusWorkerConfiguration.Parse(values));
        }
        finally { Directory.Delete(dir,true); }
    }
    [Fact]
    public void SourceLibpqUriKeepsPercentEncodedCredentialsAndOptions()
    {
        string dir=Path.Combine(Path.GetTempPath(),"radius-uri-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(dir);
        try {
            string route=Path.Combine(dir,"route.json");File.WriteAllText(route,RadiusCollectionRouteTests.Route);
            var env=new Dictionary<string,string?> { ["SLI_NPS_AGENT_IMPORT_ENABLED"]="1",["SLI_NPS_AGENT_WORKER_DSN"]="postgresql://worker:p%20w@localhost:5432/sli_oracle?sslmode=disable&application_name=radius%2Btest",["ADLOG_RADIUS_COLLECTION_ROUTES_PATH"]=route,["ADLOG_DATA_DIR"]=dir };
            var b=new Npgsql.NpgsqlConnectionStringBuilder(RadiusWorkerConfiguration.Parse(env).WorkerDsn);
            Assert.Equal("worker",b.Username);Assert.Equal("p w",b.Password);Assert.Equal("sli_oracle",b.Database);Assert.Equal("radius+test",b.ApplicationName);
        } finally { Directory.Delete(dir,true); }
    }
}
