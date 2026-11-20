using System.Text;
using Npgsql;
using Sli.Server.Agents.SnapshotPublication;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class GpoWorkerConfigurationTests
{
    [Fact]
    public void RequiredConfigurationNamesTheFailingSecretWithoutItsContentsOrPath()
    {
        var values = new Dictionary<string, string?> { ["ADLOG_AD_CONTEXT_WORKER_DSN"] = "host=localhost dbname=sli user=synthetic",
            ["ADLOG_AD_CONTEXT_WORKER_PASSWORD_FILE"] = "synthetic-private-path" };
        string Parse() => GpoWorkerConfiguration.CreateNamed(values.GetValueOrDefault, _ => throw new IOException("synthetic-private-value"),
            "ADLOG_AD_CONTEXT_WORKER_DSN", "ADLOG_AD_CONTEXT_WORKER_PASSWORD", "synthetic", 30);
        Assert.Equal("server_configuration_invalid:ADLOG_AD_CONTEXT_WORKER_PASSWORD_FILE:unavailable",
            Assert.Throws<Sli.Server.Hosting.ServerConfigurationException>(Parse).Message);
        values.Remove("ADLOG_AD_CONTEXT_WORKER_DSN");
        Assert.Equal("server_configuration_invalid:ADLOG_AD_CONTEXT_WORKER_DSN:missing",
            Assert.Throws<Sli.Server.Hosting.ServerConfigurationException>(Parse).Message);
    }

    private static bool Parse(Dictionary<string,string> env, Dictionary<string,string> files, out NpgsqlConnectionStringBuilder? result)
    {
        bool ok = GpoWorkerConfiguration.TryCreate(k => env.GetValueOrDefault(k), p => Encoding.UTF8.GetBytes(files[p]), out var value);
        result = ok ? new NpgsqlConnectionStringBuilder(value!) : null;
        return ok;
    }

    [Fact]
    public void SourceDeploymentDsnAndSeparatePasswordAreTranslatedWithoutChangingSpaces()
    {
        var env = new Dictionary<string,string> { ["ADLOG_AD_CONTEXT_WORKER_DSN"] = "host=postgres port=5432 dbname=sli user=sli_context_login", ["ADLOG_AD_CONTEXT_WORKER_PASSWORD_FILE"] = "password" };
        Assert.True(Parse(env, new() { ["password"] = " synthetic password \r\n" }, out var b));
        Assert.Equal("postgres",b!.Host); Assert.Equal("sli",b.Database); Assert.Equal("sli_context_login",b.Username);
        Assert.Equal(" synthetic password ",b.Password); Assert.False(b.Multiplexing); Assert.False(b.Pooling);
    }

    [Fact]
    public void QuotedValuesAndEscapesWorkWhileConflictsAndUnknownFormsFailClosed()
    {
        var env = new Dictionary<string,string> { ["ADLOG_AD_CONTEXT_WORKER_DSN_FILE"] = "dsn" };
        var files = new Dictionary<string,string> { ["dsn"] = "host=localhost dbname='sample db' user='worker\\'one'\n" };
        Assert.True(Parse(env,files,out var b)); Assert.Equal("sample db",b!.Database); Assert.Equal("worker'one",b.Username);
        env["ADLOG_AD_CONTEXT_WORKER_DSN"] = "host=elsewhere"; Assert.False(Parse(env,files,out _));
        env.Remove("ADLOG_AD_CONTEXT_WORKER_DSN"); files["dsn"] = "host=localhost dbname=sli user=worker options=unsafe"; Assert.False(Parse(env,files,out _));
        files["dsn"] = "postgresql://localhost/sli"; Assert.False(Parse(env,files,out _));
        files["dsn"] = "host=localhost dbname=sli user=worker password=inline";
        env["ADLOG_AD_CONTEXT_WORKER_PASSWORD"] = "separate"; Assert.False(Parse(env,files,out _));
        env.Remove("ADLOG_AD_CONTEXT_WORKER_PASSWORD");
        files["dsn"] = "Host=localhost;Database=sli;Username=worker;Multiplexing=false"; Assert.True(Parse(env,files,out _));
        files["dsn"] = "Host=localhost;Database=sli;Username=worker;Multiplexing=true"; Assert.False(Parse(env,files,out _));
    }
}
