using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth.ReportKeys;
using Xunit;

namespace Sli.Server.Tests.Access;

public sealed class ReportCatalogCompositionTests
{
    [Fact]
    public void ProgramProvidesOneCatalogToHttpAndReportKeyServices()
    {
        using var host = new WebApplicationFactory<Program>().WithWebHostBuilder(Sli.Server.Tests.Domains.SafeTestEnvironment.ConfigureApiHost).WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sli:TrustedProxies"] = "", ["Sli:AuthRequired"] = "1",
                ["Sli:AllowUnauthenticated"] = "1", ["Sli:OwnerSetup"] = "0",
                ["Sli:AuthAllowInsecureHttp"] = "1",
                ["ConnectionStrings:Sli"] = "Host=127.0.0.1;Port=1;Database=synthetic;Username=synthetic"
            })));
        var catalog = host.Services.GetRequiredService<ReportRuleCatalog>();
        Assert.Same(catalog, host.Services.GetRequiredService<IReportCatalogProvider>());
        Assert.Same(catalog, host.Services.GetRequiredService<IReportRuleCatalog>());
        using var scope = host.Services.CreateScope();
        Assert.IsType<DomainAccessService>(scope.ServiceProvider.GetRequiredService<IDomainAccessService>());
        Assert.IsType<ReportAssignmentWriter>(scope.ServiceProvider.GetRequiredService<IReportAssignmentWriter>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<IReportKeyAdministration>());
    }
}
