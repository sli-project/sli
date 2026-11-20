using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Sli.Server.Auth.Lifecycle.Security;

public static class LoginSecurityServices
{
    public static IServiceCollection AddAuthLoginSecurity(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton<ISourceAdmission>(provider => new LoginSourceAdmission(
            provider.GetRequiredService<IConfiguration>(), provider.GetRequiredService<TimeProvider>()));
        services.AddSingleton<IAccountThrottle, AccountThrottle>();
        services.AddSingleton<IAuthAudit, AuthAudit>();
        return services;
    }
}
