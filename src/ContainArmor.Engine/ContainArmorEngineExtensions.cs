using ContainArmor.Engine.Services;
using Microsoft.Extensions.DependencyInjection;

namespace ContainArmor.Engine;

public static class ContainArmorEngineExtensions
{
    public static IServiceCollection AddContainArmorEngine(this IServiceCollection services)
    {
        services.AddSingleton<IDockerClientService, DockerUnixSocketClient>();
        services.AddSingleton<ContainerSecurityInspector>();
        services.AddSingleton<BridgeIsolationAuditor>();
        services.AddSingleton<IptablesAuditor>();
        services.AddSingleton<RemediationService>();
        services.AddSingleton<SecurityOrchestrator>();
        services.AddHostedService<SecurityMonitoringBackgroundService>();

        return services;
    }
}
