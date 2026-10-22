using ContainArmor.Api.Hubs;
using ContainArmor.Engine.Models;
using ContainArmor.Engine.Services;
using Microsoft.AspNetCore.SignalR;

namespace ContainArmor.Api.Services;

public class SignalRTelemetryBroadcaster : IHostedService
{
    private readonly SecurityOrchestrator _orchestrator;
    private readonly IHubContext<SecurityHub> _hubContext;
    private readonly ILogger<SignalRTelemetryBroadcaster> _logger;

    public SignalRTelemetryBroadcaster(
        SecurityOrchestrator orchestrator,
        IHubContext<SecurityHub> hubContext,
        ILogger<SignalRTelemetryBroadcaster> logger)
    {
        _orchestrator = orchestrator;
        _hubContext = hubContext;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _orchestrator.OnSecurityEventReceived += HandleSecurityEventAsync;
        _orchestrator.OnAuditCompleted += HandleAuditCompletedAsync;
        _logger.LogInformation("SignalRTelemetryBroadcaster hooked into SecurityOrchestrator events.");
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _orchestrator.OnSecurityEventReceived -= HandleSecurityEventAsync;
        _orchestrator.OnAuditCompleted -= HandleAuditCompletedAsync;
        return Task.CompletedTask;
    }

    private async Task HandleSecurityEventAsync(SecurityEvent ev)
    {
        try
        {
            await _hubContext.Clients.All.SendAsync("SecurityAlertDetected", ev);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to broadcast security alert via SignalR");
        }
    }

    private async Task HandleAuditCompletedAsync(AuditSummary summary)
    {
        try
        {
            await _hubContext.Clients.All.SendAsync("AuditCompleted", summary);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to broadcast audit summary via SignalR");
        }
    }
}
