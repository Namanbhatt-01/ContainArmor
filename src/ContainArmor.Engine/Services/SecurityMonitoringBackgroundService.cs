using ContainArmor.Engine.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ContainArmor.Engine.Services;

public class SecurityMonitoringBackgroundService : BackgroundService
{
    private readonly SecurityOrchestrator _orchestrator;
    private readonly IDockerClientService _dockerClient;
    private readonly ILogger<SecurityMonitoringBackgroundService> _logger;

    public SecurityMonitoringBackgroundService(
        SecurityOrchestrator orchestrator,
        IDockerClientService dockerClient,
        ILogger<SecurityMonitoringBackgroundService> logger)
    {
        _orchestrator = orchestrator;
        _dockerClient = dockerClient;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("SecurityMonitoringBackgroundService started. Performing initial audit scan...");

        try
        {
            await _orchestrator.RunFullAuditAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Initial security audit run failed");
        }

        // Start listening to real-time Docker events in parallel
        _ = ListenDockerEventsLoopAsync(stoppingToken);

        // Periodic heartbeat audit pulse
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(25), stoppingToken);
                await _orchestrator.RunFullAuditAsync();
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in periodic audit cycle");
            }
        }
    }

    private async Task ListenDockerEventsLoopAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await foreach (var ev in _dockerClient.ListenEventsAsync(stoppingToken))
                {
                    var containerId = ev.Actor?.ID ?? string.Empty;
                    var containerName = ev.Actor?.Attributes.TryGetValue("name", out var n) == true ? n : containerId;

                    _logger.LogInformation("Docker event detected: {Action} on {Container}", ev.Action, containerName);

                    var secEvent = new SecurityEvent
                    {
                        EventType = $"docker_{ev.Action}",
                        Severity = DetermineSeverityForDockerAction(ev.Action),
                        ContainerId = containerId,
                        ContainerName = containerName,
                        Title = $"Docker Event: {ev.Action}",
                        Message = $"Container '{containerName}' triggered action '{ev.Action}'. Updating security audit.",
                        Timestamp = DateTime.UtcNow
                    };

                    _orchestrator.RecordEvent(secEvent);

                    // Re-audit container landscape
                    await _orchestrator.RunFullAuditAsync();
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Docker events stream disconnected. Retrying in 5s...");
                await Task.Delay(5000, stoppingToken);
            }
        }
    }

    private static SeverityLevel DetermineSeverityForDockerAction(string action)
    {
        return action.ToLowerInvariant() switch
        {
            "die" or "kill" => SeverityLevel.Medium,
            "start" or "create" => SeverityLevel.Info,
            "pause" => SeverityLevel.Low,
            _ => SeverityLevel.Info
        };
    }
}
