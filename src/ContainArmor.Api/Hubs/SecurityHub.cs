using ContainArmor.Engine.Models;
using ContainArmor.Engine.Services;
using Microsoft.AspNetCore.SignalR;

namespace ContainArmor.Api.Hubs;

public class SecurityHub : Hub
{
    private readonly SecurityOrchestrator _orchestrator;
    private readonly ILogger<SecurityHub> _logger;

    public SecurityHub(SecurityOrchestrator orchestrator, ILogger<SecurityHub> logger)
    {
        _orchestrator = orchestrator;
        _logger = logger;
    }

    public Task<AuditSummary> RequestSummary()
    {
        return Task.FromResult(_orchestrator.GetLatestSummary());
    }

    public Task<List<SecurityEvent>> RequestRecentEvents()
    {
        return Task.FromResult(_orchestrator.GetRecentEvents(25));
    }

    public async Task<AuditSummary> TriggerAudit()
    {
        _logger.LogInformation("SignalR client {ConnectionId} requested audit scan", Context.ConnectionId);
        return await _orchestrator.RunFullAuditAsync();
    }

    public async Task<RemediationResult> RequestRemediation(RemediationRequest request)
    {
        _logger.LogInformation("SignalR client {ConnectionId} requested remediation: {Action} on {ContainerId}",
            Context.ConnectionId, request.Action, request.ContainerId);
        var result = await _orchestrator.RemediateAsync(request);
        await Clients.All.SendAsync("RemediationExecuted", result);
        return result;
    }
}
