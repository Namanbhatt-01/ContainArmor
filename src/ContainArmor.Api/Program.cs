using ContainArmor.Api.Hubs;
using ContainArmor.Api.Services;
using ContainArmor.Engine;
using ContainArmor.Engine.Models;
using ContainArmor.Engine.Services;

var builder = WebApplication.CreateBuilder(args);

// Add Engine services & background workers
builder.Services.AddContainArmorEngine();
builder.Services.AddSignalR();
builder.Services.AddHostedService<SignalRTelemetryBroadcaster>();

// Add CORS for Blazor UI
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.SetIsOriginAllowed(_ => true)
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

app.UseCors("AllowAll");

// SignalR Hub Endpoint
app.MapHub<SecurityHub>("/hubs/security");

// REST Endpoints
app.MapGet("/api/health", async (IDockerClientService dockerClient) =>
{
    var available = await dockerClient.IsDockerAvailableAsync();
    return Results.Ok(new
    {
        Status = "Online",
        Platform = "ContainArmor Daemon v1.0",
        DockerConnected = available,
        Timestamp = DateTime.UtcNow
    });
});

app.MapGet("/api/containers", (SecurityOrchestrator orchestrator) =>
{
    return Results.Ok(orchestrator.GetContainerProfiles());
});

app.MapGet("/api/containers/{id}", (string id, SecurityOrchestrator orchestrator) =>
{
    var profiles = orchestrator.GetContainerProfiles();
    var match = profiles.FirstOrDefault(p => p.Id == id || p.CleanName == id || p.ShortId == id);
    return match != null ? Results.Ok(match) : Results.NotFound(new { Message = $"Container {id} not found." });
});

app.MapGet("/api/audit/summary", (SecurityOrchestrator orchestrator) =>
{
    return Results.Ok(orchestrator.GetLatestSummary());
});

app.MapGet("/api/audit/bridges", (SecurityOrchestrator orchestrator) =>
{
    return Results.Ok(orchestrator.GetBridgeAudits());
});

app.MapGet("/api/audit/iptables", (SecurityOrchestrator orchestrator) =>
{
    return Results.Ok(orchestrator.GetIptablesAudit());
});

app.MapGet("/api/events", (int? limit, SecurityOrchestrator orchestrator) =>
{
    return Results.Ok(orchestrator.GetRecentEvents(limit ?? 50));
});

app.MapPost("/api/audit/run", async (SecurityOrchestrator orchestrator) =>
{
    var summary = await orchestrator.RunFullAuditAsync();
    return Results.Ok(summary);
});

app.MapPost("/api/remediation", async (RemediationRequest request, SecurityOrchestrator orchestrator) =>
{
    var result = await orchestrator.RemediateAsync(request);
    return Results.Ok(result);
});

app.MapPost("/api/remediation/isolate/{id}", async (string id, SecurityOrchestrator orchestrator) =>
{
    var req = new RemediationRequest { ContainerId = id, Action = "isolate_network" };
    var result = await orchestrator.RemediateAsync(req);
    return Results.Ok(result);
});

app.MapPost("/api/remediation/pause/{id}", async (string id, SecurityOrchestrator orchestrator) =>
{
    var req = new RemediationRequest { ContainerId = id, Action = "pause" };
    var result = await orchestrator.RemediateAsync(req);
    return Results.Ok(result);
});

app.MapPost("/api/remediation/stop/{id}", async (string id, SecurityOrchestrator orchestrator) =>
{
    var req = new RemediationRequest { ContainerId = id, Action = "stop" };
    var result = await orchestrator.RemediateAsync(req);
    return Results.Ok(result);
});

app.MapPost("/api/remediation/apply-drop", async (RemediationRequest request, SecurityOrchestrator orchestrator) =>
{
    request.Action = "apply_iptables_drop";
    var result = await orchestrator.RemediateAsync(request);
    return Results.Ok(result);
});

app.Run();
