using ContainArmor.Engine.Models;
using ContainArmor.Engine.Services;
using Microsoft.AspNetCore.SignalR.Client;

namespace ContainArmor.Blazor.Services;

public class ContainArmorStateService : IAsyncDisposable
{
    private readonly SecurityOrchestrator _orchestrator;
    private readonly ILogger<ContainArmorStateService> _logger;
    private readonly IConfiguration _configuration;
    private HubConnection? _hubConnection;

    public AuditSummary Summary { get; private set; } = new();
    public List<ContainerSecurityProfile> Containers { get; private set; } = [];
    public List<BridgeNetworkAudit> BridgeAudits { get; private set; } = [];
    public IptablesFirewallAudit Iptables { get; private set; } = new();
    public List<SecurityEvent> Events { get; private set; } = [];
    public List<RemediationResult> RemediationLogs { get; private set; } = [];

    public bool IsSignalRConnected => _hubConnection?.State == HubConnectionState.Connected;
    public bool IsAuditing { get; private set; }
    public SecurityEvent? LatestToastAlert { get; private set; }

    public event Action? OnChange;

    public ContainArmorStateService(
        SecurityOrchestrator orchestrator,
        ILogger<ContainArmorStateService> logger,
        IConfiguration configuration)
    {
        _orchestrator = orchestrator;
        _logger = logger;
        _configuration = configuration;

        // Hook into in-process orchestrator events
        _orchestrator.OnSecurityEventReceived += HandleIncomingEventAsync;
        _orchestrator.OnAuditCompleted += HandleAuditCompletedAsync;
    }

    public async Task InitializeAsync()
    {
        await RefreshLocalStateAsync();
        await TryConnectSignalRAsync();
    }

    private async Task RefreshLocalStateAsync()
    {
        Summary = _orchestrator.GetLatestSummary();
        Containers = _orchestrator.GetContainerProfiles();
        BridgeAudits = _orchestrator.GetBridgeAudits();
        Iptables = _orchestrator.GetIptablesAudit();
        Events = _orchestrator.GetRecentEvents(30);

        if (Containers.Count == 0)
        {
            await TriggerAuditAsync();
        }
        else
        {
            NotifyStateChanged();
        }
    }

    public async Task TriggerAuditAsync()
    {
        IsAuditing = true;
        NotifyStateChanged();

        try
        {
            Summary = await _orchestrator.RunFullAuditAsync();
            Containers = _orchestrator.GetContainerProfiles();
            BridgeAudits = _orchestrator.GetBridgeAudits();
            Iptables = _orchestrator.GetIptablesAudit();
            Events = _orchestrator.GetRecentEvents(30);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to run audit");
        }
        finally
        {
            IsAuditing = false;
            NotifyStateChanged();
        }
    }

    public async Task<RemediationResult> ExecuteRemediationAsync(RemediationRequest request)
    {
        var result = await _orchestrator.RemediateAsync(request);
        RemediationLogs.Insert(0, result);
        await RefreshLocalStateAsync();
        return result;
    }

    private Task HandleIncomingEventAsync(SecurityEvent ev)
    {
        Events.Insert(0, ev);
        if (Events.Count > 50) Events.RemoveAt(Events.Count - 1);

        if (ev.Severity >= SeverityLevel.High)
        {
            LatestToastAlert = ev;
        }

        NotifyStateChanged();
        return Task.CompletedTask;
    }

    private Task HandleAuditCompletedAsync(AuditSummary summary)
    {
        Summary = summary;
        Containers = _orchestrator.GetContainerProfiles();
        BridgeAudits = _orchestrator.GetBridgeAudits();
        Iptables = _orchestrator.GetIptablesAudit();
        NotifyStateChanged();
        return Task.CompletedTask;
    }

    private async Task TryConnectSignalRAsync()
    {
        var apiUrl = _configuration["ApiBaseUrl"] ?? "http://localhost:5100";
        try
        {
            _hubConnection = new HubConnectionBuilder()
                .WithUrl($"{apiUrl}/hubs/security")
                .WithAutomaticReconnect()
                .Build();

            _hubConnection.On<SecurityEvent>("SecurityAlertDetected", ev =>
            {
                HandleIncomingEventAsync(ev);
            });

            _hubConnection.On<AuditSummary>("AuditCompleted", summary =>
            {
                HandleAuditCompletedAsync(summary);
            });

            await _hubConnection.StartAsync();
            _logger.LogInformation("SignalR connected to {Url}", apiUrl);
            NotifyStateChanged();
        }
        catch (Exception ex)
        {
            _logger.LogDebug("SignalR remote hub connection not active ({Message}). Operating in direct in-process mode.", ex.Message);
        }
    }

    public void DismissToast()
    {
        LatestToastAlert = null;
        NotifyStateChanged();
    }

    private void NotifyStateChanged() => OnChange?.Invoke();

    public async ValueTask DisposeAsync()
    {
        _orchestrator.OnSecurityEventReceived -= HandleIncomingEventAsync;
        _orchestrator.OnAuditCompleted -= HandleAuditCompletedAsync;

        if (_hubConnection != null)
        {
            await _hubConnection.DisposeAsync();
        }
    }
}
