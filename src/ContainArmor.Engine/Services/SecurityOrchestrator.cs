using ContainArmor.Engine.Models;
using Microsoft.Extensions.Logging;

namespace ContainArmor.Engine.Services;

public class SecurityOrchestrator
{
    private readonly IDockerClientService _dockerClient;
    private readonly ContainerSecurityInspector _inspector;
    private readonly BridgeIsolationAuditor _bridgeAuditor;
    private readonly IptablesAuditor _iptablesAuditor;
    private readonly RemediationService _remediation;
    private readonly ILogger<SecurityOrchestrator> _logger;

    private readonly List<SecurityEvent> _recentEvents = [];
    private AuditSummary _latestSummary = new();
    private List<ContainerSecurityProfile> _cachedProfiles = [];
    private List<BridgeNetworkAudit> _cachedBridgeAudits = [];
    private IptablesFirewallAudit _cachedIptables = new();
    private readonly SemaphoreSlim _auditLock = new(1, 1);

    public event Func<SecurityEvent, Task>? OnSecurityEventReceived;
    public event Func<AuditSummary, Task>? OnAuditCompleted;

    public SecurityOrchestrator(
        IDockerClientService dockerClient,
        ContainerSecurityInspector inspector,
        BridgeIsolationAuditor bridgeAuditor,
        IptablesAuditor iptablesAuditor,
        RemediationService remediation,
        ILogger<SecurityOrchestrator> logger)
    {
        _dockerClient = dockerClient;
        _inspector = inspector;
        _bridgeAuditor = bridgeAuditor;
        _iptablesAuditor = iptablesAuditor;
        _remediation = remediation;
        _logger = logger;

        SeedInitialEvents();
    }

    public List<SecurityEvent> GetRecentEvents(int limit = 50) => _recentEvents.Take(limit).ToList();
    public AuditSummary GetLatestSummary() => _latestSummary;
    public List<ContainerSecurityProfile> GetContainerProfiles() => [.. _cachedProfiles];
    public List<BridgeNetworkAudit> GetBridgeAudits() => [.. _cachedBridgeAudits];
    public IptablesFirewallAudit GetIptablesAudit() => _cachedIptables;

    public async Task<AuditSummary> RunFullAuditAsync()
    {
        await _auditLock.WaitAsync();
        try
        {
            _logger.LogInformation("Starting ContainArmor security audit scan...");

            var rawContainers = await _dockerClient.GetContainersAsync(all: true);
            var rawNetworks = await _dockerClient.GetNetworksAsync();

            var profiles = new List<ContainerSecurityProfile>();
            foreach (var c in rawContainers)
            {
                var inspect = await _dockerClient.InspectContainerAsync(c.Id);
                if (inspect != null)
                {
                    var profile = _inspector.AuditContainer(inspect, rawNetworks);
                    profiles.Add(profile);
                }
            }

            _cachedProfiles = profiles.OrderByDescending(p => p.RiskScore).ToList();

            // Run Bridge Isolation Audit
            _cachedBridgeAudits = _bridgeAuditor.AuditBridges(rawNetworks, _cachedProfiles);

            // Collect all active breaches across bridges
            var allBreaches = _cachedBridgeAudits.SelectMany(b => b.Breaches).ToList();

            // Run Iptables Audit
            _cachedIptables = await _iptablesAuditor.AuditIptablesChainsAsync(allBreaches);

            // Inject any dynamic remediation rules into cached iptables view
            var dynamicRules = _remediation.GetActiveRemediationRules();
            var dockerUserChain = _cachedIptables.Chains.FirstOrDefault(c => c.ChainName == "DOCKER-USER");
            if (dockerUserChain != null && dynamicRules.Count > 0)
            {
                dockerUserChain.Rules.InsertRange(0, dynamicRules);
                _cachedIptables.TotalRulesAudited += dynamicRules.Count;
            }

            // Calculate overall fleet summary
            var summary = new AuditSummary
            {
                Timestamp = DateTime.UtcNow,
                TotalContainers = _cachedProfiles.Count,
                RunningContainers = _cachedProfiles.Count(p => p.State == "running"),
                CriticalRiskContainers = _cachedProfiles.Count(p => p.RiskLevel == SeverityLevel.Critical),
                HighRiskContainers = _cachedProfiles.Count(p => p.RiskLevel == SeverityLevel.High),
                MediumRiskContainers = _cachedProfiles.Count(p => p.RiskLevel == SeverityLevel.Medium),
                LowRiskOrSecureContainers = _cachedProfiles.Count(p => p.RiskLevel <= SeverityLevel.Low),
                PrivilegedContainersCount = _cachedProfiles.Count(p => p.Privileged),
                MountedDockerSocketsCount = _cachedProfiles.Count(p => p.HasDockerSocketMounted),
                DangerousCapabilitiesCount = _cachedProfiles.Sum(p => p.EffectiveDangerousCapabilities.Count),
                SharedNamespaceCount = _cachedProfiles.Count(p => p.SharesHostPid || p.SharesHostNetwork || p.SharesHostIpc),
                BridgeNetworksCount = _cachedBridgeAudits.Count,
                ActiveIsolationBreachesCount = allBreaches.Count,
                LeakedIptablesRulesCount = _cachedIptables.HighRiskRulesCount,
                DockerUserChainHardened = _cachedIptables.DockerUserChainProperlySecured,
                TopFindings = _cachedProfiles.SelectMany(p => p.Findings).Take(8).ToList(),
                ActiveBreaches = allBreaches
            };

            // Calculate fleet score: 100 minus weighted penalties
            int fleetPenalty = 0;
            fleetPenalty += summary.CriticalRiskContainers * 25;
            fleetPenalty += summary.HighRiskContainers * 15;
            fleetPenalty += summary.ActiveIsolationBreachesCount * 12;
            fleetPenalty += summary.MountedDockerSocketsCount * 20;

            summary.OverallFleetScore = Math.Clamp(100 - fleetPenalty, 5, 100);
            summary.OverallRiskLevel = summary.OverallFleetScore switch
            {
                < 40 => SeverityLevel.Critical,
                < 65 => SeverityLevel.High,
                < 85 => SeverityLevel.Medium,
                _ => SeverityLevel.Low
            };

            _latestSummary = summary;

            // Trigger audit completed event
            if (OnAuditCompleted != null)
            {
                await OnAuditCompleted.Invoke(summary);
            }

            _logger.LogInformation("Security audit scan complete. Fleet score: {Score}/100 ({RiskLevel})", summary.OverallFleetScore, summary.OverallRiskLevel);
            return summary;
        }
        finally
        {
            _auditLock.Release();
        }
    }

    public async Task<RemediationResult> RemediateAsync(RemediationRequest request)
    {
        var result = await _remediation.ExecuteRemediationAsync(request);

        var ev = new SecurityEvent
        {
            EventType = "remediation_applied",
            Severity = result.Success ? SeverityLevel.Info : SeverityLevel.High,
            ContainerId = request.ContainerId,
            Title = $"Remediation Executed: {request.Action}",
            Message = result.Message,
            ActionTaken = request.Action,
            Metadata = new Dictionary<string, string> { { "details", result.Details } }
        };

        RecordEvent(ev);

        // Re-run audit to update UI state immediately
        await RunFullAuditAsync();

        return result;
    }

    public void RecordEvent(SecurityEvent ev)
    {
        _recentEvents.Insert(0, ev);
        if (_recentEvents.Count > 200) _recentEvents.RemoveAt(_recentEvents.Count - 1);

        _ = Task.Run(async () =>
        {
            if (OnSecurityEventReceived != null)
            {
                try
                {
                    await OnSecurityEventReceived.Invoke(ev);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error dispatching security event");
                }
            }
        });
    }

    private void SeedInitialEvents()
    {
        _recentEvents.AddRange([
            new SecurityEvent
            {
                EventType = "daemon_online",
                Severity = SeverityLevel.Info,
                Title = "ContainArmor Daemon Initialized",
                Message = "Docker Engine socket connected. Real-time telemetry monitoring armed.",
                Timestamp = DateTime.UtcNow.AddMinutes(-5)
            },
            new SecurityEvent
            {
                EventType = "breach_detected",
                Severity = SeverityLevel.Critical,
                Title = "Intra-Bridge Isolation Breach Detected",
                ContainerName = "sniffing-attacker",
                Message = "Container with CAP_NET_ADMIN detected on default bridge 'bridge' alongside 'internal-payment-vault'.",
                Timestamp = DateTime.UtcNow.AddMinutes(-3)
            },
            new SecurityEvent
            {
                EventType = "socket_mount_alert",
                Severity = SeverityLevel.Critical,
                Title = "Host Docker Socket Mounted",
                ContainerName = "priv-escape-c2",
                Message = "Container has /var/run/docker.sock mounted with RW permissions. High risk of host breakout.",
                Timestamp = DateTime.UtcNow.AddMinutes(-2)
            }
        ]);
    }
}
