namespace ContainArmor.Engine.Models;

public class AuditSummary
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public int OverallFleetScore { get; set; } = 100; // 0 (catastrophic) to 100 (fully hardened)
    public SeverityLevel OverallRiskLevel { get; set; } = SeverityLevel.Low;
    
    // Container metrics
    public int TotalContainers { get; set; }
    public int RunningContainers { get; set; }
    public int CriticalRiskContainers { get; set; }
    public int HighRiskContainers { get; set; }
    public int MediumRiskContainers { get; set; }
    public int LowRiskOrSecureContainers { get; set; }

    // Threat counters
    public int PrivilegedContainersCount { get; set; }
    public int MountedDockerSocketsCount { get; set; }
    public int DangerousCapabilitiesCount { get; set; }
    public int SharedNamespaceCount { get; set; }

    // Network & Firewall metrics
    public int BridgeNetworksCount { get; set; }
    public int ActiveIsolationBreachesCount { get; set; }
    public int LeakedIptablesRulesCount { get; set; }
    public bool DockerUserChainHardened { get; set; }

    public List<SecurityFinding> TopFindings { get; set; } = [];
    public List<IsolationBreach> ActiveBreaches { get; set; } = [];
}

public class SecurityEvent
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string EventType { get; set; } = string.Empty; // container_started, breach_detected, privileged_alert, socket_mount_alert, remediation_applied
    public SeverityLevel Severity { get; set; } = SeverityLevel.Info;
    public string ContainerId { get; set; } = string.Empty;
    public string ContainerName { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public string ActionTaken { get; set; } = string.Empty;
    public Dictionary<string, string> Metadata { get; set; } = [];
}

public class RemediationRequest
{
    public string ContainerId { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty; // isolate_network, pause, stop, apply_iptables_drop, quarantine_all
    public string TargetNetwork { get; set; } = string.Empty;
    public string CustomRule { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
}

public class RemediationResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string ContainerId { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
    public DateTime ExecutedAt { get; set; } = DateTime.UtcNow;
}
