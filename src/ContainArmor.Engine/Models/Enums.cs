namespace ContainArmor.Engine.Models;

public enum SeverityLevel
{
    Info,
    Low,
    Medium,
    High,
    Critical
}

public enum RiskCategory
{
    PrivilegeEscalation,
    SocketLeak,
    CapabilityAbuse,
    NetworkExposure,
    FilesystemIntegrity,
    NamespaceSharing,
    ResourceExhaustion,
    BridgeIsolation
}

public enum RuleStatus
{
    Compliant,
    DangerousPromiscuous,
    Misordered,
    MissingDrop,
    LeakedPolicy
}

public enum ContainerSecurityState
{
    Running,
    Paused,
    Isolated,
    Terminated,
    Exited,
    Quarantined
}
