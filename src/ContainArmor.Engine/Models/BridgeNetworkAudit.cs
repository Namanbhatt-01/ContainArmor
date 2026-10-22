namespace ContainArmor.Engine.Models;

public class NetworkPeerConnection
{
    public string SourceContainerId { get; set; } = string.Empty;
    public string SourceContainerName { get; set; } = string.Empty;
    public string TargetContainerId { get; set; } = string.Empty;
    public string TargetContainerName { get; set; } = string.Empty;
    public string SourceIP { get; set; } = string.Empty;
    public string TargetIP { get; set; } = string.Empty;
    public bool CanCommunicate { get; set; }
    public bool HasPrivilegeAsymmetry { get; set; } // Low-privilege container can reach high-privilege container
    public string RiskDescription { get; set; } = string.Empty;
    public SeverityLevel RiskSeverity { get; set; } = SeverityLevel.Info;
}

public class IsolationBreach
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string NetworkId { get; set; } = string.Empty;
    public string NetworkName { get; set; } = string.Empty;
    public string SourceContainer { get; set; } = string.Empty;
    public string TargetContainer { get; set; } = string.Empty;
    public string BreachType { get; set; } = string.Empty;
    public SeverityLevel Severity { get; set; } = SeverityLevel.High;
    public string Detail { get; set; } = string.Empty;
    public string RecommendedIptablesRule { get; set; } = string.Empty;
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}

public class BridgeNetworkAudit
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Driver { get; set; } = "bridge";
    public string Scope { get; set; } = "local";
    public bool EnableIcc { get; set; } = true; // Docker default is true (Inter-Container Communication)
    public string Subnet { get; set; } = string.Empty;
    public string Gateway { get; set; } = string.Empty;
    public bool Internal { get; set; }
    public bool Attachable { get; set; }
    public Dictionary<string, string> Options { get; set; } = [];

    public List<ContainerNetworkEndpoint> ConnectedContainers { get; set; } = [];
    public List<NetworkPeerConnection> InterContainerMatrix { get; set; } = [];
    public List<IsolationBreach> Breaches { get; set; } = [];

    public int SecurityScore { get; set; } = 100;
    public SeverityLevel RiskLevel { get; set; } = SeverityLevel.Low;
    public string StatusSummary { get; set; } = string.Empty;
}
