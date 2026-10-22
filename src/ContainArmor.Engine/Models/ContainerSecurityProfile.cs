namespace ContainArmor.Engine.Models;

public class ContainerMountInfo
{
    public string Source { get; set; } = string.Empty;
    public string Destination { get; set; } = string.Empty;
    public string Mode { get; set; } = string.Empty;
    public bool RW { get; set; }
    public string Type { get; set; } = string.Empty;
    public bool IsSensitive { get; set; }
    public string RiskExplanation { get; set; } = string.Empty;
}

public class ContainerPortMapping
{
    public int PrivatePort { get; set; }
    public int PublicPort { get; set; }
    public string Type { get; set; } = "tcp";
    public string IP { get; set; } = "0.0.0.0";
}

public class ContainerNetworkEndpoint
{
    public string NetworkName { get; set; } = string.Empty;
    public string NetworkId { get; set; } = string.Empty;
    public string IPAddress { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public string Gateway { get; set; } = string.Empty;
    public bool InterContainerCommEnabled { get; set; }
}

public class ContainerSecurityProfile
{
    public string Id { get; set; } = string.Empty;
    public string ShortId => Id.Length >= 12 ? Id[..12] : Id;
    public string Name { get; set; } = string.Empty;
    public string CleanName => Name.TrimStart('/');
    public string Image { get; set; } = string.Empty;
    public string State { get; set; } = "running";
    public ContainerSecurityState SecurityState { get; set; } = ContainerSecurityState.Running;
    public DateTime CreatedAt { get; set; }

    // Core privilege attributes
    public bool Privileged { get; set; }
    public List<string> CapAdd { get; set; } = [];
    public List<string> CapDrop { get; set; } = [];
    public List<string> EffectiveDangerousCapabilities { get; set; } = [];
    public bool ReadonlyRootfs { get; set; }

    // Mounts & Filesystem
    public List<ContainerMountInfo> Mounts { get; set; } = [];
    public bool HasDockerSocketMounted { get; set; }
    public bool HasProcMounted { get; set; }
    public bool HasSysMounted { get; set; }
    public bool HasRootMounted { get; set; }

    // Namespaces
    public string PidMode { get; set; } = string.Empty;
    public string IpcMode { get; set; } = string.Empty;
    public string NetworkMode { get; set; } = string.Empty;
    public string UtsMode { get; set; } = string.Empty;
    public bool SharesHostPid => string.Equals(PidMode, "host", StringComparison.OrdinalIgnoreCase);
    public bool SharesHostIpc => string.Equals(IpcMode, "host", StringComparison.OrdinalIgnoreCase);
    public bool SharesHostNetwork => string.Equals(NetworkMode, "host", StringComparison.OrdinalIgnoreCase);

    // Security profiles
    public string AppArmorProfile { get; set; } = string.Empty;
    public string SeccompProfile { get; set; } = string.Empty;
    public bool IsAppArmorUnconfined => string.Equals(AppArmorProfile, "unconfined", StringComparison.OrdinalIgnoreCase);
    public bool IsSeccompUnconfined => string.Equals(SeccompProfile, "unconfined", StringComparison.OrdinalIgnoreCase);

    // Identity & Isolation
    public string User { get; set; } = string.Empty;
    public bool RunsAsRoot
    {
        get
        {
            if (string.IsNullOrWhiteSpace(User)) return true;
            var uidPart = User.Split(':')[0].Trim();
            return uidPart == "0" || string.Equals(uidPart, "root", StringComparison.OrdinalIgnoreCase);
        }
    }

    // Resources
    public long MemoryLimitBytes { get; set; }
    public long PidsLimit { get; set; }
    public int CpuShares { get; set; }

    // Networking
    public List<ContainerNetworkEndpoint> Networks { get; set; } = [];
    public List<ContainerPortMapping> Ports { get; set; } = [];

    // Audit scoring
    public int RiskScore { get; set; } // 0 - 100
    public SeverityLevel RiskLevel { get; set; } = SeverityLevel.Low;
    public List<SecurityFinding> Findings { get; set; } = [];
    public List<string> EscapeVectors { get; set; } = [];
    public List<string> Recommendations { get; set; } = [];
    public DateTime LastAuditedAt { get; set; } = DateTime.UtcNow;
}
