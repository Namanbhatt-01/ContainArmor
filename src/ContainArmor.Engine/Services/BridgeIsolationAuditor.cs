using ContainArmor.Engine.Models;
using Microsoft.Extensions.Logging;

namespace ContainArmor.Engine.Services;

public class BridgeIsolationAuditor
{
    private readonly ILogger<BridgeIsolationAuditor> _logger;

    public BridgeIsolationAuditor(ILogger<BridgeIsolationAuditor> logger)
    {
        _logger = logger;
    }

    public List<BridgeNetworkAudit> AuditBridges(
        List<DockerNetworkInspectResponse> rawNetworks,
        List<ContainerSecurityProfile> containers)
    {
        var audits = new List<BridgeNetworkAudit>();

        foreach (var net in rawNetworks)
        {
            // Only inspect bridge networks
            if (!string.Equals(net.Driver, "bridge", StringComparison.OrdinalIgnoreCase))
                continue;

            var audit = new BridgeNetworkAudit
            {
                Id = net.Id,
                Name = net.Name,
                Driver = net.Driver,
                Scope = net.Scope,
                Internal = net.Internal,
                Attachable = net.Attachable,
                Options = net.Options ?? []
            };

            // Inspect ICC option (com.docker.network.bridge.enable_icc)
            if (net.Options != null && net.Options.TryGetValue("com.docker.network.bridge.enable_icc", out var iccStr))
            {
                audit.EnableIcc = !string.Equals(iccStr, "false", StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                // Default Docker behavior is ICC enabled!
                audit.EnableIcc = true;
            }

            // Subnet & Gateway
            if (net.IPAM?.Config != null && net.IPAM.Config.Count > 0)
            {
                audit.Subnet = net.IPAM.Config[0].Subnet;
                audit.Gateway = net.IPAM.Config[0].Gateway;
            }

            // Find all containers attached to this network
            var attachedContainers = new List<ContainerSecurityProfile>();
            foreach (var c in containers)
            {
                var endpoint = c.Networks.FirstOrDefault(n => n.NetworkId == net.Id || n.NetworkName == net.Name);
                if (endpoint != null)
                {
                    audit.ConnectedContainers.Add(endpoint);
                    attachedContainers.Add(c);
                }
                else if (net.Containers != null && net.Containers.ContainsKey(c.Id))
                {
                    var rawEp = net.Containers[c.Id];
                    var ep = new ContainerNetworkEndpoint
                    {
                        NetworkId = net.Id,
                        NetworkName = net.Name,
                        IPAddress = rawEp.IPv4Address.Split('/')[0],
                        MacAddress = rawEp.MacAddress,
                        Gateway = audit.Gateway,
                        InterContainerCommEnabled = audit.EnableIcc
                    };
                    audit.ConnectedContainers.Add(ep);
                    attachedContainers.Add(c);
                }
            }

            // Build Inter-Container Connectivity Matrix & Detect Breaches
            EvaluateInterContainerMatrix(audit, attachedContainers);

            audits.Add(audit);
        }

        return audits;
    }

    private static void EvaluateInterContainerMatrix(BridgeNetworkAudit audit, List<ContainerSecurityProfile> containers)
    {
        var matrix = new List<NetworkPeerConnection>();
        var breaches = new List<IsolationBreach>();
        int securityDeduction = 0;

        for (int i = 0; i < containers.Count; i++)
        {
            for (int j = 0; j < containers.Count; j++)
            {
                if (i == j) continue;

                var source = containers[i];
                var target = containers[j];

                var sourceEp = source.Networks.FirstOrDefault(n => n.NetworkId == audit.Id || n.NetworkName == audit.Name);
                var targetEp = target.Networks.FirstOrDefault(n => n.NetworkId == audit.Id || n.NetworkName == audit.Name);

                var sourceIP = !string.IsNullOrWhiteSpace(sourceEp?.IPAddress) ? sourceEp.IPAddress : string.Empty;
                var targetIP = !string.IsNullOrWhiteSpace(targetEp?.IPAddress) ? targetEp.IPAddress : string.Empty;

                // Can they communicate? If ICC is enabled on this bridge, yes!
                bool canComm = audit.EnableIcc;

                var conn = new NetworkPeerConnection
                {
                    SourceContainerId = source.Id,
                    SourceContainerName = source.CleanName,
                    TargetContainerId = target.Id,
                    TargetContainerName = target.CleanName,
                    SourceIP = !string.IsNullOrEmpty(sourceIP) ? sourceIP : "dynamic",
                    TargetIP = !string.IsNullOrEmpty(targetIP) ? targetIP : "dynamic",
                    CanCommunicate = canComm
                };

                // Check for Privilege Asymmetry:
                // If source has High or Critical risk, or has CAP_NET_ADMIN / Privileged / docker.sock,
                // and target is a lower-privilege or sensitive container, this is an isolation failure!
                if (canComm && (source.RiskScore >= 45 || source.Privileged || source.EffectiveDangerousCapabilities.Contains("NET_ADMIN")))
                {
                    conn.HasPrivilegeAsymmetry = true;
                    conn.RiskSeverity = SeverityLevel.Critical;
                    conn.RiskDescription = $"High-risk container '{source.CleanName}' can directly transmit packets to '{target.CleanName}' on unsegmented bridge '{audit.Name}'.";

                    // Log an isolation breach if not already logged
                    if (!breaches.Any(b => b.SourceContainer == source.CleanName && b.TargetContainer == target.CleanName))
                    {
                        var brName = audit.Name == "bridge" ? "docker0" : audit.Name;
                        var rule = (!string.IsNullOrEmpty(sourceIP) && !string.IsNullOrEmpty(targetIP))
                            ? $"iptables -I DOCKER-USER -s {sourceIP} -d {targetIP} -j DROP"
                            : (!string.IsNullOrEmpty(sourceIP)
                                ? $"iptables -I DOCKER-USER -s {sourceIP} -j DROP"
                                : $"iptables -I DOCKER-USER -i {brName} -o {brName} -m conntrack --ctstate NEW -j DROP");

                        var targetInfo = !string.IsNullOrEmpty(targetIP) ? $"IP: {targetIP}" : $"Target: {target.CleanName}";

                        var breach = new IsolationBreach
                        {
                            NetworkId = audit.Id,
                            NetworkName = audit.Name,
                            SourceContainer = source.CleanName,
                            TargetContainer = target.CleanName,
                            BreachType = "Privilege-Asymmetric Intra-Bridge Packet Sniffing / Lateral Traversal",
                            Severity = SeverityLevel.Critical,
                            Detail = $"Container '{source.CleanName}' (Risk {source.RiskScore}/100, Caps: {string.Join(',', source.EffectiveDangerousCapabilities)}) shares bridge '{audit.Name}' with '{target.CleanName}' ({targetInfo}) without intra-container drop rules.",
                            RecommendedIptablesRule = rule
                        };
                        breaches.Add(breach);
                        securityDeduction += 20;
                    }
                }
                else if (canComm && audit.Name == "bridge")
                {
                    conn.RiskSeverity = SeverityLevel.Medium;
                    conn.RiskDescription = $"Inter-container communication enabled by default on standard bridge. No network policy enforcement.";
                    securityDeduction += 5;
                }

                matrix.Add(conn);
            }
        }

        audit.InterContainerMatrix = matrix;
        audit.Breaches = breaches;

        audit.SecurityScore = Math.Clamp(100 - securityDeduction, 10, 100);
        audit.RiskLevel = audit.SecurityScore switch
        {
            < 50 => SeverityLevel.Critical,
            < 70 => SeverityLevel.High,
            < 85 => SeverityLevel.Medium,
            _ => SeverityLevel.Low
        };

        audit.StatusSummary = audit.EnableIcc
            ? (audit.Breaches.Count > 0
                ? $"FAILED: {audit.Breaches.Count} lateral isolation breaches detected. ICC enabled without micro-segmentation."
                : "WARNING: Inter-Container Communication (ICC) is enabled across all attached containers.")
            : "SECURE: ICC disabled (com.docker.network.bridge.enable_icc=false). Intra-bridge packet exchange blocked.";
    }
}
