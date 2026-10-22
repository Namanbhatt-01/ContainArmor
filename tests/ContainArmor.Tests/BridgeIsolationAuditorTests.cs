using ContainArmor.Engine.Models;
using ContainArmor.Engine.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace ContainArmor.Tests;

public class BridgeIsolationAuditorTests
{
    private readonly BridgeIsolationAuditor _auditor;

    public BridgeIsolationAuditorTests()
    {
        _auditor = new BridgeIsolationAuditor(NullLogger<BridgeIsolationAuditor>.Instance);
    }

    [Fact]
    public void AuditBridges_IccEnabled_DetectsPrivilegeAsymmetryBreach()
    {
        // Arrange
        var rawNetworks = new List<DockerNetworkInspectResponse>
        {
            new()
            {
                Id = "net-app-bridge",
                Name = "app-bridge",
                Driver = "bridge",
                Options = new Dictionary<string, string>
                {
                    { "com.docker.network.bridge.enable_icc", "true" }
                },
                IPAM = new DockerIPAM
                {
                    Config = [new DockerIPAMConfig { Subnet = "172.20.0.0/16", Gateway = "172.20.0.1" }]
                }
            }
        };

        var highRiskAttacker = new ContainerSecurityProfile
        {
            Id = "attacker-1",
            Name = "/attacker-pod",
            RiskScore = 75,
            RiskLevel = SeverityLevel.Critical,
            EffectiveDangerousCapabilities = ["NET_ADMIN"],
            Networks = [new ContainerNetworkEndpoint { NetworkId = "net-app-bridge", NetworkName = "app-bridge", IPAddress = "172.20.0.2" }]
        };

        var sensitiveTarget = new ContainerSecurityProfile
        {
            Id = "db-target-1",
            Name = "/db-vault",
            RiskScore = 15,
            RiskLevel = SeverityLevel.Low,
            Networks = [new ContainerNetworkEndpoint { NetworkId = "net-app-bridge", NetworkName = "app-bridge", IPAddress = "172.20.0.3" }]
        };

        // Act
        var audits = _auditor.AuditBridges(rawNetworks, [highRiskAttacker, sensitiveTarget]);

        // Assert
        Assert.Single(audits);
        var bridgeAudit = audits[0];
        Assert.True(bridgeAudit.EnableIcc);
        Assert.Single(bridgeAudit.Breaches);

        var breach = bridgeAudit.Breaches[0];
        Assert.Equal("attacker-pod", breach.SourceContainer);
        Assert.Equal("db-vault", breach.TargetContainer);
        Assert.Equal(SeverityLevel.Critical, breach.Severity);
        Assert.Contains("iptables -I DOCKER-USER -s 172.20.0.2 -d 172.20.0.3 -j DROP", breach.RecommendedIptablesRule);
    }

    [Fact]
    public void AuditBridges_IccDisabled_BlocksCrossContainerCommunication()
    {
        // Arrange
        var rawNetworks = new List<DockerNetworkInspectResponse>
        {
            new()
            {
                Id = "net-isolated",
                Name = "containarmor-isolated",
                Driver = "bridge",
                Options = new Dictionary<string, string>
                {
                    { "com.docker.network.bridge.enable_icc", "false" }
                }
            }
        };

        var container1 = new ContainerSecurityProfile
        {
            Id = "c1",
            Name = "/service-a",
            RiskScore = 20,
            Networks = [new ContainerNetworkEndpoint { NetworkId = "net-isolated", NetworkName = "containarmor-isolated", IPAddress = "10.0.1.2" }]
        };

        var container2 = new ContainerSecurityProfile
        {
            Id = "c2",
            Name = "/service-b",
            RiskScore = 20,
            Networks = [new ContainerNetworkEndpoint { NetworkId = "net-isolated", NetworkName = "containarmor-isolated", IPAddress = "10.0.1.3" }]
        };

        // Act
        var audits = _auditor.AuditBridges(rawNetworks, [container1, container2]);

        // Assert
        Assert.Single(audits);
        var b = audits[0];
        Assert.False(b.EnableIcc);
        Assert.Empty(b.Breaches);
        Assert.Contains(b.InterContainerMatrix, m => !m.CanCommunicate);
    }

    [Fact]
    public void AuditBridges_StoppedContainerWithEmptyIp_GeneratesValidInterfaceFallbackRule()
    {
        // Arrange
        var rawNetworks = new List<DockerNetworkInspectResponse>
        {
            new()
            {
                Id = "net-bridge",
                Name = "bridge",
                Driver = "bridge",
                Options = new Dictionary<string, string> { { "com.docker.network.bridge.enable_icc", "true" } }
            }
        };

        var highRiskAttacker = new ContainerSecurityProfile
        {
            Id = "attacker-stopped",
            Name = "/attacker-stopped",
            RiskScore = 55,
            EffectiveDangerousCapabilities = ["NET_ADMIN"],
            Networks = [new ContainerNetworkEndpoint { NetworkId = "net-bridge", NetworkName = "bridge", IPAddress = "" }]
        };

        var target = new ContainerSecurityProfile
        {
            Id = "target-stopped",
            Name = "/target-stopped",
            Networks = [new ContainerNetworkEndpoint { NetworkId = "net-bridge", NetworkName = "bridge", IPAddress = "" }]
        };

        // Act
        var audits = _auditor.AuditBridges(rawNetworks, [highRiskAttacker, target]);

        // Assert
        var b = audits[0];
        Assert.NotEmpty(b.Breaches);
        var breach = b.Breaches[0];
        Assert.DoesNotContain("-s  -d", breach.RecommendedIptablesRule);
        Assert.Contains("docker0", breach.RecommendedIptablesRule);
    }

    [Fact]
    public void AuditBridges_NonBridgeNetworksIgnored_OnlyProcessesBridgeDriver()
    {
        // Arrange
        var rawNetworks = new List<DockerNetworkInspectResponse>
        {
            new() { Id = "host-net", Name = "host", Driver = "host" },
            new() { Id = "null-net", Name = "none", Driver = "null" },
            new() { Id = "overlay-net", Name = "overlay-swarm", Driver = "overlay" }
        };

        var container = new ContainerSecurityProfile
        {
            Id = "c1",
            Name = "/test-host",
            Networks = [new ContainerNetworkEndpoint { NetworkId = "host-net", NetworkName = "host" }]
        };

        // Act
        var audits = _auditor.AuditBridges(rawNetworks, [container]);

        // Assert: All non-bridge drivers should be excluded
        Assert.Empty(audits);
    }

    [Fact]
    public void AuditBridges_TriContainerBridge_DetectsAsymmetricLateralThreatToAllBenignPeers()
    {
        // Arrange
        var rawNetworks = new List<DockerNetworkInspectResponse>
        {
            new()
            {
                Id = "net-shared",
                Name = "prod-bridge",
                Driver = "bridge",
                Options = new Dictionary<string, string> { { "com.docker.network.bridge.enable_icc", "true" } }
            }
        };

        var attacker = new ContainerSecurityProfile
        {
            Id = "c-attacker",
            Name = "/c-attacker",
            RiskScore = 80,
            EffectiveDangerousCapabilities = ["NET_ADMIN", "NET_RAW"],
            Networks = [new ContainerNetworkEndpoint { NetworkId = "net-shared", NetworkName = "prod-bridge", IPAddress = "172.22.0.10" }]
        };

        var targetWeb = new ContainerSecurityProfile
        {
            Id = "c-web",
            Name = "/c-web",
            RiskScore = 15,
            Networks = [new ContainerNetworkEndpoint { NetworkId = "net-shared", NetworkName = "prod-bridge", IPAddress = "172.22.0.11" }]
        };

        var targetDb = new ContainerSecurityProfile
        {
            Id = "c-db",
            Name = "/c-db",
            RiskScore = 10,
            Networks = [new ContainerNetworkEndpoint { NetworkId = "net-shared", NetworkName = "prod-bridge", IPAddress = "172.22.0.12" }]
        };

        // Act
        var audits = _auditor.AuditBridges(rawNetworks, [attacker, targetWeb, targetDb]);

        // Assert
        Assert.Single(audits);
        var bridge = audits[0];

        // 3 containers => 3 * 2 = 6 directional matrix peer connections
        Assert.Equal(6, bridge.InterContainerMatrix.Count);

        // Attacker -> Web and Attacker -> DB are breaches (2 breaches total)
        Assert.Equal(2, bridge.Breaches.Count);
        Assert.Contains(bridge.Breaches, b => b.SourceContainer == "c-attacker" && b.TargetContainer == "c-web");
        Assert.Contains(bridge.Breaches, b => b.SourceContainer == "c-attacker" && b.TargetContainer == "c-db");
        Assert.True(bridge.SecurityScore < 70);
    }

    [Fact]
    public void AuditBridges_EmptyBridgeWithoutContainers_HasCleanStatus()
    {
        // Arrange
        var rawNetworks = new List<DockerNetworkInspectResponse>
        {
            new()
            {
                Id = "net-vacant",
                Name = "vacant-bridge",
                Driver = "bridge"
            }
        };

        // Act
        var audits = _auditor.AuditBridges(rawNetworks, []);

        // Assert
        Assert.Single(audits);
        Assert.Empty(audits[0].ConnectedContainers);
        Assert.Empty(audits[0].InterContainerMatrix);
        Assert.Empty(audits[0].Breaches);
        Assert.Equal(100, audits[0].SecurityScore);
    }
}
