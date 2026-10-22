using ContainArmor.Engine.Models;
using ContainArmor.Engine.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace ContainArmor.Tests;

public class SecurityOrchestratorTests
{
    [Fact]
    public async Task RunFullAuditAsync_CorrelatesContainersAndComputesFleetScore()
    {
        // Arrange
        var mockDocker = new MockDockerService();
        var inspector = new ContainerSecurityInspector(NullLogger<ContainerSecurityInspector>.Instance);
        var bridgeAuditor = new BridgeIsolationAuditor(NullLogger<BridgeIsolationAuditor>.Instance);
        var iptablesAuditor = new IptablesAuditor(NullLogger<IptablesAuditor>.Instance);
        var remediation = new RemediationService(mockDocker, NullLogger<RemediationService>.Instance);

        var orchestrator = new SecurityOrchestrator(
            mockDocker,
            inspector,
            bridgeAuditor,
            iptablesAuditor,
            remediation,
            NullLogger<SecurityOrchestrator>.Instance);

        // Act
        var summary = await orchestrator.RunFullAuditAsync();

        // Assert
        Assert.NotNull(summary);
        Assert.True(summary.TotalContainers > 0);
        Assert.True(summary.OverallFleetScore >= 0 && summary.OverallFleetScore <= 100);
        Assert.NotEmpty(orchestrator.GetContainerProfiles());
        Assert.NotEmpty(orchestrator.GetBridgeAudits());
        Assert.NotNull(orchestrator.GetIptablesAudit());
    }

    [Fact]
    public async Task RemediateAsync_ExecutesActionAndDispatchesEvent()
    {
        // Arrange
        var mockDocker = new MockDockerService();
        var inspector = new ContainerSecurityInspector(NullLogger<ContainerSecurityInspector>.Instance);
        var bridgeAuditor = new BridgeIsolationAuditor(NullLogger<BridgeIsolationAuditor>.Instance);
        var iptablesAuditor = new IptablesAuditor(NullLogger<IptablesAuditor>.Instance);
        var remediation = new RemediationService(mockDocker, NullLogger<RemediationService>.Instance);

        var orchestrator = new SecurityOrchestrator(
            mockDocker,
            inspector,
            bridgeAuditor,
            iptablesAuditor,
            remediation,
            NullLogger<SecurityOrchestrator>.Instance);

        var request = new RemediationRequest
        {
            ContainerId = "target-1234",
            Action = "pause"
        };

        SecurityEvent? capturedEvent = null;
        orchestrator.OnSecurityEventReceived += ev =>
        {
            capturedEvent = ev;
            return Task.CompletedTask;
        };

        // Act
        var result = await orchestrator.RemediateAsync(request);

        // Assert
        Assert.True(result.Success);
        var recentEvents = orchestrator.GetRecentEvents();
        Assert.Contains(recentEvents, e => e.EventType == "remediation_applied");
    }

    [Fact]
    public void RecordEvent_CapsHistoryBufferAtMaxCapacity()
    {
        // Arrange
        var mockDocker = new MockDockerService();
        var inspector = new ContainerSecurityInspector(NullLogger<ContainerSecurityInspector>.Instance);
        var bridgeAuditor = new BridgeIsolationAuditor(NullLogger<BridgeIsolationAuditor>.Instance);
        var iptablesAuditor = new IptablesAuditor(NullLogger<IptablesAuditor>.Instance);
        var remediation = new RemediationService(mockDocker, NullLogger<RemediationService>.Instance);

        var orchestrator = new SecurityOrchestrator(
            mockDocker,
            inspector,
            bridgeAuditor,
            iptablesAuditor,
            remediation,
            NullLogger<SecurityOrchestrator>.Instance);

        // Act: Insert 250 events
        for (int i = 0; i < 250; i++)
        {
            orchestrator.RecordEvent(new SecurityEvent
            {
                Title = $"Event {i}",
                EventType = "test"
            });
        }

        // Assert: Buffer capped at 200
        var events = orchestrator.GetRecentEvents(300);
        Assert.True(events.Count <= 200);
    }

    [Fact]
    public async Task RunFullAuditAsync_EmptyFleet_ProducesBaselineHealthScore100()
    {
        // Arrange
        var mockDocker = new MockDockerService { Containers = [] };
        var inspector = new ContainerSecurityInspector(NullLogger<ContainerSecurityInspector>.Instance);
        var bridgeAuditor = new BridgeIsolationAuditor(NullLogger<BridgeIsolationAuditor>.Instance);
        var iptablesAuditor = new IptablesAuditor(NullLogger<IptablesAuditor>.Instance);
        var remediation = new RemediationService(mockDocker, NullLogger<RemediationService>.Instance);

        var orchestrator = new SecurityOrchestrator(
            mockDocker,
            inspector,
            bridgeAuditor,
            iptablesAuditor,
            remediation,
            NullLogger<SecurityOrchestrator>.Instance);

        // Act
        var summary = await orchestrator.RunFullAuditAsync();

        // Assert
        Assert.Equal(0, summary.TotalContainers);
        Assert.Equal(100, summary.OverallFleetScore);
        Assert.Equal(SeverityLevel.Low, summary.OverallRiskLevel);
    }

    [Fact]
    public async Task RunFullAuditAsync_WithActiveRemediation_InjectsRuleIntoDockerUserChain()
    {
        // Arrange
        var mockDocker = new MockDockerService();
        var inspector = new ContainerSecurityInspector(NullLogger<ContainerSecurityInspector>.Instance);
        var bridgeAuditor = new BridgeIsolationAuditor(NullLogger<BridgeIsolationAuditor>.Instance);
        var iptablesAuditor = new IptablesAuditor(NullLogger<IptablesAuditor>.Instance);
        var remediation = new RemediationService(mockDocker, NullLogger<RemediationService>.Instance);

        var orchestrator = new SecurityOrchestrator(
            mockDocker,
            inspector,
            bridgeAuditor,
            iptablesAuditor,
            remediation,
            NullLogger<SecurityOrchestrator>.Instance);

        // Act: Apply drop rule remediation
        await orchestrator.RemediateAsync(new RemediationRequest
        {
            Action = "apply_iptables_drop",
            CustomRule = "10.0.0.99",
            Reason = "Automated test mitigation"
        });

        // Assert: DOCKER-USER chain in cached iptables contains injected remediation rule
        var iptables = orchestrator.GetIptablesAudit();
        Assert.NotNull(iptables);
        var dockerUser = iptables.Chains.FirstOrDefault(c => c.ChainName == "DOCKER-USER");
        Assert.NotNull(dockerUser);
        Assert.Contains(dockerUser.Rules, r => r.Source == "10.0.0.99" && r.Target == "DROP");
    }

    private class MockDockerService : IDockerClientService
    {
        public List<DockerContainerListItem>? Containers { get; set; }

        public Task<bool> IsDockerAvailableAsync() => Task.FromResult(true);
        public Task<List<DockerContainerListItem>> GetContainersAsync(bool all = true)
        {
            return Task.FromResult(Containers ?? new List<DockerContainerListItem>
            {
                new() { Id = "c1", Names = ["/web-node"], Image = "nginx:alpine", State = "running" }
            });
        }

        public Task<DockerContainerInspectResponse?> InspectContainerAsync(string id)
        {
            return Task.FromResult<DockerContainerInspectResponse?>(new DockerContainerInspectResponse
            {
                Id = id,
                Name = "/web-node",
                Image = "nginx:alpine",
                State = new DockerContainerState { Running = true, Status = "running" },
                HostConfig = new DockerHostConfig { Privileged = false }
            });
        }

        public Task<List<DockerNetworkInspectResponse>> GetNetworksAsync()
        {
            return Task.FromResult(new List<DockerNetworkInspectResponse>
            {
                new() { Id = "net-1", Name = "bridge", Driver = "bridge" }
            });
        }

        public Task<DockerNetworkInspectResponse?> InspectNetworkAsync(string networkId) => Task.FromResult<DockerNetworkInspectResponse?>(null);
        public Task<bool> PauseContainerAsync(string id) => Task.FromResult(true);
        public Task<bool> UnpauseContainerAsync(string id) => Task.FromResult(true);
        public Task<bool> StopContainerAsync(string id, int timeout = 5) => Task.FromResult(true);
        public Task<bool> DisconnectNetworkAsync(string networkId, string containerId, bool force = true) => Task.FromResult(true);
        public Task<bool> ConnectNetworkAsync(string networkId, string containerId) => Task.FromResult(true);
        public async IAsyncEnumerable<DockerEventItem> ListenEventsAsync([System.Runtime.CompilerServices.EnumeratorCancellation] System.Threading.CancellationToken cancellationToken = default)
        {
            await Task.CompletedTask;
            yield break;
        }
    }
}
