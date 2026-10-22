using ContainArmor.Engine.Models;
using ContainArmor.Engine.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace ContainArmor.Tests;

public class RemediationServiceTests
{
    [Fact]
    public async Task ExecuteRemediation_ApplyIptablesDrop_AddsRuleToActiveList()
    {
        // Arrange
        var mockClient = new MockDockerClient();
        var remediation = new RemediationService(mockClient, NullLogger<RemediationService>.Instance);

        var request = new RemediationRequest
        {
            ContainerId = "test-container-id",
            Action = "apply_iptables_drop",
            CustomRule = "172.17.0.5",
            Reason = "Lateral breach mitigation"
        };

        // Act
        var result = await remediation.ExecuteRemediationAsync(request);

        // Assert
        Assert.True(result.Success);
        Assert.Equal("apply_iptables_drop", result.Action);

        var activeRules = remediation.GetActiveRemediationRules();
        Assert.Single(activeRules);
        Assert.Equal("DROP", activeRules[0].Target);
        Assert.Equal("172.17.0.5", activeRules[0].Source);
        Assert.True(activeRules[0].IsRemediationRule);
    }

    [Fact]
    public async Task ExecuteRemediation_PauseAction_CallsDockerPause()
    {
        // Arrange
        var mockClient = new MockDockerClient();
        var remediation = new RemediationService(mockClient, NullLogger<RemediationService>.Instance);

        var request = new RemediationRequest
        {
            ContainerId = "target-container-1234",
            Action = "pause"
        };

        // Act
        var result = await remediation.ExecuteRemediationAsync(request);

        // Assert
        Assert.True(result.Success);
        Assert.Contains("target-conta", result.Message);
        Assert.True(mockClient.PauseWasCalled);
    }

    [Fact]
    public async Task ExecuteRemediation_Quarantine_DisconnectsFromNetworks()
    {
        // Arrange
        var mockClient = new MockDockerClient();
        var remediation = new RemediationService(mockClient, NullLogger<RemediationService>.Instance);

        var request = new RemediationRequest
        {
            ContainerId = "attacker-container",
            Action = "quarantine"
        };

        // Act
        var result = await remediation.ExecuteRemediationAsync(request);

        // Assert
        Assert.True(result.Success);
        Assert.True(mockClient.DisconnectWasCalled);
    }

    [Fact]
    public async Task ExecuteRemediation_NullContainerId_DoesNotThrowAndReturnsCleanMessage()
    {
        // Arrange
        var mockClient = new MockDockerClient();
        var remediation = new RemediationService(mockClient, NullLogger<RemediationService>.Instance);

        var request = new RemediationRequest
        {
            ContainerId = null!,
            Action = "pause"
        };

        // Act
        var result = await remediation.ExecuteRemediationAsync(request);

        // Assert: No NullReferenceException was thrown
        Assert.NotNull(result);
        Assert.True(mockClient.PauseWasCalled);
    }

    [Fact]
    public async Task ExecuteRemediation_UnknownAction_ReturnsFailureWithoutException()
    {
        // Arrange
        var mockClient = new MockDockerClient();
        var remediation = new RemediationService(mockClient, NullLogger<RemediationService>.Instance);

        var request = new RemediationRequest
        {
            ContainerId = "target-123",
            Action = "invalid_action_xyz"
        };

        // Act
        var result = await remediation.ExecuteRemediationAsync(request);

        // Assert
        Assert.False(result.Success);
        Assert.Contains("Unknown remediation action", result.Message);
    }

    [Fact]
    public async Task ExecuteRemediation_UnpauseAndStop_ExecutesSuccessfullyAndPopulatesHistory()
    {
        // Arrange
        var mockClient = new MockDockerClient();
        var remediation = new RemediationService(mockClient, NullLogger<RemediationService>.Instance);

        // Act
        var unpauseResult = await remediation.ExecuteRemediationAsync(new RemediationRequest
        {
            ContainerId = "cont-1234567890",
            Action = "unpause"
        });

        var stopResult = await remediation.ExecuteRemediationAsync(new RemediationRequest
        {
            ContainerId = "cont-1234567890",
            Action = "stop"
        });

        // Assert
        Assert.True(unpauseResult.Success);
        Assert.True(stopResult.Success);
        var history = remediation.GetExecutionHistory();
        Assert.Equal(2, history.Count);
        Assert.Equal("stop", history[0].Action);
        Assert.Equal("unpause", history[1].Action);
    }

    private class MockDockerClient : IDockerClientService
    {
        public bool PauseWasCalled { get; private set; }
        public bool DisconnectWasCalled { get; private set; }

        public Task<bool> IsDockerAvailableAsync() => Task.FromResult(true);
        public Task<List<DockerContainerListItem>> GetContainersAsync(bool all = true) => Task.FromResult(new List<DockerContainerListItem>());
        public Task<DockerContainerInspectResponse?> InspectContainerAsync(string id)
        {
            return Task.FromResult<DockerContainerInspectResponse?>(new DockerContainerInspectResponse
            {
                Id = id,
                NetworkSettings = new DockerNetworkSettings
                {
                    Networks = new Dictionary<string, DockerNetworkEndpointItem>
                    {
                        { "bridge", new DockerNetworkEndpointItem { NetworkID = "net-1", IPAddress = "172.17.0.2" } }
                    }
                }
            });
        }
        public Task<List<DockerNetworkInspectResponse>> GetNetworksAsync() => Task.FromResult(new List<DockerNetworkInspectResponse>());
        public Task<DockerNetworkInspectResponse?> InspectNetworkAsync(string networkId) => Task.FromResult<DockerNetworkInspectResponse?>(null);
        public Task<bool> PauseContainerAsync(string id) { PauseWasCalled = true; return Task.FromResult(true); }
        public Task<bool> UnpauseContainerAsync(string id) => Task.FromResult(true);
        public Task<bool> StopContainerAsync(string id, int timeout = 5) => Task.FromResult(true);
        public Task<bool> DisconnectNetworkAsync(string networkId, string containerId, bool force = true) { DisconnectWasCalled = true; return Task.FromResult(true); }
        public Task<bool> ConnectNetworkAsync(string networkId, string containerId) => Task.FromResult(true);
        public async IAsyncEnumerable<DockerEventItem> ListenEventsAsync([System.Runtime.CompilerServices.EnumeratorCancellation] System.Threading.CancellationToken cancellationToken = default)
        {
            await Task.CompletedTask;
            yield break;
        }
    }
}
