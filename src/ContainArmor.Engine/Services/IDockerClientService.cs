using ContainArmor.Engine.Models;

namespace ContainArmor.Engine.Services;

public interface IDockerClientService
{
    Task<bool> IsDockerAvailableAsync();
    Task<List<DockerContainerListItem>> GetContainersAsync(bool all = true);
    Task<DockerContainerInspectResponse?> InspectContainerAsync(string id);
    Task<List<DockerNetworkInspectResponse>> GetNetworksAsync();
    Task<DockerNetworkInspectResponse?> InspectNetworkAsync(string networkId);
    Task<bool> PauseContainerAsync(string id);
    Task<bool> UnpauseContainerAsync(string id);
    Task<bool> StopContainerAsync(string id, int timeout = 5);
    Task<bool> DisconnectNetworkAsync(string networkId, string containerId, bool force = true);
    Task<bool> ConnectNetworkAsync(string networkId, string containerId);
    IAsyncEnumerable<DockerEventItem> ListenEventsAsync(CancellationToken cancellationToken = default);
}
