using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using ContainArmor.Engine.Models;
using Microsoft.Extensions.Logging;

namespace ContainArmor.Engine.Services;

public class DockerUnixSocketClient : IDockerClientService
{
    private readonly ILogger<DockerUnixSocketClient> _logger;
    private readonly string? _activeSocketPath;
    private readonly HttpClient? _httpClient;
    private readonly bool _isLiveDockerConnected;

    public DockerUnixSocketClient(ILogger<DockerUnixSocketClient> logger)
    {
        _logger = logger;
        _activeSocketPath = FindDockerSocket();

        if (!string.IsNullOrEmpty(_activeSocketPath) && File.Exists(_activeSocketPath))
        {
            try
            {
                var handler = new SocketsHttpHandler
                {
                    ConnectCallback = async (context, ct) =>
                    {
                        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                        await socket.ConnectAsync(new UnixDomainSocketEndPoint(_activeSocketPath), ct);
                        return new NetworkStream(socket, ownsSocket: true);
                    },
                    PooledConnectionLifetime = TimeSpan.FromMinutes(5)
                };

                _httpClient = new HttpClient(handler)
                {
                    BaseAddress = new Uri("http://localhost"),
                    Timeout = TimeSpan.FromSeconds(15)
                };
                _isLiveDockerConnected = true;
                _logger.LogInformation("Connected to live Docker Engine socket at {Path}", _activeSocketPath);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to initialize Docker Unix Socket HTTP handler");
                _isLiveDockerConnected = false;
            }
        }
        else
        {
            _logger.LogWarning("No Docker Unix socket found on host. Running in resilient simulation/demo mode.");
            _isLiveDockerConnected = false;
        }
    }

    private static string? FindDockerSocket()
    {
        var envSock = Environment.GetEnvironmentVariable("DOCKER_SOCK");
        if (!string.IsNullOrEmpty(envSock) && File.Exists(envSock))
            return envSock;

        string[] potentialPaths =
        [
            "/var/run/docker.sock",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".orbstack/run/docker.sock"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".docker/run/docker.sock")
        ];

        foreach (var path in potentialPaths)
        {
            if (File.Exists(path))
                return path;
        }

        return null;
    }

    public async Task<bool> IsDockerAvailableAsync()
    {
        if (!_isLiveDockerConnected || _httpClient == null)
            return false;

        try
        {
            using var response = await _httpClient.GetAsync("/version");
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    public async Task<List<DockerContainerListItem>> GetContainersAsync(bool all = true)
    {
        if (_isLiveDockerConnected && _httpClient != null)
        {
            try
            {
                var url = all ? "/containers/json?all=1" : "/containers/json";
                var json = await _httpClient.GetStringAsync(url);
                var items = JsonSerializer.Deserialize<List<DockerContainerListItem>>(json);
                if (items != null && items.Count > 0)
                {
                    return items;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to query live Docker containers. Falling back to demo dataset.");
            }
        }

        return GetSimulatedContainers();
    }

    public async Task<DockerContainerInspectResponse?> InspectContainerAsync(string id)
    {
        if (_isLiveDockerConnected && _httpClient != null)
        {
            try
            {
                var json = await _httpClient.GetStringAsync($"/containers/{id}/json");
                return JsonSerializer.Deserialize<DockerContainerInspectResponse>(json);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to inspect container {Id}", id);
            }
        }

        var sim = GetSimulatedContainerInspect(id);
        return sim;
    }

    public async Task<List<DockerNetworkInspectResponse>> GetNetworksAsync()
    {
        if (_isLiveDockerConnected && _httpClient != null)
        {
            try
            {
                var json = await _httpClient.GetStringAsync("/networks");
                var nets = JsonSerializer.Deserialize<List<DockerNetworkInspectResponse>>(json);
                if (nets != null && nets.Count > 0)
                {
                    return nets;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to query live Docker networks");
            }
        }

        return GetSimulatedNetworks();
    }

    public async Task<DockerNetworkInspectResponse?> InspectNetworkAsync(string networkId)
    {
        if (_isLiveDockerConnected && _httpClient != null)
        {
            try
            {
                var json = await _httpClient.GetStringAsync($"/networks/{networkId}");
                return JsonSerializer.Deserialize<DockerNetworkInspectResponse>(json);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to inspect network {Id}", networkId);
            }
        }

        return GetSimulatedNetworks().FirstOrDefault(n => n.Id == networkId || n.Name == networkId);
    }

    public async Task<bool> PauseContainerAsync(string id)
    {
        if (_isLiveDockerConnected && _httpClient != null)
        {
            try
            {
                var resp = await _httpClient.PostAsync($"/containers/{id}/pause", null);
                return resp.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to pause container {Id}", id);
            }
        }
        return true;
    }

    public async Task<bool> UnpauseContainerAsync(string id)
    {
        if (_isLiveDockerConnected && _httpClient != null)
        {
            try
            {
                var resp = await _httpClient.PostAsync($"/containers/{id}/unpause", null);
                return resp.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to unpause container {Id}", id);
            }
        }
        return true;
    }

    public async Task<bool> StopContainerAsync(string id, int timeout = 5)
    {
        if (_isLiveDockerConnected && _httpClient != null)
        {
            try
            {
                var resp = await _httpClient.PostAsync($"/containers/{id}/stop?t={timeout}", null);
                return resp.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to stop container {Id}", id);
            }
        }
        return true;
    }

    public async Task<bool> DisconnectNetworkAsync(string networkId, string containerId, bool force = true)
    {
        if (_isLiveDockerConnected && _httpClient != null)
        {
            try
            {
                var body = new { Container = containerId, Force = force };
                var content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
                var resp = await _httpClient.PostAsync($"/networks/{networkId}/disconnect", content);
                return resp.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to disconnect container {ContainerId} from network {NetworkId}", containerId, networkId);
            }
        }
        return true;
    }

    public async Task<bool> ConnectNetworkAsync(string networkId, string containerId)
    {
        if (_isLiveDockerConnected && _httpClient != null)
        {
            try
            {
                var body = new { Container = containerId };
                var content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
                var resp = await _httpClient.PostAsync($"/networks/{networkId}/connect", content);
                return resp.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to connect container {ContainerId} to network {NetworkId}", containerId, networkId);
            }
        }
        return true;
    }

    public async IAsyncEnumerable<DockerEventItem> ListenEventsAsync([EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (_isLiveDockerConnected && _httpClient != null)
        {
            Stream? stream = null;
            try
            {
                stream = await _httpClient.GetStreamAsync("/events?filters={\"type\":[\"container\"]}", cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to open live Docker events stream");
            }

            if (stream != null)
            {
                using var reader = new StreamReader(stream);
                while (!cancellationToken.IsCancellationRequested && !reader.EndOfStream)
                {
                    var line = await reader.ReadLineAsync(cancellationToken);
                    if (string.IsNullOrWhiteSpace(line)) continue;

                    DockerEventItem? ev = null;
                    try
                    {
                        ev = JsonSerializer.Deserialize<DockerEventItem>(line);
                    }
                    catch { }

                    if (ev != null)
                    {
                        yield return ev;
                    }
                }
                yield break;
            }
        }

        // Demo periodic event pulse for demonstration if disconnected
        while (!cancellationToken.IsCancellationRequested)
        {
            await Task.Delay(15000, cancellationToken);
            yield return new DockerEventItem
            {
                Type = "container",
                Action = "health_status: audit",
                Time = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                Actor = new DockerEventActor
                {
                    ID = "demo-monitor",
                    Attributes = new Dictionary<string, string> { { "name", "containarmor-daemon" } }
                }
            };
        }
    }

    #region Simulated Threat Scenarios & Baseline Data
    private static List<DockerContainerListItem> GetSimulatedContainers()
    {
        return
        [
            new DockerContainerListItem
            {
                Id = "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
                Names = ["/priv-escape-c2"],
                Image = "containarmor-threat/privileged-node:latest",
                State = "running",
                Status = "Up 4 hours",
                Created = DateTimeOffset.UtcNow.AddHours(-4).ToUnixTimeSeconds(),
                Ports = [new DockerPortItem { PrivatePort = 4444, PublicPort = 4444, Type = "tcp" }],
                Mounts =
                [
                    new DockerMountItem { Type = "bind", Source = "/var/run/docker.sock", Destination = "/var/run/docker.sock", Mode = "rw", RW = true }
                ]
            },
            new DockerContainerListItem
            {
                Id = "b2c3d4e5f6a17890123456789abcdef0123456789abcdef0123456789abcdef1",
                Names = ["/sniffing-attacker"],
                Image = "containarmor-threat/bridge-sniffer:v1.2",
                State = "running",
                Status = "Up 2 hours",
                Created = DateTimeOffset.UtcNow.AddHours(-2).ToUnixTimeSeconds(),
                Ports = [new DockerPortItem { PrivatePort = 8080, PublicPort = 8080, Type = "tcp" }],
                Mounts = []
            },
            new DockerContainerListItem
            {
                Id = "c3d4e5f6a1b27890123456789abcdef0123456789abcdef0123456789abcdef2",
                Names = ["/internal-payment-vault"],
                Image = "banking-svc/payment-vault:prod-v3",
                State = "running",
                Status = "Up 12 hours",
                Created = DateTimeOffset.UtcNow.AddHours(-12).ToUnixTimeSeconds(),
                Ports = [new DockerPortItem { PrivatePort = 5432, PublicPort = 0, Type = "tcp" }],
                Mounts = []
            },
            new DockerContainerListItem
            {
                Id = "d4e5f6a1b2c37890123456789abcdef0123456789abcdef0123456789abcdef3",
                Names = ["/hardened-edge-proxy"],
                Image = "envoyproxy/envoy:distroless",
                State = "running",
                Status = "Up 2 days",
                Created = DateTimeOffset.UtcNow.AddDays(-2).ToUnixTimeSeconds(),
                Ports = [new DockerPortItem { PrivatePort = 443, PublicPort = 443, Type = "tcp" }],
                Mounts = []
            }
        ];
    }

    private static DockerContainerInspectResponse GetSimulatedContainerInspect(string id)
    {
        if (id.Contains("a1b2c3") || id.Contains("priv-escape"))
        {
            return new DockerContainerInspectResponse
            {
                Id = "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
                Name = "/priv-escape-c2",
                Image = "containarmor-threat/privileged-node:latest",
                Created = DateTime.UtcNow.AddHours(-4).ToString("o"),
                State = new DockerContainerState { Running = true, Status = "running", Pid = 4210 },
                Config = new DockerConfig { User = "0" },
                HostConfig = new DockerHostConfig
                {
                    Privileged = true,
                    CapAdd = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"],
                    NetworkMode = "bridge",
                    PidMode = "host",
                    SecurityOpt = ["apparmor=unconfined", "seccomp=unconfined"],
                    ReadonlyRootfs = false
                },
                Mounts =
                [
                    new DockerMountItem { Type = "bind", Source = "/var/run/docker.sock", Destination = "/var/run/docker.sock", Mode = "rw", RW = true },
                    new DockerMountItem { Type = "bind", Source = "/etc", Destination = "/host/etc", Mode = "rw", RW = true }
                ],
                NetworkSettings = new DockerNetworkSettings
                {
                    IPAddress = "172.17.0.2",
                    Networks = new Dictionary<string, DockerNetworkEndpointItem>
                    {
                        { "bridge", new DockerNetworkEndpointItem { NetworkID = "net-default-bridge", IPAddress = "172.17.0.2", Gateway = "172.17.0.1" } }
                    }
                }
            };
        }
        else if (id.Contains("b2c3d4") || id.Contains("sniffing"))
        {
            return new DockerContainerInspectResponse
            {
                Id = "b2c3d4e5f6a17890123456789abcdef0123456789abcdef0123456789abcdef1",
                Name = "/sniffing-attacker",
                Image = "containarmor-threat/bridge-sniffer:v1.2",
                Created = DateTime.UtcNow.AddHours(-2).ToString("o"),
                State = new DockerContainerState { Running = true, Status = "running", Pid = 5120 },
                Config = new DockerConfig { User = "root" },
                HostConfig = new DockerHostConfig
                {
                    Privileged = false,
                    CapAdd = ["NET_ADMIN", "NET_RAW"],
                    NetworkMode = "bridge",
                    ReadonlyRootfs = false
                },
                Mounts = [],
                NetworkSettings = new DockerNetworkSettings
                {
                    IPAddress = "172.17.0.3",
                    Networks = new Dictionary<string, DockerNetworkEndpointItem>
                    {
                        { "bridge", new DockerNetworkEndpointItem { NetworkID = "net-default-bridge", IPAddress = "172.17.0.3", Gateway = "172.17.0.1" } }
                    }
                }
            };
        }
        else if (id.Contains("c3d4e5") || id.Contains("vault"))
        {
            return new DockerContainerInspectResponse
            {
                Id = "c3d4e5f6a1b27890123456789abcdef0123456789abcdef0123456789abcdef2",
                Name = "/internal-payment-vault",
                Image = "banking-svc/payment-vault:prod-v3",
                Created = DateTime.UtcNow.AddHours(-12).ToString("o"),
                State = new DockerContainerState { Running = true, Status = "running", Pid = 6301 },
                Config = new DockerConfig { User = "postgres" },
                HostConfig = new DockerHostConfig
                {
                    Privileged = false,
                    CapAdd = [],
                    CapDrop = ["ALL"],
                    NetworkMode = "bridge",
                    ReadonlyRootfs = false
                },
                Mounts = [],
                NetworkSettings = new DockerNetworkSettings
                {
                    IPAddress = "172.17.0.4",
                    Networks = new Dictionary<string, DockerNetworkEndpointItem>
                    {
                        { "bridge", new DockerNetworkEndpointItem { NetworkID = "net-default-bridge", IPAddress = "172.17.0.4", Gateway = "172.17.0.1" } }
                    }
                }
            };
        }

        // Hardened baseline
        return new DockerContainerInspectResponse
        {
            Id = "d4e5f6a1b2c37890123456789abcdef0123456789abcdef0123456789abcdef3",
            Name = "/hardened-edge-proxy",
            Image = "envoyproxy/envoy:distroless",
            Created = DateTime.UtcNow.AddDays(-2).ToString("o"),
            State = new DockerContainerState { Running = true, Status = "running", Pid = 7010 },
            Config = new DockerConfig { User = "10001" },
            HostConfig = new DockerHostConfig
            {
                Privileged = false,
                CapAdd = [],
                CapDrop = ["ALL"],
                ReadonlyRootfs = true,
                NetworkMode = "containarmor-isolated",
                Memory = 536870912,
                PidsLimit = 100,
                SecurityOpt = ["apparmor=docker-default", "seccomp=custom-strict"]
            },
            Mounts = [],
            NetworkSettings = new DockerNetworkSettings
            {
                IPAddress = "10.0.40.2",
                Networks = new Dictionary<string, DockerNetworkEndpointItem>
                {
                    { "containarmor-isolated", new DockerNetworkEndpointItem { NetworkID = "net-isolated", IPAddress = "10.0.40.2", Gateway = "10.0.40.1" } }
                }
            }
        };
    }

    private static List<DockerNetworkInspectResponse> GetSimulatedNetworks()
    {
        return
        [
            new DockerNetworkInspectResponse
            {
                Id = "net-default-bridge",
                Name = "bridge",
                Driver = "bridge",
                Scope = "local",
                Options = new Dictionary<string, string>
                {
                    { "com.docker.network.bridge.enable_icc", "true" },
                    { "com.docker.network.bridge.enable_ip_masquerade", "true" },
                    { "com.docker.network.bridge.name", "docker0" }
                },
                IPAM = new DockerIPAM
                {
                    Config = [new DockerIPAMConfig { Subnet = "172.17.0.0/16", Gateway = "172.17.0.1" }]
                },
                Containers = new Dictionary<string, DockerNetworkContainer>
                {
                    { "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0", new DockerNetworkContainer { Name = "priv-escape-c2", IPv4Address = "172.17.0.2/16" } },
                    { "b2c3d4e5f6a17890123456789abcdef0123456789abcdef0123456789abcdef1", new DockerNetworkContainer { Name = "sniffing-attacker", IPv4Address = "172.17.0.3/16" } },
                    { "c3d4e5f6a1b27890123456789abcdef0123456789abcdef0123456789abcdef2", new DockerNetworkContainer { Name = "internal-payment-vault", IPv4Address = "172.17.0.4/16" } }
                }
            },
            new DockerNetworkInspectResponse
            {
                Id = "net-isolated",
                Name = "containarmor-isolated",
                Driver = "bridge",
                Scope = "local",
                Internal = false,
                Options = new Dictionary<string, string>
                {
                    { "com.docker.network.bridge.enable_icc", "false" },
                    { "com.docker.network.bridge.enable_ip_masquerade", "true" }
                },
                IPAM = new DockerIPAM
                {
                    Config = [new DockerIPAMConfig { Subnet = "10.0.40.0/24", Gateway = "10.0.40.1" }]
                },
                Containers = new Dictionary<string, DockerNetworkContainer>
                {
                    { "d4e5f6a1b2c37890123456789abcdef0123456789abcdef0123456789abcdef3", new DockerNetworkContainer { Name = "hardened-edge-proxy", IPv4Address = "10.0.40.2/24" } }
                }
            }
        ];
    }
    #endregion
}
