using System.Text.Json.Serialization;

namespace ContainArmor.Engine.Models;

public class DockerContainerListItem
{
    [JsonPropertyName("Id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("Names")]
    public List<string> Names { get; set; } = [];

    [JsonPropertyName("Image")]
    public string Image { get; set; } = string.Empty;

    [JsonPropertyName("State")]
    public string State { get; set; } = string.Empty;

    [JsonPropertyName("Status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("Created")]
    public long Created { get; set; }

    [JsonPropertyName("Ports")]
    public List<DockerPortItem> Ports { get; set; } = [];

    [JsonPropertyName("NetworkSettings")]
    public DockerListNetworkSettings? NetworkSettings { get; set; }

    [JsonPropertyName("Mounts")]
    public List<DockerMountItem> Mounts { get; set; } = [];
}

public class DockerPortItem
{
    [JsonPropertyName("PrivatePort")]
    public int PrivatePort { get; set; }

    [JsonPropertyName("PublicPort")]
    public int PublicPort { get; set; }

    [JsonPropertyName("Type")]
    public string Type { get; set; } = "tcp";

    [JsonPropertyName("IP")]
    public string? IP { get; set; }
}

public class DockerListNetworkSettings
{
    [JsonPropertyName("Networks")]
    public Dictionary<string, DockerNetworkEndpointItem> Networks { get; set; } = [];
}

public class DockerNetworkEndpointItem
{
    [JsonPropertyName("NetworkID")]
    public string NetworkID { get; set; } = string.Empty;

    [JsonPropertyName("EndpointID")]
    public string EndpointID { get; set; } = string.Empty;

    [JsonPropertyName("Gateway")]
    public string Gateway { get; set; } = string.Empty;

    [JsonPropertyName("IPAddress")]
    public string IPAddress { get; set; } = string.Empty;

    [JsonPropertyName("MacAddress")]
    public string MacAddress { get; set; } = string.Empty;
}

public class DockerMountItem
{
    [JsonPropertyName("Type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("Source")]
    public string Source { get; set; } = string.Empty;

    [JsonPropertyName("Destination")]
    public string Destination { get; set; } = string.Empty;

    [JsonPropertyName("Mode")]
    public string Mode { get; set; } = string.Empty;

    [JsonPropertyName("RW")]
    public bool RW { get; set; }
}

public class DockerContainerInspectResponse
{
    [JsonPropertyName("Id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("Created")]
    public string Created { get; set; } = string.Empty;

    [JsonPropertyName("Name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("State")]
    public DockerContainerState? State { get; set; }

    [JsonPropertyName("Image")]
    public string Image { get; set; } = string.Empty;

    [JsonPropertyName("Config")]
    public DockerConfig? Config { get; set; }

    [JsonPropertyName("HostConfig")]
    public DockerHostConfig? HostConfig { get; set; }

    [JsonPropertyName("Mounts")]
    public List<DockerMountItem> Mounts { get; set; } = [];

    [JsonPropertyName("NetworkSettings")]
    public DockerNetworkSettings? NetworkSettings { get; set; }
}

public class DockerContainerState
{
    [JsonPropertyName("Status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("Running")]
    public bool Running { get; set; }

    [JsonPropertyName("Paused")]
    public bool Paused { get; set; }

    [JsonPropertyName("Pid")]
    public int Pid { get; set; }
}

public class DockerConfig
{
    [JsonPropertyName("User")]
    public string User { get; set; } = string.Empty;

    [JsonPropertyName("Image")]
    public string Image { get; set; } = string.Empty;

    [JsonPropertyName("Env")]
    public List<string> Env { get; set; } = [];
}

public class DockerHostConfig
{
    [JsonPropertyName("Privileged")]
    public bool Privileged { get; set; }

    [JsonPropertyName("CapAdd")]
    public List<string>? CapAdd { get; set; }

    [JsonPropertyName("CapDrop")]
    public List<string>? CapDrop { get; set; }

    [JsonPropertyName("ReadonlyRootfs")]
    public bool ReadonlyRootfs { get; set; }

    [JsonPropertyName("NetworkMode")]
    public string NetworkMode { get; set; } = string.Empty;

    [JsonPropertyName("IpcMode")]
    public string IpcMode { get; set; } = string.Empty;

    [JsonPropertyName("PidMode")]
    public string PidMode { get; set; } = string.Empty;

    [JsonPropertyName("UTSMode")]
    public string UTSMode { get; set; } = string.Empty;

    [JsonPropertyName("SecurityOpt")]
    public List<string>? SecurityOpt { get; set; }

    [JsonPropertyName("Memory")]
    public long Memory { get; set; }

    [JsonPropertyName("PidsLimit")]
    public long? PidsLimit { get; set; }

    [JsonPropertyName("CpuShares")]
    public int CpuShares { get; set; }
}

public class DockerNetworkSettings
{
    [JsonPropertyName("IPAddress")]
    public string IPAddress { get; set; } = string.Empty;

    [JsonPropertyName("Networks")]
    public Dictionary<string, DockerNetworkEndpointItem> Networks { get; set; } = [];
}

public class DockerNetworkInspectResponse
{
    [JsonPropertyName("Id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("Name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("Driver")]
    public string Driver { get; set; } = "bridge";

    [JsonPropertyName("Scope")]
    public string Scope { get; set; } = "local";

    [JsonPropertyName("EnableIPv6")]
    public bool EnableIPv6 { get; set; }

    [JsonPropertyName("Internal")]
    public bool Internal { get; set; }

    [JsonPropertyName("Attachable")]
    public bool Attachable { get; set; }

    [JsonPropertyName("Options")]
    public Dictionary<string, string>? Options { get; set; }

    [JsonPropertyName("IPAM")]
    public DockerIPAM? IPAM { get; set; }

    [JsonPropertyName("Containers")]
    public Dictionary<string, DockerNetworkContainer>? Containers { get; set; }
}

public class DockerIPAM
{
    [JsonPropertyName("Config")]
    public List<DockerIPAMConfig>? Config { get; set; }
}

public class DockerIPAMConfig
{
    [JsonPropertyName("Subnet")]
    public string Subnet { get; set; } = string.Empty;

    [JsonPropertyName("Gateway")]
    public string Gateway { get; set; } = string.Empty;
}

public class DockerNetworkContainer
{
    [JsonPropertyName("Name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("IPv4Address")]
    public string IPv4Address { get; set; } = string.Empty;

    [JsonPropertyName("MacAddress")]
    public string MacAddress { get; set; } = string.Empty;
}

public class DockerEventItem
{
    [JsonPropertyName("Type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("Action")]
    public string Action { get; set; } = string.Empty;

    [JsonPropertyName("Actor")]
    public DockerEventActor? Actor { get; set; }

    [JsonPropertyName("time")]
    public long Time { get; set; }
}

public class DockerEventActor
{
    [JsonPropertyName("ID")]
    public string ID { get; set; } = string.Empty;

    [JsonPropertyName("Attributes")]
    public Dictionary<string, string> Attributes { get; set; } = [];
}
