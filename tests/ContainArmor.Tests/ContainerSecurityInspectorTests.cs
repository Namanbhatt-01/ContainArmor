using ContainArmor.Engine.Models;
using ContainArmor.Engine.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace ContainArmor.Tests;

public class ContainerSecurityInspectorTests
{
    private readonly ContainerSecurityInspector _inspector;

    public ContainerSecurityInspectorTests()
    {
        _inspector = new ContainerSecurityInspector(NullLogger<ContainerSecurityInspector>.Instance);
    }

    [Fact]
    public void AuditContainer_PrivilegedFlag_ScoresHighRiskAndCriticalSeverity()
    {
        // Arrange
        var raw = new DockerContainerInspectResponse
        {
            Id = "test-priv-1234567890",
            Name = "/priv-test",
            Image = "alpine:latest",
            State = new DockerContainerState { Running = true, Status = "running" },
            HostConfig = new DockerHostConfig
            {
                Privileged = true
            }
        };

        // Act
        var profile = _inspector.AuditContainer(raw, []);

        // Assert
        Assert.True(profile.Privileged);
        Assert.True(profile.RiskScore >= 45);
        Assert.True(profile.RiskLevel >= SeverityLevel.High);
        Assert.Contains(profile.Findings, f => f.RuleId == "CIS-5.1" && f.Severity == SeverityLevel.Critical);
        Assert.Contains(profile.EscapeVectors, v => v.Contains("Kernel device injection"));
    }

    [Fact]
    public void AuditContainer_MountedDockerSocket_FlagsCriticalFinding()
    {
        // Arrange
        var raw = new DockerContainerInspectResponse
        {
            Id = "test-sock-1234567890",
            Name = "/sock-hijacker",
            Image = "docker:dind",
            State = new DockerContainerState { Running = true, Status = "running" },
            Mounts =
            [
                new DockerMountItem
                {
                    Type = "bind",
                    Source = "/var/run/docker.sock",
                    Destination = "/var/run/docker.sock",
                    RW = true
                }
            ]
        };

        // Act
        var profile = _inspector.AuditContainer(raw, []);

        // Assert
        Assert.True(profile.HasDockerSocketMounted);
        Assert.True(profile.RiskScore >= 40);
        Assert.Contains(profile.Findings, f => f.RuleId == "CIS-5.31" && f.Severity == SeverityLevel.Critical);
        Assert.Contains(profile.EscapeVectors, v => v.Contains("Docker socket hijacking"));
    }

    [Fact]
    public void AuditContainer_DangerousCapabilities_FlagsSysAdminAndNetAdmin()
    {
        // Arrange
        var raw = new DockerContainerInspectResponse
        {
            Id = "test-caps-1234567890",
            Name = "/cap-abuser",
            Image = "ubuntu:24.04",
            HostConfig = new DockerHostConfig
            {
                CapAdd = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"]
            }
        };

        // Act
        var profile = _inspector.AuditContainer(raw, []);

        // Assert
        Assert.Contains("SYS_ADMIN", profile.EffectiveDangerousCapabilities);
        Assert.Contains("NET_ADMIN", profile.EffectiveDangerousCapabilities);
        Assert.Contains("SYS_PTRACE", profile.EffectiveDangerousCapabilities);
        Assert.Contains(profile.Findings, f => f.RuleId == "CIS-5.2-SYSADMIN");
        Assert.Contains(profile.Findings, f => f.RuleId == "CIS-5.2-NETADMIN");
        Assert.Equal(SeverityLevel.Critical, profile.RiskLevel);
    }

    [Fact]
    public void AuditContainer_HostNamespaceSharing_FlagsPidAndNetworkModes()
    {
        // Arrange
        var raw = new DockerContainerInspectResponse
        {
            Id = "test-ns-1234567890",
            Name = "/ns-snooper",
            Image = "alpine:latest",
            HostConfig = new DockerHostConfig
            {
                PidMode = "host",
                NetworkMode = "host",
                IpcMode = "host"
            }
        };

        // Act
        var profile = _inspector.AuditContainer(raw, []);

        // Assert
        Assert.True(profile.SharesHostPid);
        Assert.True(profile.SharesHostNetwork);
        Assert.True(profile.SharesHostIpc);
        Assert.Contains(profile.Findings, f => f.RuleId == "CIS-5.6");
        Assert.Contains(profile.Findings, f => f.RuleId == "CIS-5.5");
        Assert.Contains(profile.Findings, f => f.RuleId == "CIS-5.7");
    }

    [Fact]
    public void AuditContainer_HardenedBaseline_ScoresLowRisk()
    {
        // Arrange
        var raw = new DockerContainerInspectResponse
        {
            Id = "test-hardened-1234567890",
            Name = "/hardened-pod",
            Image = "distroless:latest",
            Config = new DockerConfig { User = "10001" },
            HostConfig = new DockerHostConfig
            {
                Privileged = false,
                CapDrop = ["ALL"],
                ReadonlyRootfs = true
            }
        };

        // Act
        var profile = _inspector.AuditContainer(raw, []);

        // Assert
        Assert.False(profile.Privileged);
        Assert.True(profile.ReadonlyRootfs);
        Assert.False(profile.RunsAsRoot);
        Assert.Empty(profile.EffectiveDangerousCapabilities);
        Assert.Empty(profile.EscapeVectors);
        Assert.True(profile.RiskScore <= 20);
        Assert.True(profile.RiskLevel <= SeverityLevel.Low);
    }

    [Fact]
    public void AuditContainer_SensitiveProcAndSysMounts_DetectsFilesystemIntegrityRisks()
    {
        // Arrange
        var raw = new DockerContainerInspectResponse
        {
            Id = "test-proc-mount",
            Name = "/proc-mounter",
            Image = "alpine:latest",
            Mounts =
            [
                new DockerMountItem { Source = "/proc", Destination = "/host/proc", RW = true },
                new DockerMountItem { Source = "/sys", Destination = "/host/sys", RW = true },
                new DockerMountItem { Source = "/etc", Destination = "/host/etc", RW = false }
            ]
        };

        // Act
        var profile = _inspector.AuditContainer(raw, []);

        // Assert
        Assert.True(profile.HasProcMounted);
        Assert.True(profile.HasSysMounted);
        Assert.True(profile.HasRootMounted);
        Assert.Contains(profile.Findings, f => f.RuleId == "CIS-5.3-PROC");
        Assert.Contains(profile.EscapeVectors, v => v.Contains("core_pattern"));
    }

    [Theory]
    [InlineData("", true)]
    [InlineData("root", true)]
    [InlineData("0", true)]
    [InlineData("0:0", true)]
    [InlineData("1000", false)]
    [InlineData("appuser", false)]
    [InlineData("10001:10001", false)]
    public void AuditContainer_UserSpecification_CorrectlyFlagsRootUser(string configuredUser, bool shouldFlagRoot)
    {
        // Arrange
        var raw = new DockerContainerInspectResponse
        {
            Id = "test-user-eval",
            Name = "/user-test",
            Image = "app:latest",
            Config = new DockerConfig { User = configuredUser },
            HostConfig = new DockerHostConfig { ReadonlyRootfs = true }
        };

        // Act
        var profile = _inspector.AuditContainer(raw, []);

        // Assert
        Assert.Equal(shouldFlagRoot, profile.RunsAsRoot);
        if (shouldFlagRoot)
        {
            Assert.Contains(profile.Findings, f => f.RuleId == "CIS-5.4-USER");
        }
        else
        {
            Assert.DoesNotContain(profile.Findings, f => f.RuleId == "CIS-5.4-USER");
        }
    }

    [Fact]
    public void AuditContainer_AppArmorAndSeccompSecurityOpts_ParsedAccurately()
    {
        // Arrange
        var raw = new DockerContainerInspectResponse
        {
            Id = "test-secopts",
            Name = "/profiled-pod",
            Image = "nginx:alpine",
            HostConfig = new DockerHostConfig
            {
                SecurityOpt =
                [
                    "apparmor=docker-default",
                    "seccomp=/etc/docker/custom-seccomp.json"
                ]
            }
        };

        // Act
        var profile = _inspector.AuditContainer(raw, []);

        // Assert
        Assert.Equal("docker-default", profile.AppArmorProfile);
        Assert.Equal("/etc/docker/custom-seccomp.json", profile.SeccompProfile);
    }

    [Fact]
    public void AuditContainer_NullAndEmptyPayloads_HandledGracefullyWithoutExceptions()
    {
        // Arrange
        var raw = new DockerContainerInspectResponse
        {
            Id = "bare-minimum",
            Name = "/bare",
            Image = "scratch",
            HostConfig = null,
            Config = null,
            State = null,
            Mounts = null,
            NetworkSettings = null
        };

        // Act
        var profile = _inspector.AuditContainer(raw, []);

        // Assert
        Assert.NotNull(profile);
        Assert.Equal("unknown", profile.State);
        Assert.Equal(ContainerSecurityState.Exited, profile.SecurityState);
        Assert.False(profile.Privileged);
        Assert.Empty(profile.Mounts);
        Assert.Empty(profile.Networks);
        Assert.True(profile.RiskScore >= 0 && profile.RiskScore <= 100);
    }
}
