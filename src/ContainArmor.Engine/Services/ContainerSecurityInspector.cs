using ContainArmor.Engine.Models;
using Microsoft.Extensions.Logging;

namespace ContainArmor.Engine.Services;

public class ContainerSecurityInspector
{
    private readonly ILogger<ContainerSecurityInspector> _logger;

    public ContainerSecurityInspector(ILogger<ContainerSecurityInspector> logger)
    {
        _logger = logger;
    }

    public ContainerSecurityProfile AuditContainer(DockerContainerInspectResponse raw, List<DockerNetworkInspectResponse> networks)
    {
        var profile = new ContainerSecurityProfile
        {
            Id = raw.Id,
            Name = raw.Name,
            Image = raw.Image,
            State = raw.State?.Status ?? "unknown",
            CreatedAt = DateTime.TryParse(raw.Created, out var dt) ? dt : DateTime.UtcNow
        };

        if (raw.State?.Paused == true) profile.SecurityState = ContainerSecurityState.Paused;
        else if (raw.State?.Running == true) profile.SecurityState = ContainerSecurityState.Running;
        else profile.SecurityState = ContainerSecurityState.Exited;

        var hostConfig = raw.HostConfig ?? new DockerHostConfig();
        var config = raw.Config ?? new DockerConfig();

        profile.Privileged = hostConfig.Privileged;
        profile.CapAdd = hostConfig.CapAdd ?? [];
        profile.CapDrop = hostConfig.CapDrop ?? [];
        profile.ReadonlyRootfs = hostConfig.ReadonlyRootfs;
        profile.PidMode = hostConfig.PidMode ?? string.Empty;
        profile.IpcMode = hostConfig.IpcMode ?? string.Empty;
        profile.NetworkMode = hostConfig.NetworkMode ?? string.Empty;
        profile.UtsMode = hostConfig.UTSMode ?? string.Empty;
        profile.User = config.User ?? string.Empty;
        profile.MemoryLimitBytes = hostConfig.Memory;
        profile.PidsLimit = hostConfig.PidsLimit ?? 0;
        profile.CpuShares = hostConfig.CpuShares;

        // Security Options
        if (hostConfig.SecurityOpt != null)
        {
            foreach (var opt in hostConfig.SecurityOpt)
            {
                if (opt.StartsWith("apparmor=", StringComparison.OrdinalIgnoreCase))
                    profile.AppArmorProfile = opt.Split('=')[1];
                if (opt.StartsWith("seccomp=", StringComparison.OrdinalIgnoreCase))
                    profile.SeccompProfile = opt.Split('=')[1];
            }
        }

        // Mounts audit
        var mounts = raw.Mounts ?? [];
        foreach (var m in mounts)
        {
            var mountInfo = new ContainerMountInfo
            {
                Source = m.Source,
                Destination = m.Destination,
                Mode = m.Mode,
                RW = m.RW,
                Type = m.Type
            };

            if (m.Source.Contains("docker.sock") || m.Destination.Contains("docker.sock"))
            {
                mountInfo.IsSensitive = true;
                mountInfo.RiskExplanation = "Direct access to Docker daemon Unix Socket grants root control over host system.";
                profile.HasDockerSocketMounted = true;
            }
            else if (m.Source == "/proc" || m.Destination == "/proc" || m.Source.StartsWith("/proc/"))
            {
                mountInfo.IsSensitive = true;
                mountInfo.RiskExplanation = "Mounted /proc filesystem allows container to leak host kernel telemetry or trigger sysrq/core_pattern escapes.";
                profile.HasProcMounted = true;
            }
            else if (m.Source == "/sys" || m.Destination == "/sys" || m.Source.StartsWith("/sys/"))
            {
                mountInfo.IsSensitive = true;
                mountInfo.RiskExplanation = "Mounted /sys filesystem exposes host cgroup and device configurations to tampering.";
                profile.HasSysMounted = true;
            }
            else if (m.Source == "/" || m.Source == "/root" || m.Source == "/etc")
            {
                mountInfo.IsSensitive = true;
                mountInfo.RiskExplanation = $"Direct bind mount of sensitive host filesystem path '{m.Source}'.";
                profile.HasRootMounted = true;
            }

            profile.Mounts.Add(mountInfo);
        }

        // Networks
        if (raw.NetworkSettings?.Networks != null)
        {
            foreach (var kvp in raw.NetworkSettings.Networks)
            {
                var net = networks.FirstOrDefault(n => n.Name == kvp.Key || n.Id == kvp.Value.NetworkID);
                var icc = true;
                if (net?.Options != null && net.Options.TryGetValue("com.docker.network.bridge.enable_icc", out var iccVal))
                {
                    icc = !string.Equals(iccVal, "false", StringComparison.OrdinalIgnoreCase);
                }

                profile.Networks.Add(new ContainerNetworkEndpoint
                {
                    NetworkName = kvp.Key,
                    NetworkId = kvp.Value.NetworkID,
                    IPAddress = kvp.Value.IPAddress,
                    Gateway = kvp.Value.Gateway,
                    MacAddress = kvp.Value.MacAddress,
                    InterContainerCommEnabled = icc
                });
            }
        }

        // Run CIS Docker Benchmark checks & Calculate Risk
        EvaluateFindingsAndScore(profile);

        return profile;
    }

    private static void EvaluateFindingsAndScore(ContainerSecurityProfile p)
    {
        int score = 0;
        var findings = new List<SecurityFinding>();
        var escapeVectors = new List<string>();
        var recommendations = new List<string>();

        // 1. Privileged Container Check (CIS 5.1)
        if (p.Privileged)
        {
            score += 45;
            findings.Add(new SecurityFinding
            {
                RuleId = "CIS-5.1",
                Title = "Privileged Mode Enabled (--privileged)",
                Severity = SeverityLevel.Critical,
                Category = RiskCategory.PrivilegeEscalation,
                Description = "Container runs with full root capabilities and unrestricted device access, effectively defeating container isolation boundaries.",
                Impact = "Attacker can mount host block devices, access /dev/kmem, load kernel modules, or escape to host root within seconds.",
                Remediation = "Remove the '--privileged' flag. Run with specific, granular capabilities if hardware access is strictly required.",
                CisBenchmark = "CIS Docker Benchmark v1.6.0 - 5.1"
            });
            escapeVectors.Add("Kernel device injection via cgroups & mknod (host takeover)");
            recommendations.Add("Disable '--privileged' flag immediately.");
        }

        // 2. Mounted Docker Socket (CIS 5.31)
        if (p.HasDockerSocketMounted)
        {
            score += 40;
            findings.Add(new SecurityFinding
            {
                RuleId = "CIS-5.31",
                Title = "Docker Engine Socket Mounted (/var/run/docker.sock)",
                Severity = SeverityLevel.Critical,
                Category = RiskCategory.SocketLeak,
                Description = "Container has read/write access to the host's Docker daemon UNIX socket.",
                Impact = "Any process inside this container can issue Docker API commands to spawn a new privileged container mounting the host root filesystem ('docker run -v /:/host').",
                Remediation = "Do not mount /var/run/docker.sock into application containers. Use rootless Docker or an authenticated proxy daemon with strict path filtering.",
                CisBenchmark = "CIS Docker Benchmark v1.6.0 - 5.31"
            });
            escapeVectors.Add("Docker socket hijacking (instant host root execution)");
            recommendations.Add("Unbind /var/run/docker.sock mount from container specification.");
        }

        // 3. Dangerous Linux Capabilities (CIS 5.2)
        var dangerousCaps = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "DAC_OVERRIDE", "SYS_RAWIO", "SYS_MODULE", "NET_RAW"
        };

        foreach (var cap in p.CapAdd)
        {
            var normalizedCap = cap.Replace("CAP_", "", StringComparison.OrdinalIgnoreCase).ToUpperInvariant();
            if (dangerousCaps.Contains(normalizedCap))
            {
                p.EffectiveDangerousCapabilities.Add(normalizedCap);

                if (normalizedCap == "SYS_ADMIN")
                {
                    score += 35;
                    findings.Add(new SecurityFinding
                    {
                        RuleId = "CIS-5.2-SYSADMIN",
                        Title = "CAP_SYS_ADMIN Capability Added",
                        Severity = SeverityLevel.Critical,
                        Category = RiskCategory.CapabilityAbuse,
                        Description = "CAP_SYS_ADMIN grants extensive administrative capabilities (mount, swapon, sethostname, eBPF, perf).",
                        Impact = "Equivalent to near-root capabilities; enables filesystem remounts, release_agent breakout, and cgroup manipulation.",
                        Remediation = "Remove CAP_SYS_ADMIN (--cap-drop=SYS_ADMIN).",
                        CisBenchmark = "CIS Docker Benchmark v1.6.0 - 5.2"
                    });
                    escapeVectors.Add("cgroup release_agent execution escape via CAP_SYS_ADMIN");
                }
                else if (normalizedCap == "NET_ADMIN")
                {
                    score += 25;
                    findings.Add(new SecurityFinding
                    {
                        RuleId = "CIS-5.2-NETADMIN",
                        Title = "CAP_NET_ADMIN Capability Added (Bridge Sniffing Vector)",
                        Severity = SeverityLevel.High,
                        Category = RiskCategory.NetworkExposure,
                        Description = "Allows container to configure network interfaces, modify routing tables, inspect packet queues, and alter iptables.",
                        Impact = "Can perform ARP poisoning, DNS spoofing, and packet sniffing on the shared Docker bridge network.",
                        Remediation = "Drop CAP_NET_ADMIN. Use dedicated network sidecars if traffic proxying is required.",
                        CisBenchmark = "CIS Docker Benchmark v1.6.0 - 5.2"
                    });
                    escapeVectors.Add("Intra-bridge ARP poisoning and packet eavesdropping (CAP_NET_ADMIN)");
                }
                else if (normalizedCap == "SYS_PTRACE")
                {
                    score += 20;
                    findings.Add(new SecurityFinding
                    {
                        RuleId = "CIS-5.2-PTRACE",
                        Title = "CAP_SYS_PTRACE Capability Added",
                        Severity = SeverityLevel.High,
                        Category = RiskCategory.PrivilegeEscalation,
                        Description = "Allows container processes to trace and inspect other processes using ptrace().",
                        Impact = "Enables memory dumping, injection into co-located container processes, and credential extraction.",
                        Remediation = "Drop CAP_SYS_PTRACE (--cap-drop=SYS_PTRACE).",
                        CisBenchmark = "CIS Docker Benchmark v1.6.0 - 5.2"
                    });
                    escapeVectors.Add("Process memory inspection and injection via ptrace");
                }
            }
        }

        // 4. Host Namespace Sharing (CIS 5.5, 5.6, 5.7)
        if (p.SharesHostPid)
        {
            score += 30;
            findings.Add(new SecurityFinding
            {
                RuleId = "CIS-5.6",
                Title = "Host PID Namespace Shared (--pid=host)",
                Severity = SeverityLevel.High,
                Category = RiskCategory.NamespaceSharing,
                Description = "Container shares the process namespace with the host machine.",
                Impact = "Container can see and send signals to any host process, inspect /proc/<pid>/environ for secrets, and kill host daemons.",
                Remediation = "Remove '--pid=host'. Maintain separate PID namespace.",
                CisBenchmark = "CIS Docker Benchmark v1.6.0 - 5.6"
            });
            escapeVectors.Add("Host process environment secret snooping (/proc/$PID/environ)");
        }

        if (p.SharesHostNetwork)
        {
            score += 25;
            findings.Add(new SecurityFinding
            {
                RuleId = "CIS-5.5",
                Title = "Host Network Namespace Shared (--net=host)",
                Severity = SeverityLevel.High,
                Category = RiskCategory.NamespaceSharing,
                Description = "Container attaches directly to the host's network interfaces, bypassing Docker bridge isolation entirely.",
                Impact = "Container can listen on any host port, sniff loopback traffic (127.0.0.1 services), and alter host routing tables.",
                Remediation = "Use a user-defined bridge network instead of '--net=host'.",
                CisBenchmark = "CIS Docker Benchmark v1.6.0 - 5.5"
            });
        }

        if (p.SharesHostIpc)
        {
            score += 20;
            findings.Add(new SecurityFinding
            {
                RuleId = "CIS-5.7",
                Title = "Host IPC Namespace Shared (--ipc=host)",
                Severity = SeverityLevel.Medium,
                Category = RiskCategory.NamespaceSharing,
                Description = "Container shares inter-process communication mechanisms (shared memory, semaphores) with the host.",
                Impact = "Processes in container can inspect or corrupt shared memory segments of host applications.",
                Remediation = "Remove '--ipc=host'.",
                CisBenchmark = "CIS Docker Benchmark v1.6.0 - 5.7"
            });
        }

        // 5. Sensitive Mounts
        if (p.HasProcMounted)
        {
            score += 25;
            findings.Add(new SecurityFinding
            {
                RuleId = "CIS-5.3-PROC",
                Title = "Host /proc Filesystem Mounted",
                Severity = SeverityLevel.High,
                Category = RiskCategory.FilesystemIntegrity,
                Description = "Host /proc filesystem is mounted inside container.",
                Impact = "Allows container to modify host kernel variables (e.g., /proc/sys/kernel/core_pattern) to execute arbitrary commands.",
                Remediation = "Never mount host /proc into containers.",
                CisBenchmark = "CIS Docker Benchmark v1.6.0 - 5.3"
            });
            escapeVectors.Add("Kernel core_pattern overwrite escape (/proc/sys/kernel/core_pattern)");
        }

        // 6. Root User Check (CIS 5.4)
        if (p.RunsAsRoot)
        {
            score += 15;
            findings.Add(new SecurityFinding
            {
                RuleId = "CIS-5.4-USER",
                Title = "Container Process Runs as Root (UID 0)",
                Severity = SeverityLevel.Medium,
                Category = RiskCategory.PrivilegeEscalation,
                Description = "No non-root user specified. Container defaults to running as root user inside the container namespace.",
                Impact = "If a container breakout occurs, attacker immediately assumes root privileges on the underlying host.",
                Remediation = "Specify a non-root user in Dockerfile ('USER nonroot') or at runtime ('--user 10001:10001').",
                CisBenchmark = "CIS Docker Benchmark v1.6.0 - 5.4"
            });
            recommendations.Add("Set unprivileged UID/GID with '--user 10001:10001'.");
        }

        // 7. Readonly Rootfs (CIS 5.12)
        if (!p.ReadonlyRootfs)
        {
            score += 10;
            findings.Add(new SecurityFinding
            {
                RuleId = "CIS-5.12",
                Title = "Root Filesystem is Writable",
                Severity = SeverityLevel.Low,
                Category = RiskCategory.FilesystemIntegrity,
                Description = "Container root filesystem is mounted with read-write permissions.",
                Impact = "Attackers can persist web shells, download malicious binaries, or tamper with system binaries inside the container.",
                Remediation = "Run container with '--read-only' and mount explicit tmpfs for writable paths (/tmp, /run).",
                CisBenchmark = "CIS Docker Benchmark v1.6.0 - 5.12"
            });
            recommendations.Add("Enable '--read-only' rootfs with tmpfs mounts.");
        }

        // 8. Shared Bridge without ICC Restriction (Key Feature)
        foreach (var net in p.Networks)
        {
            if (net.InterContainerCommEnabled && net.NetworkName == "bridge")
            {
                score += 15;
                findings.Add(new SecurityFinding
                {
                    RuleId = "NET-ICC-DEFAULT",
                    Title = "Default Bridge with Unrestricted Inter-Container Communication (ICC)",
                    Severity = SeverityLevel.High,
                    Category = RiskCategory.BridgeIsolation,
                    Description = "Container is attached to default 'docker0' bridge where com.docker.network.bridge.enable_icc is true.",
                    Impact = "Any compromised container on this bridge can establish unsolicited TCP/UDP sessions to any peer container.",
                    Remediation = "Migrate to a user-defined custom bridge with ICC disabled or deploy micro-segmentation network policies.",
                    CisBenchmark = "CIS Docker Benchmark v1.6.0 - 2.1"
                });
                recommendations.Add($"Isolate container from default bridge '{net.NetworkName}'.");
                break;
            }
        }

        // Cap and normalize score
        p.RiskScore = Math.Clamp(score, 0, 100);
        p.RiskLevel = p.RiskScore switch
        {
            >= 70 => SeverityLevel.Critical,
            >= 45 => SeverityLevel.High,
            >= 25 => SeverityLevel.Medium,
            > 0 => SeverityLevel.Low,
            _ => SeverityLevel.Info
        };

        p.Findings = findings.OrderByDescending(f => f.Severity).ToList();
        p.EscapeVectors = escapeVectors;
        p.Recommendations = recommendations;
    }
}
