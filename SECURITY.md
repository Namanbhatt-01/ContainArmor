# Security Policy

## Supported Versions

| Version | Supported | Release Date | End of Life |
|---------|-----------|--------------|-------------|
| 1.0.x   | Yes       | Q4 2026      | Active      |

---

## Vulnerability Reporting

Security is central to ContainArmor. If you identify a security vulnerability within ContainArmor (such as a privilege escalation vector, netfilter injection flaw, or denial-of-service condition), please report it responsibly:

1. Do not file public GitHub issues for security vulnerabilities.
2. Submit a detailed report including proof-of-concept (PoC), reproduction steps, and impact assessment.
3. You will receive an initial response and acknowledgment within 48 business hours.
4. The maintainers will coordinate a patch, assign a CVE identifier where applicable, and publish a security advisory.

---

## Threat Model and Security Boundaries

ContainArmor requires access to the host's Docker daemon Unix Domain Socket (`/var/run/docker.sock`) to:
* Stream container lifecycle events via HTTP/1.1 over Unix Domain Sockets.
* Inspect container attributes (capabilities, namespaces, mounts, security profiles).
* Query bridge network configurations (`com.docker.network.bridge.enable_icc`).
* Apply automated remediation actions (`pause`, `stop`, `disconnect`).

### Recommended Production Deployment Hardening
* **Socket Proxy**: Deploy behind an authenticated read-only Docker socket proxy daemon (e.g. `tecnativa/docker-socket-proxy`) to limit write API endpoints if automated quarantine is not needed.
* **Network Isolation**: Restrict ContainArmor's management interface (port 5200) to internal management VPNs or loopback addresses.
* **Input Sanitization**: ContainArmor sanitizes all container identifiers, interface names, and IP parameters before assembling netfilter commands to prevent shell injection.
